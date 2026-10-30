# Copyright (c) 2026, Oracle and/or its affiliates.
"""Isolated, v2-only command supervision with an audited pre-exec gate.

Callbacks are synchronous durability fences. The caller owns the audit store,
lease checks, and any later recovery; this primitive never retries a command.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable, Sequence
from uuid import uuid4

from app.services.sketch_state_workspaces import _collaborator_group_gid


_CHILD = Path(__file__).with_name("provider_keyed_gate_child.py").resolve(strict=True)


class GatedRunnerError(RuntimeError):
    """A command was not safely started or its supervision lost authority."""


class GatedCommandTimeoutError(GatedRunnerError):
    """The local group was canceled at its deadline; remote work may remain."""


class UnreapedGatedCommandError(GatedRunnerError):
    """A possibly live command group remains; staged keys must be retained."""


@dataclass(frozen=True)
class ProcessIdentity:
    boot_id: str
    pid: int
    pgid: int
    start_ticks: int


@dataclass(frozen=True)
class CommandIntent:
    invocation_id: str
    scratch_path: str
    argv_sha256: str


@dataclass(frozen=True)
class StartedCommand:
    intent: CommandIntent
    identity: ProcessIdentity


@dataclass(frozen=True)
class CommandResult:
    started: StartedCommand
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True)
class CommandAuditResult:
    """Bounded metadata for durable audit; command output never enters it."""
    started: StartedCommand
    returncode: int
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool = False
    execution_timeout_seconds: float | None = None
    command_elapsed_seconds: float | None = None


def linux_process_identity(pid: int) -> ProcessIdentity:
    """Read one Linux process identity; never infer liveness from PID alone."""
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        raw = Path(f"/proc/{pid}/stat").read_text()
        tail = raw[raw.rfind(")") + 2:].split()
        # tail[0] is field 3 (state); field 5 is process group; 22 is starttime.
        pgid, start = int(tail[2]), int(tail[19])
    except (OSError, ValueError, IndexError) as exc:
        raise GatedRunnerError("Linux process identity is unavailable") from exc
    if not boot or pgid != pid or start <= 0:
        raise GatedRunnerError("gated process identity is invalid")
    return ProcessIdentity(boot, pid, pgid, start)


def linux_active_group_members(identity: ProcessIdentity) -> set[int]:
    """Find non-zombie Linux members while the recorded leader remains unreaped."""
    if linux_process_identity(identity.pid) != identity:
        raise GatedRunnerError("gated group leader identity changed")
    members: set[int] = set()
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "stat").read_text()
                tail = raw[raw.rfind(")") + 2:].split()
                if int(tail[2]) == identity.pgid and tail[0] != "Z":
                    members.add(int(entry.name))
            except (FileNotFoundError, ProcessLookupError):
                continue  # Process exited during the scan.
    except (OSError, ValueError, IndexError) as exc:
        raise GatedRunnerError("cannot inspect gated process group") from exc
    return members


def _resolved_command(command: Sequence[str]) -> list[str]:
    if not command or any(not isinstance(part, str) or not part or "\x00" in part for part in command):
        raise GatedRunnerError("command arguments are invalid")
    executable = shutil.which(command[0])
    if executable is None:
        raise GatedRunnerError("command executable is unavailable")
    path = Path(executable).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise GatedRunnerError("command executable is unavailable")
    return [str(path), *command[1:]]


def _private_scratch_path(path: Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise GatedRunnerError("scratch path must be canonical and private")
    try:
        for ancestor in (candidate, *candidate.parents):
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                raise GatedRunnerError("scratch path has a symlink ancestor")
        if candidate.resolve(strict=True) != candidate:
            raise GatedRunnerError("scratch path must be canonical and private")
        metadata = candidate.stat()
    except OSError as exc:
        raise GatedRunnerError("scratch path is unavailable") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    trusted_group = _collaborator_group_gid()
    private = mode == 0o700
    collaborator_readable = (mode == 0o2750 and trusted_group is not None
                             and metadata.st_gid == trusted_group)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or not (private or collaborator_readable)):
        raise GatedRunnerError("scratch path must be owner-private 0700 or trusted collaborator 02750")
    return candidate


def _terminate_group(process: subprocess.Popen, identity: ProcessIdentity | None,
                     identity_reader: Callable[[int], ProcessIdentity],
                     group_members_reader: Callable[[ProcessIdentity], set[int]],
                     *, grace: float = 0.2) -> None:
    try:
        # A reused PID must never authorize a group signal.
        if identity is None or identity_reader(process.pid) != identity:
            raise GatedRunnerError("cannot prove process-group identity for cancellation")
        try:
            os.killpg(identity.pgid, signal.SIGTERM)
        except ProcessLookupError:
            if group_members_reader(identity):
                raise GatedRunnerError("gated process group vanished with active members")
        deadline = time.monotonic() + grace
        while group_members_reader(identity) and time.monotonic() < deadline:
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
        if group_members_reader(identity):
            if identity_reader(process.pid) != identity:
                raise GatedRunnerError("cannot prove process-group identity for forced cancellation")
            # Signal the whole group even when the unreaped leader has exited.
            try:
                os.killpg(identity.pgid, signal.SIGKILL)
            except ProcessLookupError:
                if group_members_reader(identity):
                    raise GatedRunnerError("gated process group vanished with active members")
            deadline = time.monotonic() + 1.0
            while group_members_reader(identity) and time.monotonic() < deadline:
                time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
            if group_members_reader(identity):
                raise GatedRunnerError("gated process group did not quiesce")
        process.wait(timeout=grace + 1)
    except (OSError, GatedRunnerError, subprocess.TimeoutExpired) as exc:
        raise UnreapedGatedCommandError("gated process-group quiescence is unproved") from exc


def run_gated_command(
    command: Sequence[str], *, scratch_path: Path,
    intent_callback: Callable[[CommandIntent], None],
    started_callback: Callable[[StartedCommand], None],
    heartbeat_callback: Callable[[StartedCommand], None],
    result_callback: Callable[[CommandAuditResult], None],
    provider_keyed_v2: bool = False,
    identity_reader: Callable[[int], ProcessIdentity] = linux_process_identity,
    group_members_reader: Callable[[ProcessIdentity], set[int]] = linux_active_group_members,
    heartbeat_interval: float = 1.0,
    post_leader_drain_grace: float = 0.5,
    max_output_bytes: int = 65536,
    gate_timeout_seconds: int = 30,
    env: dict[str, str] | None = None,
    execution_timeout_seconds: float | None = None,
) -> CommandResult:
    if not provider_keyed_v2:
        raise GatedRunnerError("gated runner is reserved for provider-keyed-v2")
    if (heartbeat_interval <= 0 or heartbeat_interval > 30
            or post_leader_drain_grace <= 0 or post_leader_drain_grace > 5
            or max_output_bytes <= 0
            or type(gate_timeout_seconds) is not int
            or not 1 <= gate_timeout_seconds <= 1200):
        raise GatedRunnerError("supervision limits are invalid")
    if execution_timeout_seconds is not None and (
            isinstance(execution_timeout_seconds, bool)
            or not isinstance(execution_timeout_seconds, (int, float))
            or not 0 < execution_timeout_seconds < float("inf")):
        raise GatedRunnerError("execution deadline is invalid")
    scratch = _private_scratch_path(scratch_path)
    argv = _resolved_command(command)
    digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
    intent = CommandIntent(uuid4().hex, str(scratch), digest)
    try:
        intent_callback(intent)  # Must durably fence exact intent before spawn.
    except BaseException as exc:
        raise GatedRunnerError("command intent was not durably fenced") from exc

    read_fd, write_fd = os.pipe()
    process: subprocess.Popen | None = None
    identity: ProcessIdentity | None = None
    try:
        gate_options = ([] if gate_timeout_seconds == 30
                        else [f"--gate-timeout={gate_timeout_seconds}"])
        process = subprocess.Popen(
            [str(Path(sys.executable).resolve(strict=True)), "-I", str(_CHILD), str(read_fd),
             *gate_options, "--", *argv],
            cwd=scratch, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(read_fd,), start_new_session=True, close_fds=True,
        )
        os.close(read_fd)
        read_fd = -1
        identity = identity_reader(process.pid)
        if identity.pid != process.pid or identity.pgid != process.pid or not identity.boot_id or identity.start_ticks <= 0:
            raise GatedRunnerError("gated child process identity is invalid")
        started = StartedCommand(intent, identity)
        started_callback(started)  # Must durably fence identity before GO.
        os.write(write_fd, b"G")
        os.close(write_fd)
        write_fd = -1

        execution_started = time.monotonic()
        execution_deadline = (execution_started + execution_timeout_seconds
                              if execution_timeout_seconds is not None else None)
        streams = (process.stdout, process.stderr)
        selector = selectors.DefaultSelector()
        buffers = [bytearray(), bytearray()]
        drained = [0, 0]
        truncated = [False, False]
        try:
            for index, stream in enumerate(streams):
                assert stream is not None
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            next_heartbeat = time.monotonic() + heartbeat_interval
            leader_exited_at = None
            while True:
                now = time.monotonic()
                if execution_deadline is not None and now >= execution_deadline:
                    _terminate_group(process, identity, identity_reader, group_members_reader)
                    result_callback(CommandAuditResult(started, process.returncode, drained[0], drained[1],
                                                       truncated[0], truncated[1], timed_out=True,
                                                       execution_timeout_seconds=execution_timeout_seconds,
                                                       command_elapsed_seconds=max(0.0, time.monotonic() - execution_started)))
                    raise GatedCommandTimeoutError("local bootstrap execution timed out; remote work may remain; reconciliation required")
                timeout = max(0.0, min(heartbeat_interval, next_heartbeat - now))
                if execution_deadline is not None:
                    timeout = min(timeout, max(0.0, execution_deadline - now))
                for key, _ in selector.select(timeout):
                    index = key.data
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    drained[index] += len(chunk)
                    buffers[index].extend(chunk)
                    excess = len(buffers[index]) - max_output_bytes
                    if excess > 0:
                        del buffers[index][:excess]
                        truncated[index] = True
                if time.monotonic() >= next_heartbeat:
                    heartbeat_callback(started)
                    next_heartbeat = time.monotonic() + heartbeat_interval
                # WNOWAIT keeps the leader identity available for a final
                # group scan and for cancellation if a pipe-holding descendant
                # outlives it. Popen.poll() would reap that safety witness.
                exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None and leader_exited_at is None:
                    leader_exited_at = time.monotonic()
                if (leader_exited_at is not None and selector.get_map()
                        and time.monotonic() - leader_exited_at >= post_leader_drain_grace):
                    _terminate_group(process, identity, identity_reader, group_members_reader)
                    raise GatedRunnerError("gated descendants retained command output pipes")
                if exited is not None and not selector.get_map():
                    break
            if group_members_reader(identity):
                _terminate_group(process, identity, identity_reader, group_members_reader)
                raise GatedRunnerError("gated command left active descendants")
            returncode = process.wait()
        finally:
            selector.close()
            for stream in streams:
                if stream is not None:
                    stream.close()
        result = CommandResult(started, returncode,
                               buffers[0].decode(errors="replace"), buffers[1].decode(errors="replace"),
                               truncated[0], truncated[1])
        result_callback(CommandAuditResult(started, returncode, drained[0], drained[1],
                                           truncated[0], truncated[1],
                                           execution_timeout_seconds=execution_timeout_seconds,
                                           command_elapsed_seconds=(max(0.0, time.monotonic() - execution_started)
                                                                    if execution_timeout_seconds is not None else None)))
        return result
    except BaseException as exc:
        if process is not None and process.returncode is None:
            try:
                # Before GO, EOF makes the child exit without executing.
                if write_fd >= 0:
                    os.close(write_fd)
                    write_fd = -1
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        _terminate_group(process, identity, identity_reader, group_members_reader)
                else:
                    _terminate_group(process, identity, identity_reader, group_members_reader)
            except (OSError, subprocess.TimeoutExpired, GatedRunnerError) as cleanup_exc:
                raise UnreapedGatedCommandError("gated command failed and safe reaping was not proven") from cleanup_exc
        if isinstance(exc, (GatedCommandTimeoutError, UnreapedGatedCommandError)):
            raise
        raise GatedRunnerError("gated command aborted or lost authority") from exc
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
