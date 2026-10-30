# Copyright (c) 2026, Oracle and/or its affiliates.
"""Strict fsynced gated-command journal shared by one-chain plan adapters.

No provider command output or credential enters this journal.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Callable

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, StartedCommand,
)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _regular(path: Path, error_type: type[ValueError]) -> None:
    if (path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode)
            or path.stat().st_mode & 0o077):
        raise error_type("plan command journal is missing or unsafe")


class _Journal:
    """A strict fsynced callback journal; no command output or secret enters it."""

    def __init__(self, path: Path, error_type: type[ValueError] = ValueError):
        self.error_type = error_type
        self.path = path
        self.rows: list[dict] = []
        if not (path.exists() or path.is_symlink()):
            return
        _regular(path, self.error_type)
        previous = "0" * 64
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines, 1):
                row = json.loads(line)
                if (not isinstance(row, dict)
                        or set(row) != {"seq", "phase", "kind", "data", "prev", "sha256"}
                        or row["seq"] != index or row["prev"] != previous
                        or row["phase"] not in {"version", "init", "plan", "show"}
                        or row["kind"] not in {"intent", "started", "heartbeat", "result", "quiescent"}
                        or not isinstance(row["data"], dict)
                        or row["sha256"] != _digest({k: v for k, v in row.items() if k != "sha256"})):
                    raise ValueError("invalid journal row")
                previous = row["sha256"]
                self.rows.append(row)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise self.error_type("provider command journal is invalid") from exc
        self._commands()  # Strict event grammar before any provider command.

    def append(self, phase: str, kind: str, data: dict) -> None:
        row = {"seq": len(self.rows) + 1, "phase": phase, "kind": kind, "data": data,
               "prev": self.rows[-1]["sha256"] if self.rows else "0" * 64}
        row["sha256"] = _digest(row)
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
        if not self.rows:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor = os.open(self.path, flags, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write((json.dumps(row, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        if len(self.rows) == 0:
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        self.rows.append(row)

    def _commands(self) -> list[list[dict]]:
        commands: list[list[dict]] = []
        for row in self.rows:
            kind = row["kind"]
            if kind == "intent":
                if commands and commands[-1][-1]["kind"] not in {"result", "quiescent"}:
                    raise self.error_type("provider command journal has overlapping commands")
                commands.append([row])
            else:
                if not commands or row["phase"] != commands[-1][0]["phase"]:
                    raise self.error_type("provider command journal phase differs")
                prior = commands[-1][-1]["kind"]
                allowed = {"started": {"intent"}, "heartbeat": {"started", "heartbeat"},
                           "result": {"started", "heartbeat"},
                           "quiescent": {"started", "heartbeat"}}
                if prior not in allowed[kind]:
                    raise self.error_type("provider command journal order differs")
                commands[-1].append(row)
        if sum(command[0]["phase"] == "plan" for command in commands) > 1:
            raise self.error_type("provider plan command was repeated")
        version_ok = init_ok = plan_ok = False
        for command in commands:
            phase = command[0]["phase"]
            first = command[0]["data"]
            if (set(first) != {"invocationId", "argvSha256"}
                    or not isinstance(first["invocationId"], str) or not first["invocationId"]
                    or not isinstance(first["argvSha256"], str) or len(first["argvSha256"]) != 64):
                raise self.error_type("provider command intent evidence differs")
            if len(command) > 1:
                started = command[1]["data"]
                if (command[1]["kind"] != "started"
                        or set(started) != {"invocationId", "bootId", "pid", "pgid", "startTicks"}
                        or started["invocationId"] != first["invocationId"]
                        or not isinstance(started["bootId"], str) or not started["bootId"]
                        or type(started["pid"]) is not int or started["pid"] <= 0
                        or started["pgid"] != started["pid"]
                        or type(started["startTicks"]) is not int or started["startTicks"] <= 0):
                    raise self.error_type("provider command process evidence differs")
                for event in command[2:]:
                    if event["kind"] in {"heartbeat", "quiescent"} and event["data"] != started:
                        raise self.error_type("provider command worker identity differs")
                    if event["kind"] == "result" and (
                        set(event["data"]) != set(started) | {
                            "returnCode", "stdoutBytes", "stderrBytes",
                            "stdoutTruncated", "stderrTruncated"}
                        or any(event["data"].get(k) != v for k, v in started.items())
                        or type(event["data"]["returnCode"]) is not int
                        or any(type(event["data"][k]) is not int or event["data"][k] < 0
                               for k in ("stdoutBytes", "stderrBytes"))
                        or any(type(event["data"][k]) is not bool
                               for k in ("stdoutTruncated", "stderrTruncated"))):
                        raise self.error_type("provider command result evidence differs")
            success = (command[-1]["kind"] == "result"
                       and command[-1]["data"]["returnCode"] == 0
                       and not command[-1]["data"]["stdoutTruncated"]
                       and not command[-1]["data"]["stderrTruncated"])
            if phase == "version":
                version_ok = version_ok or success
            elif phase == "init":
                if not version_ok or plan_ok:
                    raise self.error_type("provider command phase order differs")
                init_ok = init_ok or success
            elif phase == "plan":
                if not version_ok or not init_ok:
                    raise self.error_type("provider command phase order differs")
                plan_ok = success
            elif phase == "show" and not plan_ok:
                raise self.error_type("provider show precedes a completed plan")
        return commands

    def pending(self) -> list[dict] | None:
        commands = self._commands()
        return commands[-1] if commands and commands[-1][-1]["kind"] not in {"result", "quiescent"} else None

    def plan_intended(self) -> bool:
        return any(row["phase"] == "plan" and row["kind"] == "intent" for row in self.rows)


def _identity(value: StartedCommand) -> dict:
    return {"invocationId": value.intent.invocation_id,
            "bootId": value.identity.boot_id, "pid": value.identity.pid,
            "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks}


def _run_gated(
    phase: str, args: list[str], root: Path, env: dict[str, str], journal: _Journal,
    authority: Callable[[], None], runner: Callable,
    error_type: type[ValueError] = ValueError,
) -> CommandResult:
    expected_argv = hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest()
    stage = "requested"
    intent: CommandIntent | None = None
    started: StartedCommand | None = None

    def on_intent(value: CommandIntent) -> None:
        nonlocal stage, intent
        authority()
        if (stage != "requested" or value.scratch_path != str(root)
                or value.argv_sha256 != expected_argv):
            raise error_type("provider gated command intent differs")
        journal.append(phase, "intent", {"invocationId": value.invocation_id,
                                         "argvSha256": value.argv_sha256})
        intent, stage = value, "intent"

    def on_started(value: StartedCommand) -> None:
        nonlocal stage, started
        authority()
        if stage != "intent" or value.intent != intent:
            raise error_type("provider gated command start differs")
        journal.append(phase, "started", _identity(value))
        started, stage = value, "started"

    def on_heartbeat(value: StartedCommand) -> None:
        authority()
        if stage != "started" or value != started:
            raise error_type("provider gated command heartbeat differs")
        journal.append(phase, "heartbeat", _identity(value))

    def on_result(value: CommandAuditResult) -> None:
        nonlocal stage
        authority()
        if stage != "started" or value.started != started:
            raise error_type("provider gated command result differs")
        journal.append(phase, "result", {**_identity(value.started),
            "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
            "stderrBytes": value.stderr_bytes, "stdoutTruncated": value.stdout_truncated,
            "stderrTruncated": value.stderr_truncated})
        stage = "result"

    authority()
    outcome = runner(args, scratch_path=root, provider_keyed_v2=True, env=env,
                     max_output_bytes=16 * 1024 * 1024 if phase == "show" else 65536,
                     intent_callback=on_intent, started_callback=on_started,
                     heartbeat_callback=on_heartbeat, result_callback=on_result)
    if (stage != "result" or outcome.started != started
            or outcome.stdout_truncated or outcome.stderr_truncated):
        raise error_type("provider gated command completion is unproved")
    if outcome.returncode:
        raise error_type(f"provider Terraform {phase} failed")
    return outcome


def _recover_preplan(journal: _Journal, quiescent: Callable) -> None:
    error_type = journal.error_type
    pending = journal.pending()
    if pending is None:
        return
    phase = pending[0]["phase"]
    if phase not in {"version", "init", "show"} or pending[-1]["kind"] == "intent":
        raise error_type("provider command outcome requires reconciliation")
    identity = pending[1]["data"]
    if not quiescent(identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]):
        raise error_type("provider command worker quiescence is unproved")
    journal.append(phase, "quiescent", identity)
