# Copyright (c) 2026, Oracle and/or its affiliates.
"""Execute the upstream-compatible post-Terraform sketch bootstrap.

Terraform's legacy sketch templates install the engagement administration key
only on ``root``.  This service deliberately runs the pinned upstream sketch
playbook from the configured Redteam-infra checkout first, through the normal core hop chain, then installs Barragan's
separate transport public key on ``sketchssh``.  It is intentionally a deploy
readiness step: callers must not mark a chain deployed until this succeeds.
"""

from __future__ import annotations

import os
import ipaddress
import re
import selectors
import sys
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from app.services.bootstrap_command_evidence import valid_number
from app.core.command_environment import barragan_subprocess_env
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.services.capability_reconciliation import safe_capability_failure_detail
from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_gated_runner import (
    GatedCommandTimeoutError, GatedRunnerError, UnreapedGatedCommandError,
    linux_process_identity, linux_active_group_members, _terminate_group,
)
from app.services.redteam_infra_template import resolve_redteam_infra_template_source
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap import (
    SketchBootstrapCoreHost,
    SketchBootstrapNode,
    SketchBootstrapSpec,
    SketchBootstrapValidationError,
    render_sketch_bootstrap_workspace,
)
from app.services.sketch_ssh_keys import SketchSshKeyNotFoundError, write_existing_sketch_ssh_key_files
from app.services.sketch_transport_ssh_keys import write_existing_sketch_transport_ssh_key_files
from app.storage.job_repository import JobRepository
from app.storage.sketch_chain_repository import StoredSketchChain


DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
# Terraform completion means only that the provider accepted the requested
# instances. Cloud-init, sshd, and the chained management route settle on
# their own schedules. Keep the retry budget explicit and long enough for a
# fresh multi-provider chain, while still returning a terminal bootstrap-only
# failure instead of leaving an opaque background loop forever.
BOOTSTRAP_COMMAND_TIMEOUT_SECONDS = 1800
BOOTSTRAP_TIMEOUT_MESSAGE = "local bootstrap execution timed out; remote work may remain; reconciliation required"
BOOTSTRAP_READINESS_BACKOFF_SECONDS = (30, 60, 120, 180, 240, 300, 300)
CommandRunner = Callable[[list[str], Path | None, Mapping[str, str]], subprocess.CompletedProcess[str]]
BootstrapProgressReporter = Callable[[str, dict[str, object]], None]
_FULL_GIT_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_BOOTSTRAP_ANSIBLE_PATHS = ("external/sketch/ansible", "ansible/roles")

_CONTROL_PATH_ARGUMENT_ENV = (
    "ANSIBLE_SSH_ARGS",
    "ANSIBLE_SSH_COMMON_ARGS",
    "ANSIBLE_SSH_EXTRA_ARGS",
    "ANSIBLE_SFTP_EXTRA_ARGS",
    "ANSIBLE_SCP_EXTRA_ARGS",
)
_ISOLATED_CONTROL_PATH = "%(directory)s/%%C"
_WORKSPACE_SSH_ARGUMENT_DEFAULTS = {
    "ANSIBLE_SSH_ARGS": "-C -o ControlMaster=auto -o ControlPersist=60s",
    "ANSIBLE_SSH_COMMON_ARGS": "",
    "ANSIBLE_SSH_EXTRA_ARGS": "",
    "ANSIBLE_SFTP_EXTRA_ARGS": "",
    "ANSIBLE_SCP_EXTRA_ARGS": "",
}
_V2_SSH_ARGS = "-C -o ControlMaster=no -o ControlPersist=no"
_V2_FORBIDDEN_CONNECTION_ENV = (
    "ANSIBLE_SSH_EXECUTABLE",
    "ANSIBLE_SFTP_EXECUTABLE",
    "ANSIBLE_SCP_EXECUTABLE",
    "ANSIBLE_TRANSPORT",
    "ANSIBLE_CONNECTION_PLUGINS",
)

_LEGACY_APT_UPDATE_TASK = """    - name: Update apt and upgrade
      apt:
        update_cache: yes
        upgrade: dist"""
_RETRIED_APT_UPDATE_TASK = f"""{_LEGACY_APT_UPDATE_TASK}
      register: sketch_apt_update_upgrade
      retries: 20
      delay: 30
      until: sketch_apt_update_upgrade is succeeded"""
_LEGACY_APT_PACKAGES_TASK = """    - name: Install required packages
      apt:
        name:
          - unattended-upgrades
          - nginx
        state: present"""
_RETRIED_APT_PACKAGES_TASK = f"""{_LEGACY_APT_PACKAGES_TASK}
      register: sketch_apt_required_packages
      retries: 20
      delay: 30
      until: sketch_apt_required_packages is succeeded"""


class SketchBootstrapApplyError(RuntimeError):
    """A deploy-time bootstrap failure that leaves provider instances intact."""


class SketchBootstrapReconciliationRequiredError(SketchBootstrapApplyError):
    """Command execution stopped with uncertain remote state; do not replay."""


class SketchBootstrapTimeoutError(SketchBootstrapReconciliationRequiredError):
    """Local command canceled at deadline; remote state needs reconciliation."""


class SketchBootstrapQuiescenceUnprovedError(SketchBootstrapReconciliationRequiredError):
    """Local work may remain; retain keys and control sockets."""


class SketchBootstrapKeyCleanupUnprovedError(SketchBootstrapApplyError):
    """A proven-finished v2 command left staged key cleanup unproved."""


def require_pinned_sketch_ansible_source(
    *,
    env: Mapping[str, str] | None,
    required_source_root: Path,
    required_source_revision: str,
) -> Path:
    """Prove exact, clean upstream Ansible inputs before fresh v2 host contact.

    The explicit environment root prevents falling back to an unrelated
    checkout. Git's ignored inventory matters because the compatibility
    adapter copies an entire upstream role directory, not only tracked files.
    """
    try:
        if (not isinstance(env, Mapping) or not isinstance(required_source_root, Path)
                or not isinstance(required_source_revision, str)
                or not _FULL_GIT_REVISION.fullmatch(required_source_revision)
                or not required_source_root.is_absolute()
                or required_source_root.is_symlink()
                or required_source_root.resolve(strict=True) != required_source_root
                or env.get(TEMPLATE_ROOT_ENV) != str(required_source_root)):
            raise ValueError("explicit root or revision differs")
        root = required_source_root
        def git(*args: str) -> bytes:
            result = subprocess.run(
                ["git", "--no-optional-locks", "-C", str(root), *args],
                capture_output=True, check=False, timeout=15,
            )
            if result.returncode:
                raise ValueError("Git source check failed")
            return result.stdout
        toplevel = Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip())
        head = os.fsdecode(git("rev-parse", "HEAD")).strip()
        if (toplevel != root or head != required_source_revision
                or git("status", "--porcelain=v1", "-z", "--untracked-files=all",
                       "--ignored=matching", "--", *_BOOTSTRAP_ANSIBLE_PATHS)):
            raise ValueError("upstream Ansible source differs")
        for relative in _BOOTSTRAP_ANSIBLE_PATHS:
            directory = root / relative
            if (directory.is_symlink() or not directory.is_dir()
                    or directory.resolve(strict=True) != directory
                    or any(path.is_symlink() for path in directory.rglob("*"))):
                raise ValueError("upstream Ansible path is unsafe")
        return root
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SketchBootstrapApplyError("pinned upstream Ansible source is unavailable or changed") from None


@dataclass(frozen=True)
class SketchBootstrapApplyResult:
    root_returncode: int
    transport_returncode: int
    node_count: int
    user_readiness_returncode: int = 0

    def to_event_data(self) -> dict[str, object]:
        return {
            "bootstrap": "succeeded",
            "nodeCount": self.node_count,
            "phases": [
                {"name": "root-management-readiness", "status": "succeeded"},
                {"name": "upstream-root-bootstrap", "status": "succeeded", "returnCode": self.root_returncode},
                {
                    "name": "post-root-user-readiness",
                    "status": "succeeded",
                    "returnCode": self.user_readiness_returncode,
                },
                {"name": "transport-key-install", "status": "succeeded", "returnCode": self.transport_returncode},
            ],
        }


def apply_sketch_bootstrap(
    engagement_id: str,
    chain: StoredSketchChain,
    *,
    repository: JobRepository,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    strict_known_hosts_path: Path | None = None,
    initial_sketch_known_hosts_path: Path | None = None,
    pinned_core_known_hosts_path: Path | None = None,
    host_policies: Mapping[str, Mapping[str, object]] | None = None,
    proxy_egress_ip: str = "",
    progress_reporter: BootstrapProgressReporter | None = None,
    required_source_root: Path | None = None,
    required_source_revision: str | None = None,
    wait: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    only_edge_name: str | None = None,
) -> SketchBootstrapApplyResult:
    """Run both required phases and securely discard staged key files.

    This does not create either durable key: deployment must already have
    created them.  A retry therefore reuses exactly the key Terraform
    installed and cannot silently strand a partially bootstrapped chain.
    Fresh v2 enrollment uses two existing, separate known-hosts files: core
    hops must already be pinned, while Sketch hosts are added on first use and
    subsequently reject changed keys under the same node alias.
    """

    if required_source_root is not None or required_source_revision is not None:
        if (host_policies is None or required_source_root is None
                or required_source_revision is None):
            raise SketchBootstrapApplyError("pinned bootstrap source requires v2 and exact root/revision")
        require_pinned_sketch_ansible_source(
            env=env, required_source_root=required_source_root,
            required_source_revision=required_source_revision,
        )

    enrollment = initial_sketch_known_hosts_path is not None or pinned_core_known_hosts_path is not None
    if enrollment:
        if (host_policies is None or strict_known_hosts_path is not None
                or initial_sketch_known_hosts_path is None or pinned_core_known_hosts_path is None):
            raise SketchBootstrapApplyError("v2 initial enrollment requires separate known-hosts files")
        sketch_known_hosts = _require_existing_known_hosts(initial_sketch_known_hosts_path, writable=True)
        core_known_hosts = _require_existing_known_hosts(pinned_core_known_hosts_path, writable=False)
        if sketch_known_hosts == core_known_hosts or (workspace_root is not None and (
                sketch_known_hosts.is_relative_to(workspace_root)
                or core_known_hosts.is_relative_to(workspace_root))):
            raise SketchBootstrapApplyError("v2 known-hosts files must be separate and durable")
    if host_policies is not None and workspace_root is not None:
        _require_canonical_workspace_root(workspace_root)
        if workspace_root.exists() or workspace_root.is_symlink():
            raise SketchBootstrapApplyError("v2 bootstrap requires a fresh workspace root")

    source = resolve_redteam_infra_template_source(env=env)
    if required_source_root is not None and source.root != required_source_root:
        raise SketchBootstrapApplyError("pinned bootstrap source root changed")
    upstream_playbook = source.path("external", "sketch", "ansible", "sketch-playbook.yml")
    if not upstream_playbook.is_file():
        raise SketchBootstrapApplyError("upstream sketch bootstrap playbook is unavailable")
    roles_root = source.ansible_roles_root
    if not roles_root.is_dir():
        raise SketchBootstrapApplyError("upstream Ansible roles are unavailable")
    sketch_roles_root = source.path("external", "sketch", "ansible", "roles")
    if not sketch_roles_root.is_dir():
        raise SketchBootstrapApplyError("upstream sketch bootstrap roles are unavailable")
    resolution = resolve_ansible_playbook(env=env)
    if not resolution.ok or not resolution.command:
        raise SketchBootstrapApplyError(resolution.error or "ansible-playbook executable is unavailable")

    homebase, proxy = _core_hosts(
        repository, engagement_id, chain.assigned_proxy,
        require_proxy_public_alias=host_policies is not None,
    )
    middle, edges = _sketch_nodes(chain, require_exact_roles=host_policies is not None)
    if only_edge_name is not None and (
            host_policies is None or type(only_edge_name) is not str
            or [edge.name for edge in edges].count(only_edge_name) != 1):
        raise SketchBootstrapApplyError("one-edge bootstrap target differs")
    if host_policies is not None:
        if proxy.host_key_alias != proxy_egress_ip:
            raise SketchBootstrapApplyError("v2 proxy egress IP differs from active core identity")
        middle_policy = host_policies.get(middle.name) if isinstance(host_policies, Mapping) else None
        if (not isinstance(middle_policy, Mapping)
                or middle_policy.get("sketch_firewall_v2_ssh_sources") != [f"{proxy_egress_ip}/32"]):
            raise SketchBootstrapApplyError("v2 middle SSH source differs from active core identity")
    root = workspace_root or Path(tempfile.mkdtemp(prefix="barragan-sketch-bootstrap-"))
    if host_policies is not None and workspace_root is None:
        root = root.resolve(strict=True)
    root.mkdir(parents=True, exist_ok=not (host_policies is not None and workspace_root is not None), mode=0o700)
    if host_policies is not None:
        # A trusted collaborator workspace may carry SGID. mkdir inherits it
        # even with mode=0700; scratch must still be exactly owner-private for
        # the later terminal quiescence audit.
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
            path_info = root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
                raise SketchBootstrapApplyError("v2 bootstrap scratch directory is not owner-private")
        finally:
            os.close(fd)
    if host_policies is not None and any((root / child).is_symlink() for child in ("ansible", "keys")):
        raise SketchBootstrapApplyError("v2 bootstrap workspace contains an unsafe path")
    keys = root / "keys"
    ssh_control_path_dir: Path | None = None
    unreaped_command = False
    try:
        compatible_upstream_playbook = _write_upstream_playbook_compatibility(upstream_playbook, root)
        compatible_sketch_roles_root = _write_upstream_role_compatibility(sketch_roles_root, root)
        admin_private, admin_public = write_existing_sketch_ssh_key_files(engagement_id, keys)
        _transport_private, transport_public = write_existing_sketch_transport_ssh_key_files(engagement_id, keys)
        workspace = render_sketch_bootstrap_workspace(
            SketchBootstrapSpec(
                homebase=homebase,
                proxy=proxy,
                middle=middle,
                edges=edges,
                admin_private_key_path=admin_private,
                admin_public_key_path=admin_public,
                transport_public_key_path=transport_public,
                ssh_config_path=str(root / "ansible" / "ssh_config"),
                upstream_root_playbook_path=str(compatible_upstream_playbook),
                host_policies=host_policies,
                proxy_egress_ip=proxy_egress_ip,
                initial_sketch_known_hosts_path=str(sketch_known_hosts) if enrollment else "",
                pinned_core_known_hosts_path=str(core_known_hosts) if enrollment else "",
            )
        )
        _write_workspace(root, workspace, expected_host_names={node.name for node in (middle, *edges)})
        if host_policies is not None:
            _normalize_v2_scratch_artifacts(root)
        if strict_known_hosts_path is not None:
            _require_strict_known_hosts(root, strict_known_hosts_path)
        command_env = barragan_subprocess_env(env)
        if host_policies is not None:
            _configure_v2_ssh_arguments(command_env)
        else:
            _reject_control_path_argument_overrides(command_env)
            # Legacy concurrent workspaces can share inventory aliases; keep
            # their multiplexed sockets isolated to this apply invocation.
            ssh_control_path_dir = Path(tempfile.mkdtemp(prefix="bcp-", dir="/tmp"))
            ssh_control_path_dir.chmod(0o700)
            command_env["ANSIBLE_SSH_CONTROL_PATH_DIR"] = str(ssh_control_path_dir.resolve())
            command_env["ANSIBLE_SSH_CONTROL_PATH"] = _ISOLATED_CONTROL_PATH
            for name, default in _WORKSPACE_SSH_ARGUMENT_DEFAULTS.items():
                command_env.setdefault(name, default)
        existing_roles = command_env.get("ANSIBLE_ROLES_PATH", "")
        # The upstream sketch playbook uses its local disable-ipv6 role as
        # well as shared roles.  Preserve its native lookup order instead of
        # copying roles into the Barragan workspace.
        command_env["ANSIBLE_ROLES_PATH"] = ":".join(
            filter(None, (str(compatible_sketch_roles_root), str(sketch_roles_root), str(roles_root), existing_roles))
        )
        invoke = runner or _run_command
        def limit(command: list[str]) -> list[str]:
            return [*command, "--limit", only_edge_name] if only_edge_name is not None else command
        root_result, user_readiness_result, transport_result = _run_bootstrap_phases_with_readiness(
            invoke,
            limit([resolution.command, *workspace.execution.readiness_command[1:]]),
            limit([resolution.command, *workspace.execution.root_command[1:]]),
            limit([resolution.command, *workspace.execution.user_readiness_command[1:]]),
            limit([resolution.command, *workspace.execution.transport_command[1:]]),
            root,
            command_env,
            reporter=progress_reporter,
            wait=wait,
            monotonic=monotonic,
            node_refs=((only_edge_name,) if only_edge_name is not None else
                       tuple(node.name for node in (middle, *edges))),
            retry_root_playbook=host_policies is None,
            retry_transport_playbook=host_policies is None,
        )
        if root_result.returncode != 0:
            phase = (
                "sketch root management readiness"
                if _command_ends_with(root_result, "ansible/wait_for_sketch_readiness.yml")
                else "upstream sketch bootstrap"
            )
            raise SketchBootstrapApplyError(_command_failure(phase, root_result))
        if user_readiness_result.returncode != 0:
            raise SketchBootstrapApplyError(
                _command_failure("post-root sketch user readiness", user_readiness_result)
            )
        if transport_result.returncode != 0:
            raise SketchBootstrapApplyError(_command_failure("sketch transport key installation", transport_result))
        return SketchBootstrapApplyResult(
            root_result.returncode,
            transport_result.returncode,
            1 if only_edge_name is not None else 1 + len(edges),
            user_readiness_result.returncode,
        )
    except (SketchBootstrapValidationError, SketchSshKeyNotFoundError) as exc:
        raise SketchBootstrapApplyError(str(exc)) from exc
    except GatedCommandTimeoutError as exc:
        raise SketchBootstrapTimeoutError(BOOTSTRAP_TIMEOUT_MESSAGE) from exc
    except (UnreapedGatedCommandError, SketchBootstrapQuiescenceUnprovedError):
        unreaped_command = True
        raise
    finally:
        # The workspace may retain non-secret diagnostic artifacts, but no
        # materialized administration or transport private key survives it
        # unless the command group might still be using those files.
        if not unreaped_command:
            if host_policies is None:
                shutil.rmtree(keys, ignore_errors=True)
            else:
                try:
                    if keys.is_symlink():
                        raise OSError("v2 staged-key path changed")
                    if keys.exists():
                        shutil.rmtree(keys)
                    if keys.exists() or keys.is_symlink():
                        raise OSError("v2 staged-key removal was incomplete")
                except OSError as exc:
                    raise SketchBootstrapKeyCleanupUnprovedError(
                        "v2 staged-key cleanup is unproved; manual reconciliation required"
                    ) from exc
        if ssh_control_path_dir is not None and not unreaped_command:
            shutil.rmtree(ssh_control_path_dir, ignore_errors=True)


def _reject_control_path_argument_overrides(command_env: Mapping[str, str]) -> None:
    """Reject argument settings that would suppress the pinned plugin path."""

    for name in _CONTROL_PATH_ARGUMENT_ENV:
        value = command_env.get(name, "")
        if "controlpath" in value.lower():
            raise SketchBootstrapApplyError(f"{name} must not override the sketch bootstrap SSH ControlPath")


def _configure_v2_ssh_arguments(command_env: dict[str, str]) -> None:
    """Keep every v2 hop out of persistent OpenSSH control sockets."""
    for name in _V2_FORBIDDEN_CONNECTION_ENV:
        if command_env.get(name, "").strip():
            raise SketchBootstrapApplyError(f"{name} is unsupported for v2 bootstrap")
    inherited = command_env.get("ANSIBLE_SSH_ARGS", "")
    if inherited not in ("", "-C", _WORKSPACE_SSH_ARGUMENT_DEFAULTS["ANSIBLE_SSH_ARGS"], _V2_SSH_ARGS):
        raise SketchBootstrapApplyError("ANSIBLE_SSH_ARGS is unsafe for v2 bootstrap")
    for name in _CONTROL_PATH_ARGUMENT_ENV[1:]:
        if command_env.get(name, "").strip():
            raise SketchBootstrapApplyError(f"{name} has competing SSH connection options")
        # An explicit empty environment value has higher precedence than a
        # custom ansible.cfg connection setting.
        command_env[name] = ""
    if command_env.get("ANSIBLE_CONFIG", "").strip():
        raise SketchBootstrapApplyError("ANSIBLE_CONFIG is unsupported for v2 bootstrap")
    command_env["ANSIBLE_SSH_ARGS"] = _V2_SSH_ARGS
    command_env.pop("ANSIBLE_SSH_CONTROL_PATH", None)
    command_env.pop("ANSIBLE_SSH_CONTROL_PATH_DIR", None)


def _write_upstream_playbook_compatibility(source: Path, workspace: Path) -> Path:
    """Prepare the upstream playbook for the current controller runtime.

    Barragan deliberately does not modify the pinned Redteam-infra checkout.
    This adapter preserves its tasks and semantics while normalizing the two
    legacy constructs that Ansible core 2.20 rejects. Connection readiness is
    a separate Barragan-owned, no-mutation play so the upstream playbook never
    starts until every required management hop is available.
    """

    content = source.read_text(encoding="utf-8")
    content = _normalize_upstream_apt_tasks(content)
    lookup = 'key: "{{ lookup(\'file\', \'{{ ssh_pub_key }}\') }}"'
    local_action = """      local_action:
        module: file
        path: \"ansible_ips.txt\"
        state: absent
      become: no"""
    sshd_handler = """    - name: Reload sshd
      service:
        name: sshd
        state: reloaded"""
    if any(
        content.count(fragment) != 1
        for fragment in (lookup, local_action, sshd_handler)
    ):
        raise SketchBootstrapApplyError("upstream sketch bootstrap compatibility forms were not found exactly once")
    content = content.replace(lookup, 'key: "{{ lookup(\'file\', ssh_pub_key) }}"')
    content = content.replace(
        local_action,
        """      ansible.builtin.file:
        path: \"ansible_ips.txt\"
        state: absent
      delegate_to: localhost
      become: no""",
    )
    content = content.replace(
        sshd_handler,
        """    - name: Reload sshd
      service:
        name: "{{ 'ssh' if ansible_os_family == 'Debian' else 'sshd' }}"
        state: reloaded""",
    )
    compatible = workspace / "ansible" / "upstream-sketch-playbook.compat.yml"
    compatible.parent.mkdir(parents=True, exist_ok=True)
    compatible.write_text(content, encoding="utf-8")
    return compatible


def _normalize_upstream_apt_tasks(content: str) -> str:
    """Accept only the canonical legacy or bounded-retry apt tasks.

    Match complete tasks at their established indentation so a legacy prefix
    inside an already-fixed task cannot be transformed a second time. Any
    renamed, duplicated, partially edited, or otherwise drifted target fails
    closed rather than guessing at package-mutation semantics.
    """

    targets = (
        ("Update apt and upgrade", _LEGACY_APT_UPDATE_TASK, _RETRIED_APT_UPDATE_TASK),
        ("Install required packages", _LEGACY_APT_PACKAGES_TASK, _RETRIED_APT_PACKAGES_TASK),
    )
    for name, legacy, retried in targets:
        content = _normalize_exact_upstream_task(content, name=name, legacy=legacy, retried=retried)
    return content


def _normalize_exact_upstream_task(content: str, *, name: str, legacy: str, retried: str) -> str:
    lines = content.splitlines(keepends=True)
    marker = f"    - name: {name}"
    starts = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == marker]
    if len(starts) != 1:
        raise SketchBootstrapApplyError("upstream sketch apt compatibility forms were not found exactly once")

    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("    - ") or lines[index].startswith("  handlers:"):
            end = index
            break
    raw_task = "".join(lines[start:end])
    task = raw_task.rstrip("\r\n")
    if task == retried:
        return content
    if task != legacy:
        raise SketchBootstrapApplyError("upstream sketch apt compatibility forms were not found exactly once")

    trailing = raw_task[len(task) :]
    return "".join(lines[:start]) + retried + trailing + "".join(lines[end:])


def _write_upstream_role_compatibility(source_roles: Path, workspace: Path) -> Path:
    """Copy and normalize the one legacy provider-sensitive upstream role."""

    source_role = source_roles / "disable-ipv6"
    source_tasks = source_role / "tasks" / "main.yml"
    if not source_tasks.is_file():
        raise SketchBootstrapApplyError("upstream disable-ipv6 role is unavailable")
    compatible_roles = workspace / "ansible" / "roles"
    compatible_role = compatible_roles / "disable-ipv6"
    shutil.copytree(source_role, compatible_role)
    compatible_tasks = compatible_role / "tasks" / "main.yml"
    content = compatible_tasks.read_text(encoding="utf-8")
    metadata_probe = """- name: Query metadata service
  uri:
    url: "http://169.254.169.254/v1/instance"
    return_content: yes
    status_code: 400"""
    if content.count(metadata_probe) != 1:
        raise SketchBootstrapApplyError("upstream disable-ipv6 metadata compatibility form was not found exactly once")
    content = content.replace(metadata_probe, metadata_probe.replace("status_code: 400", "status_code: [400, 404]"))
    compatible_tasks.write_text(content, encoding="utf-8")
    return compatible_roles


def _core_hosts(repository: JobRepository, engagement_id: str, proxy_id: str, *,
                require_proxy_public_alias: bool = False) -> tuple[SketchBootstrapCoreHost, SketchBootstrapCoreHost]:
    _deployment_id, details = active_core_connection_details(repository, engagement_id)
    homebase = next((row for row in details if str(row.get("role") or "") == "homebase"), None)
    proxies = [row for row in details if _matches_proxy(row, proxy_id)]
    proxy = proxies[0] if proxies else None
    if homebase is None or proxy is None:
        raise SketchBootstrapApplyError("active core connection details must include homebase and assigned proxy")
    if require_proxy_public_alias and len(proxies) != 1:
        raise SketchBootstrapApplyError("v2 assigned proxy core identity is ambiguous")
    key = os.environ.get(CORE_SSH_KEY_ENV, "").strip() or DEFAULT_CORE_SSH_PRIVATE_KEY
    return (
        SketchBootstrapCoreHost("homebase", _required_host(homebase, "homebase"), _entry_user(homebase), key),
        SketchBootstrapCoreHost("proxy", _required_proxy_host(proxy, proxy_id), _entry_user(proxy), key,
                                _required_proxy_public_ip(proxy) if require_proxy_public_alias else ""),
    )


def _required_proxy_public_ip(row: dict[str, Any]) -> str:
    value = row.get("publicIp")
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise SketchBootstrapApplyError("v2 assigned proxy public IP is missing or invalid") from None
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global or str(address) != value:
        raise SketchBootstrapApplyError("v2 assigned proxy public IP is missing or invalid")
    return str(address)


def _sketch_nodes(
    chain: StoredSketchChain, *, require_exact_roles: bool = False,
) -> tuple[SketchBootstrapNode, tuple[SketchBootstrapNode, ...]]:
    middle_rows = [row for row in chain.nodes if str(row.get("role") or "") == "middle"]
    edge_rows = [row for row in chain.nodes if str(row.get("role") or "") == "edge"]
    if require_exact_roles and (len(middle_rows) != 1 or len(middle_rows) + len(edge_rows) != len(chain.nodes)):
        raise SketchBootstrapApplyError("v2 bootstrap requires exactly one middle and only middle/edge nodes")
    middle_row = middle_rows[0] if middle_rows else None
    if middle_row is None or not edge_rows:
        raise SketchBootstrapApplyError("provider deployment did not report a middle and at least one edge for bootstrap")
    middle = _node(middle_row)
    return middle, tuple(_node(row) for row in edge_rows)


def _require_canonical_workspace_root(root: Path) -> None:
    if not root.is_absolute() or root != root.resolve(strict=False):
        raise SketchBootstrapApplyError("v2 bootstrap workspace root must be an absolute canonical path without symlinks")


def _node(row: dict[str, Any]) -> SketchBootstrapNode:
    name = str(row.get("hostname") or row.get("name") or "").strip()
    public_ip = str(row.get("publicIp") or "").strip()
    private_ip = str(row.get("privateIp") or "").strip()
    if not name or not public_ip:
        raise SketchBootstrapApplyError("provider deployment reported incomplete sketch node connection details")
    return SketchBootstrapNode(name, public_ip, private_ip)


def _write_workspace(root: Path, workspace, *, expected_host_names: set[str]) -> None:
    host_vars_root = root / "ansible" / "host_vars"
    expected_paths = {f"{name}.json" for name in expected_host_names} if workspace.host_vars else set()
    actual_targets = {artifact.target for artifact in workspace.host_vars}
    expected_targets = {f"ansible/host_vars/{name}" for name in expected_paths}
    if actual_targets != expected_targets or len(workspace.host_vars) != len(expected_paths):
        raise SketchBootstrapApplyError("v2 host policy does not cover exactly the bootstrap inventory")
    ansible_root = root / "ansible"
    if ansible_root.is_symlink():
        raise SketchBootstrapApplyError("bootstrap Ansible path is unsafe")
    if host_vars_root.exists() or host_vars_root.is_symlink():
        if host_vars_root.is_symlink() or not host_vars_root.is_dir():
            raise SketchBootstrapApplyError("bootstrap host_vars path is unsafe")
        for existing in host_vars_root.iterdir():
            if (existing.name not in expected_paths or existing.is_symlink()
                    or not existing.is_file()):
                raise SketchBootstrapApplyError("bootstrap host_vars contains an unexpected or unsafe file")
    artifacts = (
        workspace.inventory,
        workspace.user_inventory,
        workspace.ssh_config,
        workspace.readiness_playbook,
        workspace.user_readiness_playbook,
        workspace.root_variables,
        workspace.transport_playbook,
        workspace.manifest,
        *workspace.host_vars,
    )
    if workspace.host_vars and any((root / artifact.target).is_symlink() for artifact in artifacts):
        raise SketchBootstrapApplyError("v2 bootstrap artifact path is unsafe")
    for artifact in artifacts:
        path = root / artifact.target
        if artifact.target in actual_targets:
            if path.parent != host_vars_root or path.is_symlink():
                raise SketchBootstrapApplyError("bootstrap host_vars target is unsafe")
            host_vars_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            host_vars_root.chmod(0o700)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=host_vars_root,
                                             prefix=".host-vars-", delete=False) as temporary:
                temporary_path = Path(temporary.name)
                temporary_path.chmod(0o600)
                temporary.write(artifact.content)
            temporary_path.replace(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")
    if host_vars_root.exists() and {path.name for path in host_vars_root.iterdir()} != expected_paths:
        raise SketchBootstrapApplyError("bootstrap host_vars coverage changed during materialization")
    (root / "ansible" / "ssh_config").chmod(0o600)


def _normalize_v2_scratch_artifacts(root: Path) -> None:
    """Keep rendered and copied artifacts compatible with strict quiescence.

    A collaborator service commonly uses umask 0002, while copied upstream
    roles retain their source modes. Normalize only the private v2 scratch,
    before any host command, without changing process-wide umask or upstream.
    """

    def walk_error(error: OSError) -> None:
        raise SketchBootstrapApplyError("v2 bootstrap scratch inventory is unsafe") from error

    try:
        for _directory, directories, files, parent_fd in os.fwalk(
                root, topdown=False, follow_symlinks=False, onerror=walk_error):
            for name in (*directories, *files):
                original = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                is_directory = stat.S_ISDIR(original.st_mode)
                if (original.st_uid != os.geteuid()
                        or not (is_directory or stat.S_ISREG(original.st_mode))
                        or (is_directory and original.st_mode & 0o500 != 0o500)):
                    raise SketchBootstrapApplyError("v2 bootstrap scratch artifact is unsafe")
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                if is_directory:
                    flags |= os.O_DIRECTORY
                child_fd = os.open(name, flags, dir_fd=parent_fd)
                try:
                    current = os.fstat(child_fd)
                    if ((current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
                            or current.st_uid != os.geteuid()):
                        raise SketchBootstrapApplyError("v2 bootstrap scratch artifact changed")
                    expected_mode = stat.S_IMODE(current.st_mode) & ~0o022
                    os.fchmod(child_fd, expected_mode)
                    if stat.S_IMODE(os.fstat(child_fd).st_mode) != expected_mode:
                        raise SketchBootstrapApplyError("v2 bootstrap scratch artifact mode changed")
                finally:
                    os.close(child_fd)
    except OSError as exc:
        raise SketchBootstrapApplyError("v2 bootstrap scratch inventory is unsafe") from exc


def _require_strict_known_hosts(root: Path, known_hosts_path: Path) -> None:
    """Pin every bootstrap hop to a separately reviewed host-key file."""

    resolved = known_hosts_path.resolve(strict=True)
    ssh_config = root / "ansible" / "ssh_config"
    ssh_text = ssh_config.read_text(encoding="utf-8")
    if ssh_text.count("  UserKnownHostsFile /dev/null") == 0 or ssh_text.count(
        "  StrictHostKeyChecking no"
    ) == 0:
        raise SketchBootstrapApplyError("bootstrap SSH policy was not in the expected fail-open form")
    strict_lines: list[str] = []
    for line in ssh_text.splitlines():
        strict_lines.append(line)
        if line.startswith("Host "):
            strict_lines.append(f"  HostKeyAlias {line.removeprefix('Host ')}")
    ssh_text = "\n".join(strict_lines)
    ssh_text = ssh_text.replace("  UserKnownHostsFile /dev/null", f"  UserKnownHostsFile {resolved}")
    ssh_text = ssh_text.replace("  StrictHostKeyChecking no", "  StrictHostKeyChecking yes")
    ssh_config.write_text(ssh_text, encoding="utf-8")
    marker = "-o StrictHostKeyChecking=accept-new"
    for relative_path in ("ansible/inventory.ini", "ansible/user_inventory.ini"):
        inventory = root / relative_path
        inventory_text = inventory.read_text(encoding="utf-8")
        if inventory_text.count(marker) != 1:
            raise SketchBootstrapApplyError(
                f"bootstrap inventory SSH policy was not found exactly once: {relative_path}"
            )
        inventory.write_text(
            inventory_text.replace(
                marker,
                f"-o UserKnownHostsFile={resolved} -o StrictHostKeyChecking=yes",
            ),
            encoding="utf-8",
        )


def _require_existing_known_hosts(path: Path, *, writable: bool) -> Path:
    """Validate retained trust material without creating or rewriting it."""
    try:
        if (not isinstance(path, Path) or not path.is_absolute()
                or path.is_symlink() or path.resolve(strict=True) != path):
            raise ValueError("noncanonical known-hosts path")
        info = path.stat()
        parent = path.parent.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in ({os.geteuid()} if writable else {os.geteuid(), 0})
                or stat.S_IMODE(info.st_mode) & 0o022
                or not stat.S_IMODE(info.st_mode) & 0o400
                or (writable and not stat.S_IMODE(info.st_mode) & 0o200)
                or parent.st_uid not in {os.geteuid(), 0}
                or stat.S_IMODE(parent.st_mode) & 0o022
                or not os.access(path, os.R_OK)
                or (writable and not os.access(path, os.W_OK))
                or (not writable and not path.read_bytes().strip())):
            raise ValueError("unsafe known-hosts file")
        return path
    except (OSError, ValueError):
        raise SketchBootstrapApplyError("v2 known-hosts file is missing or unsafe") from None


def _run_command(command: list[str], cwd: Path | None, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    if not sys.platform.startswith("linux"):
        raise SketchBootstrapApplyError("Linux process supervision is required for sketch bootstrap")
    try:
        process = subprocess.Popen(command, cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        raise SketchBootstrapApplyError("local bootstrap command could not start") from exc
    identity = None
    streams = (process.stdout, process.stderr)
    selector = selectors.DefaultSelector()
    buffers = [bytearray(), bytearray()]
    try:
        identity = linux_process_identity(process.pid)
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        deadline = time.monotonic() + BOOTSTRAP_COMMAND_TIMEOUT_SECONDS
        exited_at = None
        while True:
            now = time.monotonic()
            if now >= deadline:
                _terminate_group(process, identity, linux_process_identity, linux_active_group_members)
                raise SketchBootstrapTimeoutError(BOOTSTRAP_TIMEOUT_MESSAGE)
            for key, _ in selector.select(min(0.1, max(0.0, deadline - now))):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(chunk)
                del buffers[key.data][:-65536]
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and exited_at is None:
                exited_at = time.monotonic()
            if exited_at is not None and selector.get_map() and time.monotonic() - exited_at >= 0.5:
                _terminate_group(process, identity, linux_process_identity, linux_active_group_members)
                raise SketchBootstrapReconciliationRequiredError("bootstrap descendants retained command output pipes; remote work may remain; reconciliation required")
            if exited is not None and not selector.get_map():
                if linux_active_group_members(identity):
                    _terminate_group(process, identity, linux_process_identity, linux_active_group_members)
                    raise SketchBootstrapReconciliationRequiredError("bootstrap left active descendants; remote work may remain; reconciliation required")
                returncode = process.wait(timeout=1)
                return subprocess.CompletedProcess(command, returncode,
                                                   buffers[0].decode(errors="replace"),
                                                   buffers[1].decode(errors="replace"))
    except BaseException as exc:
        if process.returncode is None:
            try:
                _terminate_group(process, identity, linux_process_identity, linux_active_group_members)
            except (GatedRunnerError, OSError) as cleanup_exc:
                raise SketchBootstrapQuiescenceUnprovedError(
                    "local bootstrap process-group quiescence unproved; reconciliation required"
                ) from cleanup_exc
        if isinstance(exc, UnreapedGatedCommandError):
            raise SketchBootstrapQuiescenceUnprovedError(
                "local bootstrap process-group quiescence unproved; reconciliation required"
            ) from exc
        raise
    finally:
        selector.close()
        for stream in streams:
            if stream is not None:
                stream.close()


def _run_bootstrap_phases_with_readiness(
    invoke: CommandRunner,
    readiness_command: list[str],
    root_command: list[str],
    user_readiness_command: list[str],
    transport_command: list[str],
    cwd: Path,
    env: Mapping[str, str],
    *,
    reporter: BootstrapProgressReporter | None,
    wait: Callable[[float], None],
    monotonic: Callable[[], float],
    node_refs: tuple[str, ...] = (),
    retry_root_playbook: bool = True,
    retry_transport_playbook: bool = True,
) -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]:
    """Run mutations only after the complete management chain is ready.

    Root readiness gates the upstream play. After that play succeeds, a
    separate inventory verifies the normal ``user`` identity on every node.
    Fresh v2 calls never replay the upstream root play after it starts; a
    failure requires reconciliation because partial host changes may exist.
    Legacy calls preserve bounded root retries. Transient user or transport
    failures recheck user readiness without rerunning a successful root play.
    A v2 transport play may already have restarted SSH; its outcome is
    one-shot and a failed reconnect requires read-only reconciliation.
    """

    started = monotonic()
    attempts = len(BOOTSTRAP_READINESS_BACKOFF_SECONDS) + 1
    command_timing = {}

    def invoke_timed(command, phase, identity, attempt, maximum):
        nonlocal command_timing
        command_started = monotonic()
        try:
            result = invoke(command, cwd, env)
        except (SketchBootstrapTimeoutError, GatedCommandTimeoutError):
            elapsed = monotonic() - command_started
            command_timing = ({"executionTimeoutSeconds": BOOTSTRAP_COMMAND_TIMEOUT_SECONDS,
                               "commandElapsedSeconds": elapsed, "timedOut": True}
                              if valid_number(elapsed) else {})
            _report_phase_failure(reporter, phase, identity, "execution_timeout", attempt, maximum,
                                  started, monotonic, node_refs, retry_exhausted=False,
                                  command_timing=command_timing)
            raise
        elapsed = monotonic() - command_started
        command_timing = ({"executionTimeoutSeconds": BOOTSTRAP_COMMAND_TIMEOUT_SECONDS,
                           "commandElapsedSeconds": elapsed, "timedOut": False}
                          if valid_number(elapsed) else {})
        return result

    root_result: subprocess.CompletedProcess[str] | None = None
    for root_attempt in range(1, attempts + 1):
        _report_phase(reporter, "checking", "root-management-readiness", root_attempt, attempts, started, monotonic, node_refs)
        readiness_result = invoke_timed(readiness_command, "root-management-readiness", "root-admin", root_attempt, attempts)
        if readiness_result.returncode != 0:
            failure_class = _classify_ssh_failure(readiness_result)
            if failure_class != "settling" or root_attempt == attempts:
                _report_phase_failure(
                    reporter, "root-management-readiness", "root-admin", failure_class,
                    root_attempt, attempts, started, monotonic, node_refs,
                    retry_exhausted=failure_class == "settling" and root_attempt == attempts, command_timing=command_timing,
                )
                return readiness_result, _not_run_result(user_readiness_command), _not_run_result(transport_command)
            _report_phase_failure(reporter, "root-management-readiness", "root-admin", failure_class,
                                  root_attempt, attempts, started, monotonic, node_refs,
                                  retry_exhausted=False, command_timing=command_timing)
            _wait_for_next_readiness_attempt(
                reporter, root_attempt, started, monotonic, wait, phase="root-management-readiness"
            )
            continue
        _report_phase(reporter, "completed", "root-management-readiness", root_attempt, attempts, started, monotonic, node_refs, command_timing=command_timing)
        _report_phase(reporter, "starting", "upstream-root-bootstrap",
                      root_attempt if retry_root_playbook else 1,
                      attempts if retry_root_playbook else 1, started, monotonic)
        root_result = invoke_timed(root_command, "upstream-root-bootstrap", "root-admin",
                                   root_attempt if retry_root_playbook else 1,
                                   attempts if retry_root_playbook else 1)
        if root_result.returncode != 0:
            failure_class = _classify_ssh_failure(root_result)
            if not retry_root_playbook or failure_class != "settling" or root_attempt == attempts:
                _report_phase_failure(
                    reporter, "upstream-root-bootstrap", "root-admin", failure_class,
                    root_attempt if retry_root_playbook else 1,
                    attempts if retry_root_playbook else 1, started, monotonic, node_refs,
                    retry_exhausted=failure_class == "settling" and (not retry_root_playbook or root_attempt == attempts), command_timing=command_timing,
                )
                return root_result, _not_run_result(user_readiness_command), _not_run_result(transport_command)
            _report_phase_failure(reporter, "upstream-root-bootstrap", "root-admin", failure_class,
                                  root_attempt, attempts, started, monotonic, node_refs,
                                  retry_exhausted=False, command_timing=command_timing)
            root_result = None
            _wait_for_next_readiness_attempt(
                reporter, root_attempt, started, monotonic, wait, phase="upstream-root-bootstrap"
            )
            continue
        _report_phase(reporter, "completed", "upstream-root-bootstrap",
                      root_attempt if retry_root_playbook else 1,
                      attempts if retry_root_playbook else 1, started, monotonic, node_refs, command_timing=command_timing)
        break

    if root_result is None:
        raise AssertionError("root bootstrap attempt budget unexpectedly exhausted")

    # Root readiness, user readiness, and transport each have an independent
    # bounded failure budget. Transport retries always return through user
    # readiness, but they never consume that identity phase's attempts.
    user_attempt = 1
    transport_attempt = 1
    while user_attempt <= attempts and transport_attempt <= attempts:
        _report_phase(reporter, "checking", "post-root-user-readiness", user_attempt, attempts, started, monotonic, node_refs)
        user_readiness_result = invoke_timed(user_readiness_command, "post-root-user-readiness", "user-admin", user_attempt, attempts)
        if user_readiness_result.returncode != 0:
            failure_class = _classify_ssh_failure(user_readiness_result)
            if failure_class != "settling" or user_attempt == attempts:
                _report_phase_failure(
                    reporter, "post-root-user-readiness", "user-admin", failure_class,
                    user_attempt, attempts, started, monotonic, node_refs,
                    retry_exhausted=failure_class == "settling" and user_attempt == attempts, command_timing=command_timing,
                )
                return root_result, user_readiness_result, _not_run_result(transport_command)
            _report_phase_failure(reporter, "post-root-user-readiness", "user-admin", failure_class,
                                  user_attempt, attempts, started, monotonic, node_refs,
                                  retry_exhausted=False, command_timing=command_timing)
            _wait_for_next_readiness_attempt(
                reporter, user_attempt, started, monotonic, wait, phase="post-root-user-readiness"
            )
            user_attempt += 1
            continue
        _report_phase(reporter, "completed", "post-root-user-readiness", user_attempt, attempts, started, monotonic, node_refs, command_timing=command_timing)
        _report_phase(
            reporter,
            "starting",
            "transport-key-install",
            transport_attempt,
            attempts,
            started,
            monotonic,
        )
        transport_result = invoke_timed(transport_command, "transport-key-install", "transport-runtime", transport_attempt, attempts)
        if transport_result.returncode == 0:
            _report_phase(reporter, "completed", "transport-key-install", transport_attempt, attempts,
                          started, monotonic, node_refs, command_timing=command_timing)
            return root_result, user_readiness_result, transport_result
        failure_class = _classify_ssh_failure(transport_result)
        if not retry_transport_playbook or failure_class != "settling" or transport_attempt == attempts:
            _report_phase_failure(
                reporter, "transport-key-install", "transport-runtime", failure_class,
                transport_attempt, attempts, started, monotonic, node_refs,
                retry_exhausted=failure_class == "settling" and transport_attempt == attempts, command_timing=command_timing,
            )
            return root_result, user_readiness_result, transport_result
        _report_phase_failure(reporter, "transport-key-install", "transport-runtime", failure_class,
                              transport_attempt, attempts, started, monotonic, node_refs,
                              retry_exhausted=False, command_timing=command_timing)
        _wait_for_next_readiness_attempt(
            reporter, transport_attempt, started, monotonic, wait, phase="transport-key-install"
        )
        transport_attempt += 1

    raise AssertionError("post-root attempt budget unexpectedly exhausted")


def _report_phase(
    reporter: BootstrapProgressReporter | None,
    status: str,
    phase: str,
    attempt: int,
    max_attempts: int,
    started: float,
    monotonic: Callable[[], float],
    node_refs: tuple[str, ...] = (),
    *, command_timing: dict | None = None,
) -> None:
    data: dict[str, object] = {
        "phase": phase,
        "attempt": attempt,
        "maxAttempts": max_attempts,
        "elapsedSeconds": _elapsed_seconds(started, monotonic),
    }
    if node_refs:
        data.update(nodeCount=len(node_refs), nodeRefs=list(node_refs))
    _report(reporter, status, **data, **(command_timing or {}))


def _report_phase_failure(
    reporter: BootstrapProgressReporter | None,
    phase: str,
    identity_boundary: str,
    failure_class: str,
    attempt: int,
    max_attempts: int,
    started: float,
    monotonic: Callable[[], float],
    node_refs: tuple[str, ...],
    *,
    retry_exhausted: bool,
    command_timing: dict | None = None,
) -> None:
    _report(
        reporter,
        "failed",
        phase=phase,
        identityBoundary=identity_boundary,
        failureClass=failure_class,
        retryExhausted=retry_exhausted,
        attempt=attempt,
        maxAttempts=max_attempts,
        elapsedSeconds=_elapsed_seconds(started, monotonic),
        nodeCount=len(node_refs),
        nodeRefs=list(node_refs),
        **(command_timing or {}),
    )


def _wait_for_next_readiness_attempt(
    reporter: BootstrapProgressReporter | None,
    attempt: int,
    started: float,
    monotonic: Callable[[], float],
    wait: Callable[[float], None],
    *,
    phase: str,
) -> None:
    backoff = BOOTSTRAP_READINESS_BACKOFF_SECONDS[attempt - 1]
    _report(
        reporter,
        "waiting",
        phase=phase,
        attempt=attempt,
        maxAttempts=len(BOOTSTRAP_READINESS_BACKOFF_SECONDS) + 1,
        elapsedSeconds=_elapsed_seconds(started, monotonic),
        nextBackoffSeconds=backoff,
    )
    wait(backoff)


def _report(reporter: BootstrapProgressReporter | None, status: str, **data: object) -> None:
    if reporter is not None:
        reporter(status, {"bootstrap": "readiness", "status": status, **data})


def _elapsed_seconds(started: float, monotonic: Callable[[], float]) -> int:
    return max(0, int(monotonic() - started))


def _not_run_result(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 1, "", "phase not run")


def _command_ends_with(result: subprocess.CompletedProcess[str], suffix: str) -> bool:
    args = result.args
    return isinstance(args, (list, tuple)) and bool(args) and str(args[-1]).endswith(suffix)


def _classify_ssh_failure(result: subprocess.CompletedProcess[str]) -> str:
    """Classify SSH failures without retrying deterministic identity defects."""

    output = "\n".join(part for part in (result.stdout, result.stderr) if part).lower()
    authentication_markers = (
        "permission denied (",
        "permission denied, please try again",
        "too many authentication failures",
        "no supported authentication methods available",
        "authentication failed",
        "invalid user",
        "account is locked",
        "not allowed because not listed in allowusers",
        "not allowed because listed in denyusers",
    )
    if any(marker in output for marker in authentication_markers):
        return "authentication"
    if result.returncode not in {2, 4} or "unreachable" not in output:
        return "terminal"
    settling_markers = (
        "kex_exchange_identification",
        "ssh_exchange_identification",
        "banner exchange",
        "connection closed",
        "connection reset by peer",
        "connection refused",
        "connection timed out",
        "operation timed out",
        "no route to host",
        "network is unreachable",
    )
    return "settling" if any(marker in output for marker in settling_markers) else "terminal"


def _is_retryable_ssh_unreachable(result: subprocess.CompletedProcess[str]) -> bool:
    """Compatibility predicate retained for focused callers and tests."""

    return _classify_ssh_failure(result) == "settling"


def _command_failure(phase: str, result: subprocess.CompletedProcess[str]) -> str:
    """Return a bounded operator diagnostic without retaining key material.

    The provider instances intentionally remain available for an explicit retry,
    so the job needs to identify whether root bootstrap or transport handoff
    failed. Ansible's stderr is generally the only useful cause. Keep a short,
    redacted excerpt in the guarded job event; never include a private-key body.
    """

    # Ansible sends task failures and recap data to stdout, while collection
    # and deprecation warnings commonly land on stderr. Keep both, with the
    # end of the combined stream favored so the failed task is not masked by
    # an early warning.
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    safe_lines = output.splitlines()
    # Preserve the Ansible task heading immediately preceding each fatal line.
    # A plain tail can retain only PLAY RECAP and hide the actionable task when
    # several hosts finish at different times.
    diagnostic_lines: list[str] = []
    latest_task = ""
    for line in safe_lines:
        stripped = line.strip()
        if stripped.startswith("TASK ["):
            latest_task = stripped
        if "FAILED!" in stripped or "UNREACHABLE!" in stripped:
            if latest_task and latest_task not in diagnostic_lines:
                diagnostic_lines.append(latest_task)
            diagnostic_lines.append(stripped)
    has_diagnostic = bool(diagnostic_lines)
    if has_diagnostic:
        recap_start = next((index for index, line in enumerate(safe_lines) if line.strip().startswith("PLAY RECAP")), -1)
        if recap_start >= 0:
            diagnostic_lines.extend(safe_lines[recap_start:])
        first_warning = next((line for line in safe_lines if line.strip().startswith("[WARNING]")), "")
        if first_warning:
            diagnostic_lines.append(first_warning)
        excerpt_lines = diagnostic_lines
    else:
        excerpt_lines = safe_lines
    excerpt = " ".join(" ".join(line.split()) for line in excerpt_lines).strip()
    if len(excerpt) > 1_200:
        excerpt = f"{excerpt[:900]} ... {excerpt[-295:]}" if has_diagnostic else f"...{excerpt[-1_197:]}"
    excerpt = _safe_bootstrap_failure_detail(excerpt)
    detail = f"; Ansible: {excerpt}" if excerpt else ""
    return f"{phase} failed (exit {result.returncode}){detail}; provider infrastructure was retained for retry"


def _safe_bootstrap_failure_detail(value: str) -> str:
    """Apply shared command redaction plus sketch SSH-key redaction."""

    redacted = re.sub(
        r"(?i)\b(authorization\s*:\s*)(?:bearer|basic)\s+[^\s,}\"']+",
        r"\1[REDACTED]",
        value,
    )
    redacted = re.sub(
        r"-----BEGIN [^-\n]*PUBLIC KEY-----.*?(?:-----END [^-\n]*PUBLIC KEY-----|\Z)",
        "[REDACTED SSH PUBLIC KEY]",
        redacted,
        flags=re.DOTALL,
    )
    redacted = re.sub(
        r"(?i)\b(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+\s+[A-Za-z0-9+/=]+(?:\s+[^\s,}\"']+)?",
        "[REDACTED SSH PUBLIC KEY]",
        redacted,
    )
    return safe_capability_failure_detail(redacted)


def _matches_proxy(row: dict[str, Any], proxy_id: str) -> bool:
    return (
        str(row.get("sshAlias") or "") == proxy_id
        or str(row.get("name") or "") == proxy_id
        or str(row.get("displayName") or "").startswith(f"{proxy_id}-")
    )


def _required_host(row: dict[str, Any], role: str) -> str:
    value = str(row.get("publicIp") or row.get("privateIp") or "").strip()
    if not value:
        raise SketchBootstrapApplyError(f"active core connection details must include an address for {role}")
    return value


def _required_proxy_host(row: dict[str, Any], role: str) -> str:
    value = str(row.get("privateIp") or row.get("publicIp") or "").strip()
    if not value:
        raise SketchBootstrapApplyError(f"active core connection details must include an address for {role}")
    return value


def _entry_user(row: dict[str, Any]) -> str:
    return str(row.get("sshUser") or "user").strip() or "user"
