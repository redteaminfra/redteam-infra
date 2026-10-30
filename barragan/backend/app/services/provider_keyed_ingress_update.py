# Copyright (c) 2026, Oracle and/or its affiliates.
"""One retained keyed-state ingress plan and one-shot saved-binary Apply.

The caller owns the engagement lease, authenticated route/host/provider
receipts, and channel publication. This adapter never selects a channel from
an overview and never retries an uncertain Terraform command.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_ingress_plan_gate import (
    KeyedIngressRoute, require_keyed_ingress_saved_plan,
)
from app.services.provider_keyed_initial_plan_gate import (
    _same, _verify_audited_workspace as audit_digitalocean,
)
from app.services.provider_keyed_linode_initial_plan_gate import _workspace as audit_linode
from app.services.provider_keyed_linode_udp_source_gate import (
    _CANDIDATE_SOURCE_REVISION, require_candidate_linode_udp_workspace,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_saved_plan_runner import _require_canonical_workspace_paths
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, SCHEMA, mark_provider_keyed_applied,
    mark_provider_keyed_apply_started, read_provider_topology,
)
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.terraform_plan_gate import PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES
from app.storage.credential_repository import CredentialRepository


class KeyedIngressUpdateAttention(ValueError):
    """The update is unreviewed, uncertain, or requires observation."""


@dataclass(frozen=True)
class KeyedIngressUpdate:
    workspace: ProviderKeyedWorkspace
    job_id: str
    selected_channel_id: str
    retained_resources: Mapping[str, Mapping[str, object]]
    prior_routes: tuple[KeyedIngressRoute, ...]
    next_routes: tuple[KeyedIngressRoute, ...]
    attached_node_addresses: tuple[str, ...]
    observed_host_ports: Mapping[str, tuple[tuple[str, int], ...]]
    retained_variables: Mapping[str, object]
    reviewed_variables: Mapping[str, object]
    retained_input_path: Path
    retained_input_sha256: str
    state_sha256: str
    topology_sha256: str
    predecessor_receipt_sha256: str | None = None


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]
ReleaseValidator = Callable[..., object]


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise KeyedIngressUpdateAttention("keyed ingress artifact is missing or unsafe")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _run(args: list[str], root: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=root, env=dict(env), capture_output=True,
                          text=True, check=False, umask=0o077)


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_private_json(path: Path, value: object) -> None:
    """Atomically publish channel evidence private from creation to replacement."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".barragan-private-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _audit(workspace: ProviderKeyedWorkspace) -> None:
    if workspace.provider == "digitalocean":
        audit_digitalocean(workspace)
    elif workspace.provider == "linode":
        if workspace.source_revision == _CANDIDATE_SOURCE_REVISION:
            require_candidate_linode_udp_workspace(workspace)
        else:
            audit_linode(workspace)
    else:
        raise KeyedIngressUpdateAttention("keyed ingress provider is unsupported")


def _credential(workspace: ProviderKeyedWorkspace, repository: CredentialRepository) -> tuple[str, str, str]:
    try:
        row = repository.get(workspace.provider_connection_id)
        default = repository.get_default(workspace.provider)
        if (row is None or default is None or row.id != default.id
                or row.id != workspace.provider_connection_id
                or row.provider != workspace.provider or default.provider != workspace.provider
                or row.status != "active" or default.status != "active"
                or row.encrypted_secret != default.encrypted_secret
                or row.updated_at != default.updated_at):
            raise ValueError("provider connection changed")
        token = decrypt_secret_value(row.encrypted_secret)
        if not isinstance(token, str) or not token:
            raise ValueError("provider token missing")
        return hashlib.sha256(row.encrypted_secret.encode()).hexdigest(), row.updated_at, token
    except Exception:
        raise KeyedIngressUpdateAttention("active provider connection differs from retained state") from None


def _paths(update: KeyedIngressUpdate) -> tuple[Path, Path, Path, Path]:
    if (not isinstance(update.job_id, str) or not update.job_id.startswith("job-")
            or len(update.job_id) > 80
            or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in update.job_id)):
        raise KeyedIngressUpdateAttention("keyed ingress job identity is invalid")
    prefix = update.workspace.path / f".barragan-ingress-{update.job_id}"
    return (Path(f"{prefix}-status.json"), Path(f"{prefix}-inputs.json"),
            Path(f"{prefix}-credential.json"), Path(f"{prefix}.tfplan"))


def _base(update: KeyedIngressUpdate, credentials: CredentialRepository,
          release_validator: ReleaseValidator) -> tuple[dict, str, str, str]:
    workspace = update.workspace
    if (not isinstance(workspace, ProviderKeyedWorkspace) or workspace.schema != SCHEMA
            or workspace.provider not in {"linode", "digitalocean"}
            or workspace.path.is_symlink() or not workspace.path.is_dir()
            or workspace.path.resolve(strict=True) != workspace.path):
        raise KeyedIngressUpdateAttention("keyed ingress workspace is invalid")
    _require_canonical_workspace_paths(workspace)
    _audit(workspace)
    if (_sha(workspace.state_path) != update.state_sha256
            or _digest(read_provider_topology(workspace)) != update.topology_sha256
            or _sha(update.retained_input_path) != update.retained_input_sha256):
        raise KeyedIngressUpdateAttention("retained keyed ingress generation changed")
    try:
        retained_input = json.loads(update.retained_input_path.read_text())
    except (OSError, ValueError) as exc:
        raise KeyedIngressUpdateAttention("retained Terraform inputs are unreadable") from exc
    if (retained_input != dict(update.retained_variables)
            or any(key in update.retained_variables for key in ("do_pat", "linode_api_token"))
            or {k: v for k, v in update.reviewed_variables.items()
                   if k not in {"allowed_tcp_ports", "allowed_udp_ports"}}
               != {k: v for k, v in update.retained_variables.items()
                   if k not in {"allowed_tcp_ports", "allowed_udp_ports"}}):
        raise KeyedIngressUpdateAttention("ingress changed unrelated Terraform inputs")
    try:
        state = json.loads(workspace.state_path.read_text())
        if _state_resources(state) != dict(update.retained_resources):
            raise ValueError("state values differ")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise KeyedIngressUpdateAttention("retained Terraform state differs") from exc
    credential_sha, credential_updated, token = _credential(workspace, credentials)
    release = release_validator(environment="devtest")
    if (getattr(release, "version", None) != "1.15.5"
            or not isinstance(getattr(release, "path", None), Path)
            or not isinstance(getattr(release, "sha256", None), str)
            or _sha(release.path) != release.sha256):
        raise KeyedIngressUpdateAttention("reviewed Terraform release differs")
    snapshot = {
        "schema": "keyed-ingress-update-v1", "jobId": update.job_id,
        "provider": workspace.provider, "connectionId": workspace.provider_connection_id,
        "sourceRevision": workspace.source_revision, "sourceSha256": workspace.source_sha256,
        "stateSha256": update.state_sha256, "topologySha256": update.topology_sha256,
        "retainedInputSha256": update.retained_input_sha256,
        "reviewedInputSha256": _digest(update.reviewed_variables),
        "routeSha256": _digest({"prior": [vars(row) for row in update.prior_routes],
                                "next": [vars(row) for row in update.next_routes],
                                "selected": update.selected_channel_id,
                                "hosts": update.observed_host_ports}),
        "credentialSha256": credential_sha, "credentialUpdatedAt": credential_updated,
        "terraformSha256": release.sha256, "lockfileSha256": _sha(workspace.path / ".terraform.lock.hcl"),
    }
    if update.predecessor_receipt_sha256 is not None:
        if (type(update.predecessor_receipt_sha256) is not str
                or re.fullmatch(r"[a-f0-9]{64}", update.predecessor_receipt_sha256) is None):
            raise KeyedIngressUpdateAttention("keyed ingress predecessor receipt differs")
        snapshot.update(schema="keyed-ingress-update-v2",
                        predecessorReceiptSha256=update.predecessor_receipt_sha256)
    return snapshot, token, str(release.path), workspace.provider


def _gate(shown: str, update: KeyedIngressUpdate, token: str, provider: str) -> None:
    if (update.prior_routes != update.next_routes
            and {(r.protocol, r.port) for r in update.prior_routes}
                == {(r.protocol, r.port) for r in update.next_routes}
            and update.predecessor_receipt_sha256 is None):
        raise KeyedIngressUpdateAttention("keyed ingress no-op requires predecessor receipt")
    secret_name = "do_pat" if provider == "digitalocean" else "linode_api_token"
    require_keyed_ingress_saved_plan(
        shown, workspace=update.workspace,
        retained_resources=update.retained_resources,
        prior_routes=update.prior_routes, next_routes=update.next_routes,
        selected_channel_id=update.selected_channel_id,
        attached_node_addresses=update.attached_node_addresses,
        observed_host_ports=update.observed_host_ports,
        reviewed_variables={**update.reviewed_variables, secret_name: token},
    )


def _state_envelope(state):
    """Ignore top-level check order; preserve every check's full contents."""
    envelope = {k: v for k, v in state.items() if k not in {'resources', 'serial'}}
    checks = envelope.get('check_results')
    if checks is None:
        return envelope
    if type(checks) is not list:
        raise ValueError('cleanup ingress checks are malformed')
    rows, identities = [], set()
    for row in checks:
        if (type(row) is not dict or type(row.get('object_kind')) is not str
                or type(row.get('config_addr')) is not str or type(row.get('objects')) is not list):
            raise ValueError('cleanup ingress check identity is malformed')
        identity = (row['object_kind'], row['config_addr'])
        if identity in identities:
            raise ValueError('cleanup ingress check identity is duplicated')
        identities.add(identity)
        addresses = set()
        for obj in row['objects']:
            if type(obj) is not dict or type(obj.get('object_addr')) is not str:
                raise ValueError('cleanup ingress check object is malformed')
            if obj['object_addr'] in addresses:
                raise ValueError('cleanup ingress check object is duplicated')
            addresses.add(obj['object_addr'])
        rows.append(json.dumps(row, sort_keys=True, separators=(',', ':')))
    envelope['check_results'] = sorted(rows)
    return envelope



def _require_noop_state(before_raw: bytes, after_raw: bytes) -> None:
    """Only exact retained state plus Terraform's check-row reorder/serial tick."""
    before, after = json.loads(before_raw), json.loads(after_raw)
    if (type(before) is not dict or type(after) is not dict
            or type(before.get("serial")) is not int or type(after.get("serial")) is not int
            or before["serial"] < 0
            or type(before.get("resources")) is not list or type(after.get("resources")) is not list
            or not _same(before["resources"], after["resources"])
            or not _same(_state_envelope(before), _state_envelope(after))):
        raise ValueError("no-op retained state envelope changed")
    for state in (before, after):
        for row in state.get("check_results") or []:
            if (not row['object_kind'] or not row['config_addr'] or row.get("status") != "pass"
                    or any(not obj['object_addr'] or obj.get("status") != "pass" for obj in row["objects"])):
                raise ValueError("no-op state checks are not passing")
    if after["serial"] == before["serial"]:
        if before_raw != after_raw:
            raise ValueError("no-op same-serial state bytes changed")
    elif after["serial"] != before["serial"] + 1:
        raise ValueError("no-op state serial differs")


def _require_local_applied_state(update: KeyedIngressUpdate, shown: str) -> str:
    """Keep every retained identity and the exact reviewed ingress projection."""
    try:
        plan = json.loads(shown)
        changes = {row["address"]: row["change"] for row in plan["resource_changes"]}
        after = _state_resources(json.loads(update.workspace.state_path.read_text()))
        before = dict(update.retained_resources)
        firewall = ("linode_firewall.firewall" if update.workspace.provider == "linode"
                    else "digitalocean_firewall.firewall")
        field = "inbound" if update.workspace.provider == "linode" else "inbound_rule"
        planned_firewall = changes[firewall]["after"]
        # The saved-plan gate already authenticated every exact no-op resource
        # and output when only per-node ownership changed, not the public union.
        if changes[firewall].get("actions") == ["no-op"]:
            before_path = update.workspace.path / f".barragan-ingress-{update.job_id}-before.tfstate"
            before_raw = before_path.read_bytes()
            if hashlib.sha256(before_raw).hexdigest() != update.state_sha256:
                raise ValueError("no-op prior state identity changed")
            _require_noop_state(before_raw, update.workspace.state_path.read_bytes())
            return _sha(update.workspace.state_path)
        if (set(after) != set(before) or after == before
                or any(not _same(after[address], values) for address, values in before.items()
                       if address != firewall)
                or not _same(after[firewall].get(field), planned_firewall[field])
                or any(not _same(after[firewall].get(key), value)
                       for key, value in before[firewall].items()
                       if key != field and key not in PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[
                           update.workspace.provider])):
            raise ValueError("retained resource or ingress differs")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise KeyedIngressUpdateAttention("keyed ingress applied state differs from reviewed plan") from exc
    return _sha(update.workspace.state_path)


def plan_keyed_ingress_update(
    update: KeyedIngressUpdate, *, credentials: CredentialRepository,
    recheck_authority: Callable[[], None], command_environment: Mapping[str, str],
    command_runner: CommandRunner = _run,
    release_validator: ReleaseValidator = require_devtest_terraform_release,
    staged_admin_material: Callable = lambda: nullcontext(lambda: None),
) -> dict:
    """Run one pinned real plan/show and persist its exact binary receipt."""
    if not callable(recheck_authority) or any(k.upper().startswith("TF_") for k in command_environment):
        raise KeyedIngressUpdateAttention("keyed ingress command authority is invalid")
    workspace = update.workspace
    status_path, inputs_path, secret_path, plan_path = _paths(update)
    lock_path = workspace.path / ".barragan-ingress.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode) or os.fstat(lock.fileno()).st_mode & 0o077:
            raise KeyedIngressUpdateAttention("keyed ingress lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            recheck_authority()
            with staged_admin_material() as material_fence:
                def run_fenced(args, root, environment):
                    material_fence()
                    result = command_runner(args, root, environment)
                    material_fence()
                    return result

                recheck_authority()
                snapshot, token, binary, provider = _base(update, credentials, release_validator)
                if any(path.exists() or path.is_symlink() for path in
                       (status_path, inputs_path, secret_path, plan_path)):
                    raise KeyedIngressUpdateAttention("keyed ingress plan already started; inspect retained artifacts")
                env = {k: v for k, v in command_environment.items() if k in {
                    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
                    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}}
                env.update(TF_DATA_DIR=str(workspace.terraform_data_dir), TF_CLI_CONFIG_FILE="/dev/null")
                material_fence()
                _write_private_json(status_path, {**snapshot, "phase": "planning"})
                _write_new(Path(f"{workspace.path / ('.barragan-ingress-' + update.job_id)}-before.tfstate"),
                           workspace.state_path.read_bytes())
                _write_new(inputs_path, (json.dumps(update.reviewed_variables, sort_keys=True) + "\n").encode())
                secret_name = "do_pat" if provider == "digitalocean" else "linode_api_token"
                _write_new(secret_path, (json.dumps({secret_name: token}) + "\n").encode())
                try:
                    for args in (
                        [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"],
                        [binary, "plan", "-input=false", "-lock=true", "-refresh=false", "-no-color",
                         f"-out={plan_path}", f"-var-file={inputs_path}", f"-var-file={secret_path}"],
                    ):
                        recheck_authority()
                        result = run_fenced(args, workspace.path, env)
                        if type(result.returncode) is int and result.returncode != 0:
                            # The synchronous runner returned a definite result;
                            # no provider write began. Leave a redacted failure
                            # receipt for a fresh reviewed job, without a token
                            # or partial saved binary in this workspace.
                            secret_path.unlink(missing_ok=True)
                            plan_path.unlink(missing_ok=True)
                            _write_private_json(status_path, {**snapshot, "phase": "failed_pre_apply",
                                                      "failedCommand": args[1],
                                                      "returnCode": result.returncode,
                                                      "retryableWithNewJob": True})
                            raise KeyedIngressUpdateAttention("keyed ingress Terraform plan command failed")
                        if type(result.returncode) is not int:
                            raise KeyedIngressUpdateAttention("keyed ingress command outcome is uncertain")
                        if _base(update, credentials, release_validator)[0] != snapshot:
                            raise KeyedIngressUpdateAttention("keyed ingress generation changed during plan")
                    if _sha(plan_path) == hashlib.sha256(b"").hexdigest():
                        raise KeyedIngressUpdateAttention("keyed ingress saved binary is empty")
                    recheck_authority()
                    shown_result = run_fenced([binary, "show", "-json", str(plan_path)], workspace.path, env)
                    if shown_result.returncode != 0:
                        raise KeyedIngressUpdateAttention("keyed ingress saved plan show failed")
                    _gate(shown_result.stdout, update, token, provider)
                    if _base(update, credentials, release_validator)[0] != snapshot:
                        raise KeyedIngressUpdateAttention("keyed ingress generation changed after show")
                    receipt = {**snapshot, "phase": "planned", "planSha256": _sha(plan_path),
                               "showSha256": hashlib.sha256(shown_result.stdout.encode()).hexdigest()}
                    _write_private_json(status_path, receipt)
                    return receipt
                finally:
                    # A missing command result is uncertain. Keep its private
                    # credential input for observation rather than racing a child.
                    if status_path.exists() and json.loads(status_path.read_text()).get("phase") == "planned":
                        secret_path.unlink(missing_ok=True)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def apply_keyed_ingress_update(
    update: KeyedIngressUpdate, *, credentials: CredentialRepository,
    recheck_authority: Callable[[], None], post_apply_proof: Callable[[], None],
    command_environment: Mapping[str, str], command_runner: CommandRunner = _run,
    release_validator: ReleaseValidator = require_devtest_terraform_release,
    staged_admin_material: Callable = lambda: nullcontext(lambda: None),
) -> dict:
    """Re-show the reviewed binary, then release exactly one Apply intent."""
    if not callable(recheck_authority) or not callable(post_apply_proof):
        raise KeyedIngressUpdateAttention("keyed ingress Apply authority is invalid")
    workspace = update.workspace
    status_path, inputs_path, secret_path, plan_path = _paths(update)
    lock_path = workspace.path / ".barragan-ingress.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode) or os.fstat(lock.fileno()).st_mode & 0o077:
            raise KeyedIngressUpdateAttention("keyed ingress lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            recheck_authority()
            with staged_admin_material() as material_fence:
                def run_fenced(args, root, environment):
                    material_fence()
                    result = command_runner(args, root, environment)
                    material_fence()
                    return result

                recheck_authority()
                snapshot, token, binary, provider = _base(update, credentials, release_validator)
                try:
                    receipt = json.loads(status_path.read_text())
                except (OSError, ValueError) as exc:
                    raise KeyedIngressUpdateAttention("keyed ingress saved plan receipt is missing") from exc
                if (status_path.is_symlink() or receipt.get("phase") != "planned"
                        or {k: receipt.get(k) for k in snapshot} != snapshot
                        or receipt.get("planSha256") != _sha(plan_path)
                        or _sha(inputs_path) != hashlib.sha256(
                            (json.dumps(update.reviewed_variables, sort_keys=True) + "\n").encode()).hexdigest()
                        or not isinstance(receipt.get("showSha256"), str)):
                    raise KeyedIngressUpdateAttention("keyed ingress saved plan identity changed")
                env = {k: v for k, v in command_environment.items() if k in {
                    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
                    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}}
                env.update(TF_DATA_DIR=str(workspace.terraform_data_dir), TF_CLI_CONFIG_FILE="/dev/null")
                shown = run_fenced([binary, "show", "-json", str(plan_path)], workspace.path, env)
                if shown.returncode or hashlib.sha256(shown.stdout.encode()).hexdigest() != receipt["showSha256"]:
                    raise KeyedIngressUpdateAttention("keyed ingress saved binary no longer shows reviewed plan")
                _gate(shown.stdout, update, token, provider)
                recheck_authority()
                if _base(update, credentials, release_validator)[0] != snapshot or _sha(plan_path) != receipt["planSha256"]:
                    raise KeyedIngressUpdateAttention("keyed ingress authority changed before Apply")
                material_fence()
                _write_private_json(status_path, {**receipt, "phase": "apply_intent"})
                mark_provider_keyed_apply_started(workspace)
                result = run_fenced([binary, "apply", "-input=false", "-lock=true", "-no-color",
                                         str(plan_path)], workspace.path, env)
                if type(result.returncode) is not int or result.returncode != 0:
                    raise KeyedIngressUpdateAttention("keyed ingress Apply outcome requires reconciliation")
                post_state_sha = _require_local_applied_state(update, shown.stdout)
                # Preserve the definite result before an eventually consistent
                # provider GET. This phase never authorizes Apply or publication.
                after_path = Path(f"{workspace.path / ('.barragan-ingress-' + update.job_id)}-after.tfstate")
                _write_new(after_path, workspace.state_path.read_bytes())
                if _sha(after_path) != post_state_sha or _sha(workspace.state_path) != post_state_sha:
                    raise KeyedIngressUpdateAttention("keyed ingress state changed before result capture")
                result_receipt = {**receipt, "phase": "apply_result", "returnCode": 0,
                                  "postStateSha256": post_state_sha}
                _write_private_json(status_path, result_receipt)
                post_apply_proof()
                material_fence()
                if (_sha(workspace.state_path) != post_state_sha
                        or _sha(after_path) != post_state_sha):
                    raise KeyedIngressUpdateAttention("keyed ingress state changed during post-Apply proof")
                mark_provider_keyed_applied(workspace)
                done = {**receipt, "phase": "applied", "postStateSha256": post_state_sha}
                _write_private_json(status_path, done)
                return done
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
