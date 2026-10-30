# Copyright (c) 2026, Oracle and/or its affiliates.
"""Save one reviewed mixed DigitalOcean plan without Apply or publication.

The caller owns the engagement lease. Provider actions run only via the gated
command runner; this module has no live dispatcher.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Callable, Mapping

from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_gated_runner import CommandResult, run_gated_command
from app.services.provider_keyed_mixed_plan_journal import _Journal, _run_gated, _recover_preplan
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_initial_plan_gate import (
    _SOURCE_REVISION, _verify_audited_workspace as require_audited_workspace,
)
from app.services.provider_keyed_mixed_digitalocean_plan_gate import (
    require_mixed_digitalocean_keyed_initial_plan,
)
from app.services.provider_keyed_mixed_digitalocean_intent import compile_mixed_digitalocean_initial_intent
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease, reviewed_mixed_chain_rows
from app.services.provider_keyed_saved_plan_runner import (
    _require_absent_initial_state, _require_plan_topology_variables,
    _resolve_terraform, _unsafe_keyed_workspace,
)
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, prepare_provider_keyed_workspace, read_provider_topology,
    reserve_provider_topology,
)
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository

_PLAN = ".barragan-digitalocean-initial-full.tfplan"
_RECEIPT = ".barragan-digitalocean-plan-receipt.json"
_JOURNAL = ".barragan-digitalocean-plan-journal.jsonl"
_LOCK = ".barragan-digitalocean-plan.lock"
_ENV = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                  "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})


class MixedDigitalOceanSavedPlanError(ValueError):
    """The DigitalOcean plan cannot safely be prepared or reused."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _regular(path: Path, *, private: bool = True) -> None:
    if (path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode)
            or (private and path.stat().st_mode & 0o077)):
        raise MixedDigitalOceanSavedPlanError("DigitalOcean plan artifact is missing or unsafe")


def _sha(path: Path, *, private: bool = True) -> str:
    _regular(path, private=private)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path, *, private: bool = True) -> dict:
    _regular(path, private=private)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MixedDigitalOceanSavedPlanError("DigitalOcean plan JSON evidence is invalid") from exc
    if not isinstance(value, dict):
        raise MixedDigitalOceanSavedPlanError("DigitalOcean plan JSON evidence is invalid")
    return value


def _write_new(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _private_dir(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise MixedDigitalOceanSavedPlanError("DigitalOcean plan material directory is unsafe")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_mode & 0o077:
        raise MixedDigitalOceanSavedPlanError("DigitalOcean plan material directory is not private")


def _require_predecessor_reservation(
    workspace: ProviderKeyedWorkspace, intent, chains, core_plan,
) -> None:
    """Check reviewed ordinal reservation only; both plan receipts are joined later."""
    if intent.middle_key == "middle_01":
        return
    if intent.middle_key != "middle_02":
        raise MixedDigitalOceanSavedPlanError("DigitalOcean middle ordinal is unreviewed")
    ids = core_plan.evidence["pendingSketchChainIds"]
    prior = next((chain for chain in chains if chain.chain_id == ids[0]), None)
    scope = core_plan.evidence["sketchAuthorization"]["providerScopes"][1]
    if (prior is None or prior.middle_provider != "linode" or prior.edge_provider != "linode"
            or scope.get("chain", {}).get("id") != prior.chain_id):
        raise MixedDigitalOceanSavedPlanError("reviewed Linode predecessor is missing")
    connection_id = scope["providerConnectionId"]
    fingerprint = hashlib.sha256(f"linode\0{connection_id}".encode()).hexdigest()
    root = workspace.path.parents[1] / "linode" / fingerprint
    if root.is_symlink() or not root.is_dir():
        raise MixedDigitalOceanSavedPlanError("Linode predecessor reservation is absent")
    marker = _json(root / ".barragan-provider-keyed-state.json", private=False)
    topology = _json(root / ".barragan-topology.json", private=False)
    region = prior.edge_region
    expected = {"schema": workspace.schema,
                "middles": {"middle_01": {"region": prior.middle_region, "ordinal": 1}},
                "edge_groups": {f"group_01_{region.replace('-', '_')}": {
                    "region": region, "middle_node": "middle_01", "ordinals": [1]}},
                "regional_high_water": {region: 1}}
    if (topology != expected or any(marker.get(key) != value for key, value in {
        "schema": workspace.schema, "engagement_id": intent.engagement_id,
        "provider": "linode", "provider_connection_id": connection_id,
        "connection_fingerprint": fingerprint,
        "source_revision": scope["source"]["revision"],
    }.items())):
        raise MixedDigitalOceanSavedPlanError("Linode predecessor reservation differs from reviewed order")


def _show_gate(shown: str, intent, workspace, private: Path, output: Path, auth) -> str:
    try:
        parsed = json.loads(shown)
        variables = parsed["variables"]
    except (TypeError, ValueError, KeyError) as exc:
        raise MixedDigitalOceanSavedPlanError("DigitalOcean saved plan JSON is invalid") from exc
    _require_plan_topology_variables(shown, workspace)
    expected_variables = {**intent.nonsecret_varfile,
                          "ssh_priv_key_path": str(private),
                          "ssh_pub_key_path": str(private.parent / "admin-public"),
                          "ssh_config_path": str(output)}
    for key, value in expected_variables.items():
        if variables.get(key, {}).get("value") != value:
            raise MixedDigitalOceanSavedPlanError("DigitalOcean saved plan input differs")
    require_mixed_digitalocean_keyed_initial_plan(
        shown, workspace=workspace, reviewed_authorization=auth,
        expected_nodes=intent.nodes, expected_ssh_key_name=intent.ssh_key_name,
        expected_ssh_public_key=intent.admin_public_key,
        expected_firewall=intent.firewall,
        expected_middle_ordinal=int(intent.middle_key.rsplit("_", 1)[1]),
        expected_edge_ordinal=int(intent.edge_key.rsplit("-", 1)[1]),
        expected_local_files=intent.expected_local_files(private, output))
    return _digest(parsed)


def _snapshot(intent, workspace, terraform: Path, inputs: Path) -> dict:
    _require_absent_initial_state(workspace)
    require_audited_workspace(workspace)
    root = workspace.path
    return {
        "schema": "mixed-digitalocean-saved-plan-v1", "engagementId": intent.engagement_id,
        "coreJobId": intent.core_job_id, "corePlanId": intent.core_plan_id,
        "revisionId": intent.revision_id, "reviewFingerprint": intent.review_fingerprint,
        "connectionId": intent.provider_connection_id,
        "credentialSecretSha256": intent.credential_secret_sha256,
        "credentialUpdatedAt": intent.credential_updated_at,
        "adminPublicKeySha256": hashlib.sha256(intent.admin_public_key.encode()).hexdigest(),
        "sourceRevision": workspace.source_revision, "sourceSha256": workspace.source_sha256,
        "sourceMarkerSha256": _sha(root / ".barragan-provider-keyed-state.json", private=False),
        "topologySha256": _sha(root / ".barragan-topology.json", private=False),
        "lockfileSha256": _sha(root / ".terraform.lock.hcl", private=False),
        "inputSha256": _sha(inputs), "terraformVersion": "1.15.5",
        "terraformBinaryPath": str(terraform), "terraformBinarySha256": _sha(terraform, private=False),
        "planPath": str(root / _PLAN), "stateAbsent": True,
    }


def _current(engagement_id, core_job_id, owner, lookup, engagements, sketches,
             jobs, plans, credentials, keys, expected, *,
             lease_operation: str = "provider_keyed_initial") -> tuple:
    _require_lease(lookup, engagement_id, owner, operation=lease_operation)
    engagement = engagements.get(engagement_id)
    core_job = jobs.get(core_job_id)
    if engagement is None or core_job is None or not isinstance(core_job.input, dict):
        raise MixedDigitalOceanSavedPlanError("active reviewed core is missing")
    core_plan = plans.get(core_job.input.get("corePlanId", ""))
    chains = reviewed_mixed_chain_rows(
        sketches.list_for_engagement(engagement_id),
        core_plan.evidence.get("pendingSketchChainIds") if core_plan is not None else None,
        engagement_id)
    material = retrieve_sketch_ssh_key(engagement_id, keys)
    if material is None or not material.private_key:
        raise MixedDigitalOceanSavedPlanError("durable Sketch key is missing")
    intent = compile_mixed_digitalocean_initial_intent(
        engagement, chains, core_job, core_plan, job_repository=jobs,
        credential_repository=credentials, ssh_key_repository=keys,
        expected_admin_public_key=material.public_key, environment="devtest")
    record = credentials.get(intent.provider_connection_id)
    default = credentials.get_default("digitalocean")
    if (record is None or default is None or record != default
            or hashlib.sha256(record.encrypted_secret.encode()).hexdigest()
            != intent.credential_secret_sha256 or record.updated_at != intent.credential_updated_at):
        raise MixedDigitalOceanSavedPlanError("reviewed DigitalOcean credential changed")
    if expected is not None and intent != expected:
        raise MixedDigitalOceanSavedPlanError("reviewed DigitalOcean intent changed")
    return engagement, chains, core_job, core_plan, intent, record.encrypted_secret


def prepare_or_reuse_mixed_digitalocean_saved_plan(
    engagement_id: str, core_job_id: str, *, lease_owner: str,
    environment: str, state_root: Path, template_root: Path,
    engagement_repository=None, sketch_repository=None, job_repository=None,
    plan_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None, command_environment: Mapping[str, str] | None = None,
    gated_command_runner: Callable = run_gated_command,
    process_quiescence: Callable = _process_quiescent,
) -> dict:
    """Save/reuse a single DigitalOcean plan; no Apply or live caller is installed."""
    if (environment != "devtest" or not lease_owner or state_root != _default_state_root()
            or not state_root.is_absolute() or state_root.resolve(strict=False) != state_root):
        raise MixedDigitalOceanSavedPlanError("DigitalOcean plan requires the configured DevTest state root and lease")
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    _, chains, _, core_plan, intent, encrypted = _current(
        engagement_id, core_job_id, lease_owner, lookup, engagements, sketches,
        jobs, plans, credentials, keys, None)
    raw_env = os.environ if command_environment is None else command_environment
    if any(key.upper().startswith("TF_") for key in raw_env):
        raise MixedDigitalOceanSavedPlanError("unreviewed Terraform environment input")
    release = require_devtest_terraform_release(environment=environment)
    terraform = _resolve_terraform(str(release.path), raw_env)
    if _sha(terraform, private=False) != release.sha256:
        raise MixedDigitalOceanSavedPlanError("Terraform binary differs from pinned release")
    workspace = prepare_provider_keyed_workspace(
        engagement_id, "digitalocean", intent.provider_connection_id,
        template_root=template_root, source_revision=_SOURCE_REVISION,
        root=state_root, environment=environment, deployment_target="barragan-testing")
    root = workspace.path
    if (_unsafe_keyed_workspace(root) or workspace.state_path != root / "terraform.tfstate"
            or workspace.terraform_data_dir != root / ".terraform-data"
            or root.parents[3] != state_root or root.parents[2].name != engagement_id
            or root.parents[1].name != workspace.schema or root.parent.name != "digitalocean"
            or root.name != workspace.connection_fingerprint):
        raise MixedDigitalOceanSavedPlanError("DigitalOcean workspace is unsafe")
    require_audited_workspace(workspace)
    material_root = root.parents[1] / ".plan-material"
    _private_dir(material_root)
    material_dir = material_root / "digitalocean"
    _private_dir(material_dir)
    output = material_dir / "ssh-output"
    _private_dir(output)
    inputs = material_dir / "inputs.json"
    public = material_dir / "admin-public"
    private = material_dir / "admin-private"
    secret = material_dir / "credential.json"
    expected_inputs = {**intent.nonsecret_varfile, "ssh_pub_key_path": str(public),
                       "ssh_priv_key_path": str(private), "ssh_config_path": str(output)}
    input_bytes = (json.dumps(expected_inputs, sort_keys=True) + "\n").encode()
    descriptor = os.open(root / _LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+b") as lock:
        if (not stat.S_ISREG(os.fstat(lock.fileno()).st_mode)
                or os.fstat(lock.fileno()).st_mode & 0o077):
            raise MixedDigitalOceanSavedPlanError("DigitalOcean plan lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            def authority() -> None:
                _current(engagement_id, core_job_id, lease_owner, lookup, engagements,
                         sketches, jobs, plans, credentials, keys, intent)
                require_audited_workspace(workspace)

            authority()
            receipt_path = root / _RECEIPT
            plan_path = root / _PLAN
            journal = _Journal(root / _JOURNAL, MixedDigitalOceanSavedPlanError)
            reuse = receipt_path.exists() or receipt_path.is_symlink()
            _recover_preplan(journal, process_quiescence)
            if reuse:
                if read_provider_topology(workspace) != intent.topology:
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean topology changed since plan review")
            else:
                if journal.plan_intended() or plan_path.exists() or plan_path.is_symlink():
                    raise MixedDigitalOceanSavedPlanError("orphan DigitalOcean plan command requires reconciliation")
                _require_predecessor_reservation(workspace, intent, chains, core_plan)
                if reserve_provider_topology(workspace, intent.topology["middles"],
                                             intent.topology["edge_groups"]) != intent.topology:
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean topology differs from review")
            if inputs.exists() or inputs.is_symlink():
                _regular(inputs)
                if inputs.read_bytes() != input_bytes:
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean plan inputs changed")
            elif reuse:
                raise MixedDigitalOceanSavedPlanError("saved DigitalOcean plan inputs are missing")
            else:
                _write_new(inputs, input_bytes)
            if any(path.exists() or path.is_symlink() for path in (private, public, secret)):
                if reuse or journal.plan_intended():
                    raise MixedDigitalOceanSavedPlanError("staged DigitalOcean material requires reconciliation")
                for path in (private, public, secret):
                    if path.exists() or path.is_symlink():
                        _regular(path)
                        path.unlink()
            snapshot = _snapshot(intent, workspace, terraform, inputs)
            env = {key: value for key, value in raw_env.items() if key in _ENV}
            env.update(TF_DATA_DIR=str(workspace.terraform_data_dir), TF_CLI_CONFIG_FILE="/dev/null")
            def gated(phase: str, argv: list[str]) -> CommandResult:
                return _run_gated(phase, argv, root, env, journal, authority, gated_command_runner,
                                  MixedDigitalOceanSavedPlanError)
            binary = str(terraform)
            version = gated("version", [binary, "version", "-json"])
            try:
                if json.loads(version.stdout).get("terraform_version") != "1.15.5":
                    raise ValueError("wrong version")
            except (TypeError, ValueError, AttributeError) as exc:
                raise MixedDigitalOceanSavedPlanError("Terraform version is unverified") from exc
            if reuse:
                receipt = _json(receipt_path)
                _regular(plan_path)
                if not plan_path.stat().st_size:
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean saved plan binary is empty")
                expected = {**snapshot, "planSha256": _sha(plan_path),
                            "showJsonSha256": receipt.get("showJsonSha256"),
                            "journalSha256": receipt.get("journalSha256")}
                if (receipt != expected or not isinstance(receipt["showJsonSha256"], str)
                        or len(receipt["showJsonSha256"]) != 64
                        or not any(row["sha256"] == receipt["journalSha256"]
                                   and row["phase"] == "show" and row["kind"] == "result"
                                   for row in journal.rows)):
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean plan receipt drifted")
                shown = gated("show", [binary, "show", "-json", str(plan_path)]).stdout
                if (_show_gate(shown, intent, workspace, private, output,
                               core_plan.evidence["sketchAuthorization"])
                        != receipt["showJsonSha256"] or _sha(plan_path) != receipt["planSha256"]
                        or _snapshot(intent, workspace, terraform, inputs) != snapshot):
                    raise MixedDigitalOceanSavedPlanError("saved DigitalOcean plan changed during reuse")
                authority()
                return receipt
            gated("init", [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"])
            if _snapshot(intent, workspace, terraform, inputs) != snapshot:
                raise MixedDigitalOceanSavedPlanError("DigitalOcean workspace changed during init")
            token = decrypt_secret_value(encrypted)
            if not isinstance(token, str) or not token:
                raise MixedDigitalOceanSavedPlanError("DigitalOcean provider credential is unavailable")
            key_material = retrieve_sketch_ssh_key(engagement_id, keys)
            if (key_material is None or key_material.public_key.strip() != intent.admin_public_key
                    or not key_material.private_key):
                raise MixedDigitalOceanSavedPlanError("durable Sketch key changed")
            try:
                _write_new(private, key_material.private_key.encode())
                _write_new(public, intent.admin_public_key.encode())
                _write_new(secret, (json.dumps({"do_pat": token}) + "\n").encode())
                _write_new(plan_path, b"")
                gated("plan", [binary, "plan", "-input=false", "-lock=true", "-no-color",
                               f"-out={plan_path}", f"-var-file={inputs}",
                               f"-var-file={secret}"])
                _regular(plan_path)
                if plan_path.stat().st_size == 0:
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean saved plan binary is empty")
                plan_sha = _sha(plan_path)
                shown = gated("show", [binary, "show", "-json", str(plan_path)]).stdout
                show_sha = _show_gate(shown, intent, workspace, private, output,
                                      core_plan.evidence["sketchAuthorization"])
                if _sha(plan_path) != plan_sha or _snapshot(intent, workspace, terraform, inputs) != snapshot:
                    raise MixedDigitalOceanSavedPlanError("DigitalOcean plan changed before receipt")
                authority()
                receipt = {**snapshot, "planSha256": plan_sha, "showJsonSha256": show_sha,
                           "journalSha256": journal.rows[-1]["sha256"]}
                _write_new(receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode())
                return receipt
            finally:
                # Retain staging if a gated plan worker may still be running.
                pending = journal.pending()
                if pending is None or pending[0]["phase"] != "plan":
                    secret.unlink(missing_ok=True)
                    public.unlink(missing_ok=True)
                    private.unlink(missing_ok=True)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
