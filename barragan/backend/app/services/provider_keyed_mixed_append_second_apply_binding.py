# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted, read-only authority for the second mixed append one-shot Apply.

The first provider has changed.  Reopening the four-host source or paired plan
would therefore reject a legitimate append (or mask drift).  This binder uses
the saved predecessor generation, the first terminal proof, and fresh complete
provider GETs.  Only the second provider plan lock is acquired for GO.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import fcntl
import json
import os
import stat
from typing import Callable

from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_mixed_append_first_poststate import (
    collect_first_mixed_append_inventory_snapshot, prove_first_mixed_append_poststate,
)
from app.services.provider_keyed_mixed_append_first_proof_job import (
    _journal, _load_approved_first_source, _process_quiescent,
)
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_child_id
from app.services.provider_keyed_mixed_append_linode_full_plan import require_mixed_linode_append_full_plan
from app.services.provider_keyed_mixed_append_pair_apply_binding import (
    _firewall, _intent, _staged_append_admin_material,
)
from app.services.provider_keyed_mixed_append_pair_parent import _matches_request
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    _journal_complete, _name, _read, _sha,
)
from app.services.provider_keyed_mixed_append_plan_gate import (
    require_mixed_digitalocean_on_linode_append_full_plan,
)
from app.services.provider_keyed_mixed_append_second_apply_child import SecondApplySource
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_parent_id
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_partial_apply_source import ApplyObservation, classify_sealed_provider_apply
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


_OPERATION = "provider_keyed_mixed_append"


class MixedAppendSecondApplyBindingAttention(ValueError):
    """The second provider no longer matches the reviewed, one-shot source."""


@dataclass(frozen=True)
class _SecondSource:
    workspace: object
    intent: object
    receipt: dict
    receipt_sha256: str
    predecessor_state: bytes
    reviewed_show_json: bytes
    binary: bytes
    historical: StoredJobRun


def _approved_second(parent, jobs, release_check) -> _SecondSource:
    """Authenticate the second saved plan without reading changed first state."""
    # This authenticates the parent, paired approval, historical binding, and
    # first receipt.  It does not reopen the live four-host publication.
    _load_approved_first_source(parent, jobs, release_check)
    data = parent.input
    provider = data["providerOrder"][1]
    if (tuple(data["providerOrder"]) not in (("linode", "digitalocean"),
                                               ("digitalocean", "linode"))
            or tuple(data["chainOrder"]) != tuple(
                _intent(p, data["intents"][p]).chain_id for p in data["providerOrder"])
            or not _matches_request(data["reviewRequest"],
                                    _intent("digitalocean", data["intents"]["digitalocean"]),
                                    _intent("linode", data["intents"]["linode"]))):
        raise ValueError("mixed append reviewed second intent differs")
    initial = jobs.get(initial_parent_id(data["coreJobId"]))
    historical = replace(initial, events=initial.events[:7])
    completed = jobs.get(initial_child_id(data["coreJobId"], provider))
    terminal = recognize_mixed_initial_apply_terminal(completed, historical, provider)
    workspace = _prior_workspace(initial, provider, terminal)
    intent = _intent(provider, data["intents"][provider])
    root = workspace.path
    receipt_bytes = _read(root / _name(provider, "plan-receipt.json"))
    receipt = json.loads(receipt_bytes)
    predecessor = _read(root / _name(provider, "predecessor.tfstate"))
    shown = _read(root / _name(provider, "show.json"))
    binary = _read(root / _name(provider, "saved.tfplan"))
    inputs = _read(root / _name(provider, "inputs.json"))
    release = release_check(environment="devtest")
    if (_sha(receipt_bytes) != data["receiptSha256"][provider]
            or receipt.get("schema") != "mixed-append-saved-plan-receipt-v1"
            or receipt.get("provider") != provider
            or receipt.get("engagementId") != parent.target_id
            or receipt.get("coreJobId") != data["coreJobId"]
            or receipt.get("chainId") != intent.chain_id
            or receipt.get("newEdgeAddress") != intent.new_edge_address
            or receipt.get("predecessorStateSha256") != _sha(predecessor)
            or receipt.get("predecessorStateSha256") != (
                intent.digitalocean_state_sha256 if provider == "digitalocean"
                else intent.linode_state_sha256)
            or receipt.get("showJsonSha256") != _sha(shown)
            or receipt.get("planSha256") != _sha(binary)
            or receipt.get("inputSha256") != _sha(inputs)
            or json.loads(inputs) != data["reviewedInputs"][provider]
            or data["reviewedInputs"][provider] != intent.nonsecret_varfile
            or receipt.get("sourceMarkerSha256") != _sha(_read(
                root / ".barragan-provider-keyed-state.json", private=False))
            or receipt.get("topologySha256") != _sha(_read(
                root / ".barragan-topology.json", private=False))
            or receipt.get("lockfileSha256") != _sha(_read(
                root / ".terraform.lock.hcl", private=False))
            or receipt.get("sourceRevision") != workspace.source_revision
            or receipt.get("sourceSha256") != workspace.source_sha256
            or receipt.get("credentialRecordId") != workspace.provider_connection_id
            or receipt.get("terraformBinarySha256") != release.sha256
            or _sha(_read(release.path, private=False)) != release.sha256):
        raise ValueError("mixed append second approved artifact differs")
    _journal_complete(root / _name(provider, "plan-journal.jsonl"),
                      receipt["journalSha256"])
    return _SecondSource(workspace, intent, receipt, _sha(receipt_bytes),
                         predecessor, shown, binary, historical)


def _stable_first(parent, jobs, first_source, snapshot_collector,
                  credentials, linode_transport, digitalocean_transport,
                  fence: Callable[[], str]):
    child = jobs.get(first_child_id(parent.id))
    if child is None:
        raise ValueError("mixed append first child missing")
    journal, stage = _journal(parent, child, first_source)
    if stage != "terminal" or not _process_quiescent(
            journal.started_identity["bootId"], journal.started_identity["pid"],
            journal.started_identity["pgid"], journal.started_identity["startTicks"]):
        raise ValueError("mixed append first result is not quiescent terminal")
    proof_data = child.events[8].data
    snapshot = snapshot_collector(
        intent=first_source.intent, workspace=first_source.workspace,
        receipt=first_source.receipt, fence=fence,
        process_quiescent=lambda: _process_quiescent(
            journal.started_identity["bootId"], journal.started_identity["pid"],
            journal.started_identity["pgid"], journal.started_identity["startTicks"]),
        credential_repository=credentials, linode_transport=linode_transport,
        digitalocean_transport=digitalocean_transport)
    fresh = prove_first_mixed_append_poststate(
        intent=first_source.intent, predecessor_state=first_source.predecessor_state,
        reviewed_show_json=first_source.reviewed_show_json, snapshot=snapshot,
        command_result_proved=True, process_quiescent=True)
    if (fresh.state_sha256 != proof_data["stateSha256"]
            or fresh.lineage != proof_data["lineage"]
            or fresh.serial != proof_data["serial"]
            or [list(row) for row in fresh.resource_ids] != proof_data["resourceIds"]
            or fresh.new_edge_provider_id != proof_data["newEdgeProviderId"]
            or fresh.new_edge_public_ip != proof_data["newEdgePublicIp"]
            or list(fresh.attached_node_ids) != proof_data["attachedNodeIds"]
            or fresh.selector_resources_count != proof_data["selectorResourcesCount"]):
        raise ValueError("mixed append first poststate changed after terminal proof")
    return job_event_digest(child.events)


def _second_original(parent, source, credentials, collector, fence,
                     linode_transport, digitalocean_transport):
    provider = parent.input["providerOrder"][1]
    snapshot = collector(
        source.historical, provider, source.workspace, fence=fence,
        process_quiescent=lambda: True, credential_repository=credentials,
        linode_transport=linode_transport, digitalocean_transport=digitalocean_transport)
    result = classify_sealed_provider_apply(source.historical, provider,
        ApplyObservation("succeeded", True, True, snapshot.phase,
                         snapshot.state_json, True, snapshot.inventory,
                         snapshot.selector_tag_exists,
                         snapshot.selector_attached_node_ids,
                         snapshot.linode_firewall_attached_node_ids,
                         snapshot.selector_resources_count))
    retained = {address: identifier for address, identifier in (
        source.intent.retained_digitalocean_ids if provider == "digitalocean"
        else source.intent.retained_linode_ids)
        if address.startswith(("digitalocean_droplet.", "linode_instance."))
        or address in {"digitalocean_firewall.firewall", "linode_firewall.firewall",
                       "digitalocean_ssh_key.key"}}
    if (result.kind != "full" or snapshot.state_json != source.predecessor_state
            or result.state_sha256 != source.receipt["predecessorStateSha256"]
            or dict(result.resource_ids) != retained):
        raise ValueError("mixed append second original state or inventory differs")


def build_second_mixed_append_apply_bindings(
    parent_id: str, *, job_repository=None, lease_lookup=None,
    credential_repository=None, release_check=require_devtest_terraform_release,
    show_runner=run_gated_command, command_environment=None,
    first_snapshot_collector=collect_first_mixed_append_inventory_snapshot,
    second_snapshot_collector=collect_provider_inventory_snapshot,
    linode_transport=None, digitalocean_transport=None,
) -> dict:
    """Return callbacks for the private second one-shot child, with no writes."""
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    before = None

    def authority(parent, renew):
        if (parent.id != parent_id or jobs.get(parent_id) != parent
                or lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
            raise ValueError("mixed append parent or lease changed")
        renew()
        first_source = _load_approved_first_source(parent, jobs, release_check)
        second = _approved_second(parent, jobs, release_check)

        def fence():
            if (jobs.get(parent_id) != parent
                    or lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
                raise ValueError("mixed append parent or lease changed during inventory")
            renew()
            return parent.input["reviewSha256"]

        first_digest = _stable_first(parent, jobs, first_source,
            first_snapshot_collector, credentials, linode_transport,
            digitalocean_transport, fence)
        _second_original(parent, second, credentials, second_snapshot_collector,
                         fence, linode_transport, digitalocean_transport)
        provider = parent.input["providerOrder"][1]
        states = {parent.input["providerOrder"][0]: first_source.predecessor_state,
                  provider: second.predecessor_state}
        args = dict(workspace=second.workspace, intent=second.intent,
                    digitalocean_state_json=states["digitalocean"],
                    linode_state_json=states["linode"],
                    reviewed_variables=parent.input["reviewedInputs"][provider])
        if provider == "digitalocean":
            require_mixed_digitalocean_on_linode_append_full_plan(
                second.reviewed_show_json.decode(), firewall=_firewall(
                    parent.input["digitaloceanFirewall"]), **args)
        else:
            require_mixed_linode_append_full_plan(second.reviewed_show_json.decode(), **args)
        record = credentials.get(second.workspace.provider_connection_id)
        receipt = second.receipt
        if (record is None or record.id != receipt["credentialRecordId"]
                or record.provider != provider or record.status != "active"
                or record.updated_at != receipt["credentialUpdatedAt"]
                or _sha(record.encrypted_secret.encode()) != receipt["credentialSecretSha256"]):
            raise ValueError("mixed append second credential changed")
        if _read(second.workspace.state_path, private=False) != second.predecessor_state:
            raise ValueError("mixed append second state changed")
        fence()
        return first_digest, second

    def first_terminal_proof(parent, renew):
        try:
            first_source = _load_approved_first_source(parent, jobs, release_check)
            if (parent.id != parent_id or jobs.get(parent_id) != parent
                    or lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
                raise ValueError("mixed append parent or lease changed")
            def fence():
                renew()
                if (jobs.get(parent_id) != parent
                        or lookup(parent.target_id) != (
                            parent.input["corePlanId"], _OPERATION)):
                    raise ValueError("mixed append parent or lease changed")
                return parent.input["reviewSha256"]
            return _stable_first(parent, jobs, first_source, first_snapshot_collector,
                                 credentials, linode_transport, digitalocean_transport, fence)
        except Exception:
            raise MixedAppendSecondApplyBindingAttention("mixed append first terminal proof changed") from None

    def second_preflight(parent, first_proof_sha, renew):
        nonlocal before
        try:
            digest, second = authority(parent, renew)
            if digest != first_proof_sha:
                raise ValueError("mixed append first proof digest changed")
            release = release_check(environment="devtest")
            raw_env = os.environ if command_environment is None else command_environment
            if any(key.upper().startswith("TF_") for key in raw_env):
                raise ValueError("mixed append unreviewed Terraform environment")
            env = {k: v for k, v in raw_env.items() if k in {
                "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}}
            command = [str(release.path), "show", "-json", str(
                second.workspace.path / _name(second.workspace.provider, "saved.tfplan"))]
            def show_fence(_event=None):
                renew()
                if (jobs.get(parent_id) != parent
                        or lookup(parent.target_id) != (
                            parent.input["corePlanId"], _OPERATION)
                        or _sha(_read(second.workspace.path / _name(
                            second.workspace.provider, "saved.tfplan")))
                           != second.receipt["planSha256"]):
                    raise ValueError("mixed append second show source changed")
            show_fence()
            outcome = show_runner(command, scratch_path=second.workspace.path,
                                  provider_keyed_v2=True,
                                  env=dict(env, TF_DATA_DIR=str(second.workspace.terraform_data_dir),
                                           TF_CLI_CONFIG_FILE="/dev/null"),
                                  max_output_bytes=16 * 1024 * 1024,
                                  intent_callback=show_fence,
                                  started_callback=show_fence,
                                  heartbeat_callback=show_fence,
                                  result_callback=show_fence)
            if (outcome.returncode != 0 or outcome.stdout_truncated
                    or outcome.stderr_truncated
                    or outcome.stdout.encode() != second.reviewed_show_json):
                raise ValueError("mixed append second saved binary re-show differs")
            fresh_digest, fresh_second = authority(parent, renew)
            if fresh_digest != digest or fresh_second != second:
                raise ValueError("mixed append second source changed during show")
            before = (parent, digest, second)
            return parent.input["reviewSha256"]
        except Exception:
            raise MixedAppendSecondApplyBindingAttention("mixed append second preflight changed") from None

    @contextmanager
    def source_session(parent, provider, renew):
        if before is None or before[0] != parent or provider != parent.input["providerOrder"][1]:
            raise MixedAppendSecondApplyBindingAttention("mixed append second preflight missing")
        path = before[2].workspace.path / _name(provider, "plan.lock")
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r+b") as lock:
            metadata = os.fstat(lock.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise MixedAppendSecondApplyBindingAttention("mixed append second plan lock unsafe")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            def lock_fence():
                current = path.stat()
                if (path.is_symlink() or (current.st_dev, current.st_ino)
                        != (metadata.st_dev, metadata.st_ino)):
                    raise ValueError("mixed append second plan lock changed")
            lock_fence()
            with _staged_append_admin_material(parent, before[2].workspace,
                                              parent.input["reviewedInputs"][provider], jobs) as material_fence:
                def apply_fence():
                    lock_fence()
                    material_fence()
                yield SecondApplySource(before[2].workspace,
                    before[2].receipt["predecessorStateSha256"],
                    before[2].receipt["planSha256"],
                    before[2].receipt["terraformBinarySha256"], apply_fence)

    def pre_go_check(parent, source, first_proof_sha, renew):
        try:
            if before is None or before[0] != parent or before[1] != first_proof_sha:
                raise ValueError("mixed append second preflight changed")
            source.lock_fence()
            digest, second = authority(parent, renew)
            release = release_check(environment="devtest")
            if (digest != first_proof_sha or second != before[2]
                    or source.workspace != second.workspace
                    or source.predecessor_state_sha256 != second.receipt["predecessorStateSha256"]
                    or source.plan_sha256 != second.receipt["planSha256"]
                    or source.terraform_sha256 != release.sha256):
                raise ValueError("mixed append second GO source changed")
            source.lock_fence()
            renew()
            return parent.input["reviewSha256"]
        except Exception:
            raise MixedAppendSecondApplyBindingAttention("mixed append second GO requires review") from None

    return {"first_terminal_proof": first_terminal_proof,
            "second_preflight": second_preflight, "source_session": source_session,
            "pre_go_check": pre_go_check}
