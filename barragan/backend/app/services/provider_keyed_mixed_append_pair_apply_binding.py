# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private persisted-source callbacks for the first paired mixed append Apply.

The binary re-show runs before any exclusive plan lock. Once the first lock is
held, GO rechecks publication, provider GETs, credentials, lease, and exact
artifacts without acquiring another plan lock or invoking Terraform show.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

from app.services.provider_keyed_gated_runner import UnreapedGatedCommandError
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_append_pair_plan_producer import (
    _admin_material_paths, _matching_admin_key, _same_or_new, _cleanup_matching_material,
)
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate,
)
from app.services.provider_keyed_linode_initial_plan_gate import LinodeNodeCreate
from app.services.provider_keyed_mixed_append_intent import MixedDigitalOceanOnLinodeAppendIntent
from app.services.provider_keyed_mixed_append_linode_intent import MixedLinodeOnDigitalOceanAppendIntent
from app.services.provider_keyed_mixed_append_pair_apply import (
    verify_mixed_append_pair_binaries_before_first_go,
)
from app.services.provider_keyed_mixed_append_pair_apply_child import FirstApplySource
from app.services.provider_keyed_mixed_append_pair_parent import (
    _digest, _matches_request, _plan_child_id, mixed_append_approval_sha256,
)
from app.services import provider_keyed_mixed_append_pair_parent as parent_service
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_child_id, _prior_workspace,
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    _binding_child_id, recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_parent_id
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class MixedAppendPairApplyBindingAttention(ValueError):
    """The approved first Apply no longer matches its exact persisted source."""


@dataclass(frozen=True)
class _Context:
    parent: StoredJobRun
    source: object
    manifest: dict
    workspaces: dict
    states: dict[str, bytes]
    intents: dict
    inputs: dict
    firewall: DigitalOceanInitialFirewallIntent
    receipts: dict


def _intent(provider: str, payload: dict):
    value = dict(payload)
    if provider == "digitalocean":
        value["new_edge"] = DigitalOceanNodeCreate(**value["new_edge"])
        cls = MixedDigitalOceanOnLinodeAppendIntent
    else:
        value["new_edge"] = LinodeNodeCreate(**value["new_edge"])
        cls = MixedLinodeOnDigitalOceanAppendIntent
    for key in ("retained_digitalocean_ids", "retained_linode_ids"):
        value[key] = tuple(tuple(row) for row in value[key])
    for key in ("prior_trusted_ssh_cidrs", "trusted_ssh_cidrs"):
        value[key] = tuple(value[key])
    result = cls(**value)
    if _digest(asdict(result)) != _digest(payload):
        raise ValueError("mixed append persisted intent differs")
    return result


def _firewall(payload: dict) -> DigitalOceanInitialFirewallIntent:
    value = dict(payload)
    for key in ("public_tcp_ports", "public_udp_ports", "trusted_ssh_cidrs", "peer_cidrs"):
        value[key] = tuple(value[key])
    result = DigitalOceanInitialFirewallIntent(**value)
    if _digest(asdict(result)) != _digest(payload):
        raise ValueError("mixed append persisted firewall differs")
    return result


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load(parent: StoredJobRun, jobs, lookup, credentials) -> _Context:
    """Rebuild authority from selected durable rows and fresh provider GETs."""
    data = parent.input
    child = jobs.get(_plan_child_id(parent.id))
    if (parent.action != "provider_keyed_mixed_append"
            or parent.status != "running" or data.get("phase") != "apply_sealed"
            or data.get("engagementId") != parent.target_id
            or lookup(parent.target_id) != (data["corePlanId"], "provider_keyed_mixed_append")
            or child is None or child.status != "succeeded"
            or child.input.get("requestSha256") != data.get("requestSha256")
            or child.events[-1].data != {"reviewSha256": data.get("reviewSha256")}
            or parent.events[-1].data != {
                "reviewSha256": data.get("reviewSha256"), "planChildId": child.id}):
        raise ValueError("mixed append persisted approval differs")
    publication = parent_service._collect_published(
        parent.target_id, data["coreJobId"], jobs, lookup)
    source = publication.source
    initial = jobs.get(initial_parent_id(data["coreJobId"]))
    binding = jobs.get(_binding_child_id(data["coreJobId"]))
    if initial is None or binding is None:
        raise ValueError("mixed append published binding differs")
    historical = replace(initial, events=initial.events[:7])
    manifest = recognize_mixed_initial_host_binding(binding, historical)
    if (_digest(manifest) != source.binding_manifest_sha256
            or data["bindingManifestSha256"] != source.binding_manifest_sha256
            or data["sourceSha256"] != _digest(asdict(source))
            or data["liveBindingsSha256"] != publication.live_bindings_sha256
            or data["historicalRowsSha256"] != publication.historical_rows_sha256
            or mixed_append_approval_sha256(data["pairPlanSha256"], publication)
               != data["reviewSha256"]):
        raise ValueError("mixed append published source changed")
    workspaces, states = {}, {}
    for provider in ("digitalocean", "linode"):
        completed = jobs.get(initial_child_id(data["coreJobId"], provider))
        terminal = recognize_mixed_initial_apply_terminal(completed, historical, provider)
        workspace = _prior_workspace(initial, provider, terminal)
        if workspace.path != dict(publication.workspaces)[provider]:
            raise ValueError("mixed append workspace changed")
        workspaces[provider] = workspace
        states[provider] = _read(workspace.state_path, private=False)
    intents = {provider: _intent(provider, data["intents"][provider])
               for provider in workspaces}
    inputs = data["reviewedInputs"]
    firewall = _firewall(data["digitaloceanFirewall"])
    if (set(inputs) != set(workspaces)
            or any(inputs[provider] != intents[provider].nonsecret_varfile
                   for provider in workspaces)
            or not _matches_request(data["reviewRequest"],
                                    intents["digitalocean"], intents["linode"])
            or tuple(data["providerOrder"]) not in (
                ("digitalocean", "linode"), ("linode", "digitalocean"))
            or tuple(data["chainOrder"]) != tuple(
                intents[provider].chain_id for provider in data["providerOrder"])):
        raise ValueError("mixed append reviewed request differs")
    receipts = {}
    for provider, workspace in workspaces.items():
        root = workspace.path
        receipt_bytes = _read(root / _name(provider, "plan-receipt.json"))
        receipt = json.loads(receipt_bytes)
        predecessor = _read(root / _name(provider, "predecessor.tfstate"))
        if (_sha(receipt_bytes) != data["receiptSha256"][provider]
                or receipt["provider"] != provider
                or receipt["engagementId"] != parent.target_id
                or receipt["coreJobId"] != data["coreJobId"]
                or receipt["chainId"] != intents[provider].chain_id
                or receipt["predecessorStateSha256"] != _sha(states[provider])
                or predecessor != states[provider]
                or _sha(predecessor) != receipt["predecessorStateSha256"]
                or receipt["planSha256"] != _sha(_read(
                    root / _name(provider, "saved.tfplan")))
                or receipt["showJsonSha256"] != _sha(_read(
                    root / _name(provider, "show.json")))
                or receipt["inputSha256"] != _sha(_read(
                    root / _name(provider, "inputs.json")))
                or json.loads(_read(root / _name(provider, "inputs.json"))) != inputs[provider]
                or receipt["sourceMarkerSha256"] != _sha(_read(
                    root / ".barragan-provider-keyed-state.json", private=False))
                or receipt["topologySha256"] != _sha(_read(
                    root / ".barragan-topology.json", private=False))
                or receipt["lockfileSha256"] != _sha(_read(
                    root / ".terraform.lock.hcl", private=False))):
            raise ValueError("mixed append saved receipt changed")
        record = credentials.get(workspace.provider_connection_id)
        if (record is None or record.provider != provider or record.status != "active"
                or record.id != receipt["credentialRecordId"]
                or record.updated_at != receipt["credentialUpdatedAt"]
                or _sha(record.encrypted_secret.encode())
                   != receipt["credentialSecretSha256"]):
            raise ValueError("mixed append credential changed")
        receipts[provider] = receipt
    return _Context(parent, publication, manifest, workspaces, states,
                    intents, inputs, firewall, receipts)


@contextmanager
def _staged_append_admin_material(parent, workspace, variables, jobs):
    """Stage the original sealed key only while the caller holds its plan lock."""
    material = retrieve_sketch_ssh_key(parent.target_id)
    initial = jobs.get(initial_parent_id(parent.input["coreJobId"]))
    seal = validate_mixed_initial_apply_seal(initial)
    provider = workspace.provider
    receipt_raw = _read(workspace.path / f".barragan-{provider}-plan-receipt.json")
    receipt = json.loads(receipt_raw)
    index = seal["orderedProviders"].index(provider)
    if (material is None or not material.public_key or not material.private_key
            or not _matching_admin_key(material.public_key, material.private_key)
            or any(row["admin_public_key"] != material.public_key
                   for row in seal["reviewedPolicy"].values())
            or _digest(receipt) != seal["receiptSha256"][index]
            or receipt.get("adminPublicKeySha256") != _sha(material.public_key.encode())):
        raise ValueError("mixed append sealed administration key differs")
    public, private = _admin_material_paths(workspace, variables)
    paths = {public: material.public_key.encode(), private: material.private_key.encode()}
    unreaped = False
    try:
        for path, value in paths.items():
            _same_or_new(path, value)
        def material_fence():
            if any(_read(path) != value for path, value in paths.items()):
                raise ValueError("mixed append staged administration key changed")
        material_fence()
        yield material_fence
    except UnreapedGatedCommandError:
        unreaped = True
        raise
    finally:
        if not unreaped:
            _cleanup_matching_material(paths)


def build_first_mixed_append_apply_bindings(
    parent_id: str, *, job_repository=None, lease_lookup=None,
    credential_repository=None, release_check=require_devtest_terraform_release,
    show_runner=None, command_environment=None,
) -> dict:
    """Return concrete private callbacks for the existing one-shot child."""
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    before = None

    def snapshot(parent: StoredJobRun) -> _Context:
        if parent.id != parent_id or jobs.get(parent_id) != parent:
            raise MixedAppendPairApplyBindingAttention("mixed append parent changed")
        try:
            return _load(parent, jobs, lookup, credentials)
        except Exception:
            raise MixedAppendPairApplyBindingAttention(
                "mixed append first Apply source changed") from None

    def pair_preflight(parent: StoredJobRun, renew) -> str:
        nonlocal before
        current = snapshot(parent)
        kwargs = dict(
            expected_review_sha256=parent.input["pairPlanSha256"],
            source=current.source.source, binding_manifest=current.manifest,
            digitalocean_intent=current.intents["digitalocean"],
            linode_intent=current.intents["linode"],
            workspaces=current.workspaces, provider_states=current.states,
            reviewed_inputs=current.inputs,
            digitalocean_firewall=current.firewall,
            reviewed_provider_order=tuple(parent.input["providerOrder"]),
            reviewed_chain_order=tuple(parent.input["chainOrder"]),
            lease_lookup=lookup, lease_owner=parent.input["corePlanId"],
            credential_repository=credentials,
            release_check=release_check, claim_heartbeat=renew,
        )
        if show_runner is not None:
            kwargs["show_runner"] = show_runner
        if command_environment is not None:
            kwargs["command_environment"] = command_environment
        seal = verify_mixed_append_pair_binaries_before_first_go(**kwargs)
        if (seal.review_sha256 != parent.input["pairPlanSha256"]
                or mixed_append_approval_sha256(seal.review_sha256, current.source)
                   != parent.input["reviewSha256"]):
            raise MixedAppendPairApplyBindingAttention("mixed append approved review changed")
        fresh = snapshot(parent)
        if fresh != current:
            raise MixedAppendPairApplyBindingAttention("mixed append source changed during show")
        before = fresh
        return parent.input["reviewSha256"]

    @contextmanager
    def source_session(parent: StoredJobRun, provider: str, renew):
        if before is None or parent != before.parent or provider != parent.input["providerOrder"][0]:
            raise MixedAppendPairApplyBindingAttention("mixed append pair preflight missing")
        workspace = before.workspaces[provider]
        path = workspace.path / _name(provider, "plan.lock")
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r+b") as lock:
            metadata = os.fstat(lock.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise MixedAppendPairApplyBindingAttention("mixed append first plan lock differs")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

            def lock_fence():
                current = path.stat()
                if (path.is_symlink() or (current.st_dev, current.st_ino)
                    != (metadata.st_dev, metadata.st_ino)):
                    raise MixedAppendPairApplyBindingAttention("mixed append first plan lock changed")

            lock_fence()
            if snapshot(parent) != before:
                raise MixedAppendPairApplyBindingAttention("mixed append source changed before lock")
            renew()
            with _staged_append_admin_material(parent, workspace, before.inputs[provider], jobs) as material_fence:
                def apply_fence():
                    lock_fence()
                    material_fence()
                yield FirstApplySource(
                    workspace, before.receipts[provider]["predecessorStateSha256"],
                    before.receipts[provider]["planSha256"],
                    before.receipts[provider]["terraformBinarySha256"], apply_fence)

    def pre_go_check(parent: StoredJobRun, source: FirstApplySource, renew) -> str:
        if before is None or parent != before.parent:
            raise MixedAppendPairApplyBindingAttention("mixed append pair preflight missing")
        source.lock_fence()
        fresh = snapshot(parent)
        provider = parent.input["providerOrder"][0]
        release = release_check(environment="devtest")
        if (fresh != before or source.workspace != fresh.workspaces[provider]
                or source.predecessor_state_sha256
                   != fresh.receipts[provider]["predecessorStateSha256"]
                or source.plan_sha256 != fresh.receipts[provider]["planSha256"]
                or source.terraform_sha256 != release.sha256
                or _sha(_read(release.path, private=False)) != release.sha256
                or any(row["terraformBinarySha256"] != release.sha256
                       for row in fresh.receipts.values())):
            raise MixedAppendPairApplyBindingAttention("mixed append first GO source changed")
        renew()
        return parent.input["reviewSha256"]

    return {"source_session": source_session, "pair_preflight": pair_preflight,
            "pre_go_check": pre_go_check}
