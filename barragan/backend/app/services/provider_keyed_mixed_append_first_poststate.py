# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only first-provider poststate proof for a reviewed mixed append.

This does not infer a successful command from Terraform state. The caller must
first authenticate the zero-result one-shot child journal and a quiescent
process, and must collect complete provider GET pages under its active claim.
No second provider GO may use this proof without a durable child terminal CAS.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import ipaddress
import json
import time
from typing import Callable
from typing import Mapping
from uuid import UUID

from app.integrations.linode_validation import UrllibLinodeTransport
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_initial_plan_gate import _verify_audited_workspace
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_pair_apply_child import (
    ACTION as APPLY_CHILD_ACTION, _base as _apply_base,
    _child_id as _apply_child_id, _CLAIM_KEYS,
)
from app.services.provider_keyed_linode_initial_plan_gate import _workspace as _verify_linode_workspace
from app.services.provider_keyed_mixed_append_intent import (
    MixedDigitalOceanOnLinodeAppendIntent, MixedAppendIntentError,
    _SHARED_DO, _SHARED_LINODE, _read_state,
)
from app.services.provider_keyed_mixed_append_linode_intent import (
    MixedLinodeOnDigitalOceanAppendIntent,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    MixedPartialApplyInventorySettling, MixedPartialApplyInventorySnapshot,
    _FencedDigitalOceanTransport, _FencedLinodeTransport, _credential,
    _digitalocean, _linode, _local,
)
from app.services.provider_keyed_saved_plan_runner import _require_canonical_workspace_paths
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import StoredJobRun, job_event_digest


class MixedAppendFirstPoststateAttention(ValueError):
    """First-provider state or owned inventory needs read-only reconciliation."""


@dataclass(frozen=True)
class FirstPoststateProof:
    provider: str
    state_sha256: str
    lineage: str
    serial: int
    resource_ids: tuple[tuple[str, str], ...]
    new_edge_address: str
    new_edge_provider_id: str
    new_edge_public_ip: str
    inventory_sha256: str
    observation_sha256: str
    selector_resources_count: int | None
    attached_node_ids: tuple[str, ...]


@dataclass(frozen=True)
class FirstResultJournal:
    child_id: str
    provider: str
    journal_sha256: str
    result_sha256: str
    started_identity: dict[str, object]


def recognize_first_mixed_append_zero_result(
    parent: StoredJobRun, child: StoredJobRun, receipt: Mapping[str, object],
) -> FirstResultJournal:
    """Authenticate the exact persisted result-before-proof one-shot journal."""
    try:
        base = _apply_base(parent)
        events = child.events
        if (parent.action != "provider_keyed_mixed_append"
                or parent.status != "running"
                or parent.input.get("phase") != "apply_sealed"
                or child.id != _apply_child_id(parent.id)
                or child.action != APPLY_CHILD_ACTION or child.status != "running"
                or child.target_id != parent.target_id
                or child.requested_by != parent.requested_by
                or child.started_at is None or child.finished_at is not None
                or {key: value for key, value in child.input.items()
                    if key not in _CLAIM_KEYS} != base
                or len(events) != 8
                or [(event.sequence, event.level, event.message) for event in events] != [
                    (1, "info", "mixed append first Apply queued"),
                    (2, "info", "mixed append first Apply started"),
                    (3, "info", "mixed append first Apply command intended"),
                    (4, "info", "mixed append first Apply command started before GO"),
                    (5, "info", "mixed append first phase apply_started"),
                    (6, "info", "mixed append first Apply command result fenced"),
                    (7, "info", "mixed append first phase applied"),
                    (8, "info", "mixed append first awaiting exact poststate proof"),
                ]
                or events[0].data != {} or events[1].data != {}
                or events[2].data.get("invocationId") != events[3].data.get("invocationId")
                or events[3].data.get("invocationId") != events[5].data.get("invocationId")
                or receipt.get("provider") != base["provider"]
                or receipt.get("engagementId") != parent.target_id
                or receipt.get("coreJobId") != parent.input["coreJobId"]
                or events[2].data.get("planSha256") != receipt.get("planSha256")
                or events[2].data.get("terraformSha256")
                   != receipt.get("terraformBinarySha256")
                or type(events[2].data.get("argvSha256")) is not str
                or len(events[2].data["argvSha256"]) != 64
                or type(events[2].data.get("planPath")) is not str
                or not events[2].data["planPath"]
                or type(events[2].data.get("terraformPath")) is not str
                or not events[2].data["terraformPath"]
                or events[4].data != {"commandStartSequence": 4}
                or events[6].data != {"commandResultSequence": 6}
                or events[7].data != {"commandResultSequence": 6}
                or events[5].data.get("returnCode") != 0
                or events[5].data.get("stdoutTruncated") is not False
                or events[5].data.get("stderrTruncated") is not False
                or any(type(events[5].data.get(key)) is not int or events[5].data[key] < 0
                       for key in ("stdoutBytes", "stderrBytes"))):
            raise ValueError("mixed append first result journal differs")
        identity = {key: events[3].data[key]
                    for key in ("bootId", "pid", "pgid", "startTicks")}
        if (type(identity["bootId"]) is not str or not identity["bootId"]
                or any(type(identity[key]) is not int or identity[key] <= 0
                       for key in ("pid", "pgid", "startTicks"))):
            raise ValueError("mixed append process identity differs")
        result_sha = job_event_digest(events[:6])
        return FirstResultJournal(child.id, base["provider"],
                                  job_event_digest(events), result_sha, identity)
    except Exception:
        raise MixedAppendFirstPoststateAttention(
            "mixed append first Apply result journal requires review") from None


def collect_first_mixed_append_inventory_snapshot(
    *, intent: MixedDigitalOceanOnLinodeAppendIntent | MixedLinodeOnDigitalOceanAppendIntent,
    workspace: ProviderKeyedWorkspace, receipt: Mapping[str, object],
    fence: Callable[[], str], process_quiescent: Callable[[], bool],
    credential_repository=None, linode_transport=None, digitalocean_transport=None,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
) -> MixedPartialApplyInventorySnapshot:
    """GET-only complete inventory under a caller-owned journal/claim fence.

    The receipt is the approved plan receipt, not a caller-provided credential
    policy. No endpoint outside the existing instance/firewall/key/tag readers
    is requested.
    """
    try:
        provider = ("digitalocean" if type(intent) is MixedDigitalOceanOnLinodeAppendIntent
                    else "linode" if type(intent) is MixedLinodeOnDigitalOceanAppendIntent
                    else None)
        if (provider is None or workspace.provider != provider
                or workspace.provider_connection_id != receipt.get("credentialRecordId")
                or receipt.get("provider") != provider
                or receipt.get("engagementId") != intent.engagement_id
                or receipt.get("coreJobId") != intent.core_job_id
                or not callable(fence) or not callable(process_quiescent)):
            raise ValueError("mixed append inventory authority differs")
        _require_canonical_workspace_paths(workspace)
        if provider == "linode":
            _verify_linode_workspace(workspace)
        else:
            _verify_audited_workspace(workspace)
        repository = credential_repository or SqlAlchemyCredentialRepository()
        policy = {
            "provider_connection_id": receipt["credentialRecordId"],
            "credential_secret_sha256": receipt["credentialSecretSha256"],
            "credential_updated_at": receipt["credentialUpdatedAt"],
            "engagement_name": intent.new_edge.tag if provider == "linode" else None,
        }
        encrypted = _credential(repository, provider, policy)
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("mixed append provider credential unavailable")
        generation = fence()
        if type(generation) is not str or not generation or process_quiescent() is not True:
            raise ValueError("mixed append Apply process may still run")
        before = _local(workspace)
        if before[1] != "applied" or before[0] is None:
            raise ValueError("mixed append local state is not applied")
        if provider == "linode":
            inventory, attached = _linode(
                _FencedLinodeTransport(linode_transport or UrllibLinodeTransport(),
                                       fence, generation), token, fence, policy)
            selector_exists = selector_count = selector_attached = None
        else:
            inventory, selector_exists, selector_count, selector_attached = _digitalocean(
                _FencedDigitalOceanTransport(
                    digitalocean_transport or UrllibProviderCatalogTransport(),
                    fence, generation), token, intent.new_edge.firewall_selector_tag, fence,
                include_firewall_details=True)
            attached = None
        if (fence() != generation or process_quiescent() is not True
                or _local(workspace) != before
                or _credential(repository, provider, policy) != encrypted):
            raise ValueError("mixed append inventory changed during GET")
        state, phase, _ = before
        state_sha = _sha(state)
        digest = _sha(json.dumps({
            "provider": provider, "stateSha256": state_sha,
            "phase": phase, "inventory": inventory,
            "linodeAttachments": attached, "selectorExists": selector_exists,
            "selectorCount": selector_count, "selectorAttachments": selector_attached,
            "fence": generation,
        }, sort_keys=True, separators=(",", ":")).encode())
        if provider == "digitalocean" and selector_count < len(selector_attached):
            raise MixedPartialApplyInventorySettling("selector count is settling")
        return MixedPartialApplyInventorySnapshot(
            provider, state, state_sha, phase, inventory, attached,
            selector_exists, selector_count, selector_attached, digest)
    except MixedPartialApplyInventorySettling:
        raise
    except Exception:
        raise MixedAppendFirstPoststateAttention(
            "mixed append first provider inventory requires review") from None


def observe_first_mixed_append_poststate(
    *, intent, predecessor_state: bytes, reviewed_show_json: bytes,
    journal: FirstResultJournal,
    snapshot_reader: Callable[[], MixedPartialApplyInventorySnapshot],
    fence: Callable[[], str], process_quiescent: Callable[[dict], bool],
    max_attempts: int = 60,
    poll_interval_seconds: float = 5.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> FirstPoststateProof:
    """Observe attachment or exact owned DO completion settling under the claim.

    Completion projections only classify a wait: the returned proof always
    comes from a later unmodified snapshot passing the strict pure proof.
    Any other failure is immediate attention; no provider write occurs.
    """
    if (type(max_attempts) is not int or not 1 <= max_attempts <= 60
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0 <= poll_interval_seconds <= 10
            or type(journal) is not FirstResultJournal
            or journal.provider != ("digitalocean" if type(intent) is MixedDigitalOceanOnLinodeAppendIntent
                                    else "linode" if type(intent) is MixedLinodeOnDigitalOceanAppendIntent
                                    else None)
            or not callable(snapshot_reader) or not callable(fence)
            or not callable(process_quiescent)):
        raise MixedAppendFirstPoststateAttention("mixed append observation bounds differ")
    pending_sha = None
    generation = fence()
    for attempt in range(max_attempts):
        if fence() != generation:
            break
        if process_quiescent(journal.started_identity) is not True:
            break
        try:
            snapshot = snapshot_reader()
        except MixedPartialApplyInventorySettling:
            if attempt + 1 == max_attempts:
                break
            if fence() != generation:
                break
            sleeper(poll_interval_seconds)
            continue
        if pending_sha is not None and snapshot.state_sha256 != pending_sha:
            break
        try:
            result = prove_first_mixed_append_poststate(
                intent=intent, predecessor_state=predecessor_state,
                reviewed_show_json=reviewed_show_json, snapshot=snapshot,
                command_result_proved=True,
                process_quiescent=process_quiescent(journal.started_identity))
            if fence() != generation:
                break
            return result
        except MixedAppendFirstPoststateAttention:
            provider = snapshot.provider
            raw = snapshot.state_json
            try:
                rows = _state_resources(json.loads(raw))
                prefix = "linode_instance." if provider == "linode" else "digitalocean_droplet."
                node_ids = tuple(sorted(str(value["id"]) for address, value in rows.items()
                                        if address.startswith(prefix)))
                if provider == "digitalocean":
                    firewall = rows["digitalocean_firewall.firewall"]
                    selected = [row for row in snapshot.inventory
                                if row.get("kind") == "firewall"
                                and str(row.get("id")) == str(firewall["id"])]
                    observed = selected[0].get("firewall") if len(selected) == 1 else None
                    if type(observed) is dict and observed.get("status") == "waiting":
                        pending = observed.get("pending_changes")
                        if (type(pending) is not list
                                or any(type(row) is not dict
                                       or set(row) != {"droplet_id", "removing", "status"}
                                       or type(row["droplet_id"]) is not int
                                       or str(row["droplet_id"]) not in node_ids
                                       or row["removing"] is not False or row["status"] != "waiting"
                                       for row in pending)
                                or len({row["droplet_id"] for row in pending}) != len(pending)):
                            raise ValueError("owned firewall completion is not settling")
                        replacement = replace(snapshot, inventory=tuple(
                            {**row, "firewall": {**observed, "status": "succeeded", "pending_changes": []}}
                            if row is selected[0] else row for row in snapshot.inventory))
                        # Reuse the exact completion guard, including full live
                        # rules/identity, even before re-running the full proof.
                        change = next((row["change"] for row in json.loads(reviewed_show_json)["resource_changes"]
                                       if row["address"] == "digitalocean_firewall.firewall"), {})
                        _completed_firewall_poststate(firewall, change["after"],
                            change.get("after_unknown", {}), rows, replacement)
                        prove_first_mixed_append_poststate(
                            intent=intent, predecessor_state=predecessor_state,
                            reviewed_show_json=reviewed_show_json, snapshot=replacement,
                            command_result_proved=True,
                            process_quiescent=process_quiescent(journal.started_identity))
                        pending_sha = snapshot.state_sha256
                        if attempt + 1 < max_attempts:
                            if fence() != generation:
                                break
                            sleeper(poll_interval_seconds)
                            continue
                        break
                replacement = (replace(snapshot, linode_firewall_attached_node_ids=node_ids)
                               if provider == "linode" else replace(
                                   snapshot, selector_attached_node_ids=node_ids,
                                   selector_resources_count=len(node_ids)))
                # Only the attachment/count fields may be incomplete. All
                # state, reviewed-plan, and full-inventory checks must pass.
                prove_first_mixed_append_poststate(
                    intent=intent, predecessor_state=predecessor_state,
                    reviewed_show_json=reviewed_show_json, snapshot=replacement,
                    command_result_proved=True,
                    process_quiescent=process_quiescent(journal.started_identity))
                if ((provider == "linode"
                     and set(snapshot.linode_firewall_attached_node_ids) < set(node_ids))
                    or (provider == "digitalocean"
                        and set(snapshot.selector_attached_node_ids) == set(node_ids)
                        and snapshot.selector_resources_count < len(node_ids))):
                    pending_sha = snapshot.state_sha256
                    if attempt + 1 < max_attempts:
                        if fence() != generation:
                            break
                        sleeper(poll_interval_seconds)
                        continue
            except (AttributeError, KeyError, TypeError, ValueError,
                    MixedAppendFirstPoststateAttention):
                pass
            break
    raise MixedAppendFirstPoststateAttention(
        "mixed append first provider poststate or inventory did not settle")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _inventory(
    provider: str, prior: Mapping[str, dict], after: Mapping[str, dict],
    new_address: str, snapshot: MixedPartialApplyInventorySnapshot,
) -> tuple[str, ...]:
    """Require complete GET inventory, including absence of shadow identities."""
    node_kind = "linode_instance" if provider == "linode" else "digitalocean_droplet"
    node_addresses = {address for address in after if address.startswith(node_kind + ".")}
    firewall_address = "linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall"
    owned = node_addresses | {firewall_address}
    if provider == "digitalocean":
        owned.add("digitalocean_ssh_key.key")
    expected = {}
    name_key = "label" if provider == "linode" else "name"
    for address in owned:
        attributes = after[address]
        kind = "node" if address in node_addresses else ("ssh_key" if address.endswith("ssh_key.key") else "firewall")
        identity = (kind, str(attributes["id"]))
        if identity in expected:
            raise ValueError("provider IDs overlap within resource kind")
        expected[identity] = (kind, attributes[name_key], attributes.get("tags", []),
                              attributes.get("public_key") if kind == "ssh_key" else None)
    seen: set[tuple[str, str]] = set()
    matched: set[tuple[str, str]] = set()
    reviewed_names = {entry[1].casefold() for entry in expected.values()}
    reviewed_tags = {tag.casefold() for _, _, tags, _ in expected.values() for tag in tags}
    reviewed_key = after.get("digitalocean_ssh_key.key", {}).get("public_key")
    for row in snapshot.inventory:
        if (not isinstance(row, Mapping) or row.get("kind") not in {"node", "firewall", "ssh_key"}
                or type(row.get("id")) not in {str, int}
                or type(row.get("name")) is not str or type(row.get("tags")) is not list
                or any(type(tag) is not str for tag in row["tags"])):
            raise ValueError("provider inventory row incomplete")
        identity_key = (row["kind"], str(row["id"]))
        if identity_key in seen:
            raise ValueError("provider inventory ID repeated")
        seen.add(identity_key)
        if identity_key in expected:
            kind, name, tags, key = expected[identity_key]
            if ((row["kind"], row["name"], row["tags"]) != (kind, name, tags)
                    or kind == "ssh_key" and row.get("public_key") != key):
                raise ValueError("owned provider identity changed")
            matched.add(identity_key)
        elif (row["kind"] != "ssh_key" and (
                row["name"].casefold() in reviewed_names
                or any(tag.casefold() in reviewed_tags for tag in row["tags"]))
              or row["kind"] == "ssh_key" and reviewed_key is not None
              and row.get("public_key") == reviewed_key):
            raise ValueError("untracked provider resource uses reviewed identity")
    if matched != set(expected):
        raise ValueError("owned provider resource absent")
    node_ids = tuple(sorted(str(after[address]["id"]) for address in node_addresses))
    if provider == "linode":
        attached = snapshot.linode_firewall_attached_node_ids
        if (type(attached) is not tuple or len(attached) != len(set(attached))
                or set(attached) != set(node_ids)):
            raise ValueError("Linode firewall attachment incomplete")
    else:
        attached = snapshot.selector_attached_node_ids
        if (snapshot.selector_tag_exists is not True or type(attached) is not tuple
                or len(attached) != len(set(attached))
                or set(attached) != set(node_ids)
                or snapshot.selector_resources_count != len(node_ids)):
            raise ValueError("DigitalOcean selector membership incomplete")
    return node_ids


def prove_first_mixed_append_poststate(
    *, intent: MixedDigitalOceanOnLinodeAppendIntent | MixedLinodeOnDigitalOceanAppendIntent,
    predecessor_state: bytes, reviewed_show_json: bytes,
    snapshot: MixedPartialApplyInventorySnapshot,
    command_result_proved: bool, process_quiescent: bool,
) -> FirstPoststateProof:
    """Prove exactly one reviewed edge and unchanged original resources.

    The reviewed show bytes must already be bound to the saved binary receipt.
    Its known after-values and unknown mask also bind the shared firewall
    delta; computed IDs/IPs are checked separately against fresh inventory.
    """
    try:
        provider = ("digitalocean" if isinstance(intent, MixedDigitalOceanOnLinodeAppendIntent)
                    else "linode" if isinstance(intent, MixedLinodeOnDigitalOceanAppendIntent)
                    else None)
        shared = _SHARED_DO if provider == "digitalocean" else _SHARED_LINODE
        predecessor_sha = (intent.digitalocean_state_sha256 if provider == "digitalocean"
                           else intent.linode_state_sha256)
        if (provider is None or snapshot.provider != provider
                or command_result_proved is not True or process_quiescent is not True
                or type(predecessor_state) is not bytes
                or type(reviewed_show_json) is not bytes
                or type(snapshot.state_json) is not bytes
                or snapshot.phase != "applied"
                or _sha(predecessor_state) != predecessor_sha
                or snapshot.state_sha256 != _sha(snapshot.state_json)):
            raise ValueError("first Apply result or state source unproved")
        retained_ids = dict(intent.retained_digitalocean_ids if provider == "digitalocean"
                            else intent.retained_linode_ids)
        prior_state = json.loads(predecessor_state)
        prior = _read_state(predecessor_state, predecessor_sha, retained_ids,
                            set(retained_ids), {"lineage": prior_state["lineage"],
                                                 "serial": prior_state["serial"]})
        post = json.loads(snapshot.state_json)
        UUID(post["lineage"])
        if (post.get("version") != 4 or post.get("terraform_version") != "1.15.5"
                or post["lineage"] != prior_state["lineage"]
                or type(post.get("serial")) is not int
                or post["serial"] <= prior_state["serial"]):
            raise ValueError("poststate lineage or serial differs")
        after = _state_resources(post)
        expected = (set(prior) - {"local_file.ansible_inventory[0]",
                                   "local_file.ssh_stanza[0]"}) | {intent.new_edge_address}
        if set(after) != expected or not shared <= set(prior):
            raise ValueError("poststate address set differs")
        for address, attributes in prior.items():
            if address in shared and address not in {"linode_firewall.firewall",
                                                      "digitalocean_firewall.firewall"}:
                if address in after and after[address] != attributes:
                    raise ValueError("retained shared identity changed")
            elif address not in shared and after[address] != attributes:
                raise ValueError("retained node changed")
        if (any(str(after[address].get("id")) != retained_ids[address]
                for address in retained_ids if address in after)
                or str(after["linode_firewall.firewall" if provider == "linode"
                             else "digitalocean_firewall.firewall"].get("id"))
                   != retained_ids["linode_firewall.firewall" if provider == "linode"
                                   else "digitalocean_firewall.firewall"]):
            raise ValueError("retained provider ID changed")
        edge = after[intent.new_edge_address]
        name_key = "label" if provider == "linode" else "name"
        type_key = "type" if provider == "linode" else "size"
        expected_type = intent.new_edge.node_type if provider == "linode" else intent.new_edge.size
        expected_tag = intent.new_edge.tag if provider == "linode" else intent.new_edge.firewall_selector_tag
        ip = edge.get("ipv4" if provider == "linode" else "ipv4_address")
        if provider == "linode":
            ip = ip[0] if type(ip) is list and len(ip) == 1 else None
        expected_name = intent.new_edge.label if provider == "linode" else intent.new_edge.name
        if (edge.get(name_key) != expected_name
                or edge.get("image") != intent.new_edge.image
                or edge.get("region") != intent.new_edge.region
                or edge.get(type_key) != expected_type
                or edge.get("tags") != [expected_tag]
                or type(edge.get("id")) not in {int, str}
                or not str(edge["id"]) or str(edge["id"]) in {
                    retained_ids[address] for address in prior
                    if address.startswith("linode_instance." if provider == "linode"
                                          else "digitalocean_droplet.")}
                or type(ip) is not str or not ipaddress.IPv4Address(ip).is_global):
            raise ValueError("new edge identity differs")
        plan = json.loads(reviewed_show_json)
        if (plan.get("terraform_version") != "1.15.5"
                or type(plan.get("resource_changes")) is not list):
            raise ValueError("reviewed plan invalid")
        changes = {row["address"]: row["change"] for row in plan["resource_changes"]}
        if len(changes) != len(plan["resource_changes"]) or set(changes) != set(prior) | {intent.new_edge_address}:
            raise ValueError("reviewed plan address set differs")
        firewall_address = "linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall"
        planned_prior = prior
        if provider == "digitalocean":
            from app.services.provider_keyed_mixed_append_plan_gate import _require_completed_firewall_refresh
            planned_prior = _require_completed_firewall_refresh(plan.get("resource_drift"), prior,
                {address for address in prior if address.startswith("digitalocean_droplet.")})
        else:
            from app.services.provider_keyed_mixed_append_linode_plan_preflight import _require_linode_firewall_updated_refresh
            planned_prior = _require_linode_firewall_updated_refresh(plan.get("resource_drift"), prior)
        for address, actual in after.items():
            change = changes[address]
            if address == intent.new_edge_address:
                if change.get("actions") != ["create"]:
                    raise ValueError("new edge action differs")
            elif address == firewall_address:
                if change.get("actions") != ["update"] or change.get("before") != planned_prior[address]:
                    raise ValueError("firewall action differs")
            elif change.get("actions") != ["no-op"] or change.get("before") != prior[address]:
                raise ValueError("retained action differs")
            planned_after = change.get("after")
            unknown = change.get("after_unknown", {})
            if (provider == "digitalocean" and address == firewall_address
                    and type(planned_after) is dict
                    and any(actual.get(key) != planned_after.get(key)
                            for key in ("status", "pending_changes"))):
                actual = _completed_firewall_poststate(actual, planned_after, unknown,
                                                       after, snapshot)
            if (provider == "linode" and address == intent.new_edge_address
                    and type(planned_after) is dict and "private_ip" in planned_after
                    and planned_after["private_ip"] is None
                    and actual.get("private_ip") is False
                    and type(unknown) is dict and unknown.get("private_ip", {}) == {}):
                # Linode v4.7.0 instance/schema_resource.go defines private_ip as
                # Optional TypeBool without a default: an omitted create input
                # is null in the plan and false in the provider's created state.
                # Project only this known representation; retain the raw evidence.
                planned_after = {**planned_after, "private_ip": False}
            _match_planned(actual, planned_after, unknown)
        for address in set(prior) - set(after):
            if changes[address].get("actions") != ["delete"] or changes[address].get("before") != prior[address]:
                raise ValueError("local artifact deletion differs")
        _firewall_membership(provider, prior[firewall_address], after[firewall_address],
                             intent, prior, after)
        _inventory(provider, prior, after, intent.new_edge_address, snapshot)
        ids = tuple(sorted((address, str(attributes["id"])) for address, attributes in after.items()
                           if address not in {"local_file.ansible_inventory[0]",
                                              "local_file.ssh_stanza[0]"}))
        return FirstPoststateProof(
            provider, snapshot.state_sha256, post["lineage"], post["serial"], ids,
            intent.new_edge_address, str(edge["id"]), ip,
            _sha(json.dumps(snapshot.inventory, sort_keys=True, separators=(",", ":")).encode()),
            snapshot.observation_sha256, snapshot.selector_resources_count,
            (snapshot.linode_firewall_attached_node_ids if provider == "linode"
             else snapshot.selector_attached_node_ids),
        )
    except Exception:
        raise MixedAppendFirstPoststateAttention(
            "mixed append first provider requires exact poststate and owned inventory review") from None


def _match_planned(actual: object, planned: object, unknown: object) -> None:
    """Compare known Terraform after-values; unknowns are separately proved."""
    if unknown is True:
        return
    if isinstance(planned, dict):
        allowed_extra = set(unknown) if type(unknown) is dict else set()
        if (type(actual) is not dict or not set(planned) <= set(actual)
                or set(actual) - set(planned) - allowed_extra):
            raise ValueError("planned object differs")
        for key, value in planned.items():
            _match_planned(actual[key], value,
                           unknown.get(key, {}) if type(unknown) is dict else {})
    elif isinstance(planned, list):
        if type(actual) is not list or len(actual) != len(planned):
            raise ValueError("planned list differs")
        for index, value in enumerate(planned):
            _match_planned(actual[index], value,
                           unknown[index] if type(unknown) is list and index < len(unknown) else {})
    elif actual != planned:
        raise ValueError("known planned value differs")


def _completed_firewall_poststate(actual, planned, unknown, resources, snapshot):
    """Project stale Apply completion metadata only with a complete fresh GET."""
    from app.services.provider_keyed_channel_provider_proof import _do_rules
    from app.services.provider_keyed_digitalocean_attachment import _normalize_rules
    nodes = {int(value["id"]) for address, value in resources.items()
             if address.startswith("digitalocean_droplet.")}
    pending = actual.get("pending_changes")
    if (actual.get("status") != "waiting" or type(pending) is not list
            or len(pending) != len(nodes)
            or any(type(row) is not dict or set(row) != {"droplet_id", "removing", "status"}
                   or type(row["droplet_id"]) is not int or row["removing"] is not False
                   or row["status"] != "waiting" for row in pending)
            or {row["droplet_id"] for row in pending} != nodes
            or planned.get("status") != "succeeded" or planned.get("pending_changes") != []
            or type(unknown) is not dict
            or unknown.get("status", {}) != {}
            or unknown.get("pending_changes", {}) not in ({}, [])
            or actual.get("droplet_ids") != []
            or type(actual.get("tags")) is not list or len(actual["tags"]) != 1):
        raise ValueError("firewall Apply completion metadata differs")
    rows = [row for row in snapshot.inventory if row.get("kind") == "firewall"
            and str(row.get("id")) == str(actual["id"])]
    observed = rows[0].get("firewall") if len(rows) == 1 else None
    if (type(observed) is not dict or str(observed.get("id")) != str(actual["id"])
            or observed.get("name") != actual["name"]
            or observed.get("tags") != actual["tags"]
            or observed.get("droplet_ids") != []
            or observed.get("status") != "succeeded" or observed.get("pending_changes") != []
            or _normalize_rules(observed.get("inbound_rules"), "sources")
               != _do_rules(actual["inbound_rule"], "sources")
            or _normalize_rules(observed.get("outbound_rules"), "destinations")
               != _do_rules(actual["outbound_rule"], "destinations")):
        raise ValueError("fresh firewall completion or rules differ")
    # All other known values still pass through the unchanged exact matcher;
    # _inventory separately requires the full selector membership and count.
    return {**actual, "status": "succeeded", "pending_changes": []}


def _firewall_membership(provider: str, before: dict, after: dict, intent,
                         prior: Mapping[str, dict], current: Mapping[str, dict]) -> None:
    old_nodes = {address for address in prior if address.startswith(
        "linode_instance." if provider == "linode" else "digitalocean_droplet.")}
    new_nodes = old_nodes | {intent.new_edge_address}
    if provider == "linode":
        if (sorted(after.get("linodes", [])) != sorted(int(current[address]["id"]) for address in new_nodes)
                or after.get("label") != before.get("label")
                or after.get("tags") != before.get("tags")):
            raise ValueError("Linode firewall membership differs")
        inbound = after.get("inbound")
        if (type(inbound) is not list or len(inbound) != 10
                or inbound[3].get("ipv4") != list(intent.trusted_ssh_cidrs)
                or any(set(row.get("ipv4", [])) != {
                    f'{current[address]["ipv4"][0]}/32' for address in new_nodes}
                    for row in inbound[4:7])):
            raise ValueError("Linode firewall rules differ")
    else:
        if (after.get("name") != before.get("name")
                or after.get("tags") != before.get("tags")
                or after.get("droplet_ids") not in (None, [])):
            raise ValueError("DigitalOcean firewall identity differs")
        inbound = after.get("inbound_rule")
        peers = {f'{current[address]["ipv4_address"]}/32' for address in new_nodes}
        if (type(inbound) is not list or len(inbound) < 4
                or any(set(row.get("source_addresses", [])) != peers for row in inbound[:3])
                or len([row for row in inbound if row.get("protocol") == "tcp"
                        and row.get("port_range") == "22"
                        and set(row.get("source_addresses", [])) == set(intent.trusted_ssh_cidrs)]) != 1):
            raise ValueError("DigitalOcean firewall rules differ")
