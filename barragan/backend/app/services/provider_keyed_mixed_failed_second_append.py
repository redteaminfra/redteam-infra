# Copyright (c) 2026, Oracle and/or its affiliates.
"""Cleanup-only proof for a terminal first append and rejected second Apply.

The historical four-host publication stays immutable. Current five-node policy
and identity are separate cleanup evidence, never a publication or replay grant.
"""
from dataclasses import asdict, replace
from datetime import datetime, timezone
import copy
import json
import re

from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_id
from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_id
from app.services.provider_keyed_mixed_append_first_proof_job import _load_approved_first_source, _journal
from app.services.provider_keyed_mixed_append_second_apply_binding import _approved_second
from app.services.provider_keyed_mixed_append_first_poststate import prove_first_mixed_append_poststate
from app.services.provider_keyed_mixed_append_pair_plan_worker import _read, _sha
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_partial_apply_source import _state, _inventory, ProviderApplyClassification
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_channel_provider_proof import require_current_keyed_firewall
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.job_repository import job_event_digest


def second_failure_present(parent, jobs):
    return jobs.get(second_id(parent.id)) is not None


def _expired_claim(row, *, required):
    keys = {"claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt"}
    present = keys & set(row.input)
    if not present and not required:
        return
    if present != keys or type(row.input["claimOwner"]) is not str or not row.input["claimOwner"]:
        raise ValueError("failed second worker claim is incomplete")
    if type(row.input["claimToken"]) is not str or re.fullmatch(r"[0-9a-f]{32}", row.input["claimToken"]) is None:
        raise ValueError("failed second worker token differs")
    times = [datetime.fromisoformat(row.input[key]) for key in ("claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt")]
    if any(at.tzinfo is None for at in times) or not times[0] <= times[1] <= times[2] <= datetime.now(timezone.utc):
        raise ValueError("failed second worker claim is active or invalid")


def prove_second_failure_journals(parent, jobs, *, release_check=require_devtest_terraform_release,
                                  process_quiescent=_process_quiescent):
    from app.services.provider_keyed_mixed_failed_append_teardown import failure_journal
    if tuple(parent.input.get("providerOrder", ())) != ("linode", "digitalocean"):
        raise ValueError("failed second cleanup requires the reviewed Linode-first boundary")
    _expired_claim(parent, required=False)
    second = jobs.get(second_id(parent.id))
    _expired_claim(second, required=True)
    if re.fullmatch(r"mixed-append-second-[0-9a-f]{32}", second.input["claimOwner"]) is None:
        raise ValueError("failed second worker owner differs")
    identity = failure_journal(parent, second, process_quiescent=process_quiescent, second=True)
    source = _load_approved_first_source(parent, jobs, release_check)
    first = jobs.get(first_id(parent.id))
    _expired_claim(first, required=False)
    journal, stage = _journal(parent, first, source)
    started = journal.started_identity
    if stage != "terminal" or process_quiescent(started["bootId"], started["pid"], started["pgid"], started["startTicks"]) is not True:
        raise ValueError("failed second first-provider completion is unproved")
    return source, _approved_second(parent, jobs, release_check), identity


def _project_second_checks(before, after, shown):
    """Validate only the reviewed nine-row incomplete firewall-check boundary.

    Callers separately authenticate the complete saved plan/HCL and prove the
    stopped command and fresh retained provider policy. This comparison copy
    never turns the original unknown result into a successful check receipt.
    """
    from app.services.provider_keyed_mixed_failed_append_teardown import _exact_json
    variables = ("trusted_ssh_cidrs", "middle_count", "external_middle_nodes", "edge_groups",
                 "firewall_selector_tag", "edge_count_per_region", "middles")
    identities = [("var", "var." + name) for name in variables] + [
        ("output", "output.public-key"), ("resource", "digitalocean_firewall.firewall")]
    firewall = identities[-1]

    def state_rows(rows, *, current):
        if type(rows) is not list or len(rows) != len(identities):
            raise ValueError("failed second check identities differ")
        indexed = {}
        for row in rows:
            if type(row) is not dict:
                raise ValueError("failed second check row differs")
            identity = (row.get("object_kind"), row.get("config_addr"))
            if identity not in identities or identity in indexed:
                raise ValueError("failed second check identity is extra or duplicated")
            status = "unknown" if current and identity == firewall and row.get("status") == "unknown" else "pass"
            expected = {"object_kind": identity[0], "config_addr": identity[1], "status": status,
                        "objects": [{"object_addr": identity[1], "status": status}]}
            if _exact_json(row) != _exact_json(expected):
                raise ValueError("failed second check status, fields or objects differ")
            indexed[identity] = row
        return indexed

    state_rows(before, current=False)
    state_rows(after, current=True)
    checks = json.loads(shown).get("checks")
    if type(checks) is not list or len(checks) != len(identities):
        raise ValueError("failed second saved plan checks differ")
    expected_plan = {}
    for kind, address in identities:
        name = address.split(".", 1)[1]
        metadata = {"kind": "output_value" if kind == "output" else kind,
                    "name": name, "to_display": address}
        if kind == "resource":
            metadata.update(mode="managed", name="firewall", type="digitalocean_firewall")
        expected = {"address": metadata, "status": "pass", "instances": [
            {"address": {"to_display": address}, "status": "pass"}]}
        expected_plan[address] = _exact_json(expected)
    seen = set()
    for row in checks:
        metadata = row.get("address") if type(row) is dict else None
        address = metadata.get("to_display") if type(metadata) is dict else None
        if type(address) is not str or address in seen or expected_plan.get(address) != _exact_json(row):
            raise ValueError("failed second saved plan check identity, status or fields differ")
        seen.add(address)
    return copy.deepcopy(before)


def second_state_projection(predecessor, current, shown):
    """Only reviewed local deletion and the exact retained DO settling tuple."""
    from app.services.provider_keyed_mixed_failed_append_teardown import local_delete_projection, _exact_json
    before, after = json.loads(predecessor), json.loads(current)
    _exact_json(before)
    _exact_json(after)
    if current == predecessor:
        return
    projected = copy.deepcopy(after)
    def firewall(state):
        rows = [row for row in state["resources"] if row.get("mode") == "managed"
                and row.get("type") == "digitalocean_firewall" and row.get("name") == "firewall"]
        if len(rows) != 1 or len(rows[0].get("instances", [])) != 1:
            raise ValueError("failed second retained firewall identity differs")
        return rows[0]["instances"][0]["attributes"]
    old, new, adjusted = firewall(before), firewall(after), firewall(projected)
    settling = {"droplet_ids", "pending_changes", "status"}
    if any(old.get(key) != new.get(key) for key in settling):
        nodes = {str(attributes["id"]) for address, attributes in _state_resources(before).items()
                 if address.startswith("digitalocean_droplet.")}
        pending = old.get("pending_changes")
        if (len(nodes) != 2 or type(pending) is not list or len(pending) != 2
                or {str(row.get("droplet_id")) for row in pending if type(row) is dict} != nodes
                or any(set(row) != {"droplet_id", "removing", "status"}
                       or type(row["droplet_id"]) is not int or row["droplet_id"] <= 0
                       or row["removing"] is not False or row["status"] != "waiting" for row in pending)
                or old.get("droplet_ids") is not None or old.get("status") != "waiting"
                or new.get("droplet_ids") != [] or new.get("pending_changes") != [] or new.get("status") != "succeeded"
                or set(old) != set(new) or not settling <= set(old)):
            raise ValueError("failed second firewall transition is not the exact retained settling state")
        adjusted.update({key: old[key] for key in settling})
    if _exact_json(before.get("check_results")) != _exact_json(after.get("check_results")):
        projected["check_results"] = _project_second_checks(
            before.get("check_results"), after.get("check_results"), shown)
    if (set(before) == set(projected) and type(projected.get("serial")) is int
            and projected["serial"] > before["serial"]
            and _exact_json(projected) == _exact_json({**before, "serial": projected["serial"]})):
        return
    local_delete_projection(predecessor, json.dumps(projected).encode(), shown)


def current_policies(initial, first_source):
    policies = copy.deepcopy(validate_mixed_initial_apply_seal(initial)["reviewedPolicy"])
    intent = first_source.intent
    if intent.new_edge_address in policies["linode"]["nodes"]:
        raise ValueError("failed second new edge overlaps retained policy")
    policies["linode"]["nodes"][intent.new_edge_address] = asdict(intent.new_edge)
    policies["linode"]["nonsecret_varfile"] = intent.nonsecret_varfile
    policies["linode"]["topology"] = json.loads(_read(first_source.workspace.path / ".barragan-topology.json", private=False))
    return json.loads(json.dumps(policies))


def fresh_second_failure_observation(initial, append, provider, workspace, *, fence, jobs, snapshot_reader,
                                      release_check=require_devtest_terraform_release):
    first_source, second_source, identity = prove_second_failure_journals(append, jobs, release_check=release_check)
    quiet = lambda: _process_quiescent(identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"])
    snapshot = snapshot_reader(initial, provider, workspace, fence=fence, process_quiescent=quiet)
    if (snapshot.provider != provider or type(snapshot.state_json) is not bytes
            or snapshot.state_sha256 != _sha(snapshot.state_json) or type(snapshot.inventory) is not tuple):
        raise ValueError("failed second provider snapshot differs")
    if provider == "linode":
        proof = prove_first_mixed_append_poststate(intent=first_source.intent,
            predecessor_state=first_source.predecessor_state, reviewed_show_json=first_source.reviewed_show_json,
            snapshot=snapshot, command_result_proved=True, process_quiescent=True)
        saved = jobs.get(first_id(append.id)).events[8].data
        if (proof.state_sha256 != saved["stateSha256"] or proof.lineage != saved["lineage"]
                or proof.serial != saved["serial"] or [list(row) for row in proof.resource_ids] != saved["resourceIds"]
                or proof.new_edge_provider_id != saved["newEdgeProviderId"] or proof.new_edge_public_ip != saved["newEdgePublicIp"]
                or list(proof.attached_node_ids) != saved["attachedNodeIds"]):
            raise ValueError("failed second first poststate changed")
        if snapshot.phase != "applied":
            raise ValueError("failed second first phase changed")
    else:
        if snapshot.phase != "apply_started":
            raise ValueError("failed second phase changed")
        second_state_projection(second_source.predecessor_state, snapshot.state_json, second_source.reviewed_show_json)
    policy = current_policies(initial, first_source)[provider]
    state, actual, cloud = _state(provider, policy, snapshot.state_json)
    _inventory(provider, policy, actual, cloud, snapshot.inventory)
    require_current_keyed_firewall(provider, policy, actual, fence=fence)
    nodes = {cloud[address] for address in policy["nodes"]}
    attached = snapshot.linode_firewall_attached_node_ids if provider == "linode" else snapshot.selector_attached_node_ids
    if (type(attached) is not tuple or len(attached) != len(nodes) or set(attached) != nodes
            or any(type(identifier) is not str for identifier in attached)
            or provider == "linode" and len(nodes) != 3
            or provider == "digitalocean" and (len(nodes) != 2 or snapshot.selector_tag_exists is not True
                or type(snapshot.selector_resources_count) is not int or snapshot.selector_resources_count != 2)
            or _read(workspace.state_path, private=False) != snapshot.state_json or not quiet()):
        raise ValueError("failed second provider identities or attachments changed")
    return ProviderHostObservation(ProviderApplyClassification(provider, "full", _sha(snapshot.state_json),
        state["lineage"], state["serial"], tuple(sorted(cloud.items()))), snapshot.state_json)


def second_failure_history(review, *, jobs, workspaces, initial):
    from app.services.provider_keyed_mixed_failed_append_teardown import immutable_failure_evidence, _exact_json
    saved = review.failed_append_recovery
    append = jobs.get(saved["appendParentId"])
    first, _, _ = prove_second_failure_journals(append, jobs)
    if (set(saved) != {"kind", "appendParentId", "failedProvider", "source", "evidence", "currentPolicies", "currentResourceIds", "retiredEndpoints"}
            or saved["failedProvider"] != "digitalocean"
            or saved["source"] != json.loads(json.dumps(asdict(review.source)))
            or _exact_json(saved["currentPolicies"]) != _exact_json(current_policies(initial, first))
            or saved["evidence"] != immutable_failure_evidence(append, source=review.source, initial=initial, workspaces=workspaces, jobs=jobs)):
        raise ValueError("failed second saved history differs")
    proof = jobs.get(first_id(append.id)).events[8].data
    expected = {row.provider: dict(row.resource_ids) for row in review.source.provider_states}
    expected["linode"] = dict(proof["resourceIds"])
    # Initial classification resource_ids include only provider-owned cloud resources.
    expected["linode"] = {k: v for k, v in expected["linode"].items() if k.startswith("linode_instance.") or k == "linode_firewall.firewall"}
    if (saved["currentResourceIds"] != expected
            or saved["retiredEndpoints"] != [{"publicIp": proof["newEdgePublicIp"], "provider": "linode", "providerInstanceId": proof["newEdgeProviderId"]}]):
        raise ValueError("failed second saved current identities differ")
    return saved["evidence"]


def build_second_failure_recovery(review, initial, append, *, observations, workspaces, jobs):
    from app.services.provider_keyed_mixed_failed_append_teardown import immutable_failure_evidence
    first, second, _ = prove_second_failure_journals(append, jobs)
    policies = current_policies(initial, first)
    proof = jobs.get(first_id(append.id)).events[8].data
    expected = {state.provider: dict(state.resource_ids) for state in review.source.provider_states}
    expected["linode"] = {address: identifier for address, identifier in proof["resourceIds"]
                          if address.startswith("linode_instance.") or address == "linode_firewall.firewall"}
    scopes = []
    for provider, old_scope in zip(review.source.ordered_providers, review.provider_scopes, strict=True):
        observed = observations[provider]
        state, actual, cloud = _state(provider, policies[provider], observed.state_json)
        if (dict(observed.classification.resource_ids) != cloud or cloud != expected[provider]
                or _sha(observed.state_json) != observed.classification.state_sha256
                or json.loads(_read(workspaces[provider].path / ".barragan-apply-phase.json", private=False)) != {
                    "schema": "provider-keyed-v2", "phase": "applied" if provider == "linode" else "apply_started"}):
            raise ValueError("failed second current cleanup identities differ")
        if provider == "digitalocean":
            second_state_projection(second.predecessor_state, observed.state_json, second.reviewed_show_json)
        elif (_sha(observed.state_json) != proof["stateSha256"] or state["lineage"] != proof["lineage"]
                or state["serial"] != proof["serial"]):
            raise ValueError("failed second completed first state differs")
        old_kinds = {row["address"]: row["kind"] for row in old_scope["resources"]}
        old_kinds[first.intent.new_edge_address] = "instance"
        if not set(actual) <= set(old_kinds):
            raise ValueError("failed second cleanup contains unexplained resource address")
        scopes.append({**old_scope, "stateSha256": _sha(observed.state_json), "lineage": state["lineage"],
                       "serial": state["serial"], "resources": [
                           {"address": address, "id": str(actual[address]["id"]), "kind": old_kinds[address]}
                           for address in sorted(actual)]})
    recovery = {"kind": "failed-second-v1", "appendParentId": append.id, "failedProvider": "digitalocean",
                "source": json.loads(json.dumps(asdict(review.source))),
                "currentPolicies": policies, "currentResourceIds": expected,
                "retiredEndpoints": [{"publicIp": proof["newEdgePublicIp"], "provider": "linode", "providerInstanceId": proof["newEdgeProviderId"]}],
                "evidence": immutable_failure_evidence(append, source=review.source, initial=initial, workspaces=workspaces, jobs=jobs)}
    return scopes, recovery


def failed_second_scope_resource_count(review):
    """Exact cloud IDs plus retained, state-authenticated noncloud exceptions."""
    saved = review.failed_append_recovery
    if type(saved) is not dict or saved.get("kind") != "failed-second-v1":
        raise ValueError("failed second cleanup variant absent")
    expected_count = 0
    shared = {"linode": {"random_password.root_password": "random_password"}, "digitalocean": {}}
    for scope in review.provider_scopes:
        provider = scope["provider"]
        resources = scope["resources"]
        exceptions = dict(shared[provider])
        local = {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
        present_local = {row["address"] for row in resources} & local
        if present_local:
            if provider != "digitalocean" or present_local != local:
                raise ValueError("failed second local resource membership changed")
            exceptions.update({address: "local_file" for address in local})
        cloud = saved["currentResourceIds"][provider]
        nodes = saved["currentPolicies"][provider]["nodes"]
        provider_shared = {"linode_firewall.firewall"} if provider == "linode" else {"digitalocean_firewall.firewall", "digitalocean_ssh_key.key"}
        if len(nodes) != (3 if provider == "linode" else 2) or set(cloud) != set(nodes) | provider_shared:
            raise ValueError("failed second cleanup cloud geometry differs")
        seen = set()
        for row in resources:
            if (type(row) is not dict or set(row) != {"address", "id", "kind"}
                    or type(row["address"]) is not str or not row["address"]
                    or type(row["id"]) is not str or not row["id"]):
                raise ValueError("failed second cleanup resource row differs")
            address = row["address"]
            if address in seen:
                raise ValueError("failed second cleanup repeated resource")
            seen.add(address)
            if address in cloud:
                kind = ("instance" if address.startswith("linode_instance.") else
                        "droplet" if address.startswith("digitalocean_droplet.") else
                        "firewall" if address in {"linode_firewall.firewall", "digitalocean_firewall.firewall"} else
                        "ssh_key" if address == "digitalocean_ssh_key.key" else None)
                if kind is None or str(row["id"]) != cloud[address] or row["kind"] != kind:
                    raise ValueError("failed second cleanup cloud resource changed")
            elif address not in exceptions or row["kind"] != exceptions[address]:
                raise ValueError("failed second cleanup noncloud resource changed")
        if seen != set(cloud) | set(exceptions):
            raise ValueError("failed second cleanup resource membership changed")
        expected_count += len(seen)
    return expected_count


def extend_retired_targets(targets, cleanup):
    """Exact unpublished new-edge SSH-negative target under the saved cleanup seal."""
    import ipaddress
    saved = cleanup.input.get("failedAppendRecovery")
    if saved is None or saved.get("kind") != "failed-second-v1":
        return targets
    rows = saved.get("retiredEndpoints")
    if type(rows) is not list or len(rows) != 1:
        raise ValueError("failed second retired endpoint differs")
    row = rows[0]
    if type(row) is not dict or set(row) != {"publicIp", "provider", "providerInstanceId"} or row["provider"] != "linode":
        raise ValueError("failed second retired endpoint shape differs")
    address = ipaddress.ip_address(row["publicIp"])
    cloud = saved["currentResourceIds"]["linode"]
    old = next(state["resource_ids"] for state in saved["source"]["provider_states"] if state["provider"] == "linode")
    new = {value for key, value in cloud.items() if key.startswith("linode_instance.")} - {value for key, value in old}
    if (len(new) != 1 or row["providerInstanceId"] not in new or not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global or str(address) != row["publicIp"]
            or any(item["host"] == row["publicIp"] for item in targets)):
        raise ValueError("failed second retired endpoint identity differs")
    return [*targets, {"id": f"tcp:{address}:22", "type": "tcp-forbidden", "host": str(address),
                      "port": 22, "targetGroup": "retired-sketch-public-management"}]


def stopped_second_failure_attention(parent, jobs, *, process_quiescent=_process_quiescent):
    """Cheap journal-only attention label; grants neither cleanup nor replay."""
    from app.services.provider_keyed_mixed_failed_append_teardown import failure_journal
    from app.services.provider_keyed_mixed_append_pair_apply_child import _base, ACTION
    try:
        if tuple(parent.input.get("providerOrder", ())) != ("linode", "digitalocean"):
            return False
        _expired_claim(parent, required=False)
        second = jobs.get(second_id(parent.id))
        _expired_claim(second, required=True)
        if re.fullmatch(r"mixed-append-second-[0-9a-f]{32}", second.input["claimOwner"]) is None:
            return False
        failure_journal(parent, second, second=True, process_quiescent=process_quiescent)
        first = jobs.get(first_id(parent.id))
        if (first is None or first.action != ACTION or first.status != "succeeded"
                or first.finished_at is None or first.started_at is None
                or first.target != parent.target or first.target_id != parent.target_id
                or first.target_type != "engagement" or first.requested_by != parent.requested_by
                or first.input != _base(parent) or first.artifact_refs
                or len(first.events) != 10
                or any(event.sequence != index or event.level != "info" for index,event in enumerate(first.events,1))
                or first.events[-1].message != "mixed append first provider Apply succeeded"
                or first.events[-1].data != {"proofJournalSha256":job_event_digest(first.events[:9])}
                or first.events[8].message != "mixed append first exact poststate proved"
                or type(first.events[5].data.get("returnCode")) is not int or first.events[5].data["returnCode"] != 0
                or first.events[5].data.get("stdoutTruncated") is not False
                or first.events[5].data.get("stderrTruncated") is not False):
            return False
        identity = first.events[3].data
        if (set(identity) != {"invocationId","bootId","pid","pgid","startTicks"}
                or type(identity["bootId"]) is not str or not identity["bootId"]
                or any(type(identity[key]) is not int or identity[key] <= 0 for key in ("pid","pgid","startTicks"))
                or identity["pid"] != identity["pgid"]):
            return False
        return process_quiescent(identity["bootId"],identity["pid"],identity["pgid"],identity["startTicks"]) is True
    except Exception:
        return False
