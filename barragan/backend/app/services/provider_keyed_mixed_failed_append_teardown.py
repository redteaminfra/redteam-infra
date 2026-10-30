# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded read-only teardown source for a failed first append with local deletes.

Cloud resources remain the authentic four-host initial publication. This is
not append retry authority and never executes or rewrites a command journal.
"""
from dataclasses import asdict
from types import SimpleNamespace
import hashlib
import json

from app.domain import JobEvent
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_channel_provider_proof import require_current_keyed_firewall
from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent, _firewall
from app.services.provider_keyed_mixed_append_pair_apply_child import _base, _child_id, _CLAIM_KEYS
from app.services.provider_keyed_mixed_append_pair_parent import _parent_id, _plan_child_id, _matches_request, mixed_append_approval_sha256
from app.services.provider_keyed_mixed_append_pair_plan import seal_mixed_append_pair_plan
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read, _sha, _canonical, _SUMMARY_KEYS, _journal_complete
from app.services.provider_keyed_mixed_append_pair_plan_producer import _full_gate
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification, _state, _inventory, _LOCAL
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.job_repository import job_event_digest


def failure_journal(parent, child, *, process_quiescent=_process_quiescent, second=False):
    """Recognize exactly one completed nonzero first Apply; no uncertain command."""
    if second:
        from app.services.provider_keyed_mixed_append_second_apply_child import _base as base, _child_id as child_id, ACTION
    else:
        base, child_id, ACTION = _base, _child_id, "provider_keyed_mixed_append_apply_child"
    if child is None:
        raise ValueError("failed append child is missing")
    events = child.events
    expected = ["mixed append first Apply queued", "mixed append first Apply started",
        "mixed append first Apply command intended", "mixed append first Apply command started before GO",
        "mixed append first phase apply_started", "mixed append first Apply command result fenced"]
    if second:
        expected = [name.replace("first", "second") for name in expected]
    if (parent.status != "running" or parent.action != "provider_keyed_mixed_append"
            or parent.input.get("phase") != "apply_sealed" or parent.finished_at is not None
            or child.id != child_id(parent.id) or child.action != ACTION
            or child.status != "running" or child.finished_at is not None or child.started_at is None
            or child.target != parent.target or child.target_type != "engagement"
            or child.target_id != parent.target_id or child.requested_by != parent.requested_by
            or child.artifact_refs or parent.artifact_refs
            or {k: v for k, v in child.input.items() if k not in _CLAIM_KEYS} != base(parent)
            or len(events) != 6
            or [(e.sequence, e.level, e.message) for e in events]
               != [(i + 1, "info", name) for i, name in enumerate(expected)]
            or events[0].data != {} or events[1].data != {}
            or events[4].data != {"commandStartSequence": 4}):
        raise ValueError("failed append has no exact first-command journal")
    intended, started, result = (events[i].data for i in (2, 3, 5))
    if (set(intended) != {"invocationId", "argvSha256", "planSha256", "planPath", "terraformPath", "terraformSha256"}
            or set(started) != {"invocationId", "bootId", "pid", "pgid", "startTicks"}
            or set(result) != {"invocationId", "returnCode", "stdoutBytes", "stderrBytes", "stdoutTruncated", "stderrTruncated"}
            or not isinstance(intended["invocationId"], str) or not intended["invocationId"]
            or intended["invocationId"] != started["invocationId"]
            or intended["invocationId"] != result["invocationId"]
            or type(result["returnCode"]) is not int or result["returnCode"] != 1
            or any(type(result[k]) is not int or result[k] < 0 for k in ("stdoutBytes", "stderrBytes"))
            or result["stdoutTruncated"] is not False or result["stderrTruncated"] is not False
            or type(started["bootId"]) is not str or not started["bootId"]
            or any(type(started[k]) is not int or started[k] < 1 for k in ("pid", "pgid", "startTicks"))
            or started["pgid"] != started["pid"]
            or process_quiescent(started["bootId"], started["pid"], started["pgid"], started["startTicks"]) is not True):
        raise ValueError("failed append command is not a quiescent exact failure")
    return started


def _exact_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def local_delete_projection(predecessor, current, shown):
    """Every retained resource row is byte-equivalent JSON, including secrets."""
    before, after = json.loads(predecessor), json.loads(current)
    if (type(after.get("serial")) is not int or after["serial"] <= before["serial"]
            or set(before) != set(after)):
        raise ValueError("failed append state envelope differs")
    deleted = [row for row in before["resources"] if row.get("type") == "local_file"
               and row.get("name") in {"ansible_inventory", "ssh_stanza"}]
    if (len(deleted) != 2 or any(row.get("mode") != "managed" or row.get("module")
                              or len(row.get("instances", [])) != 1
                              or row["instances"][0].get("index_key") != 0 for row in deleted)):
        raise ValueError("failed append predecessor local outputs differ")
    expected = {**before, "serial": after["serial"],
                "resources": [row for row in before["resources"] if row not in deleted]}
    changes = {row["address"]: row["change"] for row in json.loads(shown)["resource_changes"]}
    if any(changes.get(address, {}).get("actions") != ["delete"] for address in _LOCAL):
        raise ValueError("failed append local deletes were not reviewed")
    # Output removal is accepted only when that exact saved plan deletes it.
    for key in set(before.get("outputs", {})) - set(after.get("outputs", {})):
        change = json.loads(shown).get("output_changes", {}).get(key, {})
        if key not in {"ansible_inventory", "ssh_stanza"} or change.get("actions") != ["delete"]:
            raise ValueError("failed append output removal was not reviewed")
        expected["outputs"] = {k: v for k, v in expected.get("outputs", {}).items() if k != key}
    if before.get("check_results") != after.get("check_results"):
        _local_delete_checks(before["check_results"], after["check_results"], json.loads(shown).get("checks"))
        expected["check_results"] = after["check_results"]
    if _exact_json(after) != _exact_json(expected):
        raise ValueError("failed append changed retained resources or metadata")


def _local_delete_checks(before, after, planned):
    """Only the already planned firewall check may become unknown after failure."""
    names = {"var.edge_count_per_region", "var.external_middle_nodes", "linode_firewall.firewall",
             "output.public-key", "var.edge_groups", "var.trusted_ssh_cidrs", "var.middles", "var.middle_count"}
    def rows(value):
        if type(value) is not list or len(value) != len(names):
            raise ValueError("failed append check membership differs")
        result = {row.get("config_addr"): row for row in value if type(row) is dict}
        if len(result) != len(names) or set(result) != names:
            raise ValueError("failed append check addresses differ")
        return result
    old, new = rows(before), rows(after)
    if type(planned) is not list or len(planned) != len(names):
        raise ValueError("failed append planned checks differ")
    plan = {row.get("address", {}).get("to_display"): row for row in planned}
    if set(plan) != names:
        raise ValueError("failed append planned check addresses differ")
    for address in names:
        kind = "resource" if address == "linode_firewall.firewall" else "output" if address.startswith("output.") else "var"
        expected = {"object_kind": kind, "config_addr": address, "status": "pass",
                    "objects": [{"object_addr": address, "status": "pass"}]}
        if (plan[address].get("status") != "pass"
                or plan[address].get("instances") != [{"address": {"to_display": address}, "status": "pass"}]):
            raise ValueError("failed append planned check was not passing")
        if old[address] != expected:
            raise ValueError("failed append prior checks are not passing")
        if address == "linode_firewall.firewall":
            expected = {**expected, "status": "unknown",
                        "objects": [{"object_addr": address, "status": "unknown"}]}
        if new[address] != expected:
            raise ValueError("failed append has a changed or failed check")


def immutable_failure_evidence(parent, *, source, initial, workspaces, jobs,
                               release_check=require_devtest_terraform_release):
    """Authenticate approval, both plan artifacts and the original failed journal."""
    from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_id
    from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id as host_id
    from app.services.provider_keyed_mixed_failed_second_append import second_failure_present, prove_second_failure_journals
    failed_second = second_failure_present(parent, jobs)
    child = jobs.get(second_id(parent.id) if failed_second else _child_id(parent.id))
    if failed_second:
        failure_journal(parent, child, second=True)
    else:
        failure_journal(parent, child)
    if failed_second:
        prove_second_failure_journals(parent, jobs, release_check=release_check)
    data = parent.input
    plan_child = jobs.get(_plan_child_id(parent.id))
    if (parent.id != _parent_id(source.core_job_id) or parent.target_id != source.engagement_id
            or data.get("corePlanId") != source.core_plan_id
            or data.get("schema") != "mixed-append-pair-parent-v1"
            or data.get("sourceSha256") != _canonical(asdict(source))
            or data.get("bindingManifestSha256") != source.binding_manifest_sha256
            or len(parent.events) != 3 or parent.events[-1] != JobEvent(3, "info", "mixed append pair approved", {
                "reviewSha256": data["reviewSha256"], "planChildId": _plan_child_id(parent.id)})
            or plan_child is None or plan_child.status != "succeeded"
            or plan_child.action != "provider_keyed_mixed_append_plan_child"
            or plan_child.input.get("appendParentId") != parent.id
            or plan_child.input.get("requestSha256") != data.get("requestSha256")
            or plan_child.events[-1].message != "mixed append pair plan reviewed"
            or plan_child.events[-1].data != {"reviewSha256": data["reviewSha256"]}
            or jobs.get(host_id(parent.id)) is not None
            or (not failed_second and jobs.get(second_id(parent.id)) is not None)
            or len(data["providerOrder"]) != 2 or set(data["providerOrder"]) != {"digitalocean", "linode"}):
        raise ValueError("failed append approval or original publication differs")
    policies = validate_mixed_initial_apply_seal(initial)["reviewedPolicy"]
    intents = {p: _intent(p, data["intents"][p]) for p in data["providerOrder"]}
    if not _matches_request(data["reviewRequest"], intents["digitalocean"], intents["linode"]):
        raise ValueError("failed append reviewed choices differ")
    release = release_check(environment="devtest")
    if (release.version != "1.15.5" or release.platform != "linux_amd64"
            or _sha(_read(release.path, private=False)) != release.sha256):
        raise ValueError("failed append Terraform binary differs")
    hashes, summaries = {}, {}
    for provider in data["providerOrder"]:
        root, intent = workspaces[provider].path, intents[provider]
        artifacts = {suffix: _read(root / _name(provider, suffix)) for suffix in (
            "predecessor.tfstate", "saved.tfplan", "show.json", "inputs.json", "plan-receipt.json", "plan-journal.jsonl")}
        receipt = json.loads(artifacts["plan-receipt.json"])
        predecessor = artifacts["predecessor.tfstate"]
        published = next(row for row in source.provider_states if row.provider == provider)
        if (_sha(predecessor) != published.state_sha256
                or _sha(artifacts["plan-receipt.json"]) != data["receiptSha256"][provider]
                or receipt["predecessorStateSha256"] != published.state_sha256
                or receipt["planSha256"] != _sha(artifacts["saved.tfplan"])
                or receipt["showJsonSha256"] != _sha(artifacts["show.json"])
                or receipt["inputSha256"] != _sha(artifacts["inputs.json"])
                or json.loads(artifacts["inputs.json"]) != intent.nonsecret_varfile
                or data["reviewedInputs"][provider] != intent.nonsecret_varfile
                or receipt["schema"] != "mixed-append-saved-plan-receipt-v1"
                or receipt["provider"] != provider or receipt["engagementId"] != source.engagement_id
                or receipt["coreJobId"] != source.core_job_id
                or receipt["chainId"] != intent.chain_id or receipt["newEdgeAddress"] != intent.new_edge_address
                or receipt["sourceRevision"] != workspaces[provider].source_revision
                or receipt["sourceSha256"] != workspaces[provider].source_sha256
                or receipt["credentialRecordId"] != policies[provider]["provider_connection_id"]
                or receipt["credentialSecretSha256"] != policies[provider]["credential_secret_sha256"]
                or receipt["credentialUpdatedAt"] != policies[provider]["credential_updated_at"]
                or receipt["terraformBinarySha256"] != release.sha256):
            raise ValueError("failed append saved artifacts differ")
        for suffix, field in ((".barragan-provider-keyed-state.json", "sourceMarkerSha256"),
                (".barragan-topology.json", "topologySha256"), (".terraform.lock.hcl", "lockfileSha256")):
            blob = _read(root / suffix, private=False)
            if receipt[field] != _sha(blob):
                raise ValueError("failed append audited source differs")
            artifacts[suffix] = blob
        _journal_complete(root / _name(provider, "plan-journal.jsonl"), receipt["journalSha256"])
        _full_gate(provider, artifacts["show.json"], workspace=workspaces[provider], intent=intent,
            provider_states={p: _read(workspaces[p].path / _name(p, "predecessor.tfstate")) for p in workspaces},
            digitalocean_firewall=_firewall(data["digitaloceanFirewall"]),
            reviewed_variables=intent.nonsecret_varfile)
        hashes[provider] = {name: _sha(blob) for name, blob in artifacts.items()}
        summaries[provider] = {key: receipt[key] for key in _SUMMARY_KEYS}
    pair = seal_mixed_append_pair_plan(intents["digitalocean"], intents["linode"],
        tuple(summaries[p] for p in data["providerOrder"]),
        reviewed_provider_order=tuple(data["providerOrder"]), reviewed_chain_order=tuple(data["chainOrder"]))
    approval = mixed_append_approval_sha256(pair.review_sha256, SimpleNamespace(
        source=source, live_bindings_sha256=data["liveBindingsSha256"],
        historical_rows_sha256=data["historicalRowsSha256"]))
    if pair.review_sha256 != data["pairPlanSha256"] or approval != data["reviewSha256"]:
        raise ValueError("failed append paired review differs")
    first = data["providerOrder"][1 if failed_second else 0]
    command = child.events[2].data
    argv = [str(release.path), "apply", "-input=false", "-lock=true", "-no-color",
            str(workspaces[first].path / _name(first, "saved.tfplan"))]
    if (command["argvSha256"] != hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
            or command["planPath"] != argv[-1] or command["terraformPath"] != str(release.path)
            or command["terraformSha256"] != release.sha256
            or command["planSha256"] != hashes[first]["saved.tfplan"]):
        raise ValueError("failed append command does not bind saved plan")
    if failed_second:
        succeeded = data["providerOrder"][0]
        completed_command = jobs.get(_child_id(parent.id)).events[2].data
        first_argv = [str(release.path), "apply", "-input=false", "-lock=true", "-no-color",
                      str(workspaces[succeeded].path / _name(succeeded, "saved.tfplan"))]
        if (completed_command != {**completed_command, "argvSha256": _canonical(first_argv),
                "planPath": first_argv[-1], "terraformPath": str(release.path),
                "terraformSha256": release.sha256, "planSha256": hashes[succeeded]["saved.tfplan"]}):
            raise ValueError("failed second first command changed")
    return {"appendParentId": parent.id, "appendParentSha256": _canonical(asdict(parent)),
            **({"secondFailureJournalSha256": job_event_digest(child.events), "secondChildSha256": _canonical(asdict(child)),
                "completedFirstChildSha256": _canonical(asdict(jobs.get(_child_id(parent.id))))} if failed_second else {"firstChildSha256": _canonical(asdict(child))}),
            "planChildSha256": _canonical(asdict(plan_child)), "artifacts": hashes}


def fresh_failed_append_observation(initial, append, provider, workspace, *, fence,
                                    jobs, snapshot_reader=collect_provider_inventory_snapshot):
    """Fresh original-policy proof, tolerating only the proved local deletion."""
    from app.services.provider_keyed_mixed_unapplied_append_teardown import no_apply_present, fresh_no_apply_observation
    if no_apply_present(append, jobs):
        return fresh_no_apply_observation(initial, append, provider, workspace, fence=fence, jobs=jobs)
    from app.services.provider_keyed_mixed_failed_second_append import second_failure_present, fresh_second_failure_observation
    if second_failure_present(append, jobs):
        return fresh_second_failure_observation(initial, append, provider, workspace,
            fence=fence, jobs=jobs, snapshot_reader=snapshot_reader)
    first = append.input["providerOrder"][0]
    child = jobs.get(_child_id(append.id))
    identity = failure_journal(append, child)
    quiet = lambda: _process_quiescent(identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"])
    snapshot = snapshot_reader(initial, provider, workspace, fence=fence, process_quiescent=quiet)
    predecessor = _read(workspace.path / _name(provider, "predecessor.tfstate"))
    if provider == first:
        if snapshot.phase != "apply_started":
            raise ValueError("failed append Apply phase differs")
        local_delete_projection(predecessor, snapshot.state_json,
                                _read(workspace.path / _name(provider, "show.json")))
    elif snapshot.phase != "applied" or snapshot.state_json != predecessor:
        raise ValueError("untouched append provider state changed")
    policy = validate_mixed_initial_apply_seal(initial)["reviewedPolicy"][provider]
    state, actual, cloud = _state(provider, policy, snapshot.state_json)
    _inventory(provider, policy, actual, cloud, snapshot.inventory)
    require_current_keyed_firewall(provider, policy, actual, fence=fence)
    if _read(workspace.state_path, private=False) != snapshot.state_json or not quiet():
        raise ValueError("failed append source changed during provider policy read")
    nodes = {identifier for address, identifier in cloud.items() if address in policy["nodes"]}
    if (len(nodes) != 2 or (set(snapshot.linode_firewall_attached_node_ids or ()) != nodes
            if provider == "linode" else snapshot.selector_tag_exists is not True
            or snapshot.selector_resources_count != 2 or set(snapshot.selector_attached_node_ids or ()) != nodes)):
        raise ValueError("failed append original cloud attachment differs")
    return ProviderHostObservation(ProviderApplyClassification(provider, "full", _sha(snapshot.state_json),
        state["lineage"], state["serial"], tuple(sorted(cloud.items()))), snapshot.state_json)


def failure_history(review, *, jobs, workspaces, initial):
    recovery = review.failed_append_recovery
    from app.services.provider_keyed_mixed_unapplied_append_teardown import KIND, no_apply_history
    if recovery.get("kind") == KIND:
        return no_apply_history(review, jobs=jobs, workspaces=workspaces, initial=initial)
    if recovery.get("kind") == "failed-second-v1":
        from app.services.provider_keyed_mixed_failed_second_append import second_failure_history
        return second_failure_history(review, jobs=jobs, workspaces=workspaces, initial=initial)
    append = jobs.get(recovery["appendParentId"])
    if (set(recovery) != {"appendParentId", "failedProvider", "source", "evidence"}
            or recovery["failedProvider"] != append.input["providerOrder"][0]
            or recovery["source"] != json.loads(json.dumps(asdict(review.source)))):
        raise ValueError("failed append saved recovery identity differs")
    current = immutable_failure_evidence(append, source=review.source, initial=initial,
        workspaces=workspaces, jobs=jobs)
    if current != review.failed_append_recovery["evidence"]:
        raise ValueError("failed append immutable history changed")
    return current
