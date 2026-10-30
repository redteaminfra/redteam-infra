# Copyright (c) 2026, Oracle and/or its affiliates.
"""Failed append never replays; only exact local-output deletes enter teardown."""
from dataclasses import replace
import json

import pytest

from app.services import provider_keyed_mixed_failed_append_teardown as recovery
from app.services.provider_keyed_mixed_append_pair_apply_child import (
    run_first_mixed_append_provider_apply, MixedAppendFirstApplyAttention, _child_id)
from test_provider_keyed_mixed_append_pair_apply_child import ready as append_ready


def test_recognizes_actual_worker_nonzero_six_event_journal_without_replay(append_ready):
    append_ready.stop["failed"] = True
    with pytest.raises(MixedAppendFirstApplyAttention):
        run_first_mixed_append_provider_apply(**append_ready.options)
    child = append_ready.jobs.get(_child_id(append_ready.parent.id))
    assert len(child.events) == 6
    identity = recovery.failure_journal(append_ready.parent, child, process_quiescent=lambda *_: True)
    assert identity["pid"] == 123
    with pytest.raises(ValueError):
        recovery.failure_journal(append_ready.parent, child, process_quiescent=lambda *_: False)
    for event_index, data in ((5, {"returnCode": 0}), (5, {"stdoutTruncated": True}),
                              (3, {"pid": True}), (2, {"invocationId": "other"})):
        events = list(child.events)
        events[event_index] = replace(events[event_index], data={**events[event_index].data, **data})
        with pytest.raises(ValueError):
            recovery.failure_journal(append_ready.parent, replace(child, events=events),
                                     process_quiescent=lambda *_: True)
    assert append_ready.calls.count("intent") == 1


def _projection():
    resources = [
        {"mode": "managed", "type": "local_file", "name": name,
         "instances": [{"index_key": 0, "attributes": {"id": name}}]}
        for name in ("ansible_inventory", "ssh_stanza")]
    resources += [{"mode": "managed", "type": "linode_instance", "name": "middle",
        "instances": [{"attributes": {"id": "1", "label": "retained"}}]},
        {"mode": "managed", "type": "random_password", "name": "root_password",
         "instances": [{"attributes": {"id": "password", "result": "secret-original"}}]}]
    predecessor = {"version": 4, "terraform_version": "1.15.5", "lineage": "stable",
                   "serial": 7, "outputs": {}, "resources": resources, "check_results": None}
    current = {**predecessor, "serial": 10, "resources": resources[2:]}
    shown = {"resource_changes": [{"address": address, "change": {"actions": ["delete"]}}
        for address in sorted(recovery._LOCAL)]}
    return predecessor, current, shown


def test_exact_local_delete_projection_preserves_every_retained_row():
    before, after, shown = _projection()
    recovery.local_delete_projection(json.dumps(before).encode(), json.dumps(after).encode(),
                                     json.dumps(shown).encode())


@pytest.mark.parametrize("drift", ["password", "node", "lineage", "serial", "unknown", "extra-cloud", "remaining-local", "unplanned-delete"])
def test_local_delete_projection_rejects_every_other_state_change(drift):
    before, after, shown = _projection()
    if drift == "password": after["resources"][1]["instances"][0]["attributes"]["result"] = "changed"
    elif drift == "node": after["resources"][0]["instances"][0]["attributes"]["id"] = "other"
    elif drift == "lineage": after["lineage"] = "changed"
    elif drift == "serial": after["serial"] = 7
    elif drift == "unknown": after["check_results"] = []
    elif drift == "extra-cloud": after["resources"] = [*after["resources"], {"type": "linode_instance", "name": "added"}]
    elif drift == "remaining-local": after["resources"] = [*after["resources"], before["resources"][0]]
    else: shown["resource_changes"][0]["change"]["actions"] = ["no-op"]
    # Detach retained rows before mutation: raw original remains authenticated.
    baseline, _, _ = _projection()
    with pytest.raises(ValueError):
        recovery.local_delete_projection(json.dumps(baseline).encode(), json.dumps(after).encode(),
                                         json.dumps(shown).encode())


def _checks():
    names = ["var.edge_count_per_region", "var.external_middle_nodes", "linode_firewall.firewall",
             "output.public-key", "var.edge_groups", "var.trusted_ssh_cidrs", "var.middles", "var.middle_count"]
    before = [{"object_kind": "resource" if name.startswith("linode_") else "output" if name.startswith("output.") else "var",
               "config_addr": name, "status": "pass", "objects": [{"object_addr": name, "status": "pass"}]}
              for name in names]
    after = json.loads(json.dumps(list(reversed(before))))
    firewall = next(row for row in after if row["config_addr"] == "linode_firewall.firewall")
    firewall["status"] = firewall["objects"][0]["status"] = "unknown"
    planned = [{"address": {"to_display": name}, "status": "pass",
                "instances": [{"address": {"to_display": name}, "status": "pass"}]} for name in names]
    return before, after, planned


def test_actual_failed_state_check_reordering_only_firewall_becomes_unknown():
    before, after, shown = _projection()
    old_checks, new_checks, planned = _checks()
    before["check_results"], after["check_results"], shown["checks"] = old_checks, new_checks, planned
    recovery.local_delete_projection(json.dumps(before).encode(), json.dumps(after).encode(), json.dumps(shown).encode())


@pytest.mark.parametrize("drift", ["failed", "new", "missing", "other-unknown", "plan-unknown"])
def test_failure_check_projection_rejects_other_checks(drift):
    before, after, planned = _checks()
    if drift == "failed": after[0]["status"] = "fail"
    elif drift == "new": after.append(after[0])
    elif drift == "missing": after.pop()
    elif drift == "other-unknown": after[0]["status"] = "unknown"
    else: planned[0]["status"] = "unknown"
    with pytest.raises(ValueError): recovery._local_delete_checks(before, after, planned)


def _saved_failure_authority(tmp_path, monkeypatch, order=None):
    from dataclasses import asdict
    import hashlib
    from types import SimpleNamespace
    from app.domain import JobEvent
    from app.storage.job_repository import StoredJobRun
    from app.services import provider_keyed_mixed_append_pair_plan_producer as producer
    from app.services.provider_keyed_mixed_append_pair_apply_child import _base
    from app.services.provider_keyed_mixed_append_pair_parent import mixed_append_approval_sha256
    from test_provider_keyed_mixed_append_pair_plan_producer import fixture
    from test_provider_keyed_mixed_append_review_runtime import _request
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    if order is not None:
        compiled = {"digitalocean": producer.compile_mixed_digitalocean_on_linode_append_intent(),
                    "linode": producer.compile_mixed_linode_on_digitalocean_append_intent()}
        kwargs["reviewed_provider_order"] = order
        kwargs["reviewed_chain_order"] = tuple(compiled[p].chain_id for p in order)
    seal = producer.produce_mixed_append_pair_plan_review(**kwargs)
    source = kwargs["source"]
    intents = {p: (producer.compile_mixed_digitalocean_on_linode_append_intent() if p == "digitalocean"
                   else producer.compile_mixed_linode_on_digitalocean_append_intent()) for p in kwargs["workspaces"]}
    receipts = {p: json.loads((w.path / recovery._name(p, "plan-receipt.json")).read_bytes()) for p, w in kwargs["workspaces"].items()}
    data = {"schema": "mixed-append-pair-parent-v1", "phase": "apply_sealed", "engagementId": source.engagement_id,
        "coreJobId": source.core_job_id, "corePlanId": source.core_plan_id,
        "providerOrder": list(kwargs["reviewed_provider_order"]), "chainOrder": list(kwargs["reviewed_chain_order"]),
        "sourceSha256": recovery._canonical(asdict(source)), "bindingManifestSha256": source.binding_manifest_sha256,
        "intents": {p: asdict(i) for p, i in intents.items()}, "reviewRequest": _request({p + "_intent": i for p, i in intents.items()}),
        "reviewedInputs": {p: i.nonsecret_varfile for p, i in intents.items()}, "digitaloceanFirewall": {},
        "receiptSha256": {p: recovery._sha((w.path / recovery._name(p, "plan-receipt.json")).read_bytes()) for p, w in kwargs["workspaces"].items()},
        "requestSha256": "a" * 64, "pairPlanSha256": seal.review_sha256, "historicalRowsSha256": "b" * 64,
        "liveBindingsSha256": "c" * 64}
    data["reviewSha256"] = mixed_append_approval_sha256(seal.review_sha256, SimpleNamespace(source=source,
        live_bindings_sha256=data["liveBindingsSha256"], historical_rows_sha256=data["historicalRowsSha256"]))
    parent_id = recovery._parent_id(source.core_job_id)
    parent = StoredJobRun(parent_id, "provider_keyed_mixed_append", "running", "engagement:" + source.engagement_id,
        "engagement", source.engagement_id, "operator", data, [], "at", "at", None,
        [JobEvent(1, "info", "mixed append pair reserved", {"requestSha256": data["requestSha256"]}),
         JobEvent(2, "info", "mixed append pair planning started", {}),
         JobEvent(3, "info", "mixed append pair approved", {"reviewSha256": data["reviewSha256"], "planChildId": recovery._plan_child_id(parent_id)})])
    plan_child = replace(parent, id=recovery._plan_child_id(parent.id), action="provider_keyed_mixed_append_plan_child",
        status="succeeded", finished_at="at", input={"appendParentId": parent.id, "requestSha256": data["requestSha256"]},
        events=[JobEvent(1, "info", "mixed append pair plan reviewed", {"reviewSha256": data["reviewSha256"]})])
    first = data["providerOrder"][0]
    root = kwargs["workspaces"][first].path
    release = kwargs["release_check"]()
    command = [str(release.path), "apply", "-input=false", "-lock=true", "-no-color", str(root / recovery._name(first, "saved.tfplan"))]
    intended = {"invocationId": "failed-once", "argvSha256": hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
        "planSha256": receipts[first]["planSha256"], "planPath": command[-1], "terraformPath": str(release.path), "terraformSha256": release.sha256}
    child = replace(parent, id=recovery._child_id(parent.id), action="provider_keyed_mixed_append_apply_child", input=_base(parent),
        events=[JobEvent(1, "info", "mixed append first Apply queued", {}), JobEvent(2, "info", "mixed append first Apply started", {}),
            JobEvent(3, "info", "mixed append first Apply command intended", intended),
            JobEvent(4, "info", "mixed append first Apply command started before GO", {"invocationId": "failed-once", "bootId": "boot", "pid": 123, "pgid": 123, "startTicks": 1}),
            JobEvent(5, "info", "mixed append first phase apply_started", {"commandStartSequence": 4}),
            JobEvent(6, "info", "mixed append first Apply command result fenced", {"invocationId": "failed-once", "returnCode": 1, "stdoutBytes": 0, "stderrBytes": 10, "stdoutTruncated": False, "stderrTruncated": False})])
    rows = {row.id: row for row in (parent, plan_child, child)}
    policy = {p: {"provider_connection_id": r["credentialRecordId"], "credential_secret_sha256": r["credentialSecretSha256"],
                  "credential_updated_at": r["credentialUpdatedAt"]} for p, r in receipts.items()}
    monkeypatch.setattr(recovery, "validate_mixed_initial_apply_seal", lambda _: {"reviewedPolicy": policy})
    monkeypatch.setattr(recovery, "_firewall", lambda _: kwargs["digitalocean_firewall"])
    recognize = recovery.failure_journal
    monkeypatch.setattr(recovery, "failure_journal", lambda p, c, **kw: recognize(p, c, process_quiescent=lambda *_: True, **kw))
    options = dict(source=source, initial=object(), workspaces=kwargs["workspaces"],
                   jobs=SimpleNamespace(get=lambda key: rows.get(key)), release_check=kwargs["release_check"])
    return parent, rows, options, calls


def test_saved_failure_authority_reopens_both_real_journals_receipts_and_pair_without_commands(tmp_path, monkeypatch):
    parent, rows, options, calls = _saved_failure_authority(tmp_path, monkeypatch)
    proof = recovery.immutable_failure_evidence(parent, **options)
    assert set(proof["artifacts"]) == {"digitalocean", "linode"}
    assert len(calls) == 8
    # Immutable reopening does not consult current state or apply phase after destruction.
    for workspace in options["workspaces"].values():
        workspace.state_path.write_text('{"resources":[]}')
        (workspace.path / ".barragan-apply-phase.json").write_text('{"phase":"destroy_applied"}')
    assert recovery.immutable_failure_evidence(parent, **options) == proof
    assert len(calls) == 8


@pytest.mark.parametrize("drift", ["source", "saved-plan", "receipt", "journal", "second-child", "approval"])
def test_saved_failure_authority_rejects_changed_source_or_replay_boundary(tmp_path, monkeypatch, drift):
    parent, rows, options, calls = _saved_failure_authority(tmp_path, monkeypatch)
    root = options["workspaces"]["digitalocean"].path
    if drift in {"saved-plan", "receipt", "journal"}:
        suffix = {"saved-plan": "saved.tfplan", "receipt": "plan-receipt.json", "journal": "plan-journal.jsonl"}[drift]
        (root / recovery._name("digitalocean", suffix)).write_bytes(b"changed")
    elif drift == "source": parent = replace(parent, input={**parent.input, "sourceSha256": "0" * 64})
    elif drift == "approval": parent = replace(parent, input={**parent.input, "pairPlanSha256": "0" * 64})
    else:
        from app.services.provider_keyed_mixed_append_second_apply_child import _child_id
        rows[_child_id(parent.id)] = parent
    with pytest.raises(ValueError): recovery.immutable_failure_evidence(parent, **options)
    assert len(calls) == 8
