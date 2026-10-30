# Copyright (c) 2026, Oracle and/or its affiliates.
"""Failed-second cleanup is an exact five-node boundary, never Apply recovery."""
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from app.services import provider_keyed_mixed_failed_second_append as failure
from app.services.provider_keyed_mixed_failed_append_teardown import failure_journal
from app.services.provider_keyed_mixed_append_second_apply_child import (
    MixedAppendSecondApplyAttention, _child_id, run_second_mixed_append_provider_apply,
)
from test_provider_keyed_mixed_append_second_apply_child import ready


def _states():
    resources = [
        {"mode": "managed", "type": "local_file", "name": name,
         "instances": [{"index_key": 0, "attributes": {"id": name}}]}
        for name in ("ansible_inventory", "ssh_stanza")]
    resources += [{"mode": "managed", "type": "digitalocean_droplet", "name": name,
                   "instances": [{"attributes": {"id": identifier, "name": name, "secret": "unchanged"}}]}
                  for name, identifier in (("middle", 1), ("edge", 2))]
    resources += [{"mode": "managed", "type": "digitalocean_firewall", "name": "firewall",
                   "instances": [{"attributes": {"id": "firewall-id", "droplet_ids": None,
                        "status": "waiting", "pending_changes": [
                            {"droplet_id": identifier, "status": "waiting", "removing": False} for identifier in (1, 2)],
                        "inbound_rule": [{"protocol": "tcp", "port_range": "22", "source_addresses": ["1.1.1.1/32"]}]}}]}]
    old = {"version": 4, "terraform_version": "1.15.5", "serial": 7,
           "lineage": "stable", "outputs": {}, "resources": resources, "check_results": None}
    new = copy.deepcopy(old)
    new["serial"] = 11
    new["resources"] = new["resources"][2:]
    firewall = new["resources"][-1]["instances"][0]["attributes"]
    firewall.update(droplet_ids=[], pending_changes=[], status="succeeded")
    shown = {"resource_changes": [{"address": f"local_file.{name}[0]", "change": {"actions": ["delete"]}}
                                   for name in ("ansible_inventory", "ssh_stanza")]}
    return old, new, shown


def _raw(value):
    return json.dumps(value).encode()


@pytest.mark.parametrize("settled,deleted", [(False, False), (False, True), (True, False), (True, True)])
def test_exact_second_state_projection_preserves_all_retained_rows(settled, deleted):
    old, new, shown = _states()
    if not settled:
        new["resources"][-1] = copy.deepcopy(old["resources"][-1])
    if not deleted:
        new["resources"] = copy.deepcopy(old["resources"][:2]) + new["resources"]
    failure.second_state_projection(_raw(old), _raw(new), _raw(shown))
    failure.second_state_projection(_raw(old), _raw(old), _raw(shown))


@pytest.mark.parametrize("change", ["extra-pending", "removing", "numeric-removing", "wrong-status",
    "missing-field", "pending-remains", "direct-attachment", "rules", "node-secret", "dependency", "check", "lineage", "serial", "boolean-integer", "nonfinite"])
def test_second_projection_rejects_unexplained_policy_identity_and_metadata(change):
    old, new, shown = _states()
    before_fw, after_fw = old["resources"][-1]["instances"][0]["attributes"], new["resources"][-1]["instances"][0]["attributes"]
    if change == "extra-pending": before_fw["pending_changes"][1]["droplet_id"] = 999
    elif change == "removing": before_fw["pending_changes"][0]["removing"] = True
    elif change == "numeric-removing": before_fw["pending_changes"][0]["removing"] = 0
    elif change == "wrong-status": before_fw["pending_changes"][0]["status"] = "succeeded"
    elif change == "missing-field": del after_fw["droplet_ids"]
    elif change == "pending-remains": after_fw["pending_changes"] = before_fw["pending_changes"]
    elif change == "direct-attachment": after_fw["droplet_ids"] = [1]
    elif change == "rules": after_fw["inbound_rule"][0]["port_range"] = "443"
    elif change == "node-secret": new["resources"][0]["instances"][0]["attributes"]["secret"] = "changed"
    elif change == "dependency": new["resources"][0]["instances"][0]["dependencies"] = ["other"]
    elif change == "check": new["check_results"] = []
    elif change == "lineage": new["lineage"] = "changed"
    elif change == "nonfinite": new["resources"][0]["instances"][0]["attributes"]["unknown"] = float("nan")
    elif change == "boolean-integer":
        old["resources"][2]["instances"][0]["attributes"]["flag"] = False
        new["resources"][0]["instances"][0]["attributes"]["flag"] = 0
    else: new["serial"] = 7
    with pytest.raises((ValueError, KeyError)):
        failure.second_state_projection(_raw(old), _raw(new), _raw(shown))


def test_actual_second_rc1_journal_is_stopped_not_replayable(ready):
    ready.change["kind"] = "nonzero"
    with pytest.raises(MixedAppendSecondApplyAttention):
        run_second_mixed_append_provider_apply(**ready.options)
    child = ready.jobs.get(_child_id(ready.parent.id))
    assert len(child.events) == 6
    identity = failure_journal(ready.parent, child, second=True, process_quiescent=lambda *_: True)
    assert identity["pid"] == 123
    with pytest.raises(ValueError):
        failure_journal(ready.parent, child, second=True, process_quiescent=lambda *_: False)
    for index, changed in ((5, {"returnCode": 0}), (5, {"stdoutTruncated": True}),
                           (3, {"pid": True}), (2, {"planSha256": "changed", "invocationId": "other"})):
        rows = list(child.events)
        rows[index] = replace(rows[index], data={**rows[index].data, **changed})
        with pytest.raises(ValueError):
            failure_journal(ready.parent, replace(child, events=rows), second=True, process_quiescent=lambda *_: True)
    with pytest.raises(MixedAppendSecondApplyAttention):
        run_second_mixed_append_provider_apply(**ready.options)
    assert len(ready.go) == 1


@pytest.mark.parametrize("drift", ["future", "missing", "bad-token", "naive", "out-of-order"])
def test_active_or_malformed_claim_cannot_reconcile(drift):
    from types import SimpleNamespace
    now = datetime.now(timezone.utc)
    data = {"claimOwner": "mixed-append-second-" + "a" * 32, "claimToken": "b" * 32,
            "claimClaimedAt": (now - timedelta(minutes=4)).isoformat(),
            "claimHeartbeatAt": (now - timedelta(minutes=3)).isoformat(),
            "claimExpiresAt": (now - timedelta(minutes=1)).isoformat()}
    if drift == "future": data["claimExpiresAt"] = (now + timedelta(minutes=1)).isoformat()
    elif drift == "missing": del data["claimHeartbeatAt"]
    elif drift == "bad-token": data["claimToken"] = "not-a-token"
    elif drift == "naive": data["claimExpiresAt"] = "2020-01-01T00:00:00"
    else: data["claimHeartbeatAt"] = (now - timedelta(minutes=5)).isoformat()
    with pytest.raises(ValueError): failure._expired_claim(SimpleNamespace(input=data), required=True)


@pytest.mark.parametrize("drift",[None,"first-command","second-command","receipt","saved-plan","approval","journal"])
def test_second_failure_reopens_both_saved_plan_artifacts_without_any_command(tmp_path,monkeypatch,drift):
    from types import SimpleNamespace
    import hashlib
    from app.domain import JobEvent
    from app.storage.job_repository import job_event_digest
    from app.services import provider_keyed_mixed_failed_append_teardown as authority
    from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_id
    from app.services.provider_keyed_mixed_append_second_apply_child import _base as second_base,_child_id as second_id,ACTION
    from test_provider_keyed_mixed_failed_append_teardown import _saved_failure_authority
    parent,rows,options,calls=_saved_failure_authority(tmp_path,monkeypatch,order=("linode","digitalocean"))
    first=rows[first_id(parent.id)]
    rows[first.id]=replace(first,status="succeeded",finished_at="at")
    root=options["workspaces"]["digitalocean"].path
    release=options["release_check"]()
    argv=[str(release.path),"apply","-input=false","-lock=true","-no-color",str(root/authority._name("digitalocean","saved.tfplan"))]
    intended={"invocationId":"second","argvSha256":hashlib.sha256(json.dumps(argv,separators=(",",":")).encode()).hexdigest(),
        "planSha256":hashlib.sha256((root/authority._name("digitalocean","saved.tfplan")).read_bytes()).hexdigest(),
        "planPath":argv[-1],"terraformPath":str(release.path),"terraformSha256":release.sha256}
    events=[replace(event,message=event.message.replace("first","second")) for event in first.events]
    events[2]=replace(events[2],data=intended)
    events[3]=replace(events[3],data={**events[3].data,"invocationId":"second"})
    events[5]=replace(events[5],data={**events[5].data,"invocationId":"second"})
    second=replace(first,id=second_id(parent.id),action=ACTION,input=second_base(parent),events=events)
    rows[second.id]=second
    # Dedicated worker/journal tests prove the terminal-first witness; here the
    # real paired receipt, binary, re-show, source hash and argv checks run.
    monkeypatch.setattr(failure,"prove_second_failure_journals",lambda *_a,**_k:None)
    before=list(calls)
    if drift=="first-command":
        altered=list(rows[first.id].events)
        altered[2]=replace(altered[2],data={**altered[2].data,"planPath":"/unreviewed"})
        rows[first.id]=replace(rows[first.id],events=altered)
    elif drift=="second-command":
        altered=list(second.events)
        altered[2]=replace(altered[2],data={**altered[2].data,"terraformPath":"/unreviewed"})
        rows[second.id]=replace(second,events=altered)
    elif drift in {"receipt","saved-plan"}:
        suffix="plan-receipt.json" if drift=="receipt" else "saved.tfplan"
        (root/authority._name("digitalocean",suffix)).write_bytes(b"changed")
    elif drift=="approval":parent=replace(parent,input={**parent.input,"reviewSha256":"0"*64})
    elif drift=="journal":rows[second.id]=replace(second,events=events[:-1])
    if drift:
        with pytest.raises((ValueError,KeyError)):
            authority.immutable_failure_evidence(parent,**options)
    else:
        result=authority.immutable_failure_evidence(parent,**options)
        assert result["secondFailureJournalSha256"]==job_event_digest(second.events)
        assert "secondChildSha256" in result and "completedFirstChildSha256" in result
    assert calls==before


# Actual nonsecret failed-second check arrays, captured 2026-10-26.
_ACTUAL_CHECKS = {'predecessorChecks': [{'object_kind': 'var',
                        'config_addr': 'var.trusted_ssh_cidrs',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.trusted_ssh_cidrs', 'status': 'pass'}]},
                       {'object_kind': 'output',
                        'config_addr': 'output.public-key',
                        'status': 'pass',
                        'objects': [{'object_addr': 'output.public-key', 'status': 'pass'}]},
                       {'object_kind': 'var',
                        'config_addr': 'var.middle_count',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.middle_count', 'status': 'pass'}]},
                       {'object_kind': 'var',
                        'config_addr': 'var.external_middle_nodes',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.external_middle_nodes',
                                     'status': 'pass'}]},
                       {'object_kind': 'var',
                        'config_addr': 'var.edge_groups',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.edge_groups', 'status': 'pass'}]},
                       {'object_kind': 'var',
                        'config_addr': 'var.firewall_selector_tag',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.firewall_selector_tag',
                                     'status': 'pass'}]},
                       {'object_kind': 'var',
                        'config_addr': 'var.edge_count_per_region',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.edge_count_per_region',
                                     'status': 'pass'}]},
                       {'object_kind': 'var',
                        'config_addr': 'var.middles',
                        'status': 'pass',
                        'objects': [{'object_addr': 'var.middles', 'status': 'pass'}]},
                       {'object_kind': 'resource',
                        'config_addr': 'digitalocean_firewall.firewall',
                        'status': 'pass',
                        'objects': [{'object_addr': 'digitalocean_firewall.firewall',
                                     'status': 'pass'}]}],
 'currentChecks': [{'object_kind': 'var',
                    'config_addr': 'var.edge_count_per_region',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.edge_count_per_region', 'status': 'pass'}]},
                   {'object_kind': 'var',
                    'config_addr': 'var.external_middle_nodes',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.external_middle_nodes', 'status': 'pass'}]},
                   {'object_kind': 'var',
                    'config_addr': 'var.firewall_selector_tag',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.firewall_selector_tag', 'status': 'pass'}]},
                   {'object_kind': 'output',
                    'config_addr': 'output.public-key',
                    'status': 'pass',
                    'objects': [{'object_addr': 'output.public-key', 'status': 'pass'}]},
                   {'object_kind': 'var',
                    'config_addr': 'var.trusted_ssh_cidrs',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.trusted_ssh_cidrs', 'status': 'pass'}]},
                   {'object_kind': 'var',
                    'config_addr': 'var.edge_groups',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.edge_groups', 'status': 'pass'}]},
                   {'object_kind': 'resource',
                    'config_addr': 'digitalocean_firewall.firewall',
                    'status': 'unknown',
                    'objects': [{'object_addr': 'digitalocean_firewall.firewall',
                                 'status': 'unknown'}]},
                   {'object_kind': 'var',
                    'config_addr': 'var.middles',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.middles', 'status': 'pass'}]},
                   {'object_kind': 'var',
                    'config_addr': 'var.middle_count',
                    'status': 'pass',
                    'objects': [{'object_addr': 'var.middle_count', 'status': 'pass'}]}],
 'planChecks': [{'address': {'kind': 'resource',
                             'mode': 'managed',
                             'name': 'firewall',
                             'to_display': 'digitalocean_firewall.firewall',
                             'type': 'digitalocean_firewall'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'digitalocean_firewall.firewall'},
                                'status': 'pass'}]},
                {'address': {'kind': 'output_value',
                             'name': 'public-key',
                             'to_display': 'output.public-key'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'output.public-key'}, 'status': 'pass'}]},
                {'address': {'kind': 'var',
                             'name': 'edge_count_per_region',
                             'to_display': 'var.edge_count_per_region'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.edge_count_per_region'},
                                'status': 'pass'}]},
                {'address': {'kind': 'var', 'name': 'edge_groups', 'to_display': 'var.edge_groups'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.edge_groups'}, 'status': 'pass'}]},
                {'address': {'kind': 'var',
                             'name': 'external_middle_nodes',
                             'to_display': 'var.external_middle_nodes'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.external_middle_nodes'},
                                'status': 'pass'}]},
                {'address': {'kind': 'var',
                             'name': 'firewall_selector_tag',
                             'to_display': 'var.firewall_selector_tag'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.firewall_selector_tag'},
                                'status': 'pass'}]},
                {'address': {'kind': 'var',
                             'name': 'middle_count',
                             'to_display': 'var.middle_count'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.middle_count'}, 'status': 'pass'}]},
                {'address': {'kind': 'var', 'name': 'middles', 'to_display': 'var.middles'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.middles'}, 'status': 'pass'}]},
                {'address': {'kind': 'var',
                             'name': 'trusted_ssh_cidrs',
                             'to_display': 'var.trusted_ssh_cidrs'},
                 'status': 'pass',
                 'instances': [{'address': {'to_display': 'var.trusted_ssh_cidrs'},
                                'status': 'pass'}]}]}


def _actual_check_states():
    old, new, shown = _states()
    old["check_results"] = copy.deepcopy(_ACTUAL_CHECKS["predecessorChecks"])
    new["check_results"] = copy.deepcopy(_ACTUAL_CHECKS["currentChecks"])
    shown["checks"] = copy.deepcopy(_ACTUAL_CHECKS["planChecks"])
    return old, new, shown


@pytest.mark.parametrize("incomplete", [False, True])
def test_actual_nine_check_rows_allow_only_reordering_and_incomplete_firewall(incomplete):
    old, new, shown = _actual_check_states()
    if not incomplete:
        for row in new["check_results"]:
            row["status"] = row["objects"][0]["status"] = "pass"
    raw = _raw(new)
    failure.second_state_projection(_raw(old), raw, _raw(shown))
    assert raw == _raw(new)  # Projection never rewrites the original check receipt/state.
    assert old["check_results"] == _ACTUAL_CHECKS["predecessorChecks"]


@pytest.mark.parametrize("drift", ["duplicate", "missing", "extra", "other-unknown", "fail",
    "extra-object", "object-address", "kind", "extra-field", "object-field", "numeric-status",
    "before-unknown", "before-field", "plan-missing", "plan-duplicate", "plan-unknown",
    "plan-extra-field", "plan-object", "plan-kind", "plan-bool", "plan-address-shape"])
def test_nine_check_projection_rejects_every_unreviewed_change(drift):
    old, new, shown = _actual_check_states()
    rows = new["check_results"]
    fw = next(row for row in rows if row["object_kind"] == "resource")
    if drift == "duplicate": rows[-1] = copy.deepcopy(rows[0])
    elif drift == "missing": rows.pop()
    elif drift == "extra": rows.append(copy.deepcopy(rows[0]))
    elif drift == "other-unknown": rows[0]["status"] = rows[0]["objects"][0]["status"] = "unknown"
    elif drift == "fail": fw["status"] = fw["objects"][0]["status"] = "fail"
    elif drift == "extra-object": fw["objects"].append(copy.deepcopy(fw["objects"][0]))
    elif drift == "object-address": fw["objects"][0]["object_addr"] = "other"
    elif drift == "kind": fw["object_kind"] = "var"
    elif drift == "extra-field": fw["reason"] = "unreviewed"
    elif drift == "object-field": fw["objects"][0]["reason"] = "unreviewed"
    elif drift == "numeric-status": fw["status"] = 0
    elif drift == "before-unknown": old["check_results"][0]["status"] = "unknown"
    elif drift == "before-field": old["check_results"][0]["extra"] = True
    elif drift == "plan-missing": shown["checks"].pop()
    elif drift == "plan-duplicate": shown["checks"][-1] = copy.deepcopy(shown["checks"][0])
    elif drift == "plan-unknown": shown["checks"][0]["status"] = "unknown"
    elif drift == "plan-extra-field": shown["checks"][0]["extra"] = False
    elif drift == "plan-object": shown["checks"][0]["instances"][0]["address"]["to_display"] = "other"
    elif drift == "plan-kind": shown["checks"][0]["address"]["kind"] = "var"
    elif drift == "plan-bool": shown["checks"][0]["instances"][0]["status"] = True
    else: shown["checks"][0]["address"] = []
    with pytest.raises((ValueError, KeyError)):
        failure.second_state_projection(_raw(old), _raw(new), _raw(shown))


def _core_intent_binding_case():
    from types import SimpleNamespace
    from app.domain import JobEvent
    from app.integrations.pilot_standard_rti import pilot_channel_rows, pilot_names
    from app.services.provider_keyed_mixed_append_live_bindings import _channel_history
    inputs = {"engagementName": "opaque", "engagementId": "eng-opaque", "proxyCount": 1,
              "deploymentMode": "hold_for_review", "target": {"name": "barragan-testing", "region": "us-sanjose-1"}}
    canonical = pilot_channel_rows(pilot_names(inputs["engagementName"]), region=inputs["target"]["region"], proxy_count=1)
    messages = ["core infrastructure deployed; preparing continuous Inspector",
                "operator inspection ready", "pilot Standard RTI run finished"]
    events = [JobEvent(index + 1, "info", message, copy.deepcopy(canonical)) for index, message in enumerate(messages)]
    events[-1] = replace(events[-1], data={**events[-1].data, "ok": True, "mutationStatus": "deployed",
        "ansibleStatus": "validated", "finalCleanupStatus": "pending_operator_teardown"})
    core = SimpleNamespace(id="job-core", action="pilot_standard_rti_guarded_execute", status="succeeded", input=inputs, events=events)
    plan = SimpleNamespace(evidence={"target": copy.deepcopy(inputs["target"]), "proxyCount": 1})
    bindings = {"channels": _channel_history([core]), "domains": (), "certificates": (), "sites": ()}
    return core, plan, bindings


def test_cleanup_core_intent_eligibility_preserves_original_history():
    from app.services.provider_keyed_mixed_published_teardown_collector import _require_no_independent_failed_second_bindings
    core, plan, bindings = _core_intent_binding_case()
    original = copy.deepcopy(bindings)
    _require_no_independent_failed_second_bindings(bindings, core, plan)
    assert bindings == original and len(bindings["channels"]) == 1
    _require_no_independent_failed_second_bindings({key: () for key in bindings}, core, plan)


@pytest.mark.parametrize("drift", ["ready", "applied", "purpose", "proxy", "port", "provider", "region", "chain",
    "extra-row", "extra-field", "missing-field", "missing-snapshot-key", "extra-event", "missing-event",
    "wrong-message", "inbound", "another-job", "later-empty-removal", "wrong-hash", "domain",
    "certificate", "site", "plan-region", "plan-count", "boolean-count", "core-action", "core-failed", "terminal"])
def test_cleanup_core_intent_eligibility_rejects_real_or_forged_bindings(drift):
    from app.services.provider_keyed_mixed_published_teardown_collector import _require_no_independent_failed_second_bindings
    from app.services.provider_keyed_mixed_append_live_bindings import _channel_history
    core, plan, bindings = _core_intent_binding_case()
    data = core.events[0].data
    row = data["outboundChannels"][0]
    if drift in {"ready", "applied"}: row["status"] = "Ready" if drift == "ready" else "Applied"
    elif drift in {"purpose", "proxy", "port", "provider", "region"}: row[drift] = "forged"
    elif drift == "chain": row["chainId"] = "chain-other"
    elif drift == "extra-row": data["outboundChannels"].append(copy.deepcopy(row))
    elif drift == "extra-field": row["configured"] = True
    elif drift == "missing-field": del row["edge"]
    elif drift == "missing-snapshot-key": del data["inboundChannels"]
    elif drift == "extra-event": core.events.insert(0, core.events[0])
    elif drift == "missing-event": core.events.pop(0)
    elif drift == "wrong-message": core.events[0] = replace(core.events[0], message="other")
    elif drift == "inbound": data["inboundChannels"] = [{"status": "Not Ready"}]
    elif drift == "another-job": core.id = "job-other"
    elif drift == "plan-region": plan.evidence["target"]["region"] = "other"
    elif drift == "plan-count": plan.evidence["proxyCount"] = 2
    elif drift == "boolean-count": core.input["proxyCount"] = True
    elif drift == "core-action": core.action = "engagement_channels_update"
    elif drift == "core-failed": core.status = "failed"
    elif drift == "terminal": core.events[-1].data["ok"] = 1
    elif drift == "domain": bindings["domains"] = (("assignment", "1", "hash"),)
    elif drift == "certificate": bindings["certificates"] = (("asset", "1", "hash"),)
    elif drift == "site": bindings["sites"] = (("service", "1", "hash"),)
    if drift not in {"another-job", "wrong-hash", "later-empty-removal"}:
        # Even a matching full raw-history fingerprint cannot authorize a
        # noncanonical intent, actual binding, or changed source.
        bindings["channels"] = _channel_history([core])
    if drift == "wrong-hash": bindings["channels"] = (("channel-mutation", core.id, "0" * 64),)
    elif drift == "later-empty-removal":
        other = copy.deepcopy(core)
        other.id = "job-later-removal"
        other.action = "engagement_channels_update"
        other.events = [replace(other.events[0], data={"inboundChannels": [], "outboundChannels": []})]
        bindings["channels"] = _channel_history([core, other])
    with pytest.raises((ValueError, KeyError)):
        _require_no_independent_failed_second_bindings(bindings, core, plan)
