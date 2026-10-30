# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published Inspector uses the exact post-OCI negative proof path."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.observer_checks import (
    INSPECTOR_ADMIN_IDENTITY_VERSION, INSPECTOR_ADMIN_USER,
    INSPECTOR_DEFAULT_SUPPORT_PACKAGES, INSPECTOR_SUPPORT_PREPARATION_VERSION,
    ObserverHost, ObserverSshKey, _record_inspector_resource,
)
from app.storage.observer_settings_repository import StoredInspectorSettings
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_oci_absence import _ready
from test_provider_keyed_mixed_zero_apply_core_absence import _absent
import app.services.provider_keyed_mixed_zero_apply_core_absence as absence
import app.services.provider_keyed_mixed_zero_apply_inspector_negative as negative


CONTROL = {"id": "inspector-external-control", "type": "tcp",
           "host": "1.1.1.1", "port": 443}


def _proof(client, ready, tmp_path, monkeypatch):
    source, jobs, calls, _, options = _ready(client, ready, tmp_path, monkeypatch)
    receipt = absence.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **options,
        absence_prover=_absent)
    core = jobs.get(source.core_job_id)
    details = [{"role": "homebase", "publicIp": "8.8.8.8"},
               {"role": "proxy", "publicIp": "9.9.9.9"}]
    events = [core.events[0],
              JobEvent(2, "info", "operator inspection ready",
                       {"connectionDetails": details}),
              replace(core.events[-2], sequence=3),
              JobEvent(4, "info", "pilot Standard RTI run finished",
                       {"connectionDetails": details})]
    jobs.save(replace(core, events=events))
    host = ObserverHost(
        "linode", "instance", "100", "inspector-opaque", "us-east", "4.4.4.4",
        INSPECTOR_ADMIN_USER, "running", {
            "adminIdentityVersion": INSPECTOR_ADMIN_IDENTITY_VERSION,
            "rootLoginDisabled": True,
            "supportPreparationVersion": INSPECTOR_SUPPORT_PREPARATION_VERSION,
            "supportPreparedPackages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES),
            "providerFirewall": {"provider": "linode", "resourceType": "firewall",
                                 "resourceId": "200", "name": "inspector-firewall-opaque",
                                 "managementSourceCidr": "8.8.8.8/32"},
        })
    settings = StoredInspectorSettings(
        source.engagement_id, True, "linode", "us-east", "g6-nanode-1",
        "continuous", [], "00:00", [], [], [], host.to_dict(), "", "", "",
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")
    rows = []
    _record_inspector_resource(SimpleNamespace(save=lambda row: rows.append(row)),
                               source.engagement_id, "Opaque", host,
                               "job-inspector-ready", status="active")
    ids = options["post_source_reader"]().owned_inspector_record_ids
    rows = [replace(row, id=ids[0 if row.resource_type == "inspector_instance" else 1])
            for row in rows]
    scans = []

    class Runner:
        def run(self, *, host, ssh_key, spec):
            scans.append(spec["negative"])
            return {"ok": True, "results": [
                {"id": CONTROL["id"], "type": "tcp", "expected": "reachable",
                 "observed": "", "ok": True},
                *[{"id": target["id"], "type": "tcp-forbidden",
                   "expected": "closed", "observed": {
                       "status": "closed", "reason": "connection_refused"}, "ok": True}
                  for target in spec["negative"]]]}

    proof_options = dict(
        environment="devtest", state_root=options["state_root"],
        core_state_root=options["core_state_root"], positive_control=CONTROL,
        job_repository=jobs, plan_repository=options["plan_repository"],
        settings_repository=SimpleNamespace(get=lambda _: settings),
        provider_resource_repository=SimpleNamespace(list_for_engagement=lambda _: rows),
        lease_lookup=options["lease_lookup"], runner=Runner(),
        ssh_key_factory=lambda _: ObserverSshKey(str(tmp_path / "inspector-key"),
                                                 "ssh-ed25519 offline"),
        identity_reader=lambda: {}, published=True,
        post_source_reader=options["post_source_reader"])
    return source, receipt, jobs, calls, scans, proof_options


def test_published_inspector_negative_runs_two_rounds_and_reuses_receipt(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, receipt, jobs, calls, scans, options = _proof(
            client, ready, tmp_path, monkeypatch)
        result = negative.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options)
        assert result.status == "succeeded" and len(scans) == 2
        assert result.input["ociAbsenceJobId"] == receipt.id
        assert result.input["sourceSha256"] == jobs.get(result.input[
            "teardownParentId"]).input["publishedSourceSha256"]
        assert calls == ["show", "apply"]
        options["runner"] = SimpleNamespace(run=lambda **kwargs: pytest.fail("reprobed"))
        assert negative.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **options) == result


def test_published_inspector_negative_vetoes_overlapping_control_without_probe(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, _, jobs, calls, scans, options = _proof(
            client, ready, tmp_path, monkeypatch)
        options["positive_control"] = {**CONTROL, "host": "8.8.8.8"}
        with pytest.raises(negative.MixedZeroApplyInspectorNegativeAttention):
            negative.prove_mixed_zero_apply_inspector_negative(
                source.engagement_id, source.core_job_id, **options)
        assert scans == [] and calls == ["show", "apply"]


def test_failed_second_extra_edge_reaches_actual_negative_writer_and_saved_terminal_reader(client,ready,tmp_path,monkeypatch):
    """Source authority is a controlled witness; the negative writer/reader are real.

    The actual five-node source and SQL source rechecks have separate workflow
    coverage. This seam proves both Inspector rounds and the saved terminal
    consumer agree on the additional unpublished endpoint, without a network.
    """
    import copy
    import app.services.provider_keyed_mixed_published_terminal as terminal
    with client.application.storage_context():
        source,absent,jobs,calls,scans,options=_proof(client,ready,tmp_path,monkeypatch)
        original=negative._authority
        recovery={"kind":"failed-second-v1","currentResourceIds":{"linode":{
            "linode_instance.middle":"retained-middle",'linode_instance.edge["append"]':"999999"}},
            "source":{"provider_states":[{"provider":"linode","resource_ids":[["linode_instance.middle","retained-middle"]]}]},
            "retiredEndpoints":[{"provider":"linode","providerInstanceId":"999999","publicIp":"45.33.62.72"}]}
        authority_rows=[]
        def authenticated(*args,**kwargs):
            rows=original(*args,**kwargs)
            parent=replace(rows[0],input={**rows[0].input,"failedAppendRecovery":copy.deepcopy(recovery)})
            result=(parent,*rows[1:])
            authority_rows[:] = [result]
            return result
        monkeypatch.setattr(negative,"_authority",authenticated)
        proved=negative.prove_mixed_zero_apply_inspector_negative(source.engagement_id,source.core_job_id,**options)
        assert proved.status=="succeeded" and len(scans)==2
        assert all(len(round_targets)==3 and any(row["host"]=="45.33.62.72" for row in round_targets) for round_targets in scans)
        parent,core,_initial,preview,applied,plan,*_=authority_rows[0]
        terminal._saved_public_receipts(parent,core,plan,preview,applied,absent,proved)
        options["runner"]=SimpleNamespace(run=lambda **kwargs:pytest.fail("completed negative proof replayed"))
        assert negative.prove_mixed_zero_apply_inspector_negative(source.engagement_id,source.core_job_id,**options)==proved
        for count in (2,True):
            forged=replace(proved,input={**proved.input,"targetCount":count})
            with pytest.raises(ValueError):terminal._saved_public_receipts(parent,core,plan,preview,applied,absent,forged)
        event=proved.events[-1]
        missing=copy.deepcopy(event.data)
        for round_data in missing["rounds"]:
            round_data["results"]=[row for row in round_data["results"] if row["id"]!="tcp:45.33.62.72:22"]
        forged=replace(proved,events=[*proved.events[:-1],replace(event,data=missing)])
        with pytest.raises(ValueError):terminal._saved_public_receipts(parent,core,plan,preview,applied,absent,forged)
        for endpoint in (
            {"provider":"linode","providerInstanceId":"retained-middle","publicIp":"45.33.62.72"},
            {"provider":"linode","providerInstanceId":"999999","publicIp":"45.33.62.73"},
        ):
            changed=copy.deepcopy(recovery)
            changed["retiredEndpoints"]=[endpoint]
            with pytest.raises(ValueError):
                terminal._saved_public_receipts(replace(parent,input={**parent.input,"failedAppendRecovery":changed}),core,plan,preview,applied,absent,proved)
        extra=copy.deepcopy(recovery)
        extra["retiredEndpoints"].append(dict(extra["retiredEndpoints"][0]))
        with pytest.raises(ValueError):
            terminal._saved_public_receipts(replace(parent,input={**parent.input,"failedAppendRecovery":extra}),core,plan,preview,applied,absent,proved)
