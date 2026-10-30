# Copyright (c) 2026, Oracle and/or its affiliates.
"""File-backed historical-negative checks with a scoped retired-receipt seam.

The negative proof/source fixture is real. The Linode terminal receipt is
injected here; its own canonical file-backed recognizer is covered separately.
"""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_inspector_negative as negative
from app.services import provider_keyed_inspector_linode_cleanup as linode
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_negative_composition import _case


def _completed(tmp_path, monkeypatch):
    state, parent, _ready, bound, _resources, core_absence = _case(tmp_path, monkeypatch)

    class Inspector:
        def run(self, *, host, ssh_key, spec):
            return {"ok": True, "results": [
                {"id": spec["positive"][0]["id"], "type": "tcp", "ok": True,
                 "expected": "reachable", "observed": ""},
                *[{"id": row["id"], "type": row["type"], "ok": True,
                   "expected": "closed",
                   "observed": {"status": "closed", "reason": "connection_refused"}}
                  for row in spec["negative"]],
            ]}

    proof = DigitalOceanAbsenceEvidence(
        bound.intent.empty_state_sha256, ("101", "102", "201", "202"),
        bound.intent.resource_ids["digitalocean_firewall.firewall"],
        bound.intent.resource_ids["digitalocean_ssh_key.key"], True, 1,
    )
    with db.bind(state):
        child = negative.prove_pending_keyed_inspector_negative(
            parent.id, environment="devtest", state_root=tmp_path,
            runner=Inspector(),
            positive_control={"id": "inspector-external-control", "type": "tcp",
                              "host": "4.2.2.2", "port": 443},
            ssh_key_factory=lambda _: SimpleNamespace(public_key="ssh-ed25519 test"),
            do_absence_reader=lambda *_a, **_k: proof,
            oci_absence_recognizer=lambda *_a, **_k: SqlAlchemyJobRepository().get(core_absence.id),
        )
        now = datetime.now(timezone.utc).isoformat()
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(parent.target_id)
        settings_repo.save(replace(settings, enabled=False, current_host={}))
        resources = SqlAlchemyProviderResourceRepository()
        host = resources.get(child.input["inspectorRecordId"])
        resources.save(replace(host, lifecycle_state="destroyed", status="destroyed",
                               destroyed_at=now))
        retired = SqlAlchemyJobRepository().save(StoredJobRun(
            "job-test-retired-inspector", linode.__name__, "succeeded",
            child.target, child.target_type, child.target_id, child.requested_by,
            {"negativeJobId": child.id,
             "negativeJournalSha256": job_event_digest(child.events),
             "negativeInputSha256": negative._sha(child.input),
             "hostRecordId": child.input["inspectorRecordId"],
             "hostId": child.input["inspectorResourceId"]},
            [], now, now, now, [JobEvent(1, "info", "fixture retired", {})],
        ))
    monkeypatch.setattr(linode, "recognize_pending_linode_inspector_retired",
                        lambda *_a, **_k: SqlAlchemyJobRepository().get(retired.id))
    return state, parent, child, retired


def test_historical_negative_restart_is_read_only(tmp_path, monkeypatch):
    state, parent, child, _retired = _completed(tmp_path, monkeypatch)
    with db.bind(db.configure(state.uri)):
        result = negative.recognize_historical_pending_keyed_inspector_negative(
            parent.id, environment="devtest")
        assert result == child
        assert len([row for row in SqlAlchemyJobRepository().list_for_engagement(parent.target_id)
                    if row.action == negative.ACTION]) == 1


@pytest.mark.parametrize("drift", [
    "target", "classification", "round", "identity", "absence", "control", "do_digest",
])
def test_historical_negative_rejects_forged_receipt(tmp_path, monkeypatch, drift):
    state, parent, child, retired = _completed(tmp_path, monkeypatch)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        if drift == "target":
            child = replace(child, input={**child.input, "targetSha256": "a" * 64})
        elif drift == "identity":
            child = replace(child, input={**child.input, "inspectorPublicIp": "8.8.4.4"})
        elif drift == "absence":
            child = replace(child, input={**child.input, "ociAbsenceJournalSha256": "a" * 64})
        elif drift == "control":
            child = replace(child, input={**child.input, "positiveControl": {
                **child.input["positiveControl"], "host": "5.5.5.5"}})
        elif drift == "do_digest":
            child = replace(child, input={**child.input,
                                          "freshDigitalOceanAbsenceSha256": "a" * 64})
        else:
            receipt = dict(child.events[-1].data)
            if drift == "classification":
                receipt["classifications"] = []
            else:
                rounds = list(receipt["rounds"])
                rounds[0] = {**rounds[0], "ok": False}
                receipt["rounds"] = rounds
            child = replace(child, events=[*child.events[:-1], replace(child.events[-1], data=receipt)])
        jobs.save(child)
        # Even a recomputed outer digest cannot make malformed inner evidence valid.
        jobs.save(replace(retired, input={**retired.input,
                                          "negativeJournalSha256": job_event_digest(child.events)}))
    with db.bind(db.configure(state.uri)):
        with pytest.raises(negative.KeyedInspectorNegativeAttention):
            negative.recognize_historical_pending_keyed_inspector_negative(
                parent.id, environment="devtest")
