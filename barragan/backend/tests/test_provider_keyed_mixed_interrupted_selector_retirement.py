# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline selector one-shot intent and restart under a sealed mixed parent."""

from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_interrupted_selector_retirement as service
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as apply_child_id, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
from app.storage.job_repository import StoredJobRun
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.models import JobRunModel
from sqlalchemy import update
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_interrupted_post_sketch_absence import _sealed


@pytest.mark.parametrize("case", [False], indirect=True)
@pytest.mark.parametrize("lost_response", [False, True])
def test_tag_only_selector_delete_is_one_shot_and_terminal_restart_is_read_only(
        ready, monkeypatch, tmp_path, lost_response):
    initial = ready.parent
    with pytest.raises(RuntimeError):
        run_mixed_initial_provider_apply(
            provider="digitalocean",
            **{**ready.args, "gated_command_runner": lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("stopped before Apply"))})
    original = ready.case.jobs.get(apply_child_id(initial.input["coreJobId"], "digitalocean"))
    order = initial.input["orderedProviders"]
    review = review_mixed_interrupted_source(
        initial, {"digitalocean": original, "linode": None},
        {"digitalocean": _snapshot("digitalocean", tag=True),
         "linode": _snapshot("linode")},
        fence=lambda: "stable", process_quiescent=lambda _identity: True)
    parent, _ = _sealed(initial, review)
    ready.case.jobs.save(parent)
    engagement_id, core_id = initial.target_id, initial.input["coreJobId"]

    def terminal(identifier, action, input_data):
        row = StoredJobRun(identifier, action, "succeeded", f"engagement:{engagement_id}",
                           "engagement", engagement_id, parent.requested_by,
                           input_data, [], "2026-10-15T00:00:00+00:00",
                           "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:01+00:00",
                           [JobEvent(1, "info", "terminal", {})])
        ready.case.jobs.save(row)
        return row

    absent = terminal(
        f"{service.absence_prefix(core_id)}-attempt-01", service.OCI_ABSENCE_ACTION, {})
    negative = terminal(service.negative_id(core_id), service.NEGATIVE_ACTION,
                        {"positiveControl": {"id": "inspector-external-control",
                                              "type": "tcp", "host": "1.1.1.1", "port": 443}})
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "_read_empty_membership",
                        lambda *_a, tag_present, **_k: [] if tag_present == visible["tag"]
                        else pytest.fail("wrong tag presence phase"))
    visible = {"tag": True}
    calls = []

    class Delete:
        def delete_tag(self, token, selector):
            calls.append("DELETE")
            visible["tag"] = False
            if lost_response:
                raise TimeoutError("response lost after provider deletion")
            return service.DeleteResponse(204, b"")

        def get_tag_status(self, token, selector):
            calls.append("GET")
            return 404 if not visible["tag"] else 200

    old_jobs = ready.case.jobs
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-selector.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id=engagement_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=engagement_id, owner_id=parent.input["corePlanId"],
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in old_jobs.list_for_engagement(engagement_id):
            def normalized(value):
                return "2026-10-15T00:00:00+00:00" if value == "now" else value
            jobs.save(replace(row, created_at=normalized(row.created_at),
                              started_at=normalized(row.started_at),
                              finished_at=normalized(row.finished_at)))
        options = dict(environment="devtest", state_root=ready.case.state_root,
                       core_state_root=ready.case.state_root,
                       job_repository=jobs,
                       plan_repository=ready.case.args["plan_repository"],
                       credential_repository=ready.case.args["credential_repository"],
                       lease_lookup=lambda _eng: (parent.input["corePlanId"],
                                                  "provider_keyed_teardown_fence"),
                       catalog_transport=object(), delete_transport=Delete(),
                       decrypt_secret=lambda encrypted: encrypted,
                       inventory_collector=lambda *_a, **kw: _snapshot(
                           "digitalocean", tag=visible["tag"], generation=kw["fence"]()),
                       process_quiescent=lambda _identity: True,
                       oci_absence_recognizer=lambda *_a, **_k: jobs.get(absent.id),
                       negative_recognizer=lambda *_a, **_k: jobs.get(negative.id))
        if lost_response:
            with pytest.raises(service.MixedInterruptedSelectorRetirementAttention):
                service.retire_mixed_interrupted_selector(engagement_id, core_id, **options)
            uncertain = jobs.get(service._child_id(core_id))
            assert [event.message for event in uncertain.events][-1] == (
                "mixed interrupted selector DELETE intended")
            assert calls == ["DELETE"]
            db.session.execute(update(JobRunModel).where(JobRunModel.id == uncertain.id).values(
                input={**uncertain.input, "claimExpiresAt": "2026-01-01T00:00:00+00:00"}))
            db.session.commit()
        result = service.retire_mixed_interrupted_selector(engagement_id, core_id, **options)
        assert result.status == "succeeded"
        assert calls == (["DELETE", "GET"] if lost_response else ["DELETE", "GET"])
        again = service.retire_mixed_interrupted_selector(engagement_id, core_id, **options)
        assert again == result and calls == ["DELETE", "GET", "GET"]
        assert service.retire_mixed_interrupted_selector(
            engagement_id, core_id, **{**options, "historical_negative": True,
                                     "negative_recognizer": lambda *_a, **_k:
                                     pytest.fail("negative probe replayed")}) == result
        assert calls == ["DELETE", "GET", "GET", "GET"]
