# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only persisted selector success checks; no second DELETE authority."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_selector_retirement as service
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository
from test_provider_keyed_selector_retirement import _case


def _retired(tmp_path, monkeypatch):
    jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    finished = service.retire_pending_digitalocean_selector(parent.id, **options)
    assert finished.status == "succeeded" and deleter.calls == 1
    options["job_repository"] = SqliteJobRepository(jobs.database_path)
    options.pop("delete_transport")
    options["status_transport"] = deleter
    return parent, catalog, deleter, options, finished


def test_saved_success_reproves_complete_absence_after_restart(tmp_path, monkeypatch):
    parent, catalog, deleter, options, finished = _retired(tmp_path, monkeypatch)
    recognized = service.recognize_pending_digitalocean_selector_retired(
        parent.id, **options)
    assert recognized == finished and deleter.calls == 1
    assert catalog.calls.count("/tags/" + catalog.selector) == 1  # before DELETE
    assert sum(path.startswith("/tags?page=") for path in catalog.calls) >= 2
    assert catalog.database_reads == 0


def test_sqlalchemy_file_reservation_survives_timestamp_roundtrip(
        tmp_path, monkeypatch):
    source_jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    state = db.configure(f"sqlite:///{tmp_path / 'selector.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        for row in source_jobs.list_for_engagement(parent.target_id):
            jobs.save(row)
        before = service._read_success_boundary(parent.id)
        bound = SimpleNamespace(**{**vars(before), "parent": jobs.get(before.parent.id),
                                   "core": jobs.get(before.core.id)})
        monkeypatch.setattr(service, "_read_success_boundary", lambda *args, **kwargs: bound)
        absence_id = f"job-provider-keyed-core-destroy-absence-{bound.core.id.removeprefix('job-')}-attempt-01"
        options["core_absence_recognizer"] = lambda *args, **kwargs: jobs.get(absence_id)
        options["job_repository"] = jobs
        finished = service.retire_pending_digitalocean_selector(parent.id, **options)
        assert finished.status == "succeeded" and deleter.calls == 1
        assert jobs.get(finished.id) == finished
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        assert SqlAlchemyJobRepository().get(finished.id) == finished


@pytest.mark.parametrize("drift", ["member", "null_volume",
                                    "firewall", "tag_present", "pagination", "auth",
                                    "journal", "credential", "initial_action",
                                    "initial_actor"])
def test_saved_success_rejects_current_visibility_or_authority_drift(
        tmp_path, monkeypatch, drift):
    parent, catalog, deleter, options, finished = _retired(tmp_path, monkeypatch)
    if drift == "member":
        original = catalog.request
        def member(base, method, path, token):
            data = original(base, method, path, token)
            if path.startswith("/volumes?"):
                return {"volumes": [{"id": "volume-1", "tags": [catalog.selector]}],
                        "meta": {"total": 1}, "links": {"pages": {}}}
            return data
        catalog.request = member
    elif drift == "null_volume":
        original = catalog.request
        def null_volume(base, method, path, token):
            data = original(base, method, path, token)
            if path.startswith("/volumes?"):
                return {"volumes": [{"id": "volume-1", "tags": None}],
                        "meta": {"total": 1}, "links": {"pages": {}}}
            return data
        catalog.request = null_volume
    elif drift == "firewall":
        catalog.firewall_reference = True
    elif drift == "tag_present":
        catalog.tag_present = True
    elif drift in {"pagination", "auth"}:
        original = catalog.request
        def broken(base, method, path, token):
            if path.startswith("/images?"):
                if drift == "auth":
                    raise PermissionError("provider scope denied")
                return {"images": [], "meta": {"total": 1},
                        "links": {"pages": {}}}
            return original(base, method, path, token)
        catalog.request = broken
    elif drift == "journal":
        jobs = options["job_repository"]
        jobs.save(replace(finished, events=[*finished.events[:-1], replace(
            finished.events[-1], data={"httpStatus": 204, "selectorTag": "forged"})]))
    elif drift in {"initial_action", "initial_actor"}:
        jobs = options["job_repository"]
        initial = jobs.get(service._job_ids(finished.input["coreJobId"])[0])
        jobs.save(replace(initial, **({"action": "unrelated"} if drift == "initial_action"
                                    else {"requested_by": "another-operator"})))
    else:
        monkeypatch.setattr(service, "_credential_snapshot",
                            lambda *args: ("different", "2026-10-09T00:00:00+00:00", "encrypted"))
    with pytest.raises(service.SelectorRetirementAttention):
        service.recognize_pending_digitalocean_selector_retired(
            parent.id, **options)
    assert deleter.calls == 1
