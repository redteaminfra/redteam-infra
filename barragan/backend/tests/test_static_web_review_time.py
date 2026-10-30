# Copyright (c) 2026, Oracle and/or its affiliates.
"""Content-review freshness must survive the real SQLite job round trip."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import subprocess

import pytest

from app.services import web_static_service as service
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from test_web_static_service import _core_jobs


NOW = datetime(2026, 10, 28, 18, 0, tzinfo=timezone.utc)


@pytest.fixture
def persisted_review(tmp_path, monkeypatch):
    state = db.configure(f"sqlite:///{tmp_path / 'reviews.sqlite'}")
    monkeypatch.setattr(service, "get_engagement", lambda _: type("Engagement", (), {"name": "opaque"})())
    monkeypatch.setattr(service, "_ensure_known_hosts_file", lambda _: None)
    monkeypatch.setattr("app.services.inbound_request_header_gate.load_active_https_request_header_gate_for_service", lambda *_args, **_kwargs: None)
    calls = []
    def inspection_runner(command, cwd):
        calls.append(command)
        assert command[0] == "ssh"
        return subprocess.CompletedProcess(command, 0, json.dumps({"state": "existing", "fingerprint": "a" * 64}), "")
    with db.bind(state):
        db.create_all()
        repo = SqlAlchemyJobRepository()
        repo.save(_core_jobs()[0])
        body = {"siteName": "site01", "domain": "opaque.example.invalid", "proxyId": "proxy01"}
        preview = service.preview_web_static_service_apply("eng-zy01", body, repository=repo, runner=inspection_runner)
        db.session.remove()
        review_id = preview["contentReview"]["reviewJobId"]
        saved = repo.get(review_id)
        # Assert that the regression exercises production SQLite serialization,
        # rather than an in-memory repository that preserves timezone offsets.
        assert datetime.fromisoformat(saved.created_at).tzinfo is None
        homebase, proxy = service._core_apply_hosts(repo, "eng-zy01", "proxy01")
        yield repo, {**body, "contentReviewJobId": review_id}, homebase, proxy, inspection_runner, calls
    state.engine.dispose()


def _authorize(fixture, actor="operator"):
    repo, body, homebase, proxy, runner, _ = fixture
    return service._authorize_content_apply(repo, "eng-zy01", service._intent_from_body("opaque", body), body, actor, homebase, proxy, runner)


def test_fresh_sqlite_persisted_preview_authorizes_apply(persisted_review):
    assert _authorize(persisted_review).content_action == "preserve"
    assert len(persisted_review[-1]) == 2  # Preview and pre-Apply remote recheck.


def test_expired_sqlite_persisted_review_still_fails_closed(persisted_review):
    repo, body, *_ = persisted_review
    review = repo.get(body["contentReviewJobId"])
    repo.save(replace(review, created_at=(datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()))
    db.session.remove()
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(persisted_review)
    assert len(persisted_review[-1]) == 1  # Stale review must not inspect or mutate.


@pytest.mark.parametrize("timestamp,allowed", [
    ((NOW - timedelta(minutes=15)).replace(tzinfo=None).isoformat(), True),
    ((NOW - timedelta(minutes=15, microseconds=1)).replace(tzinfo=None).isoformat(), False),
    ((NOW - timedelta(minutes=15)).isoformat(), True),
    ((NOW - timedelta(minutes=15, microseconds=1)).isoformat(), False),
    ((NOW - timedelta(minutes=1)).astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat(), True),
    ((NOW - timedelta(minutes=16)).astimezone(timezone(timedelta(hours=-4))).isoformat(), False),
    ("not-a-timestamp", False),
    ("", False),
    (None, False),
])
def test_freshness_cutoff_normalizes_utc_and_offsets_and_rejects_invalid(persisted_review, monkeypatch, timestamp, allowed):
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)
    monkeypatch.setattr(service, "datetime", FixedDateTime)
    repo, body, *_ = persisted_review
    get = repo.get
    review_id = body["contentReviewJobId"]
    # Keep the genuine persisted preview/binding; exercise alternate repository
    # timestamp representations only at this service's freshness boundary.
    monkeypatch.setattr(repo, "get", lambda job_id: replace(get(job_id), created_at=timestamp) if job_id == review_id else get(job_id))
    if allowed:
        assert _authorize(persisted_review).content_review_job_id == review_id
        assert len(persisted_review[-1]) == 2
    else:
        with pytest.raises(service.WebStaticServiceValidationError):
            _authorize(persisted_review)
        assert len(persisted_review[-1]) == 1


def test_fresh_persisted_review_does_not_relax_actor_or_site_binding(persisted_review):
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(persisted_review, actor="another_operator")
    persisted_review[1]["siteName"] = "another-site"
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(persisted_review)
    assert len(persisted_review[-1]) == 1
