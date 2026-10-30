# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private absence handoff never replays the successful provider destroy."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_comprehensive_teardown as service
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.storage.job_repository import job_event_digest
from test_job_repository_keyed_provider_absent import ready_row


class Jobs:
    def __init__(self, parent, child):
        self.rows = {parent.id: parent, child.id: child}
        self.publications = 0
        self.before_authority = None
        self.fail_before_publish = False

    def get(self, key):
        return self.rows.get(key)

    def list_for_engagement(self, _key):
        return list(self.rows.values())

    def publish_keyed_provider_absent_if_ready(self, child, *, proof,
                                               expected_event_digest, authority):
        if (self.rows[child.id] != child
                or job_event_digest(child.events) != expected_event_digest):
            return None
        if self.fail_before_publish:
            raise RuntimeError("crash before publication")
        self.rows[child.id] = replace(child, input={**child.input, "phase": "provider_absent"})
        try:
            if self.before_authority is not None:
                self.before_authority()
            authority()
        except Exception:
            self.rows[child.id] = child
            raise
        self.publications += 1
        self.rows[child.id] = replace(self.rows[child.id], events=[*child.events,
            JobEvent(len(child.events) + 1, "info", "provider_absent",
                     {**proof, "observedAt": "2026-10-08T00:00:00+00:00"})])
        return self.rows[child.id]


def fixture(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    from app.services import sketch_state_workspaces
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: root)
    core = SimpleNamespace(id="core-1", input={"corePlanId": "plan-1"})
    parent = SimpleNamespace(id="parent-1", target_id="eng-1",
                             action="engagement_comprehensive_teardown")
    scope = {"chainIds": ["one", "two"]}
    snapshot = {"snapshotId": "a" * 64, "providerScopeSha256": "b" * 64,
                "providerScopes": [scope]}
    parent.input = {"scopeSnapshot": snapshot}
    child = replace(ready_row(), id=service._child_id(core.id))
    jobs = Jobs(parent, child)
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        parent, core, snapshot, service._FENCE))
    ids = {"digitalocean_droplet.middle[\"one\"]": "123",
           "digitalocean_droplet.edge[\"one\"]": "456",
           "digitalocean_firewall.firewall": "11111111-1111-1111-1111-111111111111",
           "digitalocean_ssh_key.key": "789"}
    preview = SimpleNamespace(id="preview-1", events=[JobEvent(1, "info", "preview", {})])
    apply = SimpleNamespace(id="apply-1", events=[JobEvent(1, "info", "apply", {})])
    intent = SimpleNamespace(resource_ids=ids, empty_state_sha256="3" * 64)
    bound = SimpleNamespace(parent=parent, core=core, scope=scope,
                            preview_job=preview, apply_job=apply, intent=intent)
    calls = []

    def get_absence(*_args, **_kwargs):
        calls.append("GET")
        return DigitalOceanAbsenceEvidence(
            intent.empty_state_sha256, ("123", "456"),
            ids["digitalocean_firewall.firewall"], ids["digitalocean_ssh_key.key"],
            True, 1)

    def read(_parent_id):
        calls.append("read")
        return bound

    opts = dict(environment="devtest", state_root=root, job_repository=jobs,
                plan_repository=object(), sketch_repository=object(),
                credential_repository=object(),
                lease_lookup=lambda _key: ("plan-1", service._FENCE),
                retained_ready_recognizer=lambda *_args, **_kwargs: SimpleNamespace(
                    coordinator_job_id=child.id),
                absence_preflight=get_absence, boundary_reader=read)
    return parent, child, jobs, bound, calls, opts


def test_get_precedes_one_publication_and_duplicate_never_replays(tmp_path, monkeypatch):
    parent, child, jobs, _bound, calls, opts = fixture(tmp_path, monkeypatch)
    published = service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert published.input["phase"] == "provider_absent"
    assert calls.index("GET") < calls.index("read", calls.index("GET") + 1)
    assert calls.count("GET") == 2 and jobs.publications == 1
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert calls.count("GET") == 2 and jobs.publications == 1


def test_published_parent_cannot_use_boundary_only_reader(tmp_path, monkeypatch):
    parent, child, jobs, _bound, calls, opts = fixture(tmp_path, monkeypatch)
    parent.input = {**parent.input, "publishedSource": {"sealed": True}}
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert calls == []
    assert jobs.get(child.id) == child and jobs.publications == 0


def test_prepublication_drift_prevents_event(tmp_path, monkeypatch):
    parent, _child, jobs, bound, calls, opts = fixture(tmp_path, monkeypatch)

    def drift(*_args, **_kwargs):
        calls.append("GET")
        bound.intent.empty_state_sha256 = "9" * 64
        return DigitalOceanAbsenceEvidence("3" * 64, ("123", "456"),
            "11111111-1111-1111-1111-111111111111", "789", True, 1)

    opts["absence_preflight"] = drift
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert jobs.publications == 0
    assert jobs.get(service._child_id("core-1")).input["phase"] == "inspector_ready"


def test_restart_recognizes_persisted_prefix_without_provider_or_apply(tmp_path, monkeypatch):
    parent, _child, jobs, bound, calls, opts = fixture(tmp_path, monkeypatch)
    saved = service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    from app.services import provider_keyed_destroy_absence_preflight as preflight
    monkeypatch.setattr(preflight, "_read_success_boundary", lambda *_args, **_kwargs: bound)
    calls.clear()
    from app.storage.job_repository import _valid_provider_absent_handoff
    prior = replace(saved, input={**saved.input, "phase": "inspector_ready"},
                    events=saved.events[:-1])
    assert _valid_provider_absent_handoff(
        prior, job_event_digest(prior.events),
        {key: value for key, value in saved.events[-1].data.items() if key != "observedAt"})
    recognized = service.recognize_provider_keyed_destroy_absence(
        parent.id, environment="devtest", state_root=opts["state_root"],
        job_repository=jobs, plan_repository=opts["plan_repository"],
        sketch_repository=opts["sketch_repository"],
        credential_repository=opts["credential_repository"],
        lease_lookup=opts["lease_lookup"])
    assert recognized == saved and calls == []
    jobs.rows[saved.id] = replace(saved, events=[*saved.events[:-1],
        replace(saved.events[-1], data={**saved.events[-1].data,
            "verifiedAbsentSshKeyId": "999"})])
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_provider_keyed_destroy_absence(
            parent.id, environment="devtest", state_root=opts["state_root"],
            job_repository=jobs, plan_repository=opts["plan_repository"],
            sketch_repository=opts["sketch_repository"],
            credential_repository=opts["credential_repository"],
            lease_lookup=opts["lease_lookup"])


@pytest.mark.parametrize("stage_count", [4, 8])
def test_fresh_inspector_branch_uses_its_existing_ready_recognizer(
        tmp_path, monkeypatch, stage_count):
    parent, child, jobs, _bound, calls, opts = fixture(tmp_path, monkeypatch)
    messages = ["inspector_create_started", *(["inspector_create_stage"] * stage_count),
                "inspector_owned_unprepared", "inspector_prepare_started",
                "inspector selected-source proof published"]
    fresh = replace(child, input={**child.input,
        "claimOwner": "provider-keyed-inspector-ready-handoff"},
        events=[*child.events[:4], *[
            JobEvent(i + 5, "info", message, {}) for i, message in enumerate(messages)]])
    jobs.rows[child.id] = fresh
    opts["fresh_ready_recognizer"] = lambda *_args, **_kwargs: SimpleNamespace(
        coordinator_job_id=fresh.id)
    result = service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert result.input["phase"] == "provider_absent"
    assert calls.count("GET") == 2 and jobs.publications == 1


def test_second_independent_inventory_must_confirm_same_ids(tmp_path, monkeypatch):
    parent, _child, jobs, _bound, calls, opts = fixture(tmp_path, monkeypatch)
    original = opts["absence_preflight"]
    attempt_limits = []

    def second_differs(*args, **kwargs):
        attempt_limits.append(kwargs["max_attempts"])
        result = original(*args, **kwargs)
        return (result if calls.count("GET") == 1 else replace(
            result, verified_absent_ssh_key_id="999"))

    opts["absence_preflight"] = second_differs
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert calls.count("GET") == 2 and jobs.publications == 0
    assert attempt_limits == [12, 1]


def test_crash_before_cas_repeats_only_get_proof(tmp_path, monkeypatch):
    parent, child, jobs, _bound, calls, opts = fixture(tmp_path, monkeypatch)
    jobs.fail_before_publish = True
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert jobs.get(child.id) == child and calls.count("GET") == 2
    jobs.fail_before_publish = False
    service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert calls.count("GET") == 4 and jobs.publications == 1


def test_writer_transaction_parent_change_rolls_back_event(tmp_path, monkeypatch):
    parent, child, jobs, _bound, calls, opts = fixture(tmp_path, monkeypatch)
    jobs.before_authority = lambda: jobs.rows.__setitem__(parent.id, SimpleNamespace(
        **{**vars(parent), "target_id": "different-engagement"}))
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.publish_provider_keyed_destroy_absence(parent.id, **opts)
    assert jobs.get(child.id) == child
    assert jobs.publications == 0 and calls.count("GET") == 2
