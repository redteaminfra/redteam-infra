# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private group retirement requires a fresh GET and has a restart prefix."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_comprehensive_teardown as service
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.storage.job_repository import job_event_digest
from test_job_repository_keyed_provider_absent import proof as absent_proof, ready_row


class Jobs:
    def __init__(self, parent, child):
        self.rows = {parent.id: parent, child.id: child}

    def get(self, key):
        return self.rows.get(key)

    def list_for_engagement(self, _engagement_id):
        return list(self.rows.values())


class Chains:
    def __init__(self, jobs):
        self.jobs = jobs
        self.published = 0

    def publish_provider_keyed_group_retired(self, *, coordinator, authority, **kwargs):
        self.jobs.rows[coordinator.id] = replace(
            coordinator, input={**coordinator.input, "phase": "group_retired"})
        try:
            authority()
        except Exception:
            self.jobs.rows[coordinator.id] = coordinator
            raise
        self.published += 1
        return tuple(SimpleNamespace(**{**vars(row), "status": "destroyed",
                             "nodes": [], "teardown_job_id": kwargs["group_apply_job_id"]})
                     for row in kwargs["prior_chains"])


def setup(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    from app.services import sketch_state_workspaces
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: root)
    workspace = root / "group"
    workspace.mkdir()
    scope = {"chainIds": ["one", "two"]}
    snapshot = {"snapshotId": "a" * 64, "providerScopeSha256": "b" * 64,
                "providerScopes": [scope]}
    parent = SimpleNamespace(id="parent-1", target_id="eng-1",
        action="engagement_comprehensive_teardown", input={"scopeSnapshot": snapshot})
    core = SimpleNamespace(id="core-1", input={"corePlanId": "plan-1"})
    ready = replace(ready_row(), id=service._child_id(core.id))
    ids = {f'digitalocean_droplet.middle["{key}"]': value
           for key, value in (("one", "101"), ("two", "102"))}
    ids.update({f'digitalocean_droplet.edge["{key}"]': value
                for key, value in (("one", "201"), ("two", "202"))})
    ids["digitalocean_firewall.firewall"] = "11111111-1111-1111-1111-111111111111"
    ids["digitalocean_ssh_key.key"] = "789"
    preview = SimpleNamespace(id="preview-1", events=[JobEvent(1, "info", "preview", {})])
    apply = SimpleNamespace(id="apply-1", events=[JobEvent(1, "info", "apply", {})])
    intent = SimpleNamespace(resource_ids=ids, empty_state_sha256="3" * 64)
    data = {**absent_proof(ready),
            "previewJobId": preview.id,
            "previewJournalSha256": job_event_digest(preview.events),
            "applyJobId": apply.id,
            "applyJournalSha256": job_event_digest(apply.events),
            "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": sorted(("101", "102", "201", "202")),
            "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
            "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"],
            "observedAt": datetime.now(timezone.utc).isoformat()}
    child = replace(ready, input={**ready.input, "phase": "provider_absent"},
                    events=[*ready.events, JobEvent(6, "info", "provider_absent", data)])
    jobs = Jobs(parent, child)
    chain_rows = [SimpleNamespace(
        chain_id=key, status="deployed", nodes=[{"providerInstanceId": middle},
                                                 {"providerInstanceId": edge}],
        teardown_job_id="", deploy_job_id="job-initial",
        terraform_working_directory=str(workspace))
        for key, middle, edge in (("one", "101", "201"), ("two", "102", "202"))]
    current = list(chain_rows)

    def read(*_args, **_kwargs):
        return SimpleNamespace(parent=parent, core=core, scope=scope,
            workspace=SimpleNamespace(path=workspace), preview_job=preview,
            apply_job=apply, intent=intent, chains=tuple(current))

    from app.services import provider_keyed_destroy_absence_preflight as preflight
    monkeypatch.setattr(preflight, "_read_success_boundary", read)
    monkeypatch.setattr(service, "recognize_provider_keyed_destroy_absence",
                        lambda *_args, **_kwargs: jobs.get(child.id))
    resources = SimpleNamespace(list_for_engagement=lambda _id: [])
    chains = Chains(jobs)
    calls = []

    def get_absence(*_args, **_kwargs):
        calls.append("GET")
        return DigitalOceanAbsenceEvidence(
            intent.empty_state_sha256, tuple(sorted(("101", "102", "201", "202"))),
            ids["digitalocean_firewall.firewall"], ids["digitalocean_ssh_key.key"],
            True, 1)

    opts = dict(environment="devtest", state_root=root, job_repository=jobs,
        plan_repository=object(), sketch_repository=chains,
        credential_repository=object(), provider_resource_repository=resources,
        lease_lookup=lambda _id: ("plan-1", service._FENCE),
        absence_preflight=get_absence)
    return parent, child, jobs, chains, current, calls, opts, read


def test_fresh_get_then_one_group_publication(tmp_path, monkeypatch):
    parent, child, jobs, chains, _current, calls, opts, _read = setup(tmp_path, monkeypatch)
    rows = service.retire_provider_keyed_group_after_absence(parent.id, **opts)
    assert calls == ["GET"] and chains.published == 1
    assert [row.status for row in rows] == ["destroyed", "destroyed"]
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.retire_provider_keyed_group_after_absence(parent.id, **opts)
    assert calls == ["GET"] and chains.published == 1


def test_chain_drift_after_get_prevents_group_publication(tmp_path, monkeypatch):
    parent, child, jobs, chains, current, calls, opts, _read = setup(tmp_path, monkeypatch)
    normal_get = opts["absence_preflight"]

    def drift(*args, **kwargs):
        result = normal_get(*args, **kwargs)
        current[0] = replace(current[0], status="failed") if hasattr(
            current[0], "__dataclass_fields__") else SimpleNamespace(
                **{**vars(current[0]), "status": "failed"})
        return result

    opts["absence_preflight"] = drift
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.retire_provider_keyed_group_after_absence(parent.id, **opts)
    assert calls == ["GET"] and chains.published == 0
    assert jobs.get(child.id) == child


@pytest.mark.parametrize("drift_point", ["before_get", "during_get"])
def test_published_historical_source_drift_prevents_retirement(
    tmp_path, monkeypatch, drift_point,
):
    parent, child, jobs, chains, _current, calls, opts, read = setup(tmp_path, monkeypatch)
    parent.input["publishedSource"] = {"chain_projection_sha256": "a" * 64}
    from app.services import provider_keyed_teardown_source as source_module
    source_digest = ["first"]

    def historical(*_args, **_kwargs):
        if drift_point == "before_get":
            raise ValueError("historical source unproved")
        return SimpleNamespace(variant="published", digest=source_digest[0]), read()

    monkeypatch.setattr(source_module, "_read_published_post_destroy_boundary", historical)
    original_get = opts["absence_preflight"]

    def get_then_drift(*args, **kwargs):
        result = original_get(*args, **kwargs)
        source_digest[0] = "changed"
        return result

    opts["absence_preflight"] = get_then_drift
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.retire_provider_keyed_group_after_absence(parent.id, **opts)
    assert calls == ([] if drift_point == "before_get" else ["GET"])
    assert chains.published == 0
    assert jobs.get(child.id) == child


def test_restart_recognizes_group_prefix_without_get_or_apply(tmp_path, monkeypatch):
    parent, child, jobs, chains, current, calls, opts, read = setup(tmp_path, monkeypatch)
    bound = read()
    completed = datetime.now(timezone.utc)
    event = {
        "scopeSnapshotId": child.input["scopeSnapshotId"],
        "providerScopeSha256": child.input["providerScopeSha256"],
        "sourceJournalSha256": job_event_digest(child.events),
        "applyJobId": bound.apply_job.id,
        "resourceIdsSha256": _fingerprint(bound.intent.resource_ids),
        "verifiedAbsentDropletIds": sorted(("101", "102", "201", "202")),
        "verifiedAbsentFirewallId": bound.intent.resource_ids["digitalocean_firewall.firewall"],
        "verifiedAbsentSshKeyId": bound.intent.resource_ids["digitalocean_ssh_key.key"],
        "confirmationCompletedAt": completed.isoformat(),
        "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
        "chainIds": ["one", "two"], "retiredRecordIds": [],
        "observedAt": datetime.now(timezone.utc).isoformat(),
    }
    saved = replace(child, input={**child.input, "phase": "group_retired"},
                    events=[*child.events, JobEvent(7, "info", "keyed_provider_group_retired", event)])
    jobs.rows[child.id] = saved
    current[:] = [SimpleNamespace(**{**vars(row), "status": "destroyed",
                    "nodes": [], "teardown_job_id": bound.apply_job.id}) for row in current]
    recognized = service.recognize_provider_keyed_group_retired(
        parent.id, environment="devtest", state_root=opts["state_root"],
        job_repository=jobs, plan_repository=opts["plan_repository"],
        sketch_repository=chains, credential_repository=opts["credential_repository"],
        provider_resource_repository=opts["provider_resource_repository"],
        lease_lookup=opts["lease_lookup"])
    assert [row.status for row in recognized] == ["destroyed", "destroyed"]
    assert calls == []
    jobs.rows[child.id] = replace(saved, events=[*saved.events[:-1],
        replace(saved.events[-1], data={**event, "verifiedAbsentSshKeyId": "999"})])
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_provider_keyed_group_retired(
            parent.id, environment="devtest", state_root=opts["state_root"],
            job_repository=jobs, plan_repository=opts["plan_repository"],
            sketch_repository=chains, credential_repository=opts["credential_repository"],
            provider_resource_repository=opts["provider_resource_repository"],
            lease_lookup=opts["lease_lookup"])
    for altered in (
        replace(saved.events[-2], message="unrelated_absence"),
        replace(saved.events[-2], data={**saved.events[-2].data,
            "verifiedAbsentDropletIds": ["101", "102", "201", "999"]}),
        replace(saved.events[-2], data={**saved.events[-2].data,
            "verifiedAbsentFirewallId": "22222222-2222-2222-2222-222222222222"}),
        replace(saved.events[-2], data={**saved.events[-2].data,
            "verifiedAbsentSshKeyId": "999"}),
        replace(saved.events[-2], data={**saved.events[-2].data,
            "observedAt": (datetime.fromisoformat(
                saved.events[-2].data["confirmationExpiresAt"])
                + timedelta(seconds=1)).isoformat()}),
    ):
        jobs.rows[child.id] = replace(saved, events=[*saved.events[:-2],
                                                     altered, saved.events[-1]])
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
            service.recognize_provider_keyed_group_retired(
                parent.id, environment="devtest", state_root=opts["state_root"],
                job_repository=jobs, plan_repository=opts["plan_repository"],
                sketch_repository=chains, credential_repository=opts["credential_repository"],
                provider_resource_repository=opts["provider_resource_repository"],
                lease_lookup=opts["lease_lookup"])
    jobs.rows[child.id] = replace(saved, events=[*saved.events[:-1],
        replace(saved.events[-1], data={**event,
            "confirmationExpiresAt": (completed + timedelta(minutes=2)).isoformat()})])
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_provider_keyed_group_retired(
            parent.id, environment="devtest", state_root=opts["state_root"],
            job_repository=jobs, plan_repository=opts["plan_repository"],
            sketch_repository=chains, credential_repository=opts["credential_repository"],
            provider_resource_repository=opts["provider_resource_repository"],
            lease_lookup=opts["lease_lookup"])
