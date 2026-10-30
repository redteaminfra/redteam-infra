# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_runtime_preflight
from app.domain.deployment_plan import DeploymentPlan
from app.domain.job import JobEvent
from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
from app.integrations.pilot_standard_rti import pilot_names
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_runtime_preflight import (
    ProviderKeyedRuntimePreflightError,
    preflight_fresh_digitalocean_provider,
)
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


@pytest.fixture(autouse=True)
def _configured_state_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        provider_keyed_runtime_preflight, "_default_state_root",
        lambda: tmp_path / "sketch-state",
    )


def _chain(identifier: str, proxy: str, region: str) -> StoredSketchChain:
    return StoredSketchChain(
        chain_id=identifier, engagement_id="eng-opaque", assigned_proxy=proxy,
        middle_provider="digitalocean", middle_region="nyc3", middle_size="s-1vcpu-1gb",
        edge_provider="digitalocean", edge_region=region, edge_size="s-1vcpu-1gb",
        status="pending", burned=False, burned_note="", deploy_job_id="", teardown_job_id="",
        terraform_working_directory="", nodes=[], created_at="", updated_at="", edge_count=1,
        edge_intents=[{"id": "edge-01", "provider": "digitalocean", "region": region, "size": "s-1vcpu-1gb"}],
    )


def _records():
    target = normalized_oci_deployment_target("barragan-testing")
    engagement = StoredEngagement(
        id="eng-opaque", name="m4t8q2z7", status="deployed", owner="operator",
        template_id="small-dev", active_revision="rev-1",
        input_parameters={"deploymentTarget": target}, sketch_state_schema="provider-keyed-v2",
    )
    chains = [
        _chain("proxy01-sfo-01", "proxy01", "sfo3"),
        _chain("proxy02-sea-01", "proxy02", "sfo3"),
    ]
    ids = [chain.chain_id for chain in chains]
    fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in chains}
    evidence = {
        "sketchStateSchema": "provider-keyed-v2", "managedHostImageProfile": "ubuntu-22.04",
        "digitaloceanImage": "ubuntu-22-04-x64", "target": target,
        "pendingSketchChainIds": ids, "pendingSketchChainFingerprints": fingerprints,
        "sshSourceCidrs": ["203.0.113.10/32"],
    }
    job = StoredJobRun(
        id="job-core", action="pilot_standard_rti_guarded_execute", status="succeeded",
        target=f"oci-compartment:{target['name']}", target_type="oci_compartment",
        target_id=target["compartmentId"],
        requested_by="operator",
        input={
            "engagementId": engagement.id, "engagementName": engagement.name,
            "sketchStateSchema": "provider-keyed-v2", "postCoreSketchContinuationEligible": False,
            "corePlanId": "plan-core", "target": target, "proxyCount": 2,
            "pendingSketchChainIds": ids, "pendingSketchChainFingerprints": fingerprints,
            "sshSourceCidrs": ["203.0.113.10/32"],
        },
        artifact_refs=[], created_at="", started_at="", finished_at="", events=[JobEvent(
            1, "info", "core deployed", {"mutationStatus": "deployed", "connectionDetails": [
                {"role": "proxy", "displayName": pilot_names(engagement.name).proxy_name,
                 "sshAlias": pilot_names(engagement.name).proxy_name, "publicIp": "8.8.8.8"},
                {"role": "proxy", "displayName": pilot_names(engagement.name).proxy02_name,
                 "sshAlias": pilot_names(engagement.name).proxy02_name, "publicIp": "9.9.9.9"},
            ]},
        )],
    )
    plan = DeploymentPlan(
        "plan-core", engagement.id, "rev-1", "applied", "applied",
        evidence=evidence, apply_job_id=job.id,
    )
    return engagement, chains, job, plan


def _preflight(tmp_path: Path, *, records=None, chain_reader=None, lease_lookup=None,
               jobs_for_engagement=None, all_jobs=None):
    engagement, chains, job, plan = records or _records()
    job_history = all_jobs or (lambda: [job])

    def scoped_history(engagement_id):
        extra = jobs_for_engagement(engagement_id) if jobs_for_engagement else []
        return [row for row in [*extra, *job_history()]
                if row.input.get("engagementId") == engagement_id]

    return preflight_fresh_digitalocean_provider(
        engagement.id, job.id, lease_owner="provider-job", environment="devtest",
        state_root=tmp_path / "sketch-state",
        engagement_repository=SimpleNamespace(get=lambda _id: engagement),
        sketch_repository=SimpleNamespace(list_for_engagement=chain_reader or (lambda _id: chains)),
        job_repository=SimpleNamespace(
            get=lambda _id: job,
            list=job_history,
            list_for_engagement=scoped_history,
        ),
        plan_repository=SimpleNamespace(get=lambda _id: plan),
        lease_lookup=lease_lookup or (lambda _id: ("provider-job", "provider_keyed_initial")),
    )


def test_preflight_compiles_complete_current_reviewed_intent_without_writing(tmp_path: Path):
    root = tmp_path / "sketch-state"
    result = _preflight(tmp_path)
    assert result.provider == "digitalocean"
    assert [route.chain_id for route in result.chain_routes] == ["proxy01-sfo-01", "proxy02-sea-01"]
    assert result.chain_routes[0].edge_nodes == ("sfo3-01",)
    assert result.chain_routes[1].edge_nodes == ("sfo3-02",)
    assert not root.exists()


def test_preflight_rejects_extra_current_chain_even_when_reviewed_pair_matches(tmp_path: Path):
    engagement, chains, job, plan = _records()
    extra = _chain("proxy03-nyc-01", "proxy01", "nyc3")
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="exactly two"):
        _preflight(tmp_path, records=(engagement, [*chains, extra], job, plan))


def test_preflight_ignores_only_inert_aborted_template_ghost(tmp_path: Path):
    engagement, chains, job, plan = _records()
    ghost = replace(_chain("proxy01-old-01", "proxy01", "nyc3"), status="aborted")
    result = _preflight(tmp_path, records=(engagement, [ghost, *chains], job, plan))
    assert len(result.chain_routes) == 2
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="exactly two"):
        _preflight(tmp_path, records=(engagement, [replace(ghost, nodes=[{"id": "retained"}]), *chains], job, plan))
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="exactly two"):
        _preflight(tmp_path, records=(engagement, [replace(ghost, status="destroyed"), *chains], job, plan))
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="exactly two"):
        _preflight(tmp_path, records=(engagement, [replace(ghost, engagement_id="other"), *chains], job, plan))


def test_preflight_rejects_missing_or_lost_lease(tmp_path: Path):
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="lease is not held"):
        _preflight(tmp_path, lease_lookup=lambda _id: None)
    calls = 0

    def lost_on_recheck(_id):
        nonlocal calls
        calls += 1
        return ("provider-job", "provider_keyed_initial") if calls == 1 else None

    with pytest.raises(ProviderKeyedRuntimePreflightError, match="lease is not held"):
        _preflight(tmp_path, lease_lookup=lost_on_recheck)


def test_preflight_rejects_queued_teardown_before_lease_claim(tmp_path: Path):
    engagement, chains, core_job, plan = _records()
    teardown = replace(
        core_job, id="job-teardown", action="engagement_comprehensive_teardown",
        status="queued", target=f"engagement:{engagement.id}",
        target_type="engagement", target_id=engagement.id,
    )
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="teardown is queued or running"):
        _preflight(
            tmp_path, records=(engagement, chains, core_job, plan),
            jobs_for_engagement=lambda _id: [teardown],
        )


def test_preflight_rejects_teardown_queued_during_compilation(tmp_path: Path):
    engagement, chains, core_job, plan = _records()
    teardown = replace(
        core_job, id="job-teardown", action="engagement_comprehensive_teardown",
        status="queued", target=f"engagement:{engagement.id}",
        target_type="engagement", target_id=engagement.id,
    )
    checks = 0

    def jobs_for_engagement(_id):
        nonlocal checks
        checks += 1
        return [] if checks == 1 else [teardown]

    with pytest.raises(ProviderKeyedRuntimePreflightError, match="teardown is queued or running"):
        _preflight(
            tmp_path, records=(engagement, chains, core_job, plan),
            jobs_for_engagement=jobs_for_engagement,
        )


def test_preflight_rejects_existing_workspace_or_state(tmp_path: Path):
    root = tmp_path / "sketch-state"
    (root / "eng-opaque" / "provider-keyed-v2" / "digitalocean").mkdir(parents=True)
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="no existing Sketch provider workspace or state"):
        _preflight(tmp_path)


def test_preflight_rejects_symlinked_state_root(tmp_path: Path):
    actual = tmp_path / "actual"
    actual.mkdir()
    (tmp_path / "sketch-state").symlink_to(actual, target_is_directory=True)
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="not canonical"):
        _preflight(tmp_path)


def test_preflight_rejects_unrelated_empty_state_root(tmp_path: Path):
    engagement, _chains, job, _plan = _records()
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="configured runtime root"):
        preflight_fresh_digitalocean_provider(
            engagement.id, job.id, lease_owner="provider-job", environment="devtest",
            state_root=tmp_path / "unrelated-empty-directory",
            lease_lookup=lambda _id: ("provider-job", "provider_keyed_initial"),
        )


def test_preflight_rejects_chain_change_during_read(tmp_path: Path):
    engagement, chains, job, plan = _records()
    reads = 0

    def chain_reader(_id):
        nonlocal reads
        reads += 1
        return chains if reads == 1 else [replace(chains[0], status="deploying"), chains[1]]

    with pytest.raises(ProviderKeyedRuntimePreflightError, match="changed during preflight"):
        _preflight(tmp_path, records=(engagement, chains, job, plan), chain_reader=chain_reader)


def test_preflight_rejects_other_core_job_and_environment(tmp_path: Path):
    engagement, chains, job, plan = _records()
    wrong = replace(job, target_id="another-engagement")
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="targets another OCI compartment"):
        _preflight(tmp_path, records=(engagement, chains, wrong, plan))
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="ineligible"):
        _preflight(tmp_path, records=(replace(engagement, status="retired"), chains, job, plan))
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="requires DevTest"):
        preflight_fresh_digitalocean_provider(
            engagement.id, job.id, lease_owner="provider-job", environment="production",
            state_root=tmp_path / "sketch-state",
        )


def test_preflight_rejects_replaced_active_core_generation(tmp_path: Path):
    engagement, chains, job, plan = _records()
    replacement = replace(job, id="job-new-core")
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="active core generation"):
        _preflight(
            tmp_path, records=(engagement, chains, job, plan),
            all_jobs=lambda: [replacement, job],
        )


def test_reviewed_mixed_chain_rows_selects_exact_pair_without_changing_history():
    first, second = _records()[1]
    ghost = replace(first, chain_id="old-default", status="aborted")
    rows = [ghost, second, first]
    snapshot = list(rows)
    selected = provider_keyed_runtime_preflight.reviewed_mixed_chain_rows(
        rows, [first.chain_id, second.chain_id], first.engagement_id)
    assert selected == [first, second]
    assert rows == snapshot and rows[0] is ghost


@pytest.mark.parametrize("drift", [
    {"status": "pending"}, {"burned": True}, {"deploy_job_id": "job-old"},
    {"teardown_job_id": "job-old"}, {"terraform_working_directory": "/old"},
    {"nodes": [{"id": "owned"}]}, {"engagement_id": "another"},
])
def test_reviewed_mixed_chain_rows_rejects_noninert_history(drift):
    first, second = _records()[1]
    ghost = replace(first, chain_id="old-default", status="aborted", **drift) if "status" not in drift else replace(first, chain_id="old-default", **drift)
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="chain inventory"):
        provider_keyed_runtime_preflight.reviewed_mixed_chain_rows(
            [ghost, first, second], [first.chain_id, second.chain_id], first.engagement_id)


@pytest.mark.parametrize("drift", ["duplicate", "missing", "duplicate-reviewed", "missing-reviewed"])
def test_reviewed_mixed_chain_rows_rejects_ambiguous_or_missing_review(drift):
    first, second = _records()[1]
    rows = [first, second, first] if drift == "duplicate" else [first] if drift == "missing" else [first, second]
    ids = [first.chain_id, first.chain_id] if drift == "duplicate-reviewed" else None if drift == "missing-reviewed" else [first.chain_id, second.chain_id]
    with pytest.raises(ProviderKeyedRuntimePreflightError, match="chain inventory"):
        provider_keyed_runtime_preflight.reviewed_mixed_chain_rows(rows, ids, first.engagement_id)
