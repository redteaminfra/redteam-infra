# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only applied-state reconstruction across persisted job and plan rows."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_postapply_preflight as service
from app.services import provider_keyed_initial_plan_gate as audited_source
from app.services import provider_keyed_plan_evidence as plan_evidence
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_terraform_release import _REVIEWED_PATH, _REVIEWED_SHA256
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from test_provider_keyed_persisted_intent import _inputs


class OneEngagement:
    def __init__(self, engagement):
        self.engagement = engagement

    def get(self, identifier):
        return self.engagement if identifier == self.engagement.id else None


class AllChains:
    def __init__(self, chains):
        self.chains = chains

    def list_for_engagement(self, _identifier):
        return list(self.chains)


def _private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def _private_file(path, content):
    path.write_text(content)
    path.chmod(0o600)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _persisted_fixture(tmp_path, monkeypatch, *, incident_identity=None):
    state_root = tmp_path / "state"
    engagement, chains, core, plan, profile = _inputs()
    if incident_identity is not None:
        engagement_id, core_id = incident_identity
        engagement = replace(engagement, id=engagement_id)
        chains = [replace(chain, engagement_id=engagement_id) for chain in chains]
        core = replace(core, id=core_id,
                       input={**core.input, "engagementId": engagement_id})
        plan = replace(plan, engagement_id=engagement_id, apply_job_id=core_id)
    target = engagement.input_parameters["deploymentTarget"]
    core = replace(core, target=f"oci-compartment:{target['name']}", target_type="oci_compartment",
                   target_id=target["compartmentId"], created_at="2026-10-07T00:00:00+00:00",
                   started_at="2026-10-07T00:00:01+00:00", finished_at="2026-10-07T00:01:00+00:00")
    intent = compile_fresh_digitalocean_persisted_intent(
        engagement, chains, core, plan, profile, environment="devtest",
        mode="applied_read", provider_state_exists=True,
    )
    connection_id = "connection-opaque"
    fingerprint = hashlib.sha256(f"digitalocean\0{connection_id}".encode()).hexdigest()
    schema_root = state_root / engagement.id / "provider-keyed-v2"
    provider_root = schema_root / "digitalocean"
    workspace_root = provider_root / fingerprint
    for directory in (state_root, state_root / engagement.id, schema_root, provider_root,
                      workspace_root, workspace_root / ".terraform-data",
                      schema_root / ".plan-material", schema_root / ".plan-material" / "digitalocean",
                      schema_root / ".plan-material" / "digitalocean" / "ssh-output"):
        _private_directory(directory)
    _private_file(schema_root / ".regional-ordinals.lock", "")
    _private_file(schema_root / "regional-ordinals.json", "{}")
    owner = {"schema": "provider-keyed-v2", "engagementId": engagement.id,
             "provider": "digitalocean", "providerConnectionId": connection_id,
             "coreJobId": core.id, "planJobId": service._child_ids(core.id)[0],
             "sourceRevision": _SOURCE_REVISION}
    _private_file(workspace_root / ".barragan-initial-plan-owner.json", json.dumps(owner))
    marker_sha = _private_file(workspace_root / ".barragan-provider-keyed-state.json", "{}")
    topology_sha = _private_file(workspace_root / ".barragan-topology.json", json.dumps(intent.topology))
    lock_sha = _private_file(workspace_root / ".terraform.lock.hcl", "lock fixture")
    inputs = schema_root / ".plan-material" / "digitalocean" / "inputs.json"
    input_sha = _private_file(inputs, json.dumps(intent.nonsecret_varfile))
    _private_file(workspace_root / ".barragan-apply-phase.json",
                  json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
    resources = []
    for index, (address, node) in enumerate(sorted(intent.nodes.items()), 101):
        kind, suffix = address.split("[", 1)
        resource_type, resource_name = kind.split(".")
        key = json.loads("[" + suffix)[0]
        resources.append({"mode": "managed", "type": resource_type, "name": resource_name,
                          "instances": [{"index_key": key, "attributes": {
                              "id": str(index), "name": node.name, "region": node.region,
                              "ipv4_address": f"192.0.2.{index - 90}",
                              "tags": [intent.selector_tag],
                          }}]})
    resources.append({"mode": "managed", "type": "digitalocean_firewall", "name": "firewall",
                      "instances": [{"attributes": {
                          "id": "11111111-2222-4333-8444-555555555555",
                          "name": intent.firewall.name, "tags": [intent.selector_tag],
                      }}]})
    state_path = workspace_root / "terraform.tfstate"
    state_sha = _private_file(state_path, json.dumps({"version": 4, "serial": 1,
        "lineage": "11111111-1111-4111-8111-111111111111", "resources": resources}))
    material = schema_root / ".plan-material" / "digitalocean"
    plan_path = workspace_root / ".barragan-initial-full.tfplan"
    evidence = {
        "coreJobId": core.id, "corePlanId": plan.id, "revisionId": intent.revision_id,
        "providerConnectionId": connection_id, "selectorTag": intent.selector_tag,
        "sourceRevision": _SOURCE_REVISION, "planPath": str(plan_path), "planSha256": "a" * 64,
        "sourceSha256": _SOURCE_SHA256, "markerSha256": marker_sha,
        "topologySha256": topology_sha, "lockfileSha256": lock_sha,
        "inputSha256": [[str(inputs), input_sha]], "credentialSecretSha256": "b" * 64,
        "credentialUpdatedAt": "2026-10-07T00:00:00+00:00",
        "terraformBinaryPath": str(_REVIEWED_PATH), "terraformBinarySha256": _REVIEWED_SHA256,
        "terraformVersion": "1.15.5", "adminPublicKeySha256": "c" * 64,
        "adminPrivateKeyPath": str(material / "admin-private"),
        "adminPublicKeyPath": str(material / "admin-public"),
        "sshOutputDirectory": str(material / "ssh-output"),
    }
    plan_job = StoredJobRun(
        id=service._child_ids(core.id)[0], action="provider_keyed_initial_plan", status="succeeded",
        target=f"engagement:{engagement.id}", target_type="engagement", target_id=engagement.id,
        requested_by="operator", input={"engagementId": engagement.id, "coreJobId": core.id,
                                        "mutation": False}, artifact_refs=[str(plan_path)],
        created_at="2026-10-07T00:02:00+00:00", started_at="2026-10-07T00:02:01+00:00",
        finished_at="2026-10-07T00:03:00+00:00",
        events=[JobEvent(1, "info", "reviewed provider plan saved", evidence)],
    )
    apply_job = StoredJobRun(
        id=service._child_ids(core.id)[1], action="provider_keyed_initial_apply", status="succeeded",
        target=f"engagement:{engagement.id}", target_type="engagement", target_id=engagement.id,
        requested_by="operator", input={"engagementId": engagement.id, "coreJobId": core.id,
                                        "corePlanId": plan.id, "planJobId": plan_job.id,
                                        "mutation": True}, artifact_refs=[],
        created_at="2026-10-07T00:04:00+00:00", started_at="2026-10-07T00:04:01+00:00",
        finished_at="2026-10-07T00:05:00+00:00",
        events=[JobEvent(1, "info", "provider saved-plan apply completed; proof pending",
            {"stateSha256": state_sha, "selectorTag": intent.selector_tag,
             "attachmentProofPending": True, "hostProofPending": True})],
    )
    state = db.configure("sqlite:///:memory:")
    monkeypatch.setattr(service, "_default_state_root", lambda: state_root)
    monkeypatch.setattr(service, "_verify_audited_workspace", lambda workspace: None)
    monkeypatch.setattr(service, "resolve_default_provider_connection", lambda *_a, **_kw: connection_id)
    monkeypatch.setattr(service, "require_fresh_digitalocean_review_authorization", lambda *_a, **_kw: None)
    monkeypatch.setattr(service, "_credential_snapshot", lambda *_a, **_kw: ("b" * 64, evidence["credentialUpdatedAt"], "encrypted"))
    return state, engagement, chains, core, plan, plan_job, apply_job, intent, state_root, workspace_root, evidence


def _run(rows, *, engagement=None, chains=None, lookup=None):
    state, original_engagement, original_chains, core, plan, plan_job, apply_job, intent, state_root, root, evidence = rows
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        for job in (core, plan_job, apply_job):
            jobs.save(job)
        plans.save(plan)
        return service.preflight_applied_digitalocean_provider(
            original_engagement.id, core.id, lease_owner=plan.id, environment="devtest",
            state_root=state_root, lease_lookup=lookup or (lambda _id: (plan.id, "provider_keyed_initial")),
            engagement_repository=OneEngagement(engagement or original_engagement),
            sketch_repository=AllChains(chains or original_chains),
            job_repository=jobs, plan_repository=plans, credential_repository=object(),
        )


def test_reconstructs_applied_attachment_inputs_from_sqlalchemy_jobs_and_plan(tmp_path, monkeypatch):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    intent, workspace, evidence, apply = _run(rows)
    assert intent == rows[7]
    assert workspace.state_path.is_file()
    assert evidence == rows[10]
    assert apply.id == rows[6].id
    assert not (rows[9] / ".barragan-initial-full.tfplan").exists()


def test_incident_read_accepts_only_bound_destroy_started_child(tmp_path, monkeypatch):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    state, engagement, chains, core, plan, plan_job, apply_job, intent, state_root, root, _ = rows
    _private_file(root / ".barragan-apply-phase.json",
                  json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"}))
    parent_id = "job-parent-incident"
    child_id = f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}"
    parent = type("Parent", (), {"id": parent_id})()
    monkeypatch.setattr(service, "engagement_teardown_in_progress", lambda *_a, **_kw: parent)
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        for row in (core, plan_job, apply_job):
            jobs.save(row)
        plans.save(plan)
        child = replace(apply_job, id=child_id, action="provider_keyed_initial_destroy_apply",
                        status="running", finished_at=None,
                        input={"teardownParentId": parent_id, "coreJobId": core.id},
                        events=[JobEvent(index, "info", "provider destroy command started before GO", {})
                                for index in range(1, 10)])
        jobs.save(child)
        kwargs = dict(
            environment="devtest", state_root=state_root,
            allowed_teardown_parent_id=parent_id, incident_destroy_child_id=child_id,
            engagement_repository=OneEngagement(engagement), sketch_repository=AllChains(chains),
            job_repository=jobs, plan_repository=plans, credential_repository=object(),
        )
        actual = service.read_applied_digitalocean_provider_for_teardown(
            engagement.id, core.id, mode="destroy_started_read", **kwargs)
        assert actual[0] == intent
        with pytest.raises(service.ProviderKeyedPostapplyPreflightError):
            service.read_applied_digitalocean_provider_for_teardown(
                engagement.id, core.id, mode="applied_read", **kwargs)
        with pytest.raises(service.ProviderKeyedPostapplyPreflightError):
            service.read_applied_digitalocean_provider_for_teardown(
                engagement.id, core.id, mode="destroy_started_read",
                **{**kwargs, "incident_destroy_child_id": "job-other"})


def test_second_incident_recovery_read_rebinds_only_exact_persisted_claimed_child(
    tmp_path, monkeypatch,
):
    rows = _persisted_fixture(
        tmp_path, monkeypatch,
        incident_identity=("eng-6ad4d5fb880e", "job-b4f1bceb4a7d"),
    )
    state, engagement, chains, core, plan, plan_job, apply_job, intent, state_root, root, _ = rows
    _private_file(root / ".barragan-apply-phase.json",
                  json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"}))
    parent_id = "job-engagement-teardown-b4f1bceb4a7d"
    child_id = "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d"
    parent = type("Parent", (), {"id": parent_id})()
    monkeypatch.setattr(service, "engagement_teardown_in_progress", lambda *_a, **_kw: parent)
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        for row in (core, plan_job, apply_job):
            jobs.save(row)
        plans.save(plan)
        child = replace(
            apply_job, id=child_id, action="provider_keyed_initial_destroy_apply",
            status="running", finished_at=None,
            input={"teardownParentId": parent_id, "coreJobId": core.id},
            events=[JobEvent(index, "info", "provider destroy command started before GO", {})
                    for index in range(1, 10)],
        )
        jobs.save(child)
        claimed = jobs.get(child_id)
        kwargs = dict(
            environment="devtest", state_root=state_root,
            allowed_teardown_parent_id=parent_id, incident_destroy_child_id=child_id,
            incident_recovery_child=claimed,
            engagement_repository=OneEngagement(engagement), sketch_repository=AllChains(chains),
            job_repository=jobs, plan_repository=plans, credential_repository=object(),
        )
        assert service.read_applied_digitalocean_provider_for_teardown(
            engagement.id, core.id, mode="destroy_started_recovery_read", **kwargs)[0] == intent
        for drift in (
            {"incident_recovery_child": replace(claimed, status="failed")},
            {"allowed_teardown_parent_id": "job-engagement-teardown-db19aa91df17"},
            {"incident_destroy_child_id": "job-provider-keyed-initial-destroy-apply-db19aa91df17"},
        ):
            with pytest.raises(service.ProviderKeyedPostapplyPreflightError):
                service.read_applied_digitalocean_provider_for_teardown(
                    engagement.id, core.id, mode="destroy_started_recovery_read",
                    **{**kwargs, **drift})


def test_applied_preflight_accepts_empty_sketch_known_hosts_in_audited_workspace(tmp_path, monkeypatch):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    root, evidence = rows[9], rows[10]
    # Render an actual audited source inventory instead of the usual focused
    # fixture's mocked source verifier, then exercise the entire preflight.
    source_bytes = {
        "middle.tf": b"middle fixture", "edge.tf": b"edge fixture",
        "firewall.tf": b"legacy firewall fixture", "providers.tf": b"legacy provider fixture",
        "barragan-v2/firewall.tf": b"safe firewall fixture",
        "barragan-v2/providers.tf": b"pinned provider fixture",
        "barragan-v2/.terraform.lock.hcl": b"pinned provider lock fixture",
    }
    source_files = {name: hashlib.sha256(content).hexdigest() for name, content in source_bytes.items()}
    rendered = dict(source_files)
    for target, origin in (("firewall.tf", "barragan-v2/firewall.tf"),
                           ("providers.tf", "barragan-v2/providers.tf"),
                           (".terraform.lock.hcl", "barragan-v2/.terraform.lock.hcl")):
        rendered[target] = source_files[origin]
    for name in rendered:
        origin = {"firewall.tf": "barragan-v2/firewall.tf",
                  "providers.tf": "barragan-v2/providers.tf",
                  ".terraform.lock.hcl": "barragan-v2/.terraform.lock.hcl"}.get(name, name)
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source_bytes[origin])
    source_sha = hashlib.sha256(json.dumps(source_files, sort_keys=True).encode()).hexdigest()
    marker = {
        "schema": "provider-keyed-v2", "provider": "digitalocean",
        "provider_connection_id": "connection-opaque", "connection_fingerprint": root.name,
        "source_revision": _SOURCE_REVISION,
        "source_files": source_files, "rendered_files": rendered,
    }
    evidence["markerSha256"] = _private_file(root / ".barragan-provider-keyed-state.json", json.dumps(marker))
    evidence["lockfileSha256"] = hashlib.sha256((root / ".terraform.lock.hcl").read_bytes()).hexdigest()
    evidence["sourceSha256"] = source_sha
    monkeypatch.setattr(audited_source, "_SOURCE_SHA256", source_sha)
    monkeypatch.setattr(service, "_SOURCE_SHA256", source_sha)
    monkeypatch.setattr(plan_evidence, "_SOURCE_SHA256", source_sha)
    monkeypatch.setattr(service, "_verify_audited_workspace", audited_source._verify_audited_workspace)
    from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
    audited_source._verify_audited_workspace(ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", "provider-keyed-v2",
        "digitalocean", "connection-opaque", root.name, _SOURCE_REVISION, source_sha,
    ))

    before = _run(rows)
    path = root / ".barragan-sketch-known-hosts"
    path.touch(mode=0o600)
    path.chmod(0o600)
    after = _run(rows)
    assert before[0] == after[0] == rows[7]
    assert before[1] == after[1]
    assert path.read_bytes() == b""


def test_exact_private_saved_plan_may_remain_after_successful_apply(tmp_path, monkeypatch):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    rows[10]["planSha256"] = _private_file(rows[9] / ".barragan-initial-full.tfplan", "retained plan fixture")
    assert _run(rows)[0] == rows[7]


def _insert_failed_plan(rows, **changes):
    fields = {"id": "job-earlier-failed-plan", "status": "failed", "artifact_refs": [], "events": [],
              "created_at": "2026-10-07T00:01:01+00:00", "started_at": "2026-10-07T00:01:02+00:00",
              "finished_at": "2026-10-07T00:01:30+00:00"}
    fields.update(changes)
    failed = replace(rows[5], **fields)
    with db.bind(rows[0]):
        db.create_all()
        SqlAlchemyJobRepository().save(failed)


def test_safe_failed_plan_predecessor_does_not_block_applied_read(tmp_path, monkeypatch):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    _insert_failed_plan(rows)
    assert _run(rows)[0] == rows[7]


@pytest.mark.parametrize("unsafe", ["saved_artifact", "late_finish", "wrong_target"])
def test_unsafe_failed_plan_predecessor_blocks_applied_read(tmp_path, monkeypatch, unsafe):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    changes = {
        "saved_artifact": {"artifact_refs": ["unreviewed.tfplan"]},
        "late_finish": {"finished_at": "2026-10-07T00:02:30+00:00"},
        "wrong_target": {"target_id": "other-engagement"},
    }[unsafe]
    _insert_failed_plan(rows, **changes)
    with pytest.raises(service.ProviderKeyedPostapplyPreflightError, match="preflight failed"):
        _run(rows)


@pytest.mark.parametrize("artifact", ["state_writable", "state_symlink", "phase_public",
                                     "phase_symlink", "terraform_data_writable", "terraform_data_symlink"])
def test_rejects_unsafe_applied_artifacts(tmp_path, monkeypatch, artifact):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    workspace = rows[9]
    if artifact == "state_writable":
        (workspace / "terraform.tfstate").chmod(0o666)
    elif artifact == "state_symlink":
        path = workspace / "terraform.tfstate"
        path.rename(workspace / "state-target")
        path.symlink_to("state-target")
    elif artifact == "phase_public":
        (workspace / ".barragan-apply-phase.json").chmod(0o644)
    elif artifact == "phase_symlink":
        path = workspace / ".barragan-apply-phase.json"
        path.rename(workspace / "phase-target")
        path.symlink_to("phase-target")
    elif artifact == "terraform_data_writable":
        (workspace / ".terraform-data").chmod(0o777)
    else:
        path = workspace / ".terraform-data"
        path.rename(workspace / "data-target")
        path.symlink_to("data-target")
    with pytest.raises(service.ProviderKeyedPostapplyPreflightError, match="preflight failed"):
        _run(rows)


@pytest.mark.parametrize("drift", [
    "lease", "chain", "owner", "state", "credential", "duplicate_plan",
    "retained_plan", "phase", "extra_workspace",
])
def test_rejects_postapply_drift_without_provider_calls(tmp_path, monkeypatch, drift):
    rows = _persisted_fixture(tmp_path, monkeypatch)
    kwargs = {}
    if drift == "lease":
        kwargs["lookup"] = lambda _id: ("other-plan", "provider_keyed_initial")
    elif drift == "chain":
        kwargs["chains"] = [replace(rows[2][0], middle_region="sfo3"), rows[2][1]]
    elif drift == "owner":
        path = rows[9] / ".barragan-initial-plan-owner.json"
        path.write_text(path.read_text().replace("connection-opaque", "wrong-connection"))
    elif drift == "state":
        path = rows[9] / "terraform.tfstate"
        path.write_text(path.read_text() + " ")
    elif drift == "credential":
        monkeypatch.setattr(service, "_credential_snapshot", lambda *_a, **_kw: ("d" * 64, "changed", "encrypted"))
    elif drift == "retained_plan":
        _private_file(rows[9] / ".barragan-initial-full.tfplan", "unreviewed plan")
    elif drift == "phase":
        _private_file(rows[9] / ".barragan-apply-phase.json",
                      json.dumps({"schema": "provider-keyed-v2", "phase": "started"}))
    elif drift == "extra_workspace":
        _private_directory(rows[9].parent / "unreviewed")
    else:
        original_run = _run
        def duplicate(rows, **kwargs):
            state = rows[0]
            with db.bind(state):
                db.create_all()
                jobs = SqlAlchemyJobRepository()
                jobs.save(replace(rows[5], id="other-plan-job"))
            return original_run(rows, **kwargs)
        runner = duplicate
    with pytest.raises(service.ProviderKeyedPostapplyPreflightError, match="preflight failed"):
        (runner if drift == "duplicate_plan" else _run)(rows, **kwargs)
