# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only retained-plan boundary before a future keyed apply caller."""

import hashlib
import json
import stat
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_planned_state_preflight as service
import app.services.provider_keyed_initial_plan_gate as initial_gate
from app.domain import JobEvent
from app.services.provider_keyed_sketch import prepare_provider_keyed_workspace, reserve_provider_topology


class Repository:
    def __init__(self, record):
        self.record = record

    def get(self, identifier):
        return self.record if identifier == self.record.id else None


class Jobs(Repository):
    def __init__(self, core, planned):
        self.core = core
        self.record = planned
        self.related = [core, planned]

    def get(self, identifier):
        return next((job for job in self.related if job.id == identifier), None)

    def list_for_engagement(self, _):
        return list(self.related)


def _file(path: Path, payload: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload)
    path.chmod(0o600)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path, monkeypatch):
    engagement_id = "eng-opaque"
    core_id = "job-core"
    planned_id = "job-plan"
    connection = "connection-opaque"
    fingerprint = hashlib.sha256(f"digitalocean\0{connection}".encode()).hexdigest()
    state_root = tmp_path / "state"
    schema = state_root / engagement_id / service.SCHEMA
    root = schema / "digitalocean" / fingerprint
    material = schema / ".plan-material" / "digitalocean"
    output = material / "ssh-output"
    for path in (state_root, state_root / engagement_id, schema, root.parent, root,
                 root / ".terraform-data", material.parent, material, output):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    intent = SimpleNamespace(revision_id="revision", selector_tag="selector", topology={"schema": service.SCHEMA, "middles": {"middle": {}}, "edge_groups": {}})
    marker = {"engagement_id": engagement_id, "provider_connection_id": connection,
              "rendered_files": {"middle.tf": "source"}}
    hashes = {
        "markerSha256": _file(root / ".barragan-provider-keyed-state.json", json.dumps(marker)),
        "topologySha256": _file(root / ".barragan-topology.json", json.dumps(intent.topology)),
        "lockfileSha256": _file(root / ".terraform.lock.hcl", "lock"),
        "planSha256": _file(root / service._PLAN, "binary plan"),
    }
    _file(root / "middle.tf", "source")
    _file(root / service._OWNER, json.dumps({
        "schema": service.SCHEMA, "engagementId": engagement_id, "provider": "digitalocean",
        "providerConnectionId": connection, "coreJobId": core_id, "planJobId": planned_id,
        "sourceRevision": service._SOURCE_REVISION,
    }))
    _file(root / ".barragan-initial-full-plan.lock", "")
    _file(schema / ".regional-ordinals.lock", "")
    _file(schema / "regional-ordinals.json", "{}")
    inputs = material / "inputs.json"
    input_digest = _file(inputs, "{}")
    evidence = {
        "coreJobId": core_id, "corePlanId": "plan-core", "revisionId": "revision",
        "providerConnectionId": connection, "selectorTag": "selector",
        "sourceRevision": service._SOURCE_REVISION, "sourceSha256": service._SOURCE_SHA256,
        "planPath": str(root / service._PLAN), "inputSha256": [[str(inputs), input_digest]],
        "credentialSecretSha256": "1" * 64, "credentialUpdatedAt": "today",
        "terraformBinaryPath": str(service._REVIEWED_PATH),
        "terraformBinarySha256": service._REVIEWED_SHA256,
        "terraformVersion": "1.15.5", "adminPublicKeySha256": "3" * 64,
        "adminPrivateKeyPath": str(material / "admin-private"),
        "adminPublicKeyPath": str(material / "admin-public"),
        "sshOutputDirectory": str(output), **hashes,
    }
    engagement = SimpleNamespace(id=engagement_id, status="deployed", input_parameters={"deploymentTarget": "testing"})
    core = SimpleNamespace(id=core_id, action="pilot_standard_rti_guarded_execute", input={"corePlanId": "plan-core"}, target_type="oci_compartment", target="oci-compartment:barragan-testing", target_id="compartment")
    planned = SimpleNamespace(
        id=planned_id, action=service._PLAN_ACTION, status="succeeded",
        target_type="engagement", target_id=engagement_id, target=f"engagement:{engagement_id}",
        input={"engagementId": engagement_id, "coreJobId": core_id, "mutation": False},
        created_at="2026-10-07T02:00:00Z", finished_at="2026-10-07T02:01:00Z",
        artifact_refs=[str(root / service._PLAN)],
        events=[JobEvent(1, "info", "reviewed provider plan saved", evidence)],
    )
    plan = SimpleNamespace(id="plan-core", evidence={"managedHostImageProfile": "profile"})
    jobs = Jobs(core, planned)
    monkeypatch.setattr(service, "_default_state_root", lambda: state_root)
    monkeypatch.setattr(service, "engagement_teardown_in_progress", lambda *a, **kw: None)
    monkeypatch.setattr(service, "normalized_oci_deployment_target", lambda _: {"name": "barragan-testing", "compartmentId": "compartment"})
    monkeypatch.setattr(service, "active_core_connection_details", lambda *a: (core_id, []))
    monkeypatch.setattr(service, "managed_host_image_profile_named", lambda _: object())
    monkeypatch.setattr(service, "compile_fresh_digitalocean_persisted_intent", lambda *a, **kw: intent)
    monkeypatch.setattr(service, "resolve_default_provider_connection", lambda *a, **kw: connection)
    monkeypatch.setattr(service, "require_fresh_digitalocean_review_authorization", lambda *a, **kw: None)
    monkeypatch.setattr(service, "_verify_audited_workspace", lambda _: None)
    monkeypatch.setattr(service, "_credential_snapshot", lambda *a: ("1" * 64, "today", "secret"))
    monkeypatch.setattr(service, "_binary_digest", lambda _: service._REVIEWED_SHA256)
    chains = SimpleNamespace(list_for_engagement=lambda _: ["chain-a", "chain-b"])
    return {
        "engagement_id": engagement_id, "core_job_id": core_id, "plan_job_id": planned_id,
        "lease_owner": "plan-core", "environment": "devtest", "state_root": state_root,
        "lease_lookup": lambda _: ("plan-core", "provider_keyed_initial"),
        "engagement_repository": Repository(engagement), "sketch_repository": chains,
        "job_repository": jobs, "plan_repository": Repository(plan),
        "credential_repository": object(),
    }, root, material, jobs, evidence


def test_planned_preflight_reads_exact_retained_evidence_without_writing(tmp_path, monkeypatch):
    kwargs, root, material, _, evidence = _fixture(tmp_path, monkeypatch)
    before = sorted(str(path) for path in kwargs["state_root"].rglob("*"))
    intent, workspace, retained = service.preflight_planned_digitalocean_provider(**kwargs)
    assert intent.selector_tag == "selector"
    assert workspace.path == root and retained == evidence
    assert sorted(str(path) for path in kwargs["state_root"].rglob("*")) == before
    assert not (material / "admin-private").exists()


def test_ancillary_orientation_progress_does_not_invalidate_provider_authority(
    tmp_path, monkeypatch,
):
    kwargs, root, _, jobs, evidence = _fixture(tmp_path, monkeypatch)
    refresh = SimpleNamespace(
        id="job-orientation", action="infra_orientation_refresh", status="running",
        events=[JobEvent(1, "info", "orientation started", {})],
    )
    jobs.related.append(refresh)
    original_list = jobs.list_for_engagement
    reads = 0

    def progress_between_reads(engagement_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            jobs.related[-1] = SimpleNamespace(
                id=refresh.id, action=refresh.action, status="failed",
                events=[*refresh.events, JobEvent(2, "error", "orientation failed", {})],
            )
        return original_list(engagement_id)

    monkeypatch.setattr(jobs, "list_for_engagement", progress_between_reads)
    _, workspace, retained = service.preflight_planned_digitalocean_provider(**kwargs)
    assert workspace.path == root and retained == evidence
    assert reads == 2 and jobs.related[-1].status == "failed"


@pytest.mark.parametrize("change", [
    "new_apply", "new_teardown", "plan_event_drift", "parent_event_drift",
])
def test_authority_job_drift_during_preflight_still_fails_closed(
    tmp_path, monkeypatch, change,
):
    kwargs, _, _, jobs, _ = _fixture(tmp_path, monkeypatch)
    if change == "parent_event_drift":
        jobs.related.append(SimpleNamespace(
            id="job-initial", action="provider_keyed_initial", status="running",
            events=[JobEvent(1, "info", "initial started", {})],
        ))
    original_list = jobs.list_for_engagement
    reads = 0

    def change_between_reads(engagement_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            if change in {"plan_event_drift", "parent_event_drift"}:
                index = 1 if change == "plan_event_drift" else 2
                old = jobs.related[index]
                jobs.related[index] = SimpleNamespace(
                    **{**vars(old), "events": [
                        *old.events, JobEvent(2, "info", "authority changed", {}),
                    ]},
                )
            else:
                jobs.related.append(SimpleNamespace(
                    id="job-new", action={
                        "new_apply": "provider_keyed_initial_apply",
                        "new_teardown": "provider_keyed_comprehensive_teardown",
                    }[change], status="queued",
                ))
        return original_list(engagement_id)

    monkeypatch.setattr(jobs, "list_for_engagement", change_between_reads)
    with pytest.raises(service.ProviderKeyedPlannedStatePreflightError):
        service.preflight_planned_digitalocean_provider(**kwargs)
    assert reads == 2


def _apply_job(kwargs):
    engagement_id = kwargs["engagement_id"]
    return SimpleNamespace(
        id="job-apply", action="provider_keyed_initial_apply", status="queued",
        target_type="engagement", target_id=engagement_id,
        target=f"engagement:{engagement_id}",
        input={"engagementId": engagement_id, "coreJobId": kwargs["core_job_id"],
               "corePlanId": "plan-core", "planJobId": kwargs["plan_job_id"],
               "mutation": True},
    )


@pytest.mark.parametrize("status", ["queued", "running"])
def test_planned_preflight_allows_only_same_apply_job_under_lease(tmp_path, monkeypatch, status):
    kwargs, root, _, jobs, evidence = _fixture(tmp_path, monkeypatch)
    apply_job = _apply_job(kwargs)
    apply_job.status = status
    jobs.related.append(apply_job)
    with pytest.raises(service.ProviderKeyedPlannedStatePreflightError):
        service.preflight_planned_digitalocean_provider(**kwargs)
    _, workspace, retained = service.preflight_planned_digitalocean_provider(
        **kwargs, allowed_apply_job_id="job-apply",
    )
    assert workspace.path == root and retained == evidence
    assert not (root / ".barragan-apply-phase.json").exists()


@pytest.mark.parametrize("tamper", [
    "wrong_lease", "wrong_bound_owner", "wrong_id", "wrong_action", "wrong_status", "wrong_target_type",
    "wrong_target_id", "wrong_target", "wrong_engagement_input", "wrong_core_input",
    "wrong_core_plan_input", "wrong_plan_input", "mutation_false", "mutation_zero",
    "extra_input", "extra_apply", "destroy", "missing_apply", "phase", "state",
])
def test_planned_preflight_resume_rejects_any_other_audit_or_state(
    tmp_path, monkeypatch, tamper,
):
    kwargs, root, _, jobs, _ = _fixture(tmp_path, monkeypatch)
    apply_job = _apply_job(kwargs)
    jobs.related.append(apply_job)
    if tamper == "wrong_lease":
        kwargs["lease_owner"] = "other-job"
    elif tamper == "wrong_bound_owner":
        kwargs["lease_owner"] = "other-job"
        kwargs["lease_lookup"] = lambda _: ("other-job", "provider_keyed_initial")
    elif tamper == "wrong_id":
        apply_job.id = "other-job"
    elif tamper == "wrong_action":
        apply_job.action = "provider_keyed_initial_destroy"
    elif tamper == "wrong_status":
        apply_job.status = "succeeded"
    elif tamper == "wrong_target_type":
        apply_job.target_type = "oci_compartment"
    elif tamper == "wrong_target_id":
        apply_job.target_id = "another-engagement"
    elif tamper == "wrong_target":
        apply_job.target = "engagement:another-engagement"
    elif tamper == "wrong_engagement_input":
        apply_job.input["engagementId"] = "another-engagement"
    elif tamper == "wrong_core_input":
        apply_job.input["coreJobId"] = "other-core"
    elif tamper == "wrong_core_plan_input":
        apply_job.input["corePlanId"] = "other-plan"
    elif tamper == "wrong_plan_input":
        apply_job.input["planJobId"] = "other-plan-job"
    elif tamper == "mutation_false":
        apply_job.input["mutation"] = False
    elif tamper == "mutation_zero":
        apply_job.input["mutation"] = 0
    elif tamper == "extra_input":
        apply_job.input["unexpected"] = "value"
    elif tamper == "extra_apply":
        jobs.related.append(deepcopy(apply_job))
    elif tamper == "destroy":
        other = deepcopy(apply_job)
        other.id = "job-destroy"
        other.action = "provider_keyed_initial_destroy"
        jobs.related.append(other)
    elif tamper == "missing_apply":
        jobs.related.pop()
    elif tamper == "phase":
        _file(root / ".barragan-apply-phase.json", '{}')
    else:
        _file(root / "terraform.tfstate", '{}')
    with pytest.raises(service.ProviderKeyedPlannedStatePreflightError):
        service.preflight_planned_digitalocean_provider(
            **kwargs, allowed_apply_job_id="job-apply",
        )


def test_planned_preflight_accepts_rendered_workspace_and_json_job_event(tmp_path, monkeypatch):
    """The reader must accept the writer's real path and serialized evidence shapes."""
    source = tmp_path / "redteam-infra"
    template = source / "external" / "sketch" / "digitalocean"
    sidecar = template / "barragan-v2"
    sidecar.mkdir(parents=True)
    for path, content in {
        "middle.tf": 'resource "test_instance" "middle" {}\n',
        "edge.tf": 'resource "test_instance" "edge" {}\n',
        "providers.tf": 'terraform { required_version = ">= 1.0" }\n',
        "firewall.tf": "# legacy firewall\n",
        "barragan-v2/providers.tf": 'terraform { required_version = "= 1.15.5" }\n',
        "barragan-v2/firewall.tf": "# keyed firewall\n",
        "barragan-v2/.terraform.lock.hcl": "# pinned fixture\n",
    }.items():
        (template / path).write_text(content, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Test",
                    "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
    revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    engagement_id, core_id, plan_id, connection_id = "eng-opaque", "job-core", "job-plan", "connection-opaque"
    state_root = tmp_path / "state"
    workspace = prepare_provider_keyed_workspace(
        engagement_id, "digitalocean", connection_id, template_root=source,
        source_revision=revision, root=state_root, environment="devtest",
        deployment_target="barragan-testing",
    )
    topology = reserve_provider_topology(
        workspace, {"middle": {"region": "nyc3", "ordinal": 1}},
        {"sea": {"region": "sfo3", "middle_node": "middle", "count": 1}},
    )
    monkeypatch.setattr(service, "_SOURCE_REVISION", revision)
    monkeypatch.setattr(initial_gate, "_SOURCE_REVISION", revision)
    monkeypatch.setattr(service, "_SOURCE_SHA256", workspace.source_sha256)
    monkeypatch.setattr(initial_gate, "_SOURCE_SHA256", workspace.source_sha256)

    schema_root = workspace.path.parents[1]
    material = schema_root / ".plan-material" / "digitalocean"
    output = material / "ssh-output"
    output.mkdir(parents=True, mode=0o700)
    for path in (material.parent, material, output):
        path.chmod(0o700)
    _file(workspace.path / service._OWNER, json.dumps({
        "schema": service.SCHEMA, "engagementId": engagement_id,
        "provider": "digitalocean", "providerConnectionId": connection_id,
        "coreJobId": core_id, "planJobId": plan_id, "sourceRevision": revision,
    }))
    _file(workspace.path / service._PLAN, "saved plan fixture")
    _file(workspace.path / ".barragan-initial-full-plan.lock", "")
    inputs = material / "inputs.json"
    input_digest = _file(inputs, "{}")
    plan_path = workspace.path / service._PLAN
    evidence = {
        "coreJobId": core_id, "corePlanId": "plan-core", "revisionId": "revision",
        "providerConnectionId": connection_id, "selectorTag": "selector",
        "sourceRevision": revision, "sourceSha256": workspace.source_sha256,
        "planPath": str(plan_path), "planSha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "markerSha256": hashlib.sha256((workspace.path / ".barragan-provider-keyed-state.json").read_bytes()).hexdigest(),
        "topologySha256": hashlib.sha256((workspace.path / ".barragan-topology.json").read_bytes()).hexdigest(),
        "lockfileSha256": hashlib.sha256((workspace.path / ".terraform.lock.hcl").read_bytes()).hexdigest(),
        "inputSha256": ((str(inputs), input_digest),),
        "credentialSecretSha256": "1" * 64, "credentialUpdatedAt": "today",
        "terraformBinaryPath": str(service._REVIEWED_PATH),
        "terraformBinarySha256": service._REVIEWED_SHA256,
        "terraformVersion": "1.15.5", "adminPublicKeySha256": "3" * 64,
        "adminPrivateKeyPath": str(material / "admin-private"),
        "adminPublicKeyPath": str(material / "admin-public"),
        "sshOutputDirectory": str(output),
    }
    # Job events cross a JSON-backed repository boundary; tuples become lists.
    persisted_evidence = json.loads(json.dumps(evidence))
    assert persisted_evidence["inputSha256"] == [[str(inputs), input_digest]]
    engagement = SimpleNamespace(id=engagement_id, status="deployed", input_parameters={"deploymentTarget": "testing"})
    core = SimpleNamespace(id=core_id, action="pilot_standard_rti_guarded_execute",
                           input={"corePlanId": "plan-core"}, target_type="oci_compartment",
                           target="oci-compartment:barragan-testing", target_id="compartment")
    planned = SimpleNamespace(
        id=plan_id, action=service._PLAN_ACTION, status="succeeded", target_type="engagement",
        target_id=engagement_id, target=f"engagement:{engagement_id}",
        input={"engagementId": engagement_id, "coreJobId": core_id, "mutation": False},
        created_at="2026-10-07T02:00:00Z", finished_at="2026-10-07T02:01:00Z",
        artifact_refs=[str(plan_path)],
        events=[JobEvent(1, "info", "reviewed provider plan saved", persisted_evidence)],
    )
    plan = SimpleNamespace(id="plan-core", evidence={"managedHostImageProfile": "profile"})
    jobs = Jobs(core, planned)
    monkeypatch.setattr(service, "_default_state_root", lambda: state_root)
    monkeypatch.setattr(service, "engagement_teardown_in_progress", lambda *a, **kw: None)
    monkeypatch.setattr(service, "normalized_oci_deployment_target",
                        lambda _: {"name": "barragan-testing", "compartmentId": "compartment"})
    monkeypatch.setattr(service, "active_core_connection_details", lambda *a: (core_id, []))
    monkeypatch.setattr(service, "managed_host_image_profile_named", lambda _: object())
    intent = SimpleNamespace(revision_id="revision", selector_tag="selector", topology=topology)
    monkeypatch.setattr(service, "compile_fresh_digitalocean_persisted_intent", lambda *a, **kw: intent)
    monkeypatch.setattr(service, "resolve_default_provider_connection", lambda *a, **kw: connection_id)
    monkeypatch.setattr(service, "require_fresh_digitalocean_review_authorization", lambda *a, **kw: None)
    monkeypatch.setattr(service, "_credential_snapshot", lambda *a: ("1" * 64, "today", "secret"))
    monkeypatch.setattr(service, "_binary_digest", lambda _: service._REVIEWED_SHA256)

    def tree_snapshot():
        return {
            path.relative_to(state_root).as_posix(): (
                stat.S_IMODE(path.stat().st_mode), path.stat().st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
            ) for path in [state_root, *state_root.rglob("*")]
        }

    before = tree_snapshot()
    returned_intent, returned_workspace, returned_evidence = service.preflight_planned_digitalocean_provider(
        engagement_id, core_id, plan_id, lease_owner="plan-core", environment="devtest",
        state_root=state_root, lease_lookup=lambda _: ("plan-core", "provider_keyed_initial"),
        engagement_repository=Repository(engagement),
        sketch_repository=SimpleNamespace(list_for_engagement=lambda _: ["chain-a", "chain-b"]),
        job_repository=jobs, plan_repository=Repository(plan), credential_repository=object(),
    )
    assert returned_intent is intent
    assert returned_workspace == workspace
    assert returned_evidence == persisted_evidence
    assert tree_snapshot() == before
    assert not (material / "admin-private").exists()


def _failed_predecessor():
    return SimpleNamespace(
        id="job-failed", action=service._PLAN_ACTION, status="failed",
        target_type="engagement", target_id="eng-opaque", target="engagement:eng-opaque",
        input={"engagementId": "eng-opaque", "coreJobId": "job-core", "mutation": False},
        created_at="2026-10-07T00:00:00Z", finished_at="2026-10-07T01:00:00Z",
        artifact_refs=[], events=[JobEvent(1, "error", "provider plan preparation failed", {})],
    )


def test_terminal_abandoned_plan_history_can_precede_success(tmp_path, monkeypatch):
    kwargs, _, _, jobs, _ = _fixture(tmp_path, monkeypatch)
    jobs.related.append(_failed_predecessor())
    _, workspace, _ = service.preflight_planned_digitalocean_provider(**kwargs)
    assert workspace.provider == "digitalocean"


@pytest.mark.parametrize("drift", [
    "extra_plan_job", "credential", "plan_digest", "input_digest", "extra_workspace",
    "owner", "apply_phase", "state", "extra_artifact", "topology", "apply_job",
    "failed_artifact", "failed_unfinished", "failed_after_current", "failed_saved_event",
])
def test_planned_preflight_fails_closed_on_drift(tmp_path, monkeypatch, drift):
    kwargs, root, material, jobs, evidence = _fixture(tmp_path, monkeypatch)
    if drift == "extra_plan_job":
        jobs.related.append(SimpleNamespace(id="another", action=service._PLAN_ACTION))
    elif drift == "apply_job":
        jobs.related.append(SimpleNamespace(id="another", action="provider_keyed_initial_apply"))
    elif drift.startswith("failed_"):
        failed = _failed_predecessor()
        if drift == "failed_artifact":
            failed.artifact_refs = ["/unexpected/plan"]
        elif drift == "failed_unfinished":
            failed.finished_at = None
        elif drift == "failed_after_current":
            failed.finished_at = "2026-10-07T03:00:00Z"
        elif drift == "failed_saved_event":
            failed.events.append(JobEvent(2, "info", "reviewed provider plan saved", {}))
        jobs.related.append(failed)
    elif drift == "credential":
        monkeypatch.setattr(service, "_credential_snapshot", lambda *a: ("9" * 64, "today", "secret"))
    elif drift == "plan_digest":
        _file(root / service._PLAN, "changed")
    elif drift == "input_digest":
        _file(material / "inputs.json", "changed")
    elif drift == "extra_workspace":
        (root.parent / "other").mkdir()
    elif drift == "owner":
        _file(root / service._OWNER, "{}")
    elif drift == "apply_phase":
        _file(root / ".barragan-apply-phase.json", "{}")
    elif drift == "state":
        _file(root / "terraform.tfstate", "{}")
    elif drift == "extra_artifact":
        _file(root / "surprise", "unexpected")
    elif drift == "topology":
        changed = {"schema": service.SCHEMA, "middles": {"other": {}}, "edge_groups": {}}
        evidence["topologySha256"] = _file(root / ".barragan-topology.json", json.dumps(changed))
    with pytest.raises(service.ProviderKeyedPlannedStatePreflightError):
        service.preflight_planned_digitalocean_provider(**kwargs)
