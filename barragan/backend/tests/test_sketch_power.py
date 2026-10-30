# Copyright (c) 2026, Oracle and/or its affiliates.
from app.domain import JobEvent
from app.services.sketch_power import (
    ProviderPowerResult,
    SketchPowerValidationError,
    run_sketch_power_job,
)
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


class FakePowerRunner:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    def run(self, *, provider, provider_instance_id, action, token):
        self.calls.append(
            {
                "provider": provider,
                "providerInstanceId": provider_instance_id,
                "action": action,
                "token": token,
            }
        )
        return ProviderPowerResult(provider, provider_instance_id, action, self.ok, 202 if self.ok else 500)


class FakeCredentialResolver:
    def __init__(self, token):
        self.token = token
        self.calls = []

    def __call__(self, provider, alias):
        self.calls.append((provider, alias))
        return self.token


class FakeJobRepository:
    def __init__(self, jobs):
        self.jobs = list(jobs)
        self.saved = []

    def list(self):
        return list(self.jobs)

    def get(self, job_id):
        for job in self.jobs:
            if job.id == job_id:
                return job
        return None

    def save(self, job):
        self.jobs = [existing for existing in self.jobs if existing.id != job.id]
        self.jobs.insert(0, job)
        self.saved.append(job)
        return job


def test_run_sketch_power_job_stops_nodes_by_provider_instance_id_without_persisting_token():
    secret = "linode-token-sensitive-value"
    runner = FakePowerRunner()
    resolver = FakeCredentialResolver(secret)
    repository = FakeJobRepository([_deploy_job()])

    result = run_sketch_power_job(
        _chain(status="deployed"),
        action="stop",
        requested_by="operator",
        repository=repository,
        credential_resolver=resolver,
        runner=runner,
    )

    assert result.status == "succeeded"
    assert resolver.calls == [("linode", "linode-barragan")]
    assert [call["providerInstanceId"] for call in runner.calls] == ["1111", "2222"]
    assert [call["action"] for call in runner.calls] == ["stop", "stop"]
    assert all(call["token"] == secret for call in runner.calls)
    body = result.to_dict()
    assert body["action"] == "sketch_chain_stop"
    assert body["events"][-1]["data"]["status"] == "stopped"
    assert body["events"][-1]["data"]["opsecBoundary"]["providerApiOnly"] is True
    assert body["events"][-1]["data"]["opsecBoundary"]["directSketchAccessFromAppHost"] is False
    assert "1111" in str(body)
    assert secret not in str(body)
    assert "token-sensitive-value" not in str(body)
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)


def test_run_sketch_power_job_starts_nodes_and_records_failed_provider_result():
    runner = FakePowerRunner(ok=False)
    result = run_sketch_power_job(
        _chain(status="stopped"),
        action="start",
        requested_by="operator",
        repository=FakeJobRepository([_deploy_job()]),
        credential_resolver=FakeCredentialResolver("linode-token-sensitive-value"),
        runner=runner,
    )

    assert result.status == "failed"
    assert result.to_dict()["action"] == "sketch_chain_start"
    assert result.to_dict()["events"][-1]["data"]["status"] == "failed"


def test_run_sketch_power_job_requires_provider_instance_ids():
    try:
        run_sketch_power_job(
            _chain(status="deployed", nodes=[{"provider": "linode", "role": "middle", "hostname": "middle-zy01"}]),
            action="stop",
            repository=FakeJobRepository([_deploy_job()]),
            credential_resolver=FakeCredentialResolver("token"),
            runner=FakePowerRunner(),
        )
    except SketchPowerValidationError as exc:
        assert exc.errors == ["chain has no providerInstanceId values; redeploy or refresh the chain before stop/start"]
    else:
        raise AssertionError("expected SketchPowerValidationError")


def _deploy_job():
    return StoredJobRun(
        id="job-deploy",
        action="linode_sketch_deploy",
        status="succeeded",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={
            "engagementId": "eng-zy01",
            "chainId": "proxy01-sea-01",
            "middleCredentialAlias": "linode-barragan",
            "edgeCredentialAlias": "linode-barragan",
        },
        artifact_refs=[],
        created_at="2026-06-04T12:00:00+00:00",
        started_at="2026-06-04T12:01:00+00:00",
        finished_at="2026-06-04T12:02:00+00:00",
        events=[
            JobEvent(1, "info", "terraform output recorded", {"sketchInfrastructure": []}),
        ],
    )


def _chain(status, nodes=None):
    return StoredSketchChain(
        chain_id="proxy01-sea-01",
        engagement_id="eng-zy01",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        status=status,
        burned=False,
        burned_note="",
        deploy_job_id="job-deploy",
        teardown_job_id="",
        terraform_working_directory="/tmp/linode",
        nodes=nodes
        if nodes is not None
        else [
            {
                "provider": "linode",
                "providerInstanceId": "1111",
                "role": "middle",
                "hostname": "middle-zy01",
                "status": status,
            },
            {
                "provider": "linode",
                "providerInstanceId": "2222",
                "role": "edge",
                "hostname": "edge-zy01",
                "status": status,
            },
        ],
        created_at="2026-06-04T12:00:00+00:00",
        updated_at="2026-06-04T12:00:00+00:00",
    )
