# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.backflips_service import (
    BACKFLIPS_APPLY_CONFIRMATION,
    BACKFLIPS_SERVICE_NAME,
    BackflipsApplyWorkspace,
    BackflipsCoreHost,
    BackflipsServiceValidationError,
    apply_backflips_service,
    _ensure_known_hosts_file,
    _known_hosts_file,
    preview_backflips_service_apply,
    render_backflips_apply_workspace,
)
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


def test_renders_backflips_workspace_for_selected_proxy_only():
    workspace = render_backflips_apply_workspace(
        homebase=BackflipsCoreHost("homebase", "203.0.113.10", "ubuntu", "/keys/core", "", "/tmp/known_hosts"),
        proxy=BackflipsCoreHost("proxy01", "192.168.2.11", "ubuntu", "/keys/core", "ubuntu@203.0.113.10", "/tmp/known_hosts"),
        sketch_key_path="/opt/ssh-proxy/keys/zy01-sketch",
        middle_ip="198.51.100.20",
        sketch_private_key_src="/tmp/keys/zy01-sketch-transport",
    )

    assert workspace.to_dict()["status"] == "Pending Service Apply"
    assert workspace.to_dict()["mutation"] is False
    assert workspace.inventory.target == "ansible/inventory.ini"
    assert "[selected_proxy]" in workspace.inventory.content
    assert "proxy01 ansible_host=192.168.2.11 ansible_user=ubuntu" in workspace.inventory.content
    assert "ProxyCommand='ssh -i /keys/core" in workspace.inventory.content
    assert "UserKnownHostsFile=/tmp/known_hosts" in workspace.inventory.content
    assert "[homebase]" not in workspace.inventory.content
    assert "middle-" not in workspace.inventory.content
    assert "edge-" not in workspace.inventory.content

    assert workspace.playbook.target == "ansible/apply_backflips.yml"
    assert "hosts: selected_proxy" in workspace.playbook.content
    assert "roles:" in workspace.playbook.content
    assert "roles/backflips_v2" in workspace.playbook.content
    assert "sketchkey: /opt/ssh-proxy/keys/zy01-sketch" in workspace.playbook.content
    assert "dest: /opt/ssh-proxy/keys/zy01-sketch" in workspace.playbook.content
    assert "middleIP = 198.51.100.20" in workspace.playbook.content
    assert "Reload systemd after Backflips role" in workspace.playbook.content
    assert "name: docker.socket" in workspace.playbook.content
    assert "name: docker.service" in workspace.playbook.content
    assert workspace.playbook.content.index("name: docker.socket") < workspace.playbook.content.index(
        "name: docker.service"
    )
    assert "Wait for Docker daemon readiness" in workspace.playbook.content
    assert "until: backflips_docker_readiness.rc == 0" in workspace.playbook.content
    assert "hosts: middle" not in workspace.playbook.content
    assert "hosts: edge" not in workspace.playbook.content

    assert '"sketchMiddleTargets": []' in workspace.manifest.content
    assert '"sketchEdgeTargets": []' in workspace.manifest.content
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(workspace.to_dict())


def test_preview_backflips_service_uses_latest_core_connection_details(monkeypatch):
    monkeypatch.setattr("app.services.backflips_service.get_engagement", lambda engagement_id: SimpleNamespace(name="zy01"))
    repo = _FakeJobRepository(_core_jobs())

    result = preview_backflips_service_apply(
        "eng-zy01",
        proxy_id="proxy01",
        requested_by="operator",
        repository=repo,
        sketch_repository=_FakeSketchChainRepository([]),
    )

    assert result is not None
    assert result["workspace"]["inventory"]["target"] == "ansible/inventory.ini"
    assert "proxy01 ansible_host=192.168.2.11" in result["workspace"]["inventory"]["content"]
    assert "UserKnownHostsFile=/tmp/barragan-backflips-known-hosts/eng-zy01-job-core.known_hosts" in result["workspace"]["inventory"]["content"]
    assert "203.0.113.10" in result["workspace"]["manifest"]["content"]
    assert "Install engagement sketch transport identity" in result["workspace"]["playbook"]["content"]
    assert "src: /run/barragan/secure-material/sketch-transport-key" in result["workspace"]["playbook"]["content"]
    assert result["job"]["action"] == "backflips_service_apply_preview"
    event_data = result["job"]["events"][0]["data"]
    assert event_data["inventoryTargets"] if "inventoryTargets" in event_data else ["selected_proxy"]
    assert "inboundChannels" not in event_data
    assert "middle-" not in result["workspace"]["inventory"]["content"]
    assert "edge-" not in result["workspace"]["inventory"]["content"]


def test_preview_backflips_service_rejects_missing_core_connection_details(monkeypatch):
    monkeypatch.setattr("app.services.backflips_service.get_engagement", lambda engagement_id: SimpleNamespace(name="zy01"))
    repo = _FakeJobRepository([])

    with pytest.raises(BackflipsServiceValidationError) as exc:
        preview_backflips_service_apply(
            "eng-zy01",
            repository=repo,
            sketch_repository=_FakeSketchChainRepository([]),
        )

    assert "latest core deployment connectionDetails must include homebase" in exc.value.errors


def test_apply_backflips_service_requires_confirmation_before_resolving_ansible(monkeypatch):
    monkeypatch.setattr("app.services.backflips_service.get_engagement", lambda engagement_id: object())

    with pytest.raises(BackflipsServiceValidationError) as exc:
        apply_backflips_service("eng-zy01", confirmation="wrong", repository=_FakeJobRepository(_core_jobs()))

    assert f'confirmation must equal "{BACKFLIPS_APPLY_CONFIRMATION}"' in exc.value.errors


def test_apply_backflips_service_writes_workspace_and_runs_one_playbook(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.backflips_service.get_engagement", lambda engagement_id: SimpleNamespace(name="zy01"))
    monkeypatch.setattr(
        "app.services.backflips_service.write_existing_sketch_transport_ssh_key_files",
        lambda engagement_id, directory: (str(directory / "zy01-sketch-transport"), str(directory / "zy01-sketch-transport.pub")),
    )
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    commands = []

    def runner(command, cwd):
        commands.append((command, cwd))
        assert (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8").count("[selected_proxy]") == 1
        assert "middle-" not in (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        assert "edge-" not in (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = apply_backflips_service(
        "eng-zy01",
        confirmation=BACKFLIPS_APPLY_CONFIRMATION,
        proxy_id="proxy01",
        requested_by="operator",
        repository=_FakeJobRepository(_core_jobs()),
        sketch_repository=_FakeSketchChainRepository(
            [
                _sketch_chain(
                    "proxy01-sea-01",
                    "proxy01",
                    nodes=[{"role": "middle", "hostname": "middle-zy01", "publicIp": "198.51.100.20"}],
                )
            ]
        ),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["status"] == "Configured"
    assert result["job"]["status"] == "succeeded"
    assert result["job"]["input"]["coreDeploymentId"] == "job-core"
    assert result["job"]["input"]["coreProxyIdentity"] == {
        "displayName": "proxy01-zy01",
        "publicIp": "203.0.113.11",
        "privateIp": "192.168.2.11",
        "sshAlias": "proxy01",
    }
    assert len(commands) == 1
    assert commands[0][0] == [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/apply_backflips.yml"]
    final_event = result["job"]["events"][-1]["data"]
    assert final_event["servicePlacements"][0]["service"] == BACKFLIPS_SERVICE_NAME
    assert "inboundChannels" not in final_event
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(result)
    playbook = (commands[0][1] / "ansible" / "apply_backflips.yml").read_text(encoding="utf-8")
    assert "sketchkey: /opt/ssh-proxy/keys/zy01-sketch" in playbook
    assert "middleIP = 198.51.100.20" in playbook


def test_apply_backflips_service_records_failed_service_state_when_docker_readiness_fails(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("app.services.backflips_service.get_engagement", lambda engagement_id: SimpleNamespace(name="zy01"))
    monkeypatch.setattr(
        "app.services.backflips_service.write_existing_sketch_transport_ssh_key_files",
        lambda engagement_id, directory: (str(directory / "zy01-sketch-transport"), str(directory / "zy01-sketch-transport.pub")),
    )
    ansible_playbook = _executable(tmp_path, "ansible-playbook")

    def runner(command, cwd):
        playbook = (cwd / "ansible" / "apply_backflips.yml").read_text(encoding="utf-8")
        assert "Wait for Docker daemon readiness" in playbook
        assert "until: backflips_docker_readiness.rc == 0" in playbook
        return subprocess.CompletedProcess(command, 2, "", "Docker daemon readiness check failed")

    result = apply_backflips_service(
        "eng-zy01",
        confirmation=BACKFLIPS_APPLY_CONFIRMATION,
        proxy_id="proxy01",
        requested_by="operator",
        repository=_FakeJobRepository(_core_jobs()),
        sketch_repository=_FakeSketchChainRepository([]),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["status"] == "Failed"
    assert result["job"]["status"] == "failed"
    final_event = result["job"]["events"][-1]["data"]
    assert final_event["servicePlacements"][0]["status"] == "Failed"
    assert "inboundChannels" not in final_event
    first_event = result["job"]["events"][0]["data"]
    assert first_event["servicePlacements"][0]["status"] == "Applying"
    assert "inboundChannels" not in first_event


def test_ensure_known_hosts_file_creates_deployment_scoped_file(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.backflips_service.DEFAULT_KNOWN_HOSTS_ROOT", tmp_path / "known-hosts")

    path = _known_hosts_file("eng/a86", "job/core")
    _ensure_known_hosts_file(path)

    assert path.endswith("eng_a86-job_core.known_hosts")
    assert (tmp_path / "known-hosts" / "eng_a86-job_core.known_hosts").exists()


def _core_jobs():
    return [
        StoredJobRun(
            id="job-core",
            action="pilot_standard_rti_guarded_execute",
            status="succeeded",
            target="oci-compartment:barragan-testing",
            target_type="oci_compartment",
            target_id="ocid1.compartment.oc1..testing",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:00:00+00:00",
            started_at="2026-06-04T12:01:00+00:00",
            finished_at="2026-06-04T12:05:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "operator inspection ready",
                    {
                        "connectionDetails": [
                            {
                                "role": "homebase",
                                "displayName": "homebase-zy01",
                                "publicIp": "203.0.113.10",
                                "privateIp": "192.168.0.10",
                                "sshUser": "ubuntu",
                            },
                            {
                                "role": "proxy",
                                "displayName": "proxy01-zy01",
                                "publicIp": "203.0.113.11",
                                "privateIp": "192.168.2.11",
                                "sshUser": "ubuntu",
                            },
                        ]
                    },
                )
            ],
        )
    ]


def _executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class _FakeJobRepository:
    def __init__(self, jobs):
        self.jobs = list(jobs)
        self.saved = []

    def list(self):
        return list(self.jobs)

    def list_for_engagement(self, engagement_id, *, limit=None):
        jobs = [job for job in self.list() if (
            job.target_id == engagement_id or job.target == f"engagement:{engagement_id}"
            or job.input.get("engagementId") == engagement_id
        )]
        jobs.sort(key=lambda job: job.created_at, reverse=True)
        return jobs if limit is None else jobs[:limit]

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


class _FakeSketchChainRepository:
    def __init__(self, chains):
        self.chains = list(chains)

    def list_for_engagement(self, engagement_id):
        return list(self.chains)

    def get(self, engagement_id, chain_id):
        for chain in self.chains:
            if chain.chain_id == chain_id:
                return chain
        return None

    def save(self, chain):
        self.chains = [existing for existing in self.chains if existing.chain_id != chain.chain_id]
        self.chains.append(chain)
        return chain


def _sketch_chain(chain_id, proxy, *, status="deployed", burned=False, nodes=None):
    return StoredSketchChain(
        chain_id=chain_id,
        engagement_id="eng-zy01",
        assigned_proxy=proxy,
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        status=status,
        burned=burned,
        burned_note="",
        deploy_job_id="job-sketch",
        teardown_job_id="",
        terraform_working_directory="",
        nodes=list(nodes or []),
        created_at="2026-07-26T00:00:00+00:00",
        updated_at="2026-07-26T00:00:00+00:00",
    )
