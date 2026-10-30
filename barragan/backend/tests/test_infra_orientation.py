# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from app.domain import JobEvent
from app.services import infra_orientation
from app.storage.job_repository import StoredJobRun


def test_render_infra_orientation_is_compact_and_omits_middle_details():
    markdown = infra_orientation.render_infra_orientation_markdown(
        _overview_fixture(),
        engagement_name="demo01",
        generated_at="2026-07-09T12:00:00+00:00",
    )

    assert "# Infrastructure Overview: demo01" in markdown
    assert "| Host | Role | Public IP | Private IP | Services |" in markdown
    assert "| Host | Role | Status |" not in markdown
    assert "proxy01" in markdown
    assert "3333" in markdown
    assert "/opt/proxy01/proxy01-sea-01-socks5.conf" in markdown
    assert "/opt/proxy02/proxy02-sfo-01-socks5.conf" in markdown
    assert "edge01-demo" in markdown
    assert "203.0.113.10" in markdown
    assert "middle01-demo" not in markdown
    assert "middle02-demo" not in markdown
    assert "www[.]example[.]test" in markdown
    assert "Static Web" in markdown
    assert "Mythic" in markdown
    assert "AVOID: burned edge" in markdown
    assert "curl " not in markdown
    assert "ssh " not in markdown
    assert "proxychains " not in markdown
    assert "BEGIN OPENSSH PRIVATE KEY" not in markdown


def test_execute_refresh_writes_infra_markdown_workspace(monkeypatch, tmp_path):
    repo = _FakeJobRepository()
    job = repo.save(_refresh_job())
    captured = {}

    monkeypatch.setattr(infra_orientation, "_get_operations_overview", lambda *args, **kwargs: _overview_fixture())
    monkeypatch.setattr(infra_orientation, "get_engagement", lambda _engagement_id: SimpleNamespace(name="demo01"))
    monkeypatch.setattr(
        infra_orientation,
        "_homebase_from_latest_core",
        lambda _repo, _engagement_id: {
            "name": "homebase",
            "ansibleHost": "198.51.100.10",
            "ansibleUser": "ubuntu",
            "sshPrivateKeyFile": "/var/lib/barragan/.ssh/barragan_testing",
            "knownHostsFile": str(tmp_path / "known_hosts"),
        },
    )

    def runner(command, cwd):
        captured["command"] = command
        captured["content"] = (cwd / "files" / "INFRA.md").read_text(encoding="utf-8")
        captured["playbook"] = (cwd / "ansible" / "write_infra_orientation.yml").read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    result = infra_orientation.execute_infra_orientation_refresh(
        job.id,
        repository=repo,
        runner=runner,
        workspace_root=tmp_path,
    )

    assert result["status"] == "Wrote"
    assert captured["command"][-1] == "ansible/write_infra_orientation.yml"
    assert "Ensure engagement workspace exists as fallback" in captured["playbook"]
    assert "Ensure engagement loot directory exists as fallback" in captured["playbook"]
    assert "path: /engagement/loot" in captured["playbook"]
    assert "dest: /engagement/INFRA.md" in captured["playbook"]
    assert "proxy01-sea-01-socks5.conf" in captured["content"]
    assert repo.get(job.id).status == "succeeded"


class _FakeJobRepository:
    def __init__(self):
        self.jobs = {}

    def list(self):
        return list(self.jobs.values())

    def list_for_engagement(self, engagement_id, *, limit=None):
        jobs = [job for job in self.jobs.values() if job.target_id == engagement_id or job.input.get("engagementId") == engagement_id]
        return jobs[:limit] if limit is not None else jobs

    def list_summaries(self, *, limit, offset):
        return [], 0

    def count(self):
        return len(self.jobs)

    def get(self, job_id):
        return self.jobs.get(job_id)

    def save(self, job):
        self.jobs[job.id] = job
        return job


def _refresh_job() -> StoredJobRun:
    return StoredJobRun(
        id="job-refresh",
        action=infra_orientation.INFRA_ORIENTATION_REFRESH_ACTION,
        status="queued",
        target="engagement:eng-demo",
        target_type="engagement",
        target_id="eng-demo",
        requested_by="operator",
        input={"engagementId": "eng-demo"},
        artifact_refs=[],
        created_at="2026-07-09T12:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "queued", {})],
    )


def _overview_fixture():
    return {
        "engagementId": "eng-demo",
        "coreInfrastructure": [
            {
                "hostname": "homebase-demo",
                "role": "homebase",
                "publicIp": "198.51.100.10",
                "privateIp": "192.168.0.10",
                "services": ["dropbox NFS export"],
            },
            {
                "hostname": "proxy01-demo",
                "role": "proxy",
                "publicIp": "198.51.100.11",
                "privateIp": "192.168.2.11",
                "services": ["Static Web"],
            },
        ],
        "sketchInfrastructure": [
            {
                "chainId": "proxy01-sea-01",
                "role": "middle",
                "hostname": "middle01-demo",
                "publicIp": "203.0.113.20",
            },
            {
                "chainId": "proxy01-sea-01",
                "role": "edge",
                "hostname": "edge01-demo",
                "publicIp": "203.0.113.10",
                "burned": False,
            },
            {
                "chainId": "proxy02-sfo-01",
                "role": "middle",
                "hostname": "middle02-demo",
                "publicIp": "203.0.113.21",
            },
            {
                "chainId": "proxy02-sfo-01",
                "role": "edge",
                "hostname": "edge02-demo",
                "publicIp": "203.0.113.11",
                "burned": True,
                "burnedNote": "provider abuse report",
            },
        ],
        "outboundChannels": [
            {
                "chainId": "proxy01-sea-01",
                "proxy": "proxy01",
                "middle": "middle01-demo",
                "edge": "edge01-demo",
                "port": "3333",
                "domain": "proxy01-sea-01",
                "publicationPath": "/opt/proxy01/proxy01-sea-01-socks5.conf",
                "purpose": "operator egress",
                "status": "Validated",
            },
            {
                "chainId": "proxy02-sfo-01",
                "proxy": "proxy02",
                "middle": "middle02-demo",
                "edge": "edge02-demo",
                "port": "3334",
                "purpose": "backup egress",
                "status": "Validated",
            },
        ],
        "inboundChannels": [
            {
                "channelId": "www",
                "domain": "www.example.test",
                "protocol": "https-openresty",
                "externalPort": "443",
                "edge": "edge01-demo",
                "middle": "middle01-demo",
                "proxy": "proxy01",
                "terminatesOn": "proxy01",
                "service": "Static Web",
                "internalPort": "18080",
                "purpose": "landing site",
                "status": "Validated",
            }
        ],
        "servicePlacements": [
            {
                "service": "Static Web",
                "serviceType": "web-static",
                "hostId": "proxy01",
                "port": "18080",
                "domain": "www.example.test",
                "detail": "site OpenResty container serves static content",
                "status": "Configured",
            },
            {
                "service": "Mythic",
                "serviceType": "generic",
                "hostId": "homebase",
                "port": "7443",
                "detail": "reverse-proxied C2 service",
                "status": "Active",
            },
        ],
    }
