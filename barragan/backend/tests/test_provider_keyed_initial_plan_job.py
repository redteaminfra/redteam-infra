# Copyright (c) 2026, Oracle and/or its affiliates.
"""Orchestration checks for the non-applying DevTest keyed plan job."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_initial_plan_job as service
from app.domain import JobEvent
from app.storage.job_repository import StoredJobRun


class Jobs:
    def __init__(self, job):
        self.job = job
        self.saved = []

    def get(self, job_id):
        return self.job if job_id == self.job.id else None

    def save(self, job):
        self.job = job
        self.saved.append(job)
        return job


def _job(*, status="queued", environment_target="engagement:eng-opaque"):
    return StoredJobRun(
        id="job-plan-opaque", action=service.ACTION, status=status,
        target=environment_target, target_type="engagement", target_id="eng-opaque",
        requested_by="example_operator_three", input={"engagementId": "eng-opaque", "coreJobId": "job-core-opaque", "mutation": False},
        artifact_refs=[], created_at="2026-10-02T00:00:00Z", started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "job queued", {})],
    )


@pytest.mark.parametrize("transport_missing", [False, True])
def test_plan_job_uses_persisted_intent_and_removes_private_key(tmp_path, monkeypatch, transport_missing):
    state_root = tmp_path / "state"
    schema_root = state_root / "eng-opaque" / "provider-keyed-v2"
    workspace_root = schema_root / "digitalocean" / "fingerprint"
    workspace_root.mkdir(parents=True)
    workspace = SimpleNamespace(path=workspace_root)
    topology = {
        "middles": {"middle_01": {"region": "nyc3", "ordinal": 1}},
        "edge_groups": {"group_01_sfo3": {"region": "sfo3", "middle_node": "middle_01", "ordinals": [1]}},
    }
    nodes = {
        'digitalocean_droplet.middle["middle_01"]': SimpleNamespace(name="middle01-opaque"),
        'digitalocean_droplet.edge["sfo3-01"]': SimpleNamespace(name="edge-opaque-sfo3-01"),
    }
    intent = SimpleNamespace(
        engagement_id="eng-opaque", core_job_id="job-core-opaque", core_plan_id="plan-opaque",
        revision_id="revision-opaque", engagement_name="opaque", selector_tag="selector-opaque",
        topology=topology, nodes=nodes, firewall=object(),
        nonsecret_varfile={"middles": topology["middles"], "edge_groups": topology["edge_groups"]},
    )
    jobs = Jobs(_job())
    def preflight(*_args, **kwargs):
        assert kwargs["lease_owner"] == "plan-opaque"
        return intent
    monkeypatch.setattr(service, "preflight_fresh_digitalocean_provider", preflight)
    monkeypatch.setattr(service, "require_devtest_terraform_release", lambda **kw: SimpleNamespace(path=Path("/usr/bin/terraform"), sha256="a" * 64))
    monkeypatch.setattr(service, "resolve_default_provider_connection", lambda *a, **kw: "credential-opaque")
    monkeypatch.setattr(service, "require_fresh_digitalocean_review_authorization",
                        lambda *a, **kw: None)
    monkeypatch.setattr(service, "prepare_provider_keyed_workspace", lambda *a, **kw: workspace)
    monkeypatch.setattr(service, "reserve_provider_topology", lambda *a, **kw: topology)
    key = SimpleNamespace(private_key="PRIVATE-FIXTURE-BYTES", public_key="ssh-ed25519 PUBLIC-FIXTURE")
    monkeypatch.setattr(service, "ensure_sketch_ssh_key",
                        lambda *a, **kw: pytest.fail("existing key must not be regenerated"))
    monkeypatch.setattr(service, "retrieve_sketch_ssh_key", lambda *a, **kw: key)
    transport = SimpleNamespace(private_key="TRANSPORT-PRIVATE-FIXTURE",
                                public_key="ssh-ed25519 TRANSPORT-PUBLIC-FIXTURE")
    retained_transport = [None]
    transport_calls = []

    def retrieve_transport(engagement_id):
        assert engagement_id == "eng-opaque"
        transport_calls.append("retrieve")
        return retained_transport[0]

    def ensure_transport(engagement_id):
        assert engagement_id == "eng-opaque"
        transport_calls.append("ensure")
        if not transport_missing:
            retained_transport[0] = transport

    monkeypatch.setattr(service, "retrieve_sketch_transport_ssh_key", retrieve_transport)
    monkeypatch.setattr(service, "ensure_sketch_transport_ssh_key", ensure_transport)
    calls = []

    def plan(workspace, **kwargs):
        calls.append(kwargs)
        varfile = next(iter(kwargs["input_sha256"]))
        assert varfile.is_file() and varfile.stat().st_mode & 0o077 == 0
        assert "do_pat" not in json.loads(varfile.read_text())
        assert kwargs["expected_local_files"]["local_file.ansible_inventory[0]"]["content"].startswith("[all:vars]\n")
        return SimpleNamespace(
            plan_path=workspace.path / ".barragan-initial-full.tfplan", plan_sha256="b" * 64,
            source_sha256="c" * 64, marker_sha256="d" * 64, topology_sha256="e" * 64,
            lockfile_sha256="f" * 64, input_sha256=((str(varfile), hashlib.sha256(varfile.read_bytes()).hexdigest()),),
            credential_secret_sha256="1" * 64, credential_updated_at="2026-10-02T00:00:00Z",
            terraform_binary_path=Path("/usr/bin/terraform"), terraform_binary_sha256="a" * 64,
            terraform_version="1.15.5",
        )

    monkeypatch.setattr(service, "prepare_digitalocean_keyed_initial_full_plan", plan)
    if transport_missing:
        with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="provider plan preparation failed"):
            service.run_fresh_digitalocean_initial_plan_job(
                "job-plan-opaque", lease_owner="plan-opaque", environment="devtest", state_root=state_root,
                template_root=tmp_path / "upstream", job_repository=jobs, credential_repository=object(),
                plan_repository=SimpleNamespace(get=lambda _id: object()),
            )
        assert transport_calls == ["retrieve", "ensure", "retrieve"]
        assert [job.status for job in jobs.saved] == ["running", "failed"]
        assert not calls
        return
    result = service.run_fresh_digitalocean_initial_plan_job(
        "job-plan-opaque", lease_owner="plan-opaque", environment="devtest", state_root=state_root,
        template_root=tmp_path / "upstream", job_repository=jobs, credential_repository=object(),
        plan_repository=SimpleNamespace(get=lambda _id: object()),
    )
    assert result.status == "succeeded" and len(calls) == 1
    assert transport_calls == ["retrieve", "ensure", "retrieve"]
    assert [job.status for job in jobs.saved] == ["running", "succeeded"]
    event = result.events[-1].data
    assert event["adminPublicKeySha256"] == hashlib.sha256(b"ssh-ed25519 PUBLIC-FIXTURE").hexdigest()
    assert not Path(event["adminPrivateKeyPath"]).exists()
    assert not Path(event["adminPublicKeyPath"]).exists()
    assert Path(event["sshOutputDirectory"]).is_dir()
    owner = json.loads((workspace_root / ".barragan-initial-plan-owner.json").read_text())
    assert owner["planJobId"] == "job-plan-opaque"
    assert owner["providerConnectionId"] == "credential-opaque"
    assert "PRIVATE-FIXTURE-BYTES" not in json.dumps(result.input) + json.dumps(event)
    assert transport.private_key not in json.dumps(result.input) + json.dumps(event)
    assert transport.public_key not in json.dumps(result.input) + json.dumps(event)
    assert calls[0]["expected_ssh_public_key"] == key.public_key
    assert transport.public_key != calls[0]["expected_ssh_public_key"]


def test_expected_inventory_matches_audited_keyed_template_whitespace():
    # Exact templatefile output from Terraform 1.15.5 against clean upstream
    # ca5bcad7, including the blank line between node groups.
    names = {
        'digitalocean_droplet.middle["first"]': SimpleNamespace(name="middle01-opaque"),
        'digitalocean_droplet.middle["second"]': SimpleNamespace(name="middle02-opaque"),
        'digitalocean_droplet.edge["nyc3-01"]': SimpleNamespace(name="edge-opaque-nyc3-01"),
        'digitalocean_droplet.edge["sfo3-01"]': SimpleNamespace(name="edge-opaque-sfo3-01"),
    }
    intent = SimpleNamespace(
        engagement_name="opaque", nodes=names,
        topology={"middles": {"second": {}, "first": {}},
                  "edge_groups": {"west": {"region": "sfo3", "ordinals": [1]},
                                  "east": {"region": "nyc3", "ordinals": [1]}}},
    )
    assert service._expected_inventory(intent, Path("/private/key")) == (
        "[all:vars]\n"
        "infra_user=ubuntu\n"
        "ansible_connection=ssh\n"
        "ansible_ssh_user=root\n"
        "ansible_ssh_host_key_checking=no\n"
        "ansible_ssh_common_args=-o UserKnownHostsFile=/dev/null "
        "-o ProxyCommand='ssh -o UserKnownHostsFile=/dev/null "
        "-o StrictHostKeyChecking=no -i /private/key -W %h:%p "
        "{{ infra_user }}@homebase-opaque'\n\n"
        "[middle]\n"
        "middle01-opaque\n"
        "middle02-opaque\n\n"
        "[edge]\n"
        "edge-opaque-nyc3-01\n"
        "edge-opaque-sfo3-01\n"
    )


def test_expected_inventory_matches_real_terraform_templatefile_fixture():
    """Capture from Terraform 1.15.5 console on clean upstream ca5bcad7."""
    intent = SimpleNamespace(
        engagement_name="opaque",
        nodes={
            'digitalocean_droplet.middle["first"]': SimpleNamespace(name="middle01-opaque"),
            'digitalocean_droplet.edge["sfo3-01"]': SimpleNamespace(name="edge-opaque-sfo3-01"),
        },
        topology={
            "middles": {"first": {}},
            "edge_groups": {"west": {"region": "sfo3", "ordinals": [1]}},
        },
    )
    fixture = Path(__file__).parent / "fixtures/provider_keyed/digitalocean-inventory-templatefile-1.15.5.txt"
    assert service._expected_inventory(intent, Path("/tmp/admin-private")) == fixture.read_text()


def test_job_rejects_non_devtest_before_touching_repositories():
    jobs = Jobs(_job())
    with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="queued DevTest"):
        service.run_fresh_digitalocean_initial_plan_job(
            "job-plan-opaque", lease_owner="plan-opaque", environment="prod", state_root=Path("/tmp/unused"),
            template_root=Path("/tmp/unused"), job_repository=jobs,
        )
    assert not jobs.saved


def test_review_mismatch_fails_before_workspace_or_terraform(tmp_path, monkeypatch):
    jobs = Jobs(_job())
    intent = SimpleNamespace(core_plan_id="plan-opaque", core_job_id="job-core-opaque")
    monkeypatch.setattr(service, "preflight_fresh_digitalocean_provider", lambda *a, **kw: intent)
    monkeypatch.setattr(service, "require_devtest_terraform_release",
                        lambda **kw: pytest.fail("Terraform release check must follow reviewed authorization"))
    monkeypatch.setattr(service, "resolve_default_provider_connection", lambda *a, **kw: "credential-opaque")
    def reject(*_args, **_kwargs):
        raise ValueError("reviewed authorization changed")
    monkeypatch.setattr(service, "require_fresh_digitalocean_review_authorization", reject)
    monkeypatch.setattr(service, "prepare_provider_keyed_workspace",
                        lambda *a, **kw: pytest.fail("workspace must not be created"))
    monkeypatch.setattr(service, "prepare_digitalocean_keyed_initial_full_plan",
                        lambda *a, **kw: pytest.fail("Terraform plan must not run"))
    with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="provider plan preparation failed"):
        service.run_fresh_digitalocean_initial_plan_job(
            "job-plan-opaque", lease_owner="plan-opaque", environment="devtest", state_root=tmp_path / "state",
            template_root=tmp_path / "upstream", job_repository=jobs,
            credential_repository=object(), plan_repository=SimpleNamespace(get=lambda _id: object()),
        )
    assert [job.status for job in jobs.saved] == ["running", "failed"]
    assert "reviewed authorization changed" not in json.dumps(jobs.job.events[-1].to_dict())


@pytest.mark.parametrize("mismatch", ["plan", "job"])
def test_preflight_core_identity_mismatch_fails_before_workspace_or_terraform(tmp_path, monkeypatch, mismatch):
    jobs = Jobs(_job())
    intent = SimpleNamespace(
        core_plan_id="other-plan" if mismatch == "plan" else "plan-opaque",
        core_job_id="other-job" if mismatch == "job" else "job-core-opaque",
    )
    monkeypatch.setattr(service, "preflight_fresh_digitalocean_provider", lambda *_a, **_kw: intent)
    monkeypatch.setattr(service, "resolve_default_provider_connection",
                        lambda *_a, **_kw: pytest.fail("credential lookup must not run"))
    monkeypatch.setattr(service, "prepare_provider_keyed_workspace",
                        lambda *_a, **_kw: pytest.fail("workspace must not be created"))
    monkeypatch.setattr(service, "prepare_digitalocean_keyed_initial_full_plan",
                        lambda *_a, **_kw: pytest.fail("Terraform plan must not run"))
    with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="provider plan preparation failed"):
        service.run_fresh_digitalocean_initial_plan_job(
            "job-plan-opaque", lease_owner="plan-opaque", environment="devtest",
            state_root=tmp_path / "state", template_root=tmp_path / "upstream",
            job_repository=jobs, credential_repository=object(),
        )
    assert [job.status for job in jobs.saved] == ["running", "failed"]
    assert jobs.job.input == _job().input
    assert not (tmp_path / "state").exists()


def test_private_material_refuses_existing_symlink(tmp_path):
    material = tmp_path / "material"
    material.symlink_to(tmp_path)
    with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="unsafe"):
        service._prepare_private_material_directory(material)


def test_private_material_accepts_owner_only_setgid_directory(tmp_path):
    material = tmp_path / "material"
    material.mkdir()
    material.chmod(0o2700)
    service._prepare_private_material_directory(material)
    material.chmod(0o2710)
    with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="unsafe"):
        service._prepare_private_material_directory(material)


def test_private_file_creation_is_exclusive(tmp_path):
    path = tmp_path / "key"
    path.write_text("existing")
    with pytest.raises(FileExistsError):
        service._write_private_new(path, "new secret")
    assert path.read_text() == "existing"


def test_plan_failure_removes_private_key_and_records_redacted_failure(tmp_path, monkeypatch):
    state_root = tmp_path / "state"
    schema_root = state_root / "eng-opaque" / "provider-keyed-v2"
    workspace_root = schema_root / "digitalocean" / "fingerprint"
    workspace_root.mkdir(parents=True)
    topology = {"middles": {"middle_01": {"region": "nyc3", "ordinal": 1}},
                "edge_groups": {"sfo": {"region": "sfo3", "middle_node": "middle_01", "ordinals": [1]}}}
    intent = SimpleNamespace(
        engagement_id="eng-opaque", core_job_id="job-core-opaque", core_plan_id="plan-opaque",
        engagement_name="opaque", topology=topology,
        nonsecret_varfile={}, nodes={}, firewall=object(),
    )
    jobs = Jobs(_job())
    monkeypatch.setattr(service, "preflight_fresh_digitalocean_provider", lambda *a, **kw: intent)
    monkeypatch.setattr(service, "require_devtest_terraform_release", lambda **kw: SimpleNamespace(path=Path("/usr/bin/terraform"), sha256="a" * 64))
    monkeypatch.setattr(service, "resolve_default_provider_connection", lambda *a, **kw: "credential-opaque")
    monkeypatch.setattr(service, "require_fresh_digitalocean_review_authorization",
                        lambda *a, **kw: None)
    monkeypatch.setattr(service, "prepare_provider_keyed_workspace", lambda *a, **kw: SimpleNamespace(path=workspace_root))
    monkeypatch.setattr(service, "reserve_provider_topology", lambda *a, **kw: topology)
    key = SimpleNamespace(private_key="PRIVATE-FIXTURE-BYTES", public_key="ssh-ed25519 PUBLIC-FIXTURE")
    key_calls = []
    monkeypatch.setattr(service, "retrieve_sketch_ssh_key",
                        lambda *a, **kw: key if key_calls else None)
    monkeypatch.setattr(service, "ensure_sketch_ssh_key",
                        lambda *a, **kw: key_calls.append("created"))
    monkeypatch.setattr(service, "prepare_digitalocean_keyed_initial_full_plan",
                        lambda *a, **kw: (_ for _ in ()).throw(ValueError("secret-from-provider")))
    with pytest.raises(service.ProviderKeyedInitialPlanJobError, match="provider plan preparation failed"):
        service.run_fresh_digitalocean_initial_plan_job(
            "job-plan-opaque", lease_owner="plan-opaque", environment="devtest", state_root=state_root,
            template_root=tmp_path / "upstream", job_repository=jobs, credential_repository=object(),
            plan_repository=SimpleNamespace(get=lambda _id: object()),
        )
    material = schema_root / ".plan-material" / "digitalocean"
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()
    assert jobs.job.status == "failed"
    assert key_calls == ["created"]
    assert "secret-from-provider" not in json.dumps(jobs.job.events[-1].to_dict())
