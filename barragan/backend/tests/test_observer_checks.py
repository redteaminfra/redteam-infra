# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import ast
import base64
import errno
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from dataclasses import asdict, replace

from app.domain import JobEvent
from app.integrations.command_resolution import CommandResolution
from app.services import inspector_scheduler, observer_checks
from app.services.observer_checks import (
    _OBSERVER_SCRIPT,
    _record_certificate_binding_validation,
    DigitalOceanObserverProvider,
    InspectorCreateStage,
    InspectorCreateUncertainError,
    INSPECTOR_READINESS_ACTION,
    INSPECTOR_CLEANUP_ACTION,
    InspectorCleanupValidationError,
    LinodeObserverProvider,
    _inspector_firewall_tag,
    _settings_response,
    _provider_factory_for_engagement,
    ObserverCheckValidationError,
    ObserverHost,
    ObserverSshKey,
    SshObserverRunner,
    cleanup_inspector_for_infrastructure_teardown,
    ensure_continuous_inspector_ready,
    ensure_inspector_for_infrastructure_teardown,
    inspector_state_for_infrastructure_teardown,
    inspection_targets,
    preview_inspector_cleanup,
    observer_check_targets,
    start_inspection,
    start_inspector_cleanup,
    start_observer_check,
    verify_retired_public_endpoints_for_teardown,
)
from app.integrations.digitalocean_validation import DigitalOceanValidationError
from app.integrations.linode_validation import LinodeValidationError
from app.integrations.managed_host_images import MANAGED_HOST_IMAGE_PROFILES
from app.services.engagement_operations import get_operations_overview
from app.services.inbound_raw_route_plan import apply_plan_to_channel, plan_new_raw_route
from app.storage.inspection_run_repository import SqlAlchemyInspectionRunRepository, StoredInspectionRun
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository, StoredObserverSettings
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord
from app.storage.domain_repository import (
    SqlAlchemyDomainRepository,
    StoredDomainAsset,
    StoredDomainAssignment,
)
from app.storage.certificate_repository import StoredCertificateBinding


class FakeObserverProvider:
    def __init__(self, cleanup_ok: bool = True):
        self.cleanup_ok = cleanup_ok
        self.created = []
        self.destroyed = []

    def create(self, *, token: str, name: str, region: str, size: str, public_key: str) -> ObserverHost:
        self.created.append({"token": token, "name": name, "region": region, "size": size, "publicKey": public_key})
        return ObserverHost(
            provider="linode",
            resource_type="instance",
            resource_id="12345",
            name=name,
            region=region,
            public_ip="198.51.100.25",
            metadata={"publicIps": ["198.51.100.25"]},
        )

    def destroy(self, *, token: str, host: ObserverHost) -> bool:
        self.destroyed.append({"token": token, "host": host})
        return self.cleanup_ok


def test_default_inspector_factory_uses_engagement_profile(monkeypatch):
    monkeypatch.setattr(
        observer_checks,
        "resolve_or_pin_profile_for_new_managed_host",
        lambda _engagement_id: MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"],
    )

    factory = _provider_factory_for_engagement("eng-1", None)

    assert factory("linode").image == "linode/ubuntu22.04"
    assert factory("digitalocean").image == "ubuntu-22-04-x64"


def _observer_script_http_probe(http_client):
    tree = ast.parse(_OBSERVER_SCRIPT)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "http_probe"
    )
    namespace = {"http": SimpleNamespace(client=http_client)}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observer-http-probe>", "exec"), namespace)
    return namespace["http_probe"]


class FakeObserverRunner:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls = []

    def run(self, *, host: ObserverHost, ssh_key: ObserverSshKey, spec: dict):
        self.calls.append({"host": host, "sshKey": ssh_key, "spec": spec})
        return {
            "ok": self.ok,
            "results": [
                {"id": target["id"], "type": target["type"], "ok": self.ok}
                for target in spec.get("positive", [])
            ],
        }


class FakeFailingObserverRunner:
    def run(self, *, host: ObserverHost, ssh_key: ObserverSshKey, spec: dict):
        raise ObserverCheckValidationError(["inspector SSH did not become ready", "ssh: connect to host 198.51.100.25 port 22: Connection timed out"])


class FakeTeardownVerificationRunner:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls = []

    def run(self, *, host: ObserverHost, ssh_key: ObserverSshKey, spec: dict):
        self.calls.append({"host": host, "sshKey": ssh_key, "spec": spec})
        return {
            "ok": self.ok,
            "results": [
                {"id": target["id"], "type": target["type"], "ok": self.ok}
                for target in spec.get("negative", [])
            ],
        }


class FakePreparingInspectorRunner(SshObserverRunner):
    def __init__(self):
        super().__init__(readiness_attempts=1, readiness_delay_seconds=0)
        self.prepared = []
        self.verified = []
        self.calls = []

    def verify_access(self, *, host: ObserverHost, ssh_key: ObserverSshKey) -> None:
        self.verified.append({"host": host, "sshKey": ssh_key})

    def prepare_support_host(self, *, host: ObserverHost, ssh_key: ObserverSshKey, packages=("nmap",)) -> ObserverHost:
        self.prepared.append({"host": host, "sshKey": ssh_key, "packages": packages})
        metadata = dict(host.metadata or {})
        metadata["adminIdentityVersion"] = 1
        metadata["rootLoginDisabled"] = True
        metadata["supportPreparationVersion"] = 1
        metadata["supportPreparedPackages"] = sorted(packages)
        return replace(host, ssh_user="barragan", metadata=metadata)

    def run(self, *, host: ObserverHost, ssh_key: ObserverSshKey, spec: dict):
        self.calls.append({"host": host, "sshKey": ssh_key, "spec": spec})
        return {"ok": True, "results": []}


class FakeFailingPreparationRunner(FakePreparingInspectorRunner):
    def prepare_support_host(self, *, host: ObserverHost, ssh_key: ObserverSshKey, packages=("nmap",)) -> ObserverHost:
        raise ObserverCheckValidationError(["Inspector support-host preparation failed"])


class FakeRejectedReuseInspectorRunner(FakePreparingInspectorRunner):
    def verify_access(self, *, host: ObserverHost, ssh_key: ObserverSshKey) -> None:
        self.verified.append({"host": host, "sshKey": ssh_key})
        raise ObserverCheckValidationError(["retained Inspector SSH verification failed"])


class FakeInspectorSettingsRepository:
    def __init__(self, engagement_id: str):
        self.settings = StoredObserverSettings(
            engagement_id=engagement_id,
            enabled=True,
            provider="linode",
            region="us-sea",
            size="g6-nanode-1",
            mode="regular",
            schedule_weekdays=["mon"],
            schedule_time_utc="01:00",
            check_families=["inbound"],
            forbidden_tcp_ports=[2222],
            port_scan_profiles=[],
            current_host={},
            idle_retention_until="",
            last_scheduled_slot="",
            last_mutation_job_inspected="",
            created_at="2026-08-18T00:00:00+00:00",
            updated_at="2026-08-18T00:00:00+00:00",
        )

    def get(self, _engagement_id):
        return self.settings

    def save(self, settings):
        self.settings = settings
        return settings


class FakeInspectorResourceRepository:
    def __init__(self):
        self.records = []
        self.save_calls = []

    def list_for_engagement(self, engagement_id):
        return [record for record in self.records if record.engagement_id == engagement_id]

    def save(self, record):
        self.save_calls.append(record)
        self.records = [current for current in self.records if current.id != record.id] + [record]
        return record


class MissingObserverTransport:
    def __init__(self, error: Exception):
        self.error = error
        self.calls = []

    def request(self, method: str, path: str, token: str, body: dict | None = None):
        self.calls.append((method, path))
        raise self.error


class RecordingObserverTransport:
    def __init__(self, responses):
        self.responses = dict(responses)
        self.calls = []

    def request(self, method: str, path: str, token: str, body: dict | None = None):
        self.calls.append((method, path, body))
        response = self.responses.get((method, path))
        if isinstance(response, Exception):
            raise response
        if response is None:
            return {}
        return response


def test_linode_inspector_create_attaches_default_deny_firewall_before_instance():
    transport = RecordingObserverTransport(
        {
            ("POST", "/networking/firewalls"): {"id": 42},
            ("POST", "/linode/instances"): {"id": 123, "status": "running", "ipv4": ["198.51.100.25"]},
            ("GET", "/linode/instances/123"): {"id": 123, "status": "running", "ipv4": ["198.51.100.25"]},
        }
    )
    provider = LinodeObserverProvider(
        transport=transport,
        poll_attempts=1,
        poll_delay_seconds=0,
        management_source_resolver=lambda: "203.0.113.10/32",
        image="linode/ubuntu22.04",
    )

    host = provider.create(token="token", name="inspector-opaque", region="us-sea", size="g6-nanode-1", public_key="ssh-ed25519 test")

    firewall = transport.calls[0][2]
    instance = transport.calls[1][2]
    assert firewall["rules"]["inbound_policy"] == "DROP"
    assert firewall["rules"]["outbound_policy"] == "ACCEPT"
    assert firewall["rules"]["inbound"] == [{"action": "ACCEPT", "protocol": "TCP", "ports": "22", "addresses": {"ipv4": ["203.0.113.10/32"]}}]
    assert instance["firewall_id"] == 42
    assert instance["image"] == "linode/ubuntu22.04"
    cloud_init = base64.b64decode(instance["metadata"]["user_data"]).decode("utf-8")
    assert "name: barragan" in cloud_init
    assert "lock_passwd: true" in cloud_init
    assert "ssh_pwauth: false" in cloud_init
    assert host.ssh_user == "barragan"
    assert host.metadata["providerFirewall"]["resourceId"] == "42"


def test_digitalocean_inspector_waits_for_firewall_attachment_before_host_ready():
    transport = RecordingObserverTransport(
        {
            ("POST", "/tags"): {},
            ("POST", "/firewalls"): {"firewall": {"id": "fw-42"}},
            ("POST", "/droplets"): {"droplet": {"id": 456}},
            ("POST", "/firewalls/fw-42/droplets"): {},
            ("GET", "/firewalls/fw-42"): {"firewall": {"droplet_ids": [456], "pending_changes": []}},
            ("GET", "/droplets/456"): {
                "droplet": {"id": 456, "status": "active", "networks": {"v4": [{"type": "public", "ip_address": "198.51.100.26"}]}}
            },
        }
    )
    provider = DigitalOceanObserverProvider(
        transport=transport,
        poll_attempts=1,
        poll_delay_seconds=0,
        management_source_resolver=lambda: "203.0.113.10/32",
        image="ubuntu-22-04-x64",
    )

    host = provider.create(token="token", name="inspector-opaque", region="sfo3", size="s-1vcpu-1gb", public_key="ssh-ed25519 test")

    assert transport.calls[0] == ("POST", "/tags", {"name": _inspector_firewall_tag("inspector-opaque")})
    firewall = transport.calls[1][2]
    droplet = transport.calls[2][2]
    assert firewall["inbound_rules"] == [{"protocol": "tcp", "ports": "22", "sources": {"addresses": ["203.0.113.10/32"]}}]
    assert {rule["protocol"] for rule in firewall["outbound_rules"]} == {"tcp", "udp", "icmp"}
    assert "barragan" in droplet["tags"] and "inspector" in droplet["tags"]
    assert droplet["image"] == "ubuntu-22-04-x64"
    assert "name: barragan" in droplet["user_data"]
    assert "name: observer" not in droplet["user_data"]
    assert host.ssh_user == "barragan"
    assert transport.calls[3] == ("POST", "/firewalls/fw-42/droplets", {"droplet_ids": [456]})
    assert host.metadata["providerFirewall"]["resourceId"] == "fw-42"


def _hooked_inspector_provider(provider_name, timeline, *, failed_post=None):
    if provider_name == "linode":
        responses = {
            ("POST", "/networking/firewalls"): {"id": 42},
            ("POST", "/linode/instances"): {"id": 123, "status": "running", "ipv4": ["198.51.100.25"]},
            ("GET", "/linode/instances/123"): {"id": 123, "status": "running", "ipv4": ["198.51.100.25"]},
        }
        provider_class = LinodeObserverProvider
    else:
        responses = {
            ("POST", "/tags"): {},
            ("POST", "/firewalls"): {"firewall": {"id": "fw-42"}},
            ("POST", "/droplets"): {"droplet": {"id": 456}},
            ("POST", "/firewalls/fw-42/droplets"): {},
            ("GET", "/firewalls/fw-42"): {"firewall": {"droplet_ids": [456], "pending_changes": []}},
            ("GET", "/droplets/456"): {"droplet": {"id": 456, "status": "active", "networks": {
                "v4": [{"type": "public", "ip_address": "198.51.100.26"}]}}},
        }
        provider_class = DigitalOceanObserverProvider
    if failed_post is not None:
        responses[failed_post] = RuntimeError("provider response lost: secret-token")
    class TimelineTransport(RecordingObserverTransport):
        def request(self, method, path, token, body=None):
            if method == "POST":
                timeline.append(("POST", path))
            return super().request(method, path, token, body)
    transport = TimelineTransport(responses)
    provider = provider_class(
        transport=transport, poll_attempts=1, poll_delay_seconds=0,
        management_source_resolver=lambda: "203.0.113.10/32",
        image="linode/ubuntu22.04" if provider_name == "linode" else "ubuntu-22-04-x64",
    )
    return provider, transport


@pytest.mark.parametrize("provider_name,stages", [
    ("linode", ["firewall", "instance"]),
    ("digitalocean", ["tag", "firewall", "droplet", "attachment"]),
])
def test_hooked_inspector_create_journals_each_post_before_and_after(provider_name, stages):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline)
    receipts = []
    name = "inspector-" + "a" * 32
    def hook(stage: InspectorCreateStage):
        receipts.append(stage)
        timeline.append((stage.point, stage.stage))
    host = provider.create(
        token="secret-token", name=name, region="us-sea" if provider_name == "linode" else "sfo3",
        size="g6-nanode-1" if provider_name == "linode" else "s-1vcpu-1gb",
        public_key="ssh-ed25519 secret-public-key", stage_hook=hook,
    )
    assert [(item.stage, item.point) for item in receipts] == [
        (stage, point) for stage in stages for point in ("before_post", "response_received")]
    assert all(item.provider == provider_name and item.resource_name == name for item in receipts)
    assert [item.resource_id for item in receipts if item.point == "response_received"] == (
        ["42", "123"] if provider_name == "linode" else ["", "fw-42", "456", ""])
    if provider_name == "digitalocean":
        assert receipts[1].tag_name == _inspector_firewall_tag(name)
        assert receipts[1].tag_exclusive is False
        assert receipts[-1].firewall_id == "fw-42" and receipts[-1].droplet_id == "456"
    assert [entry[0] for entry in timeline] == [
        item for _stage in stages for item in ("before_post", "POST", "response_received")]
    assert host.name == name
    assert "secret-token" not in repr(receipts)
    assert "secret-public-key" not in repr(receipts)
    assert all("token" not in asdict(item) and "public_key" not in asdict(item) for item in receipts)


@pytest.mark.parametrize("provider_name,stages,ids", [
    ("linode", ["firewall", "instance"], ("123", "42", "")),
    ("digitalocean", ["tag", "firewall", "droplet", "attachment"],
     ("456", "fw-42", _inspector_firewall_tag("inspector-" + "a" * 32))),
])
def test_staged_inspector_submission_stops_after_last_receipt_without_get_or_delete(provider_name, stages, ids):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline)
    receipts = []
    name = "inspector-" + "a" * 32
    def hook(stage):
        receipts.append(stage)
        timeline.append((stage.point, stage.stage))
    submitted = provider.submit_staged_inspector(
        token="secret-token", name=name, region="us-sea" if provider_name == "linode" else "sfo3",
        size="small", public_key="ssh-ed25519 secret-public-key", stage_hook=hook,
    )
    assert submitted.provider == provider_name and submitted.resource_name == name
    assert (submitted.host_id, submitted.firewall_id, submitted.tag_name) == ids
    assert submitted.tag_exclusive is False
    assert [(item.stage, item.point) for item in receipts] == [
        (stage, point) for stage in stages for point in ("before_post", "response_received")]
    assert [item[0] for item in timeline] == [
        part for _stage in stages for part in ("before_post", "POST", "response_received")]
    assert all(method == "POST" for method, _path, _body in transport.calls)
    assert "secret-token" not in repr(submitted) and "secret-public-key" not in repr(submitted)


@pytest.mark.parametrize("provider_name", ["linode", "digitalocean"])
def test_staged_inspector_submission_requires_hook_and_opaque_name_before_provider(provider_name):
    provider, transport = _hooked_inspector_provider(provider_name, [])
    with pytest.raises(observer_checks.ObserverProviderError):
        provider.submit_staged_inspector(
            token="secret-token", name="inspector-" + "a" * 32, region="us-sea", size="small",
            public_key="ssh-ed25519 test", stage_hook=None,
        )
    with pytest.raises(observer_checks.ObserverProviderError):
        provider.submit_staged_inspector(
            token="secret-token", name="inspector-human-engagement", region="us-sea", size="small",
            public_key="ssh-ed25519 test", stage_hook=lambda _stage: None,
        )
    assert transport.calls == []


@pytest.mark.parametrize("provider_name", ["linode", "digitalocean"])
def test_staged_inspector_submit_callback_failure_stops_without_cleanup(provider_name):
    provider, transport = _hooked_inspector_provider(provider_name, [])
    with pytest.raises(InspectorCreateUncertainError):
        provider.submit_staged_inspector(
            token="secret-token", name="inspector-" + "a" * 32, region="us-sea", size="small",
            public_key="ssh-ed25519 test",
            stage_hook=lambda stage: (_ for _ in ()).throw(RuntimeError("private-token"))
            if stage.point == "response_received" else None,
        )
    assert not any(method in {"GET", "DELETE"} for method, _path, _body in transport.calls)


@pytest.mark.parametrize("provider_name,failed_post", [
    ("linode", ("POST", "/linode/instances")),
    ("digitalocean", ("POST", "/firewalls/fw-42/droplets")),
])
def test_staged_inspector_submit_lost_response_is_uncertain_without_cleanup(provider_name, failed_post):
    provider, transport = _hooked_inspector_provider(provider_name, [], failed_post=failed_post)
    with pytest.raises(InspectorCreateUncertainError) as error:
        provider.submit_staged_inspector(
            token="secret-token", name="inspector-" + "a" * 32,
            region="us-sea" if provider_name == "linode" else "sfo3", size="small",
            public_key="ssh-ed25519 test", stage_hook=lambda _stage: None,
        )
    assert any((method, path) == failed_post for method, path, _body in transport.calls)
    assert not any(method in {"GET", "DELETE"} for method, _path, _body in transport.calls)
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize("provider_name,stop_stage,stop_point,expected_posts", [
    ("linode", "firewall", "before_post", []),
    ("linode", "firewall", "response_received", ["/networking/firewalls"]),
    ("digitalocean", "tag", "response_received", ["/tags"]),
    ("digitalocean", "droplet", "before_post", ["/tags", "/firewalls"]),
    ("digitalocean", "droplet", "response_received", ["/tags", "/firewalls", "/droplets"]),
])
def test_hook_failure_stops_before_later_post_without_delete(provider_name, stop_stage, stop_point, expected_posts):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline)
    def hook(stage):
        if (stage.stage, stage.point) == (stop_stage, stop_point):
            raise RuntimeError("secret-token in callback failure")
    with pytest.raises(InspectorCreateUncertainError) as error:
        provider.create(token="secret-token", name="inspector-" + "a" * 32,
                        region="us-sea" if provider_name == "linode" else "sfo3",
                        size="small", public_key="ssh-ed25519 secret-public-key", stage_hook=hook)
    assert [path for method, path, _body in transport.calls if method == "POST"] == expected_posts
    assert not any(method == "DELETE" for method, _path, _body in transport.calls)
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize("provider_name,failed_post", [
    ("linode", ("POST", "/linode/instances")),
    ("digitalocean", ("POST", "/droplets")),
])
def test_hooked_response_loss_never_auto_deletes(provider_name, failed_post):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline, failed_post=failed_post)
    with pytest.raises(InspectorCreateUncertainError) as error:
        provider.create(token="secret-token", name="inspector-" + "a" * 32,
                        region="us-sea" if provider_name == "linode" else "sfo3",
                        size="small", public_key="ssh-ed25519 secret-public-key", stage_hook=lambda _stage: None)
    assert any((method, path) == failed_post for method, path, _body in transport.calls)
    assert not any(method == "DELETE" for method, _path, _body in transport.calls)
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize("provider_name,path,response,forbidden_post,malformed_stage", [
    ("linode", "/networking/firewalls", {"id": []}, "/linode/instances", "firewall"),
    ("linode", "/linode/instances", {"id": True}, None, "instance"),
    ("digitalocean", "/firewalls", {"firewall": {"id": {}}}, "/droplets", "firewall"),
    ("digitalocean", "/droplets", {"droplet": {"id": []}}, "/firewalls/fw-42/droplets", "droplet"),
])
def test_hooked_malformed_returned_id_vetoes_later_post_without_delete(
    provider_name, path, response, forbidden_post, malformed_stage,
):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline)
    transport.responses[("POST", path)] = response
    receipts = []
    with pytest.raises(InspectorCreateUncertainError):
        provider.create(token="secret-token", name="inspector-" + "a" * 32,
                        region="us-sea" if provider_name == "linode" else "sfo3",
                        size="small", public_key="ssh-ed25519 test", stage_hook=receipts.append)
    assert not any(method == "DELETE" for method, _path, _body in transport.calls)
    if forbidden_post is not None:
        assert ("POST", forbidden_post) not in [(method, called_path) for method, called_path, _ in transport.calls]
    assert (malformed_stage, "response_received") not in [(item.stage, item.point) for item in receipts]


@pytest.mark.parametrize("provider_name,get_path", [
    ("linode", "/linode/instances/123"),
    ("digitalocean", "/firewalls/fw-42"),
])
def test_hooked_get_failure_after_receipts_does_not_delete(provider_name, get_path):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline)
    transport.responses[("GET", get_path)] = RuntimeError("secret-token in GET failure")
    with pytest.raises(InspectorCreateUncertainError) as error:
        provider.create(token="secret-token", name="inspector-" + "a" * 32,
                        region="us-sea" if provider_name == "linode" else "sfo3",
                        size="small", public_key="ssh-ed25519 test", stage_hook=lambda _stage: None)
    assert not any(method == "DELETE" for method, _path, _body in transport.calls)
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize("provider_name", ["linode", "digitalocean"])
def test_hooked_create_rejects_nonopaque_name_before_callback_or_provider(provider_name):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline)
    with pytest.raises(observer_checks.ObserverProviderError):
        provider.create(token="secret-token", name="inspector-human-engagement",
                        region="us-sea", size="small", public_key="ssh-ed25519 test",
                        stage_hook=lambda stage: timeline.append(stage))
    assert timeline == [] and transport.calls == []


@pytest.mark.parametrize("provider_name,failed_post,expected_deletes", [
    ("linode", ("POST", "/linode/instances"), ["/networking/firewalls/42"]),
    ("digitalocean", ("POST", "/droplets"), ["/firewalls/fw-42", "/tags/" + _inspector_firewall_tag("inspector-legacy")]),
])
def test_legacy_create_error_keeps_existing_best_effort_cleanup(provider_name, failed_post, expected_deletes):
    timeline = []
    provider, transport = _hooked_inspector_provider(provider_name, timeline, failed_post=failed_post)
    with pytest.raises(observer_checks.ObserverProviderError):
        provider.create(token="secret-token", name="inspector-legacy",
                        region="us-sea" if provider_name == "linode" else "sfo3",
                        size="small", public_key="ssh-ed25519 secret-public-key")
    assert [path for method, path, _body in transport.calls if method == "DELETE"] == expected_deletes


def test_inspector_destroy_removes_tracked_linode_firewall_after_host_is_absent():
    transport = RecordingObserverTransport(
        {
            ("DELETE", "/linode/instances/123"): {},
            ("GET", "/linode/instances/123"): LinodeValidationError("HTTP 404"),
            ("DELETE", "/networking/firewalls/42"): {},
        }
    )
    provider = LinodeObserverProvider(transport=transport, poll_attempts=1, poll_delay_seconds=0)
    host = ObserverHost(
        "linode", "instance", "123", "inspector-opaque", "us-sea", "198.51.100.25",
        metadata={"providerFirewall": {"provider": "linode", "resourceId": "42"}},
    )

    assert provider.destroy(token="token", host=host) is True
    assert [(method, path) for method, path, _body in transport.calls] == [
        ("DELETE", "/linode/instances/123"),
        ("GET", "/linode/instances/123"),
        ("DELETE", "/networking/firewalls/42"),
    ]


def test_inspector_destroy_removes_tracked_digitalocean_firewall_and_tag_after_host_is_absent():
    transport = RecordingObserverTransport(
        {
            ("DELETE", "/droplets/456"): {},
            ("GET", "/droplets/456"): DigitalOceanValidationError("HTTP 404"),
            ("DELETE", "/firewalls/fw-42"): {},
            ("DELETE", "/tags/bi-test"): {},
        }
    )
    provider = DigitalOceanObserverProvider(transport=transport, poll_attempts=1, poll_delay_seconds=0)
    host = ObserverHost(
        "digitalocean", "droplet", "456", "inspector-opaque", "sfo3", "198.51.100.26",
        metadata={"providerFirewall": {"provider": "digitalocean", "resourceId": "fw-42", "tag": "bi-test"}},
    )

    assert provider.destroy(token="token", host=host) is True
    assert [(method, path) for method, path, _body in transport.calls] == [
        ("DELETE", "/droplets/456"),
        ("GET", "/droplets/456"),
        ("DELETE", "/firewalls/fw-42"),
        ("DELETE", "/tags/bi-test"),
    ]


def test_linode_inspector_destroy_treats_already_absent_as_verified_cleanup():
    transport = MissingObserverTransport(LinodeValidationError("Linode API DELETE failed with HTTP 404: not found"))
    provider = LinodeObserverProvider(transport=transport, poll_attempts=1, poll_delay_seconds=0)

    cleaned = provider.destroy(
        token="live-token-secret",
        host=ObserverHost("linode", "instance", "12345", "inspector-stale", "us-sea", "198.51.100.25"),
    )

    assert cleaned is True
    assert transport.calls == [("DELETE", "/linode/instances/12345")]


def test_digitalocean_inspector_destroy_treats_already_absent_as_verified_cleanup():
    transport = MissingObserverTransport(DigitalOceanValidationError("DigitalOcean API DELETE failed with HTTP 404: not found"))
    provider = DigitalOceanObserverProvider(transport=transport, poll_attempts=1, poll_delay_seconds=0)

    cleaned = provider.destroy(
        token="live-token-secret",
        host=ObserverHost("digitalocean", "droplet", "67890", "inspector-stale", "sfo3", "198.51.100.26"),
    )

    assert cleaned is True
    assert transport.calls == [("DELETE", "/droplets/67890")]


def test_observer_settings_api_validates_allowed_regions(client):
    engagement_id = _create_engagement(client, "ff-observer")

    response = client.get(f"/api/engagements/{engagement_id}/observer-settings")
    assert response.status_code == 200
    body = response.get_json()
    assert body["settings"]["provider"] == "linode"
    assert body["settings"]["configured"] is True
    assert body["settings"]["confirmationToken"] == "observer-ff-observer"

    response = client.patch(
        f"/api/engagements/{engagement_id}/observer-settings",
        json={
            "provider": "linode",
            "region": "us-lax",
            "size": "g6-nanode-1",
            "forbiddenTcpPorts": ["22"],
        },
    )
    assert response.status_code == 400
    assert response.get_json()["errors"] == ["linode region us-lax is not allowed by Global Settings"]

    response = client.patch(
        f"/api/engagements/{engagement_id}/observer-settings",
        json={
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "forbiddenTcpPorts": ["22", "2222", "22"],
        },
    )
    assert response.status_code == 200
    settings = response.get_json()["settings"]
    assert settings["configured"] is True
    assert settings["forbiddenTcpPorts"] == ["22", "2222"]


def test_inspector_settings_default_to_enabled_continuous_and_validate_scan_profiles(client):
    engagement_id = _create_engagement(client, "ff-inspector")

    response = client.get(f"/api/engagements/{engagement_id}/inspector-settings")
    assert response.status_code == 200
    settings = response.get_json()["settings"]
    assert settings["enabled"] is True
    assert settings["mode"] == "continuous"
    assert settings["scheduleTimeUtc"] == "00:00"
    assert settings["confirmationToken"] == "inspect-ff-inspector"
    assert settings["defaults"]["forbiddenTcpPorts"] == ["2222", "5000", "5173", "5900"]
    assert settings["forbiddenTcpPorts"] == ["2222", "5000", "5173", "5900"]

    response = client.patch(
        f"/api/engagements/{engagement_id}/inspector-settings",
        json={
            "enabled": True,
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "mode": "regular",
            "scheduleWeekdays": ["mon", "wed"],
            "scheduleTimeUtc": "23:15",
            "forbiddenTcpPorts": ["22"],
            "portScanProfiles": [
                {
                    "enabled": True,
                    "targetGroup": "core-public-management",
                    "ports": "80; rm -rf /",
                    "timing": "normal",
                    "scanMode": "tcp-connect",
                }
            ],
        },
    )
    assert response.status_code == 400
    errors = response.get_json()["errors"]
    assert "portScanProfiles[0].ports must contain ports or ranges between 1 and 65535" in errors
    assert "portScanProfiles[0] must acknowledge the OPSEC warning before scanning core public management IPs" in errors

    response = client.patch(
        f"/api/engagements/{engagement_id}/inspector-settings",
        json={
            "enabled": True,
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "mode": "regular",
            "scheduleWeekdays": ["mon"],
            "scheduleTimeUtc": "23:15",
            "forbiddenTcpPorts": ["22", "2222", "5000", "5173", "5900"],
        },
    )
    assert response.status_code == 200
    assert response.get_json()["settings"]["forbiddenTcpPorts"] == ["2222", "5000", "5173", "5900"]


def test_continuous_inspector_readiness_creates_prepared_retained_host(client):
    engagement_id = _create_engagement(client, "ff-inspector-readiness")
    provider = FakeObserverProvider()
    runner = FakePreparingInspectorRunner()

    with client.application.storage_context():
        result = ensure_continuous_inspector_ready(
            engagement_id,
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=runner,
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
        settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)
        job = SqlAlchemyJobRepository().get(result["job"]["id"])

    assert result["ready"] is True
    assert result["status"] == "ready"
    assert len(provider.created) == 1
    assert len(runner.prepared) == 1
    assert settings is not None
    assert settings.current_host["resourceId"] == "12345"
    assert settings.current_host["metadata"]["supportPreparationVersion"] == 1
    assert job is not None
    assert job.action == INSPECTOR_READINESS_ACTION
    assert job.status == "succeeded"


def test_continuous_inspector_readiness_reuses_prepared_host(client):
    engagement_id = _create_engagement(client, "ff-inspector-readiness-reuse")
    provider = FakeObserverProvider()
    runner = FakePreparingInspectorRunner()
    dependencies = {
        "settings_repository": SqlAlchemyObserverSettingsRepository(),
        "job_repository": SqlAlchemyJobRepository(),
        "provider_resource_repository": SqlAlchemyProviderResourceRepository(),
        "provider_factory": lambda _provider: provider,
        "runner": runner,
        "ssh_key_factory": lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        "credential_alias_resolver": lambda _provider: "linode-default",
        "credential_secret_resolver": lambda _provider, _alias: "live-token-secret",
    }

    with client.application.storage_context():
        first = ensure_continuous_inspector_ready(engagement_id, **dependencies)
        second = ensure_continuous_inspector_ready(engagement_id, **dependencies)

    assert first["ready"] is True
    assert second["required"] is True
    assert second["ready"] is True
    assert second["status"] == "ready"
    assert second["reused"] is True
    assert second["inspectorHost"]["resourceId"] == "12345"
    assert second["job"] is None
    assert len(provider.created) == 1
    assert len(runner.prepared) == 1
    assert len(runner.verified) == 1


def test_continuous_inspector_readiness_replaces_reused_host_that_rejects_key(client):
    engagement_id = _create_engagement(client, "ff-inspector-readiness-replace")
    provider = FakeObserverProvider()
    runner = FakeRejectedReuseInspectorRunner()
    dependencies = {
        "settings_repository": SqlAlchemyObserverSettingsRepository(),
        "job_repository": SqlAlchemyJobRepository(),
        "provider_resource_repository": SqlAlchemyProviderResourceRepository(),
        "provider_factory": lambda _provider: provider,
        "runner": runner,
        "ssh_key_factory": lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        "credential_alias_resolver": lambda _provider: "linode-default",
        "credential_secret_resolver": lambda _provider, _alias: "live-token-secret",
    }

    with client.application.storage_context():
        first = ensure_continuous_inspector_ready(engagement_id, **dependencies)
        second = ensure_continuous_inspector_ready(engagement_id, **dependencies)

    assert first["ready"] is True
    assert second["ready"] is True
    assert len(provider.created) == 2
    assert len(provider.destroyed) == 1
    assert len(runner.prepared) == 2
    assert len(runner.verified) == 1
    assert second["job"]["input"]["replacesUnreachableInspector"] is True


def test_continuous_inspector_readiness_preserves_reused_host_when_cleanup_fails(client):
    engagement_id = _create_engagement(client, "ff-inspector-readiness-replace-cleanup")
    provider = FakeObserverProvider(cleanup_ok=False)
    runner = FakeRejectedReuseInspectorRunner()
    dependencies = {
        "settings_repository": SqlAlchemyObserverSettingsRepository(),
        "job_repository": SqlAlchemyJobRepository(),
        "provider_resource_repository": SqlAlchemyProviderResourceRepository(),
        "provider_factory": lambda _provider: provider,
        "runner": runner,
        "ssh_key_factory": lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        "credential_alias_resolver": lambda _provider: "linode-default",
        "credential_secret_resolver": lambda _provider, _alias: "live-token-secret",
    }

    with client.application.storage_context():
        ensure_continuous_inspector_ready(engagement_id, **dependencies)
        result = ensure_continuous_inspector_ready(engagement_id, **dependencies)
        settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)

    assert result["ready"] is False
    assert len(provider.created) == 1
    assert len(provider.destroyed) == 1
    assert settings is not None
    assert settings.current_host["resourceId"] == "12345"


def test_continuous_inspector_readiness_cleans_new_host_after_baseline_failure(client):
    engagement_id = _create_engagement(client, "ff-inspector-readiness-cleanup")
    provider = FakeObserverProvider()

    with client.application.storage_context():
        result = ensure_continuous_inspector_ready(
            engagement_id,
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=FakeFailingPreparationRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
        settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)
        job = SqlAlchemyJobRepository().get(result["job"]["id"])

    assert result["ready"] is False
    assert result["status"] == "failed"
    assert len(provider.created) == 1
    assert len(provider.destroyed) == 1
    assert settings is not None
    assert settings.current_host == {}
    assert job is not None
    failure = next(event for event in job.events if event.message == "continuous Inspector readiness failed")
    assert failure.data["errors"] == ["Inspector support-host preparation failed"]


def test_continuous_inspector_readiness_records_cleanup_required_when_host_destroy_fails(client):
    engagement_id = _create_engagement(client, "ff-inspector-readiness-cleanup-required")
    provider = FakeObserverProvider(cleanup_ok=False)

    with client.application.storage_context():
        result = ensure_continuous_inspector_ready(
            engagement_id,
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=FakeFailingPreparationRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
        settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)
        resources = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)

    assert result["ready"] is False
    assert len(provider.destroyed) == 1
    assert settings is not None
    assert settings.current_host["resourceId"] == "12345"
    assert resources[-1].status == "cleanup_required"


def test_start_inspection_returns_existing_running_job_without_creating_host(client):
    engagement_id = _create_engagement(client, "ff-inspector-single-flight")
    provider = FakeObserverProvider()

    with client.application.storage_context():
        now = "2026-07-22T10:00:00+00:00"
        job_repo = SqlAlchemyJobRepository()
        inspection_repo = SqlAlchemyInspectionRunRepository()
        existing_job = job_repo.save(
            StoredJobRun(
                id="job-running-inspector",
                action="inspector_inspection",
                status="running",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="inspector-scheduler",
                input={
                    "engagementId": engagement_id,
                    "provider": "linode",
                    "region": "us-sea",
                    "mode": "continuous",
                    "triggerType": "mutation",
                },
                artifact_refs=[],
                created_at=now,
                started_at=now,
                finished_at=None,
                events=[JobEvent(1, "info", "inspection queued", {})],
            )
        )
        existing_run = inspection_repo.save(
            StoredInspectionRun(
                id="insp-running-inspector",
                engagement_id=engagement_id,
                job_id=existing_job.id,
                trigger_type="mutation",
                mode="continuous",
                status="running",
                provider="linode",
                region="us-sea",
                host={},
                targets={},
                evidence={},
                findings=[],
                created_at=now,
                started_at=now,
                finished_at=None,
            )
        )

        result = start_inspection(
            engagement_id,
            {"triggerType": "manual"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=job_repo,
            inspection_repository=inspection_repo,
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=FakeObserverRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )

    assert result is not None
    assert result["idempotent"] is True
    assert result["status"] == "running"
    assert result["job"]["id"] == existing_job.id
    assert result["inspection"]["id"] == existing_run.id
    assert provider.created == []


def test_inspector_scheduler_skips_when_inspection_is_running(client, monkeypatch):
    engagement_id = _create_engagement(client, "ff-inspector-scheduler-single-flight")

    with client.application.storage_context():
        now = "2026-07-22T10:00:00+00:00"
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-running-scheduler-inspector",
                action="inspector_inspection",
                status="running",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="inspector-scheduler",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at=now,
                started_at=now,
                finished_at=None,
                events=[JobEvent(1, "info", "inspection queued", {})],
            )
        )
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None

        calls = []
        monkeypatch.setattr(inspector_scheduler, "start_inspection", lambda *args, **kwargs: calls.append((args, kwargs)))
        inspector_scheduler._run_due_mutation_inspection(settings, settings_repo)

    assert calls == []


def test_observer_check_route_requires_confirmation_before_mutation(client):
    engagement_id = _create_engagement(client, "ff-observer")

    response = client.post(
        f"/api/engagements/{engagement_id}/observer-checks",
        json={"confirmation": "observer-wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be observer-ff-observer"]


def test_observer_check_targets_use_ip_when_channel_domain_is_not_assigned(client):
    engagement_id = _create_engagement(client, "ff-observer")
    _save_observer_settings(client, engagement_id)
    _seed_operations(client, engagement_id)

    with client.application.storage_context():
        targets = observer_check_targets(engagement_id)

    assert {"tcp", "http"}.issubset({target["type"] for target in targets["positive"]})
    assert "dns" not in {target["type"] for target in targets["positive"]}
    tcp_target = next(target for target in targets["positive"] if target["type"] == "tcp")
    http_target = next(target for target in targets["positive"] if target["type"] == "http")
    assert tcp_target["host"] == "203.0.113.44"
    assert tcp_target["connectHost"] == "203.0.113.44"
    assert tcp_target["hostHeader"] == "203.0.113.44"
    assert http_target["host"] == "203.0.113.44"
    assert http_target["connectHost"] == "203.0.113.44"
    assert http_target["hostHeader"] == "www.example.invalid"
    assert tcp_target["edgePublicIp"] == "203.0.113.44"
    assert tcp_target["port"] == 80
    forbidden = {(target["host"], target["port"]) for target in targets["negative"]}
    assert ("203.0.113.44", 22) in forbidden
    assert ("203.0.113.44", 80) not in forbidden


def test_observer_check_targets_resolve_duplicate_hostname_by_exact_component(monkeypatch):
    overview = {
        "inboundChannels": [
            {
                "channelId": "udp-selected",
                "protocol": "UDP",
                "externalPort": "34561",
                "edge": "edge-duplicate",
                "edgeComponentId": "edge-selected-id",
                "chainId": "proxy01-selected",
                "status": "Validated",
                "validationProfile": {
                    "type": "udp-send-receive",
                    "requestText": "PING",
                    "expectedResponse": "PONG",
                },
            }
        ],
        "sketchInfrastructure": [
            {
                "role": "edge",
                "hostname": "edge-duplicate",
                "componentId": "edge-selected-id",
                "chainId": "proxy01-selected",
                "publicIp": "203.0.113.10",
                "status": "deployed",
            },
            {
                "role": "edge",
                "hostname": "edge-duplicate",
                "componentId": "edge-other-id",
                "chainId": "proxy01-other",
                "publicIp": "203.0.113.20",
                "status": "deployed",
            },
        ],
        "coreInfrastructure": [],
    }
    monkeypatch.setattr("app.services.observer_checks.get_operations_overview", lambda *_args, **_kwargs: overview)
    monkeypatch.setattr(
        "app.services.observer_checks._settings_for_engagement",
        lambda *_args, **_kwargs: SimpleNamespace(forbidden_tcp_ports=[]),
    )
    monkeypatch.setattr("app.services.observer_checks._assigned_domain_names", lambda _engagement_id: set())

    targets = observer_check_targets("eng-duplicate")

    udp = next(target for target in targets["positive"] if target["type"] == "udp")
    assert udp["edgePublicIp"] == "203.0.113.10"
    assert udp["connectHost"] == "203.0.113.10"

    overview["sketchInfrastructure"][0]["status"] = ""
    with pytest.raises(ObserverCheckValidationError) as rejected:
        observer_check_targets("eng-duplicate")
    assert rejected.value.errors == [
        "inbound channel udp-selected does not resolve one exact deployed edge component"
    ]


def test_observer_check_targets_reject_ambiguous_legacy_edge_hostname(monkeypatch):
    overview = {
        "inboundChannels": [
            {
                "channelId": "legacy-udp",
                "protocol": "UDP",
                "externalPort": "34561",
                "edge": "edge-duplicate",
                "status": "Validated",
            }
        ],
        "sketchInfrastructure": [
            {"role": "edge", "hostname": "edge-duplicate", "publicIp": "203.0.113.10"},
            {"role": "edge", "hostname": "edge-duplicate", "publicIp": "203.0.113.20"},
        ],
        "coreInfrastructure": [],
    }
    monkeypatch.setattr("app.services.observer_checks.get_operations_overview", lambda *_args, **_kwargs: overview)
    monkeypatch.setattr(
        "app.services.observer_checks._settings_for_engagement",
        lambda *_args, **_kwargs: SimpleNamespace(forbidden_tcp_ports=[]),
    )
    monkeypatch.setattr("app.services.observer_checks._assigned_domain_names", lambda _engagement_id: set())

    with pytest.raises(ObserverCheckValidationError) as rejected:
        observer_check_targets("eng-duplicate")
    assert rejected.value.errors == ["legacy inbound channel legacy-udp has an ambiguous edge hostname"]


def test_edge_inventory_retains_duplicate_hostnames_for_inspector_scans(monkeypatch):
    overview = {
        "sketchInfrastructure": [
            {
                "role": "edge",
                "hostname": "edge-duplicate",
                "componentId": "edge-one",
                "chainId": "chain-one",
                "publicIp": "203.0.113.10",
            },
            {
                "role": "edge",
                "hostname": "edge-duplicate",
                "componentId": "edge-two",
                "chainId": "chain-two",
                "publicIp": "203.0.113.20",
            },
        ]
    }
    edges = observer_checks._edge_public_ips(overview)

    assert [(edge["componentId"], edge["publicIp"]) for edge in edges] == [
        ("edge-one", "203.0.113.10"),
        ("edge-two", "203.0.113.20"),
    ]
    monkeypatch.setattr("app.services.observer_checks.get_operations_overview", lambda *_args, **_kwargs: overview)
    scans = observer_checks._port_scan_targets(
        "eng-duplicate",
        [
            {
                "enabled": True,
                "targetGroup": "edges",
                "scanMode": "tcp-connect",
                "timing": "normal",
                "ports": "443",
            }
        ],
    )
    assert [(target["id"], target["host"]) for target in scans] == [
        ("nmap:0:chain-one:edge-one:443", "203.0.113.10"),
        ("nmap:0:chain-two:edge-two:443", "203.0.113.20"),
    ]


def test_raw_route_inspector_targets_bind_isolation_to_saved_fingerprints_and_udp_control(monkeypatch):
    channel = {
        "channelId": "udp-route", "protocol": "UDP", "mode": "udp-forward", "externalPort": "34561",
        "relayPort": "8000", "middleRelayPort": "8000", "proxyRelayPort": "8000",
        "edge": "edge-one", "edgeComponentId": "edge-one-id", "middle": "middle-one",
        "middleComponentId": "middle-one-id", "chainId": "proxy01-chain", "proxy": "proxy01-demo",
        "terminatesOn": "homebase-demo", "internalPort": "23461", "purpose": "test",
        "service": "UDP service", "status": "Validated",
        "validationProfile": {"type": "udp-send-receive", "requestText": "PING", "expectedResponse": "PONG"},
    }
    overview = {
        "inboundChannels": [],
        "sketchInfrastructure": [
            {
                "role": "edge", "hostname": "edge-one", "componentId": "edge-one-id",
                "chainId": "proxy01-chain", "publicIp": "203.0.113.10", "status": "deployed",
            },
            {
                "role": "middle", "hostname": "middle-one", "componentId": "middle-one-id",
                "chainId": "proxy01-chain", "publicIp": "203.0.113.11", "status": "deployed",
            },
            {
                "role": "middle", "hostname": "middle-other", "componentId": "middle-one-id",
                "chainId": "proxy01-other", "publicIp": "203.0.113.99", "status": "deployed",
            },
        ],
        "coreInfrastructure": [
            {"role": "proxy", "hostname": "proxy01-demo", "hostId": "proxy01", "publicIp": "203.0.113.12"},
            {"role": "homebase", "hostname": "homebase-demo", "hostId": "homebase", "publicIp": "203.0.113.13"},
        ],
    }
    plan = plan_new_raw_route({**channel, "relayPort": "", "middleRelayPort": "", "proxyRelayPort": ""}, [], overview)
    channel = apply_plan_to_channel(channel, plan)
    overview["inboundChannels"] = [channel]
    monkeypatch.setattr("app.services.observer_checks.get_operations_overview", lambda *_args, **_kwargs: overview)
    monkeypatch.setattr("app.services.observer_checks._settings_for_engagement", lambda *_args, **_kwargs: SimpleNamespace(forbidden_tcp_ports=[]))
    monkeypatch.setattr("app.services.observer_checks._assigned_domain_names", lambda _engagement_id: set())
    monkeypatch.setattr("app.services.observer_checks._dns_record_targets", lambda *_args: [])

    targets = observer_check_targets("eng-raw")

    positive = targets["positive"][0]
    isolation = targets["negative"]
    assert positive["routeFingerprint"] == plan["routeFingerprint"]
    assert {(row["role"], row["host"], row["port"]) for row in isolation} == {
        ("middle", "203.0.113.11", 8000),
        ("proxy", "203.0.113.12", 8000),
        ("termination", "203.0.113.13", 23461),
    }
    assert all(row["type"] == "udp-forbidden" for row in isolation)
    assert all(row["controlId"] == positive["id"] for row in isolation)
    assert all(row["routeFingerprint"] == plan["routeFingerprint"] for row in isolation)
    assert "same-run UDP positive control failed or was not run" in _OBSERVER_SCRIPT


def test_raw_route_inspector_rejects_plan_after_selected_infrastructure_is_recreated(monkeypatch):
    channel = {
        "channelId": "tcp-route", "protocol": "TCP", "mode": "tcp-forward", "externalPort": "34561",
        "relayPort": "8000", "middleRelayPort": "8000", "proxyRelayPort": "8000",
        "edge": "edge-one", "edgeComponentId": "edge-one-id", "middle": "middle-one",
        "middleComponentId": "middle-one-id", "chainId": "proxy01-chain", "proxy": "proxy01-demo",
        "terminatesOn": "homebase-demo", "internalPort": "23461", "purpose": "test",
        "service": "TCP service", "status": "Validated",
    }
    overview = {
        "inboundChannels": [],
        "sketchInfrastructure": [
            {
                "role": "edge", "hostname": "edge-one", "componentId": "edge-one-id",
                "chainId": "proxy01-chain", "publicIp": "203.0.113.10",
                "providerResourceId": "edge-resource-one", "status": "deployed",
            },
            {
                "role": "middle", "hostname": "middle-one", "componentId": "middle-one-id",
                "chainId": "proxy01-chain", "publicIp": "203.0.113.11",
                "providerResourceId": "middle-resource-one", "status": "deployed",
            },
        ],
        "coreInfrastructure": [
            {
                "role": "proxy", "hostname": "proxy01-demo", "hostId": "proxy01",
                "publicIp": "203.0.113.12", "providerResourceId": "proxy-resource-one",
            },
            {
                "role": "homebase", "hostname": "homebase-demo", "hostId": "homebase",
                "publicIp": "203.0.113.13", "providerResourceId": "homebase-resource-one",
            },
        ],
    }
    plan = plan_new_raw_route({**channel, "relayPort": "", "middleRelayPort": "", "proxyRelayPort": ""}, [], overview)
    overview["inboundChannels"] = [apply_plan_to_channel(channel, plan)]
    overview["sketchInfrastructure"][0]["providerResourceId"] = "edge-resource-two"
    monkeypatch.setattr("app.services.observer_checks.get_operations_overview", lambda *_args, **_kwargs: overview)
    monkeypatch.setattr("app.services.observer_checks._settings_for_engagement", lambda *_args, **_kwargs: SimpleNamespace(forbidden_tcp_ports=[]))
    monkeypatch.setattr("app.services.observer_checks._assigned_domain_names", lambda _engagement_id: set())

    with pytest.raises(ObserverCheckValidationError) as rejected:
        observer_check_targets("eng-test")
    assert any("resources were recreated or changed" in error for error in rejected.value.errors)


def test_http_inspector_target_treats_status_only_contract_as_no_body_marker(client):
    engagement_id = _create_engagement(client, "ff-observer-http-status")
    _save_observer_settings(client, engagement_id)
    _seed_operations(
        client,
        engagement_id,
        protocol="HTTP",
        mode="http-openresty",
        validation_profile={
            "type": "http",
            "requestText": "GET / HTTP/1.1\\r\\n\\r\\n",
            "expectedResponse": "HTTP status below 500",
        },
    )

    with client.application.storage_context():
        targets = observer_check_targets(engagement_id)

    http_target = next(target for target in targets["positive"] if target["type"] == "http")
    assert http_target["expectedResponse"] == ""


@pytest.mark.parametrize(
    ("status", "expected_ok"),
    [(200, True), (204, True), (405, True), (499, True), (500, False), (503, False), ("invalid", False)],
)
def test_inspector_http_probe_uses_service_neutral_non_5xx_health(status, expected_ok):
    class Response:
        def __init__(self, response_status):
            self.status = response_status

        def read(self, _limit):
            return b""

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return Response(status)

        def close(self):
            pass

    probe = _observer_script_http_probe(SimpleNamespace(HTTPConnection=Connection))
    ok, _observed = probe("198.51.100.10", "example.invalid", 80, "/", "", 1)

    assert ok is expected_ok


@pytest.mark.parametrize("failure", [TimeoutError("timed out"), ConnectionError("refused")])
def test_inspector_http_probe_rejects_transport_failures(failure):
    class Connection:
        def __init__(self, *_args, **_kwargs):
            if isinstance(failure, ConnectionError):
                raise failure

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            raise failure

    probe = _observer_script_http_probe(SimpleNamespace(HTTPConnection=Connection))
    ok, observed = probe("198.51.100.10", "example.invalid", 80, "/", "", 1)

    assert ok is False
    assert str(failure) in observed


def test_inspector_settings_report_retained_running_host_independent_of_findings():
    repository = FakeInspectorSettingsRepository("eng-inspector-retained")
    retained_host = ObserverHost(
        provider="linode",
        resource_type="instance",
        resource_id="12345",
        name="opaque-inspector",
        region="us-sea",
        public_ip="198.51.100.25",
        status="running",
    )
    repository.settings = replace(repository.settings, current_host=retained_host.to_dict())

    response = _settings_response(repository.settings, configured=True, engagement_name="OB01")

    assert response["settings"]["currentHost"]["resourceId"] == "12345"
    assert response["settings"]["currentHost"]["publicIp"] == "198.51.100.25"
    assert response["settings"]["currentHost"]["status"] == "running"


def test_observer_check_targets_include_dns_for_assigned_engagement_domain(client):
    engagement_id = _create_engagement(client, "ff-observer-domain")
    _save_observer_settings(client, engagement_id)
    _assign_domain(client, engagement_id, "operator-owned.com")
    _seed_operations(client, engagement_id, domain="www.operator-owned.com")

    with client.application.storage_context():
        targets = observer_check_targets(engagement_id)

    tcp_target = next(target for target in targets["positive"] if target["type"] == "tcp")
    dns_target = next(target for target in targets["positive"] if target["type"] == "dns")
    assert tcp_target["host"] == "www.operator-owned.com"
    assert tcp_target["connectHost"] == "203.0.113.44"
    assert tcp_target["hostHeader"] == "www.operator-owned.com"
    assert dns_target["host"] == "www.operator-owned.com"
    assert dns_target["expectedIp"] == "203.0.113.44"


def test_https_inspector_target_uses_tls_with_assigned_hostname_as_sni(client):
    engagement_id = _create_engagement(client, "ff-inspector-tls")
    _save_observer_settings(client, engagement_id)
    _assign_domain(client, engagement_id, "operator-owned.com")
    _seed_operations(
        client,
        engagement_id,
        domain="operator-owned.com",
        protocol="HTTPS",
        external_port="443",
        mode="https-openresty",
    )

    with client.application.storage_context():
        targets = observer_check_targets(engagement_id)

    https_target = next(target for target in targets["positive"] if target["type"] == "https")
    assert https_target["connectHost"] == "203.0.113.44"
    assert https_target["hostHeader"] == "operator-owned.com"
    assert https_target["port"] == 443
    assert 'context.wrap_socket(raw, server_hostname=server_name or connect_host)' in _OBSERVER_SCRIPT
    assert '"fingerprintSha256": hashlib.sha256(peer).hexdigest()' in _OBSERVER_SCRIPT


def test_inspector_nmap_requires_every_requested_port_to_be_open(tmp_path):
    script = tmp_path / "observer.py"
    script.write_text(_OBSERVER_SCRIPT, encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "positive": [
                    {
                        "id": "nmap:test:2222,3333",
                        "type": "nmap",
                        "host": "203.0.113.44",
                        "ports": "2222,3333",
                        "scanMode": "tcp-connect",
                        "timing": "normal",
                    }
                ],
                "negative": [],
            }
        ),
        encoding="utf-8",
    )
    nmap = tmp_path / "nmap"
    nmap.write_text(
        "#!/bin/sh\n"
        "printf 'PORT     STATE  SERVICE\\n2222/tcp open   EtherNetIP-1\\n3333/tcp closed dec-notes\\n'\n",
        encoding="utf-8",
    )
    nmap.chmod(0o755)

    completed = subprocess.run(
        [sys.executable, str(script), str(spec)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}"},
    )

    evidence = json.loads(completed.stdout)
    assert evidence["ok"] is False
    result = evidence["results"][0]
    assert result["ok"] is False
    assert result["observed"]["returnCode"] == 0
    assert result["observed"]["requestedPorts"] == [2222, 3333]
    assert result["observed"]["openPorts"] == [2222]
    assert result["observed"]["missingOpenPorts"] == [3333]


@pytest.mark.parametrize("case", ["missing-control", "failed-control", "silent-relay", "responding-relay"])
def test_inspector_udp_isolation_requires_working_control_and_rejects_responding_relay(case):
    positive = [] if case == "missing-control" else [{
        "id": "udp-control", "type": "udp", "host": "positive", "port": 34561,
        "requestText": "PING", "expectedResponse": "PONG",
    }]

    def udp_probe(host, _port, _request, _expected, _timeout):
        if host == "positive":
            return case != "failed-control", "PONG" if case != "failed-control" else "timeout"
        return case == "responding-relay", "EXPOSED" if case == "responding-relay" else "timeout"

    evidence = _observer_script_run(udp_probe)({
        "timeoutSeconds": 1,
        "positive": positive,
        "negative": [{
            "id": "udp-isolation", "type": "udp-forbidden", "host": "relay", "port": 8000,
            "controlId": "udp-control", "requestText": "PING",
        }],
    })

    result = next(row for row in evidence["results"] if row["id"] == "udp-isolation")
    assert evidence["ok"] is (case == "silent-relay")
    assert result["ok"] is (case == "silent-relay")
    if case in {"missing-control", "failed-control"}:
        assert "positive control failed" in result["observed"]


def _observer_script_run(udp_probe):
    tree = ast.parse(_OBSERVER_SCRIPT)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
    namespace = {
        "udp_probe": udp_probe,
        "tcp_connect": lambda *_args: (False, "unused"),
        "dns_probe": lambda *_args: (False, "unused"),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observer-run>", "exec"), namespace)
    return namespace["run"]


@pytest.mark.parametrize("error,status,reason", [
    (None, "open", "connection_succeeded"),
    (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "closed", "connection_refused"),
    (TimeoutError("timed out"), "inconclusive", "timed_out"),
    (OSError(errno.ENETUNREACH, "unreachable"), "inconclusive", "network_unreachable"),
    (OSError(errno.EHOSTUNREACH, "host unreachable"), "inconclusive", "network_unreachable"),
])
def test_inspector_tcp_absence_probe_requires_conclusive_refusal(error, status, reason):
    import errno
    import socket

    tree = ast.parse(_OBSERVER_SCRIPT)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "tcp_absence_probe")
    closed = []

    class FakeSocket:
        def settimeout(self, value):
            assert value == 4

        def connect(self, address):
            assert address == ("203.0.113.5", 22)
            if error:
                raise error

        def close(self):
            closed.append(True)

    namespace = {"errno": errno, "socket": SimpleNamespace(AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM,
                                                               gaierror=socket.gaierror, socket=lambda *_args: FakeSocket())}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observer-tcp>", "exec"), namespace)
    actual, observed = namespace["tcp_absence_probe"]("203.0.113.5", 22, 4)
    assert actual == status
    assert observed["status"] == status
    assert observed["reason"] == reason
    assert closed == [True]


def test_inspector_tcp_absence_name_failure_is_inconclusive():
    import errno
    import socket

    tree = ast.parse(_OBSERVER_SCRIPT)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "tcp_absence_probe")

    class FakeSocket:
        def settimeout(self, _value):
            pass

        def connect(self, _address):
            raise socket.gaierror(socket.EAI_NONAME, "name not found")

        def close(self):
            pass

    namespace = {"errno": errno, "socket": SimpleNamespace(AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM,
                                                               gaierror=socket.gaierror, socket=lambda *_args: FakeSocket())}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observer-tcp>", "exec"), namespace)
    status, observed = namespace["tcp_absence_probe"]("missing.example", 443, 4)
    assert status == "inconclusive"
    assert observed["reason"] == "name_resolution_failed"


def test_inspector_mixed_negative_tcp_results_fail_closed_on_inconclusive():
    tree = ast.parse(_OBSERVER_SCRIPT)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
    namespace = {
        "tcp_absence_probe": lambda host, *_args: (
            ("closed", {"status": "closed", "reason": "connection_refused"}) if host == "refused"
            else ("open", {"status": "open", "reason": "connection_succeeded"}) if host == "open"
            else ("inconclusive", {"status": "inconclusive", "reason": "timed_out"})
        ),
        "dns_probe": lambda *_args: ("absent", {"status": "answered"}),
        "DNS_ABSENCE_ATTEMPTS": 3,
        "time": SimpleNamespace(sleep=lambda _seconds: None),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observer-run>", "exec"), namespace)
    result = namespace["run"]({"strictNegativeTcp": True, "negative": [
        {"id": "closed", "type": "tcp-forbidden", "host": "refused", "port": 22},
        {"id": "timeout", "type": "tcp-forbidden", "host": "timeout", "port": 443},
        {"id": "dns", "type": "dns-absent", "host": "old.example", "expectedIp": "203.0.113.5"},
        {"id": "open", "type": "tcp-forbidden", "host": "open", "port": 80},
    ]})
    assert result["ok"] is False
    assert [(row["id"], row["ok"]) for row in result["results"]] == [
        ("closed", True), ("timeout", False), ("dns", True), ("open", False),
    ]
    assert result["results"][1]["observed"]["reason"] == "timed_out"


def test_inspector_legacy_tcp_forbidden_keeps_existing_timeout_semantics():
    tree = ast.parse(_OBSERVER_SCRIPT)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
    calls = []

    def legacy_tcp(host, _port, _timeout):
        calls.append(host)
        return (True, "") if host == "open" else (False, "timed out")

    namespace = {
        "tcp_connect": legacy_tcp,
        "tcp_absence_probe": lambda *_args: pytest.fail("strict TCP probe ran for legacy check"),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observer-run>", "exec"), namespace)
    result = namespace["run"]({"negative": [
        {"id": "timeout", "type": "tcp-forbidden", "host": "timeout", "port": 443},
        {"id": "open", "type": "tcp-forbidden", "host": "open", "port": 80},
    ]})
    assert calls == ["timeout", "open"]
    assert result["ok"] is False
    assert [(row["id"], row["ok"], row["observed"]) for row in result["results"]] == [
        ("timeout", True, "timed out"), ("open", False, "unexpectedly open"),
    ]


def _dns_script_namespace():
    import ipaddress
    import socket
    import struct
    from types import SimpleNamespace

    tree = ast.parse(_OBSERVER_SCRIPT)
    names = {"_dns_name", "_dns_ip_response", "dns_probe", "run"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {
        "socket": socket,
        "struct": struct,
        "ipaddress": ipaddress,
        "DNS_RESOLVERS": ("1.1.1.1", "8.8.8.8"),
        "DNS_ABSENCE_ATTEMPTS": 3,
        "time": SimpleNamespace(sleep=lambda _seconds: None),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<observer-dns>", "exec"), namespace)
    return namespace


@pytest.mark.parametrize("answer,expected", [
    ([], "absent"),
    (["198.51.100.4"], "present"),
    (["198.51.100.5"], "absent"),
])
def test_inspector_dns_absence_requires_both_public_resolvers_to_answer(answer, expected):
    namespace = _dns_script_namespace()
    calls = []

    def lookup(_host, resolver, _timeout):
        calls.append(resolver)
        return answer

    namespace["_dns_ip_lookup"] = lambda host, resolver, timeout, _type: lookup(host, resolver, timeout)
    status, observed = namespace["dns_probe"]("old.example", "198.51.100.4")
    assert status == expected
    assert calls == ["1.1.1.1", "8.8.8.8"]
    assert set(observed) == set(calls)


@pytest.mark.parametrize("failure", [TimeoutError, OSError, ValueError])
def test_inspector_dns_absence_never_passes_on_one_resolver_failure(failure):
    namespace = _dns_script_namespace()

    def lookup(_host, resolver, _timeout):
        if resolver == "8.8.8.8":
            raise failure("unavailable")
        return []

    namespace["_dns_ip_lookup"] = lambda host, resolver, timeout, _type: lookup(host, resolver, timeout)
    status, observed = namespace["dns_probe"]("old.example", "198.51.100.4")
    assert status == "inconclusive"
    assert observed["8.8.8.8"]["status"] == "inconclusive"


@pytest.mark.parametrize("states,expected_ok,expected_calls", [
    (["present", "absent"], True, 2),
    (["present", "present", "present"], False, 3),
    (["inconclusive"], False, 1),
])
def test_inspector_dns_absence_retries_stale_positive_but_not_inconclusive(states, expected_ok, expected_calls):
    namespace = _dns_script_namespace()
    calls = []

    def probe(_host, _expected_ip, _timeout):
        calls.append(1)
        return states[len(calls) - 1], {"resolver": "fixture"}

    namespace["dns_probe"] = probe
    result = namespace["run"]({"negative": [{"id": "old-a", "type": "dns-absent", "host": "old.example", "expectedIp": "198.51.100.4"}]})
    assert result["ok"] is expected_ok
    assert result["results"][0]["ok"] is expected_ok
    assert len(calls) == expected_calls


def test_inspector_dns_packet_rejects_truncation_servfail_and_bad_compression():
    import struct

    namespace = _dns_script_namespace()
    parse = namespace["_dns_ip_response"]
    question = b"\x03old\x07example\x00\x00\x01\x00\x01"
    header = lambda flags, count, authority=0, additional=0: struct.pack("!HHHHHH", 17, flags, 1, count, authority, additional)
    parse_a = lambda packet: parse(packet, 17, b"old.example", 1)
    soa_data = b"\x02ns\xc0\x10\x0ahostmaster\xc0\x10" + b"\x00" * 20
    soa = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 0, len(soa_data)) + soa_data
    assert parse_a(header(0x8180, 0, 1) + question + soa) == []
    assert parse_a(header(0x8183, 0, 1) + question + soa) == []
    answer_a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + b"\xc6\x33\x64\x04"
    answer_cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 0, 2) + b"\xc0\x0c"
    assert parse_a(header(0x8180, 1) + question + answer_a) == ["198.51.100.4"]
    assert parse_a(header(0x8180, 2) + question + answer_a + answer_a[:-4] + b"\xc6\x33\x64\x05") == ["198.51.100.4", "198.51.100.5"]
    alias_answer = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 0, 8) + b"\x05alias\xc0\x10"
    alias_a = b"\x05alias\xc0\x10" + struct.pack("!HHIH", 1, 1, 0, 4) + b"\xc6\x33\x64\x04"
    assert parse_a(header(0x8180, 2) + question + alias_answer + alias_a) == ["198.51.100.4"]
    for packet in (
        header(0x8380, 0) + question,  # truncated flag
        header(0x8182, 0) + question,  # SERVFAIL
        header(0x8000, 0) + question,  # non-recursive empty response
        header(0x8180, 0) + question,  # unproven empty NOERROR
        header(0x8183, 0) + question,  # unproven NXDOMAIN
        header(0x8180, 0, 1) + question,  # declared SOA omitted
        header(0x8180, 0, 1, 1) + question + soa,  # declared additional RR omitted
        header(0x8180, 0, 1) + question + soa + b"garbage",  # trailing bytes
        header(0x8180, 1) + question + b"\xc0\xff",  # invalid pointer
        header(0x8180, 1) + question + answer_cname,  # incomplete CNAME chain
    ):
        with pytest.raises(ValueError):
            parse_a(packet)
    with pytest.raises(ValueError):
        parse(header(0x8180, 0, 1) + question + soa, 17, b"other.example", 1)
    with pytest.raises(ValueError):
        parse(header(0x8180, 0, 1) + question + soa, 18, b"old.example", 1)


def test_inspector_dns_absence_queries_aaaa_for_ipv6_expected_ip():
    import ipaddress
    import struct

    namespace = _dns_script_namespace()
    types = []

    def lookup(_host, _resolver, _timeout, question_type):
        types.append(question_type)
        return ["2001:db8::4"]

    namespace["_dns_ip_lookup"] = lookup
    status, _observed = namespace["dns_probe"]("old.example", "2001:db8::4")
    assert status == "present"
    assert types == [28, 28]
    question = b"\x03old\x07example\x00\x00\x1c\x00\x01"
    header = struct.pack("!HHHHHH", 17, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 0, 16) + ipaddress.ip_address("2001:db8::4").packed
    assert namespace["_dns_ip_response"](header + question + answer, 17, b"old.example", 28) == ["2001:db8::4"]


def test_inspector_dns_absence_without_expected_ip_checks_both_address_families():
    namespace = _dns_script_namespace()
    questions = []

    def lookup(_host, resolver, _timeout, question_type):
        questions.append((resolver, question_type))
        return ["2001:db8::4"] if resolver == "8.8.8.8" and question_type == 28 else []

    namespace["_dns_ip_lookup"] = lookup
    status, _observed = namespace["dns_probe"]("old.example", None)
    assert status == "present"
    assert questions == [("1.1.1.1", 1), ("1.1.1.1", 28), ("8.8.8.8", 1), ("8.8.8.8", 28)]


def test_https_inspector_evidence_validates_matching_certificate_binding():
    binding = StoredCertificateBinding(
        id="certbind-test",
        engagement_id="eng-test",
        certificate_id="cert-test",
        service_id="web-test",
        channel_id="edge-443-to-web",
        hostname="operator-owned.com",
        status="bound",
        validation={"status": "pending"},
    )

    class Repository:
        saved = None

        def list_bindings(self, engagement_id, certificate_id=""):
            return [binding]

        def get_asset(self, engagement_id, certificate_id):
            return type("Asset", (), {"current_version_id": "certver-test"})()

        def get_version(self, version_id):
            return type("Version", (), {"fingerprint_sha256": "abc123"})()

        def save_binding(self, value):
            self.saved = value
            return value

    repository = Repository()
    _record_certificate_binding_validation(
        "eng-test",
        {
            "results": [
                {
                    "id": "edge-443-to-web",
                    "type": "https",
                    "ok": True,
                    "observed": {"fingerprintSha256": "abc123", "tlsVersion": "TLSv1.3"},
                }
            ]
        },
        "job-inspector-test",
        certificate_repository=repository,
    )

    assert repository.saved.validation["status"] == "validated"
    assert repository.saved.validation["fingerprintSha256"] == "abc123"
    assert repository.saved.validation["tlsVersion"] == "TLSv1.3"


def test_inspection_run_retains_once_host_and_persists_evidence(client):
    engagement_id = _create_engagement(client, "ff-inspector")
    response = client.patch(
        f"/api/engagements/{engagement_id}/inspector-settings",
        json={
            "enabled": True,
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "mode": "once",
            "scheduleWeekdays": ["mon"],
            "scheduleTimeUtc": "01:00",
            "forbiddenTcpPorts": ["22", "2222"],
        },
    )
    assert response.status_code == 200
    _seed_operations(client, engagement_id, channel_status="Pending Validation")
    provider = FakeObserverProvider()
    runner = FakeObserverRunner()

    with client.application.storage_context():
        targets = inspection_targets(engagement_id)
        assert {"tcp", "http"}.issubset({target["type"] for target in targets["positive"]})
        assert "dns" not in {target["type"] for target in targets["positive"]}
        result = start_inspection(
            engagement_id,
            {"triggerType": "manual"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            inspection_repository=SqlAlchemyInspectionRunRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=runner,
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )

    assert result["status"] == "succeeded"
    assert provider.created
    assert provider.destroyed == []
    assert any(event["message"] == "inspector host retained" for event in result["job"]["events"])
    assert result["inspection"]["status"] == "succeeded"
    assert result["inspection"]["evidence"]["ok"] is True
    serialized = json.dumps(result, sort_keys=True)
    assert "live-token-secret" not in serialized
    assert "fake-key" not in serialized

    with client.application.storage_context():
        settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)
        runs = SqlAlchemyInspectionRunRepository().list_for_engagement(engagement_id)
    assert settings is not None
    assert settings.current_host["resourceId"] == "12345"
    assert settings.idle_retention_until
    assert runs[0].status == "succeeded"
    assert runs[0].host["publicIp"] == "198.51.100.25"


def test_inspection_provisioning_prepares_default_support_packages_before_checks(client):
    engagement_id = _create_engagement(client, "ff-inspector-prepared")
    response = client.patch(
        f"/api/engagements/{engagement_id}/inspector-settings",
        json={
            "enabled": True,
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "mode": "once",
            "scheduleWeekdays": ["mon"],
            "scheduleTimeUtc": "01:00",
            "forbiddenTcpPorts": ["2222"],
        },
    )
    assert response.status_code == 200
    _seed_operations(client, engagement_id)
    provider = FakeObserverProvider()
    runner = FakePreparingInspectorRunner()

    with client.application.storage_context():
        result = start_inspection(
            engagement_id,
            {"triggerType": "manual"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            inspection_repository=SqlAlchemyInspectionRunRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=runner,
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )

    assert result["status"] == "succeeded"
    assert runner.prepared[0]["packages"] == ("nmap",)
    assert runner.calls[0]["host"].metadata["supportPreparedPackages"] == ["nmap"]
    event_messages = [event["message"] for event in result["job"]["events"]]
    assert event_messages.index("inspector support host preparation succeeded") < event_messages.index("inspection checks started")
    retained = result["job"]["events"][-1]["data"]["inspectorHost"]
    assert retained["metadata"]["supportPreparedPackages"] == ["nmap"]


def test_successful_inspection_marks_inbound_channel_public_ingress_verified(client):
    engagement_id = _create_engagement(client, "ff-inspector-ops")
    response = client.patch(
        f"/api/engagements/{engagement_id}/inspector-settings",
        json={
            "enabled": True,
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "mode": "once",
            "scheduleWeekdays": ["mon"],
            "scheduleTimeUtc": "01:00",
            "forbiddenTcpPorts": ["2222"],
        },
    )
    assert response.status_code == 200
    _seed_operations(client, engagement_id)

    with client.application.storage_context():
        runner = FakeObserverRunner()
        result = start_inspection(
            engagement_id,
            {"triggerType": "manual"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            inspection_repository=SqlAlchemyInspectionRunRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: FakeObserverProvider(),
            runner=runner,
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )
        overview = get_operations_overview(engagement_id, include_provider_findings=False)

    assert result["status"] == "succeeded"
    positive_targets = runner.calls[0]["spec"]["positive"]
    assert "tcp-send-expect" not in [target["type"] for target in positive_targets]
    assert "http" in [target["type"] for target in positive_targets]
    channel = overview["inboundChannels"][0]
    assert channel["channelId"] == "edge-80-to-web"
    assert channel["status"] == "Validated"
    assert channel["validation"]["status"] == "Validated"
    assert channel["validation"]["externalIngressVerified"] is True
    assert channel["validation"]["externalIngressDetail"].startswith("Public HTTP ingress verified by Inspector run ")


def test_http_inspector_evidence_wins_over_older_tcp_send_failure(client):
    engagement_id = _create_engagement(client, "ff-inspector-mixed")
    _seed_operations(client, engagement_id)

    with client.application.storage_context():
        SqlAlchemyInspectionRunRepository().save(
            StoredInspectionRun(
                id="inspection-wh02-style",
                engagement_id=engagement_id,
                job_id="job-wh02-style",
                trigger_type="manual",
                mode="once",
                status="failed",
                provider="linode",
                region="us-sea",
                host={"publicIp": "198.51.100.25"},
                targets={},
                evidence={
                    "ok": False,
                    "results": [
                        {"id": "edge-80-to-web", "channelId": "edge-80-to-web", "type": "tcp", "ok": True, "observed": "connected"},
                        {"id": "edge-80-to-web", "channelId": "edge-80-to-web", "type": "tcp-send-expect", "ok": False, "observed": "timed out"},
                        {"id": "edge-80-to-web", "channelId": "edge-80-to-web", "type": "http", "ok": True, "observed": {"status": 200}},
                    ],
                },
                findings=[],
                created_at="2026-06-25T15:22:34+00:00",
                started_at="2026-06-25T15:22:34+00:00",
                finished_at="2026-06-25T15:23:34+00:00",
            )
        )
        overview = get_operations_overview(engagement_id, include_provider_findings=False)

    channel = overview["inboundChannels"][0]
    assert channel["validation"]["externalIngressVerified"] is True
    assert channel["validation"]["externalIngressDetail"].startswith("Public HTTP ingress verified by Inspector run job-wh02-style.")

    with client.application.storage_context():
        SqlAlchemyInspectionRunRepository().save(
            StoredInspectionRun(
                id="inspection-public-failure",
                engagement_id=engagement_id,
                job_id="job-public-failure",
                trigger_type="manual",
                mode="once",
                status="failed",
                provider="linode",
                region="us-sea",
                host={"publicIp": "198.51.100.25"},
                targets={},
                evidence={
                    "ok": False,
                    "results": [
                        {
                            "id": "edge-80-to-web",
                            "channelId": "edge-80-to-web",
                            "type": "http",
                            "ok": False,
                            "observed": "connection refused",
                        }
                    ],
                },
                findings=[],
                created_at="2026-07-08T00:00:00+00:00",
                started_at="2026-07-08T00:00:00+00:00",
                finished_at="2026-07-08T00:01:00+00:00",
            )
        )
        overview = get_operations_overview(engagement_id, include_provider_findings=False)

    channel = overview["inboundChannels"][0]
    assert channel["status"] == "Validated"
    assert channel["validation"]["status"] == "Validated"
    assert channel["validation"]["externalIngressVerified"] is False
    assert channel["validation"]["externalIngressCheckedAt"] == "2026-07-08T00:01:00"
    assert channel["validation"]["externalIngressDetail"].startswith(
        "Public ingress check failed for edge-80-to-web in Inspector run job-public-failure."
    )


def test_inspection_runner_errors_are_persisted_and_visible(client):
    engagement_id = _create_engagement(client, "ff-inspector")
    _seed_operations(client, engagement_id)
    provider = FakeObserverProvider()

    with client.application.storage_context():
        result = start_inspection(
            engagement_id,
            {"triggerType": "manual"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            inspection_repository=SqlAlchemyInspectionRunRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=FakeFailingObserverRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )

    assert result["status"] == "failed"
    failure_event = next(event for event in result["job"]["events"] if event["message"] == "inspection checks failed")
    assert failure_event["data"]["errors"] == [
        "inspector SSH did not become ready",
        "ssh: connect to host 198.51.100.25 port 22: Connection timed out",
    ]
    assert result["inspection"]["evidence"]["errors"][0] == "inspector SSH did not become ready"
    assert provider.destroyed == []


def test_ssh_inspector_runner_prepares_default_support_packages_with_ansible(monkeypatch):
    calls: list[list[str]] = []
    workspaces = []

    def fake_ready(command, *, attempts, delay_seconds, description):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def fake_run(command, *, cwd=None, check=True):
        calls.append(command)
        if command[0] == "/usr/bin/ansible-playbook":
            workspaces.append(cwd)
            inventory = (cwd / command[-2]).read_text(encoding="utf-8")
            playbook = (cwd / command[-1]).read_text(encoding="utf-8")
            assert "ansible_ssh_private_key_file=/tmp/fake-key" in inventory
            if command[-1].endswith("bootstrap_inspector_admin.yml"):
                assert "ansible_user=root" in inventory
                assert "name: barragan" in playbook
                assert "/etc/sudoers.d/90-barragan-inspector" in playbook
            elif command[-1].endswith("harden_inspector_ssh.yml"):
                assert "ansible_user=barragan" in inventory
                assert "PermitRootLogin no" in playbook
                assert "/usr/sbin/sshd -t" in playbook
            else:
                assert "ansible_user=barragan" in inventory
                assert "ansible.builtin.apt" in playbook
                assert "- nmap" in playbook
                assert "which nmap" in playbook
            return subprocess.CompletedProcess(command, 0, stdout="prepared\n", stderr="")
        if command[0] == "ssh" and f"root@198.51.100.25" in command:
            return subprocess.CompletedProcess(command, 255, stdout="", stderr="Permission denied (publickey).")
        if command[0] == "ssh" and command[-2:] == ["/usr/sbin/sshd", "-T"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(observer_checks, "_run_checked_with_retries", fake_ready)
    monkeypatch.setattr(observer_checks, "_run_checked", fake_run)
    monkeypatch.setattr(
        observer_checks,
        "resolve_ansible_playbook",
        lambda: CommandResolution("ansible-playbook", "/usr/bin/ansible-playbook", "test", ()),
    )

    host = SshObserverRunner(readiness_attempts=1, readiness_delay_seconds=0).prepare_support_host(
        host=ObserverHost("linode", "instance", "12345", "inspector-test", "us-sea", "198.51.100.25"),
        ssh_key=ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
    )

    assert calls[0][0] == "ssh"
    assert calls[1][-1] == "ansible/bootstrap_inspector_admin.yml"
    assert any(command[-1:] == ["ansible/harden_inspector_ssh.yml"] for command in calls)
    assert any(command[-1:] == ["ansible/prepare_inspector.yml"] for command in calls)
    assert workspaces
    assert host.ssh_user == "barragan"
    assert host.metadata["adminIdentityVersion"] == 1
    assert host.metadata["rootLoginDisabled"] is True
    assert host.metadata["supportPreparationVersion"] == 1
    assert host.metadata["supportPreparedPackages"] == ["nmap"]


def test_ssh_inspector_runner_reports_inspector_prepare_failure(monkeypatch):
    def fake_ready(command, *, attempts, delay_seconds, description):
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def fake_run(command, *, cwd=None, check=True):
        if command[0] == "ssh" and f"root@198.51.100.25" in command:
            return subprocess.CompletedProcess(command, 255, stdout="", stderr="Permission denied (publickey).")
        if command[0] == "ssh" and command[-2:] == ["/usr/sbin/sshd", "-T"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n",
                stderr="",
            )
        if command[-1:] == ["ansible/prepare_inspector.yml"]:
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="FAILED! nmap package not found")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(observer_checks, "_run_checked_with_retries", fake_ready)
    monkeypatch.setattr(observer_checks, "_run_checked", fake_run)
    monkeypatch.setattr(
        observer_checks,
        "resolve_ansible_playbook",
        lambda: CommandResolution("ansible-playbook", "/usr/bin/ansible-playbook", "test", ()),
    )

    try:
        SshObserverRunner(readiness_attempts=1, readiness_delay_seconds=0).prepare_support_host(
            host=ObserverHost("linode", "instance", "12345", "inspector-test", "us-sea", "198.51.100.25", ssh_user="barragan"),
            ssh_key=ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        )
    except ObserverCheckValidationError as exc:
        assert exc.errors == [
            "Inspector support-host preparation failed",
            "FAILED! nmap package not found",
        ]
    else:
        raise AssertionError("expected inspector preparation error")


def test_ssh_inspector_runner_does_not_harden_before_barragan_identity_is_verified(monkeypatch):
    ansible_playbooks: list[str] = []

    def fake_ready(command, *, attempts, delay_seconds, description):
        if "barragan administration identity did not become ready" in description:
            raise ObserverCheckValidationError([description, "Permission denied (publickey)."])
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def fake_run(command, *, cwd=None, check=True):
        if command[0] == "/usr/bin/ansible-playbook":
            ansible_playbooks.append(command[-1])
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(observer_checks, "_run_checked_with_retries", fake_ready)
    monkeypatch.setattr(observer_checks, "_run_checked", fake_run)
    monkeypatch.setattr(
        observer_checks,
        "resolve_ansible_playbook",
        lambda: CommandResolution("ansible-playbook", "/usr/bin/ansible-playbook", "test", ()),
    )

    with pytest.raises(ObserverCheckValidationError):
        SshObserverRunner(readiness_attempts=1, readiness_delay_seconds=0).prepare_support_host(
            host=ObserverHost("linode", "instance", "12345", "inspector-test", "us-sea", "198.51.100.25"),
            ssh_key=ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        )

    assert ansible_playbooks == ["ansible/bootstrap_inspector_admin.yml"]


def test_ssh_inspector_runner_rejects_success_when_root_login_remains_enabled(monkeypatch):
    def fake_ready(command, *, attempts, delay_seconds, description):
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def fake_run(command, *, cwd=None, check=True):
        stdout = ""
        if command[0] == "ssh" and command[-2:] == ["/usr/sbin/sshd", "-T"]:
            stdout = "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(observer_checks, "_run_checked_with_retries", fake_ready)
    monkeypatch.setattr(observer_checks, "_run_checked", fake_run)
    monkeypatch.setattr(
        observer_checks,
        "resolve_ansible_playbook",
        lambda: CommandResolution("ansible-playbook", "/usr/bin/ansible-playbook", "test", ()),
    )

    with pytest.raises(ObserverCheckValidationError) as error:
        SshObserverRunner(readiness_attempts=1, readiness_delay_seconds=0).prepare_support_host(
            host=ObserverHost(
                "linode",
                "instance",
                "12345",
                "inspector-test",
                "us-sea",
                "198.51.100.25",
                ssh_user="barragan",
            ),
            ssh_key=ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        )

    assert error.value.errors == ["Inspector root SSH login remained enabled after hardening"]


def test_observer_check_job_creates_validates_and_cleans_up_observer_without_secret_leak(client):
    engagement_id = _create_engagement(client, "ff-observer")
    _save_observer_settings(client, engagement_id)
    _seed_operations(client, engagement_id)
    provider = FakeObserverProvider()
    runner = FakeObserverRunner()

    with client.application.storage_context():
        result = start_observer_check(
            engagement_id,
            {"confirmation": "observer-ff-observer"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=runner,
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )

    assert result["status"] == "succeeded"
    assert provider.created[0]["token"] == "live-token-secret"
    assert provider.destroyed
    assert runner.calls[0]["host"].public_ip == "198.51.100.25"
    assert any(event["message"] == "observer host cleanup verified" for event in result["job"]["events"])
    serialized = json.dumps(result["job"], sort_keys=True)
    assert "live-token-secret" not in serialized
    assert "fake-key" not in serialized

    with client.application.storage_context():
        records = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
    assert records[0].status == "destroyed"
    assert records[0].metadata["cleanupRequired"] is False


def test_observer_check_job_fails_if_observer_cleanup_is_not_verified(client):
    engagement_id = _create_engagement(client, "ff-observer")
    _save_observer_settings(client, engagement_id)
    _seed_operations(client, engagement_id)
    provider = FakeObserverProvider(cleanup_ok=False)

    with client.application.storage_context():
        result = start_observer_check(
            engagement_id,
            {"confirmation": "observer-ff-observer"},
            settings_repository=SqlAlchemyObserverSettingsRepository(),
            job_repository=SqlAlchemyJobRepository(),
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            runner=FakeObserverRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )

    assert result["status"] == "failed"
    assert any(event["message"] == "observer host cleanup failed" for event in result["job"]["events"])
    with client.application.storage_context():
        records = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
    assert records[0].status == "cleanup_required"
    assert records[0].metadata["cleanupRequired"] is True


def test_teardown_inspector_cleanup_disables_settings_and_destroys_retained_host(client):
    engagement_id = _create_engagement(client, "ff-inspector-cleanup")
    provider = FakeObserverProvider()

    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                enabled=True,
                mode="continuous",
                current_host={
                    "provider": "linode",
                    "resourceType": "instance",
                    "resourceId": "12345",
                    "name": "inspector-ff-inspector-cleanup",
                    "region": "us-sea",
                    "publicIp": "198.51.100.25",
                    "sshUser": "observer",
                    "status": "running",
                    "metadata": {"publicIps": ["198.51.100.25"]},
                },
            )
        )
        result = cleanup_inspector_for_infrastructure_teardown(
            engagement_id,
            "ff-inspector-cleanup",
            "job-teardown",
            settings_repository=settings_repo,
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
        updated = settings_repo.get(engagement_id)
        records = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)

    assert result["ok"] is True
    assert result["status"] == "destroyed"
    assert result["disabled"] is True
    assert result["cleanupVerified"] is True
    assert result["currentHostCleared"] is True
    assert provider.destroyed[0]["token"] == "live-token-secret"
    assert provider.destroyed[0]["host"].resource_id == "12345"
    assert updated is not None
    assert updated.enabled is False
    assert updated.current_host == {}
    assert records[0].status == "destroyed"
    assert records[0].metadata["cleanupRequired"] is False


def test_teardown_inspector_verification_uses_retained_host_for_negative_targets(client):
    engagement_id = _create_engagement(client, "ff-inspector-teardown-verify")
    runner = FakeTeardownVerificationRunner()

    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                enabled=True,
                mode="continuous",
                current_host={
                    "provider": "linode",
                    "resourceType": "instance",
                    "resourceId": "12345",
                    "name": "inspector-ff-inspector-teardown-verify",
                    "region": "us-sea",
                    "publicIp": "198.51.100.25",
                    "sshUser": "root",
                    "status": "running",
                },
            )
        )
        result = verify_retired_public_endpoints_for_teardown(
            engagement_id,
            "ff-inspector-teardown-verify",
            "job-teardown",
            [
                {"id": "edge-http", "type": "tcp-forbidden", "host": "203.0.113.50", "port": 80},
                {"id": "dns:www.example.invalid", "type": "dns-absent", "host": "www.example.invalid", "expectedIp": "203.0.113.50"},
            ],
            settings_repository=settings_repo,
            runner=runner,
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        )

    assert result["ok"] is True
    assert result["status"] == "verified_absent"
    assert result["targetCount"] == 2
    assert runner.calls[0]["host"].resource_id == "12345"
    assert runner.calls[0]["spec"]["positive"] == []
    assert {target["type"] for target in runner.calls[0]["spec"]["negative"]} == {"tcp-forbidden", "dns-absent"}


def test_teardown_inspector_verification_fails_when_targets_exist_without_retained_host(client):
    engagement_id = _create_engagement(client, "ff-inspector-teardown-no-host")

    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        result = verify_retired_public_endpoints_for_teardown(
            engagement_id,
            "ff-inspector-teardown-no-host",
            "job-teardown",
            [{"id": "edge-http", "type": "tcp-forbidden", "host": "203.0.113.50", "port": 80}],
            settings_repository=settings_repo,
            runner=FakeTeardownVerificationRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        )

    assert result["ok"] is False
    assert result["status"] == "inspector_unavailable"
    assert result["errors"] == ["retained Inspector host is required for teardown verification"]


def test_teardown_preflight_creates_prepares_and_persists_retained_inspector():
    engagement_id = "eng-1"
    provider = FakeObserverProvider()
    runner = FakePreparingInspectorRunner()
    settings = FakeInspectorSettingsRepository(engagement_id)
    resources = FakeInspectorResourceRepository()
    result = ensure_inspector_for_infrastructure_teardown(
        engagement_id,
        "ff-teardown-pf",
        "job-teardown",
        settings_repository=settings,
        provider_resource_repository=resources,
        provider_factory=lambda _provider: provider,
        runner=runner,
        ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        credential_alias_resolver=lambda _provider: "linode-default",
        credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
    )

    assert result["status"] == "created_prepared"
    assert len(provider.created) == 1
    assert provider.created[0]["name"] == observer_checks._inspector_host_name(
        "ff-teardown-pf", "job-teardown")
    assert len(runner.prepared) == 1
    assert settings.settings.current_host["metadata"]["supportPreparedPackages"] == ["nmap"]
    assert [(record.resource_id, record.status) for record in resources.records] == [("12345", "active")]


@pytest.mark.parametrize("chosen_provider", ["linode", "digitalocean"])
def test_teardown_preflight_forwards_exact_opaque_name(chosen_provider):
    settings = FakeInspectorSettingsRepository("eng-1")
    settings.settings = replace(settings.settings, provider=chosen_provider,
                                region="us-sea" if chosen_provider == "linode" else "nyc3",
                                size="g6-nanode-1" if chosen_provider == "linode" else "s-1vcpu-1gb")
    resources = FakeInspectorResourceRepository()
    provider = FakeObserverProvider()
    if chosen_provider == "digitalocean":
        original_create = provider.create
        def create_droplet(**kwargs):
            return replace(original_create(**kwargs), provider="digitalocean", resource_type="droplet")
        provider.create = create_droplet
    selected_name = "inspector-" + "a" * 32
    result = ensure_inspector_for_infrastructure_teardown(
        "eng-1", "human engagement name", "job-teardown", resource_name=selected_name,
        settings_repository=settings, provider_resource_repository=resources,
        provider_factory=lambda _provider: provider, runner=FakePreparingInspectorRunner(),
        ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
        credential_alias_resolver=lambda _provider: "selected-default",
        credential_secret_resolver=lambda _provider, _alias: "test-token",
    )
    assert provider.created[0]["name"] == selected_name
    assert result["inspectorHost"]["name"] == selected_name


@pytest.mark.parametrize("bad_name", [
    "", "inspector-human-engagement", "inspector-" + "A" * 32,
    "inspector-" + "a" * 31, "inspector-" + "a" * 32 + " ",
    42, {"name": "inspector-" + "a" * 32},
])
def test_teardown_preflight_bad_override_vetoes_before_any_side_effect(bad_name):
    class NoReadSettings:
        def get(self, _engagement_id):
            pytest.fail("settings read happened before name validation")
        def save(self, _settings):
            pytest.fail("settings write happened before name validation")
    class NoReadResources:
        def list_for_engagement(self, _engagement_id):
            pytest.fail("resource read happened before name validation")
        def save(self, _resource):
            pytest.fail("resource write happened before name validation")
    with pytest.raises(observer_checks.InspectionValidationError):
        ensure_inspector_for_infrastructure_teardown(
            "eng-1", "human name", "job-teardown", resource_name=bad_name,
            settings_repository=NoReadSettings(),
            provider_resource_repository=NoReadResources(),
            provider_factory=lambda _provider: pytest.fail("provider constructed"),
            ssh_key_factory=lambda _job_id: pytest.fail("key created"),
            credential_alias_resolver=lambda _provider: pytest.fail("credential resolved"),
        )


def test_teardown_preflight_prepare_failure_retains_host_for_retry():
    engagement_id = "eng-1"
    provider = FakeObserverProvider()
    settings = FakeInspectorSettingsRepository(engagement_id)
    resources = FakeInspectorResourceRepository()

    class FailingPreparation(FakePreparingInspectorRunner):
        def prepare_support_host(self, **_kwargs):
            raise ObserverCheckValidationError(["Inspector support-host preparation failed"])

    with pytest.raises(ObserverCheckValidationError):
        ensure_inspector_for_infrastructure_teardown(
            engagement_id,
            "ff-teardown-pf-retry",
            "job-teardown",
            settings_repository=settings,
            provider_resource_repository=resources,
            provider_factory=lambda _provider: provider,
            runner=FailingPreparation(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
    retry = ensure_inspector_for_infrastructure_teardown(
        engagement_id,
        "ff-teardown-pf-retry",
        "job-teardown",
        settings_repository=settings,
        provider_resource_repository=resources,
        provider_factory=lambda _provider: provider,
        runner=FakePreparingInspectorRunner(),
        ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
    )

    assert retry["status"] == "reused_prepared"
    assert len(provider.created) == 1


def test_teardown_preflight_retains_tracked_colliding_host_for_dedicated_cleanup():
    provider = FakeObserverProvider()
    settings = FakeInspectorSettingsRepository("eng-1")
    resources = FakeInspectorResourceRepository()
    targets = [{"id": "retired-edge", "type": "tcp-forbidden", "host": "198.51.100.25", "port": 22}]
    with pytest.raises(ObserverCheckValidationError) as error:
        ensure_inspector_for_infrastructure_teardown(
            "eng-1", "ff", "job-teardown", retired_targets=targets,
            settings_repository=settings, provider_resource_repository=resources,
            provider_factory=lambda _provider: provider, runner=FakePreparingInspectorRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda *_args: "secret",
        )
    assert error.value.failure_class == "retired_target_address_reuse"
    assert error.value.next_action == "Run dedicated Inspector Cleanup, then explicitly retry teardown"
    assert len(provider.created) == 1
    assert provider.destroyed == []
    assert resources.records[0].resource_id == "12345"
    assert resources.records[0].status == "active"
    assert len([record for record in resources.save_calls if record.resource_id == "12345"]) == 1
    assert targets == [{"id": "retired-edge", "type": "tcp-forbidden", "host": "198.51.100.25", "port": 22}]


def test_teardown_preflight_rejects_settings_only_host_without_adoption():
    provider = FakeObserverProvider()
    settings = FakeInspectorSettingsRepository("eng-1")
    settings.settings = replace(settings.settings, current_host={
        "provider": "linode", "resourceType": "instance", "resourceId": "settings-only",
        "name": "inspector", "region": "us-sea", "publicIp": "198.51.100.25", "status": "running",
    })
    with pytest.raises(ObserverCheckValidationError):
        ensure_inspector_for_infrastructure_teardown(
            "eng-1", "ff", "job-teardown",
            settings_repository=settings, provider_resource_repository=FakeInspectorResourceRepository(),
            provider_factory=lambda _provider: provider, runner=FakePreparingInspectorRunner(),
        )
    assert provider.created == []
    assert provider.destroyed == []


def test_teardown_preflight_preserves_reused_record_lineage():
    settings = FakeInspectorSettingsRepository("eng-1")
    resources = FakeInspectorResourceRepository()
    host = {
        "provider": "linode", "resourceType": "instance", "resourceId": "retained",
        "name": "inspector", "region": "us-sea", "publicIp": "198.51.100.26", "status": "running",
    }
    settings.settings = replace(settings.settings, current_host=host)
    resources.save(StoredProviderResourceRecord(
        id="linode:inspector:retained", engagement_id="eng-1", engagement_name="ff",
        provider="linode", resource_type="inspector_instance", resource_id="retained",
        name="inspector", region="us-sea", lifecycle_state="active", status="active",
        source="barragan_inspector_job", metadata={"role": "inspector", "barraganOwned": True, "publicIp": "198.51.100.26"},
        adoption_job_id="job-original", adopted_at="2026-09-01T00:00:00+00:00", updated_at="2026-09-01T00:00:00+00:00",
    ))
    ensure_inspector_for_infrastructure_teardown(
        "eng-1", "ff", "job-teardown", settings_repository=settings,
        provider_resource_repository=resources, runner=FakePreparingInspectorRunner(),
        ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
    )
    assert resources.records[0].adoption_job_id == "job-original"
    assert resources.records[0].metadata.get("inspectionJobId") is None


def test_teardown_verifier_rejects_self_probe_before_runner():
    settings = FakeInspectorSettingsRepository("eng-1")
    settings.settings = replace(settings.settings, current_host={
        "provider": "linode", "resourceType": "instance", "resourceId": "self",
        "name": "inspector", "region": "us-sea", "publicIp": "198.51.100.25", "status": "running",
    })
    runner = FakeTeardownVerificationRunner()
    result = verify_retired_public_endpoints_for_teardown(
        "eng-1", "ff", "job-teardown",
        [{"type": "dns-absent", "host": "old.example", "expectedIp": "198.51.100.25"}],
        settings_repository=settings, runner=runner,
    )
    assert result["failureClass"] == "retired_target_address_reuse"
    assert runner.calls == []


def test_teardown_state_tracks_settings_current_host_without_provider_record():
    settings = FakeInspectorSettingsRepository("eng-1")
    settings.settings = replace(
        settings.settings,
        current_host={
            "provider": "linode",
            "resourceType": "instance",
            "resourceId": "12345",
            "publicIp": "198.51.100.25",
            "status": "running",
        },
    )

    state = inspector_state_for_infrastructure_teardown(
        "eng-1",
        settings_repository=settings,
        provider_resource_repository=FakeInspectorResourceRepository(),
    )

    assert state["tracked"] is True
    assert state["reusable"] is True
    assert state["ownedProviderRecordIds"] == []


def test_teardown_state_includes_owned_inspector_firewall_without_treating_it_as_a_host():
    settings = FakeInspectorSettingsRepository("eng-1")
    resources = FakeInspectorResourceRepository()
    resources.records.extend(
        [
            SimpleNamespace(
                id="digitalocean:inspector:12345",
                engagement_id="eng-1",
                provider="digitalocean",
                resource_type="inspector_droplet",
                resource_id="12345",
                name="inspector-test",
                region="sfo3",
                status="active",
                metadata={
                    "barraganOwned": True,
                    "role": "inspector",
                    "publicIp": "198.51.100.25",
                },
            ),
            SimpleNamespace(
                id="digitalocean:inspector-firewall:firewall-1",
                engagement_id="eng-1",
                provider="digitalocean",
                resource_type="inspector_firewall",
                resource_id="firewall-1",
                name="inspector-test-ssh",
                region="sfo3",
                status="active",
                metadata={"barraganOwned": True, "role": "inspector_firewall"},
            ),
        ]
    )

    state = inspector_state_for_infrastructure_teardown(
        "eng-1",
        settings_repository=settings,
        provider_resource_repository=resources,
    )

    assert state["reusable"] is True
    assert state["ownedProviderRecordIds"] == [
        "digitalocean:inspector-firewall:firewall-1",
        "digitalocean:inspector:12345",
    ]


def test_teardown_preflight_refuses_duplicate_for_unusable_active_inspector_record():
    settings = FakeInspectorSettingsRepository("eng-1")
    resources = FakeInspectorResourceRepository()
    resources.records.append(
        SimpleNamespace(
            id="linode:inspector:stale",
            engagement_id="eng-1",
            provider="linode",
            resource_type="inspector_instance",
            resource_id="stale",
            name="inspector-stale",
            region="us-sea",
            status="active",
            metadata={"barraganOwned": True, "role": "inspector", "publicIps": []},
        )
    )
    provider = FakeObserverProvider()

    with pytest.raises(ObserverCheckValidationError) as error:
        ensure_inspector_for_infrastructure_teardown(
            "eng-1",
            "ff-teardown-pf",
            "job-teardown",
            settings_repository=settings,
            provider_resource_repository=resources,
            provider_factory=lambda _provider: provider,
            runner=FakePreparingInspectorRunner(),
            ssh_key_factory=lambda _job_id: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )

    assert provider.created == []
    assert "no usable public IPv4" in error.value.errors[0]


def test_teardown_inspector_cleanup_destroys_every_tracked_retained_host(client):
    engagement_id = _create_engagement(client, "ff-inspector-multiple-cleanup")
    provider = FakeObserverProvider()

    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        resource_repo = SqlAlchemyProviderResourceRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                enabled=True,
                mode="continuous",
                current_host={
                    "provider": "linode",
                    "resourceType": "instance",
                    "resourceId": "12345",
                    "name": "inspector-current",
                    "region": "us-sea",
                    "publicIp": "198.51.100.25",
                    "sshUser": "root",
                    "status": "running",
                },
            )
        )
        resource_repo.save(
            StoredProviderResourceRecord(
                id="linode:inspector:67890",
                engagement_id=engagement_id,
                engagement_name="ff-inspector-multiple-cleanup",
                provider="linode",
                resource_type="inspector_instance",
                resource_id="67890",
                name="inspector-stale",
                region="us-sea",
                lifecycle_state="active",
                status="active",
                source="barragan_inspector_job",
                metadata={
                    "role": "inspector",
                    "barraganOwned": True,
                    "publicIp": "198.51.100.26",
                    "publicIps": ["198.51.100.26"],
                },
                adoption_job_id="job-inspection-old",
                adopted_at="2026-07-08T00:00:00+00:00",
                updated_at="2026-07-08T00:00:00+00:00",
            )
        )

        result = cleanup_inspector_for_infrastructure_teardown(
            engagement_id,
            "ff-inspector-multiple-cleanup",
            "job-teardown",
            settings_repository=settings_repo,
            provider_resource_repository=resource_repo,
            provider_factory=lambda _provider: provider,
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
        updated = settings_repo.get(engagement_id)
        records = resource_repo.list_for_engagement(engagement_id)

    assert result["ok"] is True
    assert result["cleanupVerified"] is True
    assert result["currentHostCleared"] is True
    assert {entry["resourceId"] for entry in result["inspectorHosts"]} == {"12345", "67890"}
    assert {entry["host"].resource_id for entry in provider.destroyed} == {"12345", "67890"}
    assert updated is not None
    assert updated.current_host == {}
    assert {record.status for record in records} == {"destroyed"}


def test_teardown_inspector_cleanup_preserves_host_when_destroy_fails(client):
    engagement_id = _create_engagement(client, "ff-inspector-cleanup-fails")
    provider = FakeObserverProvider(cleanup_ok=False)

    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                enabled=True,
                mode="continuous",
                current_host={
                    "provider": "linode",
                    "resourceType": "instance",
                    "resourceId": "12345",
                    "name": "inspector-ff-inspector-cleanup-fails",
                    "region": "us-sea",
                    "publicIp": "198.51.100.25",
                    "sshUser": "observer",
                    "status": "running",
                },
            )
        )
        result = cleanup_inspector_for_infrastructure_teardown(
            engagement_id,
            "ff-inspector-cleanup-fails",
            "job-teardown",
            settings_repository=settings_repo,
            provider_resource_repository=SqlAlchemyProviderResourceRepository(),
            provider_factory=lambda _provider: provider,
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
        )
        updated = settings_repo.get(engagement_id)
        records = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)

    assert result["ok"] is False
    assert result["status"] == "cleanup_required"
    assert result["disabled"] is True
    assert result["cleanupVerified"] is False
    assert result["currentHostCleared"] is False
    assert updated is not None
    assert updated.enabled is False
    assert updated.current_host["resourceId"] == "12345"
    assert records[0].status == "cleanup_required"
    assert records[0].metadata["cleanupRequired"] is True


@pytest.mark.parametrize("provider_name", ["linode", "digitalocean"])
def test_standalone_inspector_cleanup_previews_and_destroys_only_tracked_resources(client, provider_name):
    engagement_id = _create_engagement(client, f"ff-{provider_name}-standalone-cleanup")
    provider = FakeObserverProvider()
    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        resource_repo = SqlAlchemyProviderResourceRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                enabled=True,
                provider=provider_name,
                mode="continuous",
                current_host={
                    "provider": provider_name,
                    "resourceType": "instance",
                    "resourceId": "host-123",
                    "name": "opaque-inspector",
                    "region": "test-region",
                    "publicIp": "198.51.100.25",
                    "status": "running",
                    "metadata": {
                        "providerFirewall": {
                            "provider": provider_name,
                            "resourceId": "firewall-456",
                            "name": "opaque-firewall",
                            "tag": "opaque-tag",
                        }
                    },
                },
            )
        )
        resource_repo.save(
            StoredProviderResourceRecord(
                id=f"{provider_name}:inspector:unmanaged",
                engagement_id=engagement_id,
                engagement_name=f"ff-{provider_name}-standalone-cleanup",
                provider=provider_name,
                resource_type="inspector_instance",
                resource_id="unmanaged-host",
                name="manually-managed-inspector",
                region="test-region",
                lifecycle_state="active",
                status="active",
                source="provider_inventory",
                metadata={"role": "inspector", "barraganOwned": False, "publicIp": "198.51.100.26"},
                adoption_job_id="",
                adopted_at="2026-09-03T00:00:00+00:00",
                updated_at="2026-09-03T00:00:00+00:00",
            )
        )
        preview = preview_inspector_cleanup(
            engagement_id,
            settings_repository=settings_repo,
            provider_resource_repository=resource_repo,
            job_repository=SqlAlchemyJobRepository(),
        )
        assert preview is not None
        result = start_inspector_cleanup(
            engagement_id,
            {"confirmation": preview["confirmationToken"]},
            settings_repository=settings_repo,
            job_repository=SqlAlchemyJobRepository(),
            provider_resource_repository=resource_repo,
            provider_factory=lambda _provider: provider,
            credential_alias_resolver=lambda _provider: "provider-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )
        updated = settings_repo.get(engagement_id)

    assert preview["scope"]["inspectorOnly"] is True
    assert preview["scope"]["coreInfrastructure"] is False
    assert preview["hosts"][0]["associatedResources"][0]["resourceId"] == "firewall-456"
    assert {host["resourceId"] for host in preview["hosts"]} == {"host-123"}
    assert result is not None
    assert result["status"] == "succeeded"
    assert result["job"]["action"] == INSPECTOR_CLEANUP_ACTION
    assert result["job"]["input"]["inspectorOnly"] is True
    assert updated is not None
    assert updated.enabled is False
    assert updated.current_host == {}
    assert {entry["host"].resource_id for entry in provider.destroyed} == {"host-123"}


def test_standalone_inspector_cleanup_failure_retains_host_for_retry(client):
    engagement_id = _create_engagement(client, "ff-standalone-cleanup-retry")
    provider = FakeObserverProvider(cleanup_ok=False)
    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                enabled=True,
                current_host={
                    "provider": "linode",
                    "resourceType": "instance",
                    "resourceId": "host-retry",
                    "name": "opaque-inspector",
                    "region": "us-sea",
                    "publicIp": "198.51.100.25",
                    "status": "running",
                },
            )
        )
        preview = preview_inspector_cleanup(engagement_id, settings_repository=settings_repo)
        assert preview is not None
        result = start_inspector_cleanup(
            engagement_id,
            {"confirmation": preview["confirmationToken"]},
            settings_repository=settings_repo,
            provider_factory=lambda _provider: provider,
            credential_alias_resolver=lambda _provider: "linode-default",
            credential_secret_resolver=lambda _provider, _alias: "live-token-secret",
            background_runner=lambda task: task(),
        )
        updated = settings_repo.get(engagement_id)

    assert result is not None
    assert result["status"] == "failed"
    assert updated is not None
    assert updated.current_host["resourceId"] == "host-retry"
    assert result["job"]["events"][-1]["data"]["inspectorCleanup"]["status"] == "cleanup_required"


def test_standalone_inspector_cleanup_rejects_running_inspection(client):
    engagement_id = _create_engagement(client, "ff-cleanup-lock")
    with client.application.storage_context():
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(engagement_id)
        assert settings is not None
        settings_repo.save(
            replace(
                settings,
                current_host={
                    "provider": "linode",
                    "resourceType": "instance",
                    "resourceId": "host-lock",
                    "name": "opaque-inspector",
                    "region": "us-sea",
                    "publicIp": "198.51.100.25",
                    "status": "running",
                },
            )
        )
        jobs = SqlAlchemyJobRepository()
        jobs.save(
            StoredJobRun(
                id="job-running-inspection",
                action="inspector_inspection",
                status="running",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={},
                artifact_refs=[],
                created_at="2026-09-03T00:00:00+00:00",
                started_at="2026-09-03T00:00:00+00:00",
                finished_at=None,
                events=[],
            )
        )
        preview = preview_inspector_cleanup(engagement_id, settings_repository=settings_repo, job_repository=jobs)
        assert preview is not None
        with pytest.raises(InspectorCleanupValidationError) as error:
            start_inspector_cleanup(
                engagement_id,
                {"confirmation": preview["confirmationToken"]},
                settings_repository=settings_repo,
                job_repository=jobs,
                background_runner=lambda task: task(),
            )

    assert preview["canDestroy"] is False
    assert "already running" in error.value.errors[0]


def _create_engagement(client, name: str) -> str:
    response = client.post(
        "/api/engagements",
        json={"name": name, "owner": "operator"},
    )
    assert response.status_code == 201
    return response.get_json()["engagement"]["id"]


def _save_observer_settings(client, engagement_id: str) -> None:
    response = client.patch(
        f"/api/engagements/{engagement_id}/observer-settings",
        json={
            "provider": "linode",
            "region": "us-sea",
            "size": "g6-nanode-1",
            "forbiddenTcpPorts": ["22", "2222", "80"],
        },
    )
    assert response.status_code == 200


def _assign_domain(client, engagement_id: str, domain_name: str) -> None:
    now = "2026-06-17T00:00:00+00:00"
    with client.application.storage_context():
        repo = SqlAlchemyDomainRepository()
        repo.save_asset(
            StoredDomainAsset(
                id=f"domain-{domain_name}",
                domain_name=domain_name,
                registrar="namecheap",
                registration_started_at="2026-01-01",
                expiration_at="2027-01-01",
                auto_renew=True,
                provider_status="active",
                notes="",
                risk_status="green",
                risk_flags=[],
                cooldown_until="",
                assignable_override=False,
                catalog_state="auto",
                metadata={},
                last_synced_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        repo.save_assignment(
            StoredDomainAssignment(
                id=None,
                domain_id=f"domain-{domain_name}",
                engagement_id=engagement_id,
                engagement_name="ff-observer-domain",
                purpose="rti",
                purpose_tags=["rti"],
                status="active",
                notes="",
                assigned_by="test",
                released_by="",
                assigned_at=now,
                released_at=None,
            )
        )


def _seed_operations(
    client,
    engagement_id: str,
    *,
    domain: str = "www.example.invalid",
    channel_status: str = "Validated",
    protocol: str = "TCP",
    external_port: str = "80",
    mode: str = "tcp-forward",
    validation_profile: dict | None = None,
) -> None:
    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        repo.save(
            StoredJobRun(
                id="job-observer-sketch",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="test",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-17T00:00:00+00:00",
                started_at="2026-06-17T00:00:00+00:00",
                finished_at="2026-06-17T00:01:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "sketch deployed",
                        {
                            "sketchInfrastructure": [
                                {
                                    "chainId": "proxy01-sea-01",
                                    "hostname": "edge-ff-observer-us-sea-proxy01-sea-01",
                                    "role": "edge",
                                    "provider": "linode",
                                    "publicIp": "203.0.113.44",
                                    "region": "us-sea",
                                    "proxy": "proxy01",
                                    "status": "deployed",
                                }
                            ]
                        },
                    )
                ],
            )
        )
        repo.save(
            StoredJobRun(
                id="job-observer-inbound",
                action="engagement_channels_update",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="test",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-17T00:02:00+00:00",
                started_at="2026-06-17T00:02:00+00:00",
                finished_at="2026-06-17T00:02:01+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "channels updated",
                        {
                            "inboundChannels": [
                                {
                                    "channelId": "edge-80-to-web",
                                    "domain": domain,
                                    "protocol": protocol,
                                    "mode": mode,
                                    "externalPort": external_port,
                                    "edge": "edge-ff-observer-us-sea-proxy01-sea-01",
                                    "middle": "middle-ff-observer-us-sea-proxy01-sea-01",
                                    "proxy": "proxy01",
                                    "terminatesOn": "proxy01",
                                    "internalPort": "18080",
                                    "service": "Static Web",
                                    "purpose": "public site",
                                    "status": channel_status,
                                    "validationProfile": validation_profile
                                    or {"type": "tcp-send-receive", "requestText": "GET / HTTP/1.0\\r\\n\\r\\n", "expectedResponse": "hola"},
                                }
                            ]
                        },
                    )
                ],
            )
        )


def _serialized_probe_matrix(*, raw=False):
    positive = [{"type": kind} for kind in ("tcp", "tcp", "tcp", "http", "https", "dns", "udp")]
    negative = [{"type": "tcp-forbidden"} for _ in range(32)]
    if raw:
        # Four edges, each with TCP and UDP request/response acceptance, and
        # forbidden exposure at the three unselected middle/sibling targets.
        positive += [{"type": kind} for _ in range(4) for kind in ("tcp-send-expect", "udp")]
        negative += [{"type": kind} for _ in range(12) for kind in ("tcp-forbidden", "udp-forbidden")]
    return {"positive": positive, "negative": negative, "timeoutSeconds": 8}


@pytest.mark.parametrize("raw, expected", [(False, 324), (True, 660)])
def test_ssh_check_execution_budget_covers_serialized_matrix_only(monkeypatch, raw, expected):
    spec = _serialized_probe_matrix(raw=raw)
    assert observer_checks._observer_check_execution_timeout(spec) == expected
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs["timeout"]))
        output = '{"ok":true,"results":[]}' if any(str(arg).endswith("/observer_check.py") for arg in command) else ""
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
    monkeypatch.setattr(observer_checks.subprocess, "run", run)
    evidence = SshObserverRunner(readiness_attempts=1, readiness_delay_seconds=0).run(
        host=ObserverHost("linode", "instance", "12345", "inspector-test", "us-sea", "198.51.100.25"),
        ssh_key=ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"), spec=spec)
    assert evidence["ok"] is True
    assert len(calls) == 4
    for command, timeout in calls:
        is_check = command[0] == "ssh" and "python3" in command
        assert timeout == (expected if is_check else 120)


def test_check_budget_accounts_for_probe_timeout_dns_retries_and_scan():
    spec = {"timeoutSeconds": 3, "positive": [{"type": "dns"}, {"type": "nmap"}],
            "negative": [{"type": "dns-absent"}, {"type": "udp-forbidden"}]}
    assert observer_checks._observer_check_execution_timeout(spec) == 60 + 12 + 60 + 36 + 4 + 6
    assert observer_checks._observer_check_execution_timeout({"positive": [], "negative": []}) == 120


def test_oversized_inspector_matrix_rejects_before_remote_commands(monkeypatch):
    monkeypatch.setattr(observer_checks.subprocess, "run", lambda *a, **kw: pytest.fail("remote command started"))
    with pytest.raises(observer_checks.ObserverCheckValidationError) as caught:
        SshObserverRunner().run(
            host=ObserverHost("linode", "instance", "12345", "inspector-test", "us-sea", "198.51.100.25"),
            ssh_key=ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
            spec={"positive": [{"type": "nmap"}] * 60, "negative": []})
    assert caught.value.errors == ["Inspector check matrix exceeds the bounded execution budget"]


@pytest.mark.parametrize("timeout", [True, 0, -1, 3601, 1.5])
def test_observer_command_timeout_remains_finite_and_typed(monkeypatch, timeout):
    monkeypatch.setattr(observer_checks.subprocess, "run", lambda *a, **kw: pytest.fail("command started"))
    with pytest.raises(ValueError, match="command timeout differs"):
        observer_checks._run_checked(["ssh"], timeout_seconds=timeout)
