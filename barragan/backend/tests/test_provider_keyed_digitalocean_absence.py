# Copyright (c) 2026, Oracle and/or its affiliates.
"""Injected GET-only post-destroy DigitalOcean inventory proof."""

import copy
import hashlib
import json

import pytest

import app.services.provider_keyed_digitalocean_absence as service
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace


class Repository:
    def get(self, identifier):
        return self.get_default("digitalocean") if identifier == "cred-000000000001" else None

    def get_default(self, provider):
        assert provider == "digitalocean"
        return type("Credential", (), {
            "id": "cred-000000000001", "provider": provider,
            "status": "active", "is_default": True,
            "encrypted_secret": "encrypted-token", "updated_at": "2026-10-02T00:00:00Z",
        })()


class Transport:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []
        self.attempt = 0

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET"
        assert token == "token-fixture"
        self.calls.append(path)
        if path == "/droplets?page=1&per_page=200":
            self.attempt += 1
        value = self.pages[path]
        if isinstance(value, list):
            return copy.deepcopy(value[min(self.attempt - 1, len(value) - 1)])
        return copy.deepcopy(value)


def _page(key, rows, *, total=None, next_url=None):
    links = {"pages": {"next": next_url}} if next_url else {}
    return {key: rows, "meta": {"total": len(rows) if total is None else total}, "links": links}


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = tmp_path / "provider-state"
    root.mkdir()
    state = {
        "version": 4, "terraform_version": "1.15.5", "serial": 3,
        "lineage": "db0cb9ba-cad2-43dc-9a6e-8b2418517370", "resources": [],
    }
    state_path = root / "terraform.tfstate"
    state_path.write_text(json.dumps(state))
    phase_path = root / ".barragan-apply-phase.json"
    phase_path.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_applied"}))
    workspace = ProviderKeyedWorkspace(
        root, state_path, root / ".terraform-data", "provider-keyed-v2",
        "digitalocean", "cred-000000000001", "fingerprint",
        "ca5bcad7d2be274aaa79d6c9127cbd9b5c2b10cc", "source-hash",
    )
    firewall = "bb4b2611-3d72-467b-8602-280330ecd65c"
    selector = "opaque-selector-a1"
    intent = service.DigitalOceanAbsenceIntent(
        resource_ids={
            'digitalocean_droplet.middle["primary"]': "101",
            'digitalocean_droplet.edge["sfo3-01"]': "102",
            "digitalocean_firewall.firewall": firewall,
            "digitalocean_ssh_key.key": "301",
            "local_file.ansible_inventory[0]": "/tmp/inventory",
            "local_file.ssh_stanza[0]": "/tmp/stanza",
        },
        selector_tag=selector,
        pre_destroy_state_sha256="a" * 64,
        state_lineage=state["lineage"], pre_destroy_serial=2,
        empty_state_sha256=hashlib.sha256(state_path.read_bytes()).hexdigest(),
        destroy_phase_sha256=hashlib.sha256(phase_path.read_bytes()).hexdigest(),
        credential_record_id=workspace.provider_connection_id,
        credential_secret_sha256=hashlib.sha256(b"encrypted-token").hexdigest(),
        credential_updated_at="2026-10-02T00:00:00Z",
    )
    pages = {
        "/droplets?page=1&per_page=200": _page("droplets", []),
        "/droplets?page=1&per_page=200&type=gpus": _page("droplets", []),
        "/firewalls?page=1&per_page=200": _page("firewalls", []),
        "/account/keys?page=1&per_page=200": _page("ssh_keys", []),
        "/tags?page=1&per_page=200": _page("tags", [{
            "name": selector, "resources": {"count": 0},
        }]),
    }
    monkeypatch.setattr(service, "decrypt_secret_value", lambda encrypted: "token-fixture")
    return workspace, intent, pages


def _run(prepared, pages=None, **kwargs):
    workspace, intent, default_pages = prepared
    transport = Transport(pages or default_pages)
    result = service.reconcile_digitalocean_keyed_destroy_absence(
        workspace, intent, environment="devtest", deployment_target="barragan-testing",
        credential_repository=Repository(), transport=transport,
        sleeper=lambda seconds: None, **kwargs,
    )
    return result, transport


def test_waits_for_owned_resources_to_disappear_and_reports_empty_tag(prepared):
    _, intent, original = prepared
    pages = copy.deepcopy(original)
    pages["/droplets?page=1&per_page=200"] = [
        _page("droplets", [{"id": 101, "tags": [intent.selector_tag]}]),
        original["/droplets?page=1&per_page=200"],
    ]
    pages["/firewalls?page=1&per_page=200"] = [
        _page("firewalls", [{"id": intent.resource_ids["digitalocean_firewall.firewall"],
                             "tags": [intent.selector_tag]}]),
        original["/firewalls?page=1&per_page=200"],
    ]
    pages["/account/keys?page=1&per_page=200"] = [
        _page("ssh_keys", [{"id": 301}]), original["/account/keys?page=1&per_page=200"],
    ]
    pages["/tags?page=1&per_page=200"] = [
        _page("tags", [{"name": intent.selector_tag, "resources": {"count": 1}}]),
        original["/tags?page=1&per_page=200"],
    ]
    result, transport = _run(prepared, pages)
    assert result.attempts == 2
    assert result.verified_absent_droplet_ids == ("101", "102")
    assert result.selector_tag_cleanup_pending is True
    assert len(transport.calls) == 10
    assert "token-fixture" not in repr(result)


def test_gpu_inventory_catches_owned_droplet_and_tag_reuse(prepared):
    _, intent, original = prepared
    pages = copy.deepcopy(original)
    pages["/droplets?page=1&per_page=200&type=gpus"] = _page(
        "droplets", [{"id": 102, "tags": [intent.selector_tag]}],
    )
    with pytest.raises(service.DigitalOceanAbsenceError, match="did not settle"):
        _run(prepared, pages, max_attempts=2)
    pages["/droplets?page=1&per_page=200&type=gpus"] = _page(
        "droplets", [{"id": 999, "tags": [intent.selector_tag]}],
    )
    with pytest.raises(service.DigitalOceanAbsenceError, match="unreviewed Droplet"):
        _run(prepared, pages)


def test_unreviewed_firewall_selector_reuse_fails_closed(prepared):
    _, intent, original = prepared
    pages = copy.deepcopy(original)
    pages["/firewalls?page=1&per_page=200"] = _page("firewalls", [{
        "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "tags": [intent.selector_tag],
    }])
    with pytest.raises(service.DigitalOceanAbsenceError, match="unreviewed firewall"):
        _run(prepared, pages)


def test_tag_absent_requires_no_cleanup_and_nonempty_tag_cannot_complete(prepared):
    _, _, original = prepared
    pages = copy.deepcopy(original)
    pages["/tags?page=1&per_page=200"] = _page("tags", [])
    result, _ = _run(prepared, pages)
    assert result.selector_tag_cleanup_pending is False
    pages["/tags?page=1&per_page=200"] = _page("tags", [{
        "name": "opaque-selector-a1", "resources": {"count": 1},
    }])
    with pytest.raises(service.DigitalOceanAbsenceError, match="did not settle"):
        _run(prepared, pages, max_attempts=2)


def test_paginates_all_inventory_and_rejects_truncation(prepared):
    _, _, original = prepared
    pages = copy.deepcopy(original)
    pages["/account/keys?page=1&per_page=200"] = _page(
        "ssh_keys", [{"id": 401}], total=2,
        next_url="https://api.digitalocean.com/v2/account/keys?page=2&per_page=200",
    )
    pages["/account/keys?page=2&per_page=200"] = _page("ssh_keys", [{"id": 402}], total=2)
    result, transport = _run(prepared, pages)
    assert result.selector_tag_cleanup_pending
    assert "/account/keys?page=2&per_page=200" in transport.calls
    pages["/account/keys?page=2&per_page=200"] = _page("ssh_keys", [], total=2)
    with pytest.raises(service.DigitalOceanAbsenceError, match="did not settle"):
        _run(prepared, pages, max_attempts=2)


def test_follows_provider_capped_page_size(prepared):
    _, _, original = prepared
    pages = copy.deepcopy(original)
    pages["/account/keys?page=1&per_page=200"] = _page(
        "ssh_keys", [{"id": 401}], total=2,
        next_url="https://api.digitalocean.com/v2/account/keys?page=2&per_page=100",
    )
    pages["/account/keys?page=2&per_page=100"] = _page("ssh_keys", [{"id": 402}], total=2)
    result, transport = _run(prepared, pages)
    assert result.selector_tag_cleanup_pending
    assert "/account/keys?page=2&per_page=100" in transport.calls


def test_requires_post_destroy_empty_state_and_fence_before_provider_reads(prepared):
    workspace, intent, pages = prepared
    (workspace.path / ".barragan-apply-phase.json").write_text(
        json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"})
    )
    transport = Transport(pages)
    with pytest.raises(service.DigitalOceanAbsenceError, match="retained destroy state"):
        service.reconcile_digitalocean_keyed_destroy_absence(
            workspace, intent, environment="devtest", deployment_target="barragan-testing",
            credential_repository=Repository(), transport=transport,
        )
    assert transport.calls == []


def test_transport_failure_is_bounded_and_never_proves_absence(prepared):
    workspace, intent, _ = prepared

    class FailingTransport:
        calls = 0

        def request(self, origin, method, path, token):
            self.calls += 1
            raise RuntimeError("provider detail with token-fixture")

    transport = FailingTransport()
    with pytest.raises(service.DigitalOceanAbsenceError, match="did not settle") as error:
        service.reconcile_digitalocean_keyed_destroy_absence(
            workspace, intent, environment="devtest", deployment_target="barragan-testing",
            credential_repository=Repository(), transport=transport,
            max_attempts=2, sleeper=lambda seconds: None,
        )
    assert transport.calls == 2
    assert "token-fixture" not in str(error.value)


def test_rejects_scope_without_provider_reads(prepared):
    workspace, intent, pages = prepared
    transport = Transport(pages)
    with pytest.raises(service.DigitalOceanAbsenceError, match="DevTest"):
        service.reconcile_digitalocean_keyed_destroy_absence(
            workspace, intent, environment="prod", deployment_target="barragan-testing",
            credential_repository=Repository(), transport=transport,
        )
    assert transport.calls == []
