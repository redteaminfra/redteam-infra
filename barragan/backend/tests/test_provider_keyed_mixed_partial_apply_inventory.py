# Copyright (c) 2026, Oracle and/or its affiliates.
"""Complete GET snapshots remain separate from Apply outcomes and destroy authority."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_partial_apply_inventory as inventory
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA


def _page(key, rows, *, total=None, next_url=None):
    return {key: rows, "meta": {"total": len(rows) if total is None else total},
            "links": {"pages": {"next": next_url} if next_url else {}}}


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    policy = {
        "linode": {"engagement_name": "opaque", "provider_connection_id": "linode-credential",
                   "credential_secret_sha256": hashlib.sha256(b"sealed-linode").hexdigest(),
                   "credential_updated_at": "2026-10-01"},
        "digitalocean": {"selector_tag": "opaque-selector",
                         "provider_connection_id": "do-credential",
                         "credential_secret_sha256": hashlib.sha256(b"sealed-do").hexdigest(),
                         "credential_updated_at": "2026-10-01"},
    }
    monkeypatch.setattr(inventory, "validate_mixed_initial_apply_seal", lambda parent: {
        "orderedProviders": ["linode", "digitalocean"], "reviewedPolicy": policy})
    monkeypatch.setattr(inventory, "_require_canonical_workspace_paths", lambda workspace: None)
    monkeypatch.setattr(inventory, "_verify_linode_workspace", lambda workspace: None)
    monkeypatch.setattr(inventory, "_verify_audited_workspace", lambda workspace: None)
    records = {}
    for provider, secret in (("linode", "sealed-linode"), ("digitalocean", "sealed-do")):
        connection = policy[provider]["provider_connection_id"]
        records[provider] = SimpleNamespace(
            id=connection, provider=provider, status="active", is_default=True,
            encrypted_secret=secret, updated_at="2026-10-01")

    class Credentials:
        def get(self, connection):
            return next((row for row in records.values() if row.id == connection), None)

        def get_default(self, provider):
            return records[provider]

    def workspace(provider):
        root = tmp_path / provider
        root.mkdir()
        return ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
                                      SCHEMA, provider, policy[provider]["provider_connection_id"],
                                      "fingerprint", "0" * 40, "sha")

    return SimpleNamespace(credentials=Credentials(), workspace=workspace)


def test_linode_complete_firewall_device_pages(boundary):
    workspace = boundary.workspace("linode")
    workspace.state_path.write_bytes(b'{"version":4}')
    calls = []

    class Transport:
        def request(self, method, path, token):
            calls.append((method, path))
            assert method == "GET" and token == "sealed-linode"
            if path.startswith("/linode/instances?"):
                rows = [{"id": 101, "label": "opaque-middle", "tags": ["opaque"]}]
            elif path.startswith("/networking/firewalls?"):
                rows = [{"id": 301, "label": "fw-opaque-firewall", "tags": ["opaque"]}]
            elif path.startswith("/networking/firewalls/301/devices?"):
                rows = [{"id": 901, "entity": {"id": 101, "type": "linode"}}]
            else:
                raise AssertionError(path)
            return {"data": rows, "page": 1, "pages": 1, "results": len(rows)}

    result = inventory.collect_provider_inventory_snapshot(
        object(), "linode", workspace, fence=lambda: "same-journal-generation",
        process_quiescent=lambda: True, credential_repository=boundary.credentials,
        linode_transport=Transport(), decrypt_secret=lambda value: value)
    assert result.linode_firewall_attached_node_ids == ("101",)
    assert result.state_json == b'{"version":4}'
    assert len(result.inventory) == 2
    assert len(calls) == 3 and all(method == "GET" for method, _ in calls)


def test_destroy_phase_requires_explicit_mode_and_keeps_full_fence(boundary):
    workspace = boundary.workspace("linode")
    (workspace.path / ".barragan-apply-phase.json").write_text(
        '{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
    calls = []

    class Transport:
        def request(self, method, path, token):
            calls.append(path)
            assert method == "GET" and token == "sealed-linode"
            return {"data": [], "page": 1, "pages": 1, "results": 0}

    options = dict(fence=lambda: "same-generation", process_quiescent=lambda: True,
                   credential_repository=boundary.credentials,
                   linode_transport=Transport(), decrypt_secret=lambda value: value)
    with pytest.raises(inventory.MixedPartialApplyInventoryAttention):
        inventory.collect_provider_inventory_snapshot(object(), "linode", workspace, **options)
    assert calls == []
    observed = inventory.collect_provider_inventory_snapshot(
        object(), "linode", workspace, phase_mode="destroy_applied", **options)
    assert observed.state_json is None and observed.phase == "destroy_applied"
    assert len(calls) == 2


def test_digitalocean_selector_and_ssh_key_are_read_without_database(boundary):
    workspace = boundary.workspace("digitalocean")
    paths = []

    class Transport:
        def request(self, origin, method, path, token):
            assert method == "GET" and token == "sealed-do"
            paths.append(path)
            if path.startswith("/droplets?"):
                rows = [] if "type=gpus" in path else [{
                    "id": 17, "name": "opaque-middle", "tags": ["opaque-selector"]}]
                return _page("droplets", rows)
            if path.startswith("/firewalls?"):
                return _page("firewalls", [{"id": "fw-1", "name": "opaque-firewall",
                                            "tags": ["opaque-selector"]}])
            if path.startswith("/account/keys?"):
                return _page("ssh_keys", [{"id": 23, "name": "opaque-key", "public_key": "ssh-ed25519 opaque"}])
            if path.startswith("/tags?"):
                return _page("tags", [{"name": "opaque-selector", "resources": {"count": 1}}])
            raise AssertionError(path)

    result = inventory.collect_provider_inventory_snapshot(
        object(), "digitalocean", workspace, fence=lambda: "same-journal-generation",
        process_quiescent=lambda: True, credential_repository=boundary.credentials,
        digitalocean_transport=Transport(), decrypt_secret=lambda value: value)
    assert result.selector_tag_exists is True
    assert result.selector_resources_count == 1
    assert result.selector_attached_node_ids == ("17",)
    assert {row["kind"] for row in result.inventory} == {"node", "firewall", "ssh_key"}
    assert not any("database" in path for path in paths)


@pytest.mark.parametrize("include_details", [False, True])
def test_digitalocean_firewall_details_are_opt_in_and_selector_scoped(monkeypatch, include_details):
    selected = dict(id="owned", name="opaque-firewall", tags=["selector"],
                    status="succeeded", pending_changes=[], droplet_ids=[],
                    inbound_rules=[], outbound_rules=[])
    unrelated = dict(id="other", name="other", tags=["other"], status="waiting")
    pages = {"/droplets": [], "/firewalls": [selected, unrelated],
             "/account/keys": [], "/tags": []}
    calls = []
    def read(client, token, endpoint, key, **kwargs):
        calls.append(endpoint)
        return pages[endpoint]
    monkeypatch.setattr(inventory, "_do_inventory", read)
    rows, _, _, _ = inventory._digitalocean(object(), "token", "selector", lambda: "fence",
        include_firewall_details=include_details)
    owned, other = rows
    assert owned.get("firewall") == (selected if include_details else None)
    assert "firewall" not in other
    assert calls == ["/droplets", "/droplets", "/firewalls", "/account/keys", "/tags"]


def test_changed_journal_fence_fails_closed(boundary):
    workspace = boundary.workspace("linode")
    count = 0

    def fence():
        nonlocal count
        count += 1
        return "changed" if count > 1 else "original"

    class Transport:
        def request(self, method, path, token):
            return {"data": [], "page": 1, "pages": 1, "results": 0}

    with pytest.raises(inventory.MixedPartialApplyInventoryAttention):
        inventory.collect_provider_inventory_snapshot(
            object(), "linode", workspace, fence=fence,
            process_quiescent=lambda: True, credential_repository=boundary.credentials,
            linode_transport=Transport(), decrypt_secret=lambda value: value)


def test_state_changed_during_provider_read_fails_closed(boundary):
    workspace = boundary.workspace("linode")
    workspace.state_path.write_bytes(b'{"serial":1}')

    class Transport:
        def request(self, method, path, token):
            workspace.state_path.write_bytes(b'{"serial":2}')
            return {"data": [], "page": 1, "pages": 1, "results": 0}

    with pytest.raises(inventory.MixedPartialApplyInventoryAttention):
        inventory.collect_provider_inventory_snapshot(
            object(), "linode", workspace, fence=lambda: "same-generation",
            process_quiescent=lambda: True, credential_repository=boundary.credentials,
            linode_transport=Transport(), decrypt_secret=lambda value: value)


def test_linode_two_pages_recheck_fence_on_each_get(boundary):
    workspace = boundary.workspace("linode")
    generation = "one"
    calls = []

    class Transport:
        def request(self, method, path, token):
            nonlocal generation
            calls.append(path)
            if path == "/linode/instances?page=1&page_size=100":
                return {"data": [{"id": 101, "label": "unrelated-one", "tags": []}],
                        "page": 1, "pages": 2, "results": 2}
            if path == "/linode/instances?page=2&page_size=100":
                generation = "two"  # Claim changes during the second page.
                return {"data": [{"id": 102, "label": "unrelated-two", "tags": []}],
                        "page": 2, "pages": 2, "results": 2}
            raise AssertionError(path)

    with pytest.raises(inventory.MixedPartialApplyInventoryAttention):
        inventory.collect_provider_inventory_snapshot(
            object(), "linode", workspace, fence=lambda: generation,
            process_quiescent=lambda: True, credential_repository=boundary.credentials,
            linode_transport=Transport(), decrypt_secret=lambda value: value)
    assert calls == ["/linode/instances?page=1&page_size=100",
                     "/linode/instances?page=2&page_size=100"]


def test_digitalocean_selector_count_mismatch_fails_closed(boundary):
    workspace = boundary.workspace("digitalocean")

    class Transport:
        def request(self, origin, method, path, token):
            if path.startswith("/droplets?"):
                rows = [] if "type=gpus" in path else [{"id": 17, "name": "owned", "tags": ["opaque-selector"]}]
                return _page("droplets", rows)
            if path.startswith("/firewalls?"):
                return _page("firewalls", [])
            if path.startswith("/account/keys?"):
                return _page("ssh_keys", [])
            if path.startswith("/tags?"):
                return _page("tags", [{"name": "opaque-selector", "resources": {"count": 2}}])
            raise AssertionError(path)

    with pytest.raises(inventory.MixedPartialApplyInventoryAttention):
        inventory.collect_provider_inventory_snapshot(
            object(), "digitalocean", workspace, fence=lambda: "same-generation",
            process_quiescent=lambda: True, credential_repository=boundary.credentials,
            digitalocean_transport=Transport(), decrypt_secret=lambda value: value)


def test_digitalocean_two_page_inventory_checks_fence(boundary):
    workspace = boundary.workspace("digitalocean")
    generation = "one"
    calls = []

    class Transport:
        def request(self, origin, method, path, token):
            nonlocal generation
            calls.append(path)
            if path == "/droplets?page=1&per_page=200":
                return _page("droplets", [{"id": 17, "name": "first", "tags": []}], total=2,
                             next_url="https://api.digitalocean.com/v2/droplets?page=2&per_page=200")
            if path == "/droplets?page=2&per_page=200":
                generation = "two"
                return _page("droplets", [{"id": 18, "name": "second", "tags": []}], total=2)
            raise AssertionError(path)

    with pytest.raises(inventory.MixedPartialApplyInventoryAttention):
        inventory.collect_provider_inventory_snapshot(
            object(), "digitalocean", workspace, fence=lambda: generation,
            process_quiescent=lambda: True, credential_repository=boundary.credentials,
            digitalocean_transport=Transport(), decrypt_secret=lambda value: value)
    assert calls == ["/droplets?page=1&per_page=200", "/droplets?page=2&per_page=200"]
