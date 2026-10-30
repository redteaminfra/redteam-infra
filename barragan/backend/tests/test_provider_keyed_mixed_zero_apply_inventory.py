# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline provider GET visibility after a real persisted mixed fence."""

from dataclasses import replace
import hashlib

import pytest

from app.services import provider_keyed_mixed_zero_apply_inventory as inventory
from app.services.provider_keyed_mixed_zero_apply_cleanup import _proposal
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    audit_mixed_zero_apply_teardown_source,
)
from test_provider_keyed_mixed_zero_apply_teardown_source import case  # noqa: F401


def _linode_page(rows, *, page=1, pages=1, results=None):
    return {"data": rows, "page": page, "pages": pages,
            "results": len(rows) if results is None else results}


def _do_page(kind, rows, *, total=None, next_page=None):
    body = {kind: rows, "meta": {"total": len(rows) if total is None else total}}
    if next_page is not None:
        body["links"] = {"pages": {"next": next_page}}
    return body


class LinodeGET:
    def __init__(self):
        self.calls = []
        self.rows = {
            "/linode/instances?page=1&page_size=100": _linode_page([
                {"id": 100, "label": "inspector-opaque", "tags": ["barragan", "inspector"]}]),
            "/networking/firewalls?page=1&page_size=100": _linode_page([
                {"id": 200, "label": "inspector-firewall-opaque", "tags": ["barragan", "inspector"]}]),
        }

    def request(self, method, path, token):
        assert method == "GET" and token
        self.calls.append(path)
        return self.rows[path]


class DigitalOceanGET:
    def __init__(self):
        self.calls = []
        self.rows = {
            "/tags?page=1&per_page=200": _do_page("tags", []),
            "/droplets?page=1&per_page=200": _do_page("droplets", []),
            "/droplets?page=1&per_page=200&type=gpus": _do_page("droplets", []),
            "/firewalls?page=1&per_page=200": _do_page("firewalls", []),
        }

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token
        self.calls.append(path)
        return self.rows[path]


@pytest.fixture()
def fenced(case):
    case.rows[0] = replace(case.rows[0], name="inspector-opaque")
    case.rows[1] = replace(case.rows[1], name="inspector-firewall-opaque")
    source = audit_mixed_zero_apply_teardown_source(**case.args)
    case.jobs.save(_proposal(source, "operator"))
    lease = lambda _: (source.core_plan_id, "provider_keyed_teardown_fence")
    linode = LinodeGET()
    digitalocean = DigitalOceanGET()
    args = {**case.args, "lease_lookup": lease,
            "linode_transport": linode, "digitalocean_transport": digitalocean,
            "decrypt_secret": lambda secret: f"opaque-token-{len(secret)}"}
    return source, args, linode, digitalocean


def test_complete_get_only_inventory_allows_exact_inspector_in_both_orders(fenced):
    source, args, linode, digitalocean = fenced
    result = inventory.inspect_mixed_zero_apply_provider_inventory(**args)
    assert result.linode_instances_checked == 1
    assert result.linode_firewalls_checked == 1
    assert result.digitalocean_tags_checked == 0
    assert result.digitalocean_droplets_checked == 0
    assert result.digitalocean_firewalls_checked == 0
    assert len(result.observation_sha256) == 64
    assert source.engagement_id not in repr(result)
    assert linode.calls == ["/linode/instances?page=1&page_size=100",
                            "/networking/firewalls?page=1&page_size=100"]
    assert digitalocean.calls == ["/tags?page=1&per_page=200",
                                  "/droplets?page=1&per_page=200",
                                  "/droplets?page=1&per_page=200&type=gpus",
                                  "/firewalls?page=1&per_page=200"]


@pytest.mark.parametrize("endpoint,shared_id", [
    ("/networking/firewalls", 100),  # Inspector instance 100 is a different type.
    ("/linode/instances", 200),      # Inspector firewall 200 is a different type.
])
def test_unrelated_linode_type_may_reuse_inspector_numeric_id(fenced, endpoint, shared_id):
    _source, args, linode, _digitalocean = fenced
    path = f"{endpoint}?page=1&page_size=100"
    linode.rows[path]["data"].append(
        {"id": shared_id, "label": "unrelated", "tags": ["other"]})
    linode.rows[path]["results"] = 2
    proof = inventory.inspect_mixed_zero_apply_provider_inventory(**args)
    assert (proof.linode_firewalls_checked if endpoint == "/networking/firewalls"
            else proof.linode_instances_checked) == 2


def test_complete_pagination_and_provider_settling(fenced):
    _source, args, linode, digitalocean = fenced
    linode.rows["/linode/instances?page=1&page_size=100"] = _linode_page(
        [{"id": 100, "label": "inspector-opaque", "tags": ["inspector"]}],
        pages=2, results=2)
    linode.rows["/linode/instances?page=2&page_size=100"] = _linode_page(
        [{"id": 300, "label": "unrelated", "tags": []}],
        page=2, pages=2, results=2)
    digitalocean.rows["/droplets?page=1&per_page=200"] = _do_page(
        "droplets", [{"id": 1, "name": "unrelated", "tags": []}], total=2,
        next_page="https://api.digitalocean.com/v2/droplets?page=2&per_page=200")
    digitalocean.rows["/droplets?page=2&per_page=200"] = _do_page(
        "droplets", [{"id": 2, "name": "other", "tags": []}], total=2)
    result = inventory.inspect_mixed_zero_apply_provider_inventory(**args)
    assert result.linode_instances_checked == 2
    assert result.digitalocean_droplets_checked == 2
    assert "/linode/instances?page=2&page_size=100" in linode.calls
    assert "/droplets?page=2&per_page=200" in digitalocean.calls


def test_visible_identity_can_settle_only_on_a_fresh_explicit_read(fenced):
    _source, args, _linode, digitalocean = fenced
    path = "/droplets?page=1&per_page=200"
    digitalocean.rows[path] = _do_page("droplets", [
        {"id": 9, "name": "unrelated", "tags": ["s" + hashlib.sha256(
            args["engagement_id"].encode()).hexdigest()[:20]]}])
    with pytest.raises(inventory.MixedZeroApplyInventoryAttention):
        inventory.inspect_mixed_zero_apply_provider_inventory(**args)
    assert digitalocean.calls.count(path) == 1
    digitalocean.rows[path] = _do_page("droplets", [])
    assert inventory.inspect_mixed_zero_apply_provider_inventory(
        **args).digitalocean_droplets_checked == 0


@pytest.mark.parametrize("drift", ["source", "credential"])
def test_change_during_get_is_caught_by_final_fence(fenced, drift):
    source, args, linode, _digitalocean = fenced
    original = linode.request
    changed = [False]
    credentials = args["credential_repository"]

    def changing(method, path, token):
        value = original(method, path, token)
        if not changed[0]:
            changed[0] = True
            if drift == "source":
                parent = args["job_repository"].get(source.parent_job_id)
                args["job_repository"].save(replace(
                    parent, events=[*parent.events,
                                    replace(parent.events[-1], sequence=len(parent.events) + 1)]))
        return value

    linode.request = changing
    if drift == "credential":
        class ChangingCredential:
            def get(self, identifier):
                return None if changed[0] else credentials.get(identifier)

            def get_default(self, provider):
                return None if changed[0] else credentials.get_default(provider)

        args["credential_repository"] = ChangingCredential()
    with pytest.raises(inventory.MixedZeroApplyInventoryAttention):
        inventory.inspect_mixed_zero_apply_provider_inventory(**args)


@pytest.mark.parametrize("drift", ["linode-label", "linode-tag", "linode-firewall-label",
                                  "linode-inspector", "do-tag", "do-droplet",
                                  "do-firewall", "do-selector-firewall", "gpu-droplet",
                                  "linode-truncated", "do-truncated", "provider-exception",
                                  "source", "credential"])
def test_collision_or_uncertain_visibility_stops_without_write(fenced, drift):
    source, args, linode, digitalocean = fenced
    _, _, _, _, intents = inventory._records(
        source.core_job_id, source.engagement_id, source.core_plan_id,
        args["lease_lookup"], args["engagement_repository"],
        args["sketch_repository"], args["job_repository"],
        args["plan_repository"], args["credential_repository"],
        args["ssh_key_repository"], lease_operation="provider_keyed_teardown_fence")
    if drift == "linode-label":
        linode.rows["/linode/instances?page=1&page_size=100"]["data"].append(
            {"id": 301, "label": next(iter(intents["linode"].nodes.values())).label,
             "tags": []})
        linode.rows["/linode/instances?page=1&page_size=100"]["results"] = 2
    elif drift == "linode-tag":
        linode.rows["/networking/firewalls?page=1&page_size=100"]["data"].append(
            {"id": 301, "label": "other", "tags": ["opaque-fixture"]})
        linode.rows["/networking/firewalls?page=1&page_size=100"]["results"] = 2
    elif drift == "linode-firewall-label":
        linode.rows["/networking/firewalls?page=1&page_size=100"]["data"].append(
            {"id": 301, "label": f'fw-{intents["linode"].engagement_name}-firewall', "tags": []})
        linode.rows["/networking/firewalls?page=1&page_size=100"]["results"] = 2
    elif drift == "linode-inspector":
        linode.rows["/linode/instances?page=1&page_size=100"]["data"][0]["label"] = "changed"
    elif drift == "do-tag":
        digitalocean.rows["/tags?page=1&per_page=200"] = _do_page(
            "tags", [{"name": "s" + hashlib.sha256(
                source.engagement_id.encode()).hexdigest()[:20]}])
    elif drift in {"do-droplet", "gpu-droplet"}:
        path = ("/droplets?page=1&per_page=200&type=gpus" if drift == "gpu-droplet"
                else "/droplets?page=1&per_page=200")
        digitalocean.rows[path] = _do_page("droplets", [
            {"id": 10, "name": next(iter(intents["digitalocean"].nodes.values())).name,
             "tags": []}])
    elif drift == "do-firewall":
        digitalocean.rows["/firewalls?page=1&per_page=200"] = _do_page(
            "firewalls", [{"id": "fw", "name": "opaque-fixture-firewall", "tags": []}])
    elif drift == "do-selector-firewall":
        digitalocean.rows["/firewalls?page=1&per_page=200"] = _do_page(
            "firewalls", [{"id": "fw", "name": "unrelated",
                           "tags": [intents["digitalocean"].selector_tag]}])
    elif drift == "linode-truncated":
        linode.rows["/linode/instances?page=1&page_size=100"]["results"] = 2
    elif drift == "do-truncated":
        digitalocean.rows["/droplets?page=1&per_page=200"]["meta"]["total"] = 1
    elif drift == "provider-exception":
        class SensitiveProviderError(Exception):
            pass
        digitalocean.rows["/tags?page=1&per_page=200"] = SensitiveProviderError("secret body")
        original = digitalocean.request
        def failing(origin, method, path, token):
            value = digitalocean.rows[path]
            if isinstance(value, Exception):
                raise value
            return original(origin, method, path, token)
        digitalocean.request = failing
    elif drift == "source":
        case = args["job_repository"]
        parent = case.get(source.parent_job_id)
        case.save(replace(parent, events=[*parent.events,
                                          replace(parent.events[-1], sequence=len(parent.events) + 1)]))
    else:
        args["credential_repository"] = type("Changed", (), {"get": lambda *_: None,
                                                           "get_default": lambda *_: None})()
    with pytest.raises(inventory.MixedZeroApplyInventoryAttention) as exc:
        inventory.inspect_mixed_zero_apply_provider_inventory(**args)
    assert "secret body" not in str(exc.value)
