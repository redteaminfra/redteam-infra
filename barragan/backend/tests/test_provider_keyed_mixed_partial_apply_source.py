# Copyright (c) 2026, Oracle and/or its affiliates.
"""The partial-Apply classifier never turns uncertain provider writes into cleanup."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from app.services import provider_keyed_mixed_partial_apply_source as source


@pytest.fixture
def seal(monkeypatch):
    policy = {
        "linode": {
            "engagement_name": "opaque-test", "nodes": {
                'linode_instance.middle["middle_01"]': {
                    "label": "opaque-middle", "tag": "opaque-tag", "image": "linode/ubuntu24.04",
                    "region": "us-east", "node_type": "g6-standard-1"},
                'linode_instance.edge["edge_01"]': {
                    "label": "opaque-edge", "tag": "opaque-tag", "image": "linode/ubuntu24.04",
                    "region": "us-east", "node_type": "g6-standard-1"},
            },
        },
        "digitalocean": {
            "ssh_key_name": "opaque-do-key", "admin_public_key": "ssh-ed25519 opaque",
            "nodes": {
                'digitalocean_droplet.middle["middle_02"]': {
                    "name": "opaque-do-middle", "firewall_selector_tag": "opaque-selector",
                    "image": "ubuntu-24-04-x64", "region": "nyc1", "size": "s-1vcpu-1gb"},
            },
            "firewall": {"name": "opaque-do-firewall", "selector_tag": "opaque-selector"},
        },
    }
    monkeypatch.setattr(source, "validate_mixed_initial_apply_seal", lambda parent: {
        "orderedProviders": ["linode", "digitalocean"], "reviewedPolicy": policy,
    })
    return object()


def _state(provider, resources, serial=1):
    return json.dumps({
        "version": 4, "terraform_version": "1.15.5", "lineage": str(uuid4()),
        "serial": serial, "resources": resources,
    }).encode()


def _resource(kind, name, attributes, key=None):
    instance = {"attributes": attributes}
    if key is not None:
        instance["index_key"] = key
    return {"mode": "managed", "type": kind, "name": name,
            "instances": [instance]}


def _linode_middle():
    return _resource("linode_instance", "middle", {
        "id": 101, "label": "opaque-middle", "tags": ["opaque-tag"],
        "image": "linode/ubuntu24.04", "region": "us-east", "type": "g6-standard-1",
    }, "middle_01")


def _obs(outcome="failed", state=None, inventory=(), *, intent=True,
         phase="apply_started", complete=True, quiescent=True,
         selector=None, attached=None, linode_attached=(), selector_count=None):
    if selector_count is None and attached is not None:
        selector_count = len(attached)
    return source.ApplyObservation(outcome, intent, quiescent, phase, state,
                                   complete, tuple(inventory), selector, attached,
                                   linode_attached, selector_count)


def _row(id=101, name="opaque-middle", tags=None, kind="node"):
    return {"id": id, "name": name, "tags": ["opaque-tag"] if tags is None else tags,
            "kind": kind}


def test_unstarted_requires_no_command_or_visible_reviewed_identity(seal):
    empty = _obs("not_started", None, intent=False, phase=None)
    assert source.classify_sealed_provider_apply(seal, "linode", empty).kind == "unstarted"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs("not_started", None, [_row()], intent=False, phase=None)).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs("unknown", None, intent=True)).kind == "uncertain"


def test_partial_requires_durable_failure_exact_state_and_provider_id(seal):
    state = _state("linode", [_linode_middle()])
    result = source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=[_row()]))
    assert result.kind == "partial"
    assert result.resource_ids == (('linode_instance.middle["middle_01"]', "101"),)
    assert result.state_sha256
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs("unknown", state, [_row()])).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=[_row()], quiescent=False)).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=[_row()], complete=False)).kind == "uncertain"


def test_partial_rejects_extra_planned_identity_outside_state(seal):
    state = _state("linode", [_linode_middle()])
    result = source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=[_row(), _row(202, "opaque-edge")]))
    assert result.kind == "uncertain"


def test_linode_firewall_attachments_must_be_complete_and_state_backed(seal):
    state = _state("linode", [_linode_middle(), _resource("linode_firewall", "firewall", {
        "id": 301, "label": "fw-opaque-test-firewall", "tags": ["opaque-test"],
    })])
    rows = [_row(), _row(301, "fw-opaque-test-firewall", ["opaque-test"], "firewall")]
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=rows,
                             linode_attached=("101",))).kind == "partial"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=rows,
                             linode_attached=("999",))).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=rows,
                             linode_attached=None)).kind == "uncertain"


def test_linode_node_and_firewall_ids_use_separate_namespaces(seal):
    state = _state("linode", [_linode_middle(), _resource("linode_firewall", "firewall", {
        "id": 101, "label": "fw-opaque-test-firewall", "tags": ["opaque-test"],
    })])
    rows = [_row(), _row(101, "fw-opaque-test-firewall", ["opaque-test"], "firewall")]
    result = source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=rows, linode_attached=("101",)))
    assert result.kind == "partial"


def test_linode_full_waits_for_both_reviewed_firewall_attachments(seal):
    edge = _resource("linode_instance", "edge", {
        "id": 102, "label": "opaque-edge", "tags": ["opaque-tag"],
        "image": "linode/ubuntu24.04", "region": "us-east", "type": "g6-standard-1",
    }, "edge_01")
    state = _state("linode", [
        _linode_middle(), edge,
        _resource("linode_firewall", "firewall", {
            "id": 301, "label": "fw-opaque-test-firewall", "tags": ["opaque-test"]}),
        _resource("random_password", "root_password", {"id": "password"}),
        _resource("local_file", "ansible_inventory", {"id": "inventory"}, 0),
        _resource("local_file", "ssh_stanza", {"id": "ssh"}, 0),
    ])
    rows = [_row(), _row(102, "opaque-edge"),
            _row(301, "fw-opaque-test-firewall", ["opaque-test"], "firewall")]
    missing = _obs("succeeded", state, rows, phase="applied", linode_attached=("101",))
    assert source.classify_sealed_provider_apply(seal, "linode", missing).kind == "uncertain"
    settled = _obs("succeeded", state, rows, phase="applied", linode_attached=("101", "102"))
    assert source.classify_sealed_provider_apply(seal, "linode", settled).kind == "full"
    result = source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=state, inventory=[_row(202, "opaque-middle")]))
    assert result.kind == "uncertain"


def test_partial_rejects_unknown_address_and_state_identity_drift(seal):
    wrong = _resource("linode_instance", "other", {"id": 101}, "other")
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=_state("linode", [wrong]), inventory=[_row()])).kind == "uncertain"
    middle = _linode_middle()
    middle["instances"][0]["attributes"]["region"] = "us-west"
    assert source.classify_sealed_provider_apply(
        seal, "linode", _obs(state=_state("linode", [middle]), inventory=[_row()])).kind == "uncertain"


def test_do_partial_checks_exact_selector_and_duplicate_inventory(seal):
    state = _state("digitalocean", [_resource("digitalocean_droplet", "middle", {
        "id": "17", "name": "opaque-do-middle", "tags": ["opaque-selector"],
        "image": "ubuntu-24-04-x64", "region": "nyc1", "size": "s-1vcpu-1gb",
    }, "middle_02")])
    row = _row("17", "opaque-do-middle", ["opaque-selector"])
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs(state=state, inventory=[row],
                                   selector=True, attached=("17",))).kind == "partial"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs(state=state, inventory=[row, row],
                                   selector=True, attached=("17",))).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs(state=state, inventory=[row, _row("18", "other", ["opaque-selector"])],
                                   selector=True, attached=("17", "18"))).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs(state=state, inventory=[row])).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs(state=state, inventory=[row], selector=True,
                                   attached=("17",), selector_count=2)).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs("not_started", None, intent=False, phase=None,
                                   selector=True, attached=())).kind == "uncertain"


def test_do_node_firewall_and_key_ids_use_separate_namespaces(seal):
    state = _state("digitalocean", [
        _resource("digitalocean_droplet", "middle", {
            "id": "17", "name": "opaque-do-middle", "tags": ["opaque-selector"],
            "image": "ubuntu-24-04-x64", "region": "nyc1", "size": "s-1vcpu-1gb",
        }, "middle_02"),
        _resource("digitalocean_firewall", "firewall", {
            "id": "17", "name": "opaque-do-firewall", "tags": ["opaque-selector"],
        }),
        _resource("digitalocean_ssh_key", "key", {
            "id": "17", "name": "opaque-do-key", "public_key": "ssh-ed25519 opaque",
        }),
    ])
    rows = [
        _row("17", "opaque-do-middle", ["opaque-selector"]),
        _row("17", "opaque-do-firewall", ["opaque-selector"], "firewall"),
        {"id": "17", "name": "opaque-do-key", "tags": [], "kind": "ssh_key",
         "public_key": "ssh-ed25519 opaque"},
    ]
    result = source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs(state=state, inventory=rows,
                                   selector=True, attached=("17",)))
    assert result.kind == "partial"


def test_unstarted_do_ignores_unrelated_account_ssh_key_names(seal):
    keys = [
        {"id": id, "name": name, "tags": [], "kind": "ssh_key",
         "public_key": f"ssh-ed25519 unrelated-{id}"}
        for id, name in ((31, "do-key"), (32, "DO-KEY"),
                         (33, "opaque-do-key"), (34, "other"))
    ]
    observed = _obs("not_started", None, keys, intent=False, phase=None,
                    selector=False, attached=())
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", observed).kind == "unstarted"


def test_unbacked_do_key_with_reviewed_public_material_is_uncertain(seal):
    key = {"id": 31, "name": "renamed", "tags": [], "kind": "ssh_key",
           "public_key": "ssh-ed25519 opaque"}
    observed = _obs("not_started", None, [key], intent=False, phase=None,
                    selector=False, attached=())
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", observed).kind == "uncertain"


def test_full_requires_all_reviewed_addresses_success_and_applied_phase(seal):
    state = _state("digitalocean", [
        _resource("digitalocean_droplet", "middle", {
            "id": "17", "name": "opaque-do-middle", "tags": ["opaque-selector"],
            "image": "ubuntu-24-04-x64", "region": "nyc1", "size": "s-1vcpu-1gb",
        }, "middle_02"),
        _resource("digitalocean_firewall", "firewall", {
            "id": "22", "name": "opaque-do-firewall", "tags": ["opaque-selector"],
        }),
        _resource("digitalocean_ssh_key", "key", {"id": "23", "name": "opaque-do-key",
                                                  "public_key": "ssh-ed25519 opaque"}),
        _resource("local_file", "ansible_inventory", {"id": "24"}, 0),
        _resource("local_file", "ssh_stanza", {"id": "25"}, 0),
    ])
    rows = [_row("17", "opaque-do-middle", ["opaque-selector"]),
            _row("22", "opaque-do-firewall", ["opaque-selector"], "firewall"),
            {"id": "23", "name": "opaque-do-key", "tags": [], "kind": "ssh_key",
             "public_key": "ssh-ed25519 opaque"}]
    full = _obs("succeeded", state, rows, phase="applied", selector=True, attached=("17",))
    assert source.classify_sealed_provider_apply(seal, "digitalocean", full).kind == "full"
    wrong_key = [*rows[:-1], {**rows[-1], "public_key": "ssh-ed25519 unrelated"}]
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs("succeeded", state, wrong_key, phase="applied",
                                   selector=True, attached=("17",))).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs("succeeded", state, rows[:-1], phase="applied",
                                   selector=True, attached=("17",))).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs("failed", state, rows, selector=True,
                                   attached=("17",))).kind == "uncertain"
    assert source.classify_sealed_provider_apply(
        seal, "digitalocean", _obs("succeeded", state, rows, selector=True,
                                   attached=("17",))).kind == "uncertain"


def test_invalid_seal_is_rejected_before_classification(monkeypatch):
    def fail(_):
        raise ValueError("seal changed")
    monkeypatch.setattr(source, "validate_mixed_initial_apply_seal", fail)
    with pytest.raises(ValueError, match="seal changed"):
        source.classify_sealed_provider_apply(object(), "linode", _obs())
