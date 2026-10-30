# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import re

import pytest

from app.services.terraform_plan_gate import (
    FirewallIngressDelta,
    FirewallIngressPort,
    PlannedResourceChange,
    PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES,
    TerraformPlanGateError,
    classify_saved_plan_actions,
    require_edge_transition_changes,
    require_exact_resource_changes,
    require_only_in_place_resource_update,
    require_provider_firewall_ingress_update,
)


def test_provider_firewall_computed_attribute_boundary_is_exact_and_immutable():
    assert PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES == {
        "linode": frozenset({"created", "fingerprint", "status", "updated", "version"}),
        "digitalocean": frozenset({"created_at", "pending_changes", "status"}),
    }
    assert all(isinstance(attributes, frozenset) for attributes in PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES.values())


@pytest.mark.parametrize(
    ("actions", "classification"),
    [
        (["no-op"], "no-op"),
        (["create"], "create"),
        (["read"], "read"),
        (["update"], "update"),
        (["delete"], "delete"),
        (["forget"], "forget"),
        (["delete", "create"], "replace"),
        (["create", "delete"], "replace"),
    ],
)
def test_saved_plan_action_classifier_accepts_only_exact_supported_sequences(actions, classification):
    assert classify_saved_plan_actions(actions) == classification


@pytest.mark.parametrize(
    "actions",
    [[], ["create", "update"], ["create", "create"], ["read", "update"], ["forget", "create"], ["delete", "create", "delete"], [1]],
)
def test_saved_plan_action_classifier_rejects_malformed_or_ambiguous_sequences(actions):
    with pytest.raises(TerraformPlanGateError, match="unsupported resource action"):
        classify_saved_plan_actions(actions)


def _event(address: str, action: str) -> str:
    return '{"type":"planned_change","change":{"action":"' + action + '","resource":{"addr":"' + address + '"}}}'


def _linode_rule(protocol: str, port: int) -> dict:
    return {
        "action": "ACCEPT",
        "description": "",
        "ipv4": ["0.0.0.0/0"],
        "ipv6": None,
        "label": f"allow-{protocol.lower()}-{port}",
        "ports": str(port),
        "protocol": protocol.upper(),
    }


def _digitalocean_rule(protocol: str, port: int) -> dict:
    return {
        "port_range": str(port),
        "protocol": protocol.lower(),
        "source_addresses": ["0.0.0.0/0"],
        "source_droplet_ids": [],
        "source_kubernetes_ids": [],
        "source_load_balancer_uids": [],
        "source_tags": [],
    }


def _provider_firewall(provider: str) -> dict:
    if provider == "linode":
        return {
            "id": "3754360",
            "label": "opaque-firewall",
            "linodes": [101, 102],
            "devices": [
                {"entity_id": 101, "id": 501, "label": "middle", "type": "linode", "url": "/v4/linode/instances/101"},
                {"entity_id": 102, "id": 502, "label": "edge", "type": "linode", "url": "/v4/linode/instances/102"},
            ],
            "nodebalancers": [],
            "tags": ["barragan", "opaque"],
            "inbound_policy": "DROP",
            "outbound_policy": "ACCEPT",
            "inbound": [
                _linode_rule("tcp", 22),
                {
                    "action": "ACCEPT",
                    "ipv4": ["192.0.2.10/32", "192.0.2.11/32"],
                    "ipv6": [],
                    "label": "allow-opaque-host-tcp",
                    "ports": "",
                    "protocol": "TCP",
                },
                {
                    "action": "DROP",
                    "ipv4": [],
                    "ipv6": ["::/0"],
                    "label": "block-ipv6-tcp",
                    "ports": "",
                    "protocol": "TCP",
                },
            ],
            "outbound": [
                {
                    "action": "DROP",
                    "ipv4": [],
                    "ipv6": ["::/0"],
                    "label": "block-ipv6-tcp",
                    "ports": "",
                    "protocol": "TCP",
                }
            ],
        }
    return {
        "id": "2a524ebd-251e-46f9-b830-241e0f46edc8",
        "name": "opaque-firewall",
        "droplet_ids": [201, 202],
        "tags": ["barragan", "opaque"],
        "inbound_rule": [
            _digitalocean_rule("tcp", 22),
            {
                **_digitalocean_rule("tcp", 1),
                "port_range": "1-65535",
                "source_addresses": ["192.0.2.20/32", "192.0.2.21/32"],
            },
            {
                **_digitalocean_rule("udp", 1),
                "port_range": "1-65535",
                "source_addresses": ["::/0"],
            },
        ],
        "outbound_rule": [
            {
                "destination_addresses": ["0.0.0.0/0"],
                "destination_droplet_ids": [],
                "destination_kubernetes_ids": [],
                "destination_load_balancer_uids": [],
                "destination_tags": [],
                "port_range": "1-65535",
                "protocol": "tcp",
            }
        ],
    }


def _firewall_plan(
    provider: str,
    before: dict,
    after: dict,
    *,
    after_unknown: dict | None = None,
    extras: list[dict] | None = None,
) -> str:
    address = "linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall"
    return json.dumps(
        {
            "resource_changes": [
                *(extras or []),
                {
                    "address": address,
                    "type": address.split(".")[0],
                    "name": "firewall",
                    "change": {
                        "actions": ["update"],
                        "before": before,
                        "after": after,
                        "after_unknown": after_unknown or {},
                    },
                },
            ]
        }
    )


def test_accepts_only_the_exact_approved_edge_retirement():
    changes = require_exact_resource_changes(
        _event("linode_instance.edge[1]", "delete"),
        expected={("linode_instance.edge[1]", "delete")},
    )

    assert [(change.address, change.action) for change in changes] == [("linode_instance.edge[1]", "delete")]


def test_rejects_middle_or_sibling_changes_even_when_one_edge_is_deleted():
    plan = "\n".join((_event("linode_instance.edge[1]", "delete"), _event("linode_instance.middle[0]", "update")))

    with pytest.raises(TerraformPlanGateError, match="unapproved"):
        require_exact_resource_changes(plan, expected={("linode_instance.edge[1]", "delete")})


def test_rejects_non_json_plan_output():
    with pytest.raises(TerraformPlanGateError, match="machine-readable"):
        require_exact_resource_changes("Plan: 0 to add, 0 to change, 1 to destroy.", expected=set())


def test_firewall_update_gate_accepts_only_the_expected_in_place_update_or_no_changes():
    changes = require_only_in_place_resource_update(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "linode_firewall.firewall",
                        "change": {"actions": ["update"]},
                    }
                ]
            }
        ),
        expected_address="linode_firewall.firewall",
    )

    assert [(change.address, change.action) for change in changes] == [
        ("linode_firewall.firewall", "update")
    ]
    assert require_only_in_place_resource_update(
        '{"resource_changes": []}', expected_address="linode_firewall.firewall"
    ) == []


def test_firewall_update_gate_reads_saved_plan_json_and_normalizes_replacement():
    saved_plan = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "linode_firewall.firewall",
                    "change": {"actions": ["update"]},
                },
                {
                    "address": "linode_instance.middle[0]",
                    "change": {"actions": ["delete", "create"]},
                },
            ]
        }
    )

    with pytest.raises(TerraformPlanGateError, match="replace"):
        require_only_in_place_resource_update(
            saved_plan,
            expected_address="linode_firewall.firewall",
        )


@pytest.mark.parametrize(
    ("address", "action"),
    (
        ("linode_instance.middle[0]", "replace"),
        ("digitalocean_ssh_key.key[0]", "create"),
        ("digitalocean_firewall.firewall", "delete"),
        ("data.digitalocean_ssh_keys.matching_key", "read"),
    ),
)
def test_firewall_update_gate_rejects_compute_key_and_non_update_changes(address, action):
    with pytest.raises(TerraformPlanGateError, match=re.escape(f"{action} {address}")):
        require_only_in_place_resource_update(
            json.dumps(
                {
                    "resource_changes": [
                        {
                            "address": address,
                            "change": {
                                "actions": ["delete", "create"]
                                if action == "replace"
                                else [action]
                            },
                        }
                    ]
                }
            ),
            expected_address="digitalocean_firewall.firewall",
        )


@pytest.mark.parametrize(
    ("provider", "protocol", "port", "ingress_attribute", "rule_factory"),
    (
        ("linode", "udp", 3478, "inbound", _linode_rule),
        ("digitalocean", "tcp", 8443, "inbound_rule", _digitalocean_rule),
    ),
)
def test_semantic_firewall_gate_accepts_exact_provider_ingress_addition(
    provider, protocol, port, ingress_attribute, rule_factory
):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))
    after[ingress_attribute].append(rule_factory(protocol, port))

    changes = require_provider_firewall_ingress_update(
        _firewall_plan(
            provider,
            before,
            after,
            extras=[
                {
                    "address": "local_file.ansible_inventory[0]",
                    "change": {"actions": ["no-op"], "before": {}, "after": {}},
                }
            ],
        ),
        provider=provider,
        expected_delta=FirewallIngressDelta(
            added=frozenset({FirewallIngressPort(protocol, port)})
        ),
    )

    assert changes == [
        PlannedResourceChange("linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall", "update")
    ]


@pytest.mark.parametrize(
    ("provider", "protocol", "port", "ingress_attribute", "rule_factory"),
    (
        ("linode", "tcp", 18085, "inbound", _linode_rule),
        ("digitalocean", "udp", 3478, "inbound_rule", _digitalocean_rule),
    ),
)
def test_semantic_firewall_gate_accepts_exact_provider_ingress_removal(
    provider, protocol, port, ingress_attribute, rule_factory
):
    before = _provider_firewall(provider)
    before[ingress_attribute].append(rule_factory(protocol, port))
    after = json.loads(json.dumps(before))
    after[ingress_attribute].remove(rule_factory(protocol, port))

    require_provider_firewall_ingress_update(
        _firewall_plan(provider, before, after),
        provider=provider,
        expected_delta=FirewallIngressDelta(
            removed=frozenset({FirewallIngressPort(protocol.upper(), port)})
        ),
    )


def test_semantic_firewall_gate_accepts_noop_only_for_empty_delta():
    assert require_provider_firewall_ingress_update(
        json.dumps({"resource_changes": []}),
        provider="linode",
        expected_delta=FirewallIngressDelta(),
    ) == []

    with pytest.raises(TerraformPlanGateError, match="omitted"):
        require_provider_firewall_ingress_update(
            json.dumps({"resource_changes": []}),
            provider="linode",
            expected_delta=FirewallIngressDelta(
                added=frozenset({FirewallIngressPort("tcp", 18085)})
            ),
        )


def test_semantic_firewall_gate_rejects_authorizing_ssh_rule_mutation():
    before = _provider_firewall("linode")
    after = json.loads(json.dumps(before))
    after["inbound"].remove(_linode_rule("tcp", 22))

    with pytest.raises(TerraformPlanGateError, match="cannot modify SSH"):
        require_provider_firewall_ingress_update(
            _firewall_plan("linode", before, after),
            provider="linode",
            expected_delta=FirewallIngressDelta(
                removed=frozenset({FirewallIngressPort("tcp", 22)})
            ),
        )


@pytest.mark.parametrize(
    ("provider", "computed_values"),
    (
        (
            "linode",
            {
                "created": "2026-02-02T21:35:30Z",
                "fingerprint": "provider-fingerprint",
                "status": "enabled",
                "updated": "2026-02-02T21:35:30Z",
                "version": 7,
            },
        ),
        (
            "digitalocean",
            {
                "created_at": "2026-02-02T21:35:30Z",
                "pending_changes": [{"droplet_id": 201, "status": "waiting"}],
                "status": "waiting",
            },
        ),
    ),
)
def test_semantic_firewall_gate_ignores_provider_computed_status_drift(
    provider, computed_values
):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))
    before.update(computed_values)
    after.update({attribute: None for attribute in computed_values})

    require_provider_firewall_ingress_update(
        _firewall_plan(
            provider,
            before,
            after,
            after_unknown={attribute: True for attribute in computed_values},
        ),
        provider=provider.upper(),
        expected_delta=FirewallIngressDelta(),
    )


@pytest.mark.parametrize(
    ("provider", "after_unknown"),
    (
        ("linode", {"inbound": [{"ports": True}]}),
        ("linode", {"linodes": True}),
        ("linode", {"devices": True}),
        ("linode", {"outbound_policy": True}),
        ("digitalocean", {"inbound_rule": True}),
        ("digitalocean", {"droplet_ids": True}),
        ("digitalocean", {"outbound_rule": [{"destination_addresses": True}]}),
        ("digitalocean", {"tags": True}),
    ),
)
def test_semantic_firewall_gate_rejects_unknown_protected_values(provider, after_unknown):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))

    with pytest.raises(TerraformPlanGateError, match="protected provider firewall values unknown"):
        require_provider_firewall_ingress_update(
            _firewall_plan(provider, before, after, after_unknown=after_unknown),
            provider=provider,
            expected_delta=FirewallIngressDelta(),
        )


def test_semantic_firewall_gate_rejects_known_linode_device_attachment_swap():
    before = _provider_firewall("linode")
    after = json.loads(json.dumps(before))
    after["devices"][-1]["entity_id"] += 9000

    with pytest.raises(TerraformPlanGateError, match="identity, attachments, policy, or metadata"):
        require_provider_firewall_ingress_update(
            _firewall_plan("linode", before, after),
            provider="linode",
            expected_delta=FirewallIngressDelta(),
        )


@pytest.mark.parametrize("provider", ("linode", "digitalocean"))
def test_semantic_firewall_gate_rejects_attachment_swap(provider):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))
    attachment = "linodes" if provider == "linode" else "droplet_ids"
    after[attachment][-1] += 9000

    with pytest.raises(TerraformPlanGateError, match="identity, attachments, policy, or metadata"):
        require_provider_firewall_ingress_update(
            _firewall_plan(provider, before, after),
            provider=provider,
            expected_delta=FirewallIngressDelta(),
        )


@pytest.mark.parametrize("provider", ("linode", "digitalocean"))
def test_semantic_firewall_gate_rejects_outbound_rule_deletion(provider):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))
    outbound = "outbound" if provider == "linode" else "outbound_rule"
    after[outbound].clear()

    with pytest.raises(TerraformPlanGateError, match="identity, attachments, policy, or metadata"):
        require_provider_firewall_ingress_update(
            _firewall_plan(provider, before, after),
            provider=provider,
            expected_delta=FirewallIngressDelta(),
        )


@pytest.mark.parametrize("provider", ("linode", "digitalocean"))
def test_semantic_firewall_gate_rejects_sibling_ingress_deletion_during_expected_add(provider):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    rule_factory = _linode_rule if provider == "linode" else _digitalocean_rule
    after[ingress].remove(rule_factory("tcp", 22))
    after[ingress].append(rule_factory("udp", 3478))

    with pytest.raises(TerraformPlanGateError, match="unapproved provider ingress"):
        require_provider_firewall_ingress_update(
            _firewall_plan(provider, before, after),
            provider=provider,
            expected_delta=FirewallIngressDelta(
                added=frozenset({FirewallIngressPort("udp", 3478)})
            ),
        )


@pytest.mark.parametrize("provider", ("linode", "digitalocean"))
def test_semantic_firewall_gate_rejects_metadata_and_policy_changes(provider):
    before = _provider_firewall(provider)
    after = json.loads(json.dumps(before))
    after["tags"] = ["foreign-owner"]
    if provider == "linode":
        after["outbound_policy"] = "DROP"

    with pytest.raises(TerraformPlanGateError, match="identity, attachments, policy, or metadata"):
        require_provider_firewall_ingress_update(
            _firewall_plan(provider, before, after),
            provider=provider,
            expected_delta=FirewallIngressDelta(),
        )


def test_semantic_firewall_gate_rejects_noncanonical_public_rule_shape():
    before = _provider_firewall("digitalocean")
    after = json.loads(json.dumps(before))
    unsafe = _digitalocean_rule("udp", 3478)
    unsafe["source_addresses"] = ["0.0.0.0/0", "::/0"]
    after["inbound_rule"].append(unsafe)

    with pytest.raises(TerraformPlanGateError, match="unapproved provider ingress"):
        require_provider_firewall_ingress_update(
            _firewall_plan("digitalocean", before, after),
            provider="digitalocean",
            expected_delta=FirewallIngressDelta(
                added=frozenset({FirewallIngressPort("udp", 3478)})
            ),
        )


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("description", "unexpected provider rule"),
        ("ipv6", []),
        ("ipv6", ["::/0"]),
        ("label", "unexpected-label"),
        ("action", "DROP"),
        ("protocol", "TCP"),
    ),
)
def test_semantic_firewall_gate_rejects_linode_rule_semantic_mismatch(field, unsafe_value):
    before = _provider_firewall("linode")
    after = json.loads(json.dumps(before))
    unsafe = _linode_rule("udp", 53)
    unsafe[field] = unsafe_value
    after["inbound"].append(unsafe)

    with pytest.raises(TerraformPlanGateError, match="unapproved provider ingress"):
        require_provider_firewall_ingress_update(
            _firewall_plan("linode", before, after),
            provider="linode",
            expected_delta=FirewallIngressDelta(
                added=frozenset({FirewallIngressPort("udp", 53)})
            ),
        )


def test_semantic_firewall_gate_rejects_linode_rule_unknown_extra_attribute():
    before = _provider_firewall("linode")
    after = json.loads(json.dumps(before))
    unsafe = _linode_rule("udp", 53)
    unsafe["unexpected"] = "value"
    after["inbound"].append(unsafe)

    with pytest.raises(TerraformPlanGateError, match="unapproved provider ingress"):
        require_provider_firewall_ingress_update(
            _firewall_plan("linode", before, after),
            provider="linode",
            expected_delta=FirewallIngressDelta(
                added=frozenset({FirewallIngressPort("udp", 53)})
            ),
        )


def test_semantic_firewall_gate_rejects_linode_rule_missing_canonical_description():
    before = _provider_firewall("linode")
    after = json.loads(json.dumps(before))
    unsafe = _linode_rule("udp", 53)
    unsafe.pop("description")
    after["inbound"].append(unsafe)

    with pytest.raises(TerraformPlanGateError, match="unapproved provider ingress"):
        require_provider_firewall_ingress_update(
            _firewall_plan("linode", before, after),
            provider="linode",
            expected_delta=FirewallIngressDelta(
                added=frozenset({FirewallIngressPort("udp", 53)})
            ),
        )


def test_semantic_firewall_gate_rejects_unrelated_resource_change():
    before = _provider_firewall("linode")
    after = json.loads(json.dumps(before))

    with pytest.raises(TerraformPlanGateError, match="unapproved resource changes"):
        require_provider_firewall_ingress_update(
            _firewall_plan(
                "linode",
                before,
                after,
                extras=[
                    {
                        "address": "linode_instance.middle[0]",
                        "change": {"actions": ["delete", "create"], "before": {}, "after": {}},
                    }
                ],
            ),
            provider="linode",
            expected_delta=FirewallIngressDelta(),
        )


def test_accepts_only_known_firewall_and_local_dependents_for_edge_transition():
    plan = "\n".join(
        (
            _event("linode_instance.edge[1]", "delete"),
            _event("linode_firewall.firewall", "update"),
            _event("local_file.ssh_stanza[0]", "update"),
            _event("local_file.ansible_inventory[0]", "update"),
        )
    )

    changes = require_edge_transition_changes(
        plan,
        provider="linode",
        edge_address="linode_instance.edge[1]",
        edge_action="delete",
    )

    assert len(changes) == 4


def test_rejects_retained_edge_mutation_during_edge_transition():
    plan = "\n".join((_event("digitalocean_droplet.edge[1]", "create"), _event("digitalocean_droplet.edge[0]", "update")))

    with pytest.raises(TerraformPlanGateError, match="unapproved"):
        require_edge_transition_changes(
            plan,
            provider="digitalocean",
            edge_address="digitalocean_droplet.edge[1]",
            edge_action="create",
        )
