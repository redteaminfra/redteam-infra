# Copyright (c) 2026, Oracle and/or its affiliates.
"""The stored edge artifact must survive full firewall and SSH reinterpretation."""

import json
import pytest

from app.services.provider_keyed_append_host_collection import verify_append_edge_host_collection
from app.services.provider_keyed_host_surface_interpreter import _key_digest
from provider_keyed_append_receipts import strict_edge_raw_fixture
from test_provider_keyed_host_surface_interpreter import _key


def test_real_raw_interpreter_fixture_is_accepted(monkeypatch):
    raw = strict_edge_raw_fixture(monkeypatch,
        manifest_sha="a" * 64, chain_id="chain", address="address",
        provider_id="123", region="region", public_ip="198.51.100.3",
        hostname="host", middle_ip="192.0.2.7",
        admin_public_key=_key(1), transport_public_key=_key(2))
    result = verify_append_edge_host_collection(
        raw, manifest_sha256="a" * 64, chain_id="chain",
        terraform_address="address", provider_instance_id="123",
        public_ipv4="198.51.100.3", region="region", hostname="host",
        predecessor_ipv4="192.0.2.7",
        expected_policy={"sketch_firewall_v2_enabled": True,
                         "sketch_firewall_v2_ssh_sources": ["192.0.2.7/32"],
                         "sketch_firewall_v2_rules": []},
        admin_key_sha256=_key_digest(_key(1) + "\n"),
        transport_key_sha256=_key_digest(_key(2) + "\n"),
    )
    assert result.identity.provider_instance_id == "123"
    for field, value in (("region", "wrong-region"), ("hostname", "wrong-host")):
        changed = json.loads(raw)
        for segment in (changed, changed["firewall_before"],
                        changed["surface"], changed["firewall_after"]):
            segment["identity"][field] = value
        with pytest.raises(ValueError):
            verify_append_edge_host_collection(
                json.dumps(changed).encode(), manifest_sha256="a" * 64,
                chain_id="chain", terraform_address="address",
                provider_instance_id="123", public_ipv4="198.51.100.3",
                region="region", hostname="host", predecessor_ipv4="192.0.2.7",
                expected_policy={"sketch_firewall_v2_enabled": True,
                                 "sketch_firewall_v2_ssh_sources": ["192.0.2.7/32"],
                                 "sketch_firewall_v2_rules": []},
                admin_key_sha256=_key_digest(_key(1) + "\n"),
                transport_key_sha256=_key_digest(_key(2) + "\n"))
