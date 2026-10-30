# Copyright (c) 2026, Oracle and/or its affiliates.
"""Structured host evidence is checked without contacting Sketch hosts."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_host_proof import (
    HostObservation, ListenerEvidence, ProviderKeyedHostProofError, SshAccountEvidence,
    UfwRule, UfwSnapshot, verify_projected_host_evidence,
)
from test_provider_keyed_chain_projection import _fixture


ADMIN = "a" * 64
TRANSPORT = "b" * 64


def _observations():
    reviewed, attachment, proof, chains = _fixture()
    projected = project_digitalocean_initial_chains(reviewed, attachment, proof, chains)
    observations = []
    for item in projected:
        for row in item.chain.nodes:
            name = row["hostname"]
            policy = item.host_policies[name]
            rules = (UfwRule("allow", "in", "tcp", 22,
                             policy["sketch_firewall_v2_ssh_sources"][0]),)
            ufw = UfwSnapshot(True, "deny", "deny", "allow", rules, True,
                              True, "deny", "deny", (), True)
            ssh = (
                SshAccountEvidence("user", frozenset({ADMIN}), False, "yes", "no", True),
                SshAccountEvidence("sketchssh", frozenset({TRANSPORT}), False,
                                   "local" if row["role"] == "middle" else "yes",
                                   "no" if row["role"] == "middle" else "yes", True),
            )
            observations.append(HostObservation(
                name, row["terraformAddress"], row["providerInstanceId"], row["publicIp"],
                ufw, ufw, ssh, (ListenerEvidence("tcp", "0.0.0.0", 22, "sshd"),), True,
            ))
    return projected, observations


def _verify(projected, observations):
    return verify_projected_host_evidence(
        projected, observations, admin_key_sha256=ADMIN, transport_key_sha256=TRANSPORT,
    )


def test_exact_two_chain_host_evidence_validates_without_claiming_live_collection():
    projected, observations = _observations()
    validation = _verify(projected, observations)
    assert set(validation.hostnames) == {row["hostname"] for item in projected for row in item.chain.nodes}
    assert set(validation.provider_instance_ids) == {
        row["providerInstanceId"] for item in projected for row in item.chain.nodes
    }
    assert [item.chain.status for item in projected] == ["pending", "pending"]


@pytest.mark.parametrize("drift", [
    "broad_ssh", "active_persisted_mismatch", "wrong_admin_key",
    "wrong_transport_key", "wrong_forwarding", "missing_host", "missing_ssh_listener",
    "default_allow", "unknown_ufw_rule", "extra_deny", "incomplete_rules", "wrong_host_id",
    "ipv6_not_enforced", "ipv6_broad_allow", "ipv6_incomplete",
])
def test_rejects_incomplete_or_widened_host_evidence(drift):
    projected, observations = _observations()
    first = observations[0]
    if drift == "broad_ssh":
        broad = UfwRule("allow", "in", "tcp", 22, "0.0.0.0/0")
        widened = replace(first.ufw_active, rules=(*first.ufw_active.rules, broad))
        observations[0] = replace(first, ufw_active=widened, ufw_persisted=widened)
    elif drift == "active_persisted_mismatch":
        observations[0] = replace(first, ufw_persisted=replace(first.ufw_persisted, rules=()))
    elif drift == "wrong_admin_key":
        accounts = list(first.ssh_accounts)
        accounts[0] = replace(accounts[0], authorized_key_sha256=frozenset({"c" * 64}))
        observations[0] = replace(first, ssh_accounts=tuple(accounts))
    elif drift == "wrong_transport_key":
        accounts = list(first.ssh_accounts)
        accounts[1] = replace(accounts[1], authorized_key_sha256=frozenset({"c" * 64}))
        observations[0] = replace(first, ssh_accounts=tuple(accounts))
    elif drift == "wrong_forwarding":
        accounts = list(first.ssh_accounts)
        accounts[1] = replace(accounts[1], allow_tcp_forwarding="yes")
        observations[0] = replace(first, ssh_accounts=tuple(accounts))
    elif drift == "missing_host":
        observations.pop()
    elif drift == "missing_ssh_listener":
        observations[0] = replace(first, listeners=())
    elif drift == "default_allow":
        widened = replace(first.ufw_active, default_incoming="allow")
        observations[0] = replace(first, ufw_active=widened, ufw_persisted=widened)
    elif drift == "unknown_ufw_rule":
        widened = replace(first.ufw_active, rules=(*first.ufw_active.rules,
            UfwRule("allow", "in", "tcp", 443, "0.0.0.0/0")))
        observations[0] = replace(first, ufw_active=widened, ufw_persisted=widened)
    elif drift == "extra_deny":
        unexpected = replace(first.ufw_active, rules=(*first.ufw_active.rules,
            UfwRule("deny", "in", "tcp", 22, "198.51.100.0/24")))
        observations[0] = replace(first, ufw_active=unexpected, ufw_persisted=unexpected)
    elif drift == "incomplete_rules":
        incomplete = replace(first.ufw_active, complete=False)
        observations[0] = replace(first, ufw_active=incomplete, ufw_persisted=incomplete)
    elif drift == "ipv6_not_enforced":
        incomplete = replace(first.ufw_active, ipv6_enabled=False)
        observations[0] = replace(first, ufw_active=incomplete, ufw_persisted=incomplete)
    elif drift == "ipv6_broad_allow":
        broad = replace(first.ufw_active, ipv6_rules=(
            UfwRule("allow", "in", "tcp", 22, "::/0"),))
        observations[0] = replace(first, ufw_active=broad, ufw_persisted=broad)
    elif drift == "ipv6_incomplete":
        incomplete = replace(first.ufw_active, ipv6_complete=False)
        observations[0] = replace(first, ufw_active=incomplete, ufw_persisted=incomplete)
    else:
        observations[0] = replace(first, provider_instance_id="wrong-id")
    with pytest.raises(ProviderKeyedHostProofError, match="evidence is incomplete or differs"):
        _verify(projected, observations)


def test_unrelated_authorized_keys_remain_permitted_by_existing_bootstrap_contract():
    projected, observations = _observations()
    first = observations[0]
    accounts = list(first.ssh_accounts)
    accounts[1] = replace(accounts[1], authorized_key_sha256=frozenset({TRANSPORT, "c" * 64}))
    observations[0] = replace(first, ssh_accounts=tuple(accounts))
    assert _verify(projected, observations).hostnames


def test_unselected_listener_is_recorded_but_host_firewall_deny_remains_decisive():
    projected, observations = _observations()
    first = observations[0]
    observations[0] = replace(first, listeners=(*first.listeners,
        ListenerEvidence("tcp", "0.0.0.0", 80, "nginx")))
    assert _verify(projected, observations).hostnames


def test_ipv6_sshd_listener_is_accepted_only_with_verified_ipv6_default_deny():
    projected, observations = _observations()
    first = observations[0]
    observations[0] = replace(first, listeners=(*first.listeners,
        ListenerEvidence("tcp", "::", 22, "sshd")))
    assert _verify(projected, observations).hostnames
    unprotected = replace(first.ufw_active, ipv6_default_incoming="allow")
    observations[0] = replace(observations[0], ufw_active=unprotected, ufw_persisted=unprotected)
    with pytest.raises(ProviderKeyedHostProofError):
        _verify(projected, observations)


def test_ipv6_only_sshd_does_not_prove_ipv4_management_route():
    projected, observations = _observations()
    first = observations[0]
    observations[0] = replace(first, listeners=(ListenerEvidence("tcp", "::", 22, "sshd"),))
    with pytest.raises(ProviderKeyedHostProofError):
        _verify(projected, observations)
