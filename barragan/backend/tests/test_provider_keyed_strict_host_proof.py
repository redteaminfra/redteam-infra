# Copyright (c) 2026, Oracle and/or its affiliates.
"""Host-set coverage and fail-closed raw interpretation boundary."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawFirewallEvidence,
    DigitalOceanRawHostCollection, DigitalOceanRawHostSurfaceEvidence,
)
from app.services.provider_keyed_strict_host_proof import StrictHostProofError, verify_strict_host_set
from test_provider_keyed_chain_projection import _fixture


def _case(monkeypatch):
    reviewed, attachment, attachment_proof, chains = _fixture()
    projections = project_digitalocean_initial_chains(
        reviewed, attachment, attachment_proof, chains)
    captures = []
    for item in projections:
        for node in item.chain.nodes:
            name = node["hostname"]
            identity = DigitalOceanHostIdentityEvidence(
                "a" * 64, node["chainId"], node["terraformAddress"],
                node["providerInstanceId"], node["region"], node["publicIp"],
                name, "00000000-0000-0000-0000-000000000001", name + "-alias",
                name + "-identity", "b" * 64, "c" * 64,
            )
            before = DigitalOceanRawFirewallEvidence(identity, name + "-before",
                                                     identity.boot_id, 1, 2, (), ())
            surface = DigitalOceanRawHostSurfaceEvidence(identity, name + "-surface",
                identity.boot_id, 3, 4, "192.0.2.7", ("192.0.2.7", 50000, node["publicIp"], 22),
                (), (), "")
            after = DigitalOceanRawFirewallEvidence(identity, name + "-after",
                                                    identity.boot_id, 5, 6, (), ())
            captures.append(DigitalOceanRawHostCollection(identity, before, surface, after))
    monkeypatch.setattr(
        "app.services.provider_keyed_strict_host_proof.interpret_digitalocean_host_policy",
        lambda collection, **_kwargs: SimpleNamespace(identity=collection.identity),
    )
    return projections, captures


def test_complete_four_host_set_is_bound_and_digested(monkeypatch):
    projections, captures = _case(monkeypatch)
    monkeypatch.setattr(
        "app.services.provider_keyed_strict_host_proof.interpret_digitalocean_host_surface",
        lambda collection, **_kwargs: SimpleNamespace(identity=collection.identity,
                                                       complete_ssh_policy=True,
                                                       publication_eligible=False),
    )
    proof = verify_strict_host_set(projections, captures,
        admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
        manifest_sha256="a" * 64)
    assert len(proof.hostnames) == len(captures) == sum(
        item.chain.edge_count + 1 for item in projections)
    assert proof.hostnames == tuple(sorted(c.identity.hostname for c in captures))
    assert len(proof.raw_evidence_sha256) == 64
    assert verify_strict_host_set(projections, list(reversed(captures)),
        admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
        manifest_sha256="a" * 64) == proof


def test_second_host_failure_or_old_capture_cannot_publish(monkeypatch):
    projections, captures = _case(monkeypatch)
    second = captures[1].identity.hostname
    monkeypatch.setattr(
        "app.services.provider_keyed_strict_host_proof.interpret_digitalocean_host_surface",
        lambda collection, **_kwargs: SimpleNamespace(identity=collection.identity,
            complete_ssh_policy=collection.identity.hostname != second),
    )
    with pytest.raises(StrictHostProofError):
        verify_strict_host_set(projections, captures,
            admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
            manifest_sha256="a" * 64)
    with pytest.raises(StrictHostProofError):
        verify_strict_host_set(projections, captures[:-1],
            admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
            manifest_sha256="a" * 64)
    monkeypatch.setattr(
        "app.services.provider_keyed_strict_host_proof.interpret_digitalocean_host_surface",
        lambda collection, **_kwargs: SimpleNamespace(identity=collection.identity,
                                                       complete_ssh_policy=False),
    )
    with pytest.raises(StrictHostProofError):
        verify_strict_host_set(projections, captures,
            admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
            manifest_sha256="a" * 64)


def test_manifest_and_identity_drift_rejected(monkeypatch):
    projections, captures = _case(monkeypatch)
    monkeypatch.setattr(
        "app.services.provider_keyed_strict_host_proof.interpret_digitalocean_host_surface",
        lambda collection, **_kwargs: SimpleNamespace(identity=collection.identity,
                                                       complete_ssh_policy=True),
    )
    with pytest.raises(StrictHostProofError):
        verify_strict_host_set(projections, captures,
            admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
            manifest_sha256="b" * 64)
    changed = [replace(captures[0], identity=replace(captures[0].identity,
               provider_instance_id="999")), *captures[1:]]
    with pytest.raises(StrictHostProofError):
        verify_strict_host_set(projections, changed,
            admin_key_sha256="d" * 64, transport_key_sha256="e" * 64,
            manifest_sha256="a" * 64)
