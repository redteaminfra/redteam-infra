# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure gate for a complete, freshly collected provider-keyed host set.

The caller owns command provenance. This interpreter binds the full private raw
collection to the reviewed projection; a legacy structured observation cannot
be upgraded into publication evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Sequence

from app.services.provider_keyed_chain_projection import ProjectedProviderKeyedChain
from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
from app.services.provider_keyed_host_policy_interpreter import interpret_digitalocean_host_policy
from app.services.provider_keyed_host_surface_interpreter import interpret_digitalocean_host_surface


class StrictHostProofError(ValueError):
    """Raw host set does not prove the reviewed four-host boundary."""


@dataclass(frozen=True)
class StrictHostSetProof:
    hostnames: tuple[str, ...]
    provider_instance_ids: tuple[str, ...]
    raw_evidence_sha256: str


def verify_strict_command_journal(events, expected_nodes: Sequence[dict],
                                  manifest_sha256: str, evidence_sha256: str) -> None:
    """Require a completed, ordered four-command route capture for every host."""
    try:
        if (len(events) < 3 or events[0].message != "strict host proof reserved"
                or events[0].data != {"manifestSha256": manifest_sha256}
                or events[1].message != "strict host proof started"
                or events[1].data != {"manifestSha256": manifest_sha256}
                or events[-1].message != "strict host proof completed"
                or events[-1].data != {"hostEvidenceSha256": evidence_sha256,
                                       "hostnames": sorted(row["hostname"] for row in expected_nodes)}):
            raise ValueError("proof journal boundary differs")
        remaining = events[2:-1]
        seen_invocations = set()
        for row in expected_nodes:
            fields = {"hostname": row["hostname"],
                      "terraformAddress": row["terraformAddress"],
                      "providerInstanceId": row["providerInstanceId"]}
            scratch, *remaining = remaining
            if (scratch.message != "strict host proof scratch intended"
                    or any(scratch.data.get(k) != v for k, v in fields.items())
                    or not isinstance(scratch.data.get("scratchPath"), str)):
                raise ValueError("scratch journal differs")
            for _ in range(4):
                intent, started, result, *remaining = remaining
                if ([event.message for event in (intent, started, result)] != [
                    "strict host proof command intended",
                    "strict host proof command started before GO",
                    "strict host proof command result fenced",
                ] or any(event.data.get(k) != v for event in
                         (intent, started, result) for k, v in fields.items())
                    or not isinstance(intent.data.get("invocationId"), str)
                    or not intent.data["invocationId"]
                    or intent.data["invocationId"] in seen_invocations
                    or started.data.get("invocationId") != intent.data["invocationId"]
                    or result.data.get("invocationId") != intent.data["invocationId"]
                    or intent.data.get("scratchPath") != scratch.data["scratchPath"]
                    or result.data.get("returnCode") != 0
                    or result.data.get("stdoutTruncated") is not False
                    or result.data.get("stderrTruncated") is not False
                    or result.data.get("stderrBytes") != 0):
                    raise ValueError("command journal differs")
                seen_invocations.add(intent.data["invocationId"])
            completed, *remaining = remaining
            if completed.message != "strict host proof capture completed" or completed.data != fields:
                raise ValueError("capture journal differs")
        if remaining:
            raise ValueError("extra host proof events")
    except (TypeError, ValueError, IndexError, KeyError, AttributeError):
        raise StrictHostProofError("strict host command journal is incomplete or differs") from None


def verify_strict_host_set(
    projected_chains: Sequence[ProjectedProviderKeyedChain],
    collections: Sequence[DigitalOceanRawHostCollection], *,
    admin_key_sha256: str, transport_key_sha256: str, manifest_sha256: str,
) -> StrictHostSetProof:
    """Interpret each exact middle/edge capture and digest all private raw bytes."""
    try:
        if (type(projected_chains) not in (list, tuple) or len(projected_chains) != 2
                or type(collections) not in (list, tuple)
                or any(type(item) is not ProjectedProviderKeyedChain for item in projected_chains)
                or any(type(item) is not DigitalOceanRawHostCollection for item in collections)):
            raise ValueError("host set shape differs")
        expected = {}
        for item in projected_chains:
            nodes = item.chain.nodes
            if (len(nodes) != item.chain.edge_count + 1 or not nodes
                    or nodes[0].get("role") != "middle"
                    or any(node.get("role") != "edge" for node in nodes[1:])
                    or set(item.host_policies) != {node.get("hostname") for node in nodes}):
                raise ValueError("projected host set differs")
            for node in nodes:
                name = node["hostname"]
                if name in expected:
                    raise ValueError("host repeats")
                predecessor = item.proxy_egress_ip if node["role"] == "middle" else nodes[0]["publicIp"]
                expected[name] = (node, item.host_policies[name], predecessor)
        if len(collections) != len(expected):
            raise ValueError("host capture coverage differs")
        observed = {}
        for collection in collections:
            identity = collection.identity
            name = identity.hostname
            if name not in expected or name in observed:
                raise ValueError("host capture identity differs")
            node, policy, predecessor = expected[name]
            if (identity.manifest_sha256 != manifest_sha256
                    or identity.chain_id != node["chainId"]
                    or identity.terraform_address != node["terraformAddress"]
                    or identity.provider_instance_id != node["providerInstanceId"]
                    or identity.public_ipv4 != node["publicIp"]
                    or identity.region != node["region"]):
                raise ValueError("host capture differs from applied node")
            firewall = interpret_digitalocean_host_policy(
                collection, expected_identity=identity,
                expected_predecessor_ipv4=predecessor, expected_policy=policy,
            )
            surface = interpret_digitalocean_host_surface(
                collection, expected_identity=identity,
                expected_predecessor_ipv4=predecessor, expected_role=node["role"],
                expected_admin_key_sha256=admin_key_sha256,
                expected_transport_key_sha256=transport_key_sha256,
                expected_policy=policy,
            )
            # The surface interpreter deliberately reports
            # publication_eligible=False: it proves SSH only. This combined
            # gate is the publication authority after independent firewall,
            # command-journal, manifest, and SQL claim checks.
            if (firewall.identity != identity or surface.identity != identity
                    or surface.complete_ssh_policy is not True):
                raise ValueError("complete raw-derived SSH proof is absent")
            observed[name] = collection
        if len({collection.identity.invocation_id for collection in collections}) != len(collections):
            raise ValueError("host probe invocation repeats")
        names = tuple(sorted(expected))
        raw = [asdict(observed[name]) for name in names]
        digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return StrictHostSetProof(names,
                                  tuple(expected[name][0]["providerInstanceId"] for name in names), digest)
    except Exception:
        raise StrictHostProofError("reviewed raw host proof is incomplete or differs") from None
