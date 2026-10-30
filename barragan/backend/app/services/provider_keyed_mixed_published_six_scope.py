# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only teardown scope for a published mixed six-node generation.

The append publication source and host receipt are authenticated by their
existing recognizer. This module binds them to current chain rows, both exact
provider states, and a live binding snapshot. It reserves nothing and grants
no destroy or external-binding DELETE authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping

from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixHostProofReceipt, SixNodeHostSource, validate_six_host_receipt_child,
    validate_six_node_host_source,
)
from app.services.provider_keyed_mixed_published_six_source import same_published_chain
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation, _digest
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import StoredSketchChain


class MixedPublishedSixScopeAttention(ValueError):
    """The exact appended generation and live binding scope are not proved."""


@dataclass(frozen=True)
class PublishedMixedSixScope:
    source_sha256: str
    append_parent_journal_sha256: str
    bindings_sha256: str
    binding_count: int
    provider_scopes: tuple[dict, dict]


_BINDINGS = frozenset({"channels", "domains", "certificates", "sites"})
# Append disables generated local inventory/SSH files and deletes both from
# Terraform state. Require the complete post-append set, not the initial set.
_POST_APPEND_SHARED = {
    "linode": {"linode_firewall.firewall", "random_password.root_password"},
    "digitalocean": {"digitalocean_firewall.firewall", "digitalocean_ssh_key.key"},
}
_SHARED_KINDS = {
    "linode_firewall.firewall": "firewall",
    "random_password.root_password": "random_password",
    "digitalocean_firewall.firewall": "firewall",
    "digitalocean_ssh_key.key": "ssh_key",
}


def build_mixed_published_six_teardown_scope(
    source: SixNodeHostSource, *, append_parent: StoredJobRun,
    host_proof_child: StoredJobRun, host_receipt: SixHostProofReceipt,
    provider_children: Mapping[str, StoredJobRun],
    reviewed_policies: Mapping[str, dict],
    reviewed_chain_fingerprints: Mapping[str, str],
    observations: Mapping[str, ProviderHostObservation],
    chains: Mapping[str, StoredSketchChain],
    live_bindings: Mapping[str, tuple],
    host_receipt_validator: Callable = validate_six_host_receipt_child,
    current_generation=None, unpublished_cleanup: bool = False,
) -> PublishedMixedSixScope:
    """Bind six deployed hosts and complete provider states to one preview.

    The caller must reconstruct ``source`` from the saved append generation,
    validate both historical Apply journals with the strict append recognizers,
    obtain fresh provider observations under one engagement fence, and reread
    these same inputs at reservation and before every provider GO. This scope
    checks state/projection consistency; it does not itself authenticate the
    command grammar or contain binding deletion authority.
    """
    try:
        validate_six_node_host_source(source)
        order, chain_ids = source.provider_order, source.chain_ids
        expected_hashes = (source.state_sha256s if current_generation is None
                           else current_generation.state_sha256s)
        if (type(append_parent) is not StoredJobRun
                or append_parent.id != source.parent_id
                or append_parent.action != "provider_keyed_mixed_append"
                or (unpublished_cleanup and (append_parent.status != "running" or append_parent.finished_at is not None
                    or append_parent.input.get("phase") != "apply_sealed"
                    or host_proof_child.status != "failed" or host_proof_child.finished_at is None))
                or (not unpublished_cleanup and (append_parent.status != "succeeded" or append_parent.finished_at is None
                    or append_parent.input.get("phase") != "completed"))
                or append_parent.input.get("coreJobId") != source.core_job_id
                or append_parent.input.get("corePlanId") != source.core_plan_id
                or append_parent.target_id != source.engagement_id
                or tuple(append_parent.input.get("providerOrder", ())) != order
                or tuple(append_parent.input.get("chainOrder", ())) != chain_ids
                or not append_parent.events
                or (not unpublished_cleanup and (append_parent.events[-1].message
                   != "mixed append six-node generation published"
                or append_parent.events[-1].data != {
                    "source": json.loads(json.dumps(asdict(source))),
                    "sourceSha256": source.source_sha256,
                    "hostProofJournalSha256": job_event_digest(host_proof_child.events),
                    "providerProofJournalSha256": {
                        provider: source.provider_proof_digests[index]
                        for index, provider in enumerate(order)},
                    "chainIds": list(chain_ids),
                }))
                or set(provider_children) != set(order)
                or set(reviewed_policies) != set(order)
                or set(reviewed_chain_fingerprints) != set(chain_ids)
                or set(observations) != set(order)
                or set(chains) != set(chain_ids)
                or set(live_bindings) != _BINDINGS
                or any(type(rows) is not tuple or any(
                    type(row) is not tuple or len(row) != 3
                    or any(type(value) is not str or not value for value in row)
                    for row in rows) for rows in live_bindings.values())
                or len(set(source.workspace_paths)) != 2):
            raise ValueError("mixed six-node publication or bindings differ")
        if not unpublished_cleanup and host_receipt_validator(
                append_parent, host_proof_child, host_receipt,
                source=source) != host_receipt:
            raise ValueError("mixed six-node host receipt differs")

        for index, chain_id in enumerate(chain_ids):
            published, retained = (source.before_chains[index] if unpublished_cleanup else source.chains[index]), chains[chain_id]
            middle_provider = source.before_chains[index].middle_provider
            workspace = source.workspace_paths[order.index(middle_provider)]
            if (not same_published_chain(retained, published)
                    or retained.status != "deployed"
                    or retained.burned or retained.teardown_job_id
                    or retained.terraform_working_directory != workspace
                    or sketch_chain_intent_fingerprint(retained)
                       != reviewed_chain_fingerprints[chain_id]):
                raise ValueError("published six-node chain differs")

        scopes = []
        seen_addresses: set[str] = set()
        seen_ids: set[tuple[str, str]] = set()
        for index, provider in enumerate(order):
            child, observation = provider_children[provider], observations[provider]
            policy = reviewed_policies[provider]
            proof = child.events[8].data
            if (child.action != (
                    "provider_keyed_mixed_append_apply_child" if index == 0 else
                    "provider_keyed_mixed_append_second_apply_child")
                    or child.status != "succeeded" or child.finished_at is None
                    or child.target_id != source.engagement_id
                    or child.requested_by != append_parent.requested_by
                    or len(child.events) != 10
                    or child.events[-1].message != (
                        "mixed append first provider Apply succeeded" if index == 0
                        else "mixed append second provider Apply succeeded")
                    or child.events[-1].data != {
                        "proofJournalSha256": job_event_digest(child.events[:9])}
                    or job_event_digest(child.events)
                       != source.provider_proof_digests[index]
                    or proof.get("provider") != provider
                    or proof.get("reviewSha256")
                       != append_parent.input.get("reviewSha256")
                    or type(observation) is not ProviderHostObservation
                    or type(observation.state_json) is not bytes
                    or observation.classification.provider != provider
                    or observation.classification.kind != "full"
                    or observation.classification.state_sha256
                       != expected_hashes[index]
                    or hashlib.sha256(observation.state_json).hexdigest()
                       != expected_hashes[index]
                    or proof.get("stateSha256") != source.state_sha256s[index]
                    or observation.classification.lineage != proof.get("lineage")
                    or (observation.classification.serial != proof.get("serial")
                        if current_generation is None else
                        observation.classification.serial < proof.get("serial"))
                    or not isinstance(policy, Mapping)
                    or not isinstance(policy.get("nodes"), Mapping)):
                raise ValueError("mixed six-node provider proof differs")
            # Append proof IDs cover every retained state resource, including
            # the local random password. Provider observations cover cloud IDs.
            state, actual, cloud = _state(provider, policy, observation.state_json)
            if (state["lineage"] != proof["lineage"]
                    or state["serial"] != observation.classification.serial
                    or tuple(sorted(cloud.items()))
                       != tuple(sorted(observation.classification.resource_ids))
                    or [[address, str(attributes["id"])]
                        for address, attributes in sorted(actual.items())]
                       != proof.get("resourceIds")
                    or set(actual) != set(policy["nodes"]) | _POST_APPEND_SHARED[provider]
                    or not Path(source.workspace_paths[index]).is_absolute()):
                raise ValueError("mixed six-node complete provider state differs")
            rows = [row for row in source.host_rows if row.provider == provider]
            if (len(rows) != 3 or set(policy["nodes"]) != {
                    row.terraform_address for row in rows}):
                raise ValueError("mixed six-node provider host set differs")
            for row in rows:
                if (cloud.get(row.terraform_address) != row.provider_instance_id
                        or row.terraform_address in seen_addresses
                        or (provider, row.provider_instance_id) in seen_ids):
                    raise ValueError("mixed six-node host identity differs")
                seen_addresses.add(row.terraform_address)
                seen_ids.add((provider, row.provider_instance_id))
            kinds = {**{row.terraform_address: (
                "instance" if provider == "linode" else "droplet") for row in rows},
                **{address: _SHARED_KINDS[address] for address in _POST_APPEND_SHARED[provider]}}
            if set(kinds) != set(actual):
                raise ValueError("mixed six-node resource kind differs")
            scopes.append({
                "schema": "provider-keyed-v2", "provider": provider,
                "coreJobId": source.core_job_id,
                "corePlanId": source.core_plan_id,
                "workspace": source.workspace_paths[index],
                "stateSha256": expected_hashes[index],
                "lineage": state["lineage"], "serial": state["serial"],
                "chainIds": list(chain_ids),
                "resources": [{"address": address,
                               "id": str(actual[address]["id"]),
                               "kind": kinds[address]} for address in sorted(actual)],
            })
        if len(seen_addresses) != 6 or len(seen_ids) != 6:
            raise ValueError("mixed six-node host set is incomplete")
        return PublishedMixedSixScope(
            source.source_sha256, job_event_digest(append_parent.events),
            _digest({"schema": "mixed-published-six-bindings-v1",
                     "bindings": live_bindings}),
            sum(len(rows) for rows in live_bindings.values()), tuple(scopes))
    except Exception:
        raise MixedPublishedSixScopeAttention(
            "published six-node scope requires exact two-provider review") from None
