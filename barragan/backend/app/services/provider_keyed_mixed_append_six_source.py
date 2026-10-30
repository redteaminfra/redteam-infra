# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only six-node projection from two terminal mixed append proofs.

The projection is deterministic across restart. Provider/state/GET authority
belongs to the fresh collector that calls it, not to these proof-data fields.
"""

from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from dataclasses import replace
import hashlib
from pathlib import Path
from typing import Callable, Mapping

from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_host_binding import _regular_file_digest
from app.services.provider_keyed_host_binding import _core_known_hosts
from app.services.provider_keyed_mixed_append_first_poststate import (
    collect_first_mixed_append_inventory_snapshot, prove_first_mixed_append_poststate,
)
from app.services.provider_keyed_mixed_append_first_proof_job import (
    _load_approved_first_source, _process_quiescent,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixNodeHostSource, validate_six_node_host_source,
)
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_child_id
from app.services.provider_keyed_mixed_append_second_apply_binding import (
    _approved_second, _stable_first,
)
from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_child_id
from app.services.provider_keyed_mixed_append_second_proof_job import _journal as second_journal
from app.services.provider_keyed_mixed_initial_host_binding import (
    _binding_child_id, recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_bootstrap_apply import _core_hosts
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_chain_repository import StoredSketchChain


class MixedAppendSixSourceAttention(ValueError):
    """The two terminal edges cannot form the reviewed cross-provider shape."""


def verify_six_node_local_fence(source: SixNodeHostSource) -> str:
    """Short post-GET CAS fence; never contact a provider while SQLite is locked."""
    try:
        validate_six_node_host_source(source)
        if _regular_file_digest(Path(source.core_known_hosts_path), require_content=True) != (
                source.core_known_hosts_sha256):
            raise ValueError("core host trust changed")
        for index, root_text in enumerate(source.workspace_paths):
            root = Path(root_text)
            if (root.is_symlink() or root.resolve(strict=True) != root
                    or hashlib.sha256(_read(root / "terraform.tfstate", private=False)).hexdigest()
                       != source.state_sha256s[index]):
                raise ValueError("mixed append state changed")
        return source.source_sha256
    except Exception:
        raise MixedAppendSixSourceAttention(
            "mixed append local state or host trust changed before publication") from None


def collect_fresh_six_node_host_source(
    parent_id: str, *, job_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    release_check: Callable = require_devtest_terraform_release,
    snapshot_collector: Callable = collect_first_mixed_append_inventory_snapshot,
    linode_transport=None, digitalocean_transport=None,
    lease_operation: str = "provider_keyed_mixed_append",
) -> SixNodeHostSource:
    """Reopen both terminal writes and GETs before any new host contact.

    This is intentionally a full read at a phase boundary, never a heartbeat
    action or a SQLite writer-lock callback. Uncertain writes cannot produce a
    six-node source.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(parent_id)
        if (lease_operation not in {"provider_keyed_mixed_append", "provider_keyed_teardown_fence"}
                or parent is None or parent.action != "provider_keyed_mixed_append"
                or parent.status != "running" or parent.input.get("phase") != "apply_sealed"
                or lookup(parent.target_id) != (
                    parent.input["corePlanId"], lease_operation)):
            raise ValueError("mixed append parent or lease differs")
        core = jobs.get(parent.input["coreJobId"])
        if (core is None or core.status != "succeeded"
                or core.input.get("engagementId") != parent.target_id
                or active_core_connection_details(jobs, parent.target_id)[0] != core.id):
            raise ValueError("mixed append active core differs")
        all_before = tuple(chains.list_for_engagement(parent.target_id))
        chain_order = tuple(parent.input["chainOrder"])
        before_by_id = {row.chain_id: row for row in reviewed_mixed_chain_rows(
            all_before, chain_order, parent.target_id)}
        provider_order = tuple(parent.input["providerOrder"])
        if (len(before_by_id) != 2 or len(chain_order) != 2
                or set(before_by_id) != set(chain_order)
                or provider_order not in (("digitalocean", "linode"),
                                          ("linode", "digitalocean"))):
            raise ValueError("mixed append published chain rows differ")
        before = tuple(before_by_id[chain_id] for chain_id in chain_order)
        first = _load_approved_first_source(parent, jobs, release_check)
        second = _approved_second(parent, jobs, release_check)
        initial_binding = jobs.get(_binding_child_id(core.id))
        initial_current = jobs.get(second.historical.id)
        manifest = recognize_mixed_initial_host_binding(initial_binding, second.historical)
        original_rows = {(row["chainId"], row["terraformAddress"]): row
                         for row in manifest["nodes"]}
        if (len(original_rows) != 4
                or any(original_rows.get((chain.chain_id, node["terraformAddress"])) != {
                    "chainId": chain.chain_id, "provider": node["provider"],
                    "role": node["role"], "hostname": node["hostname"],
                    "terraformAddress": node["terraformAddress"],
                    "providerInstanceId": node["providerInstanceId"],
                    "publicIp": node["publicIp"], "region": node["region"],
                    "assignedProxy": chain.assigned_proxy,
                } for chain in before for node in chain.nodes)):
            raise ValueError("mixed append original host rows differ")
        first_child, second_child = (jobs.get(first_child_id(parent.id)),
                                     jobs.get(second_child_id(parent.id)))
        if first_child is None or second_child is None:
            raise ValueError("mixed append terminal provider children missing")

        def fence() -> str:
            if (jobs.get(parent.id) != parent
                    or jobs.get(core.id) != core
                    or jobs.get(initial_binding.id) != initial_binding
                    or jobs.get(second.historical.id) != initial_current
                    or jobs.get(first_child.id) != first_child
                    or jobs.get(second_child.id) != second_child
                    or lookup(parent.target_id) != (
                        parent.input["corePlanId"], lease_operation)
                    or active_core_connection_details(jobs, parent.target_id)[0]
                       != core.id
                    or tuple(chains.list_for_engagement(parent.target_id)) != all_before):
                raise ValueError("mixed append source changed during GET")
            return parent.input["reviewSha256"]

        first_digest = _stable_first(
            parent, jobs, first, snapshot_collector, credentials,
            linode_transport, digitalocean_transport, fence)
        second_result, second_stage = second_journal(
            parent, second_child, second, first_digest)
        identity = second_result.started_identity
        quiescent = lambda: _process_quiescent(
            identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"])
        if second_stage != "terminal" or not quiescent():
            raise ValueError("mixed append second provider is not terminal and quiescent")
        snapshot = snapshot_collector(
            intent=second.intent, workspace=second.workspace,
            receipt=second.receipt, fence=fence, process_quiescent=quiescent,
            credential_repository=credentials, linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)
        fresh_second = prove_first_mixed_append_poststate(
            intent=second.intent, predecessor_state=second.predecessor_state,
            reviewed_show_json=second.reviewed_show_json, snapshot=snapshot,
            command_result_proved=True, process_quiescent=True)
        saved_second = second_child.events[8].data
        if (any(saved_second[key] != value for key, value in {
                "stateSha256": fresh_second.state_sha256,
                "lineage": fresh_second.lineage,
                "serial": fresh_second.serial,
                "resourceIds": [list(row) for row in fresh_second.resource_ids],
                "newEdgeAddress": fresh_second.new_edge_address,
                "newEdgeProviderId": fresh_second.new_edge_provider_id,
                "newEdgePublicIp": fresh_second.new_edge_public_ip,
                "inventorySha256": fresh_second.inventory_sha256,
                "selectorResourcesCount": fresh_second.selector_resources_count,
                "attachedNodeIds": list(fresh_second.attached_node_ids),
        }.items())):
            raise ValueError("mixed append second provider changed after terminal proof")
        proofs = {provider_order[0]: first_child.events[8].data,
                  provider_order[1]: saved_second}
        after = project_mixed_append_six_chains(parent, before, proofs)
        workspaces = {provider_order[0]: first.workspace,
                      provider_order[1]: second.workspace}
        proxy_ips = tuple(_core_hosts(
            jobs, parent.target_id, chain.assigned_proxy,
            require_proxy_public_alias=True)[1].host_key_alias for chain in after)
        core_path, core_sha = _core_known_hosts(core)
        source = SixNodeHostSource(
            parent.id, parent.target_id, core.id, parent.input["corePlanId"],
            provider_order, chain_order, before, after,
            tuple(proofs[provider]["newEdgeAddress"] for provider in provider_order),
            (first_digest, job_event_digest(second_child.events)),
            tuple(proofs[provider]["stateSha256"] for provider in provider_order),
            tuple(str(workspaces[provider].path) for provider in provider_order),
            tuple(workspaces[provider].source_revision for provider in provider_order),
            proxy_ips, core_path, core_sha,
        )
        validate_six_node_host_source(source)
        fence()
        verify_six_node_local_fence(source)
        return source
    except Exception:
        raise MixedAppendSixSourceAttention(
            "mixed append six-node source requires fresh exact provider proof") from None


def project_mixed_append_six_chains(
    parent, before_chains: tuple[StoredSketchChain, StoredSketchChain],
    proof_data: Mapping[str, dict],
) -> tuple[StoredSketchChain, StoredSketchChain]:
    """Keep four retained hosts and append one opposite-provider edge per chain."""
    try:
        order = tuple(parent.input["providerOrder"])
        chain_order = tuple(parent.input["chainOrder"])
        if (parent.action != "provider_keyed_mixed_append"
                or parent.status != "running" or parent.input.get("phase") != "apply_sealed"
                or order not in (("digitalocean", "linode"),
                                 ("linode", "digitalocean"))
                or type(before_chains) is not tuple or len(before_chains) != 2
                or tuple(row.chain_id for row in before_chains) != chain_order
                or set(proof_data) != set(order)
                or type(parent.started_at) is not str or not parent.started_at):
            raise ValueError("mixed append reviewed pair differs")
        after = []
        for index, provider in enumerate(order):
            before, proof = before_chains[index], proof_data[provider]
            intent = parent.input["intents"][provider]
            edge = intent["new_edge"]
            address = intent["new_edge_address"]
            middle_key = ("linode_middle" if provider == "digitalocean"
                          else "digitalocean_middle")
            name = edge["name"] if provider == "digitalocean" else edge["label"]
            size = edge["size"] if provider == "digitalocean" else edge["node_type"]
            if (before.engagement_id != parent.target_id
                    or before.status != "deployed" or before.burned
                    or before.middle_provider == provider
                    or before.edge_provider != before.middle_provider
                    or before.edge_count != 1 or len(before.nodes) != 2
                    or [node.get("role") for node in before.nodes] != ["middle", "edge"]
                    or any(node.get("provider") != before.middle_provider
                           for node in before.nodes)
                    or intent[f"{middle_key}_address"]
                       != before.nodes[0].get("terraformAddress")
                    or intent[f"{middle_key}_id"]
                       != before.nodes[0].get("providerInstanceId")
                    or parent.input["selectedMiddles"][provider]
                       != before.nodes[0].get("terraformAddress")
                    or type(before.edge_intents) is not list
                    or len(before.edge_intents) != 1
                    or proof.get("provider") != provider
                    or proof.get("newEdgeAddress") != address
                    or type(proof.get("newEdgeProviderId")) is not str
                    or not proof["newEdgeProviderId"]
                    or type(proof.get("newEdgePublicIp")) is not str
                    or not proof["newEdgePublicIp"]
                    or edge["region"] != parent.input["reviewRequest"][provider]["edgeRegion"]
                    or size != parent.input["reviewRequest"][provider][
                        "edgeSize" if provider == "digitalocean" else "edgeType"]):
                raise ValueError("mixed append retained or new edge differs")
            new = {
                "chainId": before.chain_id, "role": "edge", "provider": provider,
                "hostname": name, "terraformAddress": address,
                "providerInstanceId": proof["newEdgeProviderId"],
                "region": edge["region"], "publicIp": proof["newEdgePublicIp"],
                "assignedProxy": before.assigned_proxy, "proxy": before.assigned_proxy,
                "status": "deployed", "componentId": "edge-02", "edgeId": "edge-02",
                "edgeIndex": "2", "edgeCount": "2",
            }
            next_edge = {"id": "edge-02", "provider": provider,
                         "region": edge["region"], "size": size}
            after.append(replace(
                before, edge_count=2,
                edge_intents=[*before.edge_intents, next_edge],
                nodes=[before.nodes[0], {**before.nodes[1], "edgeCount": "2"}, new],
                updated_at=parent.started_at,
            ))
        if (len({node["terraformAddress"] for chain in after for node in chain.nodes}) != 6
                or len({(node["provider"], node["providerInstanceId"])
                        for chain in after for node in chain.nodes}) != 6):
            raise ValueError("mixed append host identity repeats")
        return tuple(after)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise MixedAppendSixSourceAttention(
            "mixed append six-node projection requires exact terminal proofs") from exc
