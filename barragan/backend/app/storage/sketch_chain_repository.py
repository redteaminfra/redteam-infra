# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Protocol


class ProviderKeyedPublicationConflict(RuntimeError):
    """The reviewed two-chain host-proof generation was not published."""


_KEYED_LOCAL_FILES = frozenset({
    "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
})


def _canonical_keyed_inspector_record(record: Any) -> bool:
    """Recognize an Inspector's owned record without trusting its role alone."""
    metadata = record.metadata if isinstance(record.metadata, dict) else {}
    provider = record.provider
    host_type = {"linode": "inspector_instance",
                 "digitalocean": "inspector_droplet"}.get(provider)
    if (host_type is None or not record.resource_id
            or record.source != "barragan_inspector_job"
            or metadata.get("barraganOwned") is not True
            or not record.adoption_job_id
            or metadata.get("inspectionJobId") != record.adoption_job_id):
        return False
    if record.resource_type == host_type:
        return (record.id == f"{provider}:inspector:{record.resource_id}"
                and metadata.get("role") == "inspector")
    if record.resource_type == "inspector_firewall":
        return (record.id == f"{provider}:inspector-firewall:{record.resource_id}"
                and metadata.get("role") == "inspector_firewall"
                and type(metadata.get("inspectorHostResourceId")) is str
                and bool(metadata["inspectorHostResourceId"]))
    return False


@dataclass(frozen=True)
class StoredSketchChain:
    chain_id: str
    engagement_id: str
    assigned_proxy: str
    middle_provider: str
    middle_region: str
    middle_size: str
    edge_provider: str
    edge_region: str
    edge_size: str
    status: str
    burned: bool
    burned_note: str
    deploy_job_id: str
    teardown_job_id: str
    terraform_working_directory: str
    nodes: list[dict[str, Any]]
    created_at: str
    updated_at: str
    edge_count: int = 1
    edge_intents: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "chainId": self.chain_id,
            "engagementId": self.engagement_id,
            "assignedProxy": self.assigned_proxy,
            "middleProvider": self.middle_provider,
            "middleRegion": self.middle_region,
            "middleSize": self.middle_size,
            "edgeProvider": self.edge_provider,
            "edgeRegion": self.edge_region,
            "edgeSize": self.edge_size,
            "edgeCount": self.edge_count,
            "edges": self.edge_intents or _legacy_edges(self.edge_provider, self.edge_region, self.edge_size, self.edge_count),
            "status": self.status,
            "burned": self.burned,
            "burnedNote": self.burned_note,
            "deployJobId": self.deploy_job_id,
            "teardownJobId": self.teardown_job_id,
            "terraformWorkingDirectory": self.terraform_working_directory,
            "nodes": self.nodes,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


class SketchChainRepository(Protocol):
    def list_for_engagement(self, engagement_id: str) -> list[StoredSketchChain]:
        ...

    def get(self, engagement_id: str, chain_id: str) -> StoredSketchChain | None:
        ...

    def list_for_recovery(
        self,
        *,
        statuses: set[str] | None = None,
        updated_before: datetime | None = None,
    ) -> list[StoredSketchChain]:
        ...

    def save(self, chain: StoredSketchChain) -> StoredSketchChain:
        ...

    def save_if_matches(
        self,
        chain: StoredSketchChain,
        *,
        expected_status: str,
        expected_deploy_job_id: str,
        expected_teardown_job_id: str,
    ) -> StoredSketchChain | None:
        ...

    def publish_provider_keyed_initial_chains(
        self, *, parent: Any,
        pending_chains: tuple[StoredSketchChain, StoredSketchChain],
        projected_chains: Any, host_proof: Any,
        host_evidence_sha256: str, state_sha256: str, manifest: dict,
        manifest_sha256: str, applied_workspace_path: str,
        expected_event_digest: str, claim_owner: str, claim_token: str,
        finished_at: str,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        ...

    def publish_provider_keyed_mixed_initial_chains(
        self, *, parent: Any, proof_child: Any, receipt: Any,
        pending_chains: tuple[StoredSketchChain, StoredSketchChain],
        projected_chains: Any, source: Any, provider_workspaces: dict[str, str],
        expected_parent_event_digest: str, expected_child_event_digest: str,
        claim_owner: str, claim_token: str, finished_at: str,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        ...

    def publish_provider_keyed_mixed_append_pair(
        self, *, parent: Any,
        before_chains: tuple[StoredSketchChain, StoredSketchChain],
        after_chains: tuple[StoredSketchChain, StoredSketchChain],
        provider_proof_children: dict[str, Any], host_proof_child: Any,
        receipt: Any, expected_parent_event_digest: str,
        expected_provider_event_digests: dict[str, str],
        expected_host_event_digest: str, claim_owner: str, claim_token: str,
        finished_at: str, fresh_source: Any, local_fence: Any,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        ...


class SqlAlchemySketchChainRepository:
    def publish_provider_keyed_mixed_append_pair(
        self, *, parent: Any,
        before_chains: tuple[StoredSketchChain, StoredSketchChain],
        after_chains: tuple[StoredSketchChain, StoredSketchChain],
        provider_proof_children: dict[str, Any], host_proof_child: Any,
        receipt: Any, expected_parent_event_digest: str,
        expected_provider_event_digests: dict[str, str],
        expected_host_event_digest: str, claim_owner: str, claim_token: str,
        finished_at: str, fresh_source: Any, local_fence: Any,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        """Publish both appended edges, the parent, and lease in one SQLite commit.

        ``fresh_source`` authenticates provider state and both terminal Apply
        proofs with fresh GETs *before* the SQLite writer slot. ``local_fence``
        then checks its local state, jobs, and receipt bytes under that slot.
        SQLite cannot fence an external cloud write after the GET; keeping a
        cloud read outside the DB transaction avoids blocking unrelated writes
        while a provider is slow. This writer never repeats a provider write.
        """
        from sqlalchemy import text

        from app.services.provider_keyed_mixed_append_pair_apply_child import (
            _child_id as first_child_id,
        )
        from app.services.provider_keyed_mixed_append_second_apply_child import (
            _child_id as second_child_id,
        )
        from app.services.provider_keyed_mixed_append_pair_host_proof import (
            SixNodeHostSource, validate_six_host_receipt_child,
        )
        from app.storage.database import db
        from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
        from app.storage.models import (
            CoreMutationLeaseModel, JobEventModel, JobRunModel, SketchChainModel,
        )

        def sha(value: object) -> bool:
            return type(value) is str and len(value) == 64 and all(
                character in "0123456789abcdef" for character in value)

        try:
            finished = datetime.fromisoformat(finished_at)
            expiry = datetime.fromisoformat(parent.input["claimExpiresAt"])
            claimed = datetime.fromisoformat(parent.input["claimClaimedAt"])
            heartbeat = datetime.fromisoformat(parent.input.get(
                "claimHeartbeatAt", parent.input["claimClaimedAt"]))
            order = tuple(parent.input["providerOrder"])
            chain_order = tuple(parent.input["chainOrder"])
            if (db.engine.dialect.name != "sqlite"
                    or not isinstance(parent, StoredJobRun)
                    or not isinstance(host_proof_child, StoredJobRun)
                    or type(before_chains) is not tuple or len(before_chains) != 2
                    or type(after_chains) is not tuple or len(after_chains) != 2
                    or order not in (("linode", "digitalocean"),
                                     ("digitalocean", "linode"))
                    or len(chain_order) != 2 or len(set(chain_order)) != 2
                    or not callable(fresh_source) or not callable(local_fence)
                    or parent.action != "provider_keyed_mixed_append"
                    or parent.status != "running" or parent.finished_at is not None
                    or parent.started_at is None or parent.artifact_refs != []
                    or parent.target_type != "engagement"
                    or parent.target != f"engagement:{parent.target_id}"
                    or parent.input.get("schema") != "mixed-append-pair-parent-v1"
                    or parent.input.get("phase") != "apply_sealed"
                    or parent.input.get("mutation") is not True
                    or parent.input.get("engagementId") != parent.target_id
                    or parent.input.get("claimOwner") != claim_owner
                    or parent.input.get("claimToken") != claim_token
                    or not claim_owner or not claim_token
                    or any(value.tzinfo is None or value.utcoffset() != timedelta(0)
                           for value in (finished, claimed, heartbeat, expiry))
                    or not claimed <= heartbeat <= finished < expiry
                    or datetime.now(timezone.utc) >= expiry
                    or not all(sha(value) for value in (
                        parent.input.get("reviewSha256"), expected_parent_event_digest,
                        expected_host_event_digest))
                    or job_event_digest(parent.events) != expected_parent_event_digest
                    or not parent.events
                    or parent.events[-1].message != "mixed append pair approved"
                    or parent.events[-1].data.get("reviewSha256")
                       != parent.input["reviewSha256"]
                    or set(provider_proof_children) != set(order)
                    or set(expected_provider_event_digests) != set(order)
                    or not all(sha(value) for value in
                               expected_provider_event_digests.values())
                    or tuple(chain.chain_id for chain in before_chains) != chain_order
                    or tuple(chain.chain_id for chain in after_chains) != chain_order
                    or len({chain.engagement_id for chain in (*before_chains,
                                                             *after_chains)}) != 1
                    or before_chains[0].engagement_id != parent.target_id):
                raise ValueError("mixed append publication parent or generation differs")

            for index, (before, after) in enumerate(zip(
                    before_chains, after_chains, strict=True)):
                provider = order[index]
                old_middle, old_edge = before.nodes
                middle, retained_edge, new_edge = after.nodes
                updated = datetime.fromisoformat(after.updated_at)
                prior = datetime.fromisoformat(before.updated_at)
                # SQLite stores both retained row and parent-start projection
                # timestamps without UTC suffixes. Normalize comparisons only;
                # the selected source is still compared byte-for-byte.
                if prior.tzinfo is None:
                    prior = prior.replace(tzinfo=timezone.utc)
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                if (before.status != "deployed" or after.status != "deployed"
                        or before.burned or after.burned
                        or before.edge_count != 1 or after.edge_count != 2
                        or len(before.nodes) != 2 or len(after.nodes) != 3
                        or before.middle_provider == provider
                        or before.edge_provider != before.middle_provider
                        or after != replace(before, edge_count=2,
                                            edge_intents=after.edge_intents,
                                            nodes=after.nodes,
                                            updated_at=after.updated_at)
                        or type(before.edge_intents) is not list
                        or len(before.edge_intents) != 1
                        or type(after.edge_intents) is not list
                        or len(after.edge_intents) != 2
                        or after.edge_intents[0] != before.edge_intents[0]
                        or after.edge_intents[1].get("id") != "edge-02"
                        or updated < prior or updated > finished
                        or middle != old_middle
                        or retained_edge != {**old_edge, "edgeCount": "2"}
                        or [node.get("role") for node in before.nodes]
                           != ["middle", "edge"]
                        or [node.get("componentId") for node in before.nodes]
                           != ["middle", "edge-01"]
                        or new_edge.get("role") != "edge"
                        or new_edge.get("chainId") != before.chain_id
                        or new_edge.get("provider") != provider
                        or new_edge.get("status") != "deployed"
                        or new_edge.get("componentId") != "edge-02"
                        or new_edge.get("edgeId") != "edge-02"
                        or new_edge.get("edgeIndex") != "2"
                        or new_edge.get("edgeCount") != "2"
                        or new_edge.get("region") != after.edge_intents[1].get("region")
                        or new_edge.get("assignedProxy") != before.assigned_proxy
                        or new_edge.get("proxy") != before.assigned_proxy
                        or not new_edge.get("terraformAddress")
                        or not new_edge.get("providerInstanceId")
                        or not new_edge.get("hostname")
                        or not new_edge.get("publicIp")):
                    raise ValueError("mixed append retained or new chain differs")
            nodes = [node for chain in after_chains for node in chain.nodes]
            if (len({node.get("terraformAddress") for node in nodes}) != 6
                    or len({(node.get("provider"), node.get("providerInstanceId"))
                            for node in nodes}) != 6
                    or len({node.get("hostname") for node in nodes}) != 6):
                raise ValueError("mixed append node identity repeats")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            raise ProviderKeyedPublicationConflict(
                "mixed append publication source differs") from exc

        try:
            source = fresh_source()
        except Exception:
            raise ProviderKeyedPublicationConflict(
                "mixed append fresh six-node source unavailable") from None

        try:
            # No-op UPDATE takes SQLite's writer slot before rereading jobs,
            # rows, lease, and local six-host evidence. Provider GETs above
            # are intentionally outside this transaction.
            changed = db.session.execute(text("""
                UPDATE job_runs SET status = status WHERE id = :id
                  AND action = 'provider_keyed_mixed_append'
                  AND status = 'running' AND finished_at IS NULL
            """), {"id": parent.id})
            if changed.rowcount != 1 or datetime.now(timezone.utc) >= expiry:
                raise ValueError("mixed append parent claim changed")
            db.session.expire_all()
            jobs = SqlAlchemyJobRepository()
            saved_parent = jobs.get(parent.id)
            saved_proof = jobs.get(host_proof_child.id)
            if (saved_parent != parent or saved_proof != host_proof_child
                    or job_event_digest(saved_parent.events)
                       != expected_parent_event_digest
                    or job_event_digest(saved_proof.events)
                       != expected_host_event_digest):
                raise ValueError("mixed append job journal changed")
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=parent.target_id,
                owner_id=parent.input["corePlanId"],
                operation="provider_keyed_mixed_append",
            ).one_or_none()
            if lease is None:
                raise ValueError("mixed append engagement lease changed")
            for index, provider in enumerate(order):
                child = provider_proof_children[provider]
                saved = jobs.get(child.id)
                child_id = (first_child_id(parent.id) if index == 0
                            else second_child_id(parent.id))
                terminal_message = ("mixed append first provider Apply succeeded"
                                    if index == 0 else
                                    "mixed append second provider Apply succeeded")
                if (not isinstance(child, StoredJobRun) or saved != child
                        or child.id != child_id or child.status != "succeeded"
                        or child.action != ("provider_keyed_mixed_append_apply_child"
                                            if index == 0 else
                                            "provider_keyed_mixed_append_second_apply_child")
                        or child.target != parent.target
                        or child.target_id != parent.target_id
                        or child.requested_by != parent.requested_by
                        or child.finished_at is None or len(child.events) != 10
                        or child.events[-1].message != terminal_message
                        or child.events[-1].data != {
                            "proofJournalSha256": job_event_digest(child.events[:9])}
                        or child.events[8].data.get("reviewSha256")
                           != parent.input["reviewSha256"]
                        or job_event_digest(child.events)
                           != expected_provider_event_digests[provider]):
                    raise ValueError("mixed append provider terminal changed")
            rows = db.session.query(SketchChainModel).filter_by(
                engagement_id=parent.target_id).all()
            from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
            selected = reviewed_mixed_chain_rows(
                [_from_model(row) for row in rows], chain_order, parent.target_id)
            rows = [row for row in rows if row.chain_id in {chain.chain_id for chain in selected}]
            if ({row.chain_id for row in rows} != set(chain_order)
                    or any(_from_model(next(row for row in rows
                                             if row.chain_id == before.chain_id)) != before
                           for before in before_chains)):
                raise ValueError("mixed append published rows changed")

            if local_fence(source) != source.source_sha256:
                raise ValueError("mixed append local state fence changed")
            if datetime.now(timezone.utc) >= expiry:
                raise ValueError("mixed append parent claim expired after recheck")
            if (type(source) is not SixNodeHostSource
                    or source.parent_id != parent.id
                    or source.engagement_id != parent.target_id
                    or source.core_job_id != parent.input["coreJobId"]
                    or source.core_plan_id != parent.input["corePlanId"]
                    or source.provider_order != order
                    or source.chain_ids != chain_order
                    or source.provider_proof_digests
                       != tuple(expected_provider_event_digests[provider]
                                for provider in order)
                    or len(source.host_rows) != 6
                    or len(source.chains) != 2
                    or source.before_chains != before_chains
                    or tuple(source.chains) != after_chains):
                raise ValueError("mixed append fresh six-node source changed")
            for source_row, node in zip(
                    source.host_rows, nodes, strict=True):
                if ((source_row.chain_id, source_row.provider, source_row.role,
                     source_row.hostname, source_row.terraform_address,
                     source_row.provider_instance_id, source_row.public_ip,
                     source_row.assigned_proxy) != (
                     node["chainId"], node["provider"], node["role"],
                     node["hostname"], node["terraformAddress"],
                     node["providerInstanceId"], node["publicIp"],
                     node["assignedProxy"])):
                    raise ValueError("mixed append fresh host row changed")
            validate_six_host_receipt_child(saved_parent, saved_proof, receipt,
                                            source=source)
            if (receipt.child_event_sha256 != expected_host_event_digest
                    or receipt.claim_owner != claim_owner
                    or receipt.claim_token != claim_token):
                raise ValueError("mixed append host receipt changed")
            # Retain the authenticated, pre-publication generation for exact
            # teardown recognition after the chain rows have been updated.
            source_snapshot = json.loads(json.dumps(asdict(source)))
            for before, after in zip(before_chains, after_chains, strict=True):
                row = next(row for row in rows if row.chain_id == before.chain_id)
                row.edge_count = 2
                row.edge_intents = after.edge_intents
                row.nodes = after.nodes
                row.updated_at = datetime.fromisoformat(after.updated_at)
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1,
                level="info", message="mixed append six-node generation published",
                data={"sourceSha256": source.source_sha256,
                      "source": source_snapshot,
                      "hostProofJournalSha256": expected_host_event_digest,
                      "providerProofJournalSha256": expected_provider_event_digests,
                      "chainIds": list(chain_order)},
            ))
            parent_row = db.session.get(JobRunModel, parent.id)
            parent_row.status = "succeeded"
            parent_row.finished_at = finished
            parent_row.input = {**{key: value for key, value in parent.input.items()
                                   if not key.startswith("claim")}, "phase": "completed"}
            db.session.delete(lease)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise ProviderKeyedPublicationConflict(
                "mixed append six-node publication stopped") from None
        published = tuple(self.get(parent.target_id, chain_id) for chain_id in chain_order)
        if any(row is None for row in published):
            raise ProviderKeyedPublicationConflict("mixed append published row unavailable")
        return published

    def publish_provider_keyed_mixed_initial_chains(
        self, *, parent, proof_child, receipt,
        pending_chains: tuple[StoredSketchChain, StoredSketchChain],
        projected_chains, source, provider_workspaces: dict[str, str],
        expected_parent_event_digest: str, expected_child_event_digest: str,
        claim_owner: str, claim_token: str, finished_at: str,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        """Commit both proved provider chains, jobs, and lease in one transaction."""
        from sqlalchemy import text

        from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
        from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
        from app.services.provider_keyed_chain_projection import ProjectedProviderKeyedChain
        from app.services.provider_keyed_mixed_initial_apply_child import (
            _child_id as apply_child_id, recognize_mixed_initial_apply_terminal,
        )
        from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
        from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
        from app.services.provider_keyed_mixed_initial_host_binding import _digest as mixed_digest
        from app.services.provider_keyed_mixed_initial_publication_source import MixedInitialPublicationSource
        from app.services.provider_keyed_mixed_strict_host_receipt import validate_receipt_child
        from app.services.provider_keyed_runtime_preflight import _inert_aborted_intent
        from app.services.provider_keyed_host_surface_interpreter import _key_digest
        from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
        from app.services.sketch_transport_ssh_keys import retrieve_sketch_transport_ssh_key
        from app.storage.database import db
        from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
        from app.storage.models import (
            CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel,
            JobEventModel, JobRunModel, SketchChainModel,
        )

        try:
            finished = datetime.fromisoformat(finished_at)
            claimed = datetime.fromisoformat(parent.input["claimClaimedAt"])
            expiry = datetime.fromisoformat(parent.input["claimExpiresAt"])
            heartbeat = datetime.fromisoformat(parent.input.get(
                "claimHeartbeatAt", parent.input["claimClaimedAt"]))
            if (type(source) is not MixedInitialPublicationSource
                    or not isinstance(parent, StoredJobRun)
                    or not isinstance(proof_child, StoredJobRun)
                    or any(value.tzinfo is None or value.utcoffset() != timedelta(0)
                           for value in (finished, claimed, heartbeat, expiry))
                    or not claimed <= heartbeat <= finished < expiry
                    or datetime.now(timezone.utc) >= expiry
                    or parent.id != source.parent_job_id
                    or parent.action != "provider_keyed_mixed_initial"
                    or parent.status != "running" or parent.finished_at is not None
                    or parent.started_at is None or parent.artifact_refs != []
                    or parent.target != f"engagement:{source.engagement_id}"
                    or parent.target_type != "engagement" or parent.target_id != source.engagement_id
                    or parent.input.get("phase") != "awaiting_mixed_host_proof"
                    or parent.input.get("mutation") is not True
                    or parent.input.get("coreJobId") != source.core_job_id
                    or parent.input.get("corePlanId") != source.core_plan_id
                    or parent.input.get("revisionId") != source.revision_id
                    or parent.input.get("chainIds") != list(source.chain_ids)
                    or parent.input.get("orderedProviders") != list(source.ordered_providers)
                    or parent.input.get("claimOwner") != claim_owner
                    or parent.input.get("claimToken") != claim_token
                    or not claim_owner or not claim_token
                    or len(parent.events) != 7
                    or job_event_digest(parent.events) != expected_parent_event_digest
                    or source.parent_journal_sha256 != expected_parent_event_digest
                    or job_event_digest(proof_child.events) != expected_child_event_digest
                    or receipt.source != source or receipt.child_id != proof_child.id
                    or receipt.child_event_sha256 != expected_child_event_digest
                    or receipt.claim_owner != claim_owner or receipt.claim_token != claim_token
                    or tuple(source.ordered_providers) not in (
                        ("linode", "digitalocean"), ("digitalocean", "linode"))
                    or len(source.chain_ids) != 2 or len(set(source.chain_ids)) != 2
                    or len(source.host_rows) != 4 or len(source.provider_states) != 2
                    or set(provider_workspaces) != {"linode", "digitalocean"}
                    or any(type(path) is not str or not Path(path).is_absolute()
                           or os.path.normpath(path) != path for path in provider_workspaces.values())
                    or provider_workspaces["linode"] == provider_workspaces["digitalocean"]):
                raise ValueError("mixed source or parent claim differs")
            validate_receipt_child(source, proof_child, receipt)
            pending = {chain.chain_id: chain for chain in pending_chains}
            projected = {item.chain.chain_id: item for item in projected_chains
                         if isinstance(item, ProjectedProviderKeyedChain)}
            if (type(pending_chains) is not tuple or len(pending_chains) != 2
                    or type(projected_chains) is not tuple or len(projected_chains) != 2
                    or tuple(pending) != source.chain_ids or set(projected) != set(pending)
                    or any(chain.engagement_id != source.engagement_id
                           or chain.status != "pending" or chain.nodes or chain.burned
                           or chain.deploy_job_id or chain.teardown_job_id
                           or chain.terraform_working_directory or chain.edge_count != 1
                           or len(chain.edge_intents or []) != 1 for chain in pending_chains)):
                raise ValueError("mixed pending chain generation differs")
            for index, (provider, chain_id) in enumerate(zip(
                    source.ordered_providers, source.chain_ids, strict=True)):
                chain = pending[chain_id]
                nodes = projected[chain_id].chain.nodes
                hosts = source.host_rows[index * 2:index * 2 + 2]
                if (chain.middle_provider != provider or chain.edge_provider != provider
                        or projected[chain_id].chain != replace(chain, nodes=nodes)
                        or len(nodes) != 2
                        or [node.get("role") for node in nodes] != ["middle", "edge"]
                        or [node.get("componentId") for node in nodes] != ["middle", "edge-01"]
                        or any(node.get("chainId") != chain_id
                               or node.get("provider") != provider
                               or node.get("status") != "pending"
                               or node.get("hostname") != host.hostname
                               or node.get("terraformAddress") != host.terraform_address
                               or node.get("providerInstanceId") != host.provider_instance_id
                               or node.get("publicIp") != host.public_ip
                               or node.get("assignedProxy") != host.assigned_proxy
                               or host.chain_id != chain_id or host.provider != provider
                               for node, host in zip(nodes, hosts, strict=True))):
                    raise ValueError("mixed projected hosts differ")
            if (len({row.hostname for row in source.host_rows}) != 4
                    or len({row.terraform_address for row in source.host_rows}) != 4
                    or len({(row.provider, row.provider_instance_id)
                            for row in source.host_rows}) != 4):
                raise ValueError("mixed host identity repeats")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            raise ProviderKeyedPublicationConflict("mixed source or proof differs") from exc

        try:
            # The no-op CAS takes SQLite's writer slot before any source rows
            # are reread. Every change below is committed or rolled back once.
            changed = db.session.execute(text("""
                UPDATE job_runs SET status = status WHERE id = :id
                AND action = 'provider_keyed_mixed_initial'
                AND status = 'running' AND finished_at IS NULL
            """), {"id": parent.id})
            if changed.rowcount != 1 or datetime.now(timezone.utc) >= expiry:
                raise ValueError("mixed parent claim changed")
            db.session.expire_all()
            jobs = SqlAlchemyJobRepository()
            saved_parent, saved_child = jobs.get(parent.id), jobs.get(proof_child.id)
            if (saved_parent is None or saved_child is None
                    or saved_parent.input != parent.input or saved_parent.status != parent.status
                    or saved_parent.events != parent.events
                    or job_event_digest(saved_parent.events) != expected_parent_event_digest
                    or saved_child.input != proof_child.input
                    or saved_child.status != proof_child.status
                    or saved_child.events != proof_child.events
                    or job_event_digest(saved_child.events) != expected_child_event_digest):
                raise ValueError("mixed parent or proof child changed")
            validate_receipt_child(source, saved_child, receipt)
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=source.engagement_id, owner_id=source.core_plan_id,
                operation="provider_keyed_initial").one_or_none()
            plan = db.session.query(DeploymentPlanModel).filter_by(
                id=source.core_plan_id, engagement_id=source.engagement_id,
                revision_id=source.revision_id, status="applied", stage="applied",
                apply_job_id=source.core_job_id).one_or_none()
            engagement = db.session.query(EngagementModel).filter_by(
                id=source.engagement_id, sketch_state_schema="provider-keyed-v2").one_or_none()
            core = jobs.get(source.core_job_id)
            target = normalized_oci_deployment_target(
                engagement.input_parameters.get("deploymentTarget")) if engagement else None
            authorization = plan.evidence.get("sketchAuthorization") if plan else None
            fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain)
                            for chain in pending_chains}
            if (lease is None or plan is None or engagement is None or core is None
                    or target is None or target["name"] != "barragan-testing"
                    or core.action != "pilot_standard_rti_guarded_execute"
                    or core.status != "succeeded" or core.finished_at is None
                    or core.requested_by != parent.requested_by
                    or core.target_type != "oci_compartment"
                    or core.target != f"oci-compartment:{target['name']}"
                    or core.target_id != target["compartmentId"]
                    or core.input.get("engagementId") != source.engagement_id
                    or core.input.get("corePlanId") != source.core_plan_id
                    or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                    or core.input.get("postCoreSketchContinuationEligible") is not False
                    or core.input.get("pendingSketchChainIds") != list(source.chain_ids)
                    or core.input.get("pendingSketchChainFingerprints") != fingerprints
                    or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or plan.evidence.get("pendingSketchChainIds") != list(source.chain_ids)
                    or plan.evidence.get("pendingSketchChainFingerprints") != fingerprints
                    or not isinstance(authorization, dict)
                    or authorization.get("kind") != "bounded-mixed-post-core-v1"
                    or authorization.get("fingerprint") != parent.input.get("reviewFingerprint")
                    or mixed_digest({key: value for key, value in authorization.items()
                                     if key != "fingerprint"}) != authorization["fingerprint"]
                    or plan.review.get("reviewedConfiguration", {}).get("sketchAuthorization")
                    != authorization):
                raise ValueError("mixed reviewed core changed")
            binding, bootstrap = (jobs.get(_binding_child_id(source.core_job_id)),
                                  jobs.get(_worker_id(source.core_job_id)))
            if (binding is None or bootstrap is None
                    or binding.input.get("manifestSha256") != source.binding_manifest_sha256
                    or binding.input.get("handoffJournalSha256") != source.parent_journal_sha256
                    or bootstrap.status != "succeeded"
                    or job_event_digest(bootstrap.events) != source.host_worker_journal_sha256):
                raise ValueError("mixed host source changed")
            admin = retrieve_sketch_ssh_key(source.engagement_id)
            transport = retrieve_sketch_transport_ssh_key(source.engagement_id)
            if (admin is None or transport is None
                    or _key_digest(admin.public_key.strip() + "\n") != receipt.admin_key_sha256
                    or _key_digest(transport.public_key.strip() + "\n")
                    != receipt.transport_key_sha256):
                raise ValueError("mixed retained host keys changed")
            for provider, state in zip(source.ordered_providers, source.provider_states, strict=True):
                apply_child = jobs.get(apply_child_id(source.core_job_id, provider))
                if (apply_child is None or state.provider != provider
                        or job_event_digest(apply_child.events) != state.terminal_journal_sha256):
                    raise ValueError("mixed provider terminal changed")
                terminal = recognize_mixed_initial_apply_terminal(apply_child, parent, provider)
                if (str(Path(terminal["planPath"]).parent) != provider_workspaces[provider]
                        or terminal["proof"]["stateSha256"] != state.state_sha256
                        or terminal["proof"]["lineage"] != state.lineage
                        or terminal["proof"]["serial"] != state.serial
                        or terminal["proof"]["resourceIds"] != dict(state.resource_ids)):
                    raise ValueError("mixed provider workspace or state changed")
            rows = db.session.query(SketchChainModel).filter_by(
                engagement_id=source.engagement_id).all()
            current = {row.chain_id: row for row in rows if row.chain_id in fingerprints}
            if (set(current) != set(fingerprints)
                    or any(not _inert_aborted_intent(_from_model(row), source.engagement_id)
                           for row in rows if row.chain_id not in fingerprints)
                    or any(_from_model(current[chain.chain_id]) != chain
                           for chain in pending_chains)):
                raise ValueError("mixed pending rows changed")
            for chain in pending_chains:
                row = current[chain.chain_id]
                row.status = "deployed"
                row.nodes = [{**node, "status": "deployed"}
                             for node in projected[chain.chain_id].chain.nodes]
                row.deploy_job_id = parent.id
                row.terraform_working_directory = provider_workspaces[chain.middle_provider]
            parent_row = db.session.query(JobRunModel).filter_by(id=parent.id).one()
            child_row = db.session.query(JobRunModel).filter_by(id=proof_child.id).one()
            parent_row.status = child_row.status = "succeeded"
            parent_row.finished_at = child_row.finished_at = finished
            parent_row.input = {**{key: value for key, value in parent.input.items()
                                   if not key.startswith("claim")}, "phase": "completed"}
            child_row.input = {key: value for key, value in proof_child.input.items()
                               if not key.startswith("claim")}
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1, level="info",
                message="mixed two-provider host proof published",
                data={"sourceSha256": proof_child.events[-1].data["sourceSha256"],
                      "hostEvidenceSha256": receipt.host_evidence_sha256,
                      "chainIds": list(source.chain_ids),
                      "providerStates": [{"provider": state.provider,
                                          "stateSha256": state.state_sha256}
                                         for state in source.provider_states]},
            ))
            db.session.add(JobEventModel(
                job_id=proof_child.id, sequence=len(proof_child.events) + 1,
                level="info", message="mixed strict host proof published",
                data={"parentJobId": parent.id,
                      "hostEvidenceSha256": receipt.host_evidence_sha256},
            ))
            db.session.delete(lease)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise ProviderKeyedPublicationConflict("mixed two-provider publication stopped") from None
        return tuple(self.get(source.engagement_id, chain_id) for chain_id in source.chain_ids)

    def publish_provider_keyed_edge_append(
        self, *, parent: Any, before: StoredSketchChain, after: StoredSketchChain,
        other: StoredSketchChain, initial_source: Any, state_sha256: str,
        expected_event_digest: str, claim_owner: str, claim_token: str,
        finished_at: str,
    ) -> StoredSketchChain:
        """Commit the one-edge desired/deployed generation and receipt together.

        Provider, Terraform, and host proof belong to the caller's child
        journals. This writer only accepts their claimed terminal boundary; it
        never turns a failed or ambiguous apply into a published generation.
        """
        import re
        from dataclasses import asdict

        from sqlalchemy import text

        from app.storage.database import db
        from app.services.engagement_teardown import _fingerprint
        from app.services.provider_keyed_append_plan_job import _PLAN_EVENT_KEYS
        from app.services.provider_keyed_initial_plan_gate import _SOURCE_SHA256
        from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
        from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
        from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel, SketchChainModel

        digest = lambda value: type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        if not isinstance(initial_source, PublishedProviderKeyedSource):
            raise ProviderKeyedPublicationConflict("initial published source is unavailable")
        source_record = json.loads(json.dumps(asdict(initial_source), sort_keys=True))
        source_sha256 = _fingerprint(source_record)
        try:
            finished = datetime.fromisoformat(finished_at)
            expiry = datetime.fromisoformat(parent.input["claimExpiresAt"])
        except (TypeError, ValueError, KeyError, AttributeError):
            raise ProviderKeyedPublicationConflict("append publication time differs") from None
        if (not isinstance(parent, StoredJobRun) or not isinstance(parent.input, dict)
                or parent.action != "provider_keyed_edge_append" or parent.status != "running"
                or parent.finished_at is not None or not parent.started_at
                or parent.input.get("phase") != "awaiting_publication"
                or parent.input.get("engagementId") != before.engagement_id
                or parent.input.get("chainId") != before.chain_id
                or parent.input.get("initialSourceSha256") != source_sha256
                or initial_source.engagement_id != before.engagement_id
                or parent.input.get("mutation") is not True
                or parent.input.get("claimOwner") != claim_owner
                or parent.input.get("claimToken") != claim_token
                or parent.target_type != "engagement" or parent.target_id != before.engagement_id
                or parent.target != f"engagement:{before.engagement_id}"
                or finished.tzinfo is None or expiry.tzinfo is None
                or finished >= expiry or datetime.now(timezone.utc) >= expiry
                or not all(map(digest, (source_sha256, state_sha256,
                                        expected_event_digest)))
                or job_event_digest(parent.events) != expected_event_digest
                or not parent.events or parent.events[-1].message != "strict append host proof completed"
                or set(parent.events[-1].data) != {
                    "planJournalSha256", "applyJournalSha256", "hostProofJournalSha256",
                }
                or any(not digest(value) for value in parent.events[-1].data.values())
                or any(not isinstance(parent.input.get(key), str) or not parent.input[key]
                       for key in ("planJobId", "applyJobId", "hostProofJobId"))
                or len({parent.input[key] for key in ("planJobId", "applyJobId",
                                                      "hostProofJobId")}) != 3
                or before.engagement_id != other.engagement_id
                or before.chain_id == other.chain_id
                or before.status != "deployed" or other.status != "deployed"
                or before.edge_count != 1 or len(before.nodes) != 2
                or after.edge_count != 2 or len(after.nodes) != 3
                or after.engagement_id != before.engagement_id
                or after.chain_id != before.chain_id
                or after.status != "deployed" or after.deploy_job_id != before.deploy_job_id
                or after.teardown_job_id != before.teardown_job_id
                or after.terraform_working_directory != before.terraform_working_directory
                or after.burned or before.burned or other.burned
                or not isinstance(before.edge_intents, list) or len(before.edge_intents) != 1
                or not isinstance(after.edge_intents, list) or len(after.edge_intents) != 2
                or after.edge_intents[0] != before.edge_intents[0]
                or after.edge_intents[1].get("id") != "edge-02"
                or any(getattr(after, name) != getattr(before, name) for name in (
                    "assigned_proxy", "middle_provider", "middle_region", "middle_size",
                    "edge_provider", "edge_region", "edge_size", "created_at",
                ))):
            raise ProviderKeyedPublicationConflict("one-edge append publication differs")
        old_middle, old_edge, new_middle, new_old_edge, new_edge = (
            before.nodes[0], before.nodes[1], *after.nodes,
        )
        if (new_middle != old_middle
                or new_old_edge != {**old_edge, "edgeCount": "2"}
                or new_edge.get("chainId") != before.chain_id
                or new_edge.get("role") != "edge"
                or new_edge.get("provider") != "digitalocean"
                or new_edge.get("status") != "deployed"
                or new_edge.get("componentId") != "edge-02"
                or new_edge.get("edgeId") != "edge-02"
                or new_edge.get("edgeIndex") != "2"
                or new_edge.get("edgeCount") != "2"
                or new_edge.get("region") != after.edge_intents[1].get("region")
                or new_edge.get("assignedProxy") != before.assigned_proxy
                or new_edge.get("proxy") != before.assigned_proxy
                or not new_edge.get("providerInstanceId") or not new_edge.get("publicIp")
                or len({node.get("terraformAddress") for node in [*after.nodes, *other.nodes]}) != 5
                or len({node.get("providerInstanceId") for node in [*after.nodes, *other.nodes]}) != 5):
            raise ProviderKeyedPublicationConflict("retained or appended node identity differs")
        try:
            # The conditional write takes SQLite's writer slot before source
            # rows are reread. All changes commit as one transaction.
            changed = db.session.execute(text("""
                UPDATE job_runs SET status = status
                WHERE id = :id AND action = 'provider_keyed_edge_append'
                  AND status = 'running' AND finished_at IS NULL
            """), {"id": parent.id})
            if changed.rowcount != 1:
                raise ValueError("append parent claim changed")
            if datetime.now(timezone.utc) >= expiry:
                raise ValueError("append parent claim expired")
            db.session.expire_all()
            saved = SqlAlchemyJobRepository().get(parent.id)
            rows = db.session.query(SketchChainModel).filter_by(engagement_id=before.engagement_id).all()
            if (saved != parent or len(rows) != 2
                    or {row.chain_id for row in rows} != {before.chain_id, other.chain_id}
                    or any(_from_model(row) != expected for row, expected in (
                        (next(row for row in rows if row.chain_id == before.chain_id), before),
                        (next(row for row in rows if row.chain_id == other.chain_id), other),
                    ))):
                raise ValueError("append source rows changed")
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=before.engagement_id,
                owner_id=parent.input["corePlanId"],
                operation="provider_keyed_edge_append",
            ).one_or_none()
            if lease is None:
                raise ValueError("append lease changed")
            for kind, action, mutation in (
                ("plan", "provider_keyed_edge_append_plan", False),
                ("apply", "provider_keyed_edge_append_apply", True),
                ("hostProof", "provider_keyed_edge_append_host_proof", False),
            ):
                child = SqlAlchemyJobRepository().get(parent.input[f"{kind}JobId"])
                if (child is None or child.action != action or child.status != "succeeded"
                        or not child.finished_at or child.target != parent.target
                        or child.target_type != parent.target_type
                        or child.target_id != parent.target_id
                        or child.requested_by != (
                            parent.requested_by if kind == "plan" else
                            parent.input.get("applyRequestedBy", parent.requested_by))
                        or child.input.get("parentJobId") != parent.id
                        or child.input.get("mutation") is not mutation
                        or job_event_digest(child.events) !=
                        parent.events[-1].data[f"{kind}JournalSha256"]):
                    raise ValueError("append child journal changed")
                if kind == "apply" and (not child.events
                        or child.events[-1].data.get("stateSha256") != state_sha256):
                    raise ValueError("append apply state digest differs")
                if kind == "plan":
                    plan_data = child.events[-1].data if child.events else None
                    reviews = [event for event in parent.events
                               if event.message == "provider append plan ready for review"]
                    if (not isinstance(plan_data, dict) or set(plan_data) != _PLAN_EVENT_KEYS
                            or len(reviews) != 1 or reviews[0].level != "info"
                            or reviews[0].data != {
                                "planJobId": child.id, "planSha256": plan_data["planSha256"]}
                            or parent.input.get("planJournalSha256") != job_event_digest(child.events)
                            or plan_data["initialSourceSha256"] != source_sha256
                            or plan_data["initialSource"] != source_record
                            or plan_data["selectedChain"] != before.to_dict()
                            or plan_data["newEdgeAddress"] != new_edge["terraformAddress"]
                            or plan_data["planPath"] != str(Path(
                                before.terraform_working_directory) / ".barragan-edge-append.tfplan")
                            or plan_data["stateSha256"] != initial_source.state_sha256
                            or plan_data["sourceSha256"] != _SOURCE_SHA256
                            or any(not digest(plan_data[key]) for key in (
                                "planSha256", "stateSha256", "topologySha256", "sourceSha256",
                                "lockfileSha256", "credentialSecretSha256",
                                "terraformBinarySha256"))
                            or not isinstance(plan_data["inputSha256"], list)
                            or len(plan_data["inputSha256"]) != 1
                            or plan_data["inputSha256"][0] != [
                                str(Path(before.terraform_working_directory).parents[1]
                                    / ".plan-material" / "digitalocean" / "append-inputs.json"),
                                plan_data["inputSha256"][0][1],
                            ]
                            or not digest(plan_data["inputSha256"][0][1])
                            or any(not isinstance(plan_data[key], str) or not plan_data[key]
                                   for key in ("credentialRecordId", "credentialUpdatedAt",
                                               "terraformBinaryPath"))
                            or not isinstance(plan_data["retainedSharedIds"], dict)
                            or set(plan_data["retainedSharedIds"]) != {
                                "digitalocean_firewall.firewall", "digitalocean_ssh_key.key",
                            } or any(not isinstance(value, str) or not value
                                     for value in plan_data["retainedSharedIds"].values())):
                        raise ValueError("historical append source snapshot differs")
            from app.services.provider_keyed_append_apply_job import _completed_apply_child_receipt
            from app.services.provider_keyed_append_host_proof_job import (
                _completed_child_receipt, _host_evidence_path,
            )
            plan_sha = parent.input["planJournalSha256"]
            _completed_apply_child_receipt(
                SqlAlchemyJobRepository().get(parent.input["applyJobId"]),
                parent, plan_sha, plan_data,
                {str(node["providerInstanceId"])
                 for row in (before, other) for node in row.nodes})
            proof = SqlAlchemyJobRepository().get(parent.input["hostProofJobId"])
            reservation = [event for event in parent.events
                           if event.message == "strict append host proof reserved"]
            if (len(reservation) != 1
                    or set(reservation[0].data) != {"manifestSha256"}):
                raise ValueError("append host reservation differs")
            _completed_child_receipt(
                proof, parent, SqlAlchemyJobRepository().get(parent.input["applyJobId"]),
                reservation[0].data["manifestSha256"], {
                    "newEdgeAddress": new_edge["terraformAddress"],
                    "newEdgeProviderId": new_edge["providerInstanceId"],
                    "stateSha256": state_sha256,
                }, _host_evidence_path(Path(before.terraform_working_directory), parent.id),
                selected=after, jobs=SqlAlchemyJobRepository())
            row = next(row for row in rows if row.chain_id == before.chain_id)
            row.edge_count = 2
            row.edge_intents = after.edge_intents
            row.nodes = after.nodes
            row.updated_at = datetime.fromisoformat(after.updated_at)
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1, level="info",
                message="provider one-edge append published",
                data={"initialSource": source_record, "stateSha256": state_sha256},
            ))
            saved_row = db.session.get(JobRunModel, parent.id)
            saved_row.status = "succeeded"
            saved_row.finished_at = finished
            saved_row.input = {**{key: value for key, value in parent.input.items()
                                  if not key.startswith("claim")}, "phase": "completed"}
            db.session.delete(lease)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise ProviderKeyedPublicationConflict("one-edge append publication stopped") from None
        result = self.get(before.engagement_id, before.chain_id)
        if result is None:
            raise ProviderKeyedPublicationConflict("published append row is unavailable")
        return result

    def publish_provider_keyed_pending_group_retired(
        self, *, coordinator, prior_chains: tuple[StoredSketchChain, StoredSketchChain],
        prior_all_chains: tuple[StoredSketchChain, ...],
        prior_records: tuple, group_apply_job_id: str, resource_ids: dict[str, str],
        chain_fingerprints: dict[str, str], proof: dict, authority,
        allowed_record_origins: frozenset[str],
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        """Atomically retire an unmaterialized two-chain generation after exact absence.

        This is deliberately separate from deployed-chain retirement. It keeps
        the empty deployment IDs and reviewed desired intent for redeployment.
        """
        import re

        from sqlalchemy import text, update

        from app.domain import JobEvent
        from app.services.engagement_teardown import _fingerprint
        from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
        from app.services.provider_keyed_runtime_preflight import _inert_aborted_intent
        from app.storage.database import db
        from app.storage.job_repository import (
            SqlAlchemyJobRepository, _PROVIDER_ABSENT_PROOF_KEYS, _parse_datetime,
            _sqlalchemy_apply_input_conditions, _utc_instant,
            _valid_provider_absent_handoff, job_event_digest,
        )
        from app.storage.models import (
            JobEventModel, JobRunModel, ProviderResourceRecordModel, SketchChainModel,
        )
        from app.storage.provider_resource_repository import (
            TERMINAL_RECORD_STATUSES, _from_model as provider_record_from_model,
            is_barragan_owned_record,
        )

        def kind(record) -> str | None:
            return {
                "droplet": "digitalocean_droplet", "digitalocean_droplet": "digitalocean_droplet",
                "firewall": "digitalocean_firewall", "digitalocean_firewall": "digitalocean_firewall",
                "ssh_key": "digitalocean_ssh_key", "digitalocean_ssh_key": "digitalocean_ssh_key",
            }.get(record.resource_type.lower().replace("-", "_"))

        expected = {row.chain_id: row for row in prior_chains}
        all_expected = {row.chain_id: row for row in prior_all_chains}
        digest = job_event_digest(coordinator.events)
        if (len(coordinator.events) not in (6, 13, 17)
                or [event.sequence for event in coordinator.events]
                != list(range(1, len(coordinator.events) + 1))
                or coordinator.events[-1].level != "info"
                or coordinator.events[-1].message != "provider_absent"
                or type(coordinator.events[-1].data) is not dict):
            raise ProviderKeyedPublicationConflict("pending absence journal differs")
        absent = coordinator.events[-1].data
        ready_event = coordinator.events[-2]
        ready_data = ready_event.data
        inspector_ids = ({ready_data.get("hostRecordId"), ready_data.get("firewallRecordId")}
                         if type(ready_data) is dict else set())
        ready = replace(coordinator, input={**coordinator.input, "phase": "inspector_ready"},
                        events=coordinator.events[:-1])
        absent_proof = {key: value for key, value in absent.items() if key != "observedAt"}
        ids_by_kind = {
            "digitalocean_droplet": {value for key, value in resource_ids.items()
                                     if key.startswith("digitalocean_droplet.")},
            "digitalocean_firewall": {resource_ids.get("digitalocean_firewall.firewall")},
            "digitalocean_ssh_key": {resource_ids.get("digitalocean_ssh_key.key")},
        }
        expected_proof_keys = {
            "scopeSnapshotId", "providerScopeSha256", "sourceJournalSha256",
            "applyJobId", "resourceIdsSha256", "verifiedAbsentDropletIds",
            "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId",
            "confirmationCompletedAt", "confirmationExpiresAt",
        }
        if (not callable(authority) or type(prior_records) is not tuple
                or type(resource_ids) is not dict or type(chain_fingerprints) is not dict
                or type(allowed_record_origins) is not frozenset
                or not allowed_record_origins
                or len(prior_chains) != 2 or len(expected) != 2
                or type(prior_all_chains) is not tuple
                or len(all_expected) != len(prior_all_chains)
                or not set(expected).issubset(all_expected)
                or any(all_expected[row.chain_id] != row for row in prior_chains)
                or any(not _inert_aborted_intent(row, coordinator.target_id)
                       for row in prior_all_chains if row.chain_id not in expected)
                or set(chain_fingerprints) != set(expected)
                or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
                       for value in chain_fingerprints.values())
                or any(sketch_chain_intent_fingerprint(row) != chain_fingerprints[row.chain_id]
                       for row in prior_chains)
                or coordinator.action != "provider_keyed_comprehensive_teardown"
                or coordinator.status != "running" or coordinator.finished_at is not None
                or coordinator.input.get("phase") != "provider_absent"
                or ready_event.message not in {
                    "retained_inspector_ready", "inspector selected-source proof published"}
                or len(inspector_ids) != 2
                or any(type(value) is not str or not value for value in inspector_ids)
                or coordinator.target_type != "engagement"
                or coordinator.target != f"engagement:{coordinator.target_id}"
                or not coordinator.started_at or coordinator.artifact_refs != []
                or set(absent) != _PROVIDER_ABSENT_PROOF_KEYS | {"observedAt"}
                or not _valid_provider_absent_handoff(ready, job_event_digest(ready.events), absent_proof)
                or _utc_instant(absent["observedAt"]) is None
                or not (_utc_instant(absent["confirmationCompletedAt"])
                        <= _utc_instant(absent["observedAt"])
                        < _utc_instant(absent["confirmationExpiresAt"]))
                or set(proof) != expected_proof_keys
                or _utc_instant(proof["confirmationCompletedAt"]) is None
                or _utc_instant(proof["confirmationExpiresAt"]) is None
                or not (_utc_instant(proof["confirmationCompletedAt"])
                        < _utc_instant(proof["confirmationExpiresAt"])
                        <= _utc_instant(proof["confirmationCompletedAt"])
                        + timedelta(seconds=30))
                or proof["sourceJournalSha256"] != digest
                or proof["scopeSnapshotId"] != coordinator.input.get("scopeSnapshotId")
                or proof["providerScopeSha256"] != coordinator.input.get("providerScopeSha256")
                or proof["applyJobId"] != group_apply_job_id
                or absent["applyJobId"] != group_apply_job_id
                or proof["resourceIdsSha256"] != _fingerprint(resource_ids)
                or absent["resourceIdsSha256"] != proof["resourceIdsSha256"]
                or proof["verifiedAbsentDropletIds"] != sorted(ids_by_kind["digitalocean_droplet"])
                or proof["verifiedAbsentFirewallId"] != resource_ids.get("digitalocean_firewall.firewall")
                or proof["verifiedAbsentSshKeyId"] != resource_ids.get("digitalocean_ssh_key.key")
                or any(absent[key] != proof[key] for key in (
                    "verifiedAbsentDropletIds", "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId"))
                or any(type(value) is not str or not value for value in resource_ids.values())
                or any(not (key.startswith("digitalocean_droplet.") or key in {
                    "digitalocean_firewall.firewall", "digitalocean_ssh_key.key"
                } | _KEYED_LOCAL_FILES)
                    for key in resource_ids)
                or (bool(_KEYED_LOCAL_FILES.intersection(resource_ids))
                    and not _KEYED_LOCAL_FILES.issubset(resource_ids))
                or any(row.engagement_id != coordinator.target_id or row.status != "pending"
                       or row.deploy_job_id or row.teardown_job_id or row.nodes
                       or row.terraform_working_directory
                       for row in prior_chains)):
            raise ProviderKeyedPublicationConflict("pending group retirement authority differs")
        for record in prior_records:
            if record.engagement_id != coordinator.target_id:
                raise ProviderKeyedPublicationConflict("provider resource engagement differs")
            if record.id in inspector_ids and _canonical_keyed_inspector_record(record):
                continue
            if str(record.status).lower() in TERMINAL_RECORD_STATUSES:
                record_kind = kind(record)
                if (record.provider == "digitalocean" and is_barragan_owned_record(record)
                        and record.adoption_job_id in allowed_record_origins
                        and record_kind is not None
                        and record.resource_id in ids_by_kind[record_kind]):
                    raise ProviderKeyedPublicationConflict("historical provider record is ambiguous")
                continue
            record_kind = kind(record)
            if (record.provider != "digitalocean" or not is_barragan_owned_record(record)
                    or record_kind is None or record.resource_id not in ids_by_kind[record_kind]
                    or record.adoption_job_id not in allowed_record_origins):
                raise ProviderKeyedPublicationConflict("unexpected active provider resource record")

        try:
            if db.session.get_bind().dialect.name != "sqlite":
                raise ProviderKeyedPublicationConflict("pending retirement requires SQLite")
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == coordinator.id,
                JobRunModel.action == coordinator.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.created_at == _parse_datetime(coordinator.created_at),
                JobRunModel.started_at == _parse_datetime(coordinator.started_at),
                JobRunModel.target == coordinator.target,
                JobRunModel.target_type == coordinator.target_type,
                JobRunModel.target_id == coordinator.target_id,
                JobRunModel.requested_by == coordinator.requested_by,
                JobRunModel.artifact_refs == [],
                *_sqlalchemy_apply_input_conditions(JobRunModel, coordinator.input),
                text("julianday('now') >= julianday(:completed) AND "
                     "julianday('now') < julianday(:expires)").bindparams(
                         completed=proof["confirmationCompletedAt"],
                         expires=proof["confirmationExpiresAt"]),
            ).values(input={**coordinator.input, "phase": "pending_group_retired"}))
            if changed.rowcount != 1:
                raise ProviderKeyedPublicationConflict("pending retirement CAS lost")
            journal = db.session.query(JobEventModel).filter_by(job_id=coordinator.id).order_by(
                JobEventModel.sequence.asc()).all()
            if ([JobEvent(row.sequence, row.level, row.message, row.data) for row in journal]
                    != coordinator.events or job_event_digest(coordinator.events) != digest):
                raise ProviderKeyedPublicationConflict("pending retirement journal changed")
            db.session.expire_all()
            authority()
            rows = db.session.query(SketchChainModel).filter_by(
                engagement_id=coordinator.target_id).all()
            if (len(rows) != len(prior_all_chains)
                    or {row.chain_id for row in rows} != set(all_expected)):
                raise ProviderKeyedPublicationConflict("complete pending chain set changed")
            active_rows = []
            for row in rows:
                stored = _from_model(row)
                if stored != all_expected[row.chain_id]:
                    raise ProviderKeyedPublicationConflict("complete pending chain set changed")
                if row.chain_id in expected:
                    if sketch_chain_intent_fingerprint(stored) != chain_fingerprints[row.chain_id]:
                        raise ProviderKeyedPublicationConflict("pending chain intent changed")
                    active_rows.append(row)
                elif not _inert_aborted_intent(stored, coordinator.target_id):
                    raise ProviderKeyedPublicationConflict("aborted chain is no longer inert")
            records = db.session.query(ProviderResourceRecordModel).filter_by(
                engagement_id=coordinator.target_id).all()
            if tuple(sorted((provider_record_from_model(row) for row in records),
                            key=lambda item: item.id)) != prior_records:
                raise ProviderKeyedPublicationConflict("provider resource records changed")
            observed = db.session.execute(text(
                "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')"
            )).scalar_one()
            fresh = db.session.execute(text(
                "SELECT julianday(:completed) <= julianday(:observed) "
                "AND julianday(:observed) < julianday(:expires)"
            ), {"completed": proof["confirmationCompletedAt"],
                "observed": observed, "expires": proof["confirmationExpiresAt"]}).scalar_one()
            if fresh != 1:
                raise ProviderKeyedPublicationConflict("pending retirement proof expired")
            moment = datetime.fromisoformat(observed)
            retired_ids = []
            for row in active_rows:
                row.status = "destroyed"
                row.nodes = []
                row.teardown_job_id = group_apply_job_id
                row.updated_at = moment
            for row in records:
                record = provider_record_from_model(row)
                if (record.id in inspector_ids and _canonical_keyed_inspector_record(record)
                        or str(record.status).lower() in TERMINAL_RECORD_STATUSES):
                    continue
                row.status = "destroyed"
                row.lifecycle_state = "destroyed"
                row.destroyed_at = moment
                row.updated_at = moment
                retired_ids.append(row.id)
            db.session.add(JobEventModel(
                job_id=coordinator.id, sequence=len(coordinator.events) + 1,
                level="info", message="keyed_pending_provider_group_retired",
                data={**proof, "chainIds": sorted(expected),
                      "chainFingerprints": {key: chain_fingerprints[key] for key in sorted(expected)},
                      "retiredRecordIds": sorted(retired_ids), "observedAt": observed},
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return tuple(self.get(coordinator.target_id, chain_id) for chain_id in sorted(expected))

    def publish_provider_keyed_group_retired(
        self, *, coordinator, prior_chains: tuple[StoredSketchChain, StoredSketchChain],
        prior_records: tuple, group_apply_job_id: str, resource_ids: dict[str, str],
        proof: dict, authority, prior_chain_projection_sha256: str | None = None,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        """Retire both keyed runtime projections and journal in one SQLite commit.

        The caller must have freshly GET-proved exact provider absence. This
        transaction preserves topology, deployment history, and workspace.
        """
        import re

        from sqlalchemy import text, update

        from app.domain import JobEvent
        from app.services.engagement_teardown import _fingerprint
        from app.storage.database import db
        from app.storage.job_repository import (
            SqlAlchemyJobRepository, _PROVIDER_ABSENT_PROOF_KEYS, _parse_datetime,
            _sqlalchemy_apply_input_conditions, _utc_instant,
            _valid_provider_absent_handoff, job_event_digest,
            _inspector_prefix_boundary, _inspector_prefix_still_matches,
        )
        from app.storage.models import (
            JobEventModel, JobRunModel, ProviderResourceRecordModel, SketchChainModel,
        )
        from app.storage.provider_resource_repository import (
            TERMINAL_RECORD_STATUSES, _from_model as provider_record_from_model,
            is_barragan_owned_record,
        )

        def record_kind(record) -> str | None:
            kind = record.resource_type.lower().replace("-", "_")
            return {
                "droplet": "digitalocean_droplet", "digitalocean_droplet": "digitalocean_droplet",
                "firewall": "digitalocean_firewall", "digitalocean_firewall": "digitalocean_firewall",
                "ssh_key": "digitalocean_ssh_key", "digitalocean_ssh_key": "digitalocean_ssh_key",
            }.get(kind)

        expected = {row.chain_id: row for row in prior_chains}
        if prior_chain_projection_sha256 is not None and (
                type(prior_chain_projection_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", prior_chain_projection_sha256) is None
                or prior_chain_projection_sha256 != _fingerprint({
                    row.chain_id: row.to_dict() for row in prior_chains
                })):
            raise ProviderKeyedPublicationConflict("sealed prior chain projection differs")
        prior_digest = job_event_digest(coordinator.events)
        if (len(coordinator.events) not in (6, 13, 17)
                or coordinator.events[-1].sequence != len(coordinator.events)
                or coordinator.events[-1].level != "info"
                or coordinator.events[-1].message != "provider_absent"
                or [event.sequence for event in coordinator.events]
                != list(range(1, len(coordinator.events) + 1))
                or type(coordinator.events[-1].data) is not dict):
            raise ProviderKeyedPublicationConflict("prior absence journal differs")
        absent = coordinator.events[-1].data
        ready = replace(coordinator, input={**coordinator.input, "phase": "inspector_ready"},
                        events=coordinator.events[:-1])
        absent_proof = {key: value for key, value in absent.items() if key != "observedAt"}
        jobs = SqlAlchemyJobRepository()
        prefix_boundary = _inspector_prefix_boundary(ready, jobs.get)
        if prefix_boundary is None:
            raise ProviderKeyedPublicationConflict("keyed retirement parent prefix differs")
        if (set(absent) != _PROVIDER_ABSENT_PROOF_KEYS | {"observedAt"}
                or not _valid_provider_absent_handoff(
                    ready, job_event_digest(ready.events), absent_proof, prefix_boundary[0])
                or _utc_instant(absent["observedAt"]) is None
                or not (_utc_instant(absent["confirmationCompletedAt"])
                        <= _utc_instant(absent["observedAt"])
                        < _utc_instant(absent["confirmationExpiresAt"]))
                or absent["applyJobId"] != group_apply_job_id
                or absent["scopeSnapshotId"] != coordinator.input.get("scopeSnapshotId")
                or absent["providerScopeSha256"] != coordinator.input.get("providerScopeSha256")
                or absent["resourceIdsSha256"] != _fingerprint(resource_ids)):
            raise ProviderKeyedPublicationConflict("prior absence proof differs")
        ids_by_kind = {
            "digitalocean_droplet": {v for k, v in resource_ids.items()
                                     if k.startswith("digitalocean_droplet.")},
            "digitalocean_firewall": {resource_ids.get("digitalocean_firewall.firewall")},
            "digitalocean_ssh_key": {resource_ids.get("digitalocean_ssh_key.key")},
        }
        if (not callable(authority) or len(expected) != 2
                or type(prior_records) is not tuple or type(resource_ids) is not dict
                or any(not (key.startswith("digitalocean_droplet.") or key in {
                    "digitalocean_firewall.firewall", "digitalocean_ssh_key.key"
                } | _KEYED_LOCAL_FILES)
                    for key in resource_ids)
                or (bool(_KEYED_LOCAL_FILES.intersection(resource_ids))
                    and not _KEYED_LOCAL_FILES.issubset(resource_ids))
                or {value for key, value in resource_ids.items()
                    if key not in _KEYED_LOCAL_FILES} != set().union(*ids_by_kind.values())
                or any(type(value) is not str or not value for value in resource_ids.values())
                or coordinator.action != "provider_keyed_comprehensive_teardown"
                or coordinator.status != "running" or coordinator.finished_at is not None
                or coordinator.input.get("phase") != "provider_absent"
                or coordinator.target_type != "engagement"
                or coordinator.target != f"engagement:{coordinator.target_id}"
                or coordinator.artifact_refs != [] or not coordinator.started_at
                or group_apply_job_id != proof.get("applyJobId")
                or set(proof) != {
                    "scopeSnapshotId", "providerScopeSha256", "sourceJournalSha256",
                    "applyJobId", "resourceIdsSha256", "verifiedAbsentDropletIds",
                    "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId",
                    "confirmationCompletedAt", "confirmationExpiresAt",
                }
                or proof["sourceJournalSha256"] != prior_digest
                or proof["scopeSnapshotId"] != coordinator.input.get("scopeSnapshotId")
                or proof["providerScopeSha256"] != coordinator.input.get("providerScopeSha256")
                or proof["verifiedAbsentDropletIds"] != sorted(ids_by_kind["digitalocean_droplet"])
                or proof["verifiedAbsentFirewallId"] not in ids_by_kind["digitalocean_firewall"]
                or proof["verifiedAbsentSshKeyId"] not in ids_by_kind["digitalocean_ssh_key"]
                or absent["verifiedAbsentDropletIds"] != proof["verifiedAbsentDropletIds"]
                or absent["verifiedAbsentFirewallId"] != proof["verifiedAbsentFirewallId"]
                or absent["verifiedAbsentSshKeyId"] != proof["verifiedAbsentSshKeyId"]
                or type(proof["resourceIdsSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", proof["resourceIdsSha256"]) is None
                or proof["resourceIdsSha256"] != _fingerprint(resource_ids)
                or any(row.engagement_id != coordinator.target_id
                       or row.status != "deployed" or row.teardown_job_id
                       or not row.deploy_job_id or not row.nodes
                       for row in prior_chains)
                or {str(node.get("providerInstanceId")) for row in prior_chains
                    for node in row.nodes} != ids_by_kind["digitalocean_droplet"]):
            raise ProviderKeyedPublicationConflict("keyed group retirement authority differs")
        for record in prior_records:
            if record.engagement_id != coordinator.target_id:
                raise ProviderKeyedPublicationConflict("provider resource engagement differs")
            if (record.resource_type in {"inspector", "inspector_firewall"}
                    or (isinstance(record.metadata, dict) and record.metadata.get("role") in {
                        "inspector", "inspector_firewall"})):
                continue
            if str(record.status).lower() in TERMINAL_RECORD_STATUSES:
                continue
            kind = record_kind(record)
            if (record.provider != "digitalocean" or not is_barragan_owned_record(record)
                    or kind is None or record.resource_id not in ids_by_kind[kind]
                    or record.adoption_job_id not in {
                        row.deploy_job_id for row in prior_chains}):
                raise ProviderKeyedPublicationConflict("unexpected active provider resource record")

        try:
            if db.session.get_bind().dialect.name != "sqlite":
                raise ProviderKeyedPublicationConflict("keyed retirement requires SQLite")
            # Conditional job write obtains the writer slot before any multi-row
            # publication; the entire operation rolls back on drift or crash.
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == coordinator.id,
                JobRunModel.action == coordinator.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.created_at == _parse_datetime(coordinator.created_at),
                JobRunModel.started_at == _parse_datetime(coordinator.started_at),
                JobRunModel.target == coordinator.target,
                JobRunModel.target_type == coordinator.target_type,
                JobRunModel.target_id == coordinator.target_id,
                JobRunModel.requested_by == coordinator.requested_by,
                JobRunModel.artifact_refs == [],
                *_sqlalchemy_apply_input_conditions(JobRunModel, coordinator.input),
                text("julianday('now') >= julianday(:completed) AND "
                     "julianday('now') < julianday(:expires)").bindparams(
                         completed=proof["confirmationCompletedAt"],
                         expires=proof["confirmationExpiresAt"]),
            ).values(input={**coordinator.input, "phase": "group_retired"}))
            if changed.rowcount != 1:
                raise ProviderKeyedPublicationConflict("keyed retirement CAS lost")
            journal = db.session.query(JobEventModel).filter_by(job_id=coordinator.id).order_by(
                JobEventModel.sequence.asc()).all()
            if ([JobEvent(row.sequence, row.level, row.message, row.data) for row in journal]
                    != coordinator.events):
                raise ProviderKeyedPublicationConflict("keyed retirement journal changed")
            db.session.expire_all()
            if not _inspector_prefix_still_matches(ready, prefix_boundary, jobs.get):
                raise ProviderKeyedPublicationConflict("keyed retirement parent changed")
            authority()
            rows = db.session.query(SketchChainModel).filter_by(
                engagement_id=coordinator.target_id).all()
            from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
            try:
                selected = reviewed_mixed_chain_rows(
                    [_from_model(row) for row in rows], tuple(expected), coordinator.target_id)
            except ValueError:
                raise ProviderKeyedPublicationConflict("keyed chain set changed") from None
            rows = [row for row in rows if row.chain_id in {chain.chain_id for chain in selected}]
            if {row.chain_id for row in rows} != set(expected):
                raise ProviderKeyedPublicationConflict("keyed chain set changed")
            for row in rows:
                if _from_model(row) != expected[row.chain_id]:
                    raise ProviderKeyedPublicationConflict("keyed chain runtime changed")
            if prior_chain_projection_sha256 is not None:
                parent = db.session.get(JobRunModel, coordinator.input.get("teardownParentId"))
                sealed = (parent.input.get("publishedSource") if parent is not None
                          and isinstance(parent.input, dict) else None)
                appended = (parent.input.get("publishedAppendSource") if parent is not None
                            and isinstance(parent.input, dict) else None)
                if (type(sealed) is not dict
                        or _fingerprint({row.chain_id: _from_model(row).to_dict()
                                         for row in rows}) != prior_chain_projection_sha256):
                    raise ProviderKeyedPublicationConflict("sealed prior chain projection changed")
                if appended is None:
                    if sealed.get("chain_projection_sha256") != prior_chain_projection_sha256:
                        raise ProviderKeyedPublicationConflict("sealed prior chain projection changed")
                else:
                    append_job = SqlAlchemyJobRepository().get(appended.get("append_job_id"))
                    scope = parent.input.get("scopeSnapshot", {}).get("providerScopes", [None])[0]
                    droplet_ids = {item.get("address"): item.get("id")
                                   for item in scope.get("resources", [])
                                   if item.get("kind") == "droplet"} if type(scope) is dict else {}
                    projected = {node.get("terraformAddress"): node.get("providerInstanceId")
                                 for row in rows for node in _from_model(row).nodes}
                    if (type(appended) is not dict or appended.get("initial_source") != sealed
                            or append_job is None or append_job.status != "succeeded"
                            or job_event_digest(append_job.events) != appended.get("append_journal_sha256")
                            or appended.get("state_sha256") != scope.get("stateSha256")
                            or len(droplet_ids) != 5 or projected != droplet_ids
                            or len(projected) != 5
                            or projected.get(appended.get("new_edge_address")) !=
                               appended.get("new_edge_provider_id")):
                        raise ProviderKeyedPublicationConflict("sealed appended projection changed")
            records = db.session.query(ProviderResourceRecordModel).filter_by(
                engagement_id=coordinator.target_id).all()
            if tuple(sorted((provider_record_from_model(row) for row in records),
                            key=lambda item: item.id)) != prior_records:
                raise ProviderKeyedPublicationConflict("provider resource records changed")
            observed = db.session.execute(text(
                "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')"
            )).scalar_one()
            fresh = db.session.execute(text(
                "SELECT julianday(:completed) <= julianday(:observed) "
                "AND julianday(:observed) < julianday(:expires)"
            ), {"completed": proof["confirmationCompletedAt"],
                "observed": observed, "expires": proof["confirmationExpiresAt"]}).scalar_one()
            if fresh != 1:
                raise ProviderKeyedPublicationConflict("keyed retirement proof expired")
            moment = datetime.fromisoformat(observed)
            retired_ids = []
            for row in rows:
                row.status = "destroyed"
                row.nodes = []
                row.teardown_job_id = group_apply_job_id
                row.updated_at = moment
            for row in records:
                record = provider_record_from_model(row)
                if (record.resource_type in {"inspector", "inspector_firewall"}
                        or isinstance(record.metadata, dict) and record.metadata.get("role") in {
                            "inspector", "inspector_firewall"}
                        or str(record.status).lower() in TERMINAL_RECORD_STATUSES):
                    continue
                row.status = "destroyed"
                row.lifecycle_state = "destroyed"
                row.destroyed_at = moment
                row.updated_at = moment
                retired_ids.append(row.id)
            db.session.add(JobEventModel(
                job_id=coordinator.id, sequence=len(coordinator.events) + 1,
                level="info", message="keyed_provider_group_retired",
                data={**proof, **({"priorChainProjectionSha256": prior_chain_projection_sha256}
                                if prior_chain_projection_sha256 is not None else {}),
                      "chainIds": sorted(expected),
                      "retiredRecordIds": sorted(retired_ids), "observedAt": observed},
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return tuple(self.get(coordinator.target_id, chain_id) for chain_id in sorted(expected))

    def append_provider_keyed_host_proof_event(
        self, child, event, *, owner: str, token: str, started_at: str,
        terminal_status: str | None = None,
    ):
        """Append one child audit event under an exact SQLite CAS, never rewrite history."""
        from sqlalchemy import func, text, update
        from app.domain import JobEvent
        from app.storage.database import db
        from app.storage.job_repository import (
            SqlAlchemyJobRepository, StoredJobRun, _parse_datetime,
        )
        from app.storage.models import JobEventModel, JobRunModel

        append_proof = (isinstance(child, StoredJobRun)
                        and child.action == "provider_keyed_edge_append_host_proof")
        started_message = ("strict append host proof started" if append_proof
                           else "strict host proof started")
        complete_message = ("strict append host proof completed" if append_proof
                            else "strict host proof completed")
        stopped_message = ("strict append host proof stopped; reconciliation required"
                           if append_proof else "strict host proof stopped; reconciliation required")
        if (db.engine.dialect.name != "sqlite" or not isinstance(child, StoredJobRun)
                or child.action not in {"provider_keyed_initial_host_proof",
                                        "provider_keyed_edge_append_host_proof"}
                or child.status not in {"queued", "running"}
                or child.finished_at is not None
                or not isinstance(child.input, dict)
                or child.input.get("claimOwner") != owner
                or child.input.get("claimToken") != token
                or (child.events and child.events[-1].message == complete_message)
                or not isinstance(event, JobEvent)
                or event.sequence != len(child.events) + 1
                or terminal_status not in ({None, "failed", "succeeded"} if append_proof
                                           else {None, "failed"})
                or (terminal_status == "succeeded" and event.message != complete_message)
                or (child.status == "queued" and (
                    child.started_at is not None or (event.message != started_message
                        and not (terminal_status == "failed" and
                                 event.message == stopped_message))))):
            return None
        conditions = [
            text("(SELECT COUNT(*) FROM json_each(job_runs.input)) = :proof_input_count")
                .bindparams(proof_input_count=len(child.input)),
            *(condition for key, value in sorted(child.input.items())
              for condition in (
                  func.json_type(JobRunModel.input, f"$.{key}") ==
                      ("true" if value is True else "false" if value is False else "text"),
                  func.json_extract(JobRunModel.input, f"$.{key}") ==
                      (1 if value is True else 0 if value is False else value),
              )),
        ]
        try:
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == child.id,
                JobRunModel.action == child.action,
                JobRunModel.status == child.status,
                JobRunModel.finished_at.is_(None),
                JobRunModel.target == child.target,
                JobRunModel.target_type == child.target_type,
                JobRunModel.target_id == child.target_id,
                JobRunModel.requested_by == child.requested_by,
                *conditions,
            ).values(
                status=terminal_status or "running",
                started_at=_parse_datetime(started_at) if child.status == "queued" else _parse_datetime(child.started_at),
                finished_at=_parse_datetime(started_at) if terminal_status else None,
            ))
            if changed.rowcount != 1:
                db.session.rollback()
                return None
            journal = db.session.query(JobEventModel).filter_by(job_id=child.id).order_by(
                JobEventModel.sequence.asc()).all()
            persisted = [JobEvent(row.sequence, row.level, row.message, row.data) for row in journal]
            if persisted != child.events:
                db.session.rollback()
                return None
            db.session.add(JobEventModel(job_id=child.id, sequence=event.sequence,
                                         level=event.level, message=event.message, data=event.data))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return SqlAlchemyJobRepository().get(child.id)

    def publish_provider_keyed_initial_chains(
        self, *, parent, pending_chains: tuple[StoredSketchChain, StoredSketchChain],
        projected_chains, host_proof, host_evidence_sha256: str,
        state_sha256: str, manifest: dict, manifest_sha256: str,
        applied_workspace_path: str, expected_event_digest: str,
        proof_child, proof_child_event_digest: str,
        claim_owner: str, claim_token: str, finished_at: str,
    ) -> tuple[StoredSketchChain, StoredSketchChain]:
        """Atomically publish both v2 chains, finish the parent and release its exact lease.

        The caller must independently prove collection provenance and bind the
        complete raw host evidence to ``host_evidence_sha256``. This dormant
        storage primitive validates identity and atomicity, not remote hosts.
        """
        import re

        from sqlalchemy import String, cast, func, text, update

        from app.domain import JobEvent
        from app.services.provider_keyed_chain_projection import ProjectedProviderKeyedChain
        from app.services.provider_keyed_strict_host_proof import (
            StrictHostSetProof, verify_strict_command_journal,
        )
        from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
        from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
        from app.storage.database import db
        from app.storage.job_repository import (
            StoredJobRun, _parse_datetime, _sqlalchemy_apply_input_conditions,
            job_event_digest,
        )
        from app.storage.models import (
            CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel,
            JobEventModel, JobRunModel, SketchChainModel,
        )

        def digest(value):
            return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None

        if not isinstance(parent, StoredJobRun) or not isinstance(parent.input, dict):
            raise ProviderKeyedPublicationConflict("host-proof parent differs")
        try:
            finished = datetime.fromisoformat(finished_at)
            expiry = datetime.fromisoformat(parent.input["claimExpiresAt"])
            claimed = datetime.fromisoformat(parent.input["claimClaimedAt"])
            if any(value.tzinfo is None or value.utcoffset().total_seconds() != 0
                   for value in (finished, expiry, claimed)) or not claimed <= finished < expiry:
                raise ValueError
            if "claimHeartbeatAt" in parent.input:
                heartbeat = datetime.fromisoformat(parent.input["claimHeartbeatAt"])
                if (heartbeat.tzinfo is None or heartbeat.utcoffset().total_seconds() != 0
                        or not claimed <= heartbeat <= finished):
                    raise ValueError
        except (TypeError, ValueError, KeyError, AttributeError):
            raise ProviderKeyedPublicationConflict("host-proof claim time differs") from None
        inputs = parent.input
        engagement_id, core_id, plan_id = (inputs.get(key) for key in
                                            ("engagementId", "coreJobId", "corePlanId"))
        expected_keys = {"engagementId", "coreJobId", "corePlanId", "planJobId", "applyJobId",
                         "phase", "mutation", "claimOwner", "claimToken", "claimClaimedAt",
                         "claimExpiresAt"}
        if "claimHeartbeatAt" in inputs:
            expected_keys.add("claimHeartbeatAt")
        delayed = {"nextAttachmentCheckAt", "attachmentRecheckCount"}
        if delayed & set(inputs):
            expected_keys |= delayed
        if (parent.action != "provider_keyed_initial"
                or parent.status != "running" or parent.finished_at is not None or not parent.started_at
                or parent.target_type != "engagement" or parent.target_id != engagement_id
                or parent.target != f"engagement:{engagement_id}"
                or type(engagement_id) is not str or not engagement_id
                or any(type(value) is not str or not value for value in
                       (core_id, plan_id, claim_owner, claim_token))
                or set(inputs) != expected_keys or inputs.get("mutation") is not True
                or (delayed <= set(inputs) and (type(inputs["attachmentRecheckCount"]) is not int
                    or inputs["attachmentRecheckCount"] < 0
                    or type(inputs["nextAttachmentCheckAt"]) is not str
                    or not inputs["nextAttachmentCheckAt"]))
                or inputs.get("phase") != "awaiting_strict_host_proof"
                or inputs.get("claimOwner") != claim_owner
                or inputs.get("claimToken") != claim_token
                or parent.id != f"job-provider-keyed-initial-{core_id.removeprefix('job-')}"
                or inputs.get("planJobId") != f"job-provider-keyed-initial-plan-{core_id.removeprefix('job-')}"
                or inputs.get("applyJobId") != f"job-provider-keyed-initial-apply-{core_id.removeprefix('job-')}"
                or not all(map(digest, (host_evidence_sha256, state_sha256,
                                         manifest_sha256, expected_event_digest,
                                         proof_child_event_digest)))
                or not isinstance(pending_chains, tuple) or len(pending_chains) != 2
                or not isinstance(projected_chains, tuple) or len(projected_chains) != 2
                or type(host_proof) is not StrictHostSetProof
                or host_proof.raw_evidence_sha256 != host_evidence_sha256
                or [event.sequence for event in parent.events] != list(range(1, len(parent.events) + 1))
                or not parent.events or parent.events[-1].message !=
                "provider bootstrap completed; strict host proof pending"
                or parent.events[-1].data != {
                    "manifestSha256": manifest_sha256,
                    "chainIds": [chain.chain_id for chain in pending_chains],
                    "hostProofPending": True,
                }
                or job_event_digest(parent.events) != expected_event_digest):
            raise ProviderKeyedPublicationConflict("reviewed host-proof generation differs")
        if (not isinstance(proof_child, StoredJobRun)
                or proof_child.id != f"job-provider-keyed-initial-host-proof-{core_id.removeprefix('job-')}"
                or proof_child.action != "provider_keyed_initial_host_proof"
                or proof_child.status != "running" or proof_child.finished_at is not None
                or proof_child.target != parent.target
                or proof_child.target_type != parent.target_type
                or proof_child.target_id != engagement_id
                or proof_child.requested_by != parent.requested_by
                or proof_child.artifact_refs != []
                or not isinstance(proof_child.input, dict)
                or {key: value for key, value in proof_child.input.items()
                    if not key.startswith("claim")} != {
                        "engagementId": engagement_id, "coreJobId": core_id,
                        "corePlanId": plan_id, "parentJobId": parent.id,
                        "manifestSha256": manifest_sha256, "mutation": False,
                    }
                or proof_child.input.get("claimOwner") != claim_owner
                or proof_child.input.get("claimToken") != claim_token
                or not proof_child.events
                or [event.sequence for event in proof_child.events] !=
                   list(range(1, len(proof_child.events) + 1))
                or proof_child.events[-1].message != "strict host proof completed"
                or proof_child.events[-1].data != {
                    "hostEvidenceSha256": host_evidence_sha256,
                    "hostnames": list(host_proof.hostnames),
                }
                or job_event_digest(proof_child.events) != proof_child_event_digest):
            raise ProviderKeyedPublicationConflict("strict host proof child journal differs")
        binding_events = [event for event in parent.events if
                          event.message == "provider host identity binding intended"]
        if (type(manifest) is not dict or len(binding_events) != 1
                or binding_events[0].data != manifest
                or hashlib.sha256(json.dumps(manifest, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest() != manifest_sha256
                or manifest.get("stateSha256") != state_sha256
                or manifest.get("engagementId") != engagement_id
                or manifest.get("coreJobId") != core_id
                or manifest.get("corePlanId") != plan_id
                or type(applied_workspace_path) is not str
                or not Path(applied_workspace_path).is_absolute()
                or os.path.normpath(applied_workspace_path) != applied_workspace_path
                or manifest.get("sketchKnownHostsPath") != str(
                    Path(applied_workspace_path) / ".barragan-sketch-known-hosts")):
            raise ProviderKeyedPublicationConflict("sealed applied workspace differs")
        by_id = {chain.chain_id: chain for chain in pending_chains}
        projected = {item.chain.chain_id: item for item in projected_chains
                     if isinstance(item, ProjectedProviderKeyedChain)}
        if (len(by_id) != 2 or len(projected) != 2 or set(by_id) != set(projected)
                or any(chain.engagement_id != engagement_id or chain.status != "pending"
                       or type(chain.edge_count) is not int or chain.edge_count < 1
                       or not isinstance(chain.edge_intents, list)
                       or chain.nodes or chain.deploy_job_id or chain.teardown_job_id
                       or chain.terraform_working_directory or chain.burned
                       for chain in pending_chains)):
            raise ProviderKeyedPublicationConflict("pending chain set differs")
        if (manifest.get("chainFingerprints") != [
                {"chainId": chain.chain_id,
                 "fingerprint": sketch_chain_intent_fingerprint(chain)}
                for chain in pending_chains]
                or manifest.get("hostPolicies") != [
                    {"chainId": item.chain.chain_id,
                     "proxyEgressIp": item.proxy_egress_ip,
                     "hosts": item.host_policies}
                    for item in projected_chains]):
            raise ProviderKeyedPublicationConflict("reviewed route policy differs")
        expected_nodes = [row for item in projected_chains for row in item.chain.nodes]
        try:
            verify_strict_command_journal(proof_child.events, expected_nodes,
                                          manifest_sha256, host_evidence_sha256)
        except Exception:
            raise ProviderKeyedPublicationConflict("strict host command journal differs") from None
        if (any(item.chain != replace(by_id[item.chain.chain_id], nodes=item.chain.nodes)
                for item in projected_chains)
                or any(not isinstance(row, dict) or row.get("chainId") not in by_id
                       or row.get("provider") != "digitalocean" or row.get("status") != "pending"
                       or not row.get("hostname") or not row.get("providerInstanceId")
                       or not row.get("terraformAddress") or not row.get("publicIp")
                       for row in expected_nodes)
                or any(len(item.chain.nodes) != item.chain.edge_count + 1
                       or [row.get("role") for row in item.chain.nodes]
                       != ["middle", *(["edge"] * item.chain.edge_count)]
                       or [row.get("componentId") for row in item.chain.nodes]
                       != ["middle", *[edge["id"] for edge in item.chain.edge_intents]]
                       for item in projected_chains)
                or len(expected_nodes) != len({row["hostname"] for row in expected_nodes})
                or len(expected_nodes) != len({row["providerInstanceId"] for row in expected_nodes})
                or len(expected_nodes) != len({row["terraformAddress"] for row in expected_nodes})
                or host_proof.hostnames != tuple(sorted(row["hostname"] for row in expected_nodes))
                or host_proof.provider_instance_ids != tuple(
                    next(row["providerInstanceId"] for row in expected_nodes if row["hostname"] == name)
                    for name in host_proof.hostnames)
                or manifest.get("nodes") != sorted(({
                    "chainId": row["chainId"], "role": row["role"],
                    "providerInstanceId": row["providerInstanceId"],
                    "terraformAddress": row["terraformAddress"],
                    "name": row["hostname"], "publicIp": row["publicIp"],
                    "region": row["region"],
                } for row in expected_nodes), key=lambda row: row["terraformAddress"])):
            raise ProviderKeyedPublicationConflict("host-proof node coverage differs")
        try:
            # The first conditional write takes SQLite's writer lock. All
            # journal, lease and row checks then occur before the one commit.
            base_input = {key: value for key, value in inputs.items() if not key.startswith("claim")}
            base_input["phase"] = "completed"
            changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == parent.id,
                JobRunModel.action == parent.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.target == parent.target,
                JobRunModel.target_type == parent.target_type,
                JobRunModel.target_id == parent.target_id,
                JobRunModel.requested_by == parent.requested_by,
                JobRunModel.created_at == _parse_datetime(parent.created_at),
                cast(JobRunModel.started_at, String) == _parse_datetime(
                    parent.started_at).isoformat(sep=" "),
                JobRunModel.artifact_refs == parent.artifact_refs,
                *_sqlalchemy_apply_input_conditions(JobRunModel, inputs),
            ).values(status="succeeded", finished_at=_parse_datetime(finished_at), input=base_input))
            if changed.rowcount != 1:
                raise ProviderKeyedPublicationConflict("host-proof claim changed")
            if expiry <= datetime.now(timezone.utc):
                raise ProviderKeyedPublicationConflict("host-proof claim expired")
            journal = db.session.query(JobEventModel).filter_by(job_id=parent.id).order_by(
                JobEventModel.sequence.asc()).all()
            persisted = [JobEvent(row.sequence, row.level, row.message, row.data) for row in journal]
            if persisted != parent.events or job_event_digest(persisted) != expected_event_digest:
                raise ProviderKeyedPublicationConflict("host-proof journal changed")
            child_changed = db.session.execute(update(JobRunModel).where(
                JobRunModel.id == proof_child.id,
                JobRunModel.action == proof_child.action,
                JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
                JobRunModel.target == proof_child.target,
                JobRunModel.target_type == proof_child.target_type,
                JobRunModel.target_id == proof_child.target_id,
                JobRunModel.requested_by == proof_child.requested_by,
                text("(SELECT COUNT(*) FROM json_each(job_runs.input)) = :child_input_count")
                    .bindparams(child_input_count=len(proof_child.input)),
                *(condition for key, value in sorted(proof_child.input.items())
                  for condition in (
                      func.json_type(JobRunModel.input, f"$.{key}") ==
                          ("true" if value is True else "false" if value is False else "text"),
                      func.json_extract(JobRunModel.input, f"$.{key}") ==
                          (1 if value is True else 0 if value is False else value),
                  )),
            ).values(status="succeeded", finished_at=_parse_datetime(finished_at)))
            if child_changed.rowcount != 1:
                raise ProviderKeyedPublicationConflict("host proof child claim changed")
            child_journal = db.session.query(JobEventModel).filter_by(job_id=proof_child.id).order_by(
                JobEventModel.sequence.asc()).all()
            child_persisted = [JobEvent(row.sequence, row.level, row.message, row.data)
                               for row in child_journal]
            if (child_persisted != proof_child.events
                    or job_event_digest(child_persisted) != proof_child_event_digest):
                raise ProviderKeyedPublicationConflict("host proof child journal changed")
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=engagement_id, owner_id=plan_id,
                operation="provider_keyed_initial",
            ).one_or_none()
            if lease is None:
                raise ProviderKeyedPublicationConflict("core mutation lease changed")
            plan = db.session.query(DeploymentPlanModel).filter_by(
                id=plan_id, engagement_id=engagement_id, status="applied",
                apply_job_id=core_id,
            ).one_or_none()
            if (plan is None or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or plan.evidence.get("pendingSketchChainIds") !=
                    [chain.chain_id for chain in pending_chains]
                    or plan.evidence.get("pendingSketchChainFingerprints") != {
                        chain.chain_id: sketch_chain_intent_fingerprint(chain)
                        for chain in pending_chains}):
                raise ProviderKeyedPublicationConflict("reviewed core plan differs")
            engagement = db.session.query(EngagementModel).filter_by(id=engagement_id).one_or_none()
            core = db.session.query(JobRunModel).filter_by(id=core_id).one_or_none()
            target = normalized_oci_deployment_target(
                engagement.input_parameters.get("deploymentTarget")) if engagement else None
            if (engagement is None or engagement.sketch_state_schema != "provider-keyed-v2"
                    or target is None or target["name"] != "barragan-testing"
                    or core is None or core.action != "pilot_standard_rti_guarded_execute"
                    or core.status != "succeeded" or core.finished_at is None
                    or core.requested_by != parent.requested_by
                    or core.target_type != "oci_compartment"
                    or core.target != f"oci-compartment:{target['name']}"
                    or core.target_id != target["compartmentId"]
                    or core.input.get("engagementId") != engagement_id
                    or core.input.get("corePlanId") != plan_id
                    or core.input.get("sketchStateSchema") != "provider-keyed-v2"
                    or core.input.get("postCoreSketchContinuationEligible") is not False
                    or core.input.get("pendingSketchChainIds") !=
                    [chain.chain_id for chain in pending_chains]
                    or core.input.get("pendingSketchChainFingerprints") != {
                        chain.chain_id: sketch_chain_intent_fingerprint(chain)
                        for chain in pending_chains}):
                raise ProviderKeyedPublicationConflict("reviewed core generation differs")
            rows = db.session.query(SketchChainModel).filter_by(engagement_id=engagement_id).all()
            from app.services.provider_keyed_runtime_preflight import _inert_aborted_intent

            current_rows = {row.chain_id: row for row in rows if row.chain_id in by_id}
            if (set(current_rows) != set(by_id)
                    or any(not _inert_aborted_intent(_from_model(row), engagement_id)
                           for row in rows if row.chain_id not in by_id)):
                raise ProviderKeyedPublicationConflict("complete chain set changed")
            for row in current_rows.values():
                if _from_model(row) != by_id[row.chain_id]:
                    raise ProviderKeyedPublicationConflict("pending chain identity changed")
                projection = projected[row.chain_id].chain
                row.status = "deployed"
                row.nodes = [{**node, "status": "deployed"} for node in projection.nodes]
                row.deploy_job_id = parent.id
                row.terraform_working_directory = applied_workspace_path
            db.session.add(JobEventModel(
                job_id=parent.id, sequence=len(parent.events) + 1, level="info",
                message="provider two-chain host proof published", data={
                    "hostEvidenceSha256": host_evidence_sha256,
                    "stateSha256": state_sha256, "manifestSha256": manifest_sha256,
                    "chainIds": [chain.chain_id for chain in pending_chains],
                    "hostnames": list(host_proof.hostnames),
                    "providerInstanceIds": list(host_proof.provider_instance_ids),
                },
            ))
            db.session.add(JobEventModel(
                job_id=proof_child.id, sequence=len(proof_child.events) + 1,
                level="info", message="strict host proof published",
                data={"parentJobId": parent.id, "hostEvidenceSha256": host_evidence_sha256},
            ))
            db.session.delete(lease)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise ProviderKeyedPublicationConflict("reviewed two-chain publication stopped") from None
        return tuple(self.get(engagement_id, chain.chain_id) for chain in pending_chains)

    def list_for_engagements(self, engagement_ids: list[str]) -> list[StoredSketchChain]:
        from app.storage.models import SketchChainModel

        if not engagement_ids:
            return []
        rows = (
            SketchChainModel.query.filter(SketchChainModel.engagement_id.in_(engagement_ids))
            .order_by(SketchChainModel.engagement_id.asc(), SketchChainModel.created_at.asc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def list_for_engagement(self, engagement_id: str) -> list[StoredSketchChain]:
        from app.storage.models import SketchChainModel

        rows = (
            SketchChainModel.query.filter_by(engagement_id=engagement_id)
            .order_by(SketchChainModel.created_at.asc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def get(self, engagement_id: str, chain_id: str) -> StoredSketchChain | None:
        from app.storage.models import SketchChainModel

        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain_id).first()
        if row is None:
            return None
        return _from_model(row)

    def list_for_recovery(
        self,
        *,
        statuses: set[str] | None = None,
        updated_before: datetime | None = None,
    ) -> list[StoredSketchChain]:
        from app.storage.models import SketchChainModel

        query = SketchChainModel.query.filter(
            (SketchChainModel.deploy_job_id != "") | (SketchChainModel.teardown_job_id != "")
        )
        if statuses is not None:
            query = query.filter(SketchChainModel.status.in_(statuses))
        if updated_before is not None:
            query = query.filter(SketchChainModel.updated_at <= updated_before)
        return [_from_model(row) for row in query.order_by(SketchChainModel.updated_at.asc()).all()]

    def save(self, chain: StoredSketchChain) -> StoredSketchChain:
        from app.storage.database import db
        from app.storage.models import SketchChainModel

        row = SketchChainModel.query.filter_by(
            engagement_id=chain.engagement_id,
            chain_id=chain.chain_id,
        ).first()
        if row is None:
            row = SketchChainModel(engagement_id=chain.engagement_id, chain_id=chain.chain_id)
            db.session.add(row)

        row.assigned_proxy = chain.assigned_proxy
        row.middle_provider = chain.middle_provider
        row.middle_region = chain.middle_region
        row.middle_size = chain.middle_size
        row.edge_provider = chain.edge_provider
        row.edge_region = chain.edge_region
        row.edge_size = chain.edge_size
        row.edge_count = chain.edge_count
        row.edge_intents = chain.edge_intents or []
        row.status = chain.status
        row.burned = chain.burned
        row.burned_note = chain.burned_note
        row.deploy_job_id = chain.deploy_job_id
        row.teardown_job_id = chain.teardown_job_id
        row.terraform_working_directory = chain.terraform_working_directory
        row.nodes = chain.nodes
        db.session.commit()
        return self.get(chain.engagement_id, chain.chain_id) or chain

    def save_if_matches(
        self,
        chain: StoredSketchChain,
        *,
        expected_status: str,
        expected_deploy_job_id: str,
        expected_teardown_job_id: str,
    ) -> StoredSketchChain | None:
        from app.storage.database import db
        from app.storage.models import SketchChainModel

        result = (
            SketchChainModel.query.filter_by(
                engagement_id=chain.engagement_id,
                chain_id=chain.chain_id,
                status=expected_status,
                deploy_job_id=expected_deploy_job_id,
                teardown_job_id=expected_teardown_job_id,
            )
            .update(
                {
                    "status": chain.status,
                    "terraform_working_directory": chain.terraform_working_directory,
                    "nodes": chain.nodes,
                },
                synchronize_session=False,
            )
        )
        db.session.commit()
        return self.get(chain.engagement_id, chain.chain_id) if result == 1 else None


def _from_model(row) -> StoredSketchChain:
    return StoredSketchChain(
        chain_id=row.chain_id,
        engagement_id=row.engagement_id,
        assigned_proxy=row.assigned_proxy,
        middle_provider=row.middle_provider,
        middle_region=row.middle_region,
        middle_size=row.middle_size,
        edge_provider=row.edge_provider,
        edge_region=row.edge_region,
        edge_size=row.edge_size,
        edge_count=max(1, int(row.edge_count or 1)),
        edge_intents=list(row.edge_intents or []),
        status=row.status,
        burned=bool(row.burned),
        burned_note=row.burned_note or "",
        deploy_job_id=row.deploy_job_id or "",
        teardown_job_id=row.teardown_job_id or "",
        terraform_working_directory=row.terraform_working_directory or "",
        nodes=list(row.nodes or []),
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )


def _legacy_edges(provider: str, region: str, size: str, count: int) -> list[dict[str, str]]:
    return [
        {"id": f"edge-{index:02d}", "provider": provider, "region": region, "size": size}
        for index in range(1, max(1, count) + 1)
    ]
