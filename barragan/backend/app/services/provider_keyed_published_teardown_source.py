# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only persisted source audit for a published keyed DevTest generation.

This seals a database publication fact for a future writer transaction to
reprove. It does not establish raw host-collector provenance or authorize a
teardown, provider call, or public dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import _fingerprint
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, reviewed_mixed_chain_rows
from app.services.provider_keyed_teardown_quiescence import audit_published_provider_keyed_bootstrap
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class PublishedProviderKeyedSourceError(ValueError):
    """The exact published generation cannot be audited from persisted state."""


@dataclass(frozen=True)
class PublishedProviderKeyedSource:
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    initial_job_id: str
    initial_journal_sha256: str
    core_journal_sha256: str
    scope_sha256: str
    state_sha256: str
    manifest_sha256: str
    published_host_evidence_sha256: str  # Stored receipt only; no raw collector proof.
    chain_ids: tuple[str, str]
    chain_projection_sha256: str


def audit_published_provider_keyed_source(
    core_job_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] = _db_lease_lookup,
    scope_builder=build_digitalocean_keyed_teardown_scope,
    expected_teardown_parent_id: str | None = None,
    expected_mutation_lease: tuple[str, str] | None = None,
    allowed_append_plan_parent_id: str | None = None,
) -> PublishedProviderKeyedSource:
    """Read the complete applied scope and exact terminal publication twice.

    A later SQLite writer must reprove these digests and row identities while
    acquiring its teardown lease; this read-only result is not a lock.
    """
    try:
        if environment != "devtest" or not isinstance(core_job_id, str) or not core_job_id:
            raise ValueError("published source requires an exact DevTest core")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        parent_id = _job_ids(core_job_id)[0]

        def read() -> PublishedProviderKeyedSource:
            core, parent = jobs.get(core_job_id), jobs.get(parent_id)
            if core is None or parent is None or core.status != "succeeded" or not core.finished_at:
                raise ValueError("published core or initial job missing")
            inputs = core.input
            if (not isinstance(inputs, dict) or inputs.get("sketchStateSchema") != "provider-keyed-v2"
                    or inputs.get("postCoreSketchContinuationEligible") is not False):
                raise ValueError("core generation differs")
            engagement_id, plan_id = inputs.get("engagementId"), inputs.get("corePlanId")
            if not all(isinstance(value, str) and value for value in (engagement_id, plan_id)):
                raise ValueError("core identity differs")
            plan = plans.get(plan_id)
            if (plan is None or plan.engagement_id != engagement_id or plan.status != "applied"
                    or plan.apply_job_id != core_job_id or not isinstance(plan.evidence, dict)
                    or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or plan.evidence.get("pendingSketchChainIds") != inputs.get("pendingSketchChainIds")
                    or plan.evidence.get("pendingSketchChainFingerprints") !=
                    inputs.get("pendingSketchChainFingerprints")):
                raise ValueError("applied core plan differs")
            if expected_mutation_lease is not None:
                if (expected_teardown_parent_id is not None
                        or expected_mutation_lease != (plan_id, "provider_keyed_edge_append")
                        or not allowed_append_plan_parent_id):
                    raise ValueError("unsupported published mutation lease")
                expected_lease = expected_mutation_lease
            else:
                if allowed_append_plan_parent_id is not None:
                    raise ValueError("append source review requires its lease")
                expected_lease = (None if expected_teardown_parent_id is None else
                                  (plan_id, "provider_keyed_teardown_fence"))
            if lease_lookup(engagement_id) != expected_lease:
                raise ValueError("published source mutation lease differs")
            if expected_teardown_parent_id is not None:
                from app.services.engagement_teardown import _parent_id
                if expected_teardown_parent_id != _parent_id(core_job_id):
                    raise ValueError("published teardown parent identity differs")
            scope = scope_builder(
                engagement_id, core_job_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                **({"allowed_teardown_parent_id": expected_teardown_parent_id}
                   if expected_teardown_parent_id is not None else {}),
                **({"allowed_append_plan_parent_id": allowed_append_plan_parent_id}
                   if allowed_append_plan_parent_id is not None else {}),
            )
            if (type(scope) is not dict or scope.get("schema") != "provider-keyed-v2"
                    or scope.get("provider") != "digitalocean"
                    or scope.get("coreJobId") != core_job_id or scope.get("corePlanId") != plan_id
                    or not isinstance(scope.get("workspace"), str)
                    or not isinstance(scope.get("resources"), list) or not scope["resources"]):
                raise ValueError("applied provider scope differs")
            ids = scope.get("chainIds")
            fingerprints = scope.get("chainFingerprints")
            if (not isinstance(ids, list) or len(ids) != 2 or len(set(ids)) != 2
                    or ids != inputs.get("pendingSketchChainIds")
                    or fingerprints != inputs.get("pendingSketchChainFingerprints")):
                raise ValueError("published chain set differs")
            root = Path(scope["workspace"])
            bootstrap = audit_published_provider_keyed_bootstrap(
                core_job_id, confirmed_scope=scope, workspace_root=root, job_repository=jobs,
            )
            if bootstrap.chain_ids != tuple(ids):
                raise ValueError("published bootstrap chain order differs")
            terminal = parent.events[-1]
            manifest = next(event.data for event in parent.events
                            if event.message == "provider host identity binding intended")
            if (type(manifest) is not dict or set(manifest) != {
                    "schema", "engagementId", "coreJobId", "corePlanId", "revisionId",
                    "stateSha256", "sourceRevision", "providerConnectionId",
                    "chainFingerprints", "nodes", "hostPolicies",
                    "coreKnownHostsPath", "coreKnownHostsSha256", "sketchKnownHostsPath",
                } or manifest["engagementId"] != engagement_id
                    or manifest["revisionId"] != scope.get("revisionId")
                    or manifest["sketchKnownHostsPath"] !=
                    str(root / ".barragan-sketch-known-hosts")
                    or not isinstance(manifest["hostPolicies"], list)
                    or [item.get("chainId") for item in manifest["hostPolicies"]] != ids):
                raise ValueError("published manifest shape differs")
            rows = reviewed_mixed_chain_rows(chains.list_for_engagement(engagement_id), ids, engagement_id)
            if (len(rows) != 2 or {row.chain_id for row in rows} != set(ids)
                    or any(row.engagement_id != engagement_id or row.status != "deployed"
                           or row.deploy_job_id != parent_id or row.teardown_job_id
                           or row.terraform_working_directory != scope["workspace"]
                           or row.burned or not row.nodes
                           or sketch_chain_intent_fingerprint(row) != fingerprints[row.chain_id]
                           or any(type(node) is not dict or node.get("status") != "deployed"
                                  for node in row.nodes) for row in rows)):
                raise ValueError("deployed chain projections differ")
            nodes = [node for row in rows for node in row.nodes]
            expected = sorted(({
                "chainId": node["chainId"], "role": node["role"],
                "providerInstanceId": node["providerInstanceId"],
                "terraformAddress": node["terraformAddress"], "name": node["hostname"],
                "publicIp": node["publicIp"], "region": node["region"],
            } for node in nodes), key=lambda item: item["terraformAddress"])
            names = sorted(node["hostname"] for node in nodes)
            ids_by_name = {node["hostname"]: node["providerInstanceId"] for node in nodes}
            resource_ids = {item["address"]: item["id"] for item in scope["resources"]}
            if (len(expected) != len({node["terraformAddress"] for node in nodes})
                    or len(names) != len(set(names))
                    or len(resource_ids) != len(scope["resources"])
                    or any(resource_ids.get(node["terraformAddress"]) !=
                           str(node["providerInstanceId"]) for node in nodes)
                    or manifest.get("nodes") != expected
                    or terminal.data != {
                        "hostEvidenceSha256": terminal.data.get("hostEvidenceSha256"),
                        "stateSha256": scope["stateSha256"],
                        "manifestSha256": bootstrap.manifest_sha256,
                        "chainIds": ids, "hostnames": names,
                        "providerInstanceIds": [ids_by_name[name] for name in names],
                    }
                    or type(terminal.data["hostEvidenceSha256"]) is not str
                    or len(terminal.data["hostEvidenceSha256"]) != 64
                    or any(char not in "0123456789abcdef" for char in
                           terminal.data["hostEvidenceSha256"])):
                raise ValueError("publication receipt or node identities differ")
            return PublishedProviderKeyedSource(
                engagement_id, core_job_id, plan_id, parent_id,
                job_event_digest(parent.events), job_event_digest(core.events),
                _fingerprint(scope), scope["stateSha256"], _digest_json(manifest),
                terminal.data["hostEvidenceSha256"], tuple(ids),
                _fingerprint({row.chain_id: row.to_dict() for row in rows}),
            )

        first = read()
        if read() != first:
            raise ValueError("published source changed during audit")
        return first
    except Exception:
        raise PublishedProviderKeyedSourceError("published keyed source is unproved") from None
