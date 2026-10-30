# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, read-only source selection for a reviewed keyed teardown.

The two pre-destroy histories are disjoint. This does not authorize a provider
operation. Post-destroy needs its own historical proof after live state and
deployed projections have deliberately been retired.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from copy import deepcopy
import json
from pathlib import Path
import re

from app.services.engagement_teardown import _fingerprint
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_published_teardown_source import (
    PublishedProviderKeyedSource, audit_published_provider_keyed_source,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_teardown_quiescence import (
    audit_failed_prebinding_provider_bootstrap,
    audit_pending_provider_keyed_bootstrap, audit_terminal_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.credential_repository import SqlAlchemyCredentialRepository


class ProviderKeyedTeardownSourceError(ValueError):
    """The persisted pre-destroy source cannot be proved."""


class ProviderKeyedPostDestroySourceUnavailable(ProviderKeyedTeardownSourceError):
    """The published historical post-destroy source cannot be proved."""


@dataclass(frozen=True)
class ProviderKeyedTeardownSource:
    variant: str
    teardown_parent_id: str
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    snapshot_id: str
    provider_scope_sha256: str
    initial_job_id: str
    initial_journal_sha256: str
    published_source_sha256: str | None


def load_keyed_teardown_source(
    teardown_parent_id: str, *, phase: str = "pre_go", environment: str = "devtest",
    state_root: Path | None = None, job_repository=None, plan_repository=None,
    sketch_repository=None, credential_repository=None, lease_lookup=None,
    credential_check=None,
) -> ProviderKeyedTeardownSource:
    """Reprove one exact reviewed source; never choose a variant from caller data.

    Post-destroy is a separate success-only historical interval before chain
    retirement. The original applied state is intentionally no longer present.
    """
    if phase == "post_destroy":
        try:
            source, _boundary = _read_published_post_destroy_boundary(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=job_repository, plan_repository=plan_repository,
                sketch_repository=sketch_repository, credential_repository=credential_repository,
                lease_lookup=lease_lookup, credential_check=credential_check,
            )
            return source
        except Exception:
            raise ProviderKeyedPostDestroySourceUnavailable(
                "published historical post-destroy source is unproved") from None
    try:
        if phase not in {"pre_handoff", "pre_go"} or environment != "devtest" or not teardown_parent_id:
            raise ValueError("unsupported source phase or environment")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        lookup = _db_lease_lookup
        # Import locally: the coordinator will eventually consume this source
        # selector, so a module-level import would form a cycle.
        from app.services.provider_keyed_comprehensive_teardown import _boundary
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        scope = snapshot["providerScopes"][0]
        if scope.get("provider") != "digitalocean":
            raise ValueError("unsupported provider source")
        initial_id = _job_ids(core.id)[0]
        initial = jobs.get(initial_id)
        if initial is None:
            raise ValueError("initial source missing")
        sealed = parent.input.get("publishedSource")
        if "publishedSource" in parent.input:
            if (phase != "pre_go" or operation != "provider_keyed_teardown_fence"
                    or initial.status != "succeeded"):
                raise ValueError("published source and lease differ")
            if "publishedAppendSource" in parent.input:
                from app.services.provider_keyed_append_source import (
                    audit_published_provider_keyed_append_source,
                )
                expanded = audit_published_provider_keyed_append_source(
                    core.id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=sketch_repository,
                )
                current = build_digitalocean_keyed_teardown_scope(
                    parent.target_id, core.id, environment=environment,
                    state_root=state_root, allowed_teardown_parent_id=parent.id,
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=sketch_repository,
                )
                proof = expanded.initial_source
                canonical = json.loads(json.dumps(asdict(proof), sort_keys=True))
                expanded_record = json.loads(json.dumps(asdict(expanded), sort_keys=True))
                if (type(sealed) is not dict or sealed != canonical
                        or type(parent.input["publishedAppendSource"]) is not dict
                        or parent.input["publishedAppendSource"] != expanded_record
                        or current != scope
                        or expanded.state_sha256 != scope.get("stateSha256")
                        or expanded.append_journal_sha256 != snapshot[
                            "dnsCleanupManifest"].get("appendJournalSha256")
                        or proof.initial_job_id != initial_id):
                    raise ValueError("published append source differs")
                variant = "published_append"
                published_digest = _fingerprint(expanded_record)
            else:
                proof = audit_published_provider_keyed_source(
                    core.id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=sketch_repository, lease_lookup=lookup,
                    scope_builder=build_digitalocean_keyed_teardown_scope,
                    expected_teardown_parent_id=parent.id,
                )
                canonical = json.loads(json.dumps(asdict(proof), sort_keys=True))
                if (type(sealed) is not dict or sealed != canonical
                        or proof.initial_job_id != initial_id
                        or proof.scope_sha256 != _fingerprint(scope)):
                    raise ValueError("published sealed source differs")
                variant = "published"
                published_digest = _fingerprint(canonical)
        else:
            failed_prebinding = initial.status == "failed"
            if initial.status != "running" and not failed_prebinding:
                raise ValueError("pending initial source differs")
            current = build_digitalocean_keyed_teardown_scope(
                parent.target_id, core.id, environment=environment,
                state_root=state_root, allowed_teardown_parent_id=parent.id,
                job_repository=jobs, plan_repository=plans,
                **({"sketch_repository": sketch_repository} if sketch_repository is not None else {}),
            )
            if current != scope:
                raise ValueError("pending applied scope changed")
            if failed_prebinding:
                if (phase, operation) not in {
                        ("pre_handoff", "provider_keyed_initial"),
                        ("pre_go", "provider_keyed_teardown_fence")}:
                    raise ValueError("failed prebinding source stage differs")
                audit_failed_prebinding_provider_bootstrap(
                    core.id, confirmed_scope=scope,
                    confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                )
                if phase == "pre_go":
                    from app.services.provider_keyed_comprehensive_teardown import _child_id, _same_child
                    coordinator = jobs.get(_child_id(core.id))
                    if coordinator is None:
                        raise ValueError("failed prebinding handoff marker differs")
                    if coordinator.input.get("phase") == "awaiting_inspector_preflight":
                        if not _same_child(coordinator, parent, core, snapshot):
                            raise ValueError("failed prebinding handoff marker differs")
                    elif coordinator.input.get("phase") == "inspector_ready":
                        from app.services.provider_keyed_comprehensive_teardown import (
                            recognize_retained_keyed_inspector_ready,
                        )
                        ready = recognize_retained_keyed_inspector_ready(
                            parent.id, environment=environment, job_repository=jobs,
                            plan_repository=plans, lease_lookup=lookup,
                        )
                        if (ready.coordinator_job_id != coordinator.id
                                or jobs.get(coordinator.id) != coordinator):
                            raise ValueError("failed prebinding Inspector-ready marker differs")
                    else:
                        raise ValueError("failed prebinding handoff stage differs")
                variant = "failed_prebinding"
            elif (phase == "pre_handoff" and operation == "provider_keyed_initial"
                    and initial.input.get("phase") == "awaiting_strict_host_proof"):
                audit_terminal_provider_keyed_bootstrap(
                    core.id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
                    job_repository=jobs,
                )
                variant = "pending_terminal"
            elif (phase == "pre_go" and operation == "provider_keyed_teardown_fence"
                  and initial.input.get("phase") == "teardown_handoff_pending"):
                audit_pending_provider_keyed_bootstrap(
                    core.id, confirmed_scope=scope,
                    confirmed_scope_sha256=_fingerprint(snapshot),
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                )
                variant = "pending_handoff"
            else:
                raise ValueError("pending source stage and lease differ")
            published_digest = None
        if (jobs.get(parent.id) != parent or jobs.get(initial_id) != initial
                or lookup(parent.target_id) != (core.input["corePlanId"], operation)):
            raise ValueError("source changed during audit")
        return ProviderKeyedTeardownSource(
            variant, parent.id, parent.target_id, core.id, core.input["corePlanId"],
            snapshot["snapshotId"], snapshot["providerScopeSha256"], initial_id,
            job_event_digest(initial.events), published_digest,
        )
    except Exception:
        raise ProviderKeyedTeardownSourceError("keyed pre-destroy source is unproved") from None


def _read_published_post_destroy_boundary(
    teardown_parent_id: str, *, environment: str, state_root: Path | None,
    job_repository, plan_repository, sketch_repository, credential_repository,
    lease_lookup, credential_check, retired: bool = False,
) -> tuple[ProviderKeyedTeardownSource, object]:
    """Return the exact historical source and successful saved-destroy boundary.

    Private until the published teardown lifecycle is complete. Neither read
    consults the now-empty applied scope or contacts a provider.
    """
    if environment != "devtest" or not teardown_parent_id or state_root is None:
        raise ValueError("unsupported post-destroy source")
    # Local import avoids teardown_source -> apply_job -> teardown_source cycle.
    from app.services.provider_keyed_destroy_absence_preflight import _read_success_boundary
    from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
    from app.services.provider_keyed_teardown_quiescence import audit_published_provider_keyed_bootstrap
    from app.services.sketch_state_workspaces import _default_state_root

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    state_root = state_root or _default_state_root()
    if (not isinstance(state_root, Path) or state_root != _default_state_root()
            or state_root.resolve(strict=True) != state_root):
        raise ValueError("post-destroy state root differs")
    sealed_proofs = []

    def historical_append(core_id, initial, core, parent, confirmed_scope,
                          workspace_root, rows, initial_id):
        """Reopen the sealed five-node history after Terraform emptied state."""
        from app.services.provider_keyed_append_plan_job import _PLAN_EVENT_KEYS
        from app.services.provider_keyed_append_source import _decode_initial_source, _restore_chain

        append_record = parent.input.get("publishedAppendSource")
        initial_record = parent.input.get("publishedSource")
        if type(append_record) is not dict or type(initial_record) is not dict:
            raise ValueError("historical append seal differs")
        proof = _decode_initial_source(initial_record)
        append = jobs.get(append_record.get("append_job_id"))
        from app.services.provider_keyed_teardown_scope import (
            _reconciled_unapplied_append_state_sha,
        )
        append_parents = [job for job in jobs.list_for_engagement(parent.target_id)
                          if job.action == "provider_keyed_edge_append"]
        if (len(append_parents) > 1 and
                _reconciled_unapplied_append_state_sha(
                    parent.target_id, jobs,
                    allowed_published_parent_id=append_record.get("append_job_id"),
                    expected_core_job_id=core_id,
                    expected_core_plan_id=proof.core_plan_id,
                ) != proof.state_sha256):
            raise ValueError("historical failed append reviews differ")
        if (append_record.get("initial_source") != initial_record
                or append_record.get("state_sha256") != confirmed_scope["stateSha256"]
                or proof.initial_job_id != initial_id
                or proof.initial_journal_sha256 != job_event_digest(initial.events)
                or proof.core_journal_sha256 != job_event_digest(core.events)
                or proof.engagement_id != parent.target_id
                or proof.core_job_id != core_id
                or proof.core_plan_id != confirmed_scope["corePlanId"]
                or append is None or append.status != "succeeded"
                or append.action != "provider_keyed_edge_append"
                or job_event_digest(append.events) != append_record.get("append_journal_sha256")
                or append.events[-1].message != "provider one-edge append published"
                or append.events[-1].data != {
                    "initialSource": initial_record,
                    "stateSha256": confirmed_scope["stateSha256"],
                }):
            raise ValueError("historical appended source differs")
        terminal = initial.events[-1]
        manifests = [event.data for event in initial.events
                     if event.message == "provider host identity binding intended"]
        if (len(manifests) != 1 or terminal.message != "provider two-chain host proof published"
                or terminal.data.get("stateSha256") != proof.state_sha256
                or terminal.data.get("hostEvidenceSha256") != proof.published_host_evidence_sha256
                or terminal.data.get("manifestSha256") != proof.manifest_sha256):
            raise ValueError("historical original host receipt differs")
        original = manifests[0].get("nodes")
        ids = {item["address"]: item["id"] for item in confirmed_scope["resources"]}
        if (type(original) is not list or len(original) != 4
                or len(ids) != 9 or len({node["terraformAddress"] for node in original}) != 4
                or any(ids.get(node["terraformAddress"]) != node["providerInstanceId"]
                       for node in original)
                or append_record.get("new_edge_address") in {
                    node["terraformAddress"] for node in original}
                or ids.get(append_record.get("new_edge_address")) !=
                   append_record.get("new_edge_provider_id")):
            raise ValueError("historical five-node identity differs")
        hashes = append.events[-2].data if len(append.events) >= 2 else None
        if (append.events[-2].message != "strict append host proof completed"
                or type(hashes) is not dict
                or set(hashes) != {"planJournalSha256", "applyJournalSha256",
                                   "hostProofJournalSha256"}):
            raise ValueError("historical append journals differ")
        children = {}
        for kind, action in (("plan", "provider_keyed_edge_append_plan"),
                             ("apply", "provider_keyed_edge_append_apply"),
                             ("hostProof", "provider_keyed_edge_append_host_proof")):
            child = jobs.get(append.input.get(f"{kind}JobId"))
            if (child is None or child.status != "succeeded" or child.action != action
                    or child.input.get("parentJobId") != append.id
                    or job_event_digest(child.events) != hashes[f"{kind}JournalSha256"]):
                raise ValueError("historical append child differs")
            children[kind] = child
        plan_data = children["plan"].events[-1].data
        if (set(plan_data) != _PLAN_EVENT_KEYS
                or plan_data["initialSource"] != initial_record
                or plan_data["newEdgeAddress"] != append_record["new_edge_address"]
                or children["apply"].events[-1].message != "provider append apply completed"
                or children["apply"].events[-1].data.get("stateSha256") !=
                   confirmed_scope["stateSha256"]
                or children["hostProof"].events[-1].message !=
                   "strict append host proof completed"
                or children["hostProof"].events[-1].data.get("newEdgeAddress") !=
                   append_record["new_edge_address"]
                or children["hostProof"].events[-1].data.get("newEdgeProviderId") !=
                   append_record["new_edge_provider_id"]):
            raise ValueError("historical append receipt differs")
        selected_before = _restore_chain(plan_data["selectedChain"])
        original_by_address = {node["terraformAddress"]: node for node in original}
        if (selected_before.chain_id != append.input.get("chainId")
                or any(original_by_address.get(node["terraformAddress"], {}).get(
                    "providerInstanceId") != node["providerInstanceId"]
                    for node in selected_before.nodes)):
            raise ValueError("historical selected chain differs")
        if retired:
            coordinator = jobs.get(
                f"job-provider-keyed-comprehensive-teardown-{core_id.removeprefix('job-')}")
            receipt = coordinator.events[-1].data if coordinator and coordinator.events else None
            if (coordinator is None or coordinator.input.get("phase") != "group_retired"
                    or coordinator.events[-1].message != "keyed_provider_group_retired"
                    or type(receipt) is not dict
                    or not isinstance(receipt.get("priorChainProjectionSha256"), str)
                    or any(row.status != "destroyed" or row.nodes != []
                           or row.teardown_job_id !=
                           f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}"
                           for row in rows)):
                raise ValueError("historical append retirement differs")
        else:
            projected = {node["terraformAddress"]: node for row in rows for node in row.nodes}
            if (len(projected) != 5 or set(projected) != {
                    address for address in ids if address.startswith("digitalocean_droplet.")}
                    or any(projected[address]["providerInstanceId"] != ids[address]
                           for address in projected)
                    or any(row.status != "deployed" or row.teardown_job_id
                           or row.terraform_working_directory != str(workspace_root)
                           for row in rows)):
                raise ValueError("historical expanded rows differ")
        sealed_proofs.append(proof)
        return

    def historical_initial(core_id, *, confirmed_scope, workspace_root,
                           job_repository, **_kwargs):
        initial_id = _job_ids(core_id)[0]
        initial = job_repository.get(initial_id)
        core = job_repository.get(core_id)
        parent = job_repository.get(teardown_parent_id)
        if (initial is None or core is None or parent is None
                or initial.status != "succeeded" or not initial.finished_at
                or type(parent.input.get("publishedSource")) is not dict):
            raise ValueError("published initial source differs")
        ids = confirmed_scope["chainIds"]
        rows = tuple(row for row in chains.list_for_engagement(parent.target_id)
                     if row.chain_id in ids)
        if len(rows) != 2:
            raise ValueError("published chain set differs")
        if "publishedAppendSource" in parent.input:
            if any(sketch_chain_intent_fingerprint(row) != confirmed_scope[
                    "chainFingerprints"].get(row.chain_id) for row in rows):
                raise ValueError("historical appended chain intent differs")
            return historical_append(core_id, initial, core, parent, confirmed_scope,
                                     workspace_root, rows, initial_id)
        bootstrap = audit_published_provider_keyed_bootstrap(
            core_id, confirmed_scope=confirmed_scope, workspace_root=workspace_root,
            job_repository=job_repository,
        )
        if (bootstrap.chain_ids != tuple(ids) or len(rows) != 2
                or (not retired and any(
                    row.status != "deployed" or row.teardown_job_id or row.burned
                    or row.deploy_job_id != initial_id or not row.nodes
                    or row.terraform_working_directory != str(workspace_root)
                    or any(type(node) is not dict or node.get("status") != "deployed"
                           for node in row.nodes)
                    for row in rows))):
            raise ValueError("published chain projection differs")
        manifest_events = [event for event in initial.events
                           if event.message == "provider host identity binding intended"]
        if len(manifest_events) != 1 or type(manifest_events[0].data) is not dict:
            raise ValueError("published host manifest differs")
        manifest = manifest_events[0].data
        terminal = initial.events[-1]
        if retired:
            # The nodes have been cleared in the atomic retirement commit.
            # Their sealed host manifest remains in the immutable initial journal.
            expected_nodes = manifest.get("nodes")
            droplet_ids = {
                item["address"]: str(item["id"])
                for item in confirmed_scope["resources"]
                if item["address"].startswith("digitalocean_droplet.")
            }
            if (type(expected_nodes) is not list
                    or len(expected_nodes) != len(droplet_ids)
                    or any(type(node) is not dict or set(node) != {
                        "chainId", "role", "providerInstanceId", "terraformAddress",
                        "name", "publicIp", "region",
                    } for node in expected_nodes)
                    or {node["terraformAddress"] for node in expected_nodes} != set(droplet_ids)
                    or any(node["chainId"] not in ids
                           or node["role"] not in {"middle", "edge"}
                           or not node["terraformAddress"].startswith(
                               f'digitalocean_droplet.{node["role"]}[')
                           or droplet_ids[node["terraformAddress"]] !=
                              str(node["providerInstanceId"])
                           for node in expected_nodes)
                    or any(sum(node["chainId"] == chain_id and node["role"] == "middle"
                               for node in expected_nodes) != 1
                           or not any(node["chainId"] == chain_id and node["role"] == "edge"
                                      for node in expected_nodes)
                           for chain_id in ids)):
                raise ValueError("published host manifest differs")
            nodes = [{"hostname": node["name"], **node} for node in expected_nodes]
        else:
            nodes = [node for row in rows for node in row.nodes]
            expected_nodes = sorted(({
                "chainId": node["chainId"], "role": node["role"],
                "providerInstanceId": node["providerInstanceId"],
                "terraformAddress": node["terraformAddress"], "name": node["hostname"],
                "publicIp": node["publicIp"], "region": node["region"],
            } for node in nodes), key=lambda item: item["terraformAddress"])
        resource_ids = {item["address"]: item["id"] for item in confirmed_scope["resources"]}
        names = sorted(node["hostname"] for node in nodes)
        ids_by_name = {node["hostname"]: node["providerInstanceId"] for node in nodes}
        host_digest = terminal.data.get("hostEvidenceSha256")
        if (type(host_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", host_digest) is None
                or len(resource_ids) != len(confirmed_scope["resources"])
                or len(expected_nodes) != len({item["terraformAddress"] for item in expected_nodes})
                or expected_nodes != sorted(expected_nodes,
                                            key=lambda item: item["terraformAddress"])
                or {node["chainId"] for node in nodes} != set(ids)
                or {node["role"] for node in nodes} != {"middle", "edge"}
                or len(names) != len(set(names))
                or any(resource_ids.get(node["terraformAddress"]) !=
                       str(node["providerInstanceId"]) for node in nodes)
                or manifest.get("schema") != "provider-keyed-v2"
                or manifest.get("nodes") != expected_nodes
                or manifest.get("engagementId") != parent.target_id
                or manifest.get("coreJobId") != core_id
                or manifest.get("corePlanId") != core.input["corePlanId"]
                or manifest.get("revisionId") != confirmed_scope.get("revisionId")
                or manifest.get("stateSha256") != confirmed_scope["stateSha256"]
                or manifest.get("sourceRevision") != confirmed_scope.get("sourceRevision")
                or manifest.get("providerConnectionId") != confirmed_scope.get("providerConnectionId")
                or manifest.get("chainFingerprints") != [
                    {"chainId": chain_id,
                     "fingerprint": confirmed_scope["chainFingerprints"][chain_id]}
                    for chain_id in ids]
                or manifest.get("sketchKnownHostsPath") !=
                   str(workspace_root / ".barragan-sketch-known-hosts")
                or not isinstance(manifest.get("hostPolicies"), list)
                or [item.get("chainId") for item in manifest["hostPolicies"]] != ids
                or terminal.data != {
                    "hostEvidenceSha256": terminal.data.get("hostEvidenceSha256"),
                    "stateSha256": confirmed_scope["stateSha256"],
                    "manifestSha256": bootstrap.manifest_sha256,
                    "chainIds": ids, "hostnames": names,
                    "providerInstanceIds": [ids_by_name[name] for name in names],
                }):
            raise ValueError("published host receipt differs")
        proof = PublishedProviderKeyedSource(
            parent.target_id, core_id, core.input["corePlanId"], initial_id,
            job_event_digest(initial.events), job_event_digest(core.events),
            _fingerprint(confirmed_scope), confirmed_scope["stateSha256"],
            # The bootstrap audit checks this digest against the exact manifest.
            bootstrap.manifest_sha256, host_digest,
            tuple(ids), (parent.input["publishedSource"].get("chain_projection_sha256")
                         if retired else _fingerprint({
                             row.chain_id: row.to_dict() for row in rows})),
        )
        if parent.input["publishedSource"] != json.loads(json.dumps(asdict(proof), sort_keys=True)):
            raise ValueError("sealed published source differs")
        if retired:
            child = jobs.get(
                f"job-provider-keyed-comprehensive-teardown-{core_id.removeprefix('job-')}")
            receipt = child.events[-1].data if child is not None and child.events else None
            if (child is None or child.input.get("phase") != "group_retired"
                    or child.events[-1].message != "keyed_provider_group_retired"
                    or type(receipt) is not dict
                    or receipt.get("priorChainProjectionSha256") != proof.chain_projection_sha256
                    or any(row.status != "destroyed" or row.nodes != []
                           or row.teardown_job_id !=
                           f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}"
                           or row.deploy_job_id != initial_id or row.burned
                           or row.terraform_working_directory != str(workspace_root)
                           for row in rows)):
                raise ValueError("published retirement receipt differs")
        sealed_proofs.append(proof)

    def read():
        boundary = _read_success_boundary(
            teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
            credentials=credentials, lookup=lookup,
            handoff_auditor=historical_initial,
            credential_check=credential_check or _credential_snapshot,
            state_root=state_root,
        )
        if len(sealed_proofs) == 0:
            raise ValueError("published historical source missing")
        proof = sealed_proofs[-1]
        snapshot = boundary.parent.input["scopeSnapshot"]
        appended = "publishedAppendSource" in boundary.parent.input
        if (proof.core_job_id != boundary.core.id
                or (not appended and proof.scope_sha256 != _fingerprint(boundary.scope))
                or (appended and boundary.parent.input["publishedAppendSource"].get(
                    "state_sha256") != boundary.scope["stateSha256"])
                or proof.initial_job_id != snapshot["dnsCleanupManifest"]["initialJobId"]
                or proof.initial_journal_sha256 != snapshot["dnsCleanupManifest"]["initialJournalSha256"]
                or jobs.get(boundary.parent.id) != boundary.parent
                or jobs.get(proof.initial_job_id) is None
                or job_event_digest(jobs.get(proof.initial_job_id).events)
                   != proof.initial_journal_sha256):
            raise ValueError("post-destroy source changed")
        source = ProviderKeyedTeardownSource(
            "published_append" if appended else "published",
            boundary.parent.id, boundary.parent.target_id,
            boundary.core.id, proof.core_plan_id, snapshot["snapshotId"],
            snapshot["providerScopeSha256"], proof.initial_job_id,
            proof.initial_journal_sha256, _fingerprint(boundary.parent.input[
                "publishedAppendSource" if appended else "publishedSource"]),
        )
        return source, deepcopy(boundary)

    first = read()
    if read() != first:
        raise ValueError("post-destroy source changed during read")
    return first
