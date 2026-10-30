# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only audit of exactly one published DigitalOcean edge append.

The original four-node source was audited before the one-shot append apply.
Its selected chain is retained once in the append plan child; the untouched
sibling remains in the database. Current provider state must contain exactly
those four node identities and one new edge before teardown may use it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import re
from uuid import UUID

from app.services.engagement_teardown import _fingerprint
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_initial_teardown import _SHARED, _state_resources
from app.services.provider_keyed_initial_plan_gate import _inbound, _outbound, _sorted_rules
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, StoredSketchChain


class ProviderKeyedAppendSourceError(ValueError):
    """The persisted five-node generation is not an exact published append."""


@dataclass(frozen=True)
class PublishedProviderKeyedAppendSource:
    initial_source: PublishedProviderKeyedSource
    append_job_id: str
    append_journal_sha256: str
    state_sha256: str
    new_edge_address: str
    new_edge_provider_id: str


def audit_published_provider_keyed_append_source(
    core_job_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    engagement_repository=None, sketch_repository=None, job_repository=None,
    plan_repository=None,
) -> PublishedProviderKeyedAppendSource:
    """Prove immutable initial evidence, saved row history, and current state.

    This is a reader, not a teardown or apply authorization. The eventual
    reservation writer must reread it while taking the mutation lease.
    """
    try:
        if environment != "devtest" or not isinstance(core_job_id, str) or not core_job_id:
            raise ValueError("unsupported append source")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        engagements = engagement_repository or SqlAlchemyEngagementRepository()
        core = jobs.get(core_job_id)
        if core is None or core.status != "succeeded" or not isinstance(core.input, dict):
            raise ValueError("initial core is unavailable")
        engagement_id, plan_id = core.input.get("engagementId"), core.input.get("corePlanId")
        engagement = engagements.get(engagement_id)
        core_plan = plans.get(plan_id)
        if (engagement is None or core_plan is None
                or engagement.sketch_state_schema != "provider-keyed-v2"
                or core_plan.engagement_id != engagement_id or core_plan.status != "applied"
                or core_plan.apply_job_id != core_job_id
                or core.input.get("sketchStateSchema") != "provider-keyed-v2"):
            raise ValueError("reviewed core source differs")
        appended = [job for job in jobs.list_for_engagement(engagement_id)
                    if job.action == "provider_keyed_edge_append"]
        published = [job for job in appended if job.status == "succeeded"]
        if len(published) != 1:
            raise ValueError("one published append is required")
        parent = published[0]
        if (parent.status != "succeeded" or parent.input.get("phase") != "completed"
                or not parent.finished_at or not parent.events
                or parent.events[-1].message != "provider one-edge append published"
                or set(parent.events[-1].data) != {"initialSource", "stateSha256"}):
            raise ValueError("append publication is incomplete")
        terminal = parent.events[-1].data
        source = _decode_initial_source(terminal["initialSource"])
        from app.services.provider_keyed_teardown_scope import (
            _reconciled_unapplied_append_state_sha,
        )
        if len(appended) > 1 and _reconciled_unapplied_append_state_sha(
                engagement_id, jobs, allowed_published_parent_id=parent.id,
                expected_core_job_id=core_job_id,
                expected_core_plan_id=plan_id,
                ) != source.state_sha256:
            raise ValueError("prior append review history differs")
        if (source.engagement_id != engagement_id or source.core_job_id != core_job_id
                or source.core_plan_id != plan_id
                or parent.input.get("initialSourceSha256") != _fingerprint(asdict(source))
                or parent.input.get("engagementId") != engagement_id):
            raise ValueError("initial source linkage differs")
        initial = jobs.get(_job_ids(core_job_id)[0])
        if (initial is None or initial.id != source.initial_job_id
                or initial.status != "succeeded" or not initial.events
                or job_event_digest(initial.events) != source.initial_journal_sha256
                or job_event_digest(core.events) != source.core_journal_sha256
                or initial.events[-1].message != "provider two-chain host proof published"
                or initial.events[-1].data.get("stateSha256") != source.state_sha256
                or initial.events[-1].data.get("hostEvidenceSha256") !=
                   source.published_host_evidence_sha256
                or initial.events[-1].data.get("manifestSha256") !=
                   source.manifest_sha256):
            raise ValueError("immutable initial publication differs")
        initial_apply = jobs.get(_job_ids(core_job_id)[2])
        if (initial_apply is None or initial_apply.status != "succeeded"
                or initial_apply.action != "provider_keyed_initial_apply"
                or not initial_apply.events or initial_apply.events[-1].data.get("stateSha256")
                != source.state_sha256):
            raise ValueError("initial apply receipt differs")
        manifest = [event.data for event in initial.events
                    if event.message == "provider host identity binding intended"]
        if (len(manifest) != 1 or _sha_json(manifest[0]) != source.manifest_sha256
                or manifest[0].get("stateSha256") != source.state_sha256
                or manifest[0].get("engagementId") != engagement_id):
            raise ValueError("initial host binding differs")
        children = {}
        hashes = parent.events[-2].data if len(parent.events) >= 2 else None
        if (parent.events[-2].message != "strict append host proof completed"
                or not isinstance(hashes, dict)
                or set(hashes) != {"planJournalSha256", "applyJournalSha256",
                                   "hostProofJournalSha256"}):
            raise ValueError("append child seal differs")
        for kind, action, mutation in (
            ("plan", "provider_keyed_edge_append_plan", False),
            ("apply", "provider_keyed_edge_append_apply", True),
            ("hostProof", "provider_keyed_edge_append_host_proof", False),
        ):
            child = jobs.get(parent.input.get(f"{kind}JobId"))
            if (child is None or child.action != action or child.status != "succeeded"
                    or child.target_id != engagement_id or not child.finished_at
                    or child.input.get("parentJobId") != parent.id
                    or child.input.get("mutation") is not mutation
                    or job_event_digest(child.events) != hashes[f"{kind}JournalSha256"]):
                raise ValueError("append child journal differs")
            children[kind] = child
        plan_event = children["plan"].events[-1]
        if (plan_event.message != "reviewed append plan saved"
                or plan_event.data.get("initialSourceSha256") != _fingerprint(asdict(source))
                or plan_event.data.get("initialSource") != terminal["initialSource"]
                or not isinstance(plan_event.data.get("selectedChain"), dict)
                or not isinstance(plan_event.data.get("retainedSharedIds"), dict)
                or set(plan_event.data["retainedSharedIds"]) != {
                    "digitalocean_firewall.firewall", "digitalocean_ssh_key.key",
                }):
            raise ValueError("historical selected row is unproved")
        previous = _restore_chain(plan_event.data["selectedChain"])
        current_rows = chains.list_for_engagement(engagement_id)
        if (len(current_rows) != 2 or {row.chain_id for row in current_rows}
                != set(source.chain_ids) or previous.chain_id != parent.input.get("chainId")):
            raise ValueError("expanded chain set differs")
        selected = next(row for row in current_rows if row.chain_id == previous.chain_id)
        sibling = next(row for row in current_rows if row.chain_id != previous.chain_id)
        expected_selected = replace(previous, edge_count=2,
            edge_intents=selected.edge_intents, nodes=selected.nodes,
            updated_at=selected.updated_at)
        if (selected != expected_selected or selected.edge_intents[:1] != previous.edge_intents
                or len(selected.edge_intents) != 2 or selected.edge_intents[1].get("id") != "edge-02"
                or len(selected.nodes) != 3 or previous.nodes != [
                    selected.nodes[0], {**selected.nodes[1], "edgeCount": "1"}]
                or sibling.edge_count != 1 or len(sibling.nodes) != 2
                or _fingerprint({row.chain_id: row.to_dict() for row in (previous, sibling)})
                != source.chain_projection_sha256):
            raise ValueError("initial chain projection or single-edge delta differs")
        original_nodes = [node for row in (previous, sibling) for node in row.nodes]
        original_projection = sorted(({
            "chainId": node["chainId"], "role": node["role"],
            "providerInstanceId": node["providerInstanceId"],
            "terraformAddress": node["terraformAddress"],
            "name": node["hostname"], "publicIp": node["publicIp"],
            "region": node["region"],
        } for node in original_nodes), key=lambda node: node["terraformAddress"])
        if (manifest[0].get("nodes") != original_projection
                or initial.events[-1].data.get("chainIds") != list(source.chain_ids)):
            raise ValueError("original four node identities differ")
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        intent = compile_fresh_digitalocean_persisted_intent(
            engagement, current_rows, core, core_plan, profile,
            environment=environment, provider_state_exists=True,
            mode="materialized_read", reviewed_initial_chains=(previous, sibling),
        )
        workspace = Path(selected.terraform_working_directory)
        if (workspace != Path(sibling.terraform_working_directory)
                or not workspace.is_absolute() or workspace.is_symlink()
                or state_root is not None and state_root not in workspace.parents):
            raise ValueError("appended workspace differs")
        state_path = workspace / "terraform.tfstate"
        if (workspace.resolve(strict=True) != workspace or state_path.is_symlink()
                or not state_path.is_file()):
            raise ValueError("appended state path differs")
        raw = state_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != terminal["stateSha256"]:
            raise ValueError("appended state SHA differs")
        state = json.loads(raw)
        resources = _state_resources(state)
        if set(resources) != set(intent.nodes) | _SHARED:
            raise ValueError("five-node managed state differs")
        if any(str(resources[address].get("id")) != expected
               for address, expected in plan_event.data["retainedSharedIds"].items()):
            raise ValueError("retained provider shared resource identity differs")
        projected = {node["terraformAddress"]: node for row in current_rows for node in row.nodes}
        if len(projected) != 5 or set(projected) != set(intent.nodes):
            raise ValueError("five-node projection differs")
        for address, reviewed in intent.nodes.items():
            actual, row = resources[address], projected[address]
            if (actual.get("name") != reviewed.name or actual.get("image") != reviewed.image
                    or actual.get("size") != reviewed.size or actual.get("region") != reviewed.region
                    or actual.get("tags") != [intent.selector_tag]
                    or str(actual.get("id")) != row["providerInstanceId"]
                    or actual.get("ipv4_address") != row["publicIp"]):
                raise ValueError("appended provider node differs")
        new_node = selected.nodes[2]
        if (children["apply"].events[-1].data.get("stateSha256") != terminal["stateSha256"]
                or children["apply"].events[-1].message != "provider append apply completed"
                or children["hostProof"].events[-1].message !=
                   "strict append host proof completed"
                or children["hostProof"].events[-1].data.get("newEdgeAddress")
                != new_node["terraformAddress"]
                or children["hostProof"].events[-1].data.get("newEdgeProviderId")
                != new_node["providerInstanceId"]):
            raise ValueError("append apply or host proof differs")
        from app.services.provider_keyed_append_apply_job import _completed_apply_child_receipt
        from app.services.provider_keyed_append_host_proof_job import (
            _completed_child_receipt, _host_evidence_path,
        )
        _completed_apply_child_receipt(children["apply"], parent,
                                       hashes["planJournalSha256"], plan_event.data,
                                       {str(node["providerInstanceId"])
                                        for row in (previous, sibling) for node in row.nodes})
        reservation = [event for event in parent.events
                       if event.message == "strict append host proof reserved"]
        if len(reservation) != 1 or set(reservation[0].data) != {"manifestSha256"}:
            raise ValueError("append host reservation differs")
        _completed_child_receipt(
            children["hostProof"], parent, children["apply"],
            reservation[0].data["manifestSha256"], {
                "newEdgeAddress": new_node["terraformAddress"],
                "newEdgeProviderId": new_node["providerInstanceId"],
                "stateSha256": terminal["stateSha256"],
            }, _host_evidence_path(workspace, parent.id), selected=selected, jobs=jobs)
        firewall = resources["digitalocean_firewall.firewall"]
        UUID(str(firewall.get("id")))
        peers = sorted(f"{node['publicIp']}/32" for node in projected.values())
        expected_ingress = [_inbound(proto, "1-65535", peers)
                            for proto in ("icmp", "tcp", "udp")]
        expected_ingress += [_inbound("tcp", port, ["0.0.0.0/0"])
                             for port in intent.firewall.public_tcp_ports]
        expected_ingress.append(_inbound("tcp", "22", list(intent.firewall.trusted_ssh_cidrs)))
        expected_egress = [_outbound(proto, "" if proto == "icmp" else "1-65535",
                                     "0.0.0.0/0") for proto in ("tcp", "udp", "icmp")]
        if (firewall.get("name") != intent.firewall.name
                or firewall.get("tags") != [intent.selector_tag]
                or "droplet_ids" not in firewall
                or firewall["droplet_ids"] is not None
                or _sorted_rules(firewall.get("inbound_rule")) != _sorted_rules(expected_ingress)
                or _sorted_rules(firewall.get("outbound_rule")) != _sorted_rules(expected_egress)):
            raise ValueError("expanded firewall state differs")
        return PublishedProviderKeyedAppendSource(
            source, parent.id, job_event_digest(parent.events), terminal["stateSha256"],
            new_node["terraformAddress"], new_node["providerInstanceId"],
        )
    except Exception:
        raise ProviderKeyedAppendSourceError("published appended generation is unproved") from None


def _decode_initial_source(value: object) -> PublishedProviderKeyedSource:
    if not isinstance(value, dict) or set(value) != set(PublishedProviderKeyedSource.__dataclass_fields__):
        raise ValueError("initial source schema differs")
    source = PublishedProviderKeyedSource(**{**value, "chain_ids": tuple(value["chain_ids"])})
    if len(source.chain_ids) != 2 or len(set(source.chain_ids)) != 2:
        raise ValueError("initial source chain set differs")
    for name in ("initial_journal_sha256", "core_journal_sha256", "scope_sha256",
                 "state_sha256", "manifest_sha256", "published_host_evidence_sha256",
                 "chain_projection_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", getattr(source, name)) is None:
            raise ValueError("initial source digest differs")
    return source


def _restore_chain(value: dict) -> StoredSketchChain:
    fields = {"chainId": "chain_id", "engagementId": "engagement_id",
              "assignedProxy": "assigned_proxy", "middleProvider": "middle_provider",
              "middleRegion": "middle_region", "middleSize": "middle_size",
              "edgeProvider": "edge_provider", "edgeRegion": "edge_region",
              "edgeSize": "edge_size", "edgeCount": "edge_count",
              "status": "status", "burned": "burned", "burnedNote": "burned_note",
              "deployJobId": "deploy_job_id", "teardownJobId": "teardown_job_id",
              "terraformWorkingDirectory": "terraform_working_directory",
              "nodes": "nodes", "createdAt": "created_at", "updatedAt": "updated_at"}
    if set(value) != set(fields) | {"edges"}:
        raise ValueError("initial selected row snapshot differs")
    return StoredSketchChain(**{target: value[source] for source, target in fields.items()},
                             edge_intents=value["edges"])


def _sha_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
