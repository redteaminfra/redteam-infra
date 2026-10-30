# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only scope for destroying owned initial hosts after failed web Apply.

This proves cleanup scope, never historical nonmutation. The saved evidence is
also usable after host rows retire; no current inventory is needed to reread it.
"""
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import re

from app.services.provider_keyed_mixed_public_targets import build_public_target_seal, digest
from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
from app.storage.binding_history import is_independent_binding_history
from app.storage.job_repository import job_event_digest

KEY = "publishedInitialCleanupSeal"
MARKER = "publishedInitialCleanupAuthority"
SCHEMA = "published-initial-failed-http-cleanup-v1"
RETIREMENT_SCHEMA = "published-initial-service-retirement-v1"
_READ_ONLY = {"inbound_channel_apply_preview", "web_static_service_apply_preview"}
_MUTATIONS = {"inbound_channel_apply", "web_static_service_apply", "engagement_channels_update"}


def _time(value):
    if type(value) is not str:
        raise ValueError("cleanup timestamp missing")
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _job_identity(job):
    return {"id": job.id, "action": job.action, "status": job.status,
            "requestedBy": job.requested_by,
            "target": job.target, "targetType": job.target_type, "targetId": job.target_id,
            "inputSha256": digest(job.input), "journalSha256": job_event_digest(job.events),
            "artifactRefsSha256": digest(job.artifact_refs),
            "createdAt": job.created_at, "startedAt": job.started_at, "finishedAt": job.finished_at}


def _source_job_identities(core, initial):
    from app.services.provider_keyed_initial_continuation import _job_ids
    engagement_id = core.input.get("engagementId")
    if (core.action != "pilot_standard_rti_guarded_execute" or core.status != "succeeded"
            or not engagement_id or not core.input.get("corePlanId")
            or initial.id != _job_ids(core.id)[0] or initial.action != "provider_keyed_initial"
            or initial.status != "succeeded" or initial.target_id != engagement_id
            or initial.target_type != "engagement" or initial.target != f"engagement:{engagement_id}"
            or initial.input.get("engagementId") != engagement_id
            or initial.input.get("coreJobId") != core.id
            or initial.input.get("corePlanId") != core.input["corePlanId"]):
        raise ValueError("cleanup source job lineage differs")
    return {core.id: _job_identity(core), initial.id: _job_identity(initial)}


def _related(jobs, engagement_id, *, before=None, source_jobs=None):
    """Coordinator work is not binding work; unknown binding producers reject."""
    rows = jobs.list_for_engagement(engagement_id)
    result = []
    for job in rows:
        # Exact validated sources may project auto-derived channel definitions.
        # Their complete journals are separately sealed, never silently ignored.
        if source_jobs is not None and job.id in source_jobs:
            if _job_identity(job) != source_jobs[job.id]:
                raise ValueError("cleanup source job changed during history read")
            continue
        if before is not None and _time(job.created_at) > before:
            continue
        from app.services.engagement_operations import _is_default_backflip
        raw_channel = any(
            event.data.get("outboundChannels")
            or any(not _is_default_backflip(row) for row in event.data.get("inboundChannels", []))
            for event in job.events)
        if not is_independent_binding_history(job.action) and not raw_channel:
            continue
        if (job.action not in _READ_ONLY | _MUTATIONS
                or job.target_id != engagement_id or job.target_type != "engagement"
                or job.target != f"engagement:{engagement_id}"
                or job.status not in {"succeeded", "failed"} or not job.finished_at
                or _time(job.created_at) > _time(job.started_at)
                or _time(job.started_at) > _time(job.finished_at)
                or [e.sequence for e in job.events] != list(range(1, len(job.events) + 1))):
            raise ValueError("unreviewed binding history")
        if job.action in _READ_ONLY and (job.status != "succeeded" or job.input.get("mutation") is not False):
            raise ValueError("unproved read-only binding producer")
        if job.action in _READ_ONLY:
            expected = {"inbound_channel_apply_preview": "inbound channel apply preview rendered",
                        "web_static_service_apply_preview": "static web service apply preview rendered"}[job.action]
            if (len(job.events) != 1 or job.events[0].message != expected
                    or job.events[0].level != "info" or job.events[0].data.get("mutation") is not False):
                raise ValueError("read-only binding producer journal differs")
        if job.action == "engagement_channels_update" and (
                job.status != "succeeded" or len(job.events) != 1
                or job.events[0].message != "engagement channels updated"
                or set(job.events[0].data) != {"inboundChannels", "outboundChannels"}
                or any(type(job.events[0].data[key]) is not list for key in job.events[0].data)):
            raise ValueError("channel definition producer differs")
        result.append(job)
    return sorted(result, key=lambda row: row.id)


def has_failed_web_history(jobs, engagement_id, *, before=None):
    # Presence forces sealed review, including malformed/nonterminal attempts.
    return any(row.action == "inbound_channel_apply"
               and (before is None or _time(row.created_at) <= before)
               for row in jobs.list_for_engagement(engagement_id))


def seal_marker(snapshot):
    if KEY not in snapshot:
        return None
    seal = snapshot[KEY]
    if (type(seal) is not dict or seal.get("schema") != SCHEMA
            or seal.get("sha256") != digest({k: v for k, v in seal.items() if k != "sha256"})):
        raise ValueError("published cleanup seal differs")
    return {"schema": SCHEMA, "sha256": seal["sha256"]}


def queued_cleanup_event_data(snapshot):
    result = {"snapshotId": snapshot["snapshotId"]}
    marker = seal_marker(snapshot)
    if marker is not None:
        result[MARKER] = marker
    return result


def _core_details(core):
    rows = next((e.data["connectionDetails"] for e in reversed(core.events)
                 if type(e.data.get("connectionDetails")) is list), [])
    rows = [row for row in rows if row.get("role") in {"homebase", "proxy"}]
    if (len([r for r in rows if r.get("role") == "homebase"]) != 1
            or len([r for r in rows if r.get("role") == "proxy"]) != core.input.get("proxyCount")
            or any(not all(type(r.get(k)) is str and r[k] for k in
                           ("publicIp", "privateIp", "sshAlias", "displayName", "sshUser")) for r in rows)):
        raise ValueError("core host identity incomplete")
    return rows


def _core_match(route, rows, role):
    matches = [row for row in rows if row["role"] == role
               and route.get("name") in {row["displayName"], row["sshAlias"]}
               and route.get("publicIp") == row["publicIp"]
               and route.get("privateIp") == row["privateIp"]
               and route.get("ansibleHost") == (row["publicIp"] if role == "homebase" else row["privateIp"])
               and route.get("sshUser") == row["sshUser"] and route.get("chainId") == ""]
    if len(matches) != 1:
        raise ValueError("route core host differs")
    return matches[0]


def _chronology(job, core, initial, all_jobs):
    if (core.status != "succeeded" or initial.status != "succeeded"
            or _time(core.finished_at) > _time(job.started_at)
            or _time(initial.finished_at) > _time(job.started_at)
            or any(row.action == core.action and row.id != core.id
                   and _time(row.created_at) >= _time(core.created_at) for row in all_jobs)):
        raise ValueError("binding core generation is ambiguous")


def _current_quiescence(core, jobs, all_jobs):
    """Only this exact coordinator may be active during its own pre-GO read."""
    from app.services.engagement_teardown import _parent_id
    parent_id = _parent_id(core.id)
    parent = jobs.get(parent_id)
    suffix = core.id.removeprefix("job-")
    allowed = {
        parent_id: "engagement_comprehensive_teardown",
        f"job-provider-keyed-comprehensive-teardown-{suffix}": "provider_keyed_comprehensive_teardown",
        f"job-provider-keyed-initial-destroy-plan-{suffix}": "provider_keyed_initial_destroy_plan",
        f"job-provider-keyed-initial-destroy-apply-{suffix}": "provider_keyed_initial_destroy_apply",
    }
    for row in all_jobs:
        if row.status not in {"queued", "running"}:
            continue
        if (parent is None or row.id not in allowed or row.action != allowed[row.id]
                or parent.status not in {"queued", "running"} or row.finished_at is not None
                or row.requested_by != parent.requested_by
                or row.target_id != core.input["engagementId"] or row.target_type != "engagement"
                or row.target != f"engagement:{core.input['engagementId']}"
                or row.input.get("coreJobId") != core.id
                or parent.input.get(MARKER) != seal_marker(parent.input["scopeSnapshot"])
                or parent.events[0].data != queued_cleanup_event_data(parent.input["scopeSnapshot"])):
            raise ValueError("active work is outside exact cleanup coordinator")
        if row.id != parent_id and (
                row.input.get("teardownParentId") != parent_id
                or row.input.get("corePlanId") != core.input["corePlanId"]
                or row.input.get("scopeSnapshotId") != parent.input["scopeSnapshot"]["snapshotId"]):
            raise ValueError("active cleanup child lineage differs")


def _attempt(job, core, initial, rows, chains, all_jobs):
    _chronology(job, core, initial, all_jobs)
    if job.status != "failed" or job.input.get("mutation") is not True:
        raise ValueError("only terminal failed web Apply qualifies")
    prefix = ["inbound channel apply workspace rendered", "inbound channel Ansible apply started"]
    messages = [e.message for e in job.events]
    # This is cleanup scope, not a no-write inference. Historical keyed host
    # callbacks contain opaque argv hashes and a different mixed source type;
    # they cannot establish this initial generation's host confinement.
    allowed_middle = {"keyed channel ingress requires observation"}
    if (len(messages) < 4 or messages[:2] != prefix
            or messages[-1] != "inbound channel provider ingress sync failed"
            or any(message not in allowed_middle for message in messages[2:-1])
            or messages[-2] != "keyed channel ingress requires observation"):
        raise ValueError("unreviewed failed Apply phases")
    first = job.events[0].data
    route = first.get("resolvedRoute")
    if type(route) is not dict or set(route) != {"homebase", "proxy", "middle", "edge"}:
        raise ValueError("literal failed route missing")
    homebase = _core_match(route["homebase"], rows, "homebase")
    proxy = _core_match(route["proxy"], rows, "proxy")
    candidates = [chain for chain in chains if chain.chain_id == route["edge"].get("chainId")]
    if len(candidates) != 1:
        raise ValueError("failed route chain differs")
    chain = candidates[0]
    from app.services.core_ssh import core_proxy_identity
    identity = core_proxy_identity([proxy], chain.assigned_proxy)
    if not identity or identity["displayName"] != route["proxy"]["name"]:
        raise ValueError("failed route proxy predecessor differs")
    selected = {}
    for role in ("middle", "edge"):
        target = route[role]
        nodes = [node for node in chain.nodes if node.get("role") == role
                 and node.get("hostname") == target.get("name")
                 and node.get("publicIp") == target.get("publicIp")]
        if (len(nodes) != 1 or target.get("ansibleHost") != nodes[0]["publicIp"]
                or target.get("chainId") != chain.chain_id or target.get("privateIp") != ""):
            raise ValueError("failed route Sketch host differs")
        selected[role] = nodes[0]
    evidence = first.get("workspaceEvidence")
    if type(evidence) is not dict or evidence.get("manifest", {}).get("target") != "MANIFEST.json":
        raise ValueError("failed workspace missing")
    manifest = json.loads(evidence["manifest"]["content"])
    channel = manifest.get("channel")
    if (manifest.get("mode") != "inbound_channel_apply" or manifest.get("resolvedRoute") != route
            or type(channel) is not dict or channel.get("channelId") != job.input.get("channelId")
            or channel.get("mode") not in {"http-openresty", "https-openresty"}
            or channel.get("protocol") not in {"HTTP", "HTTPS"}
            or str(channel.get("externalPort")) not in {"80", "443"}
            or channel.get("proxy") != route["proxy"]["name"]
            or channel.get("terminatesOn") != route["proxy"]["name"]
            or channel.get("middle") != route["middle"]["name"]
            or channel.get("edge") != route["edge"]["name"]
            or channel.get("chainId") != chain.chain_id
            or job.input.get("proxyId") != route["proxy"]["name"]):
        raise ValueError("failed HTTP workspace route differs")
    expected_inventory = [route[role]["name"] for role in ("proxy", "middle", "edge")]
    if (first.get("inventoryTargets") != expected_inventory
            or job.events[1].data.get("inventoryTargets") != expected_inventory
            or job.events[-1].data.get("channelId") != channel["channelId"]):
        raise ValueError("failed route inventory differs")
    # Re-render the narrow supported producer, including inventory, strict SSH
    # hops and every playbook. Metadata/labels alone cannot prove confinement.
    from app.services.inbound_channel_apply import (
        InboundResolvedRoute, InboundRouteTarget, _spec_from_channel, render_inbound_apply_workspace,
        _apply_phase_commands, _phase_command_dict,
        _proxy_upstream_host,
    )
    from app.services.inbound_channel_artifacts import render_inbound_channel_artifacts
    literal_route = InboundResolvedRoute(**{role: InboundRouteTarget(
        value["name"], value["ansibleHost"], value["publicIp"], value["privateIp"],
        value["chainId"], value["sshUser"]) for role, value in route.items()}, termination=None)
    engagement_name = core.input.get("engagementName")
    if type(engagement_name) is not str or not engagement_name.strip():
        raise ValueError("original core engagement label missing")
    spec = _spec_from_channel(engagement_name, channel)
    spec = replace(spec,
        sketch_chain_id=spec.sketch_chain_id or literal_route.edge.chain_id,
        edge_upstream_host=literal_route.middle.public_ip or literal_route.middle.ansible_host,
        middle_upstream_host=literal_route.proxy.public_ip or literal_route.proxy.ansible_host or literal_route.proxy.private_ip,
        proxy_upstream_host=_proxy_upstream_host(spec, literal_route))
    targets = manifest["targets"]
    workspace = render_inbound_apply_workspace(spec, render_inbound_channel_artifacts(spec),
        core_ssh_private_key_file=targets["homebase"]["sshPrivateKeyFile"],
        local_sketch_key_file=targets["edge"]["sshPrivateKeyFile"], route=literal_route,
        keyed_sketch_policy=True)
    rendered = workspace.to_dict()
    # The producer renders path labels from engagement.name; the compact saved
    # channel omits it. Reopen the exact retained core generation's label,
    # without inventing a fallback or changing any saved artifact.
    if rendered != evidence:
        raise ValueError("failed workspace differs from bounded HTTP producer")
    commands = job.events[1].data.get("commands")
    if (type(commands) is not list or not commands
            or type(commands[0].get("command")) is not list or not commands[0]["command"]):
        raise ValueError("failed Apply command intent missing")
    binary = commands[0]["command"][0]
    if (type(binary) is not str or binary.split("/")[-1] != "ansible-playbook"
            or commands != [_phase_command_dict(command) for command in _apply_phase_commands(binary, workspace)]
            or job.events[1].data.get("cwd") != first.get("workspaceDir")
            or job.artifact_refs != [workspace.inventory.target, workspace.ssh_config.target,
                                    *[play.target for play in workspace.playbooks], workspace.manifest.target]):
        raise ValueError("failed Apply command intent differs")
    return {"jobId": job.id, "channelId": channel["channelId"], "route": route,
            "channel": channel, "edge": selected["edge"], "middle": selected["middle"],
            "coreHosts": [homebase, proxy], "workspaceSha256": digest(evidence)}


def _bindings(engagement_id, jobs, core, initial, all_jobs, core_rows):
    from app.storage.domain_repository import SqlAlchemyDomainRepository
    from app.storage.certificate_repository import SqlAlchemyCertificateRepository
    from app.storage.service_repository import SqlAlchemyEngagementServiceRepository
    from app.services.provider_keyed_mixed_append_live_bindings import _owned_dns_rows
    domains, certificates = SqlAlchemyDomainRepository(), SqlAlchemyCertificateRepository()
    assignments = domains.list_assignments(engagement_id=engagement_id)
    if (any(getattr(row, "status", None) != "released"
            or row.engagement_id != engagement_id or not row.released_at
            or type(row.id) is not int or row.id <= 0 for row in assignments)
            or _owned_dns_rows(engagement_id)
            or certificates.list_assets(engagement_id) or certificates.list_bindings(engagement_id)):
        raise ValueError("independent DNS or certificate bindings exist")
    services = SqlAlchemyEngagementServiceRepository().list_for_engagement(engagement_id)
    result = []
    for service in services:
        apply = jobs.get(service.apply_job_id)
        if (service.engagement_id != engagement_id or service.service_type != "web-static"
                or service.status != "Configured" or apply is None
                or apply.action != "web_static_service_apply" or apply.status != "succeeded"
                or apply.target_id != engagement_id or apply.input.get("serviceId") != service.service_id
                or apply.input.get("serviceType") != "web-static"
                or apply.input.get("proxyId") != service.proxy_id
                or apply.input.get("mutation") is not True or len(apply.events) != 3
                or [e.message for e in apply.events] != ["static web service apply workspace rendered",
                    "static web service Ansible apply started", "static web service Ansible apply succeeded"]
                or apply.events[0].data.get("inventoryTargets") != ["selected_proxy"]
                or apply.events[1].data.get("inventoryTargets") != ["selected_proxy"]):
            raise ValueError("Static Web provenance differs")
        _chronology(apply, core, initial, all_jobs)
        from app.services.core_ssh import core_proxy_identity
        proxy = core_proxy_identity(core_rows, service.proxy_id)
        descriptor = apply.events[0].data.get("service", {})
        if (not proxy or descriptor.get("proxyId") != service.proxy_id
                or descriptor.get("serviceId") != service.service_id
                or descriptor.get("serviceType") != service.service_type
                or any(descriptor.get(k) != service.config.get(k) for k in service.config)
                or apply.events[-1].data.get("status") != "Configured"
                or apply.events[-1].data.get("commandResult", {}).get("ok") is not True):
            raise ValueError("Static Web owned placement differs")
        review = _static_producer(apply, descriptor, service, jobs=jobs, core=core,
                                  initial=initial, all_jobs=all_jobs, core_rows=core_rows)
        result.append({"service": asdict(service), "apply": _job_identity(apply),
                       "proxy": proxy, "descriptorSha256": digest(descriptor),
                       "review": _job_identity(review),
                       "hostBindingProof": "literal-content-review-core-binding-v1"})
    return (sorted(result, key=lambda row: row["service"]["service_id"]),
            sorted(({"assignmentId": row.id, "sha256": digest(asdict(row))} for row in assignments),
                   key=lambda row: row["assignmentId"]))


def _static_producer(job, descriptor, service, *, jobs, core, initial, all_jobs, core_rows):
    """Use the linked content review's literal inventory and core-bound hash.

    Apply itself stores metadata only. A missing raw linked review is not
    permission to infer which hosts were selected from matching byte counts.
    """
    from pathlib import PurePosixPath
    from app.services.web_static_service import _intent_from_service, _normalize_content_path
    intent = _intent_from_service(service)  # Reuse safe site/domain/proxy parsing.
    paths = {"inventory": "ansible/inventory.ini", "playbook": "ansible/apply_web_static.yml",
        "manifest": "MANIFEST.json", "siteConfig": f"files/opt/web/{intent.site_name}/conf/default.conf",
        "siteObservabilityConfig": f"files/opt/web/{intent.site_name}/conf/00-barragan-observability.conf",
        "compose": "files/opt/web/docker-compose.yml", "siteCompose": f"files/opt/web/sites/{intent.site_name}.compose.yml",
        "frontHttpConfig": "files/opt/web/nginx.conf", "frontRoute": f"files/opt/web/http/{intent.site_name}.map"}
    first, started, final = [event.data for event in job.events]
    evidence = first.get("workspaceEvidence")
    if type(evidence) is not dict or set(evidence) != set(paths) | {"contentFiles", "siteIndex"}:
        raise ValueError("Static Web producer metadata missing")
    def artifact(row, path):
        if (type(row) is not dict or set(row) != {"path", "bytes", "encoding"} or row["path"] != path
                or type(row["bytes"]) is not int or row["bytes"] < 0 or row["encoding"] not in {"text", "base64"}):
            raise ValueError("Static Web producer artifact differs")
    for key, path in paths.items():
        artifact(evidence[key], path)
    content = descriptor.get("contentFiles")
    if type(content) is not list or type(evidence["contentFiles"]) is not list or len(content) != len(evidence["contentFiles"]):
        raise ValueError("Static Web content metadata differs")
    for index, row in enumerate(content):
        path = _normalize_content_path(row.get("path"), index)
        artifact(evidence["contentFiles"][index], f"files/opt/web/{intent.site_name}/html/{path}")
        if any(evidence["contentFiles"][index][key] != row.get(key) for key in ("bytes", "encoding")):
            raise ValueError("Static Web content artifact differs")
    index_path = f"files/opt/web/{intent.site_name}/html/index.html"
    index = next((row for row in evidence["contentFiles"] if row["path"] == index_path),
                 {"path": "files/index.html", "bytes": 0, "encoding": "text"})
    if evidence["siteIndex"] != index:
        raise ValueError("Static Web index metadata differs")
    command = started.get("command")
    if (type(command) is not list or len(command) != 4 or type(command[0]) is not str
            or command[0].split("/")[-1] != "ansible-playbook"
            or command[1:] != ["-i", "ansible/inventory.ini", "ansible/apply_web_static.yml"]
            or type(first.get("workspaceDir")) is not str or not PurePosixPath(first["workspaceDir"]).is_absolute()
            or started.get("cwd") != first["workspaceDir"]
            or job.artifact_refs != ["ansible/inventory.ini", "ansible/apply_web_static.yml", "MANIFEST.json"]
            or final.get("commandResult", {}).get("returncode") != 0
            or type(final["commandResult"].get("returncode")) is not int):
        raise ValueError("Static Web producer command differs")
    review = jobs.get(job.input.get("contentReviewJobId"))
    if (review is None or review.action != "web_static_service_apply_preview" or review.status != "succeeded"
            or review.target_id != job.target_id or review.requested_by != job.requested_by
            or len(review.events) != 1 or review.input.get("serviceId") != service.service_id
            or _time(review.finished_at) > _time(job.started_at)):
        raise ValueError("Static Web linked content review missing")
    _chronology(review, core, initial, all_jobs)
    workspace = review.events[0].data.get("workspace", {})
    manifest = json.loads(workspace["manifest"]["content"])
    saved_descriptor = manifest["service"]
    if ({key: value for key, value in saved_descriptor.items() if key != "contentReviewJobId"}
            != {key: value for key, value in descriptor.items() if key != "contentReviewJobId"}):
        raise ValueError("Static Web review configuration differs")
    from app.services.core_ssh import core_proxy_identity
    from app.services.web_static_service import (
        WebStaticCoreHost, WebStaticContentFile, WebStaticIntent,
        _content_review_binding, _render_inventory, _render_manifest,
        render_web_static_apply_workspace, _workspace_evidence,
    )
    targets = manifest["targets"]
    if set(targets) != {"selectedProxy", "homebaseJump"}:
        raise ValueError("Static Web review hosts differ")
    homebase = next(row for row in core_rows if row["role"] == "homebase")
    proxy_identity = core_proxy_identity(core_rows, service.proxy_id)
    proxy_row = next(row for row in core_rows if row["publicIp"] == proxy_identity["publicIp"])
    for key, name, host, user, jump in (
            ("homebaseJump", "homebase", homebase["publicIp"], homebase["sshUser"], ""),
            ("selectedProxy", service.proxy_id, proxy_row["privateIp"], proxy_row["sshUser"],
             homebase["sshUser"] + "@" + homebase["publicIp"])):
        target = targets[key]
        if (target.get("name") != name or target.get("ansibleHost") != host
                or target.get("ansibleUser") != user or target.get("proxyJump", "") != jump
                or not target.get("sshPrivateKeyFile")):
            raise ValueError("Static Web literal reviewed host differs")
    def host(row):
        return WebStaticCoreHost(row["name"], row["ansibleHost"], row["ansibleUser"],
            row["sshPrivateKeyFile"], row.get("proxyJump", ""), row.get("knownHostsFile", ""))
    hb, proxy = host(targets["homebaseJump"]), host(targets["selectedProxy"])
    files = []
    for row in saved_descriptor["contentFiles"]:
        path = "files/opt/web/" + intent.site_name + "/html/" + row["path"]
        matches = [artifact for artifact in workspace["artifacts"] if artifact["target"] == path]
        if len(matches) != 1:
            raise ValueError("Static Web reviewed content missing")
        artifact = matches[0]
        encoding = artifact["encoding"]
        files.append(WebStaticContentFile(row["path"], artifact[
            "contentBase64" if encoding == "base64" else "content"], encoding))
    literal_intent = WebStaticIntent(service.service_id, intent.site_name, intent.domain,
        service.proxy_id, intent.internal_port, "", tuple(files),
        saved_descriptor["contentAction"], "", saved_descriptor["contentReviewJobId"])
    apply_intent = WebStaticIntent(service.service_id, intent.site_name, intent.domain,
        service.proxy_id, intent.internal_port, "", tuple(files),
        descriptor["contentAction"], "", descriptor["contentReviewJobId"])
    expected_workspace = render_web_static_apply_workspace(intent=literal_intent,
        homebase=hb, proxy=proxy, retained_binding=None).to_dict()
    # The renderer deliberately allocates a fresh private operation UUID on
    # every call. Normalize only that exact closed-shape scalar; all executable
    # content, destinations and artifact sets must still equal the producer.
    def stable_workspace(value):
        value = json.loads(json.dumps(value))
        content = value["playbook"]["content"]
        roots = re.findall(r'content_operation_root: "(/tmp/barragan-static-content-[0-9a-f]{32})"', content)
        if len(roots) != 1:
            raise ValueError("Static Web operation identity differs")
        value["playbook"]["content"] = content.replace(roots[0], "/tmp/barragan-static-content-" + "0" * 32)
        return value
    if stable_workspace(workspace) != stable_workspace(expected_workspace):
        raise ValueError("Static Web canonical review workspace differs")
    if evidence != _workspace_evidence(render_web_static_apply_workspace(
                intent=apply_intent, homebase=hb, proxy=proxy, retained_binding=None)):
        raise ValueError("Static Web canonical producer workspace differs")
    inventory = workspace["inventory"]
    if (workspace["manifest"].get("target") != "MANIFEST.json"
            or inventory.get("target") != "ansible/inventory.ini"
            or inventory.get("content") != _render_inventory(proxy)
            or workspace["manifest"]["content"] != _render_manifest(literal_intent, hb, proxy)
            or evidence["inventory"]["bytes"] != len(inventory["content"].encode())
            or evidence["manifest"]["bytes"] != len(_render_manifest(
                WebStaticIntent(service.service_id, intent.site_name, intent.domain, service.proxy_id,
                    intent.internal_port, "", tuple(files), descriptor["contentAction"], "",
                    descriptor["contentReviewJobId"]), hb, proxy).encode())
            or review.input.get("contentReview", {}).get("binding") != _content_review_binding(
                jobs, job.target_id, literal_intent, hb, proxy)):
        raise ValueError("Static Web reviewed core binding differs")
    return review


def build_cleanup_seal(core, snapshot, *, jobs, chains):
    """Current local review only. Provider GETs remain outside this collector."""
    engagement_id = core.input["engagementId"]
    from app.services.provider_keyed_initial_continuation import _job_ids
    from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
    initial = jobs.get(_job_ids(core.id)[0])
    if initial is None or snapshot.get("domainAssignments") != []:
        raise ValueError("published initial source missing")
    related = _related(jobs, engagement_id, source_jobs=_source_job_identities(core, initial))
    applies = [job for job in related if job.action == "inbound_channel_apply"]
    if not applies:
        return None
    rows = reviewed_mixed_chain_rows(chains.list_for_engagement(engagement_id),
                                    snapshot["providerScopes"][0]["chainIds"], engagement_id)
    core_rows, all_jobs = _core_details(core), jobs.list_for_engagement(engagement_id)
    _current_quiescence(core, jobs, all_jobs)
    attempts = [_attempt(job, core, initial, core_rows, rows, all_jobs) for job in applies]
    allowed_ids = {row["channelId"] for row in attempts}
    for job in related:
        for event in job.events:
            if event.data.get("outboundChannels") not in (None, []):
                raise ValueError("outbound definition exists")
            for channel in event.data.get("inboundChannels", []):
                from app.services.engagement_operations import _is_default_backflip
                if not _is_default_backflip(channel) and channel.get("channelId") not in allowed_ids:
                    raise ValueError("unreviewed channel definition")
    services, released_assignments = _bindings(engagement_id, jobs, core, initial, all_jobs, core_rows)
    if {job.id for job in related if job.action == "web_static_service_apply"} != {
            row["apply"]["id"] for row in services}:
        raise ValueError("unaccounted Static Web mutation")
    source = {"core": _job_identity(core), "initial": _job_identity(initial),
              "providerScope": snapshot["providerScopes"][0], "coreHosts": core_rows,
              "chains": [row.to_dict() for row in rows]}
    manifest = {"sourceSha256": digest(source), "coreJobId": core.id,
                "edgeTargets": [{**node, "provider": "digitalocean", "chainId": row.chain_id}
                                for row in rows for node in row.nodes if node["role"] == "edge"],
                "domains": []}
    routes = tuple(KeyedRouteIntent(row["jobId"], "web", row["edge"]["terraformAddress"],
        row["middle"]["terraformAddress"], int(row["channel"]["externalPort"]),
        int(row["channel"]["externalPort"]), ("0.0.0.0/0",)) for row in attempts)
    from app.services.provider_keyed_pending_cleanup import _require_diagnostic_targets
    # Derive the old exact core targets independently of raw failed snapshots.
    core_targets = [{"id": f"tcp:{r['publicIp']}:22", "type": "tcp-forbidden",
                     "host": r["publicIp"], "port": 22, "targetGroup": "core-public-management"}
                    for r in core_rows]
    _require_diagnostic_targets(core, {**snapshot, "publicVerificationTargets": core_targets})
    seal = {"schema": SCHEMA, "engagementId": engagement_id, "coreJobId": core.id,
            "source": source, "attempts": attempts, "services": services,
            "releasedAssignments": released_assignments,
            "evidence": [_job_identity(row) for row in related], "targetManifest": manifest,
            "publicTargets": build_public_target_seal(manifest, core_targets, routes)}
    seal["sha256"] = digest(seal)
    return json.loads(json.dumps(seal))


def cleanup_public_targets(snapshot):
    """Pure sealed projection, not job-history or provider ownership authority.

    Proposals have no persisted parent marker yet. Rebuild their exact numeric
    targets from the sealed source, leaving provenance to the existing writer
    and saved-parent checks. Never normalize the retained target bytes.
    """
    if seal_marker(snapshot) is None:
        raise ValueError("published cleanup seal missing")
    seal, core_id, engagement_id = snapshot[KEY], snapshot["coreJobId"], snapshot["engagementId"]
    source = seal["source"]
    from app.services.provider_keyed_initial_continuation import _job_ids
    if (seal["coreJobId"] != core_id or seal["engagementId"] != engagement_id
            or source["core"]["id"] != core_id
            or source["core"]["action"] != "pilot_standard_rti_guarded_execute"
            or source["core"]["status"] != "succeeded"
            or source["initial"]["id"] != _job_ids(core_id)[0]
            or source["initial"]["action"] != "provider_keyed_initial"
            or source["initial"]["status"] != "succeeded"
            or source["initial"]["targetId"] != engagement_id
            or snapshot["providerScopes"] != [source["providerScope"]]
            or source["providerScope"]["coreJobId"] != core_id
            or source["providerScope"]["provider"] != "digitalocean"
            or [row["chainId"] for row in source["chains"]] != source["providerScope"]["chainIds"]
            or any(row["engagementId"] != engagement_id for row in source["chains"])):
        raise ValueError("published cleanup target source differs")
    manifest = {"sourceSha256": digest(source), "coreJobId": core_id,
        "edgeTargets": [{**node, "provider": "digitalocean", "chainId": chain["chainId"]}
                        for chain in source["chains"] for node in chain["nodes"] if node["role"] == "edge"],
        "domains": []}
    if manifest != seal["targetManifest"]:
        raise ValueError("published cleanup target manifest differs")
    nodes = [(chain["chainId"], node) for chain in source["chains"] for node in chain["nodes"]]
    if len({node["terraformAddress"] for _, node in nodes}) != len(nodes):
        raise ValueError("published cleanup source nodes repeat")
    for attempt in seal["attempts"]:
        matches = [chain_id for chain_id, node in nodes if node == attempt["edge"] and node["role"] == "edge"]
        if (len(matches) != 1 or attempt["channel"]["chainId"] != matches[0]
                or not any(chain_id == matches[0] and node == attempt["middle"] and node["role"] == "middle"
                           for chain_id, node in nodes)):
            raise ValueError("published cleanup attempted route differs")
    routes = tuple(KeyedRouteIntent(row["jobId"], "web", row["edge"]["terraformAddress"],
        row["middle"]["terraformAddress"], int(row["channel"]["externalPort"]),
        int(row["channel"]["externalPort"]), ("0.0.0.0/0",)) for row in seal["attempts"])
    core_targets = [{"id": f"tcp:{r['publicIp']}:22", "type": "tcp-forbidden", "host": r["publicIp"],
                     "port": 22, "targetGroup": "core-public-management"} for r in source["coreHosts"]]
    rebuilt = build_public_target_seal(manifest, core_targets, routes)
    if (rebuilt != seal["publicTargets"] or snapshot["publicVerificationTargets"] != rebuilt["targets"]
            or snapshot["inspector"]["verificationTargetCount"] != len(rebuilt["targets"])):
        raise ValueError("published cleanup public target seal differs")
    return rebuilt["targets"]


def validate_saved_cleanup(parent, core, snapshot, jobs):
    """Authenticate immutable history without live inventory, lease or probes."""
    marker = seal_marker(snapshot)
    # A later deployment must not rewrite the meaning of an older cleanup.
    # Current pre-GO reads classify everything; finished receipts classify the
    # complete history through their authenticated terminal timestamp only.
    before = _time(parent.finished_at) if parent.status == "succeeded" else None
    if marker is None:
        if MARKER in parent.input or has_failed_web_history(jobs, parent.target_id, before=before):
            raise ValueError("failed history cannot downgrade to core-only cleanup")
        return None
    seal = snapshot[KEY]
    if (parent.input.get(MARKER) != marker or seal["engagementId"] != parent.target_id
            or seal["coreJobId"] != core.id or seal["source"]["core"] != _job_identity(core)
            or not parent.events or parent.events[0].data != queued_cleanup_event_data(snapshot)
            or snapshot["publicVerificationTargets"] != seal["publicTargets"]["targets"]
            or snapshot["inspector"]["verificationTargetCount"] != len(snapshot["publicVerificationTargets"])):
        raise ValueError("published cleanup marker or targets differ")
    initial = jobs.get(seal["source"]["initial"]["id"])
    if initial is None or _job_identity(initial) != seal["source"]["initial"]:
        raise ValueError("initial cleanup provenance changed")
    if [_job_identity(row) for row in _related(jobs, parent.target_id, before=before,
            source_jobs=_source_job_identities(core, initial))] != seal["evidence"]:
        raise ValueError("binding history changed after review")
    cleanup_public_targets(snapshot)
    return seal


def validate_cleanup_negative(parent, core, snapshot, negative, jobs):
    seal = validate_saved_cleanup(parent, core, snapshot, jobs)
    if seal is None:
        return
    from app.services.observer_checks import _teardown_target
    targets = [_teardown_target(row) for row in seal["publicTargets"]["targets"]]
    if (negative.input.get(MARKER) != seal_marker(snapshot)
            or negative.input.get("targetSha256") != digest(targets)
            or negative.input.get("targetCount") != len(targets)
            or negative.input.get("scopeSnapshotId") != snapshot["snapshotId"]):
        raise ValueError("sealed cleanup negative targets differ")


def service_retirement_receipt(parent, snapshot, retired_at):
    """Immutable result projection; does not read today's service definitions."""
    marker = seal_marker(snapshot)
    if marker is None:
        return None
    stamp = _time(retired_at).isoformat()
    services = snapshot[KEY]["services"]
    before = [entry["service"] for entry in services]
    if (len({row["service_id"] for row in before}) != len(before)
            or any(row["engagement_id"] != parent.target_id
                   or row["service_type"] != "web-static" or row["status"] != "Configured"
                   for row in before)):
        raise ValueError("sealed service retirement scope differs")
    receipt = {"schema": RETIREMENT_SCHEMA, "authority": marker,
               "teardownParentId": parent.id, "coreJobId": parent.input["coreJobId"],
               "scopeSnapshotId": snapshot["snapshotId"], "retiredAt": stamp,
               "services": [{"before": row, "after": {**row, "status": "Retired", "updated_at": stamp}}
                            for row in before]}
    receipt["sha256"] = digest(receipt)
    return receipt


def validate_service_retirement_receipt(parent, snapshot, receipt):
    if (type(receipt) is not dict
            or receipt != service_retirement_receipt(parent, snapshot, receipt.get("retiredAt"))):
        raise ValueError("sealed service retirement receipt differs")
    return receipt
