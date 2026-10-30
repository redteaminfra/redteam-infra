# Copyright (c) 2026, Oracle and/or its affiliates.
"""The UI may choose two edges; server authority supplies everything else."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_append_plan_context as context
from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_pair_parent import _digest
from app.services.provider_keyed_mixed_initial_apply_child import _base as initial_apply_base
from app.services.provider_keyed_mixed_initial_plan_parent import _MESSAGES as initial_messages
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import StoredSketchChain


def _put(path: Path, value: object, *, raw: bool = False) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = value if raw else (json.dumps(value, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    path.chmod(0o600)
    return data


@pytest.fixture(params=[("digitalocean", "linode"), ("linode", "digitalocean")])
def selected(tmp_path, monkeypatch, request):
    monkeypatch.setattr(context, "require_mixed_append_digitalocean_availability", lambda *args, **kwargs: None)
    monkeypatch.setattr(context, "require_no_independent_mixed_append_bindings", lambda *args, **kwargs: None)
    order = request.param
    engagement, core_id, plan_id = "eng-selected", "job-core-selected", "plan-selected"
    chain_ids = {"digitalocean": "chain-do", "linode": "chain-linode"}
    core = SimpleNamespace(id=core_id, input={"engagementId": engagement,
                                             "corePlanId": plan_id})
    plan = SimpleNamespace(id=plan_id)
    seal = {"orderedProviders": list(order),
            "chainIds": [chain_ids[p] for p in order],
            "reviewedPolicy": {}}
    manifest = {"schema": "mixed-initial-host-binding-v1",
                "engagementId": engagement, "coreJobId": core_id,
                "corePlanId": plan_id, "orderedProviders": list(order),
                "chainIds": [chain_ids[p] for p in order],
                "nodes": [{"chainId": chain_ids[p], "provider": p,
                           "role": role, "publicIp": ip}
                          for p, ips in (("digitalocean", ("203.0.113.3", "203.0.113.4")),
                                         ("linode", ("203.0.113.5", "203.0.113.6")))
                          for role, ip in zip(("middle", "edge"), ips, strict=True)]}
    schema = tmp_path / engagement / "provider-keyed-v2"
    originals, workspaces, raws, receipts = {}, {}, {}, {}
    for provider in order:
        connection_id = f"credential-{provider}"
        fingerprint = hashlib.sha256(f"{provider}\0{connection_id}".encode()).hexdigest()
        root = schema / provider / fingerprint
        root.mkdir(parents=True)
        _put(root / ".barragan-provider-keyed-state.json", {
            "provider_connection_id": connection_id,
            "source_revision": "revision", "source_files": []})
        workspace = ProviderKeyedWorkspace(
            root, root / "terraform.tfstate", root / ".terraform-data",
            "provider-keyed-v2", provider, connection_id,
            fingerprint, "revision", "0" * 64)
        workspaces[provider] = workspace
        originals[provider] = {
            "schema": "provider-keyed-v2",
            "middles": {"middle_01": {"region": "us-sea", "ordinal": 1}},
            "edge_groups": {"group_01_us_sea": {"region": "us-sea",
                                                "middle_node": "middle_01",
                                                "ordinals": [1]}},
            "regional_high_water": {"us-sea": 1}}
        _put(root / ".barragan-topology.json", originals[provider])
        raw = _put(workspace.state_path, {"resources": [{"mode": "managed", "type": provider, "name": "node", "instances": [{"attributes": {"id": "101"}}]}]})
        raws[provider] = raw
        vars = ({"docean_image": "ubuntu-20", "edge_size": "s-1vcpu-1gb",
                 "firewall_selector_tag": "selector-opaque", "engagement_name": "eng-name",
                 "allowed_tcp_ports": ["22", "80", "443", "2222"],
                 "allowed_udp_ports": [], "trusted_ssh_cidrs": ["203.0.113.4/32"]}
                if provider == "digitalocean" else
                {"linode_image": "ubuntu-20", "edge_type": "g6-nanode-1",
                 "engagement_name": "eng-name"})
        vars.update({"middles": originals[provider]["middles"],
                     "edge_groups": originals[provider]["edge_groups"]})
        seal["reviewedPolicy"][provider] = {
            "topology": originals[provider], "nonsecret_varfile": vars,
            "admin_public_key": "ssh-ed25519 retained-key",
            "provider_connection_id": connection_id,
            "selector_tag": "selector-opaque" if provider == "digitalocean" else None}
        material = schema / ".plan-material" / provider
        inputs = {**vars, "ssh_pub_key_path": str(material / "admin-public"),
                  "ssh_priv_key_path": str(material / "admin-private"),
                  "ssh_config_path": str(material / "ssh-output")}
        inputs_bytes = _put(material / "inputs.json", inputs)
        receipts[provider] = {
            "schema": f"mixed-{provider}-saved-plan-v1", "engagementId": engagement,
            "coreJobId": core_id, "corePlanId": plan_id,
            "connectionId": workspace.provider_connection_id,
            "inputSha256": hashlib.sha256(inputs_bytes).hexdigest(),
            "adminPublicKeySha256": hashlib.sha256(b"ssh-ed25519 retained-key").hexdigest()}
        _put(root / context._RECEIPT[provider], receipts[provider])
    _put(schema / "regional-ordinals.json", {"us-sea": 1})
    parent_input = {"engagementId": engagement, "coreJobId": core_id,
                    "corePlanId": plan_id, "revisionId": "revision",
                    "reviewFingerprint": "reviewed", "mutation": True,
                    "orderedProviders": list(order),
                    "chainIds": [chain_ids[p] for p in order],
                    "phase": "published"}
    events = [JobEvent(1, "info", initial_messages[0], {
        "coreJobId": core_id, "reviewFingerprint": "reviewed"}),
              JobEvent(2, "info", initial_messages[1], {}),
              *[JobEvent(index + 3, "info", initial_messages[index + 2], {
                  "provider": provider, "chainId": chain_ids[provider],
                  "receiptSha256": _digest(receipts[provider]),
                  "planSha256": "a" * 64})
                for index, provider in enumerate(order)]]
    events.append(JobEvent(5, "info", initial_messages[4], {
        "firstReceiptSha256": events[2].data["receiptSha256"],
        "secondReceiptSha256": events[3].data["receiptSha256"],
        "reviewFingerprint": "reviewed"}))
    policies = [seal["reviewedPolicy"][provider] for provider in order]
    seal.update({"schema": "mixed-initial-apply-seal-v1",
                 "corePlanId": plan_id, "reviewFingerprint": "reviewed",
                 "providerConnectionIds": [f"credential-{provider}" for provider in order],
                 "receiptSha256": [events[2].data["receiptSha256"], events[3].data["receiptSha256"]],
                 "intentSha256": [_digest(policy) for policy in policies],
                 "sourceCredentialSnapshotSha256": _digest(policies),
                 "firstFiveJournalSha256": job_event_digest(events)})
    events.append(JobEvent(6, "info", initial_messages[5], seal))
    events.extend([JobEvent(7, "info", "mixed host handoff", {}),
                   JobEvent(8, "info", "mixed publication", {})])
    initial = StoredJobRun(
        context._initial_parent_id(core_id), "provider_keyed_mixed_initial", "succeeded",
        f"engagement:{engagement}", "engagement", engagement, "operator",
        parent_input,
        [], "2026-10-19T00:00:00+00:00", None, None, events)
    manifest["handoffJournalSha256"] = job_event_digest(events[:7])
    binding = StoredJobRun(
        context._binding_child_id(core_id), "provider_keyed_mixed_initial_host_binding",
        "queued", f"engagement:{engagement}", "engagement", engagement, "operator",
        {"engagementId": engagement, "coreJobId": core_id, "corePlanId": plan_id,
         "handoffJournalSha256": manifest["handoffJournalSha256"],
         "manifestSha256": _digest(manifest), "mutation": False},
        [], "2026-10-19T00:00:00+00:00", None, None,
        [JobEvent(1, "info", "mixed host binding reserved",
                  {"manifestSha256": _digest(manifest), "manifest": manifest})])
    children = {}
    for index, provider in enumerate(order):
        base = initial_apply_base(initial, seal, provider, index)
        plan_name = (".barragan-digitalocean-initial-full.tfplan"
                     if provider == "digitalocean" else ".barragan-linode-initial-full.tfplan")
        plan_path = str(workspaces[provider].path / plan_name)
        terraform_path = "/usr/bin/terraform"
        argv = [terraform_path, "apply", "-input=false", "-lock=true", "-no-color", plan_path]
        child_events = [JobEvent(1, "info", "mixed provider Apply queued", {}),
                        JobEvent(2, "info", "mixed provider Apply started", {})]
        if provider == "digitalocean":
            child_events.extend([
                JobEvent(3, "info", "mixed selector absent before Apply",
                         {"absenceSha256": "b" * 64, "selectorTag": "selector-opaque"}),
                JobEvent(4, "info", "mixed selector POST intended",
                         {"selectorTag": "selector-opaque", "absenceSha256": "b" * 64}),
                JobEvent(5, "info", "mixed selector 201 received",
                         {"selectorTag": "selector-opaque", "httpStatus": 201}),
                JobEvent(6, "info", "mixed selector exclusive visibility proved",
                         {"selectorTag": "selector-opaque", "visibleSha256": "c" * 64})])
        command_start = len(child_events) + 2
        child_events.extend([
            JobEvent(len(child_events) + 1, "info", "mixed provider Apply command intended", {
                "invocationId": "invocation", "argvSha256": _digest(argv),
                "planSha256": "a" * 64, "planPath": plan_path,
                "terraformPath": terraform_path, "terraformSha256": "d" * 64}),
            JobEvent(len(child_events) + 2, "info", "mixed provider Apply command started before GO", {
                "invocationId": "invocation", "bootId": "boot", "pid": 10,
                "pgid": 10, "startTicks": 1}),
            JobEvent(len(child_events) + 3, "info", "mixed provider phase apply_started", {
                "commandStartSequence": command_start}),
            JobEvent(len(child_events) + 4, "info", "mixed provider Apply command result fenced", {
                "invocationId": "invocation", "returnCode": 0,
                "stdoutBytes": 1, "stderrBytes": 0,
                "stdoutTruncated": False, "stderrTruncated": False})])
        result_sequence = len(child_events)
        child_events.extend([
            JobEvent(result_sequence + 1, "info", "mixed provider phase applied",
                     {"commandResultSequence": result_sequence}),
            JobEvent(result_sequence + 2, "info", "mixed provider awaiting exact observation",
                     {"commandResultSequence": result_sequence})])
        proof = {"classifierKind": "full", "stateSha256": hashlib.sha256(raws[provider]).hexdigest(),
                 "lineage": "lineage", "serial": 1, "inventorySha256": "e" * 64,
                 "observationSha256": "f" * 64, "resourceIds": {"node": "101"},
                 "selectorResourcesCount": 1 if provider == "digitalocean" else None,
                 "selectorAttachedNodeIds": ["101"] if provider == "digitalocean" else None,
                 "linodeFirewallAttachedNodeIds": ["101"] if provider == "linode" else None,
                 "inventoryCount": 1,
                 "commandResultJournalSha256": job_event_digest(child_events[:result_sequence])}
        child_events.extend([
            JobEvent(result_sequence + 3, "info", "mixed provider full observation proved", proof),
            JobEvent(result_sequence + 4, "info", "mixed provider initial Apply succeeded",
                     {"observationSha256": proof["observationSha256"]})])
        children[provider] = StoredJobRun(
            context._child_id(core_id, provider), "provider_keyed_mixed_initial_apply_child",
            "succeeded", f"engagement:{engagement}", "engagement", engagement,
            "operator", base, [], "2026-10-19T00:00:00+00:00",
            "2026-10-19T00:00:01+00:00", "2026-10-19T00:00:02+00:00", child_events)
    rows = {chain_ids[p]: StoredSketchChain(
        chain_id=chain_ids[p], engagement_id=engagement, assigned_proxy="proxy01",
        middle_provider=p, middle_region="nyc3" if p == "digitalocean" else "us-sea",
        middle_size="small", edge_provider=p, edge_region="nyc3" if p == "digitalocean" else "us-sea",
        edge_size="small", status="deployed", burned=False, burned_note="",
        deploy_job_id="initial-apply", teardown_job_id="", terraform_working_directory="/workspace",
        nodes=[{}, {}], created_at="", updated_at="") for p in order}
    jobs = {core_id: core, initial.id: initial, binding.id: binding,
            **{child.id: child for child in children.values()}}
    job_repo = SimpleNamespace(get=jobs.get)
    plan_repo = SimpleNamespace(get=lambda key: plan if key == plan_id else None)
    sketch_repo = SimpleNamespace(list_for_engagement=lambda _: list(rows.values()))
    key_repo = SimpleNamespace()
    monkeypatch.setattr(context, "retrieve_sketch_ssh_key", lambda *_:
                        SimpleNamespace(public_key="ssh-ed25519 retained-key",
                                        private_key="retained-private-key"))
    choices = {
        "digitalocean": {"selectedChainId": chain_ids["linode"],
                         "edgeRegion": "nyc3", "edgeSize": "s-1vcpu-1gb"},
        "linode": {"selectedChainId": chain_ids["digitalocean"],
                   "edgeRegion": "us-sea", "edgeType": "g6-nanode-1"}}
    lease = {"operation": None}
    lookup = lambda _: ((plan_id, lease["operation"])
                        if lease["operation"] is not None else None)
    kwargs = dict(job_repository=job_repo, plan_repository=plan_repo,
                  sketch_repository=sketch_repo, ssh_key_repository=key_repo,
                  lease_lookup=lookup)
    return SimpleNamespace(order=order, engagement=engagement, core_id=core_id,
                           plan_id=plan_id, initial=initial, binding=binding,
                           manifest=manifest, workspaces=workspaces, raws=raws,
                           receipts=receipts, jobs=jobs, choices=choices, lease=lease,
                           kwargs=kwargs, schema=schema)


def _reserve(selected, review):
    selected.lease["operation"] = "provider_keyed_mixed_append"
    parent_id = context._parent_id(selected.core_id)
    inputs = {"schema": "mixed-append-pair-parent-v1", "phase": "planning",
              "coreJobId": selected.core_id, "corePlanId": selected.plan_id,
              "engagementId": selected.engagement,
              "reviewRequest": review.reviewed_request,
              "providerOrder": list(review.provider_order),
              "chainOrder": list(review.chain_order),
              "requestSha256": _digest({"request": review.reviewed_request,
                                        "providerOrder": review.provider_order,
                                        "chainOrder": review.chain_order})}
    selected.jobs[parent_id] = SimpleNamespace(id=parent_id, action=context.ACTION,
                                               target_id=selected.engagement, input=inputs)
    source = SimpleNamespace(engagement_id=selected.engagement,
                             core_job_id=selected.core_id, core_plan_id=selected.plan_id,
                             binding_manifest_sha256=_digest(selected.manifest),
                             provider_states=[SimpleNamespace(
                                 provider=p, state_sha256=hashlib.sha256(selected.raws[p]).hexdigest(),
                                 resource_ids=((f"{p}.node", "101"),))
                                 for p in selected.order])
    published = SimpleNamespace(source=source,
                                workspaces=tuple((p, selected.workspaces[p].path)
                                                 for p in selected.order))
    return parent_id, lambda *_: published


@pytest.mark.parametrize("inert_history", [False, True])
def test_minimal_choices_derive_server_owned_review_and_restart_context(selected, inert_history):
    if inert_history:
        repository = selected.kwargs["sketch_repository"]
        original = repository.list_for_engagement(selected.engagement)
        ghost = replace(original[0], chain_id="old-default", status="aborted",
            deploy_job_id="", teardown_job_id="", terraform_working_directory="", nodes=[])
        selected.kwargs["sketch_repository"] = SimpleNamespace(
            list_for_engagement=lambda _: [ghost, *original])
    review = context.derive_mixed_append_review_request(
        selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    assert review.provider_order == selected.order
    assert review.chain_order == tuple(
        "chain-linode" if p == "digitalocean" else "chain-do" for p in selected.order)
    assert review.reviewed_request["digitalocean"]["edgeImage"] == "ubuntu-20"
    assert review.reviewed_request["digitalocean"]["selectorTag"] == "selector-opaque"
    assert review.reviewed_request["linode"]["engagementTag"] == "eng-name"
    assert review == context.derive_mixed_append_review_request(
        selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    parent_id, reader = _reserve(selected, review)
    first = context.collect_mixed_append_pair_plan_context(
        parent_id, published_reader=reader, **selected.kwargs)
    second = context.collect_mixed_append_pair_plan_context(
        parent_id, published_reader=reader, **selected.kwargs)
    assert first == second
    assert first.producer_kwargs()["admin_private_key"] == "retained-private-key"
    assert first.digitalocean_firewall.trusted_ssh_cidrs == (
        "203.0.113.4/32", "203.0.113.5/32")
    assert first.original_regional_high_water == {"us-sea": 1}
    assert all(context._PATH_KEYS <= set(first.retained_varfiles[p])
               for p in ("digitalocean", "linode"))
    assert first.retained_varfiles["digitalocean"]["edge_size"] == "s-1vcpu-1gb"
    # A completed, exact reservation advances the durable ledger/topology,
    # while the review must still reopen the immutable original generation.
    _put(selected.schema / "regional-ordinals.json", {"us-sea": 2, "nyc3": 1})
    for provider, workspace in selected.workspaces.items():
        current = json.loads((workspace.path / ".barragan-topology.json").read_text())
        current["external_middles"] = {"middle_02": {"provider": "foreign"}}
        _put(workspace.path / ".barragan-topology.json", current)
    assert context.collect_mixed_append_pair_plan_context(
        parent_id, published_reader=reader, **selected.kwargs) == first


def test_approval_rebuilds_both_intents_from_authenticated_context(selected, monkeypatch):
    review = context.derive_mixed_append_review_request(
        selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    parent_id, reader = _reserve(selected, review)
    saved = context.collect_mixed_append_pair_plan_context(
        parent_id, published_reader=reader, **selected.kwargs)
    calls = {}

    def digitalocean(**kwargs):
        calls["digitalocean"] = kwargs
        return SimpleNamespace(nonsecret_varfile={"provider": "digitalocean"})

    def linode(**kwargs):
        calls["linode"] = kwargs
        return SimpleNamespace(nonsecret_varfile={"provider": "linode"})

    monkeypatch.setattr(context, "compile_mixed_digitalocean_on_linode_append_intent",
                        digitalocean)
    monkeypatch.setattr(context, "compile_mixed_linode_on_digitalocean_append_intent",
                        linode)
    approved = saved.approval_kwargs()
    assert set(calls) == {"digitalocean", "linode"}
    assert all(call["published_binding"] == selected.manifest for call in calls.values())
    assert all(call["provider_states"] == selected.raws for call in calls.values())
    assert all(call["provider_resource_ids"] == {
        provider: {f"{provider}.node": "101"} for provider in ("digitalocean", "linode")}
        for call in calls.values())
    assert calls["digitalocean"]["selected_chain_id"] == "chain-linode"
    assert calls["linode"]["selected_chain_id"] == "chain-do"
    assert calls["linode"]["admin_public_key"] == "ssh-ed25519 retained-key"
    assert approved["reviewed_inputs"] == {
        provider: {"provider": provider} for provider in ("digitalocean", "linode")}


def test_pre_reservation_rejects_extra_authority_and_retained_input_drift(selected):
    extra = {p: dict(v) for p, v in selected.choices.items()}
    extra["digitalocean"]["edgeImage"] = "new-image"
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, extra, **selected.kwargs)
    selected.lease["operation"] = "provider_keyed_initial"
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    selected.lease["operation"] = None
    path = (selected.schema / ".plan-material" / "digitalocean" / "inputs.json")
    path.write_text("{}")
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, selected.choices, **selected.kwargs)


def test_historical_binding_rejects_changed_handoff_journal(selected):
    selected.initial.events[6] = JobEvent(7, "info", "changed handoff", {})
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, selected.choices, **selected.kwargs)


def test_real_initial_terminal_rejects_changed_proof_before_append_review(selected):
    provider = selected.order[0]
    child = selected.jobs[context._child_id(selected.core_id, provider)]
    child.events[-2] = JobEvent(child.events[-2].sequence, "info",
                                "mixed provider full observation proved",
                                {**child.events[-2].data,
                                 "commandResultJournalSha256": "0" * 64})
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, selected.choices, **selected.kwargs)


def test_real_initial_seal_rejects_changed_receipt_before_append_review(selected):
    provider = selected.order[0]
    receipt_path = selected.workspaces[provider].path / context._RECEIPT[provider]
    _put(receipt_path, {**selected.receipts[provider], "inputSha256": "0" * 64})
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, selected.choices, **selected.kwargs)


def test_post_reservation_rejects_enriched_request_and_state_drift(selected):
    review = context.derive_mixed_append_review_request(
        selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    parent_id, reader = _reserve(selected, review)
    selected.jobs[parent_id].input["reviewRequest"] = deepcopy(review.reviewed_request)
    selected.jobs[parent_id].input["reviewRequest"]["digitalocean"]["edgeImage"] = "other"
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.collect_mixed_append_pair_plan_context(
            parent_id, published_reader=reader, **selected.kwargs)
    selected.jobs[parent_id].input["reviewRequest"] = deepcopy(review.reviewed_request)
    selected.workspaces["linode"].state_path.write_bytes(b"state-drift")
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.collect_mixed_append_pair_plan_context(
            parent_id, published_reader=reader, **selected.kwargs)


def test_group_readable_nonsecret_ledger_reopens_review_and_reserved_context(selected):
    ledger = selected.schema / 'regional-ordinals.json'
    ledger.chmod(0o640)  # Real collaborator-access mode on the diagnostic host.
    review = context.derive_mixed_append_review_request(
        selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    parent_id, reader = _reserve(selected, review)
    reopened = context.collect_mixed_append_pair_plan_context(
        parent_id, published_reader=reader, **selected.kwargs)
    assert reopened.original_regional_high_water == {'us-sea': 1}


@pytest.mark.parametrize('drift', ['value', 'shape', 'symlink', 'missing'])
def test_nonsecret_ledger_read_still_rejects_drift(selected, drift):
    ledger = selected.schema / 'regional-ordinals.json'
    if drift == 'value':
        _put(ledger, {'us-sea': 2})
    elif drift == 'shape':
        _put(ledger, [])
    elif drift == 'symlink':
        saved = ledger.with_suffix('.saved')
        ledger.rename(saved)
        ledger.symlink_to(saved)
    else:
        ledger.unlink()
    with pytest.raises(context.MixedAppendPlanContextAttention):
        context.derive_mixed_append_review_request(
            selected.engagement, selected.core_id, selected.choices, **selected.kwargs)


def test_real_state_cloud_receipts_adapt_to_complete_ids_for_both_intents(tmp_path):
    from test_provider_keyed_mixed_append_linode_intent import _case
    from test_provider_keyed_mixed_append_intent import mixed_fixture
    from app.services.provider_keyed_initial_teardown import _state_resources
    args = _case()
    do = mixed_fixture()
    cloud = {p: tuple((a, identifier) for a, identifier in ids.items()
                     if not a.startswith(('local_file.', 'random_password.')))
             for p, ids in args['provider_resource_ids'].items()}
    source = SimpleNamespace(provider_states=[SimpleNamespace(provider=p,
        state_sha256=args['provider_state_sha256'][p], resource_ids=cloud[p])
        for p in args['provider_states']])
    case = SimpleNamespace(source=source, provider_states=args['provider_states'], workspaces={}, digitalocean_firewall=None,
        binding_manifest=args['published_binding'], admin_public_key=args['admin_public_key'],
        retained_varfiles={'digitalocean': do['retained_digitalocean_varfile'],
                          'linode': args['retained_linode_varfile']},
        additions={'digitalocean': {k: do[k] for k in ('selected_chain_id', 'edge_region', 'edge_size', 'edge_image', 'selector_tag')},
                   'linode': {k: args[k] for k in ('selected_chain_id', 'edge_region', 'edge_type', 'edge_image', 'engagement_tag')}})
    from app.services.provider_keyed_mixed_initial_publication_source import MixedInitialPublicationSource, MixedProviderState
    from app.services.provider_keyed_mixed_append_reservation import propose_mixed_external_append_reservations
    for provider, variables in case.retained_varfiles.items():
        material = tmp_path / '.plan-material' / provider
        variables.update(ssh_pub_key_path=str(material / 'admin-public'),
                         ssh_priv_key_path=str(material / 'admin-private'),
                         ssh_config_path=str(material / 'ssh-output'))
    binding = case.binding_manifest
    source = MixedInitialPublicationSource(binding['engagementId'], binding['coreJobId'],
        'plan', 'revision', 'parent', ('digitalocean', 'linode'), ('chain-do', 'chain-linode'),
        '1' * 64, context._digest(binding), '2' * 64,
        tuple(MixedProviderState(p, args['provider_state_sha256'][p],
            '11111111-1111-4111-8111-111111111111', 1, cloud[p], '3' * 64)
            for p in ('digitalocean', 'linode')), ())
    case.source = source
    result = context.MixedAppendPlanContext.approval_kwargs(case)
    topologies = {p: {'schema': 'provider-keyed-v2', 'middles': v['middles'],
        'edge_groups': v['edge_groups'], 'regional_high_water': {
            ('nyc3' if p == 'digitalocean' else 'us-sea'): 1}}
        for p, v in case.retained_varfiles.items()}
    proposal = propose_mixed_external_append_reservations(source=source,
        binding_manifest=binding, digitalocean_intent=result['digitalocean_intent'],
        linode_intent=result['linode_intent'], current_topologies=topologies,
        regional_high_water={'nyc3': 1, 'us-sea': 1},
        reviewed_provider_order=('digitalocean', 'linode'))
    assert len(proposal.reservations) == 2
    assert case.source is source
    for provider, variables in result['reviewed_inputs'].items():
        assert {k: variables[k] for k in context._PATH_KEYS} == {
            k: case.retained_varfiles[provider][k] for k in context._PATH_KEYS}
    for name in ('digitalocean_intent', 'linode_intent'):
        for provider in ('digitalocean', 'linode'):
            retained = dict(getattr(result[name], f'retained_{provider}_ids'))
            assert set(retained) == set(_state_resources(json.loads(args['provider_states'][provider])))
            assert len(retained) > len(cloud[provider])


def test_append_retains_hash_verified_original_ssh_paths(selected):
    review = context.derive_mixed_append_review_request(
        selected.engagement, selected.core_id, selected.choices, **selected.kwargs)
    parent_id, reader = _reserve(selected, review)
    saved = context.collect_mixed_append_pair_plan_context(
        parent_id, published_reader=reader, **selected.kwargs)
    for provider in selected.order:
        original_path = selected.schema / '.plan-material' / provider / 'inputs.json'
        original = json.loads(original_path.read_bytes())
        assert saved.retained_varfiles[provider] == original
        assert saved.producer_kwargs()['retained_varfiles'][provider] == original
        assert {key: original[key] for key in context._PATH_KEYS} == {
            'ssh_pub_key_path': str(original_path.parent / 'admin-public'),
            'ssh_priv_key_path': str(original_path.parent / 'admin-private'),
            'ssh_config_path': str(original_path.parent / 'ssh-output')}


def test_fresh_review_checks_derived_edge_before_reservation(selected, monkeypatch):
    calls = []
    def check(policy, region, size, **kwargs):
        calls.append((policy["provider_connection_id"], region, size))
        raise context.MixedAppendAvailabilityAttention("availability unavailable; no append started")
    monkeypatch.setattr(context, "require_mixed_append_digitalocean_availability", check)
    before = dict(selected.jobs)
    with pytest.raises(context.MixedAppendPlanContextAttention, match="availability unavailable"):
        context.derive_mixed_append_review_request(selected.engagement, selected.core_id,
            selected.choices, **selected.kwargs)
    assert calls == [("credential-digitalocean", selected.choices["digitalocean"]["edgeRegion"], "s-1vcpu-1gb")]
    assert selected.jobs == before
    assert selected.lease["operation"] is None


def test_historical_plan_context_does_not_require_purchase_availability(selected, monkeypatch):
    review = context.derive_mixed_append_review_request(selected.engagement, selected.core_id,
        selected.choices, **selected.kwargs)
    parent_id, reader = _reserve(selected, review)
    def forbidden(*args, **kwargs):
        raise AssertionError("historical reader must not query purchase availability")
    monkeypatch.setattr(context, "require_mixed_append_digitalocean_availability", forbidden)
    result = context.collect_mixed_append_pair_plan_context(parent_id, published_reader=reader,
        **selected.kwargs)
    assert result.additions["digitalocean"]["edge_region"] == selected.choices["digitalocean"]["edgeRegion"]


def test_bound_fresh_review_is_rejected_before_catalog_or_reservation(selected, monkeypatch):
    def blocked(*args, **kwargs):
        raise context.MixedAppendAvailabilityAttention("Review before independent bindings; no append started")
    monkeypatch.setattr(context, "require_no_independent_mixed_append_bindings", blocked)
    monkeypatch.setattr(context, "require_mixed_append_digitalocean_availability", lambda *args, **kwargs: pytest.fail("catalog after blocked ownership"))
    before = dict(selected.jobs)
    with pytest.raises(context.MixedAppendAvailabilityContextAttention, match="before independent bindings"):
        context.derive_mixed_append_review_request(selected.engagement, selected.core_id,
            selected.choices, **selected.kwargs)
    assert selected.jobs == before and selected.lease["operation"] is None
