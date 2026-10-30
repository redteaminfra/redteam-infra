# Copyright (c) 2026, Oracle and/or its affiliates.
"""The six-node append and live binding set form one inert teardown scope."""

from dataclasses import asdict, replace
import hashlib
import json
from uuid import uuid4

import pytest

from app.domain import JobEvent
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_append_pair_host_proof import SixHostProofReceipt
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from app.services.provider_keyed_mixed_published_six_scope import (
    MixedPublishedSixScopeAttention, build_mixed_published_six_teardown_scope,
    _POST_APPEND_SHARED,
)
from app.storage.job_repository import StoredJobRun, job_event_digest
from test_provider_keyed_mixed_append_pair_host_proof import _source


def _resource(address, attributes):
    base, _, suffix = address.partition("[")
    kind, name = base.split(".", 1)
    instance = {"attributes": attributes}
    if suffix:
        instance["index_key"] = json.loads("[" + suffix)[0]
    return {"mode": "managed", "type": kind, "name": name,
            "instances": [instance]}


def _case(reverse=False):
    source = _source()
    if reverse:
        source = replace(source,
            provider_order=tuple(reversed(source.provider_order)),
            chain_ids=tuple(reversed(source.chain_ids)),
            before_chains=tuple(reversed(source.before_chains)),
            chains=tuple(reversed(source.chains)),
            new_edge_addresses=tuple(reversed(source.new_edge_addresses)),
            provider_proof_digests=tuple(reversed(source.provider_proof_digests)),
            state_sha256s=tuple(reversed(source.state_sha256s)),
            workspace_paths=tuple(reversed(source.workspace_paths)),
            source_revisions=tuple(reversed(source.source_revisions)),
            proxy_egress_ips=tuple(reversed(source.proxy_egress_ips)))
    workspaces = dict(zip(source.provider_order, source.workspace_paths, strict=True))
    before, after = [], []
    for old, new in zip(source.before_chains, source.chains, strict=True):
        path = workspaces[old.middle_provider]
        before.append(replace(old, terraform_working_directory=path))
        after.append(replace(new, terraform_working_directory=path))
    source = replace(source, before_chains=tuple(before), chains=tuple(after))

    policies, observations, children, state_hashes = {}, {}, {}, []
    for index, provider in enumerate(source.provider_order):
        rows = [row for row in source.host_rows if row.provider == provider]
        nodes = {}
        for row in rows:
            nodes[row.terraform_address] = (
                {"label": row.hostname, "tag": "tag", "image": "image",
                 "region": "test-1", "node_type": "small"}
                if provider == "linode" else
                {"name": row.hostname, "firewall_selector_tag": "tag",
                 "image": "image", "region": "test-1", "size": "small"})
        policy = {"nodes": nodes, "engagement_name": "tag",
                  "firewall": {"name": "firewall", "selector_tag": "tag"},
                  "ssh_key_name": "admin-key", "admin_public_key": "ssh-public"}
        policies[provider] = policy
        resources, cloud = [], {}
        for address, node in nodes.items():
            row = next(row for row in rows if row.terraform_address == address)
            attributes = {"id": row.provider_instance_id, "tags": ["tag"],
                          "image": "image", "region": "test-1"}
            if provider == "linode":
                attributes.update(label=node["label"], type="small")
            else:
                attributes.update(name=node["name"], size="small")
            resources.append(_resource(address, attributes))
            cloud[address] = row.provider_instance_id
        for number, address in enumerate(sorted(_POST_APPEND_SHARED[provider]), start=1):
            attributes = {"id": f"shared-{provider}-{number}"}
            if address == "linode_firewall.firewall":
                attributes.update(label="fw-tag-firewall", tags=["tag"])
                cloud[address] = attributes["id"]
            elif address == "digitalocean_firewall.firewall":
                attributes.update(name="firewall", tags=["tag"])
                cloud[address] = attributes["id"]
            elif address == "digitalocean_ssh_key.key":
                attributes.update(name="admin-key", tags=[], public_key="ssh-public")
                cloud[address] = attributes["id"]
            resources.append(_resource(address, attributes))
        lineage = str(uuid4())
        raw = json.dumps({"version": 4, "terraform_version": "1.15.5",
                          "lineage": lineage, "serial": 2,
                          "resources": resources}, sort_keys=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        state_hashes.append(digest)
        observations[provider] = ProviderHostObservation(
            ProviderApplyClassification(provider, "full", digest, lineage, 2,
                                        tuple(sorted(cloud.items()))), raw)
        proof = {"provider": provider, "reviewSha256": "a" * 64,
                 "stateSha256": digest, "lineage": lineage, "serial": 2,
                 "resourceIds": sorted(
                     [address, str(resource["instances"][0]["attributes"]["id"])]
                     for address, resource in zip(
                         [*nodes, *sorted(_POST_APPEND_SHARED[provider])],
                         resources, strict=True))}
        events = [JobEvent(number, "info", f"stage {number}", {})
                  for number in range(1, 9)]
        events.append(JobEvent(9, "info", "full provider proof", proof))
        events.append(JobEvent(10, "info", (
            "mixed append first provider Apply succeeded" if index == 0 else
            "mixed append second provider Apply succeeded"),
            {"proofJournalSha256": job_event_digest(events)}))
        children[provider] = StoredJobRun(
            f"job-{provider}", ("provider_keyed_mixed_append_apply_child"
                  if index == 0 else "provider_keyed_mixed_append_second_apply_child"),
            "succeeded", "engagement:eng-test", "engagement", "eng-test",
            "operator", {}, [], "created", "started", "finished", events)
    source = replace(source, state_sha256s=tuple(state_hashes),
                     provider_proof_digests=tuple(job_event_digest(
                         children[provider].events) for provider in source.provider_order))
    host = StoredJobRun("job-host", "host", "succeeded", "engagement:eng-test",
                        "engagement", "eng-test", "operator", {}, [],
                        "created", "started", "finished", [JobEvent(1, "info", "host", {})])
    parent = StoredJobRun(
        source.parent_id, "provider_keyed_mixed_append", "succeeded",
        "engagement:eng-test", "engagement", "eng-test", "operator",
        {"phase": "completed", "coreJobId": source.core_job_id,
         "corePlanId": source.core_plan_id,
         "providerOrder": list(source.provider_order),
         "chainOrder": list(source.chain_ids), "reviewSha256": "a" * 64},
        [], "created", "started", "finished", [
            JobEvent(1, "info", "mixed append six-node generation published", {
                "source": json.loads(json.dumps(asdict(source))),
                "sourceSha256": source.source_sha256,
                "hostProofJournalSha256": job_event_digest(host.events),
                "providerProofJournalSha256": {
                    provider: source.provider_proof_digests[index]
                    for index, provider in enumerate(source.provider_order)},
                "chainIds": list(source.chain_ids)})])
    bindings = {"channels": (("channel-mutation", "job-1", "b" * 64),),
                "domains": (("dns-ownership", "record-1", "c" * 64),),
                "certificates": (("binding", "cert-1", "d" * 64),),
                "sites": (("service", "site-1", "e" * 64),)}
    options = dict(append_parent=parent, host_proof_child=host,
                   host_receipt=object(), provider_children=children,
                   reviewed_policies=policies,
                   reviewed_chain_fingerprints={row.chain_id:
                       sketch_chain_intent_fingerprint(row) for row in source.chains},
                   observations=observations,
                   chains={row.chain_id: row for row in source.chains},
                   live_bindings=bindings,
                   host_receipt_validator=lambda _parent, _child, receipt, **_kw: receipt)
    return source, options


@pytest.mark.parametrize("reverse", [False, True])
def test_six_node_published_scope_binds_two_full_states_and_live_bindings(reverse):
    source, options = _case(reverse)
    scope = build_mixed_published_six_teardown_scope(source, **options)
    assert scope.source_sha256 == source.source_sha256
    assert scope.binding_count == 4
    assert tuple(row["provider"] for row in scope.provider_scopes) == source.provider_order
    assert all(len(row["resources"]) == 5 for row in scope.provider_scopes)
    assert build_mixed_published_six_teardown_scope(source, **options) == scope


@pytest.mark.parametrize("drift", [
    "parent", "saved_source", "child", "state", "node", "chain_intent",
    "binding", "workspace",
])
def test_six_node_scope_rejects_publication_or_current_drift(drift):
    source, options = _case()
    provider, chain_id = source.provider_order[0], source.chain_ids[0]
    if drift == "parent":
        parent = options["append_parent"]
        options["append_parent"] = replace(parent, events=[replace(
            parent.events[0], data={**parent.events[0].data,
                                    "sourceSha256": "f" * 64})])
    elif drift == "saved_source":
        parent = options["append_parent"]
        data = dict(parent.events[0].data)
        saved = dict(data["source"])
        saved["core_job_id"] = "foreign-job"
        data["source"] = saved
        options["append_parent"] = replace(parent, events=[replace(
            parent.events[0], data=data)])
    elif drift == "child":
        child = options["provider_children"][provider]
        options["provider_children"] = {**options["provider_children"],
            provider: replace(child, events=[*child.events[:-1], replace(
                child.events[-1], data={"proofJournalSha256": "f" * 64})])}
    elif drift == "state":
        observed = options["observations"][provider]
        options["observations"] = {**options["observations"], provider:
            replace(observed, state_json=observed.state_json + b" ")}
    elif drift == "node":
        chain = options["chains"][chain_id]
        nodes = [dict(row) for row in chain.nodes]
        nodes[2]["providerInstanceId"] = "foreign"
        options["chains"] = {**options["chains"], chain_id: replace(chain, nodes=nodes)}
    elif drift == "chain_intent":
        options["reviewed_chain_fingerprints"] = {
            **options["reviewed_chain_fingerprints"], chain_id: "f" * 64}
    elif drift == "binding":
        options["live_bindings"] = {**options["live_bindings"],
                                     "domains": [options["live_bindings"]["domains"][0]]}
    else:
        source = replace(source, workspace_paths=(source.workspace_paths[1],
                                                  source.workspace_paths[0]))
    with pytest.raises(MixedPublishedSixScopeAttention):
        build_mixed_published_six_teardown_scope(source, **options)


def _rebind_state(source, options, provider, resources, *, proof_ids=None):
    """Authenticate altered state so drift reaches complete-scope validation."""
    observed = options["observations"][provider]
    state = json.loads(observed.state_json)
    state["resources"] = resources
    raw = json.dumps(state, sort_keys=True).encode()
    digest = hashlib.sha256(raw).hexdigest()
    child = options["provider_children"][provider]
    events = list(child.events)
    ids = sorted([row["type"] + "." + row["name"] + (
        "[" + json.dumps(instance["index_key"]) + "]" if "index_key" in instance else ""),
        str(instance["attributes"]["id"])]
        for row in resources for instance in row["instances"])
    events[8] = replace(events[8], data={**events[8].data, "stateSha256": digest,
                                       "resourceIds": ids if proof_ids is None else proof_ids})
    events[9] = replace(events[9], data={
        "proofJournalSha256": job_event_digest(events[:9])})
    options["provider_children"][provider] = replace(child, events=events)
    options["observations"][provider] = replace(observed, state_json=raw,
        classification=replace(observed.classification, state_sha256=digest,
            resource_ids=tuple((address, value) for address, value in ids
                               if address in dict(observed.classification.resource_ids))))
    source = replace(source,
        state_sha256s=tuple(digest if item == provider else source.state_sha256s[index]
                            for index, item in enumerate(source.provider_order)),
        provider_proof_digests=tuple(job_event_digest(
            options["provider_children"][item].events) for item in source.provider_order))
    parent = options["append_parent"]
    options["append_parent"] = replace(parent, events=[replace(parent.events[0], data={
        **parent.events[0].data, "source": json.loads(json.dumps(asdict(source))),
        "sourceSha256": source.source_sha256,
        "providerProofJournalSha256": dict(zip(
            source.provider_order, source.provider_proof_digests, strict=True))})])
    return source


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
@pytest.mark.parametrize("drift", ["local_inventory", "local_ssh", "missing_shared",
                                   "extra_resource", "proof_ids"])
def test_six_scope_rejects_authenticated_post_append_resource_drift(provider, drift):
    source, options = _case()
    resources = json.loads(options["observations"][provider].state_json)["resources"]
    if drift.startswith("local_"):
        address = ("local_file.ansible_inventory[0]" if drift == "local_inventory"
                   else "local_file.ssh_stanza[0]")
        resources.append(_resource(address, {"id": "resurrected-local-file"}))
    elif drift == "missing_shared":
        # Linode's local password and DO's provider SSH key must both remain.
        kind = "random_password" if provider == "linode" else "digitalocean_ssh_key"
        resources = [row for row in resources if row["type"] != kind]
    elif drift == "extra_resource":
        resources.append(_resource("random_password.foreign", {"id": "foreign"}))
    else:
        # The state is unchanged; the full proof omits a retained resource.
        child = options["provider_children"][provider]
        events = list(child.events)
        events[8] = replace(events[8], data={**events[8].data, "resourceIds": [
            row for row in events[8].data["resourceIds"]
            if row[0] != ("random_password.root_password" if provider == "linode"
                          else "digitalocean_ssh_key.key")]})
        options["provider_children"][provider] = replace(child, events=events)
    source = _rebind_state(source, options, provider, resources,
        proof_ids=events[8].data["resourceIds"] if drift == "proof_ids" else None)
    with pytest.raises(MixedPublishedSixScopeAttention):
        build_mixed_published_six_teardown_scope(source, **options)
