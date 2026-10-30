# Copyright (c) 2026, Oracle and/or its affiliates.
"""Two-provider teardown preview is bound to persisted published rows and state."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_published_teardown_scope import (
    MixedPublishedTeardownScopeAttention,
    build_mixed_published_initial_teardown_scopes,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_initial_publication_source import _source
from app.services.provider_keyed_mixed_initial_publication_source import (
    recognize_mixed_initial_publication_source,
)


def _published(ready, tmp_path):
    inputs = _source(ready, tmp_path)
    source = recognize_mixed_initial_publication_source(**inputs)
    repository = SqlAlchemySketchChainRepository()
    workspaces = {provider: tmp_path / provider for provider in source.ordered_providers}
    for chain_id, provider in zip(source.chain_ids, source.ordered_providers, strict=True):
        chain = inputs["chains"][chain_id]
        rows = [row for row in source.host_rows if row.chain_id == chain_id]
        deployed = replace(chain, status="deployed", deploy_job_id=source.parent_job_id,
                           terraform_working_directory=str(workspaces[provider]),
                           nodes=[{
                               "chainId": row.chain_id, "provider": row.provider,
                               "role": row.role, "hostname": row.hostname,
                               "terraformAddress": row.terraform_address,
                               "providerInstanceId": row.provider_instance_id,
                               "publicIp": row.public_ip,
                               "assignedProxy": row.assigned_proxy,
                               "status": "deployed",
                           } for row in rows])
        repository.save(deployed)
    def persisted():
        return {row.chain_id: row for row in repository.list_for_engagement(source.engagement_id)}
    options = dict(
        reviewed_policies=inputs["parent"].events[5].data["reviewedPolicy"],
        reviewed_chain_fingerprints=inputs["core"].input["pendingSketchChainFingerprints"],
        observations=inputs["observations"], workspaces=workspaces,
        chains=persisted(),
    )
    return source, options, persisted


def test_both_provider_orders_make_two_complete_scopes_from_persisted_rows(client, ready, tmp_path):
    with client.application.storage_context():
        source, options, persisted = _published(ready, tmp_path)
        scopes = build_mixed_published_initial_teardown_scopes(source, **options)
        assert tuple(scope["provider"] for scope in scopes) == source.ordered_providers
        assert tuple(scope["chainIds"][0] for scope in scopes) == source.chain_ids
        assert all(len(scope["resources"]) >= 5 for scope in scopes)
        expected_kinds = {
            "linode": {
                "linode_firewall.firewall": "firewall",
                "random_password.root_password": "random_password",
                "local_file.ansible_inventory[0]": "local_file",
                "local_file.ssh_stanza[0]": "local_file",
                **{row.terraform_address: "instance" for row in source.host_rows
                   if row.provider == "linode"},
            },
            "digitalocean": {
                "digitalocean_firewall.firewall": "firewall",
                "digitalocean_ssh_key.key": "ssh_key",
                "local_file.ansible_inventory[0]": "local_file",
                "local_file.ssh_stanza[0]": "local_file",
                **{row.terraform_address: "droplet" for row in source.host_rows
                   if row.provider == "digitalocean"},
            },
        }
        for scope in scopes:
            assert {row["address"]: row["kind"] for row in scope["resources"]} == (
                expected_kinds[scope["provider"]])
        assert build_mixed_published_initial_teardown_scopes(
            source, **{**options, "chains": persisted()}) == scopes


@pytest.mark.parametrize("drift", [
    "missing_provider", "state_bytes", "state_id", "workspace", "missing_chain",
    "node_id", "node_status", "extra_node", "chain_status", "source_order",
    "same_workspace", "edge_count", "edge_intents", "edge_region", "edge_size",
])
def test_persisted_or_retained_drift_vetoes_both_scopes(client, ready, tmp_path, drift):
    with client.application.storage_context():
        source, options, _persisted = _published(ready, tmp_path)
        provider, chain_id = source.ordered_providers[0], source.chain_ids[0]
        if drift == "missing_provider":
            options["observations"] = {key: value for key, value in options["observations"].items()
                                       if key != provider}
        elif drift == "state_bytes":
            observed = options["observations"][provider]
            options["observations"] = {**options["observations"], provider:
                                       replace(observed, state_json=observed.state_json + b" ")}
        elif drift == "state_id":
            published = source.provider_states[0]
            source = replace(source, provider_states=(replace(
                published, resource_ids=((published.resource_ids[0][0], "foreign"),
                                         *published.resource_ids[1:])),
                *source.provider_states[1:]))
        elif drift == "workspace":
            options["workspaces"] = {**options["workspaces"], provider: tmp_path / "wrong"}
        elif drift == "same_workspace":
            options["workspaces"] = {key: options["workspaces"][provider]
                                     for key in source.ordered_providers}
        elif drift == "missing_chain":
            options["chains"].pop(chain_id)
        elif drift in {"node_id", "node_status", "extra_node", "chain_status",
                       "edge_count", "edge_intents", "edge_region", "edge_size"}:
            chain = options["chains"][chain_id]
            if drift == "chain_status":
                changed = replace(chain, status="pending")
            elif drift == "edge_count":
                changed = replace(chain, edge_count=2)
            elif drift == "edge_intents":
                changed = replace(chain, edge_intents=[{**chain.edge_intents[0], "id": "other"}])
            elif drift == "edge_region":
                changed = replace(chain, edge_region="other-region")
            elif drift == "edge_size":
                changed = replace(chain, edge_size="other-size")
            else:
                nodes = [dict(row) for row in chain.nodes]
                if drift == "node_id":
                    nodes[0]["providerInstanceId"] = "foreign"
                elif drift == "node_status":
                    nodes[0]["status"] = "pending"
                else:
                    nodes.append(dict(nodes[0]))
                changed = replace(chain, nodes=nodes)
            repository = SqlAlchemySketchChainRepository()
            repository.save(changed)
            options["chains"] = {row.chain_id: row for row in repository.list_for_engagement(
                source.engagement_id)}
        elif drift == "source_order":
            source = replace(source, ordered_providers=tuple(reversed(source.ordered_providers)))
        with pytest.raises(MixedPublishedTeardownScopeAttention):
            build_mixed_published_initial_teardown_scopes(source, **options)
