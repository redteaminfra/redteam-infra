# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only keyed teardown scope binds a complete applied state, including local IDs."""

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_teardown_scope import (
    ProviderKeyedTeardownScopeError, build_digitalocean_keyed_teardown_scope,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from test_provider_keyed_postapply_preflight import AllChains, OneEngagement, _persisted_fixture


def _applied_rows(tmp_path, monkeypatch):
    rows = list(_persisted_fixture(tmp_path, monkeypatch))
    state_path = rows[9] / "terraform.tfstate"
    state = json.loads(state_path.read_text())
    state["terraform_version"] = "1.15.5"
    for resource in state["resources"]:
        if resource["type"] == "digitalocean_droplet":
            for instance in resource["instances"]:
                node = next(node for node in rows[7].nodes.values()
                            if node.name == instance["attributes"]["name"])
                instance["attributes"].update(image=node.image, size=node.size)
    for kind, name, value in (
        ("digitalocean_ssh_key", "key", "key-opaque"),
        ("local_file", "ansible_inventory", "/private/inventory"),
        ("local_file", "ssh_stanza", "/private/ssh-stanza"),
    ):
        state["resources"].append({"mode": "managed", "type": kind, "name": name,
                                   "instances": [{"index_key": 0, "attributes": {"id": value}}]})
    # The SSH key is unindexed in the reviewed upstream module.
    state["resources"][-3]["instances"][0].pop("index_key")
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    sha = hashlib.sha256(state_path.read_bytes()).hexdigest()
    event = rows[6].events[0]
    rows[6] = replace(rows[6], events=[JobEvent(event.sequence, event.level, event.message,
                                               {**event.data, "stateSha256": sha})])
    return rows


def _scope(rows, *, extra_jobs=()):
    _state, engagement, chains, core, plan, plan_job, apply_job, _intent, state_root, _root, _evidence = rows
    with db.bind(_state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        for job in (core, plan_job, apply_job, *extra_jobs):
            jobs.save(job)
        plans.save(plan)
        return build_digitalocean_keyed_teardown_scope(
            engagement.id, core.id, state_root=state_root,
            engagement_repository=OneEngagement(engagement),
            sketch_repository=AllChains(chains), job_repository=jobs,
            plan_repository=plans, credential_repository=object(),
        )


def test_scope_seals_every_managed_address_and_distinguishes_local_ids(tmp_path, monkeypatch):
    rows = _applied_rows(tmp_path, monkeypatch)
    scope = _scope(rows)
    resources = {row["address"]: row for row in scope["resources"]}
    assert len(resources) == len(rows[7].nodes) + 4
    assert resources["digitalocean_ssh_key.key"]["kind"] == "ssh_key"
    assert resources["local_file.ansible_inventory[0]"] == {
        "address": "local_file.ansible_inventory[0]", "id": "/private/inventory", "kind": "local_file"}
    assert scope["stateSha256"] == rows[6].events[0].data["stateSha256"]
    assert set(scope["chainFingerprints"]) == set(scope["chainIds"])


def test_reconciled_append_history_must_match_active_core_plan(tmp_path, monkeypatch):
    rows = _applied_rows(tmp_path, monkeypatch)
    engagement, core, plan, apply_job = rows[1], rows[3], rows[4], rows[6]
    now = datetime.now(timezone.utc).isoformat()
    parent = StoredJobRun(
        "job-reconciled-append", "provider_keyed_edge_append", "failed",
        f"engagement:{engagement.id}", "engagement", engagement.id, "operator",
        {"engagementId": engagement.id, "coreJobId": core.id,
         "corePlanId": plan.id, "planJobId": "job-reconciled-append-plan",
         "phase": "unapplied_reconciled"}, [], now, now, now,
        [JobEvent(1, "info", "append plan reconciled without mutation",
                  {"stateSha256": apply_job.events[0].data["stateSha256"]})],
    )
    child = StoredJobRun(
        "job-reconciled-append-plan", "provider_keyed_edge_append_plan", "failed",
        parent.target, "engagement", engagement.id, "operator",
        {"engagementId": engagement.id, "parentJobId": parent.id,
         "coreJobId": core.id, "mutation": False}, [], now, now, now,
        [JobEvent(1, "error", "plan failed", {})],
    )
    assert _scope(rows, extra_jobs=(parent, child))["stateSha256"] == (
        apply_job.events[0].data["stateSha256"])
    with pytest.raises(ProviderKeyedTeardownScopeError):
        _scope(rows, extra_jobs=(replace(parent, input={**parent.input,
            "corePlanId": "plan-foreign"}), child))


def test_scope_rejects_extra_state_resource_even_when_apply_sha_matches(tmp_path, monkeypatch):
    rows = _applied_rows(tmp_path, monkeypatch)
    state_path = rows[9] / "terraform.tfstate"
    state = json.loads(state_path.read_text())
    state["resources"].append({"mode": "managed", "type": "local_file", "name": "unexpected",
                               "instances": [{"attributes": {"id": "/private/extra"}}]})
    state_path.write_text(json.dumps(state))
    event = rows[6].events[0]
    rows[6] = replace(rows[6], events=[JobEvent(event.sequence, event.level, event.message,
                                               {**event.data, "stateSha256": hashlib.sha256(state_path.read_bytes()).hexdigest()})])
    with pytest.raises(ProviderKeyedTeardownScopeError):
        _scope(rows)


def test_scope_rejects_incomplete_apply(tmp_path, monkeypatch):
    rows = _applied_rows(tmp_path, monkeypatch)
    rows[6] = replace(rows[6], status="failed")
    with pytest.raises(ProviderKeyedTeardownScopeError):
        _scope(rows)


def _materialize(rows):
    state = json.loads((rows[9] / "terraform.tfstate").read_text())
    resources = _state_resources(state)
    by_chain = {row.chain_id: row for row in rows[2]}
    projected = []
    for ordinal, route in enumerate(rows[7].chain_routes, 1):
        chain = by_chain[route.chain_id]
        addresses = [f'digitalocean_droplet.middle["{route.middle_node}"]'] + [
            f'digitalocean_droplet.edge["{key}"]' for key in route.edge_nodes]
        nodes = []
        for index, address in enumerate(addresses):
            attributes = resources[address]
            role = "middle" if index == 0 else "edge"
            component = "middle" if index == 0 else f"edge-{index:02d}"
            node = {
                "chainId": chain.chain_id, "role": role, "provider": "digitalocean",
                "terraformAddress": address, "hostname": attributes["name"],
                "region": attributes["region"], "assignedProxy": route.assigned_proxy,
                "proxy": route.assigned_proxy, "componentId": component,
                "status": "pending", "providerInstanceId": attributes["id"],
                "publicIp": attributes["ipv4_address"],
            }
            if index == 0:
                node["middleOrdinal"] = ordinal
            else:
                node.update(edgeId=component, edgeIndex=str(index),
                            edgeCount=str(len(route.edge_nodes)))
            nodes.append(node)
        projected.append(replace(chain, status="failed", nodes=nodes))
    rows[2] = projected


def test_materialized_scope_requires_rows_match_state_ids_and_ips(tmp_path, monkeypatch):
    rows = _applied_rows(tmp_path, monkeypatch)
    _materialize(rows)
    assert _scope(rows)["stateSha256"] == rows[6].events[0].data["stateSha256"]
    rows[2][0].nodes[0]["providerInstanceId"] = "999999"
    with pytest.raises(ProviderKeyedTeardownScopeError):
        _scope(rows)
