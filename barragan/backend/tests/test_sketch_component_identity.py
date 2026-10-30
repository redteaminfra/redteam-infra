# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.sketch_component_identity import (
    SketchComponentIdentityError,
    resolve_channel_sketch_components,
)
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


def test_selected_second_same_provider_edge_resolves_by_component_not_child_order():
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edge-01", "role": "edge", "provider": "linode"},
        {"componentId": "edge-02", "role": "edge", "provider": "linode"},
    ]
    children = {
        "edge-02": _child("edge-02", "edge", "linode", "/state/edge-02"),
        "middle": _child("middle", "middle", "linode", "/state/middle"),
        "edge-01": _child("edge-01", "edge", "linode", "/state/edge-01"),
    }
    job = _job(components=components, children=children)
    resolved = _resolve(_chain(), job, _channel("edge-02"), _rows("linode", "linode"))
    assert resolved.edge.component_id == "edge-02"
    assert resolved.edge.workspace == Path("/state/edge-02")
    assert resolved.middle.component_id == "middle"
    assert resolved.middle.workspace == Path("/state/middle")


def test_mixed_route_resolves_exact_edge_and_middle_workspaces():
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edge-02", "role": "edge", "provider": "digitalocean"},
    ]
    children = {
        "edge-02": _child("edge-02", "edge", "digitalocean", "/state/edge-do"),
        "middle": _child("middle", "middle", "linode", "/state/middle-linode"),
    }
    chain = replace(_chain(), edge_provider="digitalocean")
    resolved = _resolve(chain, _job(components=components, children=children), _channel("edge-02"), _rows("linode", "digitalocean"))
    assert (resolved.edge.provider, resolved.edge.workspace) == ("digitalocean", Path("/state/edge-do"))
    assert (resolved.middle.provider, resolved.middle.workspace) == ("linode", Path("/state/middle-linode"))


def test_shared_same_provider_route_resolves_one_canonical_workspace_for_both_roles():
    chain = replace(_chain(), terraform_working_directory="/state/shared")
    job = _job(components=None, children=None, terraformWorkingDirectory="/state/shared", middleCount=1, edgeCount=2)
    resolved = _resolve(chain, job, _channel("edge-02"), _rows("linode", "linode"))
    assert resolved.edge.component_id == "edge-02"
    assert resolved.middle.component_id == "middle"
    assert resolved.edge.workspace == resolved.middle.workspace == Path("/state/shared")
    assert resolved.edge.provider_input is job.input


@pytest.mark.parametrize("mutation", [
    "missing-channel-component",
    "duplicate-route-row",
    "duplicate-deploy-component",
    "component-provider-mismatch",
    "child-component-mismatch",
    "workspace-map-mismatch",
])
def test_resolver_fails_closed_on_missing_duplicate_or_mismatched_identity(mutation: str):
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edge-02", "role": "edge", "provider": "digitalocean"},
    ]
    children = {
        "middle": _child("middle", "middle", "linode", "/state/middle"),
        "edge-02": _child("edge-02", "edge", "digitalocean", "/state/edge-02"),
    }
    chain = replace(_chain(), edge_provider="digitalocean")
    job = _job(components=components, children=children)
    channel = _channel("edge-02")
    rows = _rows("linode", "digitalocean")
    if mutation == "missing-channel-component":
        channel.pop("edgeComponentId")
    elif mutation == "duplicate-route-row":
        rows.append(dict(rows[-1]))
    elif mutation == "duplicate-deploy-component":
        job.input["components"].append(dict(job.input["components"][1]))
    elif mutation == "component-provider-mismatch":
        job.input["components"][1]["provider"] = "linode"
    elif mutation == "child-component-mismatch":
        job.input["childInputs"]["edge-02"]["componentId"] = "edge-01"
    else:
        job.input["terraformWorkingDirectories"]["edge-02"] = "/state/other"
    with pytest.raises(SketchComponentIdentityError):
        _resolve(chain, job, channel, rows)


def test_legacy_fallback_requires_exactly_one_distinct_middle_and_edge_child():
    children = {
        "old-middle": _child("", "middle", "linode", "/state/middle"),
        "old-edge": _child("", "edge", "digitalocean", "/state/edge"),
    }
    for child in children.values():
        child.pop("engagementId")
        child.pop("chainId")
    job = _job(components=None, children=children, middleProvider="linode", edgeProvider="digitalocean")
    channel = {**_channel("old-edge"), "middleComponentId": "old-middle"}
    rows = [
        {"chainId": "chain-1", "hostname": "middle-01", "componentId": "old-middle", "role": "middle", "provider": "linode"},
        {"chainId": "chain-1", "hostname": "edge-02-host", "componentId": "old-edge", "role": "edge", "provider": "digitalocean"},
    ]
    resolved = _resolve(replace(_chain(), edge_provider="digitalocean"), job, channel, rows)
    assert (resolved.edge.component_id, resolved.middle.component_id) == ("old-edge", "old-middle")


@pytest.mark.parametrize("field,value", [
    ("components", []),
    ("components", "invalid"),
    ("childInputs", []),
    ("childInputs", "invalid"),
])
def test_legacy_fallback_applies_only_when_component_evidence_is_absent(field, value):
    children = {
        "old-middle": _child("", "middle", "linode", "/state/middle"),
        "old-edge": _child("", "edge", "digitalocean", "/state/edge"),
    }
    job = _job(components=None, children=children, middleProvider="linode", edgeProvider="digitalocean")
    job.input[field] = value
    channel = {**_channel("old-edge"), "middleComponentId": "old-middle"}
    rows = [
        {"chainId": "chain-1", "hostname": "middle-01", "componentId": "old-middle", "role": "middle", "provider": "linode"},
        {"chainId": "chain-1", "hostname": "edge-02-host", "componentId": "old-edge", "role": "edge", "provider": "digitalocean"},
    ]
    with pytest.raises(SketchComponentIdentityError):
        _resolve(replace(_chain(), edge_provider="digitalocean"), job, channel, rows)


@pytest.mark.parametrize("mutation", ["id", "action", "status", "target", "target-type", "target-id", "engagement", "chain"])
def test_resolver_requires_authoritative_successful_persisted_deploy_job(mutation):
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edge-02", "role": "edge", "provider": "digitalocean"},
    ]
    children = {
        "middle": _child("middle", "middle", "linode", "/state/middle"),
        "edge-02": _child("edge-02", "edge", "digitalocean", "/state/edge"),
    }
    job = _job(components=components, children=children)
    if mutation in {"engagement", "chain"}:
        job.input["engagementId" if mutation == "engagement" else "chainId"] = "wrong"
    else:
        replacements = {
            "id": {"id": "job-other"}, "action": {"action": "mixed_provider_sketch_teardown"},
            "status": {"status": "running"}, "target": {"target": "engagement:wrong"},
            "target-type": {"target_type": "host"}, "target-id": {"target_id": "wrong"},
        }
        job = replace(job, **replacements[mutation])
    with pytest.raises(SketchComponentIdentityError):
        _resolve(replace(_chain(), edge_provider="digitalocean"), job, _channel("edge-02"), _rows("linode", "digitalocean"))


def test_resolver_binds_selected_component_provider_to_persisted_chain_provider():
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edge-02", "role": "edge", "provider": "digitalocean"},
    ]
    children = {
        "middle": _child("middle", "middle", "linode", "/state/middle"),
        "edge-02": _child("edge-02", "edge", "digitalocean", "/state/edge"),
    }
    with pytest.raises(SketchComponentIdentityError):
        _resolve(_chain(), _job(components=components, children=children), _channel("edge-02"), _rows("linode", "digitalocean"))


@pytest.mark.parametrize("mutation", ["bool-middle", "float-middle", "two-middles", "edge-count", "row-count", "duplicate-component"])
def test_shared_workspace_requires_exact_strict_counts_and_persisted_rows(mutation):
    rows = _rows("linode", "linode")
    chain = replace(_chain(), terraform_working_directory="/state/shared", nodes=[dict(row) for row in rows])
    values = {"middleCount": 1, "edgeCount": 2}
    if mutation == "bool-middle":
        values["middleCount"] = True
    elif mutation == "float-middle":
        values["middleCount"] = 1.0
    elif mutation == "two-middles":
        values["middleCount"] = 2
    elif mutation == "edge-count":
        values["edgeCount"] = 1
    elif mutation == "row-count":
        chain.nodes.pop()
    else:
        chain.nodes[1]["componentId"] = chain.nodes[2]["componentId"]
    job = _job(components=None, children=None, terraformWorkingDirectory="/state/shared", **values)
    with pytest.raises(SketchComponentIdentityError):
        _resolve(chain, job, _channel("edge-02"), rows)


@pytest.mark.parametrize("provider,action", [
    ("linode", "linode_sketch_deploy"),
    ("linode", "linode_sketch_reconcile"),
    ("digitalocean", "digitalocean_sketch_deploy"),
    ("digitalocean", "digitalocean_sketch_reconcile"),
])
def test_shared_workspace_accepts_exact_provider_deploy_and_reconcile_jobs(provider, action):
    rows = _rows(provider, provider)
    chain = replace(
        _chain(),
        middle_provider=provider,
        edge_provider=provider,
        terraform_working_directory="/state/shared",
        nodes=[dict(row) for row in rows],
    )
    job = _job(
        components=None,
        children=None,
        _action=action,
        middleProvider=provider,
        edgeProvider=provider,
        terraformWorkingDirectory="/state/shared",
        middleCount=1,
        edgeCount=2,
    )
    resolved = _resolve(chain, job, _channel("edge-02"), rows)
    assert resolved.edge.provider == resolved.middle.provider == provider


def test_shared_workspace_rejects_unrecognized_action_with_other_evidence_unchanged():
    rows = _rows("linode", "linode")
    chain = replace(_chain(), terraform_working_directory="/state/shared", nodes=[dict(row) for row in rows])
    job = _job(
        components=None,
        children=None,
        _action="linode_sketch_teardown",
        terraformWorkingDirectory="/state/shared",
        middleCount=1,
        edgeCount=2,
    )
    with pytest.raises(SketchComponentIdentityError, match="not authoritative"):
        _resolve(chain, job, _channel("edge-02"), rows)


def _resolve(chain, job, channel, rows):
    if not chain.nodes:
        chain = replace(chain, nodes=[dict(row) for row in rows])
    return resolve_channel_sketch_components(
        "eng-1", chain, job, channel, rows,
        workspace_validator=lambda _eng, _chain, _provider, path, **_kwargs: SimpleNamespace(path=path),
    )


def _chain() -> StoredSketchChain:
    return StoredSketchChain(
        "chain-1", "eng-1", "proxy01", "linode", "us-sea", "small",
        "linode", "us-sea", "small", "deployed", False, "", "job-deploy", "", "",
        [], "now", "now", edge_count=2,
    )


def _job(*, components, children, **overrides) -> StoredJobRun:
    action = overrides.pop("_action", "mixed_provider_sketch_deploy" if children is not None else "linode_sketch_deploy")
    values = {
        "engagementId": "eng-1", "chainId": "chain-1", "middleProvider": "linode",
        "edgeProvider": "linode",
    }
    if components is not None:
        values["components"] = components
    if children is not None:
        values["childInputs"] = children
        values["terraformWorkingDirectories"] = {
            component_id: child["terraformWorkingDirectory"] for component_id, child in children.items()
        }
    values.update(overrides)
    return StoredJobRun(
        "job-deploy", action, "succeeded", "engagement:eng-1",
        "engagement", "eng-1", "operator", values, [], "now", "now", "now", [],
    )


def _child(component_id: str, role: str, provider: str, workspace: str) -> dict:
    return {
        "componentId": component_id,
        "provider": provider,
        "middleCount": 1 if role == "middle" else 0,
        "edgeCount": 0 if role == "middle" else 1,
        "edgeCountPerRegion": 0 if role == "middle" else 1,
        "engagementId": "eng-1", "chainId": "chain-1",
        "terraformWorkingDirectory": workspace,
    }


def _channel(edge_component: str) -> dict:
    return {
        "chainId": "chain-1", "edge": "edge-02-host", "edgeComponentId": edge_component,
        "middle": "middle-01", "middleComponentId": "middle",
    }


def _rows(middle_provider: str, edge_provider: str) -> list[dict]:
    return [
        {"chainId": "chain-1", "hostname": "middle-01", "componentId": "middle", "role": "middle", "provider": middle_provider},
        {"chainId": "chain-1", "hostname": "edge-01-host", "componentId": "edge-01", "role": "edge", "provider": edge_provider},
        {"chainId": "chain-1", "hostname": "edge-02-host", "componentId": "edge-02", "role": "edge", "provider": edge_provider},
    ]
