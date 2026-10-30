# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import copy
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.provider_keyed_sketch import (
    ProviderKeyedSketchError,
    compile_provider_topology,
    mark_provider_keyed_applied,
    mark_provider_keyed_apply_started,
    prepare_provider_keyed_workspace,
    resolve_default_provider_connection,
    read_provider_topology,
    require_provider_keyed_plan,
    reserve_provider_topology,
    reserve_mixed_external_provider_topologies,
)
from app.services.terraform_plan_gate import TerraformPlanGateError


def _source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "redteam-infra"
    for provider in ("linode", "digitalocean"):
        template = source / "external" / "sketch" / provider
        template.mkdir(parents=True)
        (template / "middle.tf").write_text('resource "test_instance" "middle" {}\n', encoding="utf-8")
        (template / "edge.tf").write_text('resource "test_instance" "edge" {}\n', encoding="utf-8")
        (template / "providers.tf").write_text('terraform { required_version = ">= 1.0" }\n', encoding="utf-8")
        (template / "firewall.tf").write_text('# legacy firewall\n', encoding="utf-8")
        sidecar = template / "barragan-v2"
        sidecar.mkdir()
        (sidecar / "providers.tf").write_text('terraform { required_version = "= 1.15.5" }\n', encoding="utf-8")
        (sidecar / ".terraform.lock.hcl").write_text('# pinned fixture\n', encoding="utf-8")
        (sidecar / "firewall.tf").write_text('# v2 firewall\n', encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
        check=True,
    )
    revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    return source, revision


def _prepare(tmp_path: Path, source: Path, revision: str, connection: str = "cred-000000000001", provider: str = "linode"):
    return prepare_provider_keyed_workspace(
        "eng-123", provider, connection,
        template_root=source, source_revision=revision, root=tmp_path / "state",
        environment="devtest", deployment_target="barragan-testing",
    )


def test_workspace_is_durable_scoped_and_pinned(tmp_path: Path):
    source, revision = _source(tmp_path)
    first = _prepare(tmp_path, source, revision)
    first.state_path.write_text("retained", encoding="utf-8")
    first.state_path.chmod(0o600)
    second = _prepare(tmp_path, source, revision)
    assert second == first
    assert second.state_path.read_text(encoding="utf-8") == "retained"
    assert first.provider_connection_id == "cred-000000000001"
    assert "provider-keyed-v2" in first.path.parts
    assert "cred-000000000001" not in str(first.path)
    assert (first.path / "providers.tf").read_text() == 'terraform { required_version = "= 1.15.5" }\n'
    assert (first.path / ".terraform.lock.hcl").read_text() == '# pinned fixture\n'
    assert (source / "external/sketch/linode/providers.tf").read_text() == 'terraform { required_version = ">= 1.0" }\n'
    with pytest.raises(ProviderKeyedSketchError, match="reviewed rebind"):
        _prepare(tmp_path, source, revision, "cred-000000000002")


def test_default_provider_connection_uses_immutable_credential_id():
    class Credential:
        id = "cred-000000000001"
        provider = "linode"
        status = "active"
        encrypted_secret = "rotated-value-does-not-affect-id"

    class Repository:
        def get_default(self, provider):
            assert provider == "linode"
            return Credential()

    assert resolve_default_provider_connection("linode", repository=Repository()) == "cred-000000000001"


def test_default_provider_connection_rejects_missing_or_wrong_provider():
    class Repository:
        def get_default(self, provider):
            return None

    with pytest.raises(ProviderKeyedSketchError, match="unavailable"):
        resolve_default_provider_connection("linode", repository=Repository())
    with pytest.raises(ProviderKeyedSketchError, match="unsupported"):
        resolve_default_provider_connection("other", repository=Repository())


def test_workspace_rejects_uncommitted_source_and_prod(tmp_path: Path):
    source, revision = _source(tmp_path)
    with pytest.raises(ProviderKeyedSketchError, match="DevTest"):
        prepare_provider_keyed_workspace(
            "eng-123", "linode", "cred-000000000001", template_root=source,
            source_revision=revision, root=tmp_path / "state",
            environment="production", deployment_target="barragan-testing",
        )
    (source / "external/sketch/linode/edge.tf").write_text("changed\n", encoding="utf-8")
    with pytest.raises(ProviderKeyedSketchError, match="clean committed"):
        _prepare(tmp_path, source, revision)


def test_workspace_rejects_changed_retained_module(tmp_path: Path):
    source, revision = _source(tmp_path)
    prepared = _prepare(tmp_path, source, revision)
    (prepared.path / "edge.tf").write_text("changed\n", encoding="utf-8")
    with pytest.raises(ProviderKeyedSketchError, match="source or ownership changed"):
        _prepare(tmp_path, source, revision)


def test_digitalocean_v2_firewall_overlay_preserves_manual_root(tmp_path: Path):
    source, revision = _source(tmp_path)
    workspace = _prepare(tmp_path, source, revision, "cred-000000000002", "digitalocean")
    assert (workspace.path / "firewall.tf").read_text() == '# v2 firewall\n'
    assert (source / "external/sketch/digitalocean/firewall.tf").read_text() == '# legacy firewall\n'
    (workspace.path / "firewall.tf").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ProviderKeyedSketchError, match="source or ownership changed"):
        _prepare(tmp_path, source, revision, "cred-000000000002", "digitalocean")


def test_linode_v2_firewall_overlay_preserves_manual_root(tmp_path: Path):
    source, revision = _source(tmp_path)
    workspace = _prepare(tmp_path, source, revision)
    assert (workspace.path / "firewall.tf").read_text() == '# v2 firewall\n'
    assert (source / "external/sketch/linode/firewall.tf").read_text() == '# legacy firewall\n'
    (workspace.path / "firewall.tf").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ProviderKeyedSketchError, match="source or ownership changed"):
        _prepare(tmp_path, source, revision)


@pytest.mark.parametrize("filename", ["providers.tf", ".terraform.lock.hcl", "barragan-v2/providers.tf"])
def test_workspace_rejects_changed_v2_provider_pin(tmp_path: Path, filename: str):
    source, revision = _source(tmp_path)
    prepared = _prepare(tmp_path, source, revision)
    (prepared.path / filename).write_text("changed\n", encoding="utf-8")
    with pytest.raises(ProviderKeyedSketchError, match="source or ownership changed"):
        _prepare(tmp_path, source, revision)


@pytest.mark.parametrize("filename", ["override.tf.json", "override.auto.tfvars", "override.auto.tfvars.json"])
def test_workspace_rejects_unpinned_terraform_inputs(tmp_path: Path, filename: str):
    source, revision = _source(tmp_path)
    prepared = _prepare(tmp_path, source, revision)
    unpinned = prepared.path / filename
    unpinned.write_text("{}", encoding="utf-8")
    unpinned.chmod(0o600)
    with pytest.raises(ProviderKeyedSketchError, match="unpinned Terraform source"):
        _prepare(tmp_path, source, revision)


def test_counts_expand_regionally_and_selected_retirement_does_not_reuse_ordinal():
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    groups = {
        "sfo": {"region": "sfo3", "middle_node": "primary", "count": 1},
        "sea_a": {"region": "sea", "middle_node": "primary", "count": 2},
        "sea_b": {"region": "sea", "middle_node": "primary", "count": 1},
    }
    first = compile_provider_topology(middles, groups)
    assert first["edge_groups"]["sea_a"]["ordinals"] == [1, 2]
    assert first["edge_groups"]["sea_b"]["ordinals"] == [3]
    groups["sea_a"] = {"region": "sea", "middle_node": "primary", "ordinals": [1]}
    retired = compile_provider_topology(middles, groups, previous=first)
    groups["sea_b"]["count"] = 2
    added = compile_provider_topology(middles, groups, previous=retired)
    assert added["edge_groups"]["sea_b"]["ordinals"] == [3, 4]
    assert added["regional_high_water"]["sea"] == 4


def test_count_reduction_and_ordinal_reuse_require_explicit_review():
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    group = {"sea": {"region": "sea", "middle_node": "primary", "count": 3}}
    first = compile_provider_topology(middles, group)
    with pytest.raises(ProviderKeyedSketchError, match="explicit ordinals"):
        compile_provider_topology(middles, {"sea": {**group["sea"], "count": 2}}, previous=first)
    retired = compile_provider_topology(middles, {"sea": {"region": "sea", "middle_node": "primary", "ordinals": [1, 3]}}, previous=first)
    with pytest.raises(ProviderKeyedSketchError, match="cannot be reused"):
        compile_provider_topology(middles, {"sea": {"region": "sea", "middle_node": "primary", "ordinals": [1, 2, 3]}}, previous=retired)


def test_reordering_same_region_groups_does_not_change_identity():
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    a = {"region": "sea", "middle_node": "primary", "count": 1}
    b = {"region": "sea", "middle_node": "primary", "count": 2}
    first = compile_provider_topology(middles, {"b": b, "a": a})
    second = compile_provider_topology(middles, {"a": a, "b": b})
    assert first == second
    assert first["edge_groups"]["a"]["ordinals"] == [1]
    assert first["edge_groups"]["b"]["ordinals"] == [2, 3]


def test_explicit_new_ordinal_is_not_rejected_after_count_group_advances_cursor():
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    previous = compile_provider_topology(
        middles, {"old": {"region": "sea", "middle_node": "primary", "count": 3}},
    )
    updated = compile_provider_topology(
        middles,
        {
            "old": {"region": "sea", "middle_node": "primary", "count": 3},
            "a_count": {"region": "sea", "middle_node": "primary", "count": 1},
            "z_explicit": {"region": "sea", "middle_node": "primary", "ordinals": [4]},
        },
        previous=previous,
    )
    assert updated["edge_groups"]["a_count"]["ordinals"] == [5]
    assert updated["edge_groups"]["z_explicit"]["ordinals"] == [4]


def test_shared_engagement_ledger_allocates_across_provider_states(tmp_path: Path):
    source, revision = _source(tmp_path)
    linode = _prepare(tmp_path, source, revision)
    digitalocean = _prepare(tmp_path, source, revision, "cred-000000000002", "digitalocean")
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    linode_topology = reserve_provider_topology(
        linode, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 2}},
    )
    do_topology = reserve_provider_topology(
        digitalocean, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 1}},
    )
    assert linode_topology["edge_groups"]["sea"]["ordinals"] == [1, 2]
    assert do_topology["edge_groups"]["sea"]["ordinals"] == [3]
    assert read_provider_topology(linode) == linode_topology
    assert read_provider_topology(digitalocean) == do_topology
    repeated = reserve_provider_topology(linode, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 2}})
    assert repeated["edge_groups"] == linode_topology["edge_groups"]


def test_mixed_external_pair_reserves_exact_foreign_middles_and_regional_cursor(tmp_path: Path):
    from app.services.provider_keyed_mixed_append_reservation import (
        propose_mixed_external_append_reservations,
    )
    from test_provider_keyed_mixed_append_reservation import sample

    source, revision = _source(tmp_path)
    workspaces = {
        "digitalocean": _prepare(tmp_path, source, revision, "cred-000000000002", "digitalocean"),
        "linode": _prepare(tmp_path, source, revision),
    }
    kwargs = sample()
    for provider in kwargs["reviewed_provider_order"]:
        topology = kwargs["current_topologies"][provider]
        assert reserve_provider_topology(workspaces[provider], topology["middles"],
                                         topology["edge_groups"]) == topology
    proposal = propose_mixed_external_append_reservations(**kwargs)
    result = reserve_mixed_external_provider_topologies(workspaces, proposal)
    assert result == {row.provider: row.proposed_topology for row in proposal.reservations}
    assert {p: read_provider_topology(w) for p, w in workspaces.items()} == result
    ledger = workspaces["linode"].path.parents[1] / "regional-ordinals.json"
    assert json.loads(ledger.read_text()) == {"nyc3": 2, "us-sea": 2}
    assert set(result["digitalocean"]["middles"]) == {"middle_01"}
    assert result["digitalocean"]["external_middles"]["middle_02"]["provider"] == "linode"
    assert reserve_mixed_external_provider_topologies(workspaces, proposal) == result

    # A completed retry still has to bind the original reviewed provenance.
    from dataclasses import replace
    with pytest.raises(ProviderKeyedSketchError):
        reserve_mixed_external_provider_topologies(
            workspaces, replace(proposal, original_high_water_sha256="0" * 64))
    changed = replace(proposal.reservations[0], prior_topology_sha256="0" * 64)
    with pytest.raises(ProviderKeyedSketchError):
        reserve_mixed_external_provider_topologies(
            workspaces, replace(proposal, reservations=(changed, proposal.reservations[1])))


@pytest.mark.parametrize("tamper", ["ledger", "topology", "identity"])
def test_mixed_external_pair_rejects_stale_or_tampered_proposal(tmp_path: Path, tamper: str):
    from app.services.provider_keyed_mixed_append_reservation import (
        propose_mixed_external_append_reservations,
    )
    from test_provider_keyed_mixed_append_reservation import sample

    source, revision = _source(tmp_path)
    workspaces = {
        "digitalocean": _prepare(tmp_path, source, revision, "cred-000000000002", "digitalocean"),
        "linode": _prepare(tmp_path, source, revision),
    }
    kwargs = sample()
    for provider in kwargs["reviewed_provider_order"]:
        topology = kwargs["current_topologies"][provider]
        reserve_provider_topology(workspaces[provider], topology["middles"], topology["edge_groups"])
    proposal = propose_mixed_external_append_reservations(**kwargs)
    if tamper == "ledger":
        (workspaces["linode"].path.parents[1] / "regional-ordinals.json").write_text(
            '{"nyc3":3,"us-sea":1}', encoding="utf-8")
    elif tamper == "topology":
        path = workspaces["linode"].path / ".barragan-topology.json"
        current = json.loads(path.read_text())
        current["middles"]["middle_02"]["region"] = "wrong"
        path.write_text(json.dumps(current), encoding="utf-8")
    else:
        proposal.reservations[0].proposed_topology["external_middles"]["middle_02"][
            "provider_instance_id"] = "other"
    with pytest.raises(ProviderKeyedSketchError):
        reserve_mixed_external_provider_topologies(workspaces, proposal)
    assert not (workspaces["linode"].path.parents[1] / ".mixed-external-reservation.json").exists()


def test_mixed_external_pair_recovers_only_exact_partial_write(tmp_path: Path, monkeypatch):
    import app.services.provider_keyed_sketch as sketch
    from app.services.provider_keyed_mixed_append_reservation import (
        propose_mixed_external_append_reservations,
    )
    from test_provider_keyed_mixed_append_reservation import sample

    source, revision = _source(tmp_path)
    workspaces = {
        "digitalocean": _prepare(tmp_path, source, revision, "cred-000000000002", "digitalocean"),
        "linode": _prepare(tmp_path, source, revision),
    }
    kwargs = sample()
    for provider in kwargs["reviewed_provider_order"]:
        topology = kwargs["current_topologies"][provider]
        reserve_provider_topology(workspaces[provider], topology["middles"], topology["edge_groups"])
    proposal = propose_mixed_external_append_reservations(**kwargs)
    original_write = sketch._write_json
    topology_path = workspaces["linode"].path / ".barragan-topology.json"

    def fail_second_topology(path, value):
        if path == topology_path:
            raise OSError("simulated stop before second topology")
        return original_write(path, value)

    monkeypatch.setattr(sketch, "_write_json", fail_second_topology)
    with pytest.raises(OSError, match="simulated stop"):
        reserve_mixed_external_provider_topologies(workspaces, proposal)
    marker = workspaces["linode"].path.parents[1] / ".mixed-external-reservation.json"
    assert marker.exists()
    with pytest.raises(ProviderKeyedSketchError, match="must finish first"):
        read_provider_topology(workspaces["digitalocean"])
    with pytest.raises(ProviderKeyedSketchError, match="must finish first"):
        reserve_provider_topology(workspaces["linode"],
                                  kwargs["current_topologies"]["linode"]["middles"],
                                  kwargs["current_topologies"]["linode"]["edge_groups"])
    monkeypatch.setattr(sketch, "_write_json", original_write)
    saved_marker = marker.read_text(encoding="utf-8")
    tampered = json.loads(saved_marker)
    tampered["proposed"]["digitalocean"]["external_middles"]["middle_02"][
        "terraform_address"] = 'linode_instance.middle["other"]'
    marker.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ProviderKeyedSketchError):
        sketch.resume_mixed_external_provider_topologies(workspaces)
    marker.write_text(saved_marker, encoding="utf-8")
    expected = {row.provider: row.proposed_topology for row in proposal.reservations}
    del proposal
    script = """
import sys
from pathlib import Path
from app.services.provider_keyed_sketch import prepare_provider_keyed_workspace, resume_mixed_external_provider_topologies
source, revision, root = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
workspaces = {
    provider: prepare_provider_keyed_workspace(
        'eng-123', provider, connection, template_root=source,
        source_revision=revision, root=root, environment='devtest',
        deployment_target='barragan-testing')
    for provider, connection in (
        ('digitalocean', 'cred-000000000002'), ('linode', 'cred-000000000001'))
}
resume_mixed_external_provider_topologies(workspaces)
"""
    subprocess.run(
        [sys.executable, "-c", script, str(source), revision, str(tmp_path / "state")],
        check=True, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])},
    )
    assert {p: read_provider_topology(w) for p, w in workspaces.items()} == expected
    assert not marker.exists()


def test_shared_ledger_never_reuses_retired_ordinal(tmp_path: Path):
    source, revision = _source(tmp_path)
    workspace = _prepare(tmp_path, source, revision)
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    reserve_provider_topology(workspace, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 3}})
    reserve_provider_topology(workspace, middles, {"sea": {"region": "sea", "middle_node": "primary", "ordinals": [1, 3]}})
    updated = reserve_provider_topology(workspace, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 3}})
    assert updated["edge_groups"]["sea"]["ordinals"] == [1, 3, 4]


def test_retiring_every_edge_keeps_group_tombstone(tmp_path: Path):
    source, revision = _source(tmp_path)
    workspace = _prepare(tmp_path, source, revision)
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    reserve_provider_topology(workspace, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 1}})
    empty = reserve_provider_topology(workspace, middles, {"sea": {"region": "sea", "middle_node": "primary", "ordinals": []}})
    assert empty["edge_groups"]["sea"]["ordinals"] == []
    added = reserve_provider_topology(workspace, middles, {"sea": {"region": "sea", "middle_node": "primary", "count": 1}})
    assert added["edge_groups"]["sea"]["ordinals"] == [2]


def test_reservation_rejects_missing_shared_ledger(tmp_path: Path):
    source, revision = _source(tmp_path)
    workspace = _prepare(tmp_path, source, revision)
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    groups = {"sea": {"region": "sea", "middle_node": "primary", "count": 1}}
    reserve_provider_topology(workspace, middles, groups)
    (workspace.path.parents[1] / "regional-ordinals.json").unlink()
    with pytest.raises(ProviderKeyedSketchError, match="ledger is missing"):
        reserve_provider_topology(workspace, middles, groups)


def test_reservation_rejects_topology_or_state_loss_after_apply(tmp_path: Path):
    source, revision = _source(tmp_path)
    workspace = _prepare(tmp_path, source, revision)
    middles = {"primary": {"region": "nyc3", "ordinal": 1}}
    groups = {"sea": {"region": "sea", "middle_node": "primary", "count": 1}}
    reserve_provider_topology(workspace, middles, groups)
    mark_provider_keyed_apply_started(workspace)
    workspace.state_path.write_text('{"resources": []}', encoding="utf-8")
    mark_provider_keyed_applied(workspace)
    (workspace.path / ".barragan-topology.json").unlink()
    with pytest.raises(ProviderKeyedSketchError, match="no provider topology metadata"):
        reserve_provider_topology(workspace, middles, groups)
    (workspace.path / ".barragan-topology.json").write_text(json.dumps(compile_provider_topology(middles, groups)), encoding="utf-8")
    workspace.state_path.unlink()
    with pytest.raises(ProviderKeyedSketchError, match="state is missing after an apply began"):
        reserve_provider_topology(workspace, middles, groups)


def test_saved_plan_gate_requires_exact_changes():
    edge = 'linode_instance.edge["sea-04"]'
    plan = json.dumps({"resource_changes": [
        {"address": edge, "change": {"actions": ["create"]}},
        {"address": "linode_firewall.firewall", "change": {"actions": ["update"]}},
    ]})
    assert len(require_provider_keyed_plan(
        json.dumps({"resource_changes": [{"address": edge, "change": {"actions": ["create"]}}]}),
        provider="linode", expected_node_changes={(edge, "create")},
    )) == 1
    with pytest.raises(TerraformPlanGateError, match="unapproved"):
        require_provider_keyed_plan(plan, provider="linode", expected_node_changes={(edge, "create")})
    with pytest.raises(TerraformPlanGateError, match="before/after"):
        require_provider_keyed_plan(
            plan, provider="linode", expected_node_changes={(edge, "create")},
            expected_dependent_updates={"linode_firewall.firewall"},
        )
    replaced = json.dumps({"resource_changes": [{"address": edge, "change": {"actions": ["delete", "create"]}}]})
    with pytest.raises(TerraformPlanGateError, match="unapproved"):
        require_provider_keyed_plan(replaced, provider="linode", expected_node_changes={(edge, "create")})
    with pytest.raises(TerraformPlanGateError, match="expected shared update is invalid"):
        require_provider_keyed_plan(
            plan, provider="linode", expected_node_changes={(edge, "create")},
            expected_dependent_updates={"linode_instance.middle[\"primary\"]"},
        )


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_saved_plan_gate_rejects_unvalidated_initial_firewall(provider):
    firewall = "linode_firewall.firewall" if provider == "linode" else "digitalocean_firewall.firewall"
    node = f'{"linode_instance" if provider == "linode" else "digitalocean_droplet"}.edge["sea-01"]'
    plan = json.dumps({"resource_changes": [
        {"address": node, "change": {"actions": ["create"]}},
        {"address": firewall, "change": {"actions": ["create"], "before": None, "after": {
            "tags": ["unreviewed"], "inbound": [{"protocol": "TCP", "ports": "1-65535", "ipv4": ["0.0.0.0/0"]}],
            "outbound_rule": [{"protocol": "tcp", "destination_addresses": ["0.0.0.0/0"]}],
        }}},
    ]})
    with pytest.raises(TerraformPlanGateError, match="firewall create requires policy validation"):
        require_provider_keyed_plan(plan, provider=provider, expected_node_changes={(node, "create")},
                                    expected_shared_creates={firewall})


def _membership_plan(provider: str, action: str) -> tuple[str, str, dict]:
    linode = provider == "linode"
    node = f'{"linode_instance" if linode else "digitalocean_droplet"}.edge["sea-04"]'
    firewall = "linode_firewall.firewall" if linode else "digitalocean_firewall.firewall"
    field = "linodes" if linode else "droplet_ids"
    ingress = "inbound" if linode else "inbound_rule"
    node_id = 304
    retained = [101, 102]
    old_cidrs = ["192.0.2.1/32", "192.0.2.2/32"]
    new_cidrs = old_cidrs + ["192.0.2.4/32"]
    def rules(cidrs):
        if linode:
            return [
                {"label": "allow-public", "protocol": "TCP", "ports": "443", "action": "ACCEPT", "ipv4": ["0.0.0.0/0"]},
                *({"label": f"allow-opaque-host-{proto}", "protocol": proto.upper(), "ports": "", "action": "ACCEPT", "ipv4": cidrs} for proto in ("tcp", "udp", "icmp")),
            ]
        return [
            {"protocol": "tcp", "port_range": "443", "source_addresses": ["0.0.0.0/0"]},
            *({"protocol": proto, "port_range": "1-65535", "source_addresses": cidrs} for proto in ("tcp", "udp", "icmp")),
        ]
    before = {"id": "firewall-1", field: retained, ingress: rules(old_cidrs), "tags": ["opaque"], "outbound_policy": "ACCEPT", "outbound_rule": [{"protocol": "tcp", "destination_addresses": ["0.0.0.0/0"]}]}
    after = {**copy.deepcopy(before), field: retained + [node_id], ingress: rules(new_cidrs)}
    node_values = {"id": node_id, "ipv4": ["192.0.2.4"]} if linode else {"id": node_id, "ipv4_address": "192.0.2.4"}
    if action == "delete":
        before, after = after, before
    document = {"resource_changes": [
        {"address": node, "change": {"actions": [action], "before": node_values if action == "delete" else None, "after": node_values if action == "create" else None}},
        {"address": firewall, "change": {"actions": ["update"], "before": before, "after": after, "after_unknown": {}}},
    ]}
    return node, firewall, document


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
@pytest.mark.parametrize("action", ["create", "delete"])
def test_saved_plan_gate_accepts_provable_node_membership_and_host_cidr_delta(provider, action):
    node, firewall, document = _membership_plan(provider, action)
    result = require_provider_keyed_plan(
        json.dumps(document), provider=provider,
        expected_node_changes={(node, action)}, expected_dependent_updates={firewall},
    )
    assert {(item.address, item.action) for item in result} == {(node, action), (firewall, "update")}


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
@pytest.mark.parametrize("mutation", ["public_rule", "outbound", "tags", "extra_attachment", "extra_host_cidr", "unknown_attachment", "unknown_node_id"])
def test_saved_plan_gate_rejects_unapproved_firewall_semantics(provider, mutation):
    node, firewall, document = _membership_plan(provider, "create")
    item = document["resource_changes"][1]["change"]
    after = item["after"]
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    attachment = "linodes" if provider == "linode" else "droplet_ids"
    if mutation == "public_rule":
        after[ingress][0]["ports" if provider == "linode" else "port_range"] = "444"
    elif mutation == "outbound":
        after["outbound_rule"][0]["protocol"] = "udp"
    elif mutation == "tags":
        after["tags"] = ["different"]
    elif mutation == "extra_attachment":
        after[attachment].append(999)
    elif mutation == "extra_host_cidr":
        after[ingress][1]["ipv4" if provider == "linode" else "source_addresses"].append("192.0.2.99/32")
    elif mutation == "unknown_attachment":
        item["after_unknown"] = {attachment: True}
    else:
        document["resource_changes"][0]["change"]["after"].pop("id")
    with pytest.raises(TerraformPlanGateError):
        require_provider_keyed_plan(json.dumps(document), provider=provider,
                                    expected_node_changes={(node, "create")}, expected_dependent_updates={firewall})


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
@pytest.mark.parametrize("mutation", ["removed_wrong_id", "removed_wrong_cidr", "unknown_new_id", "unknown_new_ip", "flagged_unknown_id"])
def test_saved_plan_gate_requires_node_identity_proof(provider, mutation):
    action = "create" if mutation.startswith("unknown") or mutation == "flagged_unknown_id" else "delete"
    node, firewall, document = _membership_plan(provider, action)
    node_change = document["resource_changes"][0]["change"]
    firewall_change = document["resource_changes"][1]["change"]
    if mutation == "removed_wrong_id":
        node_change["before"]["id"] = 999
    elif mutation == "removed_wrong_cidr":
        node_change["before"]["ipv4" if provider == "linode" else "ipv4_address"] = ["192.0.2.99"] if provider == "linode" else "192.0.2.99"
    elif mutation == "unknown_new_id":
        node_change["after"].pop("id")
        node_change["after_unknown"] = {"id": True}
        firewall_change["after"]["linodes" if provider == "linode" else "droplet_ids"][-1] = None
        firewall_change["after_unknown"] = {"linodes" if provider == "linode" else "droplet_ids": True}
    elif mutation == "unknown_new_ip":
        node_change["after"].pop("ipv4" if provider == "linode" else "ipv4_address")
        node_change["after_unknown"] = {"ipv4" if provider == "linode" else "ipv4_address": True}
    else:
        node_change["after_unknown"] = {"id": True}
    with pytest.raises(TerraformPlanGateError):
        require_provider_keyed_plan(json.dumps(document), provider=provider,
                                    expected_node_changes={(node, action)}, expected_dependent_updates={firewall})
