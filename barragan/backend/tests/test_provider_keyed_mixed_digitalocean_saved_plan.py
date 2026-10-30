# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant mixed DigitalOcean saved-plan adapter with gated fake commands."""

import copy
import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_initial_plan_gate as gate
import app.services.provider_keyed_mixed_digitalocean_intent as compiler
import app.services.provider_keyed_mixed_linode_intent as linode_compiler
import app.services.provider_keyed_mixed_digitalocean_saved_plan as saved
import app.services.provider_keyed_mixed_digitalocean_plan_gate as mixed_gate
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.sketch_ssh_keys import SketchSshKeyMaterial, SketchSshKeyMetadata, _fingerprint
from test_provider_keyed_initial_plan_gate import workspace as gate_workspace
from test_provider_keyed_mixed_digitalocean_intent import _mixed_records, PUBLIC_KEY, WRONG_PUBLIC_KEY


REAL_SHOW_GATE = saved._show_gate
FIXTURE = Path(__file__).parent / "fixtures/provider_keyed/digitalocean-initial-full-terraform-1.15.5.json"


@pytest.fixture
def case(tmp_path, monkeypatch):
    records = _mixed_records(linode_first=False)
    key = [PUBLIC_KEY]

    def material(*_):
        return SketchSshKeyMaterial(
            SketchSshKeyMetadata("eng-opaque", "private", "public", _fingerprint(key[0]),
                                 [], "now", "now"), "private-key", key[0])

    monkeypatch.setattr(linode_compiler, "retrieve_sketch_ssh_key", material)
    monkeypatch.setattr(saved, "retrieve_sketch_ssh_key", material)
    state_root = tmp_path / "state"
    root = state_root / "eng-opaque" / "provider-keyed-v2" / "digitalocean" / "fprint"
    root.mkdir(parents=True, mode=0o700)
    source_parent = tmp_path / "source"
    source_parent.mkdir()
    fixture = gate_workspace.__wrapped__(source_parent, monkeypatch)
    shutil.copytree(fixture.path, root, dirs_exist_ok=True)
    marker_path = root / ".barragan-provider-keyed-state.json"
    marker = json.loads(marker_path.read_text())
    marker.update(engagement_id="eng-opaque", provider_connection_id="cred-do",
                  connection_fingerprint="fprint")
    marker_path.write_text(json.dumps(marker))
    (root / ".terraform-data").mkdir(mode=0o700, exist_ok=True)
    workspace = ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
                                       "provider-keyed-v2", "digitalocean", "cred-do", "fprint",
                                       gate._SOURCE_REVISION, fixture.source_sha256)
    monkeypatch.setattr(saved, "_default_state_root", lambda: state_root)
    monkeypatch.setattr(saved, "prepare_provider_keyed_workspace", lambda *a, **k: workspace)
    monkeypatch.setattr(saved, "_unsafe_keyed_workspace", lambda _: False)
    monkeypatch.setattr(compiler, "_SOURCE_SHA256", fixture.source_sha256)
    auth = records["core_plan"].evidence["sketchAuthorization"]
    auth["providerScopes"][0]["source"]["templateSha256"] = fixture.source_sha256
    auth["fingerprint"] = linode_compiler._digest({k: v for k, v in auth.items() if k != "fingerprint"})
    binary = tmp_path / "terraform"
    binary.write_bytes(b"offline Terraform 1.15.5")
    binary.chmod(0o700)
    monkeypatch.setattr(saved, "require_devtest_terraform_release", lambda **k: SimpleNamespace(
        path=binary, sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
    monkeypatch.setattr(saved, "decrypt_secret_value", lambda _: "offline-token")
    reservations = []

    def reserve(_, middles, groups):
        intent = compiler.compile_mixed_digitalocean_initial_intent(**records)
        (root / ".barragan-topology.json").write_text(json.dumps(intent.topology))
        reservations.append(1)
        return intent.topology

    monkeypatch.setattr(saved, "reserve_provider_topology", reserve)
    monkeypatch.setattr(saved, "_show_gate", lambda shown, *a: hashlib.sha256(shown.encode()).hexdigest())
    plan = {"variables": {}}
    calls = []
    failures = {}

    def gated(argv, *, scratch_path, provider_keyed_v2, env, max_output_bytes,
              intent_callback, started_callback, heartbeat_callback, result_callback):
        phase = argv[1]
        calls.append(phase)
        assert provider_keyed_v2 and scratch_path == root
        assert "do_pat" not in json.dumps(env)
        invocation = f"invocation-{len(calls)}"
        digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
        intent_record = CommandIntent(invocation, str(root), digest)
        intent_callback(intent_record)
        started = StartedCommand(intent_record, ProcessIdentity("boot", 1000 + len(calls),
                                                                 1000 + len(calls), 1234))
        started_callback(started)
        heartbeat_callback(started)
        if failures.get(phase) == "interrupted":
            failures.pop(phase)
            raise RuntimeError("worker interrupted before result")
        if phase == "plan":
            assert (root.parents[1] / ".plan-material/digitalocean/admin-private").is_file()
            assert json.loads((root.parents[1] / ".plan-material/digitalocean/credential.json").read_text()) == {"do_pat": "offline-token"}
            (root / saved._PLAN).write_bytes(b"saved-do-binary-plan")
        returncode = 1 if failures.pop(phase, None) == "failed" else 0
        stdout = ('{"terraform_version":"1.15.5"}' if phase == "version"
                  else json.dumps(plan) if phase == "show" else "")
        result_callback(CommandAuditResult(started, returncode, len(stdout), 0, False, False))
        return CommandResult(started, returncode, stdout, "", False, False)

    args = dict(engagement_id="eng-opaque", core_job_id="job-core", lease_owner="owner",
                environment="devtest", state_root=state_root, template_root=source_parent,
                engagement_repository=SimpleNamespace(get=lambda _: records["engagement"]),
                sketch_repository=SimpleNamespace(list_for_engagement=lambda _: records["chains"]),
                job_repository=records["job_repository"],
                plan_repository=SimpleNamespace(get=lambda _: records["core_plan"]),
                credential_repository=records["credential_repository"],
                ssh_key_repository=SimpleNamespace(),
                lease_lookup=lambda _: ("owner", "provider_keyed_initial"),
                command_environment={"PATH": str(tmp_path)}, gated_command_runner=gated,
                process_quiescence=lambda *a: True)
    return SimpleNamespace(args=args, root=root, calls=calls, failures=failures,
                           key=key, records=records, reservations=reservations)


def test_gated_receipt_restart_and_private_cleanup(case):
    receipt = saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert receipt["planSha256"] == hashlib.sha256(b"saved-do-binary-plan").hexdigest()
    assert case.calls == ["version", "init", "plan", "show"]
    assert saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args) == receipt
    assert case.calls == ["version", "init", "plan", "show", "version", "show"]
    assert len(case.reservations) == 1
    assert not (case.root.parents[1] / ".plan-material/digitalocean/credential.json").exists()
    assert not (case.root.parents[1] / ".plan-material/digitalocean/admin-private").exists()


def test_real_show_gate_binds_compiled_nodes_firewall_and_local_files(case, monkeypatch):
    intent = compiler.compile_mixed_digitalocean_initial_intent(**case.records)
    workspace = saved.prepare_provider_keyed_workspace(
        "eng-opaque", "digitalocean", "cred-do", template_root=Path("unused"),
        source_revision="unused", root=Path("unused"), environment="devtest",
        deployment_target="barragan-testing")
    saved.reserve_provider_topology(workspace, intent.topology["middles"], intent.topology["edge_groups"])
    monkeypatch.setattr(mixed_gate, "_SOURCE_SHA256", workspace.source_sha256)
    material = case.root.parents[1] / ".plan-material/digitalocean"
    private, output = material / "admin-private", material / "ssh-output"
    plan = copy.deepcopy(json.loads(FIXTURE.read_text()))
    middle = intent.nodes[f'digitalocean_droplet.middle["{intent.middle_key}"]']
    edge = intent.nodes[f'digitalocean_droplet.edge["{intent.edge_key}"]']
    local = intent.expected_local_files(private, output)
    for row in plan["resource_changes"]:
        after = row["change"]["after"]
        address = row["address"]
        if address == 'digitalocean_droplet.middle["primary"]':
            row["address"] = f'digitalocean_droplet.middle["{intent.middle_key}"]'
            after.update(name=middle.name, image=middle.image, size=middle.size,
                         region=middle.region, tags=[intent.selector_tag])
        elif address == f'digitalocean_droplet.edge["{intent.edge_key}"]':
            after.update(name=edge.name, image=edge.image, size=edge.size,
                         region=edge.region, tags=[intent.selector_tag])
        elif address == "digitalocean_firewall.firewall":
            after.update(name=intent.firewall.name, tags=[intent.selector_tag])
            for rule in after["inbound_rule"]:
                if rule["protocol"] == "tcp" and rule["port_range"] == "22":
                    rule["source_addresses"] = list(intent.trusted_ssh_cidrs)
        elif address == "digitalocean_ssh_key.key":
            after.update(name="do-key", public_key=intent.admin_public_key)
        elif address in local:
            after.update(local[address])
    plan["variables"] = {key: {"value": value} for key, value in {
        **intent.nonsecret_varfile,
        "ssh_priv_key_path": str(private),
        "ssh_pub_key_path": str(material / "admin-public"),
        "ssh_config_path": str(output),
    }.items()}
    shown = json.dumps(plan)
    assert REAL_SHOW_GATE(shown, intent, workspace, private, output,
                          case.records["core_plan"].evidence["sketchAuthorization"]) == hashlib.sha256(
                              json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    wrong_path = copy.deepcopy(plan)
    wrong_path["variables"]["ssh_priv_key_path"]["value"] = "/tmp/unreviewed-key"
    with pytest.raises(ValueError):
        REAL_SHOW_GATE(json.dumps(wrong_path), intent, workspace, private, output,
                       case.records["core_plan"].evidence["sketchAuthorization"])
    for row in plan["resource_changes"]:
        if row["address"] == "local_file.ansible_inventory[0]":
            row["change"]["after"]["content"] = "clipped or wrong inventory"
    with pytest.raises(ValueError):
        REAL_SHOW_GATE(json.dumps(plan), intent, workspace, private, output,
                       case.records["core_plan"].evidence["sketchAuthorization"])


def test_failed_init_retries_without_orphan_plan(case):
    case.failures["init"] = "failed"
    with pytest.raises(saved.MixedDigitalOceanSavedPlanError, match="init failed"):
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert not (case.root / saved._PLAN).exists()
    saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert case.calls.count("plan") == 1


def test_interrupted_init_needs_quiescence(case):
    case.failures["init"] = "interrupted"
    with pytest.raises(RuntimeError):
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    case.args["process_quiescence"] = lambda *a: False
    with pytest.raises(saved.MixedDigitalOceanSavedPlanError, match="quiescence"):
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    case.args["process_quiescence"] = lambda *a: True
    saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)


@pytest.mark.parametrize("drift", ["key", "core", "credential", "binary", "source", "orphan"])
def test_restart_drift_or_orphan_stops_without_replan(case, drift):
    if drift != "orphan":
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    if drift == "key":
        case.key[0] = WRONG_PUBLIC_KEY
    elif drift == "core":
        case.records["core_job"].input["pendingSketchChainIds"] = []
    elif drift == "credential":
        do = replace(case.records["credential_repository"].get("cred-do"), encrypted_secret="rotated")
        original = case.records["credential_repository"]
        case.args["credential_repository"] = SimpleNamespace(
            get=lambda id: do if id == "cred-do" else original.get(id),
            get_default=lambda provider: do if provider == "digitalocean" else original.get_default(provider))
    elif drift == "binary":
        (case.root / saved._PLAN).write_bytes(b"wrong")
    elif drift == "source":
        (case.root / "middle.tf").write_text("drift")
    else:
        (case.root / saved._PLAN).write_bytes(b"orphan")
    before = case.calls.count("plan")
    with pytest.raises(ValueError):
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert case.calls.count("plan") == before


def test_interrupted_plan_retains_secret_until_reconciliation(case):
    case.failures["plan"] = "interrupted"
    with pytest.raises(RuntimeError):
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert (case.root.parents[1] / ".plan-material/digitalocean/credential.json").is_file()
    with pytest.raises(saved.MixedDigitalOceanSavedPlanError, match="outcome requires reconciliation"):
        saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert case.calls.count("plan") == 1


def test_second_provider_needs_reservation_but_not_predecessor_receipt(case, monkeypatch):
    records = _mixed_records(linode_first=True, same_region=True)
    auth = records["core_plan"].evidence["sketchAuthorization"]
    auth["providerScopes"][0]["source"]["templateSha256"] = compiler._SOURCE_SHA256
    auth["fingerprint"] = linode_compiler._digest({k: v for k, v in auth.items()
                                                   if k != "fingerprint"})
    intent = compiler.compile_mixed_digitalocean_initial_intent(**records)
    assert (intent.middle_key, intent.edge_key) == ("middle_02", "us-west-02")
    workspace = saved.prepare_provider_keyed_workspace(
        "eng-opaque", "digitalocean", "cred-do", template_root=Path("unused"),
        source_revision="unused", root=Path("unused"), environment="devtest",
        deployment_target="barragan-testing")
    with pytest.raises(saved.MixedDigitalOceanSavedPlanError, match="reservation is absent"):
        saved._require_predecessor_reservation(workspace, intent, records["chains"], records["core_plan"])
    fingerprint = hashlib.sha256(b"linode\0cred-linode").hexdigest()
    root = workspace.path.parents[1] / "linode" / fingerprint
    root.mkdir(parents=True)
    scope = auth["providerScopes"][1]
    marker = {"schema": "provider-keyed-v2", "engagement_id": "eng-opaque",
              "provider": "linode", "provider_connection_id": "cred-linode",
              "connection_fingerprint": fingerprint, "source_revision": scope["source"]["revision"]}
    topology = {"schema": "provider-keyed-v2",
                "middles": {"middle_01": {"region": "us-east", "ordinal": 1}},
                "edge_groups": {"group_01_us_west": {"region": "us-west",
                                                      "middle_node": "middle_01", "ordinals": [1]}},
                "regional_high_water": {"us-west": 1}}
    (root / ".barragan-provider-keyed-state.json").write_text(json.dumps(marker))
    (root / ".barragan-topology.json").write_text(json.dumps(topology))
    assert not (root / ".barragan-linode-plan-receipt.json").exists()
    saved._require_predecessor_reservation(workspace, intent, records["chains"], records["core_plan"])

    # Planning may follow a reservation even while the predecessor plan is
    # unsaved. The later both-plans checkpoint must join full receipts.
    case.args["sketch_repository"] = SimpleNamespace(list_for_engagement=lambda _: records["chains"])
    case.args["job_repository"] = records["job_repository"]
    case.args["plan_repository"] = SimpleNamespace(get=lambda _: records["core_plan"])
    case.args["credential_repository"] = records["credential_repository"]
    def reserve(_, middles, groups):
        (case.root / ".barragan-topology.json").write_text(json.dumps(intent.topology))
        return intent.topology
    monkeypatch.setattr(saved, "reserve_provider_topology", reserve)
    receipt = saved.prepare_or_reuse_mixed_digitalocean_saved_plan(**case.args)
    assert receipt["planSha256"] == hashlib.sha256(b"saved-do-binary-plan").hexdigest()
    assert not (root / ".barragan-linode-plan-receipt.json").exists()

    topology["edge_groups"]["group_01_us_west"]["ordinals"] = [2]
    (root / ".barragan-topology.json").write_text(json.dumps(topology))
    with pytest.raises(saved.MixedDigitalOceanSavedPlanError, match="differs from reviewed order"):
        saved._require_predecessor_reservation(workspace, intent, records["chains"], records["core_plan"])


def test_current_uses_reviewed_pair_with_inert_aborted_default_history(case):
    args = case.args
    reviewed = list(case.records["chains"])
    ghost = replace(reviewed[0], chain_id="old-default", status="aborted")
    case.records["chains"] = [ghost, *reversed(reviewed)]
    result = saved._current(
        args["engagement_id"], args["core_job_id"], args["lease_owner"],
        args["lease_lookup"], args["engagement_repository"], args["sketch_repository"],
        args["job_repository"], args["plan_repository"], args["credential_repository"],
        args["ssh_key_repository"], None)
    ids = case.records["core_plan"].evidence["pendingSketchChainIds"]
    assert [row.chain_id for row in result[1]] == ids
    assert ghost in case.records["chains"]
    assert case.calls == [] and case.reservations == []
