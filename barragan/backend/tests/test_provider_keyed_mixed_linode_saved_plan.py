# Copyright (c) 2026, Oracle and/or its affiliates.
"""Durable gated Linode plan prep against the offline mock-provider plan."""

import copy
import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_linode_initial_plan_gate as gate
import app.services.provider_keyed_mixed_linode_intent as compiler
import app.services.provider_keyed_mixed_linode_saved_plan as saved
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.sketch_ssh_keys import SketchSshKeyMaterial, SketchSshKeyMetadata, _fingerprint
from test_provider_keyed_linode_initial_plan_gate import PLAN, workspace as gate_workspace
from test_provider_keyed_mixed_linode_intent import PUBLIC_KEY, WRONG_PUBLIC_KEY, _records


@pytest.fixture
def case(tmp_path, monkeypatch):
    records = _records()
    key = [PUBLIC_KEY]

    def material(*_):
        return SketchSshKeyMaterial(
            SketchSshKeyMetadata("eng-opaque", "private", "public", _fingerprint(key[0]),
                                 [], "now", "now"), "private-key", key[0])

    monkeypatch.setattr(compiler, "retrieve_sketch_ssh_key", material)
    monkeypatch.setattr(saved, "retrieve_sketch_ssh_key", material)
    state_root = tmp_path / "state"
    root = state_root / "eng-opaque" / "provider-keyed-v2" / "linode" / "fprint"
    root.mkdir(parents=True, mode=0o700)
    source_parent = tmp_path / "source"
    source_parent.mkdir()
    fixture = gate_workspace.__wrapped__(source_parent, monkeypatch)
    shutil.copytree(fixture.path, root, dirs_exist_ok=True)
    marker_path = root / ".barragan-provider-keyed-state.json"
    marker = json.loads(marker_path.read_text())
    marker.update(engagement_id="eng-opaque", provider_connection_id="cred-linode",
                  connection_fingerprint="fprint")
    marker_path.write_text(json.dumps(marker))
    (root / ".terraform-data").mkdir(mode=0o700)
    workspace = ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
                                       "provider-keyed-v2", "linode", "cred-linode", "fprint",
                                       gate._SOURCE_REVISION, gate._SOURCE_SHA256)
    monkeypatch.setattr(saved, "_default_state_root", lambda: state_root)
    monkeypatch.setattr(saved, "prepare_provider_keyed_workspace", lambda *a, **k: workspace)
    monkeypatch.setattr(saved, "_unsafe_keyed_workspace", lambda _: False)
    monkeypatch.setattr(compiler, "_SOURCE_SHA256", gate._SOURCE_SHA256)
    monkeypatch.setattr(compiler, "_LOCK_SHA256", gate._LOCK_SHA256)
    auth = records["core_plan"].evidence["sketchAuthorization"]
    auth["providerScopes"][1]["source"]["templateSha256"] = gate._SOURCE_SHA256
    auth["providerScopes"][1]["source"]["providerLock"]["sha256"] = gate._LOCK_SHA256
    auth["fingerprint"] = gate._digest({k: v for k, v in auth.items() if k != "fingerprint"})
    binary = tmp_path / "terraform"
    binary.write_bytes(b"offline Terraform 1.15.5")
    binary.chmod(0o700)
    monkeypatch.setattr(saved, "require_devtest_terraform_release", lambda **k: SimpleNamespace(
        path=binary, sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
    monkeypatch.setattr(saved, "decrypt_secret_value", lambda _: "offline-token")
    reservations = []

    def reserve(_, middles, groups):
        intent = compiler.compile_mixed_linode_initial_intent(**records)
        (root / ".barragan-topology.json").write_text(json.dumps(intent.topology))
        reservations.append(1)
        return intent.topology

    monkeypatch.setattr(saved, "reserve_provider_topology", reserve)
    intent = compiler.compile_mixed_linode_initial_intent(**records)
    material_root = root.parents[1] / ".plan-material/linode"
    private, output = material_root / "admin-private", material_root / "ssh-output"
    plan = copy.deepcopy(PLAN)
    for row in plan["resource_changes"]:
        address, after = row["address"], row["change"]["after"]
        if address.startswith("linode_instance."):
            after["authorized_keys"] = [PUBLIC_KEY]
        elif address == "linode_firewall.firewall":
            after["inbound"][3]["ipv4"] = ["8.8.8.8/32"]
        elif address == "local_file.ansible_inventory[0]":
            after["content"] = saved._inventory(intent, private)
        elif address == "local_file.ssh_stanza[0]":
            after["filename"] = str(output / "opaque-fixture-sketch")
    plan["variables"] = {key: {"value": value} for key, value in intent.nonsecret_varfile.items()}
    plan["variables"]["linode_api_token"] = {"value": "offline-token"}
    calls = []
    failures = {}

    def gated(argv, *, scratch_path, provider_keyed_v2, env, max_output_bytes,
              intent_callback, started_callback, heartbeat_callback, result_callback):
        phase = argv[1]
        calls.append(phase)
        assert provider_keyed_v2 and scratch_path == root
        assert "linode_api_token" not in json.dumps(env)
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
            (root / ".barragan-linode-initial-full.tfplan").write_bytes(b"saved-binary-plan")
        failure = failures.pop(phase, None)
        returncode = 1 if failure == "failed" else 0
        if phase == "show" and (root / ".barragan-linode-initial-full.tfplan").read_bytes() != b"saved-binary-plan":
            returncode = 1  # Real terraform show rejects a replaced/invalid saved binary.
        stdout = ('{"terraform_version":"1.15.5"}' if phase == "version"
                  else json.dumps(plan) if phase == "show" else "")
        truncated = failure == "truncated"
        result_callback(CommandAuditResult(started, returncode, len(stdout), 0, truncated, False))
        return CommandResult(started, returncode, stdout, "", truncated, False)

    args = dict(engagement_id="eng-opaque", core_job_id="job-core", lease_owner="owner",
                environment="devtest", state_root=state_root, template_root=tmp_path / "source",
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
                           key=key, plan=plan, records=records, reservations=reservations)


def test_gated_real_plan_receipt_and_restart_without_replan(case):
    receipt = saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert receipt["planSha256"] == hashlib.sha256(b"saved-binary-plan").hexdigest()
    assert case.calls == ["version", "init", "plan", "show"]
    assert saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args) == receipt
    assert case.calls == ["version", "init", "plan", "show", "version", "show"]
    assert len(case.reservations) == 1
    journal = saved._Journal(case.root / saved._JOURNAL)
    assert [row["kind"] for row in journal.rows].count("heartbeat") == 6
    assert not (case.root.parents[1] / ".plan-material/linode/credential.json").exists()


def test_failed_init_can_retry_after_terminal_gated_result(case):
    case.failures["init"] = "failed"
    with pytest.raises(saved.MixedLinodeSavedPlanError, match="init failed"):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert not (case.root / saved._PLAN).exists()
    saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls.count("plan") == 1


def test_interrupted_init_requires_quiescence_before_retry(case):
    case.failures["init"] = "interrupted"
    with pytest.raises(RuntimeError):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    case.args["process_quiescence"] = lambda *a: False
    with pytest.raises(saved.MixedLinodeSavedPlanError, match="quiescence"):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    case.args["process_quiescence"] = lambda *a: True
    saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert any(row["kind"] == "quiescent" for row in saved._Journal(case.root / saved._JOURNAL).rows)


@pytest.mark.parametrize("drift", ["key", "core", "credential", "binary", "source", "orphan"])
def test_restart_drift_or_orphan_stops_without_replan(case, drift):
    if drift != "orphan":
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    if drift == "key":
        case.key[0] = WRONG_PUBLIC_KEY
    elif drift == "core":
        case.records["core_job"].input["pendingSketchChainIds"] = []
    elif drift == "credential":
        credential = replace(case.records["credential_repository"].get("cred-linode"),
                             encrypted_secret="rotated")
        case.args["credential_repository"] = SimpleNamespace(
            get=lambda _: credential, get_default=lambda _: credential)
    elif drift == "binary":
        (case.root / saved._PLAN).write_bytes(b"wrong")
    elif drift == "source":
        (case.root / "middle.tf").write_text("drift")
    else:
        (case.root / saved._PLAN).write_bytes(b"orphan")
    before = case.calls.count("plan")
    with pytest.raises(ValueError):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls.count("plan") == before


def test_unreviewed_firewall_show_cannot_finish_receipt_or_replan(case):
    firewall = case.plan["resource_changes"][0]["change"]["after"]
    firewall["inbound"][3]["ipv4"] = ["0.0.0.0/0"]
    with pytest.raises(ValueError):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert not (case.root / saved._RECEIPT).exists()
    with pytest.raises(ValueError, match="firewall differs"):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls.count("plan") == 1


def test_restart_finishes_successful_plan_and_show_without_plan_replay(case, monkeypatch):
    original = saved._write_new

    def crash_before_receipt(path, data):
        if path == case.root / saved._RECEIPT:
            raise RuntimeError("injected crash before receipt")
        return original(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_new", crash_before_receipt)
        with pytest.raises(RuntimeError, match="injected crash"):
            saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls == ["version", "init", "plan", "show"]
    assert not (case.root / saved._RECEIPT).exists()
    assert not (case.root.parents[1] / ".plan-material/linode/credential.json").exists()
    receipt = saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls == ["version", "init", "plan", "show", "show"]
    assert receipt["planSha256"] == hashlib.sha256(b"saved-binary-plan").hexdigest()
    assert receipt["journalSha256"] == saved._Journal(case.root / saved._JOURNAL).rows[-1]["sha256"]
    assert saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args) == receipt
    assert case.calls.count("plan") == 1


@pytest.mark.parametrize("failure", [
    "plan", "show", "truncated-plan", "truncated-show", "interrupted-show",
    "token", "binary", "source", "input", "material", "lease", "state", "active",
])
def test_receipt_recovery_rejects_unproved_or_drifted_evidence(case, monkeypatch, failure):
    if failure in {"plan", "show"}:
        case.failures[failure] = "failed"
    elif failure.startswith("truncated-"):
        case.failures[failure.removeprefix("truncated-")] = "truncated"
    elif failure == "interrupted-show":
        case.failures["show"] = "interrupted"
    original = saved._write_new

    def crash_before_receipt(path, data):
        if path == case.root / saved._RECEIPT:
            raise RuntimeError("injected crash before receipt")
        return original(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_new", crash_before_receipt)
        with pytest.raises((RuntimeError, ValueError)):
            saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    if failure == "token":
        case.plan["variables"]["linode_api_token"]["value"] = "wrong-token"
    elif failure == "binary":
        (case.root / saved._PLAN).write_bytes(b"replaced-invalid-binary")
    elif failure == "source":
        (case.root / "middle.tf").write_text("drift")
    elif failure == "input":
        (case.root.parents[1] / ".plan-material/linode/inputs.json").write_text("{}")
    elif failure == "material":
        (case.root.parents[1] / ".plan-material/linode/admin-public").write_text("wrong")
    elif failure == "active":
        case.args["process_quiescence"] = lambda *_a: False
    elif failure == "lease":
        case.args["lease_lookup"] = lambda *_a: ("other", "provider_keyed_initial")
    elif failure == "state":
        (case.root / "terraform.tfstate").write_text("{}")
    before = len(case.calls)
    with pytest.raises(ValueError):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls.count("plan") == 1
    assert not (case.root / saved._RECEIPT).exists()
    if failure not in {"token", "binary"}:
        assert len(case.calls) == before


def test_receipt_recovery_rejects_wrong_plan_argv_even_with_rehashed_journal(case, monkeypatch):
    original = saved._write_new

    def crash_before_receipt(path, data):
        if path == case.root / saved._RECEIPT:
            raise RuntimeError("injected crash before receipt")
        return original(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_new", crash_before_receipt)
        with pytest.raises(RuntimeError):
            saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    journal_path = case.root / saved._JOURNAL
    rows = saved._Journal(journal_path).rows
    previous = "0" * 64
    for row in rows:
        if row["phase"] == "plan" and row["kind"] == "intent":
            row["data"]["argvSha256"] = "0" * 64
        row["prev"] = previous
        row["sha256"] = saved._digest({key: value for key, value in row.items()
                                      if key != "sha256"})
        previous = row["sha256"]
    journal_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    with pytest.raises(saved.MixedLinodeSavedPlanError, match="orphan"):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls == ["version", "init", "plan", "show"]
    assert not (case.root / saved._RECEIPT).exists()


def test_interrupted_plan_retains_secret_until_reconciliation(case):
    case.failures["plan"] = "interrupted"
    with pytest.raises(RuntimeError):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert (case.root.parents[1] / ".plan-material/linode/credential.json").is_file()
    with pytest.raises(saved.MixedLinodeSavedPlanError, match="outcome requires reconciliation"):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert case.calls.count("plan") == 1


def test_same_region_second_provider_requires_exact_predecessor_reservation(case):
    records = _records(linode_first=False, same_region=True)
    auth = records["core_plan"].evidence["sketchAuthorization"]
    auth["providerScopes"][0]["source"] = {"revision": "reviewed-do-revision"}
    auth["providerScopes"][1]["source"]["templateSha256"] = gate._SOURCE_SHA256
    auth["providerScopes"][1]["source"]["providerLock"]["sha256"] = gate._LOCK_SHA256
    auth["fingerprint"] = compiler._digest({k: v for k, v in auth.items() if k != "fingerprint"})
    intent = compiler.compile_mixed_linode_initial_intent(**records)
    assert intent.middle_key == "middle_02" and intent.edge_key == "us-west-02"
    workspace = saved.prepare_provider_keyed_workspace(
        "eng-opaque", "linode", "cred-linode", template_root=Path("unused"),
        source_revision="unused", root=Path("unused"), environment="devtest",
        deployment_target="barragan-testing")
    with pytest.raises(saved.MixedLinodeSavedPlanError, match="reservation is absent"):
        saved._require_predecessor(workspace, intent, records["chains"], records["core_plan"])
    fingerprint = hashlib.sha256(b"digitalocean\0cred-do").hexdigest()
    root = workspace.path.parents[1] / "digitalocean" / fingerprint
    root.mkdir(parents=True)
    marker = {"schema": "provider-keyed-v2", "engagement_id": "eng-opaque",
              "provider": "digitalocean", "provider_connection_id": "cred-do",
              "connection_fingerprint": fingerprint, "source_revision": "reviewed-do-revision"}
    (root / ".barragan-provider-keyed-state.json").write_text(json.dumps(marker))
    topology = {"schema": "provider-keyed-v2",
                "middles": {"middle_01": {"region": "nyc3", "ordinal": 1}},
                "edge_groups": {"group_01_us_west": {"region": "us-west",
                                                      "middle_node": "middle_01", "ordinals": [1]}},
                "regional_high_water": {"us-west": 1}}
    (root / ".barragan-topology.json").write_text(json.dumps(topology))
    saved._require_predecessor(workspace, intent, records["chains"], records["core_plan"])
    topology["edge_groups"]["group_01_us_west"]["ordinals"] = [2]
    (root / ".barragan-topology.json").write_text(json.dumps(topology))
    with pytest.raises(saved.MixedLinodeSavedPlanError, match="differs from reviewed order"):
        saved._require_predecessor(workspace, intent, records["chains"], records["core_plan"])


@pytest.mark.parametrize('value', [None, ['53']])
def test_initial_saved_plan_rejects_missing_or_public_udp_input(case, value):
    assert case.plan['variables']['allowed_udp_ports'] == {'value': []}
    if value is None:
        case.plan['variables'].pop('allowed_udp_ports')
    else:
        case.plan['variables']['allowed_udp_ports'] = {'value': value}
    with pytest.raises(saved.MixedLinodeSavedPlanError, match='input differs'):
        saved.prepare_or_reuse_mixed_linode_saved_plan(**case.args)
    assert not (case.root / saved._RECEIPT).exists()


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
