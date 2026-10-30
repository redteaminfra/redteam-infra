# Copyright (c) 2026, Oracle and/or its affiliates.
"""The private paired append pre-GO fence re-shows both saved binaries."""

from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_mixed_append_pair_apply import (
    MixedAppendPairPreGoAttention,
    verify_mixed_append_pair_binaries_before_first_go,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    reopen_mixed_append_pair_plan_review,
)
from test_provider_keyed_mixed_append_pair_plan_worker import fixture


def _prepared(tmp_path, monkeypatch, order=("digitalocean", "linode")):
    kwargs, records, gates = fixture(tmp_path, monkeypatch)
    kwargs["reviewed_provider_order"] = order
    kwargs["reviewed_chain_order"] = tuple(
        kwargs[f"{provider}_intent"].chain_id for provider in order)
    expected = reopen_mixed_append_pair_plan_review(**kwargs).review_sha256
    calls = []

    def show(command, **options):
        provider = options["scratch_path"].name
        calls.append((provider, command))
        assert command == [str(kwargs["release_check"](environment="devtest").path),
                           "show", "-json",
                           str(options["scratch_path"] /
                               f".barragan-mixed-append-{provider}-saved.tfplan")]
        options["intent_callback"](SimpleNamespace(
            scratch_path=str(options["scratch_path"]),
            argv_sha256=hashlib.sha256(
                json.dumps(command, separators=(",", ":")).encode()
            ).hexdigest()))
        options["started_callback"](object())
        for _ in range(3):
            options["heartbeat_callback"](object())
        options["result_callback"](object())
        return SimpleNamespace(returncode=0, stdout=(options["scratch_path"] /
            f".barragan-mixed-append-{provider}-show.json").read_text(),
            stdout_truncated=False, stderr_truncated=False)

    call = dict(kwargs, expected_review_sha256=expected,
                command_environment={}, show_runner=show)
    return call, calls, records, gates


@pytest.mark.parametrize("order", [
    ("digitalocean", "linode"), ("linode", "digitalocean")])
def test_exact_binary_reshow_reopens_after_restart(tmp_path, monkeypatch, order):
    call, calls, _, _ = _prepared(tmp_path, monkeypatch, order)
    first = verify_mixed_append_pair_binaries_before_first_go(**call)
    assert first == verify_mixed_append_pair_binaries_before_first_go(**call)
    assert [provider for provider, _ in calls] == list(order) * 2


@pytest.mark.parametrize("change", ["review", "binary", "show", "state", "credential", "lease"])
def test_stale_persisted_authority_never_runs_show(tmp_path, monkeypatch, change):
    call, calls, records, _ = _prepared(tmp_path, monkeypatch)
    workspace = call["workspaces"]["digitalocean"]
    prefix = ".barragan-mixed-append-digitalocean-"
    if change == "review":
        call["expected_review_sha256"] = "0" * 64
    elif change in {"binary", "show", "state"}:
        path = {"binary": workspace.path / (prefix + "saved.tfplan"),
                "show": workspace.path / (prefix + "show.json"),
                "state": workspace.state_path}[change]
        path.write_bytes(path.read_bytes() + b"drift")
    elif change == "credential":
        records["cred-digitalocean"].encrypted_secret = "rotated"
    else:
        call["lease_lookup"] = lambda _: ("other", "provider_keyed_mixed_append")
    with pytest.raises(MixedAppendPairPreGoAttention):
        verify_mixed_append_pair_binaries_before_first_go(**call)
    assert calls == []


def test_binary_show_mismatch_stops_before_second_provider(tmp_path, monkeypatch):
    call, calls, _, _ = _prepared(tmp_path, monkeypatch)
    real_show = call["show_runner"]

    def changed_show(command, **options):
        result = real_show(command, **options)
        return SimpleNamespace(**{**vars(result), "stdout": "{}"})

    call["show_runner"] = changed_show
    with pytest.raises(MixedAppendPairPreGoAttention):
        verify_mixed_append_pair_binaries_before_first_go(**call)
    assert [provider for provider, _ in calls] == ["digitalocean"]


def test_retained_provider_id_change_stops_before_show(tmp_path, monkeypatch):
    call, calls, _, _ = _prepared(tmp_path, monkeypatch)
    intent = call["digitalocean_intent"]
    changed = list(intent.retained_digitalocean_ids)
    address, _ = changed[0]
    changed[0] = (address, "different-provider-id")
    call["digitalocean_intent"] = replace(
        intent, retained_digitalocean_ids=tuple(changed))
    with pytest.raises(MixedAppendPairPreGoAttention):
        verify_mixed_append_pair_binaries_before_first_go(**call)
    assert calls == []


def test_lease_lost_during_first_show_stops_before_second(tmp_path, monkeypatch):
    call, calls, _, _ = _prepared(tmp_path, monkeypatch)
    current = {"owner": "worker-1"}
    call["lease_lookup"] = lambda _: (current["owner"], "provider_keyed_mixed_append")
    real_show = call["show_runner"]

    def lost_lease(command, **options):
        current["owner"] = "other"
        return real_show(command, **options)

    call["show_runner"] = lost_lease
    with pytest.raises(MixedAppendPairPreGoAttention):
        verify_mixed_append_pair_binaries_before_first_go(**call)
    assert [provider for provider, _ in calls] == ["digitalocean"]


def test_unreviewed_terraform_environment_stops_before_show(tmp_path, monkeypatch):
    call, calls, _, _ = _prepared(tmp_path, monkeypatch)
    call["command_environment"] = {"TF_VAR_unreviewed": "value"}
    with pytest.raises(MixedAppendPairPreGoAttention):
        verify_mixed_append_pair_binaries_before_first_go(**call)
    assert calls == []


def test_show_heartbeats_only_renew_claim_not_full_pair_audit(tmp_path, monkeypatch):
    call, _, _, gates = _prepared(tmp_path, monkeypatch)
    heartbeats = []
    call["claim_heartbeat"] = lambda: heartbeats.append(len(gates))
    verify_mixed_append_pair_binaries_before_first_go(**call)
    assert len(heartbeats) == 6
    assert heartbeats[:3] == [heartbeats[0]] * 3
    assert heartbeats[3:] == [heartbeats[3]] * 3
    assert heartbeats[3] > heartbeats[0]


def test_state_drift_during_show_vetoes_result(tmp_path, monkeypatch):
    call, calls, _, _ = _prepared(tmp_path, monkeypatch)
    real_show = call["show_runner"]

    def drift_show(command, **options):
        original_result = options["result_callback"]

        def drift_before_result(result):
            state = call["workspaces"]["digitalocean"].state_path
            state.write_bytes(state.read_bytes() + b"drift")
            original_result(result)

        options["result_callback"] = drift_before_result
        return real_show(command, **options)

    call["show_runner"] = drift_show
    with pytest.raises(MixedAppendPairPreGoAttention):
        verify_mixed_append_pair_binaries_before_first_go(**call)
    assert [provider for provider, _ in calls] == ["digitalocean"]
