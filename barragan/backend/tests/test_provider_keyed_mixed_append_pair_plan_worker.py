# Copyright (c) 2026, Oracle and/or its affiliates.
"""A paired append review reopens exact private artifacts without running Terraform."""

from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    MixedAppendPairPlanReviewAttention, reopen_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedInitialPublicationSource, MixedProviderState,
)
from app.services.provider_keyed_mixed_plan_journal import _Journal
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from test_provider_keyed_mixed_append_pair_plan import inputs


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def put(path, value, mode=0o600):
    path.write_bytes(value)
    path.chmod(mode)


def fixture(tmp_path, monkeypatch):
    do, linode, _ = inputs()
    raw = {"digitalocean": b'{"original":"do"}', "linode": b'{"original":"linode"}'}
    do = replace(do, digitalocean_state_sha256=sha(raw["digitalocean"]),
                 linode_state_sha256=sha(raw["linode"]))
    linode = replace(linode, digitalocean_state_sha256=sha(raw["digitalocean"]),
                     linode_state_sha256=sha(raw["linode"]))
    intents = {"digitalocean": do, "linode": linode}
    manifest = {"schema": "mixed-initial-host-binding-v1",
                "engagementId": do.engagement_id, "coreJobId": do.core_job_id}
    source = MixedInitialPublicationSource(
        do.engagement_id, do.core_job_id, "plan-1", "deployment-revision-1", "job-1",
        ("digitalocean", "linode"), (linode.chain_id, do.chain_id),
        "1" * 64, canonical(manifest), "2" * 64,
        (MixedProviderState("digitalocean", sha(raw["digitalocean"]), "do-lineage", 1,
                            do.retained_digitalocean_ids, "3" * 64),
         MixedProviderState("linode", sha(raw["linode"]), "linode-lineage", 1,
                            do.retained_linode_ids, "4" * 64)), ())
    terraform = tmp_path / "terraform"
    put(terraform, b"terraform pinned release", 0o755)
    release = SimpleNamespace(path=terraform, sha256=sha(terraform.read_bytes()),
                              version="1.15.5", platform="linux_amd64")
    records, workspaces, reviewed = {}, {}, {}
    for provider in ("digitalocean", "linode"):
        root = tmp_path / provider
        root.mkdir(mode=0o700)
        credential = SimpleNamespace(id=f"cred-{provider}", provider=provider,
                                     status="active", updated_at="2026-10-19T00:00:00Z",
                                     encrypted_secret=f"ciphertext-{provider}")
        records[credential.id] = credential
        workspace = ProviderKeyedWorkspace(
            root, root / "terraform.tfstate", root / ".terraform", "provider-keyed-v2",
            provider, credential.id, "fingerprint", "pinned-source-commit", "f" * 64)
        workspaces[provider] = workspace
        put(workspace.state_path, raw[provider], 0o644)
        reviewed[provider] = {"reviewed": provider}
        prefix = f".barragan-mixed-append-{provider}-"
        put(root / (prefix + "predecessor.tfstate"), raw[provider])
        put(root / (prefix + "plan.lock"), b"")
        plan = (f"binary-{provider}").encode()
        shown = json.dumps({"planned": provider}).encode()
        inputs_blob = json.dumps(reviewed[provider]).encode()
        for name, blob, mode in (
            (prefix + "saved.tfplan", plan, 0o600),
            (prefix + "show.json", shown, 0o600),
            (prefix + "inputs.json", inputs_blob, 0o600),
            (".barragan-provider-keyed-state.json", b"marker", 0o644),
            (".barragan-topology.json", b"topology", 0o644),
            (".terraform.lock.hcl", b"lockfile", 0o644),
        ):
            put(root / name, blob, mode)
        journal = _Journal(root / (prefix + "plan-journal.jsonl"))
        for phase in ("version", "init", "plan", "show"):
            invocation = f"{provider}-{phase}"
            journal.append(phase, "intent", {"invocationId": invocation,
                                              "argvSha256": "a" * 64})
            started = {"invocationId": invocation, "bootId": "boot", "pid": 101,
                       "pgid": 101, "startTicks": 1}
            journal.append(phase, "started", started)
            journal.append(phase, "result", {**started, "returnCode": 0,
                                             "stdoutBytes": 0, "stderrBytes": 0,
                                             "stdoutTruncated": False,
                                             "stderrTruncated": False})
        receipt = {
            "schema": "mixed-append-saved-plan-receipt-v1", "provider": provider,
            "engagementId": do.engagement_id, "coreJobId": do.core_job_id,
            "chainId": intents[provider].chain_id,
            "predecessorStateSha256": sha(raw[provider]),
            "newEdgeAddress": intents[provider].new_edge_address,
            "planSha256": sha(plan), "showJsonSha256": sha(shown),
            "sourceRevision": workspace.source_revision, "sourceSha256": workspace.source_sha256,
            "sourceMarkerSha256": sha(b"marker"), "topologySha256": sha(b"topology"),
            "lockfileSha256": sha(b"lockfile"), "inputSha256": sha(inputs_blob),
            "credentialRecordId": credential.id,
            "credentialSecretSha256": sha(credential.encrypted_secret.encode()),
            "credentialUpdatedAt": credential.updated_at,
            "terraformBinarySha256": release.sha256,
            "journalSha256": journal.rows[-1]["sha256"],
        }
        put(root / (prefix + "plan-receipt.json"), json.dumps(receipt).encode())
    gates = []
    monkeypatch.setattr(
        "app.services.provider_keyed_mixed_append_pair_plan_worker."
        "require_mixed_digitalocean_on_linode_append_full_plan",
        lambda *args, **kwargs: gates.append("digitalocean"))
    monkeypatch.setattr(
        "app.services.provider_keyed_mixed_append_pair_plan_worker."
        "require_mixed_linode_append_full_plan",
        lambda *args, **kwargs: gates.append("linode"))
    kwargs = dict(source=source, binding_manifest=manifest, digitalocean_intent=do,
                  linode_intent=linode, workspaces=workspaces, provider_states=raw,
                  reviewed_inputs=reviewed, digitalocean_firewall=object(),
                  reviewed_provider_order=("digitalocean", "linode"),
                  reviewed_chain_order=(do.chain_id, linode.chain_id),
                  lease_lookup=lambda _: ("worker-1", "provider_keyed_mixed_append"),
                  lease_owner="worker-1",
                  credential_repository=SimpleNamespace(get=lambda key: records.get(key)),
                  release_check=lambda **_: release)
    return kwargs, records, gates


def test_reopens_same_review_after_restart_without_command(tmp_path, monkeypatch):
    kwargs, _, gates = fixture(tmp_path, monkeypatch)
    first = reopen_mixed_append_pair_plan_review(**kwargs)
    assert first == reopen_mixed_append_pair_plan_review(**kwargs)
    assert first.provider_order == ("digitalocean", "linode")
    assert gates == ["digitalocean", "linode"] * 2


@pytest.mark.parametrize("drift", ["missing", "changed"])
def test_predecessor_snapshot_is_required_for_saved_review(tmp_path, monkeypatch, drift):
    kwargs, _, _ = fixture(tmp_path, monkeypatch)
    assert reopen_mixed_append_pair_plan_review(**kwargs)
    snapshot = (kwargs["workspaces"]["linode"].path
                / ".barragan-mixed-append-linode-predecessor.tfstate")
    if drift == "missing":
        snapshot.unlink()
    else:
        snapshot.write_bytes(b"different predecessor")
    with pytest.raises(MixedAppendPairPlanReviewAttention):
        reopen_mixed_append_pair_plan_review(**kwargs)


def test_reopens_after_quiescent_read_only_show_and_exact_resave(tmp_path, monkeypatch):
    kwargs, _, _ = fixture(tmp_path, monkeypatch)
    root = kwargs["workspaces"]["digitalocean"].path
    prefix = ".barragan-mixed-append-digitalocean-"
    path = root / (prefix + "plan-journal.jsonl")
    path.unlink()
    journal = _Journal(path)
    for phase in ("version", "init", "plan", "show", "show"):
        invocation = f"digitalocean-{phase}-{len(journal.rows)}"
        started = {"invocationId": invocation, "bootId": "boot", "pid": 101,
                   "pgid": 101, "startTicks": 1}
        journal.append(phase, "intent", {"invocationId": invocation,
                                          "argvSha256": "a" * 64})
        journal.append(phase, "started", started)
        if phase == "show" and len(journal._commands()) == 4:
            journal.append(phase, "quiescent", started)
        else:
            journal.append(phase, "result", {**started, "returnCode": 0,
                                               "stdoutBytes": 0, "stderrBytes": 0,
                                               "stdoutTruncated": False,
                                               "stderrTruncated": False})
    receipt_path = root / (prefix + "plan-receipt.json")
    receipt = json.loads(receipt_path.read_text())
    receipt["journalSha256"] = journal.rows[-1]["sha256"]
    put(receipt_path, json.dumps(receipt).encode())
    assert reopen_mixed_append_pair_plan_review(**kwargs).provider_order == (
        "digitalocean", "linode")


@pytest.mark.parametrize("change", ["binary", "show", "state", "receipt", "journal", "credential", "lease", "crossed", "inputs"])
def test_stale_or_crossed_evidence_never_seals(tmp_path, monkeypatch, change):
    kwargs, records, _ = fixture(tmp_path, monkeypatch)
    root = kwargs["workspaces"]["digitalocean"].path
    prefix = ".barragan-mixed-append-digitalocean-"
    if change in {"binary", "show", "state", "journal"}:
        path = root / {"binary": prefix + "saved.tfplan", "show": prefix + "show.json",
                       "state": "terraform.tfstate", "journal": prefix + "plan-journal.jsonl"}[change]
        path.write_bytes(path.read_bytes() + b"tamper")
    elif change in {"receipt", "crossed"}:
        path = root / (prefix + "plan-receipt.json")
        row = json.loads(path.read_text())
        row["coreJobId" if change == "receipt" else "newEdgeAddress"] = "crossed"
        path.write_text(json.dumps(row))
    elif change == "credential":
        records["cred-digitalocean"].encrypted_secret = "rotated"
    elif change == "inputs":
        kwargs["reviewed_inputs"]["digitalocean"] = {"reviewed": "wrong"}
    else:
        kwargs["lease_lookup"] = lambda _: ("other", "provider_keyed_mixed_append")
    with pytest.raises(MixedAppendPairPlanReviewAttention):
        reopen_mixed_append_pair_plan_review(**kwargs)


@pytest.mark.parametrize('drift', [False, True])
def test_reopen_binds_cloud_publication_ids_to_complete_compiler_ids(tmp_path, monkeypatch, drift):
    kwargs, _, gates = fixture(tmp_path, monkeypatch)
    source = kwargs['source']
    states = tuple(replace(row, resource_ids=tuple((a, v) for a, v in row.resource_ids
        if not a.startswith(('local_file.', 'random_password.')))) for row in source.provider_states)
    if drift:
        states = (replace(states[0], resource_ids=states[0].resource_ids[1:]), states[1])
    kwargs['source'] = replace(source, provider_states=states)
    if drift:
        with pytest.raises(MixedAppendPairPlanReviewAttention):
            reopen_mixed_append_pair_plan_review(**kwargs)
        assert not gates
    else:
        assert reopen_mixed_append_pair_plan_review(**kwargs)
        assert gates == ['digitalocean', 'linode']


@pytest.mark.parametrize('order', [('digitalocean', 'linode'), ('linode', 'digitalocean')])
def test_saved_review_binds_each_append_to_foreign_middle_chain(tmp_path, monkeypatch, order):
    kwargs, _, _ = fixture(tmp_path, monkeypatch)
    source = kwargs['source']
    native_chains = dict(zip(source.ordered_providers, source.chain_ids, strict=True))
    kwargs['source'] = replace(source, ordered_providers=order,
        chain_ids=tuple(native_chains[p] for p in order))
    assert kwargs['digitalocean_intent'].chain_id == native_chains['linode']
    assert kwargs['linode_intent'].chain_id == native_chains['digitalocean']
    assert reopen_mixed_append_pair_plan_review(**kwargs).provider_order == ('digitalocean', 'linode')
    kwargs['source'] = replace(kwargs['source'], chain_ids=kwargs['source'].chain_ids[::-1])
    with pytest.raises(MixedAppendPairPlanReviewAttention):
        reopen_mixed_append_pair_plan_review(**kwargs)
