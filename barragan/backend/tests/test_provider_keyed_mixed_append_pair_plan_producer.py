# Copyright (c) 2026, Oracle and/or its affiliates.
"""Paired append plan production is one-shot and remains non-dispatchable."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_append_pair_plan_producer import (
    MixedAppendPairPlanProductionAttention, _matching_admin_key,
    produce_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedInitialPublicationSource, MixedProviderState,
)
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
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer
    import app.services.provider_keyed_mixed_append_pair_plan_worker as reader
    do, linode, _ = inputs()
    raw = {"digitalocean": b'{"original":"do"}', "linode": b'{"original":"linode"}'}
    do = replace(do, digitalocean_state_sha256=sha(raw["digitalocean"]),
                 linode_state_sha256=sha(raw["linode"]))
    linode = replace(linode, digitalocean_state_sha256=sha(raw["digitalocean"]),
                     linode_state_sha256=sha(raw["linode"]))
    manifest = {"schema": "mixed-initial-host-binding-v1",
                "engagementId": do.engagement_id, "coreJobId": do.core_job_id}
    source = MixedInitialPublicationSource(
        do.engagement_id, do.core_job_id, "plan-1", "revision-1", "job-1",
        ("digitalocean", "linode"), (linode.chain_id, do.chain_id),
        "1" * 64, canonical(manifest), "2" * 64,
        (MixedProviderState("digitalocean", sha(raw["digitalocean"]), "do-lineage", 1,
                            do.retained_digitalocean_ids, "3" * 64),
         MixedProviderState("linode", sha(raw["linode"]), "linode-lineage", 1,
                            do.retained_linode_ids, "4" * 64)), ())
    schema = tmp_path / source.engagement_id / "provider-keyed-v2"
    schema.mkdir(mode=0o700, parents=True)
    material_root = schema / ".plan-material"
    material_root.mkdir(mode=0o700)
    records, workspaces, topologies = {}, {}, {}
    for provider, intent in (("digitalocean", do), ("linode", linode)):
        root = schema / provider / "fingerprint"
        root.mkdir(mode=0o700, parents=True)
        material = material_root / provider
        material.mkdir(mode=0o700)
        vars = {"ssh_pub_key_path": str(material / "admin-public"),
                "ssh_priv_key_path": str(material / "admin-private"),
                "ssh_config_path": str(material / "ssh-output")}
        if provider == "digitalocean":
            do = replace(do, nonsecret_varfile=vars)
        else:
            linode = replace(linode, nonsecret_varfile=vars)
        workspace = ProviderKeyedWorkspace(
            root, root / "terraform.tfstate", root / ".terraform-data",
            "provider-keyed-v2", provider, f"cred-{provider}", "fingerprint",
            "pinned-source", "f" * 64)
        workspaces[provider] = workspace
        put(workspace.state_path, raw[provider], 0o644)
        put(root / ".barragan-provider-keyed-state.json",
            json.dumps({"engagement_id": source.engagement_id}).encode(), 0o644)
        put(root / ".terraform.lock.hcl", b"lockfile", 0o644)
        topology = {"provider": provider, "reserved": True}
        topologies[provider] = topology
        put(root / ".barragan-topology.json", json.dumps(topology).encode(), 0o644)
        records[workspace.provider_connection_id] = SimpleNamespace(
            id=workspace.provider_connection_id, provider=provider,
            status="active", updated_at="2026-10-19T00:00:00Z",
            encrypted_secret=f"encrypted-{provider}")
    terraform = tmp_path / "terraform"
    put(terraform, b"terraform pinned release", 0o755)
    release = SimpleNamespace(path=terraform, sha256=sha(terraform.read_bytes()),
                              version="1.15.5", platform="linux_amd64")
    proposal = SimpleNamespace(reservations=tuple(
        SimpleNamespace(provider=provider, proposed_topology=topologies[provider])
        for provider in ("digitalocean", "linode")))
    def resources(state):
        retained = do.retained_digitalocean_ids if state["original"] == "do" else do.retained_linode_ids
        result = {address: {"id": identifier} for address, identifier in retained}
        for address, value in result.items():
            if address == "digitalocean_ssh_key.key":
                value["public_key"] = "ssh-ed25519 example"
            if address.startswith("linode_instance."):
                value["authorized_keys"] = ["ssh-ed25519 example"]
        return result
    monkeypatch.setattr(producer, "_state_resources", resources)
    monkeypatch.setattr(producer, "compile_mixed_digitalocean_on_linode_append_intent",
                        lambda **_: do)
    monkeypatch.setattr(producer, "compile_mixed_linode_on_digitalocean_append_intent",
                        lambda **_: linode)
    monkeypatch.setattr(producer, "propose_mixed_external_append_reservations",
                        lambda **_: proposal)
    monkeypatch.setattr(producer, "reserve_mixed_external_provider_topologies",
                        lambda *_: topologies)
    monkeypatch.setattr(producer, "read_provider_topology",
                        lambda workspace: topologies[workspace.provider])
    monkeypatch.setattr(producer, "_verify_audited_workspace", lambda *_: None)
    monkeypatch.setattr(producer, "require_audited_linode_workspace", lambda *_: None)
    monkeypatch.setattr(producer, "decrypt_secret_value", lambda *_: "test-token")
    monkeypatch.setattr(producer, "_matching_admin_key", lambda *args: True)
    monkeypatch.setattr("app.services.provider_keyed_mixed_append_plan_gate."
                        "require_mixed_digitalocean_on_linode_append_full_plan",
                        lambda *_, **__: None)
    monkeypatch.setattr("app.services.provider_keyed_mixed_append_linode_full_plan."
                        "require_mixed_linode_append_full_plan", lambda *_, **__: None)
    monkeypatch.setattr(reader, "require_mixed_digitalocean_on_linode_append_full_plan",
                        lambda *_, **__: None)
    monkeypatch.setattr(reader, "require_mixed_linode_append_full_plan", lambda *_, **__: None)
    calls = []

    def runner(argv, *, scratch_path, intent_callback, started_callback,
               heartbeat_callback, result_callback, **_):
        phase = argv[1]
        calls.append((scratch_path.parent.name, phase))
        intent = CommandIntent(f"{scratch_path.name}-{phase}", str(scratch_path),
                               sha(json.dumps(argv, separators=(",", ":")).encode()))
        started = StartedCommand(intent, ProcessIdentity("boot", 101 + len(calls),
                                                          101 + len(calls), 1))
        intent_callback(intent)
        started_callback(started)
        if phase == "plan":
            Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("-out="))).write_bytes(
                f"saved-{scratch_path.parent.name}".encode())
        output = (json.dumps({"terraform_version": "1.15.5"}) if phase == "version"
                  else json.dumps({"plan": scratch_path.parent.name}) if phase == "show" else "")
        result_callback(CommandAuditResult(started, 0, len(output.encode()), 0, False, False))
        return CommandResult(started, 0, output, "", False, False)

    kwargs = dict(source=source, binding_manifest=manifest, provider_states=raw,
                  workspaces=workspaces, original_topologies={p: {} for p in workspaces},
                  original_regional_high_water={}, retained_varfiles={p: {} for p in workspaces},
                  additions={p: {} for p in workspaces}, digitalocean_firewall=object(),
                  reviewed_provider_order=("digitalocean", "linode"),
                  reviewed_chain_order=(do.chain_id, linode.chain_id),
                  lease_lookup=lambda _: ("worker-1", "provider_keyed_mixed_append"),
                  lease_owner="worker-1", admin_public_key="ssh-ed25519 example",
                  admin_private_key="private-key", credential_repository=SimpleNamespace(
                      get=lambda key: records.get(key)), release_check=lambda **_: release,
                  command_environment={}, gated_command_runner=runner,
                  process_quiescence=lambda *_: True)
    return kwargs, calls, runner


def test_produces_both_saved_plans_then_reopens_without_command(tmp_path, monkeypatch):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    first = produce_mixed_append_pair_plan_review(**kwargs)
    assert first.provider_order == ("digitalocean", "linode")
    assert [phase for _, phase in calls] == ["version", "init", "plan", "show"] * 2
    assert first == produce_mixed_append_pair_plan_review(**kwargs)
    assert len(calls) == 8
    for provider, workspace in kwargs["workspaces"].items():
        snapshot = workspace.path / f".barragan-mixed-append-{provider}-predecessor.tfstate"
        assert snapshot.read_bytes() == kwargs["provider_states"][provider]
        assert snapshot.stat().st_mode & 0o077 == 0
        assert not (workspace.path / f".barragan-mixed-append-{provider}-secret.json").exists()


@pytest.mark.parametrize("drift", ["missing", "changed"])
def test_completed_plan_never_recreates_or_accepts_stale_predecessor_snapshot(
    tmp_path, monkeypatch, drift,
):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    produce_mixed_append_pair_plan_review(**kwargs)
    snapshot = (kwargs["workspaces"]["digitalocean"].path
                / ".barragan-mixed-append-digitalocean-predecessor.tfstate")
    if drift == "missing":
        snapshot.unlink()
    else:
        snapshot.write_bytes(b"changed")
    prior = list(calls)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == prior
    if drift == "missing":
        assert not snapshot.exists()


def test_interrupted_plan_is_not_replayed(tmp_path, monkeypatch):
    kwargs, calls, runner = fixture(tmp_path, monkeypatch)

    def fail_plan(argv, **options):
        if argv[1] != "plan":
            return runner(argv, **options)
        intent = CommandIntent("uncertain-plan", str(options["scratch_path"]),
                               sha(json.dumps(argv, separators=(",", ":")).encode()))
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 1))
        options["intent_callback"](intent)
        options["started_callback"](started)
        calls.append((options["scratch_path"].parent.name, "plan-uncertain"))
        raise RuntimeError("observation lost")

    kwargs["gated_command_runner"] = fail_plan
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    for provider, workspace in kwargs["workspaces"].items():
        assert (workspace.path / f".barragan-mixed-append-{provider}-predecessor.tfstate").read_bytes() == kwargs["provider_states"][provider]
    prior = list(calls)
    kwargs["gated_command_runner"] = runner
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == prior


def test_changed_predecessor_fails_before_any_command(tmp_path, monkeypatch):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    kwargs["provider_states"] = {**kwargs["provider_states"], "linode": b"changed"}
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == []


def test_private_administration_key_must_match_published_public_key():
    private = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption())
    public = private.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    assert _matching_admin_key(public.decode() + " operator", private_bytes.decode())
    assert not _matching_admin_key("ssh-ed25519 another", private_bytes.decode())


def test_second_provider_interruption_keeps_first_receipt_and_replays_nothing(
        tmp_path, monkeypatch):
    kwargs, calls, runner = fixture(tmp_path, monkeypatch)

    def fail_second(argv, **options):
        if (options["scratch_path"].parent.name != "linode"
                or argv[1] != "plan"):
            return runner(argv, **options)
        intent = CommandIntent("second-plan", str(options["scratch_path"]),
                               sha(json.dumps(argv, separators=(",", ":")).encode()))
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 1))
        options["intent_callback"](intent)
        options["started_callback"](started)
        calls.append((options["scratch_path"].parent.name, "plan-uncertain"))
        raise RuntimeError("observation lost")

    kwargs["gated_command_runner"] = fail_second
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    first = kwargs["workspaces"]["digitalocean"].path
    assert (first / ".barragan-mixed-append-digitalocean-plan-receipt.json").is_file()
    prior = list(calls)
    kwargs["gated_command_runner"] = runner
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == prior


def test_complete_show_artifact_without_receipt_recovers_without_plan_replay(
        tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer

    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    write = producer._write_new
    failed = False

    def stop_before_receipt(path, contents):
        nonlocal failed
        if path.name.endswith("plan-receipt.json") and not failed:
            failed = True
            raise RuntimeError("worker stopped after show artifact fsync")
        return write(path, contents)

    monkeypatch.setattr(producer, "_write_new", stop_before_receipt)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert [phase for _, phase in calls] == ["version", "init", "plan", "show"]
    first = kwargs["workspaces"]["digitalocean"].path
    assert (first / ".barragan-mixed-append-digitalocean-show.json").is_file()
    assert (first / ".barragan-mixed-append-digitalocean-secret.json").is_file()
    monkeypatch.setattr(producer, "_write_new", write)
    review = produce_mixed_append_pair_plan_review(**kwargs)
    assert review.provider_order == ("digitalocean", "linode")
    assert [phase for _, phase in calls] == ["version", "init", "plan", "show"] * 2
    assert not (first / ".barragan-mixed-append-digitalocean-secret.json").exists()


def test_missing_show_artifact_after_complete_command_stays_fail_closed(
        tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer

    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    write = producer._write_new

    def stop_before_receipt(path, contents):
        if path.name.endswith("plan-receipt.json"):
            raise RuntimeError("worker stopped after show artifact fsync")
        return write(path, contents)

    monkeypatch.setattr(producer, "_write_new", stop_before_receipt)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    first = kwargs["workspaces"]["digitalocean"].path
    (first / ".barragan-mixed-append-digitalocean-show.json").unlink()
    monkeypatch.setattr(producer, "_write_new", write)
    prior = list(calls)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == prior


def test_reverse_review_order_uses_stable_lock_order(tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer

    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    kwargs["reviewed_provider_order"] = ("linode", "digitalocean")
    kwargs["reviewed_chain_order"] = kwargs["reviewed_chain_order"][::-1]
    acquire = producer._regular_lock
    locks = []

    def record_lock(path, stack, **options):
        locks.append(path.parent.parent.name)
        return acquire(path, stack, **options)

    monkeypatch.setattr(producer, "_regular_lock", record_lock)
    review = produce_mixed_append_pair_plan_review(**kwargs)
    assert review.provider_order == ("linode", "digitalocean")
    assert locks == ["digitalocean", "linode"]
    assert [provider for provider, phase in calls if phase == "plan"] == [
        "linode", "digitalocean"]
    assert [phase for _, phase in calls] == ["version", "init", "plan", "show"] * 2


def test_receipt_reuse_cleans_matching_material_after_interrupted_cleanup(
        tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer

    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    cleanup = producer._cleanup_matching_material
    stopped = False

    def stop_cleanup(paths):
        nonlocal stopped
        if not stopped:
            stopped = True
            raise RuntimeError("worker stopped after receipt fsync")
        return cleanup(paths)

    monkeypatch.setattr(producer, "_cleanup_matching_material", stop_cleanup)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    first = kwargs["workspaces"]["digitalocean"].path
    secret = first / ".barragan-mixed-append-digitalocean-secret.json"
    assert (first / ".barragan-mixed-append-digitalocean-plan-receipt.json").is_file()
    assert secret.is_file()
    monkeypatch.setattr(producer, "_cleanup_matching_material", cleanup)
    review = produce_mixed_append_pair_plan_review(**kwargs)
    assert review.provider_order == ("digitalocean", "linode")
    assert [phase for _, phase in calls] == ["version", "init", "plan", "show"] * 2
    assert not secret.exists()


def test_receipt_reuse_rejects_mismatched_staged_material_without_deletion(
        tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer

    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    cleanup = producer._cleanup_matching_material
    monkeypatch.setattr(producer, "_cleanup_matching_material",
                        lambda _: (_ for _ in ()).throw(RuntimeError("stopped")))
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    first = kwargs["workspaces"]["digitalocean"].path
    secret = first / ".barragan-mixed-append-digitalocean-secret.json"
    put(secret, b'{"do_pat":"wrong-token"}')
    monkeypatch.setattr(producer, "_cleanup_matching_material", cleanup)
    prior = list(calls)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == prior
    assert secret.read_bytes() == b'{"do_pat":"wrong-token"}'


def test_matching_prejournal_material_resumes_without_duplicate_write(
        tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer

    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    run = producer._run_gated
    monkeypatch.setattr(producer, "_run_gated",
                        lambda *_, **__: (_ for _ in ()).throw(RuntimeError("before intent")))
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    first = kwargs["workspaces"]["digitalocean"].path
    assert (first / ".barragan-mixed-append-digitalocean-secret.json").is_file()
    assert not (first / ".barragan-mixed-append-digitalocean-plan-journal.jsonl").exists()
    monkeypatch.setattr(producer, "_run_gated", run)
    review = produce_mixed_append_pair_plan_review(**kwargs)
    assert review.provider_order == ("digitalocean", "linode")
    assert [phase for _, phase in calls] == ["version", "init", "plan", "show"] * 2


def test_mismatched_prejournal_material_fails_before_command(tmp_path, monkeypatch):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    first = kwargs["workspaces"]["digitalocean"].path
    put(first / ".barragan-mixed-append-digitalocean-secret.json", b"other-secret")
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert calls == []


@pytest.mark.parametrize('drift', ['bytes', 'cloud_id', 'missing_cloud_resource'])
def test_complete_id_adapter_binds_real_cloud_receipts_to_hashed_full_state(drift):
    from test_provider_keyed_mixed_append_linode_intent import _case
    from app.services.provider_keyed_mixed_append_pair_plan_producer import _complete_retained_resource_ids
    from app.services.provider_keyed_initial_teardown import _state_resources
    args = _case()
    states = {p: SimpleNamespace(state_sha256=args['provider_state_sha256'][p],
        resource_ids=tuple((a, identifier) for a, identifier in ids.items()
                           if not a.startswith(('local_file.', 'random_password.'))))
        for p, ids in args['provider_resource_ids'].items()}
    complete = _complete_retained_resource_ids(args['provider_states'], states)
    for p in complete:
        assert complete[p] == {a: str(v['id']) for a, v in _state_resources(json.loads(args['provider_states'][p])).items()}
    if drift == 'bytes':
        args['provider_states']['linode'] += b' '
    elif drift == 'cloud_id':
        states['linode'].resource_ids = ((*states['linode'].resource_ids[:-1],
            (states['linode'].resource_ids[-1][0], 'foreign')))
    else:
        states['linode'].resource_ids += (('linode_instance.foreign', 'foreign'),)
    with pytest.raises(ValueError):
        _complete_retained_resource_ids(args['provider_states'], states)


def test_known_pathless_precommand_input_upgrades_then_produces_exact_review(tmp_path, monkeypatch):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    provider = kwargs['reviewed_provider_order'][0]
    workspace = kwargs['workspaces'][provider]
    path = workspace.path / f'.barragan-mixed-append-{provider}-inputs.json'
    material = workspace.path.parents[1] / '.plan-material' / provider
    variables = {'ssh_pub_key_path': str(material / 'admin-public'),
                 'ssh_priv_key_path': str(material / 'admin-private'),
                 'ssh_config_path': str(material / 'ssh-output')}
    keys = {'ssh_pub_key_path', 'ssh_priv_key_path', 'ssh_config_path'}
    old = (json.dumps({k: v for k, v in variables.items() if k not in keys}, sort_keys=True) + '\n').encode()
    put(path, old)
    review = produce_mixed_append_pair_plan_review(**kwargs)
    assert len(calls) == 8 and review.provider_order == kwargs['reviewed_provider_order']
    assert path.read_bytes() == (json.dumps(variables, sort_keys=True) + '\n').encode()
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(path.parent.glob('.barragan-input-upgrade-*'))


@pytest.mark.parametrize('drift', ['input', 'journal', 'receipt', 'plan', 'show', 'secret', 'symlink'])
def test_pathless_input_upgrade_rejects_drift_or_any_provider_command_artifact(tmp_path, monkeypatch, drift):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    provider = kwargs['reviewed_provider_order'][0]
    workspace = kwargs['workspaces'][provider]
    path = workspace.path / f'.barragan-mixed-append-{provider}-inputs.json'
    material = workspace.path.parents[1] / '.plan-material' / provider
    variables = {'ssh_pub_key_path': str(material / 'admin-public'),
                 'ssh_priv_key_path': str(material / 'admin-private'),
                 'ssh_config_path': str(material / 'ssh-output')}
    keys = {'ssh_pub_key_path', 'ssh_priv_key_path', 'ssh_config_path'}
    old = (json.dumps({k: v for k, v in variables.items() if k not in keys}, sort_keys=True) + '\n').encode()
    put(path, old + (b' ' if drift == 'input' else b''))
    other = next(p for p in kwargs['workspaces'] if p != provider)
    suffixes = {'journal': 'plan-journal.jsonl', 'receipt': 'plan-receipt.json',
                'plan': 'saved.tfplan', 'show': 'show.json', 'secret': 'secret.json'}
    if drift == 'symlink':
        (kwargs['workspaces'][other].path / f'.barragan-mixed-append-{other}-secret.json').symlink_to(tmp_path / 'absent')
    elif drift in suffixes:
        put(kwargs['workspaces'][other].path / f'.barragan-mixed-append-{other}-{suffixes[drift]}', b'unsafe')
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert not calls
    assert path.read_bytes() == old + (b' ' if drift == 'input' else b'')


def test_completed_only_reopens_saved_pair_without_any_command(tmp_path, monkeypatch):
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    expected = produce_mixed_append_pair_plan_review(**kwargs)
    calls.clear()
    kwargs.update(completed_plans_only=True,
        gated_command_runner=lambda *a, **k: pytest.fail('completed-only command replay'))
    assert produce_mixed_append_pair_plan_review(**kwargs) == expected
    assert not calls


@pytest.mark.parametrize('drift', ['missing', 'incomplete', 'late_missing'])
def test_completed_only_never_falls_back_to_commands(tmp_path, monkeypatch, drift):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    produce_mixed_append_pair_plan_review(**kwargs)
    calls.clear()
    first = kwargs['reviewed_provider_order'][0]
    journal = kwargs['workspaces'][first].path / f'.barragan-mixed-append-{first}-plan-journal.jsonl'
    if drift == 'missing': journal.unlink()
    elif drift == 'incomplete': journal.write_bytes(b'')
    else:
        def changed(*args):
            journal.unlink()
            return True
        monkeypatch.setattr(producer, '_matching_admin_key', changed)
        # Force the absent-journal branch rather than receipt recognition.
        (journal.parent / f'.barragan-mixed-append-{first}-plan-receipt.json').unlink()
    kwargs.update(completed_plans_only=True,
        gated_command_runner=lambda *a, **k: pytest.fail('completed-only command replay'))
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert not calls


def test_completed_only_reconstructs_last_receipt_without_any_command(tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_pair_plan_producer as producer
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    last = kwargs['reviewed_provider_order'][-1]
    write = producer._write_new
    def stop_before_last_receipt(path, contents):
        if path.name == f'.barragan-mixed-append-{last}-plan-receipt.json':
            raise RuntimeError('stopped after both complete show commands')
        return write(path, contents)
    monkeypatch.setattr(producer, '_write_new', stop_before_last_receipt)
    with pytest.raises(MixedAppendPairPlanProductionAttention):
        produce_mixed_append_pair_plan_review(**kwargs)
    assert len(calls) == 8
    workspace = kwargs['workspaces'][last].path
    receipt = workspace / f'.barragan-mixed-append-{last}-plan-receipt.json'
    secret = workspace / f'.barragan-mixed-append-{last}-secret.json'
    assert not receipt.exists() and secret.is_file()
    monkeypatch.setattr(producer, '_write_new', write)
    calls.clear()
    kwargs.update(completed_plans_only=True,
        gated_command_runner=lambda *a, **k: pytest.fail('completed-only command replay'))
    review = produce_mixed_append_pair_plan_review(**kwargs)
    assert review.provider_order == kwargs['reviewed_provider_order']
    assert receipt.is_file() and not secret.exists()
    assert not calls
