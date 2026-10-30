# Copyright (c) 2026, Oracle and/or its affiliates.
"""Second GO binds the first terminal proof and untouched second saved plan."""

from dataclasses import replace
from types import SimpleNamespace
from test_provider_keyed_mixed_append_pair_apply_binding import _admin_key_setup
import app.services.provider_keyed_mixed_append_pair_apply_binding as first_binding

import pytest

from app.domain import JobEvent
import app.services.provider_keyed_mixed_append_second_apply_binding as binding
from app.services.provider_keyed_mixed_append_second_apply_child import SecondApplySource
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_mixed_append_first_poststate import _case


def _parent(order):
    return StoredJobRun(
        "job-pair", "provider_keyed_mixed_append", "running",
        "engagement:eng-one", "engagement", "eng-one", "operator",
        {"corePlanId": "plan-core", "coreJobId": "job-core",
         "providerOrder": list(order), "reviewSha256": "a" * 64,
         "reviewedInputs": {order[1]: {"input": "reviewed"}},
         "digitaloceanFirewall": {}}, [], "now", "now", None,
        [JobEvent(1, "info", "approved", {})])


@pytest.mark.parametrize("order", [("digitalocean", "linode"),
                                   ("linode", "digitalocean")])
def test_stable_first_reobserves_exact_owned_state_without_claim_digest(monkeypatch, order):
    prior = _case(order[0])
    proof = binding.prove_first_mixed_append_poststate(
        intent=prior["intent"], predecessor_state=prior["predecessor_state"],
        reviewed_show_json=prior["reviewed_show_json"], snapshot=prior["snapshot"],
        command_result_proved=True, process_quiescent=True)
    data = {"stateSha256": proof.state_sha256, "lineage": proof.lineage,
            "serial": proof.serial, "resourceIds": [list(row) for row in proof.resource_ids],
            "newEdgeProviderId": proof.new_edge_provider_id,
            "newEdgePublicIp": proof.new_edge_public_ip,
            "attachedNodeIds": list(proof.attached_node_ids),
            "selectorResourcesCount": proof.selector_resources_count,
            "observationSha256": "old claim dependent digest"}
    child = SimpleNamespace(events=[
        *(JobEvent(index, "info", "journal", {}) for index in range(1, 9)),
        JobEvent(9, "info", "proved", data),
        JobEvent(10, "info", "terminal", {})])
    jobs = SimpleNamespace(get=lambda _: child)
    first = SimpleNamespace(intent=prior["intent"],
        predecessor_state=prior["predecessor_state"],
        reviewed_show_json=prior["reviewed_show_json"],
        receipt={}, workspace=object())
    monkeypatch.setattr(binding, "_journal", lambda *args: (
        SimpleNamespace(started_identity={"bootId": "boot", "pid": 1,
                                         "pgid": 1, "startTicks": 1}), "terminal"))
    monkeypatch.setattr(binding, "_process_quiescent", lambda *args: True)
    monkeypatch.setattr(binding, "job_event_digest", lambda _: "f" * 64)
    snapshot = [prior["snapshot"]]
    reader = lambda **kwargs: snapshot[0]
    assert binding._stable_first(_parent(order), jobs, first, reader,
        object(), None, None, lambda: "fence") == "f" * 64
    snapshot[0] = replace(snapshot[0], state_sha256="0" * 64)
    with pytest.raises(Exception):
        binding._stable_first(_parent(order), jobs, first, reader,
            object(), None, None, lambda: "fence")


@pytest.mark.parametrize("order", [("digitalocean", "linode"),
                                   ("linode", "digitalocean")])
def test_second_original_requires_exact_predecessor_and_full_inventory(monkeypatch, order):
    prior = _case(order[1])
    source = SimpleNamespace(historical=object(), workspace=object(),
        predecessor_state=prior["predecessor_state"],
        receipt={"predecessorStateSha256": binding._sha(prior["predecessor_state"])},
        intent=prior["intent"])
    expected = dict(prior["intent"].retained_digitalocean_ids
                    if order[1] == "digitalocean" else prior["intent"].retained_linode_ids)
    expected = {address: identifier for address, identifier in expected.items()
                if address.startswith(("digitalocean_droplet.", "linode_instance."))
                or address in {"digitalocean_firewall.firewall", "linode_firewall.firewall",
                               "digitalocean_ssh_key.key"}}
    result = SimpleNamespace(kind="full", state_sha256=source.receipt["predecessorStateSha256"],
                             resource_ids=tuple(expected.items()))
    monkeypatch.setattr(binding, "classify_sealed_provider_apply", lambda *args: result)
    snapshots = [replace(prior["snapshot"],
                         state_json=prior["predecessor_state"],
                         state_sha256=source.receipt["predecessorStateSha256"])]
    collector = lambda *args, **kwargs: snapshots[0]
    binding._second_original(_parent(order), source, object(), collector,
                             lambda: "fence", None, None)
    snapshots[0] = replace(snapshots[0], state_json=b"changed")
    with pytest.raises(ValueError, match="original state"):
        binding._second_original(_parent(order), source, object(), collector,
                                 lambda: "fence", None, None)
    snapshots[0] = replace(prior["snapshot"], state_json=prior["predecessor_state"])
    monkeypatch.setattr(binding, "classify_sealed_provider_apply", lambda *args:
                        replace(result, kind="uncertain") if hasattr(result, "__dataclass_fields__")
                        else SimpleNamespace(**{**vars(result), "kind": "uncertain"}))
    with pytest.raises(ValueError, match="original state"):
        binding._second_original(_parent(order), source, object(), collector,
                                 lambda: "fence", None, None)


@pytest.mark.parametrize("order", [("digitalocean", "linode"),
                                   ("linode", "digitalocean")])
def test_second_callbacks_reject_drift_without_another_show_under_lock(tmp_path, monkeypatch, order):
    parent = _parent(order)
    root = tmp_path / order[1]
    root.mkdir()
    lock = root / binding._name(order[1], "plan.lock")
    lock.write_bytes(b"")
    lock.chmod(0o600)
    binary = root / binding._name(order[1], "saved.tfplan")
    binary.write_bytes(b"binary")
    binary.chmod(0o600)
    state_path = root / "terraform.tfstate"
    state_path.write_bytes(b"original")
    workspace = SimpleNamespace(path=root, state_path=state_path,
        terraform_data_dir=root / ".terraform-data", provider=order[1],
        provider_connection_id="credential")
    release_path = root / "terraform"
    release_path.write_bytes(b"release")
    release = SimpleNamespace(path=release_path, sha256=binding._sha(b"release"))
    receipt = {"predecessorStateSha256": binding._sha(b"original"),
               "planSha256": binding._sha(b"binary"),
               "terraformBinarySha256": release.sha256,
               "credentialRecordId": "credential", "credentialUpdatedAt": "now",
               "credentialSecretSha256": binding._sha(b"encrypted")}
    source = binding._SecondSource(workspace, SimpleNamespace(
        retained_digitalocean_ids=(), retained_linode_ids=()), receipt,
        "r" * 64, b"original", b'{"reviewed":true}', b"binary", object())
    first = SimpleNamespace(predecessor_state=b"other-original")
    jobs = SimpleNamespace(get=lambda _: parent)
    active = [True]
    lookup = lambda _: ("plan-core", binding._OPERATION) if active[0] else None
    source_now = [source]
    first_now = ["f" * 64]
    monkeypatch.setattr(binding, "_load_approved_first_source", lambda *args: first)
    monkeypatch.setattr(binding, "_approved_second", lambda *args: source_now[0])
    monkeypatch.setattr(binding, "_stable_first", lambda *args: first_now[0])
    monkeypatch.setattr(binding, "_second_original", lambda *args: None)
    monkeypatch.setattr(binding, "require_mixed_linode_append_full_plan", lambda *args, **kwargs: None)
    monkeypatch.setattr(binding, "require_mixed_digitalocean_on_linode_append_full_plan",
                        lambda *args, **kwargs: None)
    monkeypatch.setattr(binding, "_firewall", lambda _: object())
    record = [SimpleNamespace(id="credential", provider=order[1], status="active",
                              updated_at="now", encrypted_secret="encrypted")]
    credentials = SimpleNamespace(get=lambda _: record[0])
    shows = []
    def show(*args, **kwargs):
        shows.append(1)
        return SimpleNamespace(returncode=0, stdout='{"reviewed":true}',
                               stdout_truncated=False, stderr_truncated=False)
    callbacks = binding.build_second_mixed_append_apply_bindings(
        parent.id, job_repository=jobs, lease_lookup=lookup,
        credential_repository=credentials, release_check=lambda **kwargs: release,
        show_runner=show, command_environment={},
        first_snapshot_collector=lambda **kwargs: None,
        second_snapshot_collector=lambda *args, **kwargs: None)
    material = root.parents[1] / ".plan-material" / order[1]
    material.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.input['reviewedInputs'][order[1]] = {
        'ssh_pub_key_path': str(material / 'admin-public'),
        'ssh_priv_key_path': str(material / 'admin-private')}
    _admin_key_setup(monkeypatch, {order[1]: workspace})
    renewals = []
    renew = lambda: renewals.append(1)
    digest = callbacks["first_terminal_proof"](parent, renew)
    assert callbacks["second_preflight"](parent, digest, renew) == "a" * 64
    with callbacks["source_session"](parent, order[1], renew) as apply_source:
        assert isinstance(apply_source, SecondApplySource)
        assert (material / 'admin-public').is_file() and (material / 'admin-private').is_file()
        assert callbacks["pre_go_check"](parent, apply_source, digest, renew) == "a" * 64
        assert shows == [1]
        source_now[0] = replace(source, binary=b"tampered")
        with pytest.raises(binding.MixedAppendSecondApplyBindingAttention):
            callbacks["pre_go_check"](parent, apply_source, digest, renew)
        source_now[0] = source
        state_path.write_bytes(b"changed")
        with pytest.raises(binding.MixedAppendSecondApplyBindingAttention):
            callbacks["pre_go_check"](parent, apply_source, digest, renew)
        state_path.write_bytes(b"original")
        record[0] = SimpleNamespace(**{**vars(record[0]), "updated_at": "rotated"})
        with pytest.raises(binding.MixedAppendSecondApplyBindingAttention):
            callbacks["pre_go_check"](parent, apply_source, digest, renew)
        record[0] = SimpleNamespace(**{**vars(record[0]), "updated_at": "now"})
        source_now[0] = replace(source, receipt={**receipt, "planSha256": "0" * 64})
        with pytest.raises(binding.MixedAppendSecondApplyBindingAttention):
            callbacks["pre_go_check"](parent, apply_source, digest, renew)
        source_now[0] = source
        first_now[0] = "e" * 64
        with pytest.raises(binding.MixedAppendSecondApplyBindingAttention):
            callbacks["pre_go_check"](parent, apply_source, digest, renew)
        first_now[0] = digest
        active[0] = False
        with pytest.raises(binding.MixedAppendSecondApplyBindingAttention):
            callbacks["pre_go_check"](parent, apply_source, digest, renew)
    assert shows == [1] and renewals

    assert not (material / 'admin-public').exists()
    assert not (material / 'admin-private').exists()
