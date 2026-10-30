# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only OCI exact-ID witness tests; no cloud commands are executed."""

import json
from dataclasses import replace
import os
import subprocess

import pytest

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_oci_exact_absence import (
    OciAbsencePending, OciExactWitnessError, _default_runner, _oci_cli_environment,
    prove_oci_core_absence, prove_oci_core_visibility,
)
from test_provider_keyed_oci_core_state import _parse, _state, _ROLES, _COMPARTMENT


REGION = "us-ashburn-1"
EXE = "/usr/bin/true"
IDENTITY = {"id": "ocid1.instance.oc1..barraganapp", "compartmentId": _COMPARTMENT,
            "canonicalRegionName": REGION}


def _identity():
    return dict(IDENTITY)


def _fixture():
    inventory = _parse(_state(proxy_count=1, elk_enabled=False), proxy_count=1, elk_enabled=False)
    rows = {}
    for resource in inventory.resources:
        kind, role = _ROLES[resource.address]
        rows[resource.ocid] = {
            "id": resource.ocid, "compartment-id": _COMPARTMENT,
            "freeform-tags": {"barragan": "true", "barragan_engagement": "engagement-a",
                              "barragan_environment": "barragan-testing",
                              "barragan_provider": "oci", "barragan_role": role},
            "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
        }
    return inventory, rows


class FakeOci:
    def __init__(self, rows):
        self.rows = rows
        self.get_rows = dict(rows)
        self.calls = []
        self.failure = None

    def __call__(self, argv, env):
        self.calls.append(argv)
        assert env == _oci_cli_environment()
        assert not any(key.startswith("OCI_") for key in env)
        assert argv[:8] == (EXE, "--auth", "instance_principal", "--region", REGION,
                            "--output", "json", "--no-retry")
        service, name, action = argv[8:11]
        if self.failure == action:
            return subprocess.CompletedProcess(argv, 1, "", "ServiceError: " + json.dumps(
                {"status": 403, "code": "NotAuthorizedOrNotFound"}))
        if action == "list":
            assert argv[11:] == ("--compartment-id", _COMPARTMENT, "--all")
            items = [row for ocid, row in self.rows.items()
                     if ocid.split(".")[1] == _kind(service, name)]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": items}), "")
        assert action == "get"
        ocid = argv[-1]
        if ocid not in self.get_rows:
            return subprocess.CompletedProcess(argv, 1, "", "ServiceError: " + json.dumps(
                {"status": 404, "code": "NotAuthorizedOrNotFound"}))
        return subprocess.CompletedProcess(argv, 0, json.dumps({"data": self.get_rows[ocid]}), "")


def _kind(service, name):
    return {"dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
            "nat-gateway": "natgateway", "route-table": "routetable",
            "security-list": "securitylist"}.get(name, name)


def _positive(inventory, runner):
    return prove_oci_core_visibility(inventory, compartment_id=_COMPARTMENT,
                                     region=REGION, engagement_name="engagement-a",
                                     oci_executable=EXE, runner=runner,
                                     identity_reader=_identity)


def _absence(inventory, pre, runner, **kwargs):
    return prove_oci_core_absence(inventory, compartment_id=_COMPARTMENT,
                                  region=REGION, engagement_name="engagement-a",
                                  oci_executable=EXE, pre_witness=pre,
                                  runner=runner, pause=lambda _: None,
                                  identity_reader=_identity, **kwargs)


def test_positive_get_and_unfiltered_all_lists_bind_exact_inventory():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    proof = _positive(inventory, fake)
    assert proof.phase == "present"
    assert proof.inventory_sha256 == inventory.inventory_sha256
    assert proof.resource_ids_sha256 == _fingerprint({r.address: r.ocid for r in inventory.resources})
    assert len([a for a in fake.calls if a[10] == "list"]) == 7
    assert len([a for a in fake.calls if a[10] == "get"]) == len(inventory.resources)
    assert all("--auth" in a and "--all" in a for a in fake.calls if a[10] == "list")


@pytest.mark.parametrize("change", ["missing_list", "wrong_tag", "wrong_compartment", "get_404", "list_403"])
def test_pre_go_fails_closed_on_incomplete_or_wrong_visibility(change):
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    ocid = inventory.resources[0].ocid
    if change == "missing_list":
        del rows[ocid]
    elif change == "wrong_tag":
        rows[ocid]["freeform-tags"]["barragan_engagement"] = "other"
    elif change == "wrong_compartment":
        rows[ocid]["compartment-id"] = "ocid1.compartment.oc1..wrong"
    elif change == "get_404":
        del fake.get_rows[ocid]
    else:
        fake.failure = "list"
    with pytest.raises(OciExactWitnessError):
        _positive(inventory, fake)


def test_network_404_plus_complete_list_absence_and_compute_terminal():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    fake.rows = {ocid: {**row, "lifecycle-state": "TERMINATED"}
                 for ocid, row in rows.items() if ocid.split(".")[1] == "instance"}
    fake.get_rows = dict(fake.rows)
    proof = _absence(inventory, pre, fake)
    assert proof.phase == "absent"
    assert proof.evidence_sha256 != pre.evidence_sha256


def test_post_get_404_alone_is_never_absence():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    fake.get_rows = {}
    with pytest.raises(OciAbsencePending, match="scan bound"):
        _absence(inventory, pre, fake, max_scans=2)


def test_terminating_compute_remains_pending_with_bounded_retries():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    fake.rows = {ocid: {**row, "lifecycle-state": "TERMINATING"}
                 for ocid, row in rows.items() if ocid.split(".")[1] == "instance"}
    fake.get_rows = dict(fake.rows)
    with pytest.raises(OciAbsencePending, match="scan bound"):
        _absence(inventory, pre, fake, max_scans=2)


def test_post_rejects_wrong_pre_witness_and_auth_failure():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    with pytest.raises(OciExactWitnessError, match="pre-destroy"):
        prove_oci_core_absence(inventory, compartment_id=_COMPARTMENT,
                               region="us-phoenix-1", engagement_name="engagement-a",
                               oci_executable=EXE, pre_witness=pre, runner=fake,
                               identity_reader=_identity)
    fake.failure = "list"
    with pytest.raises(OciExactWitnessError):
        _absence(inventory, pre, fake)


def test_post_rejects_forged_pre_witness_resource_map_or_digest():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    for forged in (replace(pre, resource_ids_sha256="0" * 64),
                   replace(pre, evidence_sha256="not-a-digest")):
        with pytest.raises(OciExactWitnessError, match="pre-destroy"):
            _absence(inventory, forged, fake)


def test_fence_is_renewed_around_every_query_and_pause():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    renewals = []
    pre = prove_oci_core_visibility(inventory, compartment_id=_COMPARTMENT,
                                    region=REGION, engagement_name="engagement-a",
                                    oci_executable=EXE, runner=fake,
                                    fence=lambda: renewals.append(1),
                                    identity_reader=_identity)
    assert len(renewals) == 2 * len(fake.calls)
    fake.rows = {ocid: {**row, "lifecycle-state": "TERMINATED"}
                 for ocid, row in rows.items() if ocid.split(".")[1] == "instance"}
    fake.get_rows = dict(fake.rows)
    before = len(renewals)
    _absence(inventory, pre, fake, fence=lambda: renewals.append(1))
    assert len(renewals) > before + 2 * len(inventory.resources)


def test_cli_404_parser_fails_closed_on_non_service_error_or_malformed_json():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    fake.rows = {}

    def malformed(argv, env):
        result = fake(argv, env)
        if argv[10] == "get":
            return subprocess.CompletedProcess(argv, 1, "", "404 NotAuthorizedOrNotFound")
        return result

    with pytest.raises(OciExactWitnessError):
        _absence(inventory, pre, malformed)


def test_changed_or_missing_imds_identity_blocks_absence_even_with_empty_lists():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    fake.rows = {}
    fake.get_rows = {}
    for identity in ({**IDENTITY, "id": "ocid1.instance.oc1..other"},
                     {"id": IDENTITY["id"], "canonicalRegionName": REGION}):
        with pytest.raises(OciExactWitnessError, match="principal"):
            prove_oci_core_absence(inventory, compartment_id=_COMPARTMENT,
                                   region=REGION, engagement_name="engagement-a",
                                   oci_executable=EXE, pre_witness=pre, runner=fake,
                                   identity_reader=lambda: identity,
                                   pause=lambda _: None, max_scans=2)


def test_network_terminating_and_get_list_lag_poll_until_absent():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    network = next(r for r in inventory.resources if r.ocid.startswith("ocid1.vcn."))
    fake.rows = {network.ocid: {**rows[network.ocid], "lifecycle-state": "TERMINATING"}}
    fake.get_rows = {}
    polls = []

    def advance(_):
        polls.append(1)
        if len(polls) == 2:
            fake.rows = {}

    proof = prove_oci_core_absence(inventory, compartment_id=_COMPARTMENT,
                                   region=REGION, engagement_name="engagement-a",
                                   oci_executable=EXE, pre_witness=pre, runner=fake,
                                   identity_reader=_identity, pause=advance,
                                   max_scans=5, poll_seconds=0)
    assert proof.phase == "absent"
    assert len(polls) == 3


def test_get_list_disagreement_with_wrong_tags_is_hard_error():
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    pre = _positive(inventory, fake)
    network = next(r for r in inventory.resources if r.ocid.startswith("ocid1.vcn."))
    fake.rows = {network.ocid: {**rows[network.ocid],
                                "freeform-tags": {**rows[network.ocid]["freeform-tags"],
                                                  "barragan_role": "wrong"}}}
    fake.get_rows = {}
    with pytest.raises(OciExactWitnessError, match="ownership"):
        _absence(inventory, pre, fake, max_scans=2)


def test_cli_runner_scrubs_signer_metadata_proxy_and_credential_overrides(monkeypatch):
    import pwd
    from types import SimpleNamespace

    monkeypatch.setenv("OCI_CLI_AUTH", "api_key")
    monkeypatch.setenv("OCI_CLI_CONFIG_FILE", "/tmp/attacker")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid")
    monkeypatch.setenv("PYTHONPATH", "/tmp/attacker")
    monkeypatch.setenv("PYTHONUSERBASE", "/tmp/attacker")
    monkeypatch.setenv("HOME", "/tmp/attacker")
    monkeypatch.setenv("PATH", "/tmp/attacker")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir="/service/account"))
    observed = []

    def fake_subprocess(argv, **kwargs):
        observed.append(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, '{}', '')

    monkeypatch.setattr(subprocess, "run", fake_subprocess)
    _default_runner((EXE, "--version"), _oci_cli_environment())
    assert observed == [_oci_cli_environment()]
    assert observed[0]["PYTHONUSERBASE"] == "/service/account/.local"
    assert observed[0]["HOME"] == "/nonexistent"
    assert observed[0]["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert all(value not in observed[0] for value in
               ("OCI_METADATA_BASE_URL", "OCI_CLI_AUTH", "OCI_CLI_CONFIG_FILE",
                "HTTPS_PROXY", "PYTHONPATH"))


def test_metadata_endpoint_override_blocks_before_any_cli_call(monkeypatch):
    inventory, rows = _fixture()
    fake = FakeOci(rows)
    monkeypatch.setenv("OCI_METADATA_BASE_URL", "http://attacker.invalid/opc/v2")
    with pytest.raises(OciExactWitnessError):
        _positive(inventory, fake)
    assert fake.calls == []
