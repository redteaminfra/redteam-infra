# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure decoding of the exact result map emitted by the provider plan job."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_plan_evidence import (
    ProviderKeyedPlanEvidenceError,
    decode_preflight_initial_plan_evidence,
)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_terraform_release import _REVIEWED_PATH, _REVIEWED_SHA256


@pytest.fixture
def reviewed(tmp_path):
    # Same result keys and path relationships emitted by
    # run_fresh_digitalocean_initial_plan_job after planned-state preflight.
    import hashlib

    connection = "credential-opaque"
    fingerprint = hashlib.sha256(f"digitalocean\0{connection}".encode()).hexdigest()
    root = tmp_path / "eng-opaque" / "provider-keyed-v2" / "digitalocean" / fingerprint
    material = root.parents[1] / ".plan-material" / "digitalocean"
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", connection, fingerprint,
        _SOURCE_REVISION, _SOURCE_SHA256,
    )
    fields = {
        "coreJobId": "job-core-opaque", "corePlanId": "plan-opaque",
        "revisionId": "revision-opaque", "providerConnectionId": connection,
        "selectorTag": "selector-opaque", "sourceRevision": _SOURCE_REVISION,
        "planPath": str(root / ".barragan-initial-full.tfplan"),
        "planSha256": "a" * 64, "sourceSha256": _SOURCE_SHA256,
        "markerSha256": "b" * 64, "topologySha256": "c" * 64,
        "lockfileSha256": "d" * 64,
        "inputSha256": [[str(material / "inputs.json"), "e" * 64]],
        "credentialSecretSha256": "f" * 64,
        "credentialUpdatedAt": "2026-10-02T00:00:00Z",
        "terraformBinaryPath": str(_REVIEWED_PATH),
        "terraformBinarySha256": _REVIEWED_SHA256,
        "terraformVersion": "1.15.5",
        "adminPublicKeySha256": "1" * 64,
        "adminPrivateKeyPath": str(material / "admin-private"),
        "adminPublicKeyPath": str(material / "admin-public"),
        "sshOutputDirectory": str(material / "ssh-output"),
    }
    identities = dict(
        expected_core_job_id="job-core-opaque", expected_core_plan_id="plan-opaque",
        expected_revision_id="revision-opaque", expected_connection_id=connection,
        expected_selector_tag="selector-opaque",
    )
    return fields, workspace, identities


def test_decodes_emitter_shape_without_touching_files(reviewed):
    data, workspace, identities = reviewed
    result = decode_preflight_initial_plan_evidence(data, workspace, **identities)
    evidence = result.apply_evidence
    assert evidence.plan_path == workspace.path / ".barragan-initial-full.tfplan"
    assert evidence.input_sha256 == ((data["inputSha256"][0][0], "e" * 64),)
    assert evidence.state_sha256 is None
    assert evidence.credential_record_id == identities["expected_connection_id"]
    assert evidence.terraform_binary_path == _REVIEWED_PATH
    assert result.admin_public_key_sha256 == data["adminPublicKeySha256"]
    assert not workspace.path.exists()  # decoder itself performs no filesystem work


@pytest.mark.parametrize("key,value", [
    ("coreJobId", "different"), ("corePlanId", "different"),
    ("revisionId", "different"), ("providerConnectionId", "different"),
    ("selectorTag", "different"), ("sourceRevision", "different"),
    ("sourceSha256", "0" * 64), ("terraformVersion", "1.16.0"),
    ("planSha256", "bad"), ("adminPublicKeySha256", "bad"),
    ("credentialUpdatedAt", None), ("terraformBinaryPath", "/tmp/terraform"),
    ("terraformBinarySha256", "0" * 64),
    ("planPath", "/tmp/other.tfplan"),
    ("adminPrivateKeyPath", "/tmp/private"),
    ("adminPublicKeyPath", "/tmp/public"),
    ("sshOutputDirectory", "/tmp/output"),
    ("inputSha256", []), ("inputSha256", [["/tmp/other", "e" * 64]]),
    ("inputSha256", [["/tmp/other", "e" * 64], ["/tmp/extra", "e" * 64]]),
    ("inputSha256", [("/tmp/other", "e" * 64)]),
])
def test_rejects_result_tampering(reviewed, key, value):
    data, workspace, identities = reviewed
    data = deepcopy(data)
    data[key] = value
    with pytest.raises(ProviderKeyedPlanEvidenceError):
        decode_preflight_initial_plan_evidence(data, workspace, **identities)


@pytest.mark.parametrize("change", [
    lambda data: data.pop("planSha256"),
    lambda data: data.update({"unexpected": "secret"}),
    lambda data: data.update({"adminPublicKeySha256": None}),
    lambda data: data.update({"inputSha256": ((data["inputSha256"][0][0], "e" * 64),)}),
])
def test_rejects_missing_extra_or_wrong_shape(reviewed, change):
    data, workspace, identities = reviewed
    data = deepcopy(data)
    change(data)
    with pytest.raises(ProviderKeyedPlanEvidenceError):
        decode_preflight_initial_plan_evidence(data, workspace, **identities)


@pytest.mark.parametrize("field", [
    "expected_core_job_id", "expected_core_plan_id", "expected_revision_id",
    "expected_connection_id", "expected_selector_tag",
])
def test_rejects_independent_identity_mismatch(reviewed, field):
    data, workspace, identities = reviewed
    identities[field] = "other"
    with pytest.raises(ProviderKeyedPlanEvidenceError):
        decode_preflight_initial_plan_evidence(data, workspace, **identities)


def test_rejects_workspace_path_or_source_mismatch(reviewed):
    data, workspace, identities = reviewed
    for changed in (
        replace(workspace, path=Path("/tmp/other")),
        replace(workspace, source_sha256="0" * 64),
        replace(workspace, provider="linode"),
        replace(workspace, terraform_data_dir=workspace.path / "other"),
    ):
        with pytest.raises(ProviderKeyedPlanEvidenceError):
            decode_preflight_initial_plan_evidence(data, changed, **identities)
