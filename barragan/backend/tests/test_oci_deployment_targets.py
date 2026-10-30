# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.integrations import oci_deployment_targets as targets


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent


def _production_rows(count: int = 4) -> list[dict[str, str]]:
    return [
        {
            "name": f"production-{letter}",
            "compartmentId": f"ocid1.compartment.oc1..approvedtarget{letter}",
            "region": targets.DEFAULT_OCI_REGION,
        }
        for letter in "abcd"[:count]
    ]


def _config(rows: list[dict[str, str]] | None = None) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "expectedProductionTargetCount": 4,
        "productionTargets": rows if rows is not None else _production_rows(),
    }


def _write_config(path: Path, body: dict[str, object]) -> Path:
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


@pytest.fixture()
def configured_targets(tmp_path, monkeypatch):
    configured = targets._load_production_targets(
        _write_config(tmp_path / "targets.json", _config())
    )
    monkeypatch.setattr(targets, "PRODUCTION_OCI_TARGETS", configured)
    monkeypatch.setattr(
        targets,
        "OCI_DEPLOYMENT_TARGETS",
        (targets.BARRAGAN_TESTING_TARGET, *configured),
    )
    return configured


def test_devtest_and_local_are_restricted_to_testing():
    assert targets.allowed_oci_deployment_targets("devtest") == (
        targets.BARRAGAN_TESTING_TARGET,
    )
    assert targets.allowed_oci_deployment_targets("local") == (
        targets.BARRAGAN_TESTING_TARGET,
    )


def test_production_exposes_testing_compatibility_and_exactly_four_configured_targets(
    configured_targets,
):
    allowed = targets.allowed_oci_deployment_targets("production")

    assert allowed == (targets.BARRAGAN_TESTING_TARGET, *configured_targets)
    assert [target.name for target in allowed] == [
        "barragan-testing",
        "production-a",
        "production-b",
        "production-c",
        "production-d",
    ]


def test_production_fails_closed_when_external_registry_is_missing(monkeypatch):
    monkeypatch.setattr(targets, "PRODUCTION_OCI_TARGETS", ())

    with pytest.raises(targets.OciDeploymentTargetError, match="not configured"):
        targets.allowed_oci_deployment_targets("production")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda body: body.update(schemaVersion=2), "schemaVersion"),
        (
            lambda body: body.update(expectedProductionTargetCount=3),
            "expectedProductionTargetCount",
        ),
        (
            lambda body: body.update(productionTargets=_production_rows(3)),
            "exactly 4",
        ),
        (
            lambda body: body["productionTargets"].append(
                {
                    "name": "production-e",
                    "compartmentId": "ocid1.compartment.oc1..approvedtargete",
                    "region": targets.DEFAULT_OCI_REGION,
                }
            ),
            "exactly 4",
        ),
        (
            lambda body: body["productionTargets"][0].update(region="us-example-1"),
            "region must be",
        ),
        (
            lambda body: body["productionTargets"][0].update(auth="api_key"),
            "contain only name",
        ),
        (
            lambda body: body.update(unreviewedTargets=[]),
            "contain only schemaVersion",
        ),
        (
            lambda body: body["productionTargets"][0].update(
                compartmentId=targets.BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID
            ),
            "no-touch",
        ),
        (
            lambda body: body["productionTargets"][0].update(
                compartmentId=targets.BARRAGAN_TESTING_COMPARTMENT_ID
            ),
            "no-touch",
        ),
        (
            lambda body: body["productionTargets"][0].update(
                name=targets.BARRAGAN_TESTING_TARGET.name
            ),
            "no-touch",
        ),
        (
            lambda body: body["productionTargets"][1].update(name="production-a"),
            "must be unique",
        ),
        (
            lambda body: body["productionTargets"][1].update(
                compartmentId="ocid1.compartment.oc1..approvedtargeta"
            ),
            "must be unique",
        ),
        (
            lambda body: body["productionTargets"][0].update(
                compartmentId="REPLACE_WITH_APPROVED_COMPARTMENT_OCID_A"
            ),
            "valid compartment OCID",
        ),
    ],
)
def test_external_registry_rejects_bad_or_broadened_configuration(
    tmp_path,
    mutate,
    message,
):
    body = _config()
    mutate(body)
    path = _write_config(tmp_path / "invalid.json", body)

    with pytest.raises(targets.OciDeploymentTargetError, match=message):
        targets._load_production_targets(path)


def test_configured_invalid_registry_fails_during_module_import(tmp_path):
    path = _write_config(
        tmp_path / "invalid.json",
        _config(_production_rows(3)),
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(BACKEND_ROOT)
    env[targets.OCI_DEPLOYMENT_TARGETS_FILE_ENV] = str(path)

    result = subprocess.run(
        [sys.executable, "-c", "import app.integrations.oci_deployment_targets"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "exactly 4 production targets" in result.stderr


def test_production_runtime_fails_during_module_import_without_registry():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(BACKEND_ROOT)
    env["BARRAGAN_ENV"] = "production"
    env.pop(targets.OCI_DEPLOYMENT_TARGETS_FILE_ENV, None)

    result = subprocess.run(
        [sys.executable, "-c", "import app.integrations.oci_deployment_targets"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert targets.OCI_DEPLOYMENT_TARGETS_FILE_ENV in result.stderr


def test_resolve_requires_matching_allowlisted_name_and_ocid(configured_targets):
    target = configured_targets[0]
    assert (
        targets.resolve_oci_deployment_target(
            target.to_dict(),
            environment="production",
        )
        == target
    )
    with pytest.raises(targets.OciDeploymentTargetError, match="do not match"):
        targets.resolve_oci_deployment_target(
            {
                "name": target.name,
                "compartmentId": configured_targets[1].compartment_id,
            },
            environment="production",
        )


def test_production_target_is_rejected_in_devtest(configured_targets):
    with pytest.raises(targets.OciDeploymentTargetError, match="not available"):
        targets.resolve_oci_deployment_target(
            configured_targets[0].to_dict(),
            environment="devtest",
        )


def test_arbitrary_or_parent_compartment_is_rejected(configured_targets):
    with pytest.raises(targets.OciDeploymentTargetError, match="approved OCI target"):
        targets.resolve_oci_deployment_target(
            {"name": "unconfigured-parent", "compartmentId": "ocid1.compartment.oc1..parent"},
            environment="production",
        )


def test_normalized_target_persists_exact_allowlisted_pair_and_defaults_to_testing(
    configured_targets,
):
    assert targets.normalized_oci_deployment_target(None) == {
        "provider": "oci",
        "name": "barragan-testing",
        "compartmentId": targets.BARRAGAN_TESTING_TARGET.compartment_id,
        "region": "us-sanjose-1",
    }
    target = configured_targets[-1]
    assert (
        targets.normalized_oci_deployment_target({"name": target.name})[
            "compartmentId"
        ]
        == target.compartment_id
    )


def test_public_iam_plan_encodes_one_atomic_18_statement_policy_shape():
    plan = (REPO_ROOT / "docs" / "wi0268-oci-iam-policy-plan.md").read_text(
        encoding="utf-8"
    )
    statement_lines = [
        line
        for line in plan.splitlines()
        if line.startswith("Allow dynamic-group <BARRAGAN_DYNAMIC_GROUP>")
    ]
    resource_types = [line.split(" to manage ", 1)[1].split(" in tenancy", 1)[0] for line in statement_lines]

    assert resource_types == [
        "instances",
        "volumes",
        "volume-attachments",
        "vcns",
        "subnets",
        "route-tables",
        "internet-gateways",
        "nat-gateways",
        "dhcp-options",
        "security-lists",
        "network-security-groups",
        "vnics",
        "vnic-attachments",
        "private-ips",
        "public-ips",
    ]
    assert all(
        "in tenancy where any {<TARGET_COMPARTMENT_ID_PREDICATES>}" in line
        for line in statement_lines
    )
    assert "exactly 18 statements" in plan
    assert "existing three discovery/tag statements, retained byte-for-byte" in plan
    assert "Do not create four additional policies" in plan


def test_only_production_systemd_service_loads_external_target_registry():
    systemd = REPO_ROOT / "ops" / "systemd" / "system"
    production = (systemd / "barragan-fastapi.service").read_text(encoding="utf-8")
    devtest = (systemd / "barragan-api-devtest.service").read_text(encoding="utf-8")
    setting = (
        "BARRAGAN_OCI_DEPLOYMENT_TARGETS_FILE="
        "/var/lib/barragan/config/oci-deployment-targets.json"
    )

    assert setting in production
    assert setting not in devtest
    assert not (REPO_ROOT / "docs" / "redteam-compartments-prod.txt").exists()
    example = json.loads(
        (REPO_ROOT / "docs" / "oci-deployment-targets.example.json").read_text(
            encoding="utf-8"
        )
    )
    assert all(
        row["compartmentId"].startswith("REPLACE_WITH_APPROVED_COMPARTMENT_OCID_")
        for row in example["productionTargets"]
    )


def test_public_iam_plan_documents_etag_rollback_and_parent_tag_exception():
    plan = (REPO_ROOT / "docs" / "wi0268-oci-iam-policy-plan.md").read_text(
        encoding="utf-8"
    )

    assert "saved pre-change ETag" in plan
    assert "blind retry" in plan
    assert "ETag conflict" in plan
    assert "post-update ETag" in plan
    assert "restore the exact saved original statement array" in plan
    assert "parent-scoped `use tag-namespaces` support statement" in plan
