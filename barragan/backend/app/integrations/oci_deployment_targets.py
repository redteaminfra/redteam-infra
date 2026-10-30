# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID = os.environ.get("BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID", "").strip()
BARRAGAN_TESTING_COMPARTMENT_ID = os.environ.get("BARRAGAN_TESTING_COMPARTMENT_ID", "").strip()
DEFAULT_OCI_REGION = "us-sanjose-1"
DEFAULT_OCI_AUTH = "instance_principal"
OCI_DEPLOYMENT_TARGETS_FILE_ENV = "BARRAGAN_OCI_DEPLOYMENT_TARGETS_FILE"
EXPECTED_PRODUCTION_TARGET_COUNT = 4
DEPLOYMENT_TARGET_CONFIG_SCHEMA_VERSION = 1
_COMPARTMENT_OCID_RE = re.compile(r"^ocid1\.compartment\.oc1\.[a-z0-9.-]*\.[a-z0-9]+$")


class OciDeploymentTargetError(ValueError):
    pass


@dataclass(frozen=True)
class OciDeploymentTarget:
    name: str
    compartment_id: str
    classification: str
    parent_compartment_id: str = BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID
    region: str = DEFAULT_OCI_REGION
    auth: str = DEFAULT_OCI_AUTH

    def validate(self) -> None:
        target = _resolve_known_target(
            {"provider": "oci", "name": self.name, "compartmentId": self.compartment_id}
        )
        if target.region != self.region or target.parent_compartment_id != self.parent_compartment_id:
            raise OciDeploymentTargetError("deploymentTarget metadata does not match the approved target")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "compartmentId": self.compartment_id,
            "parentCompartmentId": self.parent_compartment_id,
            "region": self.region,
            "auth": self.auth,
            "classification": self.classification,
            "mutation": False,
        }


BARRAGAN_TESTING_TARGET = OciDeploymentTarget(
    name="barragan-testing",
    compartment_id=BARRAGAN_TESTING_COMPARTMENT_ID,
    classification="testing",
)

# Parent and non-deployment child compartments are never valid production
# entries. Deployment-specific production pairs live only in the root-owned
# external registry.
NO_TOUCH_COMPARTMENT_NAMES = frozenset(
    {
        "RedTeam",
        "RedTeam-Archive",
        "RedTeam-Monitoring",
        "RedTeam_Continuous",
        "RedTeam_Cracking",
    }
)
NO_TOUCH_COMPARTMENT_IDS = frozenset({BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID})


def _load_production_targets(
    configured_path: str | Path | None = None,
) -> tuple[OciDeploymentTarget, ...]:
    if configured_path is None:
        configured_path = os.environ.get(OCI_DEPLOYMENT_TARGETS_FILE_ENV, "").strip()
    if not configured_path:
        return ()
    try:
        body = json.loads(Path(configured_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OciDeploymentTargetError(f"unable to load OCI deployment targets: {exc}") from exc
    if not isinstance(body, Mapping):
        raise OciDeploymentTargetError("OCI deployment target file must contain an object")
    expected_keys = {
        "schemaVersion",
        "expectedProductionTargetCount",
        "productionTargets",
    }
    if set(body) != expected_keys:
        raise OciDeploymentTargetError(
            "OCI deployment target file must contain only schemaVersion, "
            "expectedProductionTargetCount, and productionTargets"
        )
    if body.get("schemaVersion") != DEPLOYMENT_TARGET_CONFIG_SCHEMA_VERSION:
        raise OciDeploymentTargetError(
            f"OCI deployment target file schemaVersion must be {DEPLOYMENT_TARGET_CONFIG_SCHEMA_VERSION}"
        )
    if body.get("expectedProductionTargetCount") != EXPECTED_PRODUCTION_TARGET_COUNT:
        raise OciDeploymentTargetError(
            f"OCI deployment target file expectedProductionTargetCount must be {EXPECTED_PRODUCTION_TARGET_COUNT}"
        )
    rows = body.get("productionTargets")
    if not isinstance(rows, list):
        raise OciDeploymentTargetError("OCI deployment target file must contain productionTargets")
    if len(rows) != EXPECTED_PRODUCTION_TARGET_COUNT:
        raise OciDeploymentTargetError(
            f"OCI deployment target file must contain exactly {EXPECTED_PRODUCTION_TARGET_COUNT} production targets"
        )
    targets = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise OciDeploymentTargetError("each production target must be an object")
        if set(row) != {"name", "compartmentId", "region"}:
            raise OciDeploymentTargetError(
                "each production target must contain only name, compartmentId, and region"
            )
        name = str(row.get("name") or "").strip()
        compartment_id = str(row.get("compartmentId") or "").strip()
        region = str(row.get("region") or "").strip()
        if not name or not _COMPARTMENT_OCID_RE.fullmatch(compartment_id):
            raise OciDeploymentTargetError(
                "each production target requires a name and valid compartment OCID"
            )
        if region != DEFAULT_OCI_REGION:
            raise OciDeploymentTargetError(
                f"each production target region must be {DEFAULT_OCI_REGION}"
            )
        no_touch_names = {candidate.casefold() for candidate in NO_TOUCH_COMPARTMENT_NAMES}
        if name.casefold() in (no_touch_names | {BARRAGAN_TESTING_TARGET.name.casefold()}) or compartment_id in (
            NO_TOUCH_COMPARTMENT_IDS | {BARRAGAN_TESTING_COMPARTMENT_ID}
        ):
            raise OciDeploymentTargetError(
                "production targets must not include testing, parent, or no-touch compartments"
            )
        targets.append(
            OciDeploymentTarget(
                name=name,
                compartment_id=compartment_id,
                classification="production",
                region=region,
            )
        )
    if len({target.name.casefold() for target in targets}) != len(targets) or len(
        {target.compartment_id for target in targets}
    ) != len(targets):
        raise OciDeploymentTargetError("production target names and compartment OCIDs must be unique")
    return tuple(targets)


PRODUCTION_OCI_TARGETS = _load_production_targets()

if os.environ.get("BARRAGAN_ENV", "").strip().lower() == "production" and not PRODUCTION_OCI_TARGETS:
    raise OciDeploymentTargetError(
        f"production requires {OCI_DEPLOYMENT_TARGETS_FILE_ENV} with exactly "
        f"{EXPECTED_PRODUCTION_TARGET_COUNT} approved production targets"
    )

OCI_DEPLOYMENT_TARGETS = (BARRAGAN_TESTING_TARGET, *PRODUCTION_OCI_TARGETS)


def allowed_oci_deployment_targets(environment: str) -> tuple[OciDeploymentTarget, ...]:
    if environment.strip().lower() == "production":
        if len(PRODUCTION_OCI_TARGETS) != EXPECTED_PRODUCTION_TARGET_COUNT:
            raise OciDeploymentTargetError(
                "production OCI deployment targets are not configured"
            )
        return (BARRAGAN_TESTING_TARGET, *PRODUCTION_OCI_TARGETS)
    return (BARRAGAN_TESTING_TARGET,)


def resolve_oci_deployment_target(
    value: Mapping[str, Any] | str | None,
    *,
    environment: str,
) -> OciDeploymentTarget:
    if value is None or value == "":
        return BARRAGAN_TESTING_TARGET

    if isinstance(value, str):
        name = value.strip()
        compartment_id = ""
    elif isinstance(value, Mapping):
        name = str(value.get("name") or "").strip()
        compartment_id = str(value.get("compartmentId") or "").strip()
    else:
        raise OciDeploymentTargetError("deploymentTarget must be an approved OCI target")

    targets = (BARRAGAN_TESTING_TARGET, *PRODUCTION_OCI_TARGETS)
    by_name = next((target for target in targets if target.name == name), None) if name else None
    by_id = next((target for target in targets if target.compartment_id == compartment_id), None) if compartment_id else None
    if by_name is not None and by_id is not None and by_name != by_id:
        raise OciDeploymentTargetError("deploymentTarget name and compartmentId do not match")
    target = by_name or by_id
    if target is None:
        raise OciDeploymentTargetError("deploymentTarget must be an approved OCI target")
    if target not in allowed_oci_deployment_targets(environment):
        raise OciDeploymentTargetError(
            f"deploymentTarget {target.name} is not available in the {environment or 'local'} runtime"
        )
    return target


def normalized_oci_deployment_target(value: Mapping[str, Any] | str | None) -> dict[str, str]:
    """Normalize only an allowlisted pair; runtime exposure is checked later."""

    if value is None or value == "":
        target = BARRAGAN_TESTING_TARGET
    else:
        target = _resolve_known_target(value)
    return {
        "provider": "oci",
        "name": target.name,
        "compartmentId": target.compartment_id,
        "region": target.region,
    }


def _resolve_known_target(value: Mapping[str, Any] | str) -> OciDeploymentTarget:
    if isinstance(value, str):
        name = value.strip()
        compartment_id = ""
    elif isinstance(value, Mapping):
        provider = str(value.get("provider") or "oci").strip().lower()
        if provider != "oci":
            raise OciDeploymentTargetError("deploymentTarget provider must be oci")
        name = str(value.get("name") or "").strip()
        compartment_id = str(value.get("compartmentId") or "").strip()
    else:
        raise OciDeploymentTargetError("deploymentTarget must be an approved OCI target")
    targets = (BARRAGAN_TESTING_TARGET, *PRODUCTION_OCI_TARGETS)
    by_name = next((target for target in targets if target.name == name), None) if name else None
    by_id = next((target for target in targets if target.compartment_id == compartment_id), None) if compartment_id else None
    if by_name is not None and by_id is not None and by_name != by_id:
        raise OciDeploymentTargetError("deploymentTarget name and compartmentId do not match")
    target = by_name or by_id
    if target is None:
        raise OciDeploymentTargetError("deploymentTarget must be an approved OCI target")
    return target
