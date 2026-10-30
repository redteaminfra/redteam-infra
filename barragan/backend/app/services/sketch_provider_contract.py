# Copyright (c) 2026, Oracle and/or its affiliates.
"""Acceptance boundary for reviewed sanitized sketch Terraform projections.

Raw ``terraform show`` JSON is not accepted. The capture sanitizer/projector
must produce the candidate before this contract is evaluated. Provider
execution integration is deliberately deferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping

from app.services.terraform_plan_gate import (
    FirewallIngressDelta,
    TerraformPlanGateError,
    require_provider_firewall_ingress_update,
)


CONTRACT_ROOT = Path(__file__).resolve().parents[1] / "provider_contracts" / "sketch"
MANIFEST_PATH = CONTRACT_ROOT / "manifest.json"
EXPECTED_MANIFEST_SHA256 = "3170b009221dbf3c8f87dff07a9b459f4cd7e8f6335ea76a6b6c87c57602de5f"
FAILURE_CODES = frozenset({
    "provider_lock_missing", "provider_lock_changed", "provider_selection_unsupported",
    "terraform_runtime_unsupported", "template_source_mismatch",
    "plan_format_unsupported", "resource_schema_unsupported", "plan_semantics_rejected",
})
_FIREWALL_ADDRESS = {
    "digitalocean": "digitalocean_firewall.firewall",
    "linode": "linode_firewall.firewall",
}
_REDACTED = re.compile(r"<redacted-[0-9a-f]{16}>")
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})"
)


class SketchProviderContractError(RuntimeError):
    def __init__(self, code: str):
        if code not in FAILURE_CODES:
            raise ValueError("unknown sketch provider contract failure code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AcceptedSketchProviderContract:
    provider: str
    scenario: str
    terraform_version: str
    platform: str
    template_revision: str
    plan_format_version: str
    firewall_schema_version: int
    reviewed_projection_sha256: str
    approved_changes: tuple[tuple[str, str], ...]


def require_sketch_provider_contract(
    provider: str,
    *,
    lock_path: Path,
    terraform_version: Mapping[str, Any],
    template_revision: str,
    sanitized_contract_projection: Mapping[str, Any],
    expected_delta: FirewallIngressDelta,
) -> AcceptedSketchProviderContract:
    """Accept an exact reviewed sanitized projection or raise a stable code."""
    if type(provider) is not str:
        raise SketchProviderContractError("provider_selection_unsupported")
    manifest = _load_manifest()
    provider_contract = manifest["providers"].get(provider)
    if not isinstance(provider_contract, dict) or provider not in _FIREWALL_ADDRESS:
        raise SketchProviderContractError("provider_selection_unsupported")
    _require_lock(lock_path, provider_contract)
    _require_runtime(terraform_version, provider_contract, manifest)
    if type(template_revision) is not str or template_revision != manifest["templateRevision"]:
        raise SketchProviderContractError("template_source_mismatch")
    scenario = _reviewed_scenario(expected_delta)
    reviewed, reviewed_sha256 = _load_reviewed_projection(manifest, scenario, provider)
    candidate = sanitized_contract_projection
    if not isinstance(candidate, Mapping):
        raise SketchProviderContractError("plan_semantics_rejected")
    if candidate.get("format_version") != manifest["plan"]["formatVersion"]:
        raise SketchProviderContractError("plan_format_unsupported")
    if candidate.get("terraform_version") != manifest["terraform"]["version"]:
        raise SketchProviderContractError("terraform_runtime_unsupported")
    _require_firewall_schema(candidate, provider, manifest)
    _require_projection_matches(reviewed, candidate)
    try:
        changes = require_provider_firewall_ingress_update(
            json.dumps(candidate, sort_keys=True, separators=(",", ":")),
            provider=provider,
            expected_delta=expected_delta,
        )
    except (TerraformPlanGateError, TypeError, ValueError) as exc:
        raise SketchProviderContractError("plan_semantics_rejected") from exc
    return AcceptedSketchProviderContract(
        provider, scenario, manifest["terraform"]["version"], manifest["terraform"]["platform"],
        manifest["templateRevision"], manifest["plan"]["formatVersion"],
        manifest["plan"]["firewallResourceSchemaVersion"], reviewed_sha256,
        tuple((change.address, change.action) for change in changes),
    )


def reviewed_contract_manifest() -> Mapping[str, Any]:
    return json.loads(json.dumps(_load_manifest()))


def _load_manifest() -> dict[str, Any]:
    try:
        raw = MANIFEST_PATH.read_bytes()
    except OSError as exc:
        raise SketchProviderContractError("provider_selection_unsupported") from exc
    if hashlib.sha256(raw).hexdigest() != EXPECTED_MANIFEST_SHA256:
        raise SketchProviderContractError("provider_selection_unsupported")
    document = _strict_json(raw, "provider_selection_unsupported")
    if not isinstance(document, dict):
        raise SketchProviderContractError("provider_selection_unsupported")
    return document


def _load_reviewed_projection(
    manifest: Mapping[str, Any], scenario: str, provider: str,
) -> tuple[dict[str, Any], str]:
    try:
        record = manifest["reviewedFixtures"][scenario]["providers"][provider]
        relative, expected_sha256 = record["projectionFile"], record["sha256"]
    except (KeyError, TypeError) as exc:
        raise SketchProviderContractError("provider_selection_unsupported") from exc
    if type(relative) is not str or type(expected_sha256) is not str \
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise SketchProviderContractError("provider_selection_unsupported")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
        raise SketchProviderContractError("provider_selection_unsupported")
    path = CONTRACT_ROOT.joinpath(*pure.parts)
    try:
        metadata, raw = path.lstat(), path.read_bytes()
    except OSError as exc:
        raise SketchProviderContractError("plan_semantics_rejected") from exc
    if not stat.S_ISREG(metadata.st_mode) or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SketchProviderContractError("plan_semantics_rejected")
    document = _strict_json(raw, "plan_semantics_rejected")
    if not isinstance(document, dict):
        raise SketchProviderContractError("plan_semantics_rejected")
    return document, expected_sha256


def _strict_json(raw: bytes, failure_code: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object,
                          parse_constant=_reject_json_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SketchProviderContractError(failure_code) from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON")


def _require_lock(path: Path, contract: Mapping[str, Any]) -> None:
    if not isinstance(path, Path):
        raise SketchProviderContractError("provider_lock_missing")
    try:
        metadata, raw = path.lstat(), path.read_bytes()
    except OSError as exc:
        raise SketchProviderContractError("provider_lock_missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or hashlib.sha256(raw).hexdigest() != contract["lockSha256"]:
        raise SketchProviderContractError("provider_lock_changed")


def _require_runtime(
    version: Mapping[str, Any], provider: Mapping[str, Any], manifest: Mapping[str, Any],
) -> None:
    allowed = {"terraform_version", "platform", "provider_selections", "terraform_outdated"}
    if not isinstance(version, Mapping) \
            or not {"terraform_version", "platform", "provider_selections"} <= set(version) \
            or not set(version) <= allowed \
            or version.get("terraform_version") != manifest["terraform"]["version"] \
            or version.get("platform") != manifest["terraform"]["platform"] \
            or ("terraform_outdated" in version and type(version["terraform_outdated"]) is not bool):
        raise SketchProviderContractError("terraform_runtime_unsupported")
    selections = version.get("provider_selections")
    if not isinstance(selections, Mapping) or dict(selections) != provider["selections"]:
        raise SketchProviderContractError("provider_selection_unsupported")


def _reviewed_scenario(delta: FirewallIngressDelta) -> str:
    if not isinstance(delta, FirewallIngressDelta) or delta.added:
        raise SketchProviderContractError("plan_semantics_rejected")
    return "remove" if delta.removed else "no-op"


def _require_firewall_schema(
    document: Mapping[str, Any], provider: str, manifest: Mapping[str, Any],
) -> None:
    address = _FIREWALL_ADDRESS[provider]
    planned = document.get("planned_values")
    if not isinstance(planned, Mapping):
        raise SketchProviderContractError("resource_schema_unsupported")
    root = planned.get("root_module")
    if not isinstance(root, Mapping):
        raise SketchProviderContractError("resource_schema_unsupported")
    resources = root.get("resources")
    if not isinstance(resources, list):
        raise SketchProviderContractError("resource_schema_unsupported")
    selected = [item for item in resources if isinstance(item, Mapping) and item.get("address") == address]
    if len(selected) != 1 or type(selected[0].get("schema_version")) is not int \
            or selected[0].get("schema_version") != manifest["plan"]["firewallResourceSchemaVersion"]:
        raise SketchProviderContractError("resource_schema_unsupported")


def _require_projection_matches(reference: Any, candidate: Any) -> None:
    forward: dict[str, str] = {}
    reverse: dict[str, str] = {}

    def compare(expected: Any, actual: Any, path: tuple[str, ...]) -> bool:
        if path == ("timestamp",) and type(actual) is str and not _REDACTED.fullmatch(actual):
            return _valid_rfc3339(actual)
        if type(expected) is str and _REDACTED.fullmatch(expected):
            if type(actual) is not str or not _REDACTED.fullmatch(actual):
                return False
            prior, owner = forward.get(expected), reverse.get(actual)
            if (prior is not None and prior != actual) or (owner is not None and owner != expected):
                return False
            forward[expected], reverse[actual] = actual, expected
            return True
        if type(expected) is not type(actual):
            return False
        if isinstance(expected, dict):
            return set(expected) == set(actual) and all(
                compare(expected[key], actual[key], (*path, key)) for key in expected
            )
        if isinstance(expected, list):
            return len(expected) == len(actual) and all(
                compare(left, right, (*path, str(index)))
                for index, (left, right) in enumerate(zip(expected, actual, strict=True))
            )
        return expected == actual

    if not compare(reference, candidate, ()):
        raise SketchProviderContractError("plan_semantics_rejected")


def _valid_rfc3339(value: str) -> bool:
    if not _RFC3339.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True
