# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, exact-OCID OCI core visibility witnesses for private DevTest teardown.

OCI's NotAuthorizedOrNotFound is ambiguous. A successful complete, unfiltered
compartment list is therefore mandatory beside every exact-ID GET. This module
does not establish Terraform ownership or authorize any provider mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import time
from typing import Callable
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_oci_core_state import (
    OciCoreStateInventory, _BASE_ROLES, _ELK_ROLES, _COMPARTMENT, _OCID,
)


class OciExactWitnessError(ValueError):
    """The selected OCI identity cannot prove exact resource visibility."""


class OciAbsencePending(OciExactWitnessError):
    """Bounded reads have not yet shown stable absence; a fresh read may retry."""


@dataclass(frozen=True)
class OciExactWitness:
    phase: str
    inventory_sha256: str
    resource_ids_sha256: str
    compartment_id: str
    region: str
    auth: str
    principal_sha256: str
    evidence_sha256: str


# OCI CLI names and GET flags match the published command reference. All LISTs
# deliberately omit display-name, VCN, lifecycle, and availability-domain filters.
_COMMANDS = {
    "vcn": ("network", "vcn", "--vcn-id"),
    "dhcpoptions": ("network", "dhcp-options", "--dhcp-id"),
    "internetgateway": ("network", "internet-gateway", "--ig-id"),
    "natgateway": ("network", "nat-gateway", "--nat-gateway-id"),
    "routetable": ("network", "route-table", "--rt-id"),
    "securitylist": ("network", "security-list", "--security-list-id"),
    "subnet": ("network", "subnet", "--subnet-id"),
    "instance": ("compute", "instance", "--instance-id"),
}
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]+\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IMDS_URL = "http://169.254.169.254/opc/v2/instance/"
_PRINCIPAL_COMPARTMENT = re.compile(r"ocid1\.(?:compartment|tenancy)\.oc[0-9]+\.[A-Za-z0-9_.-]+\Z")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise OciExactWitnessError("OCI metadata redirect is not allowed")


def _default_identity_reader() -> dict:
    """Read OCI's non-editable local instance identity from IMDSv2 only."""
    request = Request(_IMDS_URL, headers={"Authorization": "Bearer Oracle"})
    opener = build_opener(ProxyHandler({}), _NoRedirect)
    with opener.open(request, timeout=3) as response:
        raw = response.read(16385)
        if response.status != 200 or len(raw) > 16384:
            raise OciExactWitnessError("OCI instance metadata is unavailable")
    return _json(raw.decode("utf-8"))


def _principal_digest(identity_reader) -> str:
    try:
        identity = identity_reader()
        if (type(identity) is not dict or _OCID.fullmatch(identity.get("id") or "") is None
                or not identity["id"].startswith("ocid1.instance.")
                or _PRINCIPAL_COMPARTMENT.fullmatch(identity.get("compartmentId") or "") is None
                or _REGION.fullmatch(identity.get("canonicalRegionName") or "") is None):
            raise ValueError
        body = {key: identity[key] for key in ("id", "compartmentId", "canonicalRegionName")}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except (OSError, ValueError, TypeError, KeyError, UnicodeDecodeError):
        raise OciExactWitnessError("OCI instance principal identity is unavailable") from None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json(value: str):
    return json.loads(value, object_pairs_hook=_object)


def _default_runner(argv: tuple[str, ...], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, timeout=45, check=False,
                          env=env)


def _oci_cli_environment() -> dict[str, str]:
    """Never let CLI/SDK metadata, proxy, credential, or Python overrides in.

    The OCI SDK's instance-principal signer honors OCI_METADATA_BASE_URL.
    Inheriting that variable could authenticate the CLI through a different
    metadata service than the fixed local IMDSv2 endpoint used by this witness.
    An allowlist is safer than naming only the overrides known today.
    """
    if "OCI_METADATA_BASE_URL" in os.environ:
        raise OciExactWitnessError("OCI metadata endpoint override is not allowed")
    # OCI CLI 3.84.0 can emit urllib3's harmless `strict` FutureWarning on
    # every successful request. Suppress only that module/category; keep the
    # success-path stderr check strict for all other output.
    # The service's OCI entrypoint may use system Python with packages installed
    # in its user site. Bind that location to the OS account, never inherited
    # HOME/PYTHONUSERBASE, while keeping CLI configuration lookup disabled.
    user_base = str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local")
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
            "HOME": "/nonexistent",
            "PYTHONUSERBASE": user_base,
            "PYTHONWARNINGS": "ignore:The 'strict' parameter is no longer needed on Python 3+:FutureWarning:urllib3.poolmanager"}


def _run(runner, argv: tuple[str, ...], *, allow_404: bool, fence) -> dict | None:
    try:
        fence()
        environment = _oci_cli_environment()
        result = runner(argv, environment)
        # An injected runner is only a test seam. Refuse to accept one that
        # tampers with the invocation's explicitly scrubbed environment.
        if environment != _oci_cli_environment():
            raise ValueError
        fence()
        if (type(result.returncode) is not int or not isinstance(result.stdout, str)
                or not isinstance(result.stderr, str)):
            raise ValueError
        if result.returncode == 0 and not result.stderr.strip():
            payload = _json(result.stdout)
            if type(payload) is not dict or "data" not in payload:
                raise ValueError
            return payload
        # OCI CLI emits `ServiceError: {...}` for an exact GET. Any other
        # status, warning, or output shape fails closed, including auth errors.
        if allow_404 and result.returncode != 0 and not result.stdout.strip():
            match = re.fullmatch(r"\s*ServiceError:\s*(\{.*\})\s*", result.stderr, re.S)
            if match:
                error = _json(match.group(1))
                if (type(error) is dict and type(error.get("status")) is int
                        and error["status"] == 404
                        and error.get("code") == "NotAuthorizedOrNotFound"):
                    return None
        raise ValueError
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, json.JSONDecodeError):
        raise OciExactWitnessError("OCI exact visibility query failed or was ambiguous") from None


def _validate(resource, row: dict, *, compartment_id: str, engagement_name: str,
              roles: dict[str, tuple[str, str]]) -> None:
    if type(row) is not dict or row.get("id") != resource.ocid:
        raise OciExactWitnessError("OCI exact resource identity differs")
    if row.get("compartment-id") != compartment_id:
        # Default DHCP is VCN-inherited, but OCI GET/LIST must still prove its
        # compartment. The state parser permits its attribute to be omitted.
        raise OciExactWitnessError("OCI exact resource compartment differs")
    tags = row.get("freeform-tags")
    role = roles[resource.address][1]
    if (type(tags) is not dict or tags.get("barragan") != "true"
            or tags.get("barragan_engagement") != engagement_name
            or tags.get("barragan_environment") != "barragan-testing"
            or tags.get("barragan_provider") != "oci"
            or tags.get("barragan_role") != role):
        raise OciExactWitnessError("OCI exact resource ownership tags differ")


def _context(inventory, compartment_id, region, engagement_name, oci_executable,
             runner):
    if (type(inventory) is not OciCoreStateInventory
            or _HASH.fullmatch(inventory.inventory_sha256) is None
            or _COMPARTMENT.fullmatch(compartment_id or "") is None
            or _REGION.fullmatch(region or "") is None
            or not isinstance(engagement_name, str) or not engagement_name
            or not isinstance(oci_executable, str) or not Path(oci_executable).is_absolute()
            or not callable(runner)):
        raise OciExactWitnessError("OCI witness inputs differ")
    executable = Path(oci_executable)
    if (not executable.is_file() or executable.is_symlink()
            or not os.access(executable, os.X_OK)):
        raise OciExactWitnessError("OCI executable is not pinned")
    roles = dict(_BASE_ROLES)
    roles.update(_ELK_ROLES)
    roles["oci_core_instance.proxy02"] = ("instance", "proxy02")
    if (not inventory.resources or len({r.address for r in inventory.resources}) != len(inventory.resources)
            or len({r.ocid for r in inventory.resources}) != len(inventory.resources)):
        raise OciExactWitnessError("OCI inventory identities differ")
    for resource in inventory.resources:
        expected = roles.get(resource.address)
        match = _OCID.fullmatch(resource.ocid) if isinstance(resource.ocid, str) else None
        if (expected is None or match is None or match.group(1) != expected[0]
                or resource.compartment_id not in (None, compartment_id)
                or (resource.compartment_id is None
                    and resource.address != "oci_core_default_dhcp_options.pilot")):
            raise OciExactWitnessError("OCI inventory resource differs")
    return roles


def _scan(inventory, *, compartment_id, region, engagement_name, oci_executable,
          runner, phase, roles, fence):
    prefix = (oci_executable, "--auth", "instance_principal", "--region", region,
              "--output", "json", "--no-retry")
    lists = {}
    for kind in sorted({roles[r.address][0] for r in inventory.resources}):
        service, name, _ = _COMMANDS[kind]
        payload = _run(runner, prefix + (service, name, "list", "--compartment-id",
                                         compartment_id, "--all"), allow_404=False, fence=fence)
        if type(payload["data"]) is not list or any(type(item) is not dict for item in payload["data"]):
            raise OciExactWitnessError("OCI list response is incomplete")
        ids = [item.get("id") for item in payload["data"]]
        if any(not isinstance(value, str) for value in ids) or len(ids) != len(set(ids)):
            raise OciExactWitnessError("OCI list identities differ")
        lists[kind] = {item["id"]: item for item in payload["data"]}
    evidence = []
    pending = False
    for resource in inventory.resources:
        kind = roles[resource.address][0]
        service, name, flag = _COMMANDS[kind]
        get = _run(runner, prefix + (service, name, "get", flag, resource.ocid),
                   allow_404=phase == "absent", fence=fence)
        listed = lists[kind].get(resource.ocid)
        if phase == "present":
            if get is None or type(get["data"]) is not dict or listed is None:
                raise OciExactWitnessError("OCI exact resource is not visible")
            _validate(resource, get["data"], compartment_id=compartment_id,
                      engagement_name=engagement_name, roles=roles)
            _validate(resource, listed, compartment_id=compartment_id,
                      engagement_name=engagement_name, roles=roles)
            get_state = get["data"].get("lifecycle-state")
            if (not isinstance(get_state, str) or not get_state
                    or get_state != listed.get("lifecycle-state")
                    or get_state in ("DELETING", "DELETED", "TERMINATING", "TERMINATED")):
                raise OciExactWitnessError("OCI pre-destroy resource is not active")
            evidence.append((resource.address, resource.ocid, "present"))
        else:
            observed = []
            if get is not None:
                if type(get["data"]) is not dict:
                    raise OciExactWitnessError("OCI exact GET is malformed")
                observed.append(get["data"])
            if listed is not None:
                observed.append(listed)
            for row in observed:
                _validate(resource, row, compartment_id=compartment_id,
                          engagement_name=engagement_name, roles=roles)
                if not isinstance(row.get("lifecycle-state"), str) or not row["lifecycle-state"]:
                    raise OciExactWitnessError("OCI lifecycle state is malformed")
            if not observed:
                evidence.append((resource.address, resource.ocid, "absent"))
            elif (kind == "instance" and len(observed) == 2
                  and all(row["lifecycle-state"] == "TERMINATED" for row in observed)):
                evidence.append((resource.address, resource.ocid, "TERMINATED"))
            else:
                # OCI deletion is asynchronous. A GET/list disagreement or a
                # TERMINATING network object is pending, never absence. A
                # subsequent bounded scan must converge or leave attention.
                pending = True
                evidence.append((resource.address, resource.ocid, "pending"))
    return pending, evidence


def _witness(inventory, *, phase, compartment_id, region, engagement_name,
             oci_executable, runner, max_scans, pause, poll_seconds, fence,
             identity_reader, expected_principal_sha256=None):
    runner = runner or _default_runner
    roles = _context(inventory, compartment_id, region, engagement_name, oci_executable, runner)
    if (type(max_scans) is not int or max_scans < 1 or max_scans > 91
            or phase == "absent" and max_scans < 2
            or type(poll_seconds) is not int or poll_seconds < 0 or poll_seconds > 30
            or not callable(fence) or not callable(pause)
            or not callable(identity_reader)):
        raise OciExactWitnessError("OCI scan bound differs")
    principal_sha256 = _principal_digest(identity_reader)
    if (expected_principal_sha256 is not None
            and principal_sha256 != expected_principal_sha256):
        raise OciExactWitnessError("OCI instance principal changed")
    ids_hash = _fingerprint({r.address: r.ocid for r in inventory.resources})
    consecutive = 0
    last_evidence = None
    for attempt in range(max_scans):
        if _principal_digest(identity_reader) != principal_sha256:
            raise OciExactWitnessError("OCI instance principal changed during scan")
        pending, evidence = _scan(inventory, compartment_id=compartment_id, region=region,
                                  engagement_name=engagement_name, oci_executable=oci_executable,
                                  runner=runner, phase=phase, roles=roles, fence=fence)
        if _principal_digest(identity_reader) != principal_sha256:
            raise OciExactWitnessError("OCI instance principal changed during scan")
        consecutive = consecutive + 1 if not pending and evidence == last_evidence else (0 if pending else 1)
        last_evidence = evidence
        if consecutive >= (1 if phase == "present" else 2):
            body = {"phase": phase, "inventory": inventory.inventory_sha256,
                    "ids": ids_hash, "compartment": compartment_id, "region": region,
                    "auth": "instance_principal", "principal": principal_sha256,
                    "observations": evidence}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            return OciExactWitness(phase, inventory.inventory_sha256, ids_hash,
                                   compartment_id, region, "instance_principal",
                                   principal_sha256, digest)
        if attempt + 1 < max_scans:
            fence()
            pause(poll_seconds)
            fence()
    raise OciAbsencePending("OCI absence has not stabilized within the scan bound")


def prove_oci_core_visibility(
    inventory: OciCoreStateInventory, *, compartment_id: str, region: str,
    engagement_name: str, oci_executable: str,
    runner: Callable[[tuple[str, ...], dict[str, str]], subprocess.CompletedProcess[str]] | None = None,
    fence: Callable[[], None] = lambda: None,
    identity_reader: Callable[[], dict] = _default_identity_reader,
) -> OciExactWitness:
    """Prove positive GET/list visibility before a reviewed core destroy GO."""
    return _witness(inventory, phase="present", compartment_id=compartment_id,
                    region=region, engagement_name=engagement_name,
                    oci_executable=oci_executable, runner=runner, max_scans=1,
                    pause=time.sleep, poll_seconds=0, fence=fence,
                    identity_reader=identity_reader)


def prove_oci_core_absence(
    inventory: OciCoreStateInventory, *, compartment_id: str, region: str,
    engagement_name: str, oci_executable: str,
    pre_witness: OciExactWitness,
    runner: Callable[[tuple[str, ...], dict[str, str]], subprocess.CompletedProcess[str]] | None = None,
    max_scans: int = 61, poll_seconds: int = 10,
    pause: Callable[[float], None] = time.sleep,
    fence: Callable[[], None] = lambda: None,
    identity_reader: Callable[[], dict] = _default_identity_reader,
) -> OciExactWitness:
    """Require a prior positive witness and bounded exact GET/list reconciliation."""
    if (type(pre_witness) is not OciExactWitness or pre_witness.phase != "present"
            or pre_witness.inventory_sha256 != inventory.inventory_sha256
            or pre_witness.compartment_id != compartment_id
            or pre_witness.region != region or pre_witness.auth != "instance_principal"
            or pre_witness.resource_ids_sha256 != _fingerprint(
                {r.address: r.ocid for r in inventory.resources})
            or _HASH.fullmatch(pre_witness.principal_sha256 or "") is None
            or _HASH.fullmatch(pre_witness.evidence_sha256 or "") is None):
        raise OciExactWitnessError("OCI pre-destroy witness differs")
    return _witness(inventory, phase="absent", compartment_id=compartment_id,
                    region=region, engagement_name=engagement_name,
                    oci_executable=oci_executable, runner=runner, max_scans=max_scans,
                    pause=pause, poll_seconds=poll_seconds, fence=fence,
                    identity_reader=identity_reader,
                    expected_principal_sha256=pre_witness.principal_sha256)
