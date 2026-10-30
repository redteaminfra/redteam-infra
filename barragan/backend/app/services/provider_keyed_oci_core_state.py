# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure, diagnostic inventory of Barragan-rendered applied OCI core state.

This parser does not establish ownership of a state file or authorize destroy.
The future teardown child must bind these bytes to persisted plan, job, lease,
workspace, and confirmed parent evidence before using the inventory.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID


_OCI_PROVIDER = 'provider["registry.terraform.io/oracle/oci"]'
_BASE_ROLES = {
    "oci_core_vcn.pilot": ("vcn", "vcn"),
    "oci_core_default_dhcp_options.pilot": ("dhcpoptions", "default_dhcp_options"),
    "oci_core_internet_gateway.pilot": ("internetgateway", "internet_gateway"),
    "oci_core_route_table.pilot": ("routetable", "route_table"),
    "oci_core_security_list.ssh_only": ("securitylist", "core_security_list"),
    "oci_core_security_list.proxy_ingress": ("securitylist", "proxy_ingress_security_list"),
    "oci_core_security_list.homebase_nfs": ("securitylist", "homebase_nfs_security_list"),
    "oci_core_subnet.homebase": ("subnet", "homebase_subnet"),
    "oci_core_subnet.proxy": ("subnet", "proxy_subnet"),
    "oci_core_instance.homebase": ("instance", "homebase"),
    "oci_core_instance.proxy01": ("instance", "proxy01"),
}
_ELK_ROLES = {
    "oci_core_nat_gateway.utility": ("natgateway", "utility_nat_gateway"),
    "oci_core_route_table.utility": ("routetable", "utility_route_table"),
    "oci_core_subnet.utility": ("subnet", "utility_subnet"),
    "oci_core_instance.elk": ("instance", "elk"),
}
_DATA_ADDRESSES = {"oci_identity_availability_domains.ads", "oci_core_images.ubuntu"}
_OCID = re.compile(r"^ocid1\.([a-z]+)\.oc[0-9]+\.[A-Za-z0-9_.-]+$")
_COMPARTMENT = re.compile(r"^ocid1\.compartment\.oc[0-9]+\.[A-Za-z0-9_.-]+$")


class OciCoreStateError(ValueError):
    """State bytes do not match the exact Barragan-generated core schema."""


@dataclass(frozen=True)
class OciCoreStateResource:
    address: str
    ocid: str
    compartment_id: str | None


@dataclass(frozen=True)
class OciCoreStateInventory:
    raw_state_sha256: str
    inventory_sha256: str
    lineage: str
    serial: int
    resources: tuple[OciCoreStateResource, ...]


def parse_applied_oci_core_state(
    state_bytes: bytes, *, proxy_count: int, elk_enabled: bool,
    compartment_id: str, engagement_name: str,
) -> OciCoreStateInventory:
    """Describe exact managed OCIDs in one *untrusted* post-apply state blob."""
    try:
        if (not isinstance(state_bytes, bytes) or proxy_count not in (1, 2)
                or type(proxy_count) is not int or type(elk_enabled) is not bool
                or not isinstance(compartment_id, str)
                or _COMPARTMENT.fullmatch(compartment_id) is None
                or not isinstance(engagement_name, str) or not engagement_name):
            raise ValueError
        parsed = json.loads(state_bytes, object_pairs_hook=_unique_object)
        if (type(parsed) is not dict or parsed.get("version") != 4
                or type(parsed.get("version")) is not int
                or type(parsed.get("serial")) is not int or parsed["serial"] < 1
                or not isinstance(parsed.get("lineage"), str)
                or not isinstance(parsed.get("resources"), list)
                or not isinstance(parsed.get("outputs"), dict)):
            raise ValueError
        UUID(parsed["lineage"])
        expected = dict(_BASE_ROLES)
        if proxy_count == 2:
            expected["oci_core_instance.proxy02"] = ("instance", "proxy02")
        if elk_enabled:
            expected.update(_ELK_ROLES)
        seen: dict[str, OciCoreStateResource] = {}
        seen_ocids: set[str] = set()
        data_seen: set[str] = set()
        for row in parsed["resources"]:
            if (type(row) is not dict or row.get("module") is not None
                    or not isinstance(row.get("type"), str)
                    or not isinstance(row.get("name"), str)
                    or not isinstance(row.get("instances"), list)):
                raise ValueError
            address = f'{row["type"]}.{row["name"]}'
            mode = row.get("mode")
            if mode == "data":
                if (address not in _DATA_ADDRESSES or address in data_seen
                        or row.get("provider") != _OCI_PROVIDER):
                    raise ValueError
                data_seen.add(address)
                if (address.endswith(".ubuntu") and len(row["instances"]) > 1
                        or address.endswith(".ads") and len(row["instances"]) != 1):
                    raise ValueError
                for instance in row["instances"]:
                    _instance_attributes(instance, allow_data_index=address.endswith(".ubuntu"))
                continue
            # Barragan's core renderer emits no managed local or TLS resource.
            # They are explicitly denied, even if a different upstream template
            # has similarly named resources.
            if (mode != "managed" or address not in expected or address in seen
                    or row.get("provider") != _OCI_PROVIDER
                    or len(row["instances"]) != 1):
                raise ValueError
            attrs = _instance_attributes(row["instances"][0])
            kind, role = expected[address]
            ocid = attrs.get("id")
            match = _OCID.fullmatch(ocid) if isinstance(ocid, str) else None
            if match is None or match.group(1) != kind or ocid in seen_ocids:
                raise ValueError
            seen_ocids.add(ocid)
            tags = attrs.get("freeform_tags")
            if (type(tags) is not dict or tags.get("barragan") != "true"
                    or tags.get("barragan_engagement") != engagement_name
                    or tags.get("barragan_environment") != "barragan-testing"
                    or tags.get("barragan_provider") != "oci"
                    or tags.get("barragan_role") != role):
                raise ValueError
            actual_compartment = attrs.get("compartment_id")
            if address == "oci_core_default_dhcp_options.pilot":
                if actual_compartment is not None and actual_compartment != compartment_id:
                    raise ValueError
            elif actual_compartment != compartment_id:
                raise ValueError
            seen[address] = OciCoreStateResource(address, ocid, actual_compartment)
        if set(seen) != set(expected):
            raise ValueError
        if ("oci_identity_availability_domains.ads" not in data_seen
                or seen["oci_core_default_dhcp_options.pilot"].ocid
                != _attribute_for(parsed["resources"], "oci_core_vcn.pilot", "default_dhcp_options_id")):
            raise ValueError
        resources = tuple(seen[address] for address in sorted(seen))
        inventory_body = {
            "lineage": parsed["lineage"], "serial": parsed["serial"],
            "compartmentId": compartment_id, "engagementName": engagement_name,
            "proxyCount": proxy_count, "elkEnabled": elk_enabled,
            "resources": [resource.__dict__ for resource in resources],
        }
        digest = hashlib.sha256(json.dumps(inventory_body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return OciCoreStateInventory(
            hashlib.sha256(state_bytes).hexdigest(), digest,
            parsed["lineage"], parsed["serial"], resources,
        )
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        raise OciCoreStateError("applied OCI core state is invalid or differs from the Barragan render") from None


def _instance_attributes(value: Any, *, allow_data_index: bool = False) -> dict:
    if (type(value) is not dict or value.get("status") is not None
            or value.get("deposed_key") is not None
            or (value.get("index_key") is not None
                and (not allow_data_index or value["index_key"] != 0 or type(value["index_key"]) is not int))
            or type(value.get("attributes")) is not dict):
        raise ValueError
    return value["attributes"]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _attribute_for(rows: list, address: str, key: str) -> Any:
    kind, name = address.split(".")
    row = next(row for row in rows if row.get("type") == kind and row.get("name") == name)
    return row["instances"][0]["attributes"].get(key)
