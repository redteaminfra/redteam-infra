# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network diagnostic parsing of Barragan's rendered OCI core state."""

import hashlib
import json

import pytest

from app.services.provider_keyed_oci_core_state import (
    OciCoreStateError, parse_applied_oci_core_state,
)


_PROVIDER = 'provider["registry.terraform.io/oracle/oci"]'
_COMPARTMENT = "ocid1.compartment.oc1..aaaa"
_ROLES = {
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
    "oci_core_instance.proxy02": ("instance", "proxy02"),
    "oci_core_nat_gateway.utility": ("natgateway", "utility_nat_gateway"),
    "oci_core_route_table.utility": ("routetable", "utility_route_table"),
    "oci_core_subnet.utility": ("subnet", "utility_subnet"),
    "oci_core_instance.elk": ("instance", "elk"),
}


def _state(*, proxy_count=2, elk_enabled=True):
    addresses = list(_ROLES)[:11]
    if proxy_count == 2:
        addresses.append("oci_core_instance.proxy02")
    if elk_enabled:
        addresses.extend(list(_ROLES)[12:])
    resources = []
    for index, address in enumerate(addresses):
        kind, name = address.split(".")
        ocid_kind, role = _ROLES[address]
        attributes = {
            "id": f"ocid1.{ocid_kind}.oc1..id{index:02d}",
            "freeform_tags": {
                "barragan": "true", "barragan_engagement": "engagement-a",
                "barragan_environment": "barragan-testing",
                "barragan_provider": "oci", "barragan_role": role,
            },
        }
        if address != "oci_core_default_dhcp_options.pilot":
            attributes["compartment_id"] = _COMPARTMENT
        if address == "oci_core_vcn.pilot":
            attributes["default_dhcp_options_id"] = "ocid1.dhcpoptions.oc1..id01"
        resources.append({"mode": "managed", "type": kind, "name": name,
                          "provider": _PROVIDER,
                          "instances": [{"schema_version": 0, "attributes": attributes}]})
    resources.extend([
        {"mode": "data", "type": "oci_identity_availability_domains", "name": "ads",
         "provider": _PROVIDER, "instances": [{"attributes": {"id": "data-id"}}]},
        {"mode": "data", "type": "oci_core_images", "name": "ubuntu",
         "provider": _PROVIDER, "instances": [{"index_key": 0, "attributes": {"id": "image-id"}}]},
    ])
    return {"version": 4, "terraform_version": "1.15.5", "serial": 4,
            "lineage": "11111111-1111-4111-8111-111111111111", "outputs": {},
            "resources": resources}


def _parse(state, **kwargs):
    return parse_applied_oci_core_state(
        json.dumps(state).encode(), compartment_id=_COMPARTMENT,
        engagement_name="engagement-a", proxy_count=kwargs.get("proxy_count", 2),
        elk_enabled=kwargs.get("elk_enabled", True),
    )


@pytest.mark.parametrize("proxy_count,elk_enabled", [(1, False), (1, True), (2, False), (2, True)])
def test_exact_generated_resource_matrix(proxy_count, elk_enabled):
    state = _state(proxy_count=proxy_count, elk_enabled=elk_enabled)
    raw = json.dumps(state).encode()
    result = _parse(state, proxy_count=proxy_count, elk_enabled=elk_enabled)
    assert result.raw_state_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.serial == 4
    assert len(result.resources) == 11 + (proxy_count == 2) + (4 if elk_enabled else 0)
    assert result.inventory_sha256 == _parse(state, proxy_count=proxy_count, elk_enabled=elk_enabled).inventory_sha256


def test_optional_image_data_may_have_zero_instances_or_no_state_row():
    state = _state(proxy_count=1, elk_enabled=False)
    state["resources"][-1]["instances"] = []
    _parse(state, proxy_count=1, elk_enabled=False)
    state["resources"].pop()
    _parse(state, proxy_count=1, elk_enabled=False)


@pytest.mark.parametrize("change", [
    lambda s: s.update(serial=0),
    lambda s: s.update(lineage="not-a-uuid"),
    lambda s: s["resources"].pop(0),
    lambda s: s["resources"].append(s["resources"][0]),
    lambda s: s["resources"][0]["instances"][0].update(status="tainted"),
    lambda s: s["resources"][0]["instances"][0].update(deposed_key="old"),
    lambda s: s["resources"][0]["instances"][0].update(index_key=0),
    lambda s: s["resources"][0].update(module="module.extra"),
    lambda s: s["resources"][0]["instances"][0]["attributes"].update(id="ocid1.instance.oc1..wrong"),
    lambda s: s["resources"][5]["instances"][0]["attributes"].update(id="ocid1.securitylist.oc1..id04"),
    lambda s: s["resources"][0]["instances"][0]["attributes"].update(compartment_id="ocid1.compartment.oc1..other"),
    lambda s: s["resources"][0]["instances"][0]["attributes"]["freeform_tags"].update(barragan="false"),
    lambda s: s["resources"][0]["instances"][0]["attributes"].update(default_dhcp_options_id="ocid1.dhcpoptions.oc1..other"),
    lambda s: s["resources"].append({"mode": "managed", "type": "local_file", "name": "artifact", "instances": []}),
    lambda s: s["resources"].append({"mode": "managed", "type": "tls_private_key", "name": "key", "instances": []}),
    lambda s: s["resources"].append({"mode": "data", "type": "oci_core_instances", "name": "all", "instances": []}),
])
def test_rejects_incomplete_foreign_or_ambiguous_state(change):
    state = _state()
    change(state)
    with pytest.raises(OciCoreStateError):
        _parse(state)


def test_raw_hash_tracks_byte_changes_inventory_digest_tracks_semantics():
    state = _state()
    first = _parse(state)
    changed = json.dumps(state, indent=2).encode()
    second = parse_applied_oci_core_state(changed, proxy_count=2, elk_enabled=True,
                                          compartment_id=_COMPARTMENT, engagement_name="engagement-a")
    assert first.raw_state_sha256 != second.raw_state_sha256
    assert first.inventory_sha256 == second.inventory_sha256


def test_duplicate_json_key_is_rejected():
    raw = json.dumps(_state()).replace('"serial": 4,', '"serial": 4, "serial": 5,', 1).encode()
    with pytest.raises(OciCoreStateError):
        parse_applied_oci_core_state(raw, proxy_count=2, elk_enabled=True,
                                     compartment_id=_COMPARTMENT, engagement_name="engagement-a")
