# Copyright (c) 2026, Oracle and/or its affiliates.
"""Decode and re-interpret a private raw edge observation at every publish read."""

from __future__ import annotations

from dataclasses import asdict, fields, is_dataclass
import json
from types import UnionType
from typing import Union, get_args, get_origin, get_type_hints

from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
from app.services.provider_keyed_host_policy_interpreter import interpret_digitalocean_host_policy
from app.services.provider_keyed_host_surface_interpreter import interpret_digitalocean_host_surface


def _decode_type(kind, value):
    origin = get_origin(kind)
    if origin in (Union, UnionType):
        for option in get_args(kind):
            try:
                return _decode_type(option, value)
            except (TypeError, ValueError):
                pass
        raise ValueError("raw edge field union differs")
    if is_dataclass(kind):
        if type(value) is not dict:
            raise ValueError("raw edge object differs")
        hints = get_type_hints(kind)
        if set(value) != {field.name for field in fields(kind)}:
            raise ValueError("raw edge object fields differ")
        return kind(**{field.name: _decode_type(hints[field.name], value[field.name])
                       for field in fields(kind)})
    if origin is tuple:
        if type(value) is not list:
            raise ValueError("raw edge tuple differs")
        options = get_args(kind)
        if len(options) == 2 and options[1] is Ellipsis:
            return tuple(_decode_type(options[0], item) for item in value)
        if len(value) != len(options):
            raise ValueError("raw edge tuple length differs")
        return tuple(_decode_type(option, item)
                     for option, item in zip(options, value, strict=True))
    if origin is dict:
        key_kind, value_kind = get_args(kind)
        if type(value) is not dict:
            raise ValueError("raw edge map differs")
        return {_decode_type(key_kind, key): _decode_type(value_kind, item)
                for key, item in value.items()}
    if kind is object:
        if type(value) not in (str, int, float, bool, list, dict, type(None)):
            raise ValueError("raw edge object value differs")
        return value
    if kind is type(None):
        if value is not None:
            raise ValueError("raw edge non-null field differs")
        return value
    if type(value) is not kind:
        raise ValueError("raw edge primitive differs")
    return value


def verify_append_edge_host_collection(
    raw_bytes: bytes, *, manifest_sha256: str, chain_id: str,
    terraform_address: str, provider_instance_id: str, public_ipv4: str,
    region: str, hostname: str,
    predecessor_ipv4: str, expected_policy: dict,
    admin_key_sha256: str, transport_key_sha256: str,
) -> DigitalOceanRawHostCollection:
    raw = json.loads(raw_bytes)
    collection = _decode_type(DigitalOceanRawHostCollection, raw)
    if json.loads(json.dumps(asdict(collection), sort_keys=True)) != raw:
        raise ValueError("raw edge round trip differs")
    identity = collection.identity
    if (identity.manifest_sha256 != manifest_sha256
            or identity.chain_id != chain_id
            or identity.terraform_address != terraform_address
            or identity.provider_instance_id != provider_instance_id
            or identity.public_ipv4 != public_ipv4
            or identity.region != region or identity.hostname != hostname):
        raise ValueError("raw edge identity differs")
    firewall = interpret_digitalocean_host_policy(
        collection, expected_identity=identity,
        expected_predecessor_ipv4=predecessor_ipv4,
        expected_policy=expected_policy)
    surface = interpret_digitalocean_host_surface(
        collection, expected_identity=identity,
        expected_predecessor_ipv4=predecessor_ipv4, expected_role="edge",
        expected_admin_key_sha256=admin_key_sha256,
        expected_transport_key_sha256=transport_key_sha256,
        expected_policy=expected_policy)
    if (firewall.identity != identity or surface.identity != identity
            or surface.complete_ssh_policy is not True):
        raise ValueError("raw edge firewall or SSH policy differs")
    return collection
