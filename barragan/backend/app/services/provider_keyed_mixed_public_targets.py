# Copyright (c) 2026, Oracle and/or its affiliates.
"""Versioned, read-only public targets bound to the published cleanup manifest."""
from dataclasses import asdict
import hashlib
import ipaddress
import json
import re

SCHEMA = "mixed-published-public-targets-v1"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _ip(value):
    address = ipaddress.ip_address(value)
    if type(value) is not str or str(address) != value or not address.is_global:
        raise ValueError("public target address differs")
    return value


def _name(value):
    if type(value) is not str:
        raise ValueError("DNS target name differs")
    name = value.rstrip(".").lower()
    if name.startswith("*."):
        return "*." + _name(name[2:])
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?", name):
        raise ValueError("DNS target name differs")
    if any(not part or len(part) > 63 for part in name.split(".")):
        raise ValueError("DNS target name differs")
    return name


def build_public_target_seal(manifest, core_targets, routes):
    """Routes were reopened from the existing nonforking six-host proof ledger."""
    from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
    edges = {row["terraformAddress"]: row for row in manifest["edgeTargets"]}
    if len(edges) != len(manifest["edgeTargets"]):
        raise ValueError("public edge identities repeat")
    endpoints = {}
    for target in core_targets:
        if (target.get("type") != "tcp-forbidden" or target.get("port") != 22
                or target.get("id") != f"tcp:{_ip(target['host'])}:22"):
            raise ValueError("core public target differs")
        endpoints[target["id"]] = dict(target)
    listeners, seen = [], set()
    for route in routes:
        if (type(route) is not KeyedRouteIntent or route.kind not in {"web", "tcp", "udp"}
                or type(route.channel_id) is not str or not route.channel_id or route.channel_id in seen
                or route.edge_node not in edges or type(route.external_port) is not int
                or not 1 <= route.external_port <= 65535
                or route.kind == "web" and route.external_port not in {80, 443}):
            raise ValueError("public listener route differs")
        seen.add(route.channel_id)
        edge = edges[route.edge_node]
        ip = _ip(edge["publicIp"])
        proto = "udp" if route.kind == "udp" else "tcp"
        identifier = f"{proto}:{ip}:{route.external_port}"
        endpoints.setdefault(identifier, {"id": identifier, "type": f"{proto}-forbidden",
            "host": ip, "port": route.external_port, "targetGroup": "former-public-listener"})
        listeners.append({"channelId": route.channel_id, "edgeNode": route.edge_node,
            "provider": edge["provider"], "providerInstanceId": edge["providerInstanceId"],
            "chainId": edge["chainId"], "publicIp": ip, "protocol": proto,
            "port": route.external_port, "targetId": identifier})
    dns, ids = [], set()
    for domain in manifest["domains"]:
        zone = _name(domain["domainName"])
        for owned in domain["ownedRecords"]:
            record, identity = owned["record"], owned["ownershipId"]
            if type(identity) is not int or identity <= 0 or identity in ids:
                raise ValueError("DNS ownership repeats")
            ids.add(identity)
            kind, name, answer = record["type"], record["name"], record["address"]
            if kind not in {"A", "AAAA", "CNAME", "TXT", "MX", "NS"}:
                raise ValueError("owned DNS record type is unsupported")
            # Wildcard ownership is a record, not permission to invent a hostname.
            host = zone if name == "@" else _name(name + "." + zone)
            if kind in {"A", "AAAA"}:
                address = ipaddress.ip_address(answer)
                if address.version != (4 if kind == "A" else 6) or str(address) != answer:
                    raise ValueError("owned DNS previous address differs")
            elif kind in {"CNAME", "MX", "NS"}:
                answer = _name(answer)
            elif type(answer) is not str:
                raise ValueError("owned DNS previous text differs")
            ttl = int(record["ttl"])
            if not 0 <= ttl <= 86400:
                raise ValueError("owned DNS TTL differs")
            previous = f"{int(record['mxPref'])} {answer}" if kind == "MX" else answer
            identifier = f"dns:{domain['domainId']}:{identity}"
            target = {"id": identifier, "type": "dns-record-absent", "host": host,
                      "recordType": kind, "previousAnswer": previous, "ttlSeconds": ttl,
                      "targetGroup": "owned-public-dns"}
            endpoints[identifier] = target
            dns.append({"ownershipId": identity, "domainId": domain["domainId"],
                "assignmentId": domain["assignmentId"], "zone": zone,
                "record": dict(record), "targetId": identifier})
    result = {"schema": SCHEMA, "sourceSha256": manifest["sourceSha256"],
        "coreJobId": manifest["coreJobId"],
        "routeIntents": sorted([asdict(route) for route in routes], key=lambda row: row["channel_id"]),
        "listeners": sorted(listeners, key=lambda row: row["channelId"]),
        "dns": sorted(dns, key=lambda row: row["ownershipId"]),
        "targets": sorted(endpoints.values(), key=lambda row: row["id"])}
    # JSON canonical form is also the persisted form (tuples become arrays).
    result = json.loads(json.dumps(result))
    result["sha256"] = digest(result)
    return result


def published_targets(parent, core_targets):
    """Old saved receipts remain core-only; a sealed new parent cannot downgrade."""
    from app.services.provider_keyed_mixed_failed_second_append import extend_retired_targets
    manifest = parent.input.get("bindingManifest")
    seal = manifest.get("publicTargetSeal") if type(manifest) is dict else None
    expected = parent.input.get("publicTargetSealSha256")
    if seal is None:
        if expected is not None:
            raise ValueError("sealed public targets were omitted")
        return extend_retired_targets(core_targets, parent)
    from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
    if (type(seal) is not dict or seal.get("schema") != SCHEMA or expected != seal.get("sha256")
            or manifest.get("manifestSha256") != "sha256:" + digest(
                {key: value for key, value in manifest.items() if key != "manifestSha256"})):
        raise ValueError("public target seal differs")
    routes = tuple(KeyedRouteIntent(**{**row, "public_sources": tuple(row["public_sources"])})
                   for row in seal["routeIntents"])
    if build_public_target_seal(manifest, core_targets, routes) != seal:
        raise ValueError("public targets differ from owned identities")
    return extend_retired_targets(seal["targets"], parent)
