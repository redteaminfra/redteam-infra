# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only saved-plan gate for one audited keyed Linode initial chain.

This does not run Terraform or authorize Apply. The caller must derive the
trusted proxy /32, durable admin public key, labels/ordinals, and local-file
intent from reviewed/core records, bind this JSON to the saved binary plan SHA,
and recheck that reviewed authorization at use time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import _same
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, ProviderKeyedSketchError, SCHEMA, _source_files, _terraform_loadable,
)
from app.services.terraform_plan_gate import TerraformPlanGateError, classify_saved_plan_actions

# New keyed workspaces opt into UDP-capable source with an empty UDP union.
# Historical workspace audits keep their original source identity.
_SOURCE_REVISION = "cae68e63b8495f0e6d31dfa4a991f4024f18e58b"
_LEGACY_SOURCE_REVISION = "90b6895d9eccc0cf19524396b528a289f5f22fb1"
_LEGACY_SOURCE_SHA256 = "31245abf462f9ab33501f094c43c70049d6c2bfe54301590ff8fac9154e37405"
_SOURCE_SHA256 = "d0f3292ede53e09766f2710df3bc040410eaad24edd5f2f0d14b0dc8cf65d7ef"
_LOCK_SHA256 = "40e181997472ad02b0a68ef1b826c745f2d69c41426ab2a6d7000f9261399a49"
_FIREWALL = "linode_firewall.firewall"
_PASSWORD = "random_password.root_password"
_LOCAL = {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}
# SHA-256 of Terraform 1.15.5/Linode 4.5.0 known schema metadata, obtained
# from an offline plan with the pinned source and mock providers. Any provider
# schema change requires a new audited fixture and review.
_METADATA = {
    "firewall": ("543ab733bd91e37fbbe0ef4f1c162b3660132edf33f903006e4d2ff08a331bf5",
                 "e78396ade23cd82406f144db3c1b700fbd285e7a121883eaff95177c7106cd13"),
    "node": ("506342c515cf9930422aae9e5150f1da9c55b5f9321de05256ae2bf025f27f0b",
             "8fe50ab3bb4b94d1bb49ecb89ea269fdf7386232c077c5bae96aaefa98e474cd"),
    "inventory": ("44567d896be93b4c72b1b3c0f10bc473c45fc8c9d4283f3d1c6b6479d028355e",
                  "3c1a7451eb215cd5fc4fc09d4e848242cd4c78793c884ae40a1650258f9b5eb2"),
    "ssh": ("680fe43e5e0408060ad316ae55857161c9294ffb37525816d1fe88f2a9768c24",
            "3c1a7451eb215cd5fc4fc09d4e848242cd4c78793c884ae40a1650258f9b5eb2"),
    "password": ("aacd80bebb8eafcb3db53de818494e42bfe8649622e0c13432578be7223b8974",
                 "2fad781abc800d2d25a68120195945a4489c00898d647b583958e873b59516fc"),
}
_NODE_STATIC_SHA256 = "20352d07d4ef86f5fc3ec045ea71fabf2a53d3d211e897a0761c89b332ad781a"
# Terraform show -json of a fresh saved plan uses different known defaults and
# computed-field envelopes than terraform test's mock-provider output above.
# These hashes were checked against the disposable real saved plan; the exact
# after values are checked below as well.
_REAL_UNKNOWN_SHA256 = {
    "firewall": "5033269caffe912a7ed19b138a023f926b9f0bbe25af31172af8be65315f53da",
    "node": "68f9a0c666e9706db0622783c471fd1d1c769681449af3d3119ceb2ba4d95a8f",
    "inventory": "be6af67089eb486fe655e73e97eb2e5a2800ba9b0826b3fdac252ea07168da8e",
    "ssh": "97d4ba7a89eb8b1e1ef57d5bc2d7a4e398f3bf4e8dc71f3bed6d29926300ab5a",
    "password": "62d9df43d1b1c6e7057c3a665179332729576665cc647d0855935d13cb1004f0",
}
_REAL_NODE_STATIC_SHA256 = "320ff2e502d26bb33ef98ea6dec90ebd537b4fed98f1a5b8628b55faae08e0af"


@dataclass(frozen=True)
class LinodeNodeCreate:
    label: str
    image: str
    node_type: str
    region: str
    tag: str
    authorized_keys: tuple[str, ...]


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _reject(reason: str) -> None:
    raise TerraformPlanGateError(f"Linode initial plan {reason}")


def _prior_resource_state_shape(prior: object) -> str | None:
    """Distinguish exact offline and saved-plan empty-resource envelopes."""
    if prior == {"values": {"root_module": {}}}:
        return "mock"
    if (not isinstance(prior, dict)
            or set(prior) != {"format_version", "terraform_version", "values"}
            or prior["format_version"] != "1.0"
            or prior["terraform_version"] != "1.15.5"):
        return None
    values = prior["values"]
    if (not isinstance(values, dict) or set(values) != {"root_module", "outputs"}
            or values["root_module"] != {} or not isinstance(values["outputs"], dict)):
        return None
    return "saved"


def _workspace(workspace: ProviderKeyedWorkspace) -> None:
    if not isinstance(workspace, ProviderKeyedWorkspace):
        _reject("source is not audited")
    expected_sha = (_SOURCE_SHA256 if workspace.source_revision == _SOURCE_REVISION
                    else _LEGACY_SOURCE_SHA256 if workspace.source_revision == _LEGACY_SOURCE_REVISION
                    else None)
    if (workspace.schema != SCHEMA or workspace.provider != "linode"
            or expected_sha is None or workspace.source_sha256 != expected_sha):
        _reject("source is not audited")
    root = workspace.path
    try:
        marker = root / ".barragan-provider-keyed-state.json"
        if root.is_symlink() or marker.is_symlink() or not root.is_dir():
            raise ValueError("unsafe workspace")
        ownership = json.loads(marker.read_text(encoding="utf-8"))
        for key, value in {"schema": SCHEMA, "provider": "linode",
                           "provider_connection_id": workspace.provider_connection_id,
                           "connection_fingerprint": workspace.connection_fingerprint,
                           "source_revision": workspace.source_revision}.items():
            if ownership.get(key) != value:
                raise ValueError("ownership drift")
        source = ownership["source_files"]
        rendered = ownership["rendered_files"]
        expected = dict(source)
        expected["providers.tf"] = source["barragan-v2/providers.tf"]
        expected["firewall.tf"] = source["barragan-v2/firewall.tf"]
        expected[".terraform.lock.hcl"] = source["barragan-v2/.terraform.lock.hcl"]
        if (hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest() != expected_sha
                or rendered != expected
                or source["barragan-v2/.terraform.lock.hcl"] != _LOCK_SHA256
                or _source_files(root, tuple(rendered)) != rendered):
            raise ValueError("source drift")
        if any(path.relative_to(root).as_posix() not in rendered or path.is_symlink()
               for path in root.rglob("*") if _terraform_loadable(path.name)
               and (path.is_file() or path.is_symlink())):
            raise ValueError("unreviewed Terraform input")
    except (OSError, ValueError, KeyError, TypeError, ProviderKeyedSketchError) as exc:
        raise TerraformPlanGateError("Linode initial plan audited workspace failed") from exc


def _rule(action: str, protocol: str, label: str, *, ports: str | None = None,
          ipv4: list[str] | None = None, ipv6: list[str] | None = None) -> dict:
    return {"action": action, "protocol": protocol, "label": label,
            "ports": ports, "ipv4": ipv4, "ipv6": ipv6}


def require_linode_keyed_initial_full_plan(
    saved_plan_json: str, *, workspace: ProviderKeyedWorkspace,
    reviewed_authorization: Mapping[str, object],
    expected_nodes: Mapping[str, LinodeNodeCreate],
    engagement_name: str, trusted_ssh_cidrs: tuple[str, ...],
    expected_middle_ordinal: int, expected_edge_ordinal: int,
    expected_local_files: Mapping[str, Mapping[str, object]],
) -> None:
    """Require the exact fresh one-chain actions and reviewed Linode policy."""
    _workspace(workspace)
    auth = reviewed_authorization
    if (not isinstance(auth, Mapping) or auth.get("kind") != "bounded-mixed-post-core-v1"
            or not isinstance(auth.get("providerScopes"), list)
            or len(auth["providerScopes"]) != 2
            or [row.get("provider") for row in auth["providerScopes"]] != ["digitalocean", "linode"]
            or auth.get("fingerprint") != _digest({k: v for k, v in auth.items() if k != "fingerprint"})):
        _reject("reviewed mixed scope is invalid")
    if (type(expected_middle_ordinal) is not int or expected_middle_ordinal not in (1, 2)
            or type(expected_edge_ordinal) is not int or expected_edge_ordinal < 1):
        _reject("engagement-wide ordinals are invalid")
    scope = auth["providerScopes"][1]
    chain = scope.get("chain")
    source = scope.get("source")
    policy = scope.get("firewall")
    middle_address = f'linode_instance.middle["middle_{expected_middle_ordinal:02d}"]'
    edge_address = next((address for address in expected_nodes
                         if isinstance(address, str) and address.startswith('linode_instance.edge["')), None)
    if (not isinstance(chain, dict) or not isinstance(source, dict)
            or not isinstance(policy, dict) or scope.get("providerConnectionId") != workspace.provider_connection_id
            or source != {"revision": workspace.source_revision, "templateSha256": workspace.source_sha256,
                          "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                           "sha256": _LOCK_SHA256, "providerVersion": "4.5.0"}}
            or not isinstance(engagement_name, str) or not engagement_name
            or not isinstance(expected_nodes, Mapping) or len(expected_nodes) != 2
            or edge_address is None or set(expected_nodes) != {middle_address, edge_address}
            or not all(isinstance(n, LinodeNodeCreate) for n in expected_nodes.values())
            or any(n.image != scope.get("image") or n.tag != engagement_name
                   for n in expected_nodes.values())
            or not isinstance(chain.get("edges"), list) or len(chain["edges"]) != 1):
        _reject("reviewed source, connection, image, or node scope differs")
    middle = expected_nodes[middle_address]
    edge = expected_nodes[edge_address]
    if (edge_address != f'linode_instance.edge["{edge.region.lower()}-{expected_edge_ordinal:02d}"]'
            or middle.label != f"middle{expected_middle_ordinal:02d}-{engagement_name}"
            or edge.label != f"edge-{engagement_name}-{edge.region}-{expected_edge_ordinal:02d}"
            or chain.get("middle") != {"provider": "linode", "region": middle.region,
                                "size": middle.node_type}
            or chain["edges"][0].get("provider") != "linode"
            or chain["edges"][0].get("region") != edge.region
            or chain["edges"][0].get("size") != edge.node_type
            or policy != {"publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
                          "publicIpv6Allowed": False,
                          "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                                            "proxyNames": [chain.get("assignedProxy")]},
                          "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                                          "portRange": "1-65535",
                                          "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
                          "outboundIpv4": "accept", "outboundIpv6": "drop"}
            or not isinstance(trusted_ssh_cidrs, tuple) or not trusted_ssh_cidrs
            or len(set(trusted_ssh_cidrs)) != len(trusted_ssh_cidrs)):
        _reject("reviewed chain or firewall policy differs")
    try:
        if any(ipaddress.ip_network(cidr, strict=True).version != 4
               or not cidr.endswith("/32") for cidr in trusted_ssh_cidrs):
            raise ValueError("not a trusted IPv4 host")
    except (ValueError, TypeError) as exc:
        raise TerraformPlanGateError("Linode initial plan SSH source is invalid") from exc
    if not isinstance(expected_local_files, Mapping) or set(expected_local_files) != _LOCAL:
        _reject("local artifact intent is invalid")
    try:
        plan = json.loads(saved_plan_json)
    except (TypeError, ValueError) as exc:
        raise TerraformPlanGateError("Linode initial saved plan is not JSON") from exc
    shape = _prior_resource_state_shape(plan.get("prior_state")) if isinstance(plan, dict) else None
    drift = plan.get("resource_drift", []) if isinstance(plan, dict) else None
    if (not isinstance(plan, dict) or plan.get("format_version") != "1.2"
            or plan.get("terraform_version") != "1.15.5" or plan.get("applyable") is not True
            or plan.get("complete") is not True or plan.get("errored") is not False
            or type(drift) is not list or drift or shape is None
            or not isinstance(plan.get("resource_changes"), list)):
        _reject("is incomplete, drifted, or not fresh")
    expected = set(expected_nodes) | {_FIREWALL, _PASSWORD} | _LOCAL
    seen = set()
    for row in plan["resource_changes"]:
        if not isinstance(row, dict) or row.get("address") not in expected or row["address"] in seen:
            _reject("has extra or duplicate actions")
        address = row["address"]
        seen.add(address)
        change = row.get("change")
        if (not isinstance(change, dict) or classify_saved_plan_actions(change.get("actions")) != "create"
                or change.get("before", object()) is not None or change.get("before_sensitive") is not False):
            _reject("has a non-create action")
        kind = ("firewall" if address == _FIREWALL else "password" if address == _PASSWORD
                else "inventory" if address == "local_file.ansible_inventory[0]"
                else "ssh" if address == "local_file.ssh_stanza[0]" else "node")
        expected_unknown = (_REAL_UNKNOWN_SHA256[kind] if shape == "saved" else _METADATA[kind][0])
        if (_digest(change.get("after_unknown")), _digest(change.get("after_sensitive"))) != (
                expected_unknown, _METADATA[kind][1]):
            _reject("has unreviewed computed or sensitive fields")
        after = change.get("after")
        if address in expected_nodes:
            node = expected_nodes[address]
            if not isinstance(after, dict):
                _reject("node fields differ")
            static = {k: v for k, v in after.items()
                      if k not in {"authorized_keys", "image", "label", "region", "tags", "type"}}
            if (_digest(static) != (_REAL_NODE_STATIC_SHA256 if shape == "saved" else _NODE_STATIC_SHA256)
                    or {k: after.get(k) for k in ("label", "image", "type", "region", "tags", "authorized_keys")}
                    != {"label": node.label, "image": node.image, "type": node.node_type,
                        "region": node.region, "tags": [node.tag],
                        "authorized_keys": list(node.authorized_keys)}):
                _reject("node differs from reviewed intent")
        elif address == _FIREWALL:
            inbound = [_rule("ACCEPT", "TCP", f"allow-tcp-{port}", ports=port,
                             ipv4=["0.0.0.0/0"]) for port in ("80", "443", "2222")]
            inbound.append(_rule("ACCEPT", "TCP", "allow-tcp-22-trusted", ports="22",
                                 ipv4=list(trusted_ssh_cidrs)))
            peer = [_rule("ACCEPT", proto.upper(), f"allow-{engagement_name}-host-{proto}")
                    for proto in ("tcp", "udp", "icmp")]
            for rule in peer:
                del rule["ipv4"]
            inbound.extend(peer)
            blocked = [_rule("DROP", proto.upper(), f"block-ipv6-{proto}", ipv6=["::/0"])
                       for proto in ("tcp", "udp", "icmp")]
            rules = inbound + blocked
            if shape == "saved":
                rules = [{**rule, "description": ""} for rule in rules]
                blocked = [{**rule, "description": ""} for rule in blocked]
            expected_firewall = {"label": f"fw-{engagement_name}-firewall", "tags": [engagement_name],
                                 "linodes": [None, None], "inbound_policy": "DROP",
                                 "outbound_policy": "ACCEPT", "inbound": rules,
                                 "outbound": blocked}
            if shape == "saved":
                expected_firewall["disabled"] = False
            if not _same(after, expected_firewall):
                _reject("firewall differs from reviewed ingress or egress")
        elif address == _PASSWORD:
            expected_password = {"keepers": None, "length": 30, "override_special": None}
            if shape == "saved":
                expected_password.update({key: True for key in
                    ("lower", "number", "numeric", "special", "upper")})
                expected_password.update({key: 0 for key in
                    ("min_lower", "min_numeric", "min_special", "min_upper")})
            if not _same(after, expected_password):
                _reject("password policy differs")
        else:
            expected_file = dict(expected_local_files[address])
            if shape == "saved":
                expected_file["directory_permission"] = "0777"
            if not _same(after, expected_file):
                _reject("local artifact differs from reviewed intent")
    if seen != expected:
        _reject("omits expected actions")
