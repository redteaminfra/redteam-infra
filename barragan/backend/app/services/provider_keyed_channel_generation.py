# Copyright (c) 2026, Oracle and/or its affiliates.
"""Authenticate firewall-only state advances after the immutable append proof.

Each advance is anchored in the ordinary inbound job journal and private
before/after state bytes. It never rewrites the append source or initial seal.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re

from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_initial_plan_gate import _same
from app.services.provider_keyed_ingress_plan_gate import _public_rules
from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
from app.services.provider_keyed_mixed_published_six_source import derive_mixed_published_six_policies
from app.services.terraform_plan_gate import PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES


EVENT = "keyed channel provider generation advanced"


@dataclass(frozen=True)
class ChannelGeneration:
    state_sha256s: tuple[str, str]
    policies: dict[str, dict]
    input_paths: dict[str, Path]
    advances: tuple[dict, ...]
    provider_routes: dict[str, tuple]
    receipt_heads: dict[str, str] | None = None


def require_channel_host_proof(source, proof, routes):
    from app.services.provider_keyed_channel_apply import _topology, _digest
    from app.services.provider_keyed_ingress_route_ledger import render_keyed_route_projection
    from app.services.provider_keyed_append_host_collection import _decode_type
    from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
    from app.services.provider_keyed_mixed_linode_host_probe import LinodeRawHostCollection
    from app.services.provider_keyed_host_policy_interpreter import (
        interpret_digitalocean_host_policy, interpret_linode_host_policy,
    )
    if (type(proof) is not dict or set(proof) != {"path", "sha256"}
            or type(proof["path"]) is not str or type(proof["sha256"]) is not str
            or re.fullmatch(r"[a-f0-9]{64}", proof["sha256"]) is None):
        raise ValueError("keyed host proof reference differs")
    path = Path(proof["path"])
    if path.parent != Path(source.workspace_paths[0]) or not path.name.startswith(".barragan-channel-job-"):
        raise ValueError("keyed host proof path differs")
    raw = _read(path)
    topology, providers = _topology(source)
    policies = render_keyed_route_projection(topology, providers, routes).host_policies
    if sha256(raw).hexdigest() != proof["sha256"]:
        raise ValueError("keyed host policy proof differs")
    # Snapshot every expected value actually consumed by the pure verifier.
    # Safe reads and source/route projection happen even on an exact memo hit.
    expected_hosts = []
    for chain in source.chains:
        for node in chain.nodes:
            from app.services.provider_keyed_mixed_append_pair_host_proof import six_host_known_hosts_path
            known_hosts = six_host_known_hosts_path(source, source.chains.index(chain), chain.nodes.index(node))
            expected_hosts.append({
                "provider": node["provider"], "manifest_sha256": source.source_sha256,
                "chain_id": chain.chain_id,
                "sketch_known_hosts_sha256": sha256(_read(known_hosts)).hexdigest(),
                "terraform_address": node["terraformAddress"],
                "provider_instance_id": node["providerInstanceId"],
                "hostname": node["hostname"], "public_ipv4": node["publicIp"],
                "region": node["region"], "core_known_hosts_sha256": source.core_known_hosts_sha256,
                "policy": policies[node["terraformAddress"]],
            })
    expected = json.dumps({"sourceSha256": source.source_sha256,
        "policySha256": _digest(policies), "hosts": expected_hosts,
        "routes": [vars(route) for route in routes]}, sort_keys=True, separators=(",", ":")).encode()
    from app.services.provider_keyed_host_proof_verdicts import require_host_proof_verdict
    require_host_proof_verdict(raw, expected,
        ("keyed-channel-host-proof-v1", _verify_channel_host_proof, _decode_type,
         DigitalOceanRawHostCollection, LinodeRawHostCollection,
         interpret_digitalocean_host_policy, interpret_linode_host_policy),
        lambda: _verify_channel_host_proof(raw, expected))


def _verify_channel_host_proof(raw, expected_raw):
    """Pure decode/interpretation: the key bytes are the consumed inputs."""
    from app.services.provider_keyed_append_host_collection import _decode_type
    from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
    from app.services.provider_keyed_mixed_linode_host_probe import LinodeRawHostCollection
    from app.services.provider_keyed_host_policy_interpreter import (
        interpret_digitalocean_host_policy, interpret_linode_host_policy,
    )
    captured, expected = json.loads(raw), json.loads(expected_raw)
    if (captured.get("sourceSha256") != expected["sourceSha256"]
            or captured.get("policySha256") != expected["policySha256"]
            or type(captured.get("captures")) is not list or len(captured["captures"]) != 6
            or len(expected["hosts"]) != 6):
        raise ValueError("keyed host policy proof differs")
    for host, raw_capture in zip(expected["hosts"], captured["captures"], strict=True):
        kind = LinodeRawHostCollection if host["provider"] == "linode" else DigitalOceanRawHostCollection
        capture = _decode_type(kind, raw_capture)
        identity = capture.identity
        if any(getattr(identity, field) != value for field, value in host.items()
               if field not in {"provider", "policy"}):
            raise ValueError("keyed host proof identity differs")
        policy = host["policy"]
        interpreter = interpret_linode_host_policy if host["provider"] == "linode" else interpret_digitalocean_host_policy
        interpreter(capture, expected_identity=identity,
                    expected_predecessor_ipv4=policy["sketch_firewall_v2_ssh_sources"][0].removesuffix("/32"),
                    expected_policy=policy)


def read_channel_generation(source, append, initial, jobs, *, require_current_state=True) -> ChannelGeneration:
    """Reopen a single nonforking chain of completed firewall-only writes."""
    policies = derive_mixed_published_six_policies(source, append, initial)
    # Use the append writer's real artifact spelling, not a second convention.
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
    paths = {provider: Path(source.workspace_paths[index]) / _name(provider, "inputs.json")
             for index, provider in enumerate(source.provider_order)}
    hashes = dict(zip(source.provider_order, source.state_sha256s))
    provider_routes = {provider: () for provider in source.provider_order}
    receipt_heads = {provider: sha256(_read(Path(source.workspace_paths[index]) /
        _name(provider, "plan-receipt.json"))).hexdigest()
        for index, provider in enumerate(source.provider_order)}
    anchored = set()
    pending = []
    for job in jobs.list_for_engagement(source.engagement_id):
        for event in job.events:
            if event.message != EVENT:
                continue
            data = event.data
            if (job.action != "inbound_channel_apply" or job.target_id != source.engagement_id
                    or re.fullmatch(r"job-[a-z0-9-]{1,76}", job.id) is None
                    or data.get("sourceSha256") != source.source_sha256
                    or data.get("jobId") != job.id):
                raise ValueError("keyed channel generation job differs")
            pending.append(dict(data))
    ordered = []
    while pending:
        ready = [row for row in pending if row.get("provider") in hashes
                 and row.get("beforeStateSha256") == hashes[row["provider"]]
                 and (("predecessorReceiptSha256" in row
                       and row["predecessorReceiptSha256"] == receipt_heads[row["provider"]])
                      or ("predecessorReceiptSha256" not in row and row["provider"] not in anchored))]
        # Different providers may advance independently; a same-provider fork cannot.
        if not ready or len({row["provider"] for row in ready}) != len(ready):
            raise ValueError("keyed channel state history is disconnected or forked")
        for row in sorted(ready, key=lambda item: item["provider"]):
            provider = row["provider"]
            root = Path(source.workspace_paths[source.provider_order.index(provider)])
            prefix = root / f".barragan-ingress-{row['jobId']}"
            before_raw = _read(Path(f"{prefix}-before.tfstate"))
            after_raw = _read(Path(f"{prefix}-after.tfstate"))
            status_raw = _read(Path(f"{prefix}-status.json"))
            inputs_path = Path(f"{prefix}-inputs.json")
            inputs_raw = _read(inputs_path)
            status, inputs = json.loads(status_raw), json.loads(inputs_raw)
            job = jobs.get(row["jobId"])
            host_events = [event.data for event in job.events
                           if event.message == "keyed channel isolated host policy proved"]
            if (len(host_events) != 1 or host_events[0].get("hostProof") != row.get("hostProof")
                    or host_events[0].get("sourceSha256") != source.source_sha256
                    or next(event.sequence for event in job.events
                            if event.message == "keyed channel isolated host policy proved")
                       >= next(event.sequence for event in job.events
                               if event.message == EVENT and event.data == row)):
                raise ValueError("keyed provider advance lacks exact host proof")
            from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
            routes = tuple(KeyedRouteIntent(**{**r, "public_sources": tuple(r["public_sources"])})
                           for r in host_events[0]["routes"])
            if row["hostProof"].get("path") != str(Path(source.workspace_paths[0]) /
                    f".barragan-channel-{row['jobId']}-after.json"):
                raise ValueError("keyed provider advance host proof job differs")
            require_channel_host_proof(source, row["hostProof"], routes)
            from app.services.provider_keyed_channel_apply import _topology
            from app.services.provider_keyed_ingress_route_ledger import render_keyed_route_projection
            topology, providers = _topology(source)
            projection = render_keyed_route_projection(topology, providers, routes)
            reviewed_routes = projection.provider_routes[provider]
            # derive_mixed_published_six_policies already authenticated this
            # receipt and the exact source marker, topology and lockfile bytes.
            historical = json.loads(_read(root / _name(provider, "plan-receipt.json")))
            source_sha = historical["sourceSha256"]
            from app.services.provider_keyed_channel_apply import _digest
            observed = {address: tuple(sorted({(rule["proto"], rule["port"])
                        for rule in projection.host_policies[address]["sketch_firewall_v2_rules"]
                        if rule["port"] not in {80, 443, 2222}}))
                        for address in sorted(policies[provider]["nodes"])}
            route_sha = _digest({"prior": [vars(route) for route in provider_routes[provider]],
                                 "next": [vars(route) for route in reviewed_routes],
                                 "selected": job.input["channelId"], "hosts": observed})
            prior_input = _read(paths[provider])
            if (sha256(before_raw).hexdigest() != hashes[provider]
                    or sha256(after_raw).hexdigest() != row.get("afterStateSha256")
                    or sha256(status_raw).hexdigest() != row.get("receiptSha256")
                    or sha256(inputs_raw).hexdigest() != row.get("inputSha256")
                    or status.get("phase") != "applied"
                    or status.get("jobId") != row["jobId"]
                    or status.get("provider") != provider
                    or status.get("connectionId") != policies[provider]["provider_connection_id"]
                    or status.get("sourceRevision") != source.source_revisions[source.provider_order.index(provider)]
                    or status.get("sourceSha256") != source_sha
                    or status.get("topologySha256") != _digest(json.loads(_read(
                        root / ".barragan-topology.json", private=False)))
                    or status.get("lockfileSha256") != sha256(_read(
                        root / ".terraform.lock.hcl", private=False)).hexdigest()
                    or status.get("routeSha256") != route_sha
                    or status.get("credentialSha256") != policies[provider]["credential_secret_sha256"]
                    or status.get("credentialUpdatedAt") != policies[provider]["credential_updated_at"]
                    or status.get("retainedInputSha256") != sha256(prior_input).hexdigest()
                    or status.get("reviewedInputSha256") != sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    or status.get("stateSha256") != hashes[provider]
                    or status.get("postStateSha256") != row["afterStateSha256"]):
                raise ValueError("keyed channel retained receipt differs")
            v2 = "predecessorReceiptSha256" in row
            if (status.get("schema") != ("keyed-ingress-update-v2" if v2 else "keyed-ingress-update-v1")
                    or (v2 and status.get("predecessorReceiptSha256") != receipt_heads[provider])
                    or (not v2 and "predecessorReceiptSha256" in status)):
                raise ValueError("keyed channel predecessor receipt differs")
            before, after = json.loads(before_raw), json.loads(after_raw)
            old, new = _state_resources(before), _state_resources(after)
            route_only = ({(r.protocol, r.port) for r in provider_routes[provider]}
                          == {(r.protocol, r.port) for r in reviewed_routes})
            if v2 and route_only:
                from app.services.provider_keyed_ingress_update import _require_noop_state
                _require_noop_state(before_raw, after_raw)
            firewall = f"{provider}_firewall.firewall"
            field = "inbound_rule" if provider == "digitalocean" else "inbound"
            if (before["lineage"] != after["lineage"]
                    or type(before["serial"]) is not int or type(after["serial"]) is not int
                    or (after["serial"] <= before["serial"] and not (v2 and route_only))
                    or set(old) != set(new)
                    or {key for key in old[firewall] if key not in PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[provider]}
                       != {key for key in new[firewall] if key not in PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[provider]}
                    or any(not _same(old[address], new[address]) for address in old if address != firewall)
                    or any(not _same(value, new[firewall].get(key))
                           for key, value in old[firewall].items()
                           if key != field and key not in PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[provider])):
                raise ValueError("keyed channel changed retained infrastructure")
            ports, fixed = _public_rules(provider, new[firewall][field])
            if not {("tcp", 80), ("tcp", 443), ("tcp", 2222)} <= ports or ("tcp", 22) in ports:
                raise ValueError("keyed channel changed baseline public ingress")
            _, old_fixed = _public_rules(provider, old[firewall][field])
            tcp = ["22", "80", "443", "2222"] + [str(port) for port in sorted(
                port for proto, port in ports if proto == "tcp" and port not in {80, 443, 2222})]
            udp = [str(port) for port in sorted(port for proto, port in ports if proto == "udp")]
            expected_ports = {("tcp", 80), ("tcp", 443), ("tcp", 2222)} | {
                (route.protocol, route.port) for route in reviewed_routes}
            prior_inputs = policies[provider]["nonsecret_varfile"]
            if (ports != expected_ports or not _same(fixed, old_fixed)
                    or inputs.get("allowed_tcp_ports") != tcp
                    or inputs.get("allowed_udp_ports") != udp
                    or {k: v for k, v in inputs.items() if k not in {"allowed_tcp_ports", "allowed_udp_ports"}}
                       != {k: v for k, v in prior_inputs.items() if k not in {"allowed_tcp_ports", "allowed_udp_ports"}}):
                raise ValueError("keyed channel ingress inputs differ")
            policies[provider] = {**policies[provider], "nonsecret_varfile": inputs}
            hashes[provider], paths[provider] = row["afterStateSha256"], inputs_path
            provider_routes[provider] = reviewed_routes
            receipt_heads[provider] = row["receiptSha256"]
            if v2:
                anchored.add(provider)
            ordered.append(row)
            pending.remove(row)
    if require_current_state and ordered and any(sha256(_read(Path(source.workspace_paths[index]) / "terraform.tfstate", private=False)).hexdigest()
           != hashes[provider] for index, provider in enumerate(source.provider_order)):
        raise ValueError("keyed channel current state differs from authenticated history")
    return ChannelGeneration(tuple(hashes[provider] for provider in source.provider_order),
                             policies, paths, tuple(ordered), provider_routes, receipt_heads)
