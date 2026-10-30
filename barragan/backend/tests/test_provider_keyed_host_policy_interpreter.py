# Copyright (c) 2026, Oracle and/or its affiliates.
"""Synthetic policy captures; no private operational fixture is checked in."""

import hashlib
import json
from dataclasses import replace

import pytest

from app.services import provider_keyed_host_policy_interpreter as policy
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawFirewallEvidence,
    DigitalOceanRawHostCollection, DigitalOceanRawHostSurfaceEvidence,
    RawFirewallCommandEvidence, RawFirewallFileEvidence,
    _FIREWALL_COMMANDS, _FIREWALL_OPTIONAL_FILES,
)
from app.services.provider_keyed_mixed_linode_host_probe import LinodeRawHostCollection, LinodeRawHostIdentity

PREDECESSOR = "192.0.2.7"


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _fixture(monkeypatch):
    identity = DigitalOceanHostIdentityEvidence("a" * 64, "chain", 'digitalocean_droplet.middle["x"]',
        "123", "region", "198.51.100.3", "middle", "00000000-0000-0000-0000-000000000001",
        "alias", "identity", "b" * 64, "c" * 64)
    status = ("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
              "New profiles: skip\n\nTo Action From\n22/tcp ALLOW IN 192.0.2.7\n")
    save = ("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
            "-A INPUT -j ufw-before-input\n-A INPUT -j ufw-after-input\n"
            "-A ufw-before-input -i lo -j ACCEPT\n"
            "-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A ufw-user-input -s 192.0.2.7/32 -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    save6 = ("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
             "-A INPUT -j ufw6-before-input\n-A INPUT -j ufw6-after-input\n"
             "-A ufw6-before-input -i lo -j ACCEPT\n"
             "-A ufw6-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n")
    nft = {"nftables": [
        {"metainfo": {"version": "1.0.9"}},
        *[{"table": {"family": family, "name": "filter"}} for family in ("ip", "ip6")],
        *[{"chain": {"family": family, "table": "filter", "name": name, "type": "filter",
                       "hook": hook, "prio": 0, "policy": verdict}}
          for family in ("ip", "ip6") for name, hook, verdict in
          (("INPUT", "input", "drop"), ("FORWARD", "forward", "drop"), ("OUTPUT", "output", "accept"))],
        {"rule": {"family": "ip", "table": "filter", "chain": "ufw-user-input", "handle": 1,
                  "expr": [{"match": {"left": "ip saddr", "right": PREDECESSOR}},
                           {"match": {"left": "tcp dport", "right": 22}},
                           {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}
    ]}
    outputs = {name: "baseline\n" for name, _ in _FIREWALL_COMMANDS}
    outputs.update({"ufw_status_verbose": status, "ufw_user_rules": "ssh 192.0.2.7/32\n",
        "ufw_user6_rules": "no v6 rules\n", "ufw_defaults": 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_FORWARD_POLICY="DROP"\n',
        "ufw_configuration": "ENABLED=yes\n", "iptables_save": save, "ip6tables_save": save6,
        "nft_ruleset": json.dumps(nft)})
    outputs.update(policy._VERSIONS)
    baseline = {}
    for name in policy._BASELINE:
        if name == "nft_ruleset":
            value = json.dumps(policy._normal_nft(nft, PREDECESSOR), sort_keys=True, separators=(",", ":"))
        elif name.endswith("tables_save"):
            value = policy._normal_save(outputs[name], PREDECESSOR)
        else:
            value = policy._normal_ip(outputs[name], PREDECESSOR)
        baseline[name] = _sha(value)
    monkeypatch.setattr(policy, "_BASELINE", baseline)
    normalized_status = "\n".join(
        __import__("re").sub(r"^22/tcp\s+ALLOW IN\s+PREDECESSOR\s*$", "22/tcp ALLOW IN PREDECESSOR", line)
        for line in status.replace(PREDECESSOR, "PREDECESSOR").splitlines())
    monkeypatch.setattr(policy, "_STATUS_SHA256", _sha(normalized_status))
    optional = {name: "synthetic " + name for name, _ in _FIREWALL_OPTIONAL_FILES}
    monkeypatch.setattr(policy, "_OPTIONAL_HASHES", {name: _sha(value) for name, value in optional.items()})

    def snapshot(invocation, start, changed=None):
        values = dict(outputs)
        if changed:
            values.update(changed)
        commands = tuple(RawFirewallCommandEvidence(name, _sha(values[name]), len(values[name].encode()), values[name])
                         for name, _ in _FIREWALL_COMMANDS)
        files = tuple(RawFirewallFileEvidence(name, path, "present", _sha(optional[name]),
                      len(optional[name].encode()), 0, 0, 0o644, optional[name])
                      for name, path in _FIREWALL_OPTIONAL_FILES)
        return DigitalOceanRawFirewallEvidence(identity, invocation, identity.boot_id, start, start + 1,
                                                commands, files)
    surface = DigitalOceanRawHostSurfaceEvidence(identity, "surface", identity.boot_id, 103, 104,
        PREDECESSOR, (PREDECESSOR, 50000, identity.public_ipv4, 22), (), (), "listeners")
    collection = DigitalOceanRawHostCollection(identity, snapshot("before", 100), surface,
                                                snapshot("after", 105))
    expected = {"sketch_firewall_v2_enabled": True,
                "sketch_firewall_v2_ssh_sources": [PREDECESSOR + "/32"],
                "sketch_firewall_v2_rules": []}
    return collection, expected, outputs


def _verify(collection, expected):
    return policy.interpret_digitalocean_host_policy(collection, expected_identity=collection.identity,
        expected_predecessor_ipv4=PREDECESSOR, expected_policy=expected)


def _replace_output(collection, name, value):
    before = collection.firewall_before
    commands = tuple(replace(row, raw_output=value, sha256=_sha(value), byte_count=len(value.encode()))
                     if row.name == name else row for row in before.commands)
    return replace(collection, firewall_before=replace(before, commands=commands))


def _replace_after_output(collection, name, value):
    after = collection.firewall_after
    commands = tuple(replace(row, raw_output=value, sha256=_sha(value), byte_count=len(value.encode()))
                     if row.name == name else row for row in after.commands)
    return replace(collection, firewall_after=replace(after, commands=commands))


def _linode_fixture(monkeypatch):
    raw, expected, outputs = _fixture(monkeypatch)
    identity = LinodeRawHostIdentity(raw.identity.manifest_sha256, raw.identity.chain_id,
        raw.identity.terraform_address, raw.identity.provider_instance_id, "linode/ubuntu24.04",
        raw.identity.region, raw.identity.public_ipv4, raw.identity.hostname, raw.identity.boot_id,
        raw.surface.ssh_connection, raw.identity.invocation_id,
        raw.identity.core_known_hosts_sha256, raw.identity.sketch_known_hosts_sha256)
    outputs = dict(outputs)
    outputs["ufw_defaults"] = outputs["ufw_defaults"].replace("IPV6=yes", "IPV6=no")
    outputs["ip6tables_save"] = ("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n"
        ":OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n"
        "-A OUTPUT -o lo -j ACCEPT\nCOMMIT\n")
    nft = json.loads(outputs["nft_ruleset"])
    for entry in nft["nftables"]:
        chain = entry.get("chain", {})
        if chain.get("family") == "ip6" and chain.get("name") == "OUTPUT":
            chain["policy"] = "drop"
    for chain, key in (("INPUT", "iifname"), ("OUTPUT", "oifname")):
        nft["nftables"].append({"rule": {"family": "ip6", "table": "filter",
            "chain": chain, "handle": 10 if chain == "INPUT" else 11,
            "expr": [{"match": {"left": {"meta": {"key": key}},
                                "op": "==", "right": "lo"}},
                     {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}})
    outputs["nft_ruleset"] = json.dumps(nft)
    for name in ("ufw_defaults", "ip6tables_save", "nft_ruleset"):
        raw = _replace_output(raw, name, outputs[name])
        raw = _replace_after_output(raw, name, outputs[name])
    baseline = dict(policy._BASELINE)
    for name in ("ufw_defaults", "ip6tables_save", "nft_ruleset"):
        if name == "nft_ruleset":
            normalized = json.dumps(policy._normal_nft(nft, PREDECESSOR), sort_keys=True, separators=(",", ":"))
        elif name.endswith("tables_save"):
            normalized = policy._normal_save(outputs[name], PREDECESSOR)
        else:
            normalized = policy._normal_ip(outputs[name], PREDECESSOR)
        baseline[name] = _sha(normalized)
    monkeypatch.setattr(policy, "_LINODE_BASELINE", baseline)
    return LinodeRawHostCollection(identity, raw), expected, outputs


def _verify_linode(collection, expected):
    return policy.interpret_linode_host_policy(collection, expected_identity=collection.identity,
        expected_predecessor_ipv4=PREDECESSOR, expected_policy=expected)


def test_linode_explicit_profile_preserves_digitalocean_default(monkeypatch):
    collection, expected, _ = _linode_fixture(monkeypatch)
    result = _verify_linode(collection, expected)
    assert "linode" in result.profile
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(collection.raw, expected)


def test_linode_metadata_and_surface_may_use_different_ssh_source_ports(monkeypatch):
    collection, expected, _ = _linode_fixture(monkeypatch)
    identity = replace(collection.identity, ssh_connection=(PREDECESSOR, 51001,
                        collection.identity.public_ipv4, 22))
    assert "linode" in _verify_linode(replace(collection, identity=identity), expected).profile
    for port in (0, 65536, "50000"):
        surface = replace(collection.raw.surface, ssh_connection=(PREDECESSOR, port,
                          identity.public_ipv4, 22))
        with pytest.raises(policy.HostPolicyInterpretationError):
            _verify_linode(replace(collection, identity=identity,
                raw=replace(collection.raw, surface=surface)), expected)
    for connection in (("192.0.2.8", 51001, identity.public_ipv4, 22),
                       (PREDECESSOR, 51001, "198.51.100.99", 22),
                       (PREDECESSOR, 51001, identity.public_ipv4, 2222),
                       (PREDECESSOR, 0, identity.public_ipv4, 22)):
        with pytest.raises(policy.HostPolicyInterpretationError):
            _verify_linode(replace(collection, identity=replace(identity,
                ssh_connection=connection)), expected)


@pytest.mark.parametrize("name,mutation", [
    ("iptables_save", lambda x: x.replace("--dport 22", "--dport 2222")),
    ("ip6tables_save", lambda x: x.replace(":OUTPUT DROP", ":OUTPUT ACCEPT")),
    ("ufw_defaults", lambda x: x.replace("IPV6=no", "IPV6=yes")),
])
def test_linode_rejects_changed_firewall_profile(monkeypatch, name, mutation):
    collection, expected, outputs = _linode_fixture(monkeypatch)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(replace(collection, raw=_replace_output(collection.raw, name,
                             mutation(outputs[name]))), expected)


def test_linode_disabled_ipv6_allows_only_loopback(monkeypatch):
    collection, expected, outputs = _linode_fixture(monkeypatch)
    widened = outputs["ip6tables_save"].replace("-A INPUT -i lo -j ACCEPT",
        "-A INPUT -i eth0 -j ACCEPT")
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(replace(collection, raw=_replace_output(collection.raw,
            "ip6tables_save", widened)), expected)
    nft = json.loads(outputs["nft_ruleset"])
    next(item["rule"] for item in nft["nftables"]
         if "rule" in item and item["rule"].get("family") == "ip6")["expr"][0]["match"]["right"] = "eth0"
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(replace(collection, raw=_replace_output(collection.raw,
            "nft_ruleset", json.dumps(nft))), expected)


def test_linode_rejects_identity_predecessor_boot_and_sequence_drift(monkeypatch):
    collection, expected, _ = _linode_fixture(monkeypatch)
    altered = replace(collection, identity=replace(collection.identity, hostname="other"))
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(altered, expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(replace(collection, identity=replace(collection.identity,
            image="linode/ubuntu22.04")), expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        policy.interpret_linode_host_policy(collection, expected_identity=collection.identity,
            expected_predecessor_ipv4="192.0.2.8", expected_policy=expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(replace(collection, raw=replace(collection.raw,
            firewall_after=replace(collection.raw.firewall_after, boot_id="other"))), expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify_linode(replace(collection, raw=replace(collection.raw,
            firewall_before=replace(collection.raw.firewall_before,
                commands=collection.raw.firewall_before.commands[::-1]))), expected)


def test_synthetic_fresh_ssh_only_profile(monkeypatch):
    collection, expected, _ = _fixture(monkeypatch)
    assert _verify(collection, expected).predecessor_ipv4 == PREDECESSOR


@pytest.mark.parametrize("name,mutator", [
    ("iptables_save", lambda x: x.replace("*filter", "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n*filter")),
    ("ip6tables_save", lambda x: x.replace("COMMIT", "-A ufw6-user-input -j ACCEPT\nCOMMIT")),
    ("iptables_save", lambda x: x.replace("-A INPUT -j ufw-before-input", "-A INPUT -j ACCEPT\n-A INPUT -j ufw-before-input")),
    ("ufw_status_verbose", lambda x: x + "443/tcp ALLOW OUT Anywhere\n"),
])
def test_dangerous_active_drift_fails(monkeypatch, name, mutator):
    collection, expected, outputs = _fixture(monkeypatch)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(_replace_output(collection, name, mutator(outputs[name])), expected)


@pytest.mark.parametrize("mutator", [
    lambda x: x["nftables"].append({"flowtable": {"family": "ip", "name": "bypass"}}),
    lambda x: x["nftables"].append({"chain": {"family": "ip", "table": "filter", "name": "early", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}}),
    lambda x: x["nftables"][-1]["rule"]["expr"][2]["counter"].update({"hidden": 1}),
])
def test_nft_bypass_or_unknown_counter_fails(monkeypatch, mutator):
    collection, expected, outputs = _fixture(monkeypatch)
    nft = json.loads(outputs["nft_ruleset"])
    mutator(nft)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(_replace_output(collection, "nft_ruleset", json.dumps(nft)), expected)


def test_identity_timing_and_expected_policy_are_independent(monkeypatch):
    collection, expected, _ = _fixture(monkeypatch)
    with pytest.raises(policy.HostPolicyInterpretationError):
        policy.interpret_digitalocean_host_policy(collection,
            expected_identity=replace(collection.identity, hostname="different"),
            expected_predecessor_ipv4=PREDECESSOR, expected_policy=expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(replace(collection, firewall_after=replace(collection.firewall_after, started_at_ns=101)), expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(collection, {**expected, "sketch_firewall_v2_rules": [{"from_ip": "0.0.0.0/0", "port": 443, "proto": "tcp"}]})


def test_missing_or_tampered_capture_fails(monkeypatch):
    collection, expected, _ = _fixture(monkeypatch)
    before = collection.firewall_before
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(replace(collection, firewall_before=replace(before, commands=before.commands[:-1])), expected)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(replace(collection, firewall_before=replace(before,
            commands=(replace(before.commands[0], sha256="0" * 64),) + before.commands[1:])), expected)


def test_persisted_user_rule_mutation_fails(monkeypatch):
    collection, expected, outputs = _fixture(monkeypatch)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(_replace_output(collection, "ufw_user_rules",
            outputs["ufw_user_rules"].replace("192.0.2.7/32", "0.0.0.0/0")), expected)


def test_after_snapshot_status_mutation_fails(monkeypatch):
    collection, expected, outputs = _fixture(monkeypatch)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(_replace_after_output(collection, "ufw_status_verbose",
            outputs["ufw_status_verbose"] + "443/tcp ALLOW IN Anywhere\n"), expected)


def test_reordered_input_jumps_fail(monkeypatch):
    collection, expected, outputs = _fixture(monkeypatch)
    original = "-A INPUT -j ufw-before-input\n-A INPUT -j ufw-after-input"
    reversed_order = "-A INPUT -j ufw-after-input\n-A INPUT -j ufw-before-input"
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(_replace_output(collection, "iptables_save",
            outputs["iptables_save"].replace(original, reversed_order)), expected)


# Literal UFW0.36.2 formatter forms, reviewed against official Ubuntu upstream
# ufw_0.36.2.orig.tar.gz src/{common,backend_iptables}.py. The historical private
# capture confirms persisted tuple and nft payload spelling for the SSH baseline.
# These channel fixtures deliberately do not call the implementation's renderer.
_CHANNELS = [
    {"from_ip": "0.0.0.0/0", "port": 443, "proto": "tcp"},
    {"from_ip": "192.0.2.8/32", "port": 5353, "proto": "udp"},
    {"from_ip": "198.51.100.0/24", "port": 8443, "proto": "tcp"},
]


def _channel_outputs(outputs):
    outputs = dict(outputs)
    outputs["ufw_status_verbose"] += ("443/tcp ALLOW IN Anywhere\n"
        "5353/udp ALLOW IN 192.0.2.8\n8443/tcp ALLOW IN 198.51.100.0/24\n")
    outputs["ufw_user_rules"] += (
        "\n### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n"
        "-A ufw-user-input -p tcp --dport 443 -j ACCEPT\n"
        "\n### tuple ### allow udp 5353 0.0.0.0/0 any 192.0.2.8 in\n"
        "-A ufw-user-input -p udp --dport 5353 -s 192.0.2.8 -j ACCEPT\n"
        "\n### tuple ### allow tcp 8443 0.0.0.0/0 any 198.51.100.0/24 in\n"
        "-A ufw-user-input -p tcp --dport 8443 -s 198.51.100.0/24 -j ACCEPT\n")
    outputs["iptables_save"] = outputs["iptables_save"].replace("COMMIT\n",
        "-A ufw-user-input -p tcp -m tcp --dport 443 -j ACCEPT\n"
        "-A ufw-user-input -s 192.0.2.8/32 -p udp -m udp --dport 5353 -j ACCEPT\n"
        "-A ufw-user-input -s 198.51.100.0/24 -p tcp -m tcp --dport 8443 -j ACCEPT\nCOMMIT\n")
    nft = json.loads(outputs["nft_ruleset"])
    for source, protocol, port in [(None, "tcp", 443), ("192.0.2.8", "udp", 5353),
        ({"prefix": {"addr": "198.51.100.0", "len": 24}}, "tcp", 8443)]:
        expr = []
        if source is not None:
            expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                   "right": source}})
        expr.extend([{"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}},
                                "right": port}}, {"counter": {"packets": 12, "bytes": 100}}, {"accept": None}])
        nft["nftables"].append({"rule": {"family": "ip", "table": "filter", "chain": "ufw-user-input",
                                       "handle": port, "expr": expr}})
    outputs["nft_ruleset"] = json.dumps(nft)
    return outputs


def _dynamic_fixture(monkeypatch, provider):
    collection, expected, outputs = (_fixture(monkeypatch) if provider == "do" else _linode_fixture(monkeypatch))
    raw = collection if provider == "do" else collection.raw
    changed = _channel_outputs(outputs)
    for name in changed:
        raw = _replace_output(raw, name, changed[name])
        raw = _replace_after_output(raw, name, changed[name])
    collection = raw if provider == "do" else replace(collection, raw=raw)
    expected["sketch_firewall_v2_rules"] = [dict(rule) for rule in _CHANNELS]
    return collection, expected, changed


def _dynamic_verify(collection, expected, provider):
    return _verify(collection, expected) if provider == "do" else _verify_linode(collection, expected)


@pytest.mark.parametrize("provider", ["do", "linode"])
def test_exact_reviewed_channels_on_all_four_surfaces(monkeypatch, provider):
    collection, expected, _ = _dynamic_fixture(monkeypatch, provider)
    assert _dynamic_verify(collection, expected, provider).predecessor_ipv4 == PREDECESSOR
    with pytest.raises(policy.HostPolicyInterpretationError):
        _dynamic_verify(collection, {**expected, "sketch_firewall_v2_rules": []}, provider)


@pytest.mark.parametrize("provider", ["do", "linode"])
@pytest.mark.parametrize("surface", ["ufw_status_verbose", "ufw_user_rules", "iptables_save", "nft_ruleset"])
@pytest.mark.parametrize("snapshot", ["before", "after"])
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra"])
def test_reviewed_channels_fail_closed_per_surface(monkeypatch, provider, surface, snapshot, mutation):
    collection, expected, outputs = _dynamic_fixture(monkeypatch, provider)
    raw = collection if provider == "do" else collection.raw
    value = outputs[surface]
    if surface == "nft_ruleset":
        document = json.loads(value)
        dynamic = document["nftables"][-1]
        if mutation == "missing":
            document["nftables"].pop()
        else:
            duplicate = json.loads(json.dumps(dynamic))
            if mutation == "extra":
                duplicate["rule"]["expr"][1]["match"]["right"] = 9999
            document["nftables"].append(duplicate)
        value = json.dumps(document)
    else:
        literal = {"ufw_status_verbose": "443/tcp ALLOW IN Anywhere\n",
            "ufw_user_rules": "\n### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 443 -j ACCEPT\n",
            "iptables_save": "-A ufw-user-input -p tcp -m tcp --dport 443 -j ACCEPT\n"}[surface]
        value = value.replace(literal, "", 1) if mutation == "missing" else value + (
            literal if mutation == "duplicate" else literal.replace("443", "9999"))
    raw = (_replace_output if snapshot == "before" else _replace_after_output)(raw, surface, value)
    collection = raw if provider == "do" else replace(collection, raw=raw)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _dynamic_verify(collection, expected, provider)


@pytest.mark.parametrize("counter", [{"packets": -1, "bytes": 1}, {"packets": 1}, True])
def test_removed_channel_nft_counters_remain_validated(monkeypatch, counter):
    collection, expected, outputs = _dynamic_fixture(monkeypatch, "do")
    nft = json.loads(outputs["nft_ruleset"])
    nft["nftables"][-1]["rule"]["expr"][-2]["counter"] = counter
    collection = _replace_output(collection, "nft_ruleset", json.dumps(nft))
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(collection, expected)


@pytest.mark.parametrize("bad", [
    {"from_ip": "::/0", "port": 443, "proto": "tcp"},
    {"from_ip": "192.0.2.8", "port": 443, "proto": "tcp"},
    {"from_ip": "192.0.2.8/32", "port": 22, "proto": "tcp"},
    {"from_ip": "192.0.2.8/32", "port": True, "proto": "tcp"},
    {"from_ip": "192.0.2.8/32", "port": 443, "proto": "icmp"},
])
def test_invalid_independently_reviewed_channel_intent(monkeypatch, bad):
    collection, expected, _ = _dynamic_fixture(monkeypatch, "do")
    expected["sketch_firewall_v2_rules"] = [bad]
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(collection, expected)


@pytest.mark.parametrize("provider", ["do", "linode"])
@pytest.mark.parametrize("mutation", ["v6", "handle", "nested", "ssh", "raw", "persisted_order"])
def test_channels_preserve_integrity_ipv6_ssh_and_persisted_stability(monkeypatch, provider, mutation):
    collection, expected, outputs = _dynamic_fixture(monkeypatch, provider)
    raw = collection if provider == "do" else collection.raw
    if mutation in {"v6", "handle", "nested"}:
        nft = json.loads(outputs["nft_ruleset"])
        rule = nft["nftables"][-1]["rule"]
        if mutation == "v6":
            rule["family"] = "ip6"
        elif mutation == "handle":
            rule["handle"] = -1
        else:
            rule["expr"][0]["match"]["handle"] = 1
        raw = _replace_output(raw, "nft_ruleset", json.dumps(nft))
    elif mutation == "ssh":
        raw = _replace_output(raw, "iptables_save", outputs["iptables_save"].replace("--dport 22 ", "--dport 23 "))
    elif mutation == "raw":
        before = raw.firewall_before
        raw = replace(raw, firewall_before=replace(before, commands=tuple(
            replace(row, sha256="0" * 64) if row.name == "ufw_user_rules" else row
            for row in before.commands)))
    else:
        # Each snapshot independently leaves the same exact baseline; the raw
        # persisted file must nevertheless be stable across the surface probe.
        blocks = outputs["ufw_user_rules"].split("\n### tuple ###")
        reordered = blocks[0] + "\n### tuple ###" + "\n### tuple ###".join(reversed(blocks[1:]))
        raw = _replace_after_output(raw, "ufw_user_rules", reordered)
    collection = raw if provider == "do" else replace(collection, raw=raw)
    with pytest.raises(policy.HostPolicyInterpretationError):
        _dynamic_verify(collection, expected, provider)


def test_duplicate_reviewed_intent_is_rejected(monkeypatch):
    collection, expected, _ = _dynamic_fixture(monkeypatch, "do")
    expected["sketch_firewall_v2_rules"].append(dict(_CHANNELS[0]))
    with pytest.raises(policy.HostPolicyInterpretationError):
        _verify(collection, expected)
