# Copyright (c) 2026, Oracle and/or its affiliates.
"""Synthetic observed host surfaces; no private host data or keys are stored."""

import base64
import hashlib
import struct
from dataclasses import replace

import pytest

from app.services import provider_keyed_host_surface_interpreter as interp
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawFirewallEvidence,
    DigitalOceanRawHostCollection, DigitalOceanRawHostSurfaceEvidence,
)
from app.services.provider_keyed_mixed_linode_host_probe import LinodeRawHostCollection, LinodeRawHostIdentity

SOURCE = "192.0.2.7"
PUBLIC = "198.51.100.3"


def _key(byte):
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes([byte]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def _fixture(monkeypatch, role="middle"):
    identity = DigitalOceanHostIdentityEvidence("a" * 64, "chain", "address", "123", "region",
        PUBLIC, "host", "00000000-0000-0000-0000-000000000001", "alias", "identity", "b" * 64, "c" * 64)
    admin, transport = _key(1), _key(2)
    security = ("usedns no\npubkeyauthentication yes\npasswordauthentication no\n"
        "kbdinteractiveauthentication no\nhostbasedauthentication no\ngssapiauthentication no\n"
        "permitemptypasswords no\nstrictmodes yes\n"
        "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"
        "gatewayports {gateway}\nallowtcpforwarding {forward}\npermitopen any\n"
        "forcecommand none\ndisableforwarding no\n")
    user_sshd = security.format(gateway="no", forward="yes")
    sketch_sshd = security.format(gateway="no" if role == "middle" else "yes",
                                  forward="local" if role == "middle" else "yes")
    monkeypatch.setattr(interp, "_SSHD_BASELINE", {"user": interp._sha(user_sshd),
        role + "_sketchssh": interp._sha(sketch_sshd)})
    processes = {"sshd": 'users:(("sshd",pid=10,fd=3),("systemd",pid=1,fd=4))',
                 "nginx": 'users:(("nginx",pid=11,fd=3))',
                 "dns": 'users:(("systemd-resolve",pid=12,fd=3))'}
    def row(proto, state, local, remote, process):
        return f"{proto} {state} 0 0 {local} {remote} {processes[process]}\n"
    listeners = "".join((
        row("tcp", "LISTEN", "0.0.0.0:22", "0.0.0.0:*", "sshd"),
        row("tcp", "LISTEN", "[::]:22", "[::]:*", "sshd"),
        row("tcp", "LISTEN", "0.0.0.0:80", "0.0.0.0:*", "nginx"),
        row("tcp", "LISTEN", "[::]:80", "[::]:*", "nginx"),
        row("tcp", "LISTEN", "127.0.0.53%lo:53", "0.0.0.0:*", "dns"),
        row("tcp", "LISTEN", "127.0.0.54:53", "0.0.0.0:*", "dns"),
        row("udp", "UNCONN", "127.0.0.53%lo:53", "0.0.0.0:*", "dns"),
        row("udp", "UNCONN", "127.0.0.54:53", "0.0.0.0:*", "dns"),
    ))
    def firewall(invocation, started):
        return DigitalOceanRawFirewallEvidence(identity, invocation, identity.boot_id,
                                               started, started + 1, (), ())
    surface = DigitalOceanRawHostSurfaceEvidence(identity, "surface", identity.boot_id, 103, 104,
        SOURCE, (SOURCE, 50000, PUBLIC, 22),
        (("user", admin + " comment\n", 1000, 1000, 0o600),
         ("sketchssh", transport + "\n", 1001, 1001, 0o600)),
        (("user", user_sshd), ("sketchssh", sketch_sshd)), listeners)
    collection = DigitalOceanRawHostCollection(identity, firewall("before", 100), surface,
                                                firewall("after", 105))
    expected_policy = {"sketch_firewall_v2_enabled": True,
                       "sketch_firewall_v2_ssh_sources": [SOURCE + "/32"],
                       "sketch_firewall_v2_rules": []}
    return collection, expected_policy, interp._sha(admin), interp._sha(transport)


def _verify(collection, expected, admin, transport, role="middle"):
    return interp.interpret_digitalocean_host_surface(collection, expected_identity=collection.identity,
        expected_predecessor_ipv4=SOURCE, expected_role=role,
        expected_admin_key_sha256=admin, expected_transport_key_sha256=transport,
        expected_policy=expected)


def _linode_fixture(monkeypatch, role="middle"):
    raw, expected, admin, transport = _fixture(monkeypatch, role=role)
    identity = LinodeRawHostIdentity(raw.identity.manifest_sha256, raw.identity.chain_id,
        raw.identity.terraform_address, raw.identity.provider_instance_id, "linode/ubuntu24.04",
        raw.identity.region, raw.identity.public_ipv4, raw.identity.hostname, raw.identity.boot_id,
        raw.surface.ssh_connection, raw.identity.invocation_id,
        raw.identity.core_known_hosts_sha256, raw.identity.sketch_known_hosts_sha256)
    listeners = "".join(line for line in raw.surface.listeners_raw.splitlines(keepends=True)
                        if "127.0.0.5" not in line)
    listeners += ('tcp ESTAB 0 0 198.51.100.3:22 192.0.2.7:50000 '
                  'users:(("sshd",pid=10,fd=5))\n')
    raw = replace(raw, surface=replace(raw.surface, listeners_raw=listeners))
    raw = _versioned_proof(raw)
    return LinodeRawHostCollection(identity, raw), expected, admin, transport


def _verify_linode(collection, expected, admin, transport, role="middle"):
    return interp.interpret_linode_host_surface(collection, expected_identity=collection.identity,
        expected_predecessor_ipv4=SOURCE, expected_role=role,
        expected_admin_key_sha256=admin, expected_transport_key_sha256=transport,
        expected_policy=expected)


def test_linode_requires_exact_four_listeners_and_remains_unpublished(monkeypatch):
    collection, expected, admin, transport = _linode_fixture(monkeypatch)
    result = _verify_linode(collection, expected, admin, transport)
    assert len(result.listeners) == 5
    assert result.complete_ssh_policy is True
    assert result.publication_eligible is False
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(collection.raw, expected, admin, transport)
    for extra in ('tcp LISTEN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=12,fd=3))\n',
                  'tcp LISTEN 0 0 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=11,fd=3))\n'):
        altered = replace(collection, raw=replace(collection.raw, surface=replace(collection.raw.surface,
            listeners_raw=collection.raw.surface.listeners_raw + extra)))
        with pytest.raises(interp.HostSurfaceInterpretationError):
            _verify_linode(altered, expected, admin, transport)


def test_linode_surface_session_is_bound_independently_of_metadata_port(monkeypatch):
    collection, expected, admin, transport = _linode_fixture(monkeypatch)
    source, _, target, port = collection.identity.ssh_connection
    changed = replace(collection, identity=replace(collection.identity,
        ssh_connection=(source, 51001, target, port)))
    assert _verify_linode(changed, expected, admin, transport).complete_ssh_policy
    for connection in (("192.0.2.8", 51001, target, port),
                       (source, 51001, "198.51.100.99", port),
                       (source, 0, target, port)):
        with pytest.raises(interp.HostSurfaceInterpretationError):
            _verify_linode(replace(changed, identity=replace(changed.identity,
                ssh_connection=connection)), expected, admin, transport)


def test_linode_requires_one_selected_management_session_and_no_resolver_session(monkeypatch):
    collection, expected, admin, transport = _linode_fixture(monkeypatch)
    raw = collection.raw.surface.listeners_raw
    management = ('tcp ESTAB 0 0 198.51.100.3:22 192.0.2.7:50000 '
                  'users:(("sshd",pid=10,fd=5))\n')
    assert raw.count(management) == 1
    for changed in (raw.replace(management, ""), raw + management,
                    raw.replace("192.0.2.7:50000", "192.0.2.7:50001"),
                    raw + ('udp ESTAB 0 0 198.51.100.3:60000 1.1.1.1:53 '
                           'users:(("systemd-resolve",pid=12,fd=3))\n')):
        altered = replace(collection, raw=replace(collection.raw,
            surface=replace(collection.raw.surface, listeners_raw=changed)))
        with pytest.raises(interp.HostSurfaceInterpretationError):
            _verify_linode(altered, expected, admin, transport)


def test_linode_requires_pinned_image_and_complete_versioned_ssh_proof(monkeypatch):
    collection, expected, admin, transport = _linode_fixture(monkeypatch)
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify_linode(replace(collection, identity=replace(collection.identity,
            image="linode/ubuntu22.04")), expected, admin, transport)
    surface = collection.raw.surface
    for changed in (replace(surface, ssh_proof_version=None, ssh_proof=None),
                    replace(surface, ssh_proof_version=2),
                    replace(surface, ssh_proof={**surface.ssh_proof, "environment_file":
                        "SSHD_OPTS=-f /tmp/alternate\n"})):
        with pytest.raises(interp.HostSurfaceInterpretationError):
            _verify_linode(replace(collection, raw=replace(collection.raw, surface=changed)),
                           expected, admin, transport)


def test_linode_rejects_key_sshd_boot_and_order_drift(monkeypatch):
    collection, expected, admin, transport = _linode_fixture(monkeypatch)
    surface = collection.raw.surface
    mutations = [
        replace(collection.raw, surface=replace(surface, boot_id="other")),
        replace(collection.raw, surface=replace(surface, started_at_ns=50)),
        replace(collection.raw, surface=replace(surface,
            accounts=(("user", _key(4) + "\n", 1000, 1000, 0o600), surface.accounts[1]))),
        replace(collection.raw, surface=replace(surface,
            effective_sshd=(("user", surface.effective_sshd[0][1].replace(
                "passwordauthentication no", "passwordauthentication yes")), surface.effective_sshd[1]))),
    ]
    for raw in mutations:
        with pytest.raises(interp.HostSurfaceInterpretationError):
            _verify_linode(replace(collection, raw=raw), expected, admin, transport)


def test_observed_context_is_explicitly_not_publication_proof(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    result = _verify(collection, policy, admin, transport)
    assert result.observed_context_verified
    assert result.complete_ssh_policy is False
    assert result.publication_eligible is False
    assert result.alternate_keys_absent_observed is False
    assert len(result.listeners) == 8
    assert result.user_key_sha256 == frozenset({admin})
    assert result.sketchssh_key_sha256 == frozenset({transport})


def test_extra_unrelated_key_is_reported_without_claiming_readiness(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    surface = collection.surface
    extra = _key(3)
    user = surface.accounts[0]
    amended = replace(collection, surface=replace(surface,
        accounts=((user[0], user[1] + extra + "\n", *user[2:]), surface.accounts[1])))
    result = _verify(amended, policy, admin, transport)
    assert len(result.user_key_sha256) == 2
    assert result.publication_eligible is False


@pytest.mark.parametrize("mutation", [
    lambda c: replace(c, surface=replace(c.surface, boot_id="different")),
    lambda c: replace(c, surface=replace(c.surface, started_at_ns=50)),
    lambda c: replace(c, surface=replace(c.surface,
        ssh_connection=("203.0.113.8", 50000, PUBLIC, 22))),
    lambda c: replace(c, surface=replace(c.surface,
        accounts=(("user", _key(4) + "\n", 1000, 1000, 0o600), c.surface.accounts[1]))),
    lambda c: replace(c, surface=replace(c.surface,
        accounts=(("user", c.surface.accounts[0][1], 1000, 1000, 0o644), c.surface.accounts[1]))),
    lambda c: replace(c, surface=replace(c.surface,
        listeners_raw=c.surface.listeners_raw + 'tcp LISTEN 0 0 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=11,fd=3))\n')),
    lambda c: replace(c, surface=replace(c.surface,
        listeners_raw=c.surface.listeners_raw.replace('0.0.0.0:22', '0.0.0.0:2222', 1))),
])
def test_identity_key_or_listener_drift_rejected(monkeypatch, mutation):
    collection, policy, admin, transport = _fixture(monkeypatch)
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(mutation(collection), policy, admin, transport)


def test_password_authentication_change_rejected(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    surface = collection.surface
    user = surface.effective_sshd[0]
    changed = (user[0], user[1].replace("passwordauthentication no", "passwordauthentication yes"))
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(replace(collection, surface=replace(surface,
            effective_sshd=(changed, surface.effective_sshd[1]))), policy, admin, transport)


def test_transient_sessions_not_required(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch, role="edge")
    assert len(_verify(collection, policy, admin, transport, role="edge").listeners) == 8


def test_inert_time_wait_rows_do_not_obscure_required_listeners(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    time_wait = ("tcp TIME-WAIT 0 0 198.51.100.3:80 203.0.113.8:49152\n"
                 "tcp TIME-WAIT 0 0 [2001:db8::1]:80 [2001:db8::2]:49153\n")
    raw = collection.surface.listeners_raw
    amended = replace(collection, surface=replace(collection.surface, listeners_raw=raw + time_wait))
    result = _verify(amended, policy, admin, transport)
    assert len(result.listeners) == 10
    assert [(row.protocol, row.state, row.process_names) for row in result.listeners[-2:]] == [
        ("tcp", "TIME-WAIT", ()), ("tcp", "TIME-WAIT", ())]

    missing_listener = amended.surface.listeners_raw.replace(
        'tcp LISTEN 0 0 [::]:80 [::]:* users:(("nginx",pid=11,fd=3))\n', "")
    with pytest.raises(interp.HostSurfaceInterpretationError, match="complete fresh-host listening"):
        _verify(replace(amended, surface=replace(amended.surface,
            listeners_raw=missing_listener)), policy, admin, transport)


@pytest.mark.parametrize("row", [
    "tcp TIME-WAIT 1 0 198.51.100.3:80 203.0.113.8:49152\n",
    "tcp TIME-WAIT 0 1 198.51.100.3:80 203.0.113.8:49152\n",
    "tcp TIME-WAIT 0 0 198.51.100.3:80 203.0.113.8:49152 users:((\"nginx\",pid=11,fd=3))\n",
    "udp TIME-WAIT 0 0 198.51.100.3:80 203.0.113.8:49152\n",
    "tcp TIME-WAIT 0 0 198.51.100.3:80 *:*\n",
    "tcp TIME-WAIT 0 0 198.51.100.3:80 203.0.113.8:*\n",
    "tcp TIME-WAIT 0 0 0.0.0.0:* 203.0.113.8:49152\n",
])
def test_time_wait_accepts_only_inert_canonical_tcp_rows(monkeypatch, row):
    collection, policy, admin, transport = _fixture(monkeypatch)
    amended = replace(collection, surface=replace(collection.surface,
        listeners_raw=collection.surface.listeners_raw + row))
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(amended, policy, admin, transport)


def test_time_wait_does_not_relax_active_session_check(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    raw = (collection.surface.listeners_raw
        + "tcp TIME-WAIT 0 0 198.51.100.3:80 203.0.113.8:49152\n"
        + 'tcp ESTAB 0 0 198.51.100.3:22 203.0.113.8:49153 users:(("sshd",pid=10,fd=5))\n')
    with pytest.raises(interp.HostSurfaceInterpretationError, match="established management SSH"):
        _verify(replace(collection, surface=replace(collection.surface, listeners_raw=raw)),
                policy, admin, transport)


def test_new_alternate_key_absence_marker_is_observed_but_not_complete_policy(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    surface = replace(collection.surface, alternate_authorized_keys_absent=("user", "sketchssh"))
    result = _verify(replace(collection, surface=surface), policy, admin, transport)
    assert result.alternate_keys_absent_observed is True
    assert result.complete_ssh_policy is False
    assert result.publication_eligible is False
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(replace(collection, surface=replace(surface,
            alternate_authorized_keys_absent=("user",))), policy, admin, transport)


def _versioned_proof(collection):
    service = {
        "MainPID": "10", "ActiveState": "active", "SubState": "running",
        "ExecStart": "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no ; }",
        "EnvironmentFiles": "/etc/default/ssh", "Environment": "",
        "FragmentPath": "/usr/lib/systemd/system/ssh.service", "DropInPaths": "",
    }
    proof = {"service": service, "socket": "ActiveState=active\nListen=[::]:22 (Stream)\n",
             "pid": 10, "start_ticks": 5000, "boot_epoch_s": 100,
             "clock_ticks_per_second": 100, "birth_wall_ns": 150_000_000_000,
             "cmdline": ["sshd -D [listener] 0 of 10-100 startups"],
             "exe": "/usr/sbin/sshd", "environment_file": "# ssh options\nSSHD_OPTS=\n",
             "environment_changed_ns": 100_000_000_000,
             "unit_file": ["/usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n", 100_000_000_000],
             "directory_changed_ns": [["/etc/ssh", 100_000_000_000],
                                      ["/etc/ssh/sshd_config.d", 100_000_000_000]],
             "configuration": [["/etc/ssh/sshd_config",
                 "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n", 100_000_000_000],
                ["/etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf",
                 "Match User sketchssh\n    AllowTcpForwarding local\n", 100_000_000_000]]}
    surface = replace(collection.surface, alternate_authorized_keys_absent=("user", "sketchssh"),
                      ssh_proof_version=1, ssh_proof=proof)
    return replace(collection, surface=surface)


def test_versioned_daemon_proof_completes_only_ssh_gate(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    versioned = _versioned_proof(collection)
    result = _verify(versioned, policy, admin, transport)
    assert result.complete_ssh_policy is True
    assert result.publication_eligible is False
    user = versioned.surface.accounts[0]
    extra = _key(3)
    with_extra = replace(versioned, surface=replace(versioned.surface,
        accounts=((user[0], user[1] + extra + "\n", *user[2:]), versioned.surface.accounts[1])))
    assert len(_verify(with_extra, policy, admin, transport).user_key_sha256) == 2


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(service={**p["service"], "ExecStart":
        p["service"]["ExecStart"] + " -o PasswordAuthentication=yes"}),
    lambda p: p.update(service={**p["service"], "MainPID": "11"}),
    lambda p: p.update(configuration=[p["configuration"][0],
        ["/etc/ssh/sshd_config.d/90-barragan-sketch-forwarding.conf", "Match RDomain corp\n", 100_000_000_000]]),
    lambda p: p.update(configuration=[["/etc/ssh/sshd_config", "Include /tmp/custom.conf\n", 100_000_000_000]]),
    lambda p: p.update(environment_file="SSHD_OPTS=-f /tmp/alternate\n"),
    lambda p: p.update(cmdline=["sshd -D -f /tmp/alternate"]),
    lambda p: p.update(socket="ActiveState=inactive\nListen=[::]:22 (Stream)\n"),
    lambda p: p.update(configuration=[p["configuration"][0],
        [*p["configuration"][1][:2], 149_000_000_000]]),
    lambda p: p.update(environment_changed_ns=150_000_000_000),
    lambda p: p.update(unit_file=[*p["unit_file"][:2], 150_000_000_000]),
    lambda p: p.update(directory_changed_ns=[["/etc/ssh", 100_000_000_000],
        ["/etc/ssh/sshd_config.d", 150_000_000_000]]),
])
def test_versioned_daemon_override_or_unknown_config_rejected(monkeypatch, mutate):
    collection, policy, admin, transport = _fixture(monkeypatch)
    versioned = _versioned_proof(collection)
    proof = dict(versioned.surface.ssh_proof)
    mutate(proof)
    changed = replace(versioned, surface=replace(versioned.surface, ssh_proof=proof))
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(changed, policy, admin, transport)


@pytest.mark.parametrize("garbage", ["prefix", "suffix"])
def test_socket_process_field_rejects_unparsed_text(monkeypatch, garbage):
    collection, policy, admin, transport = _fixture(monkeypatch)
    raw = collection.surface.listeners_raw
    marker = 'users:(("nginx",pid=11,fd=3))'
    altered = (garbage + marker) if garbage == "prefix" else (marker + garbage)
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(replace(collection, surface=replace(collection.surface,
            listeners_raw=raw.replace(marker, altered, 1))), policy, admin, transport)


@pytest.mark.parametrize('state', sorted(interp._TCP_LIFECYCLE_STATES))
@pytest.mark.parametrize('process', ['', ' users:(("python3",pid=12,fd=3))'])
def test_finite_tcp_lifecycle_rows_are_observed_not_listeners(monkeypatch, state, process):
    collection, policy, admin, transport = _fixture(monkeypatch)
    row = f'tcp {state} 0 4294967295 127.0.0.1:40001 127.0.0.1:40002{process}\n'
    amended = replace(collection, surface=replace(collection.surface,
        listeners_raw=collection.surface.listeners_raw + row))
    result = _verify(amended, policy, admin, transport)
    assert result.listeners[-1].state == state
    assert result.listeners[-1].process_names == (('python3',) if process else ())
    missing = amended.surface.listeners_raw.replace(
        'tcp LISTEN 0 0 [::]:80 [::]:* users:(("nginx",pid=11,fd=3))\n', '')
    with pytest.raises(interp.HostSurfaceInterpretationError, match='complete fresh-host'):
        _verify(replace(amended, surface=replace(amended.surface, listeners_raw=missing)),
                policy, admin, transport)


def test_real_linux_loopback_socket_fixture(monkeypatch):
    import json
    from pathlib import Path
    fixture = json.loads((Path(__file__).parent / 'fixtures' / 'provider_keyed_loopback_ss.json').read_text())
    collection, policy, admin, transport = _fixture(monkeypatch)
    amended = replace(collection, surface=replace(collection.surface,
        listeners_raw=collection.surface.listeners_raw + ''.join(fixture['rows'])))
    observed = _verify(amended, policy, admin, transport).listeners[-4:]
    assert [row.state for row in observed] == ['CLOSE-WAIT', 'FIN-WAIT-2', 'FIN-WAIT-2', 'TIME-WAIT']
    assert [row.process_names for row in observed] == [('python3',), ('python3',), (), ()]


@pytest.mark.parametrize('row', [
    'tcp UNKNOWN 0 0 127.0.0.1:1 127.0.0.1:2',
    'udp FIN-WAIT-2 0 0 127.0.0.1:1 127.0.0.1:2',
    *[f'tcp FIN-WAIT-2 {q} 0 127.0.0.1:1 127.0.0.1:2' for q in
      ['-1', '+1', '00', '4294967296', '1.0', '1' * 100]],
    *[f'tcp CLOSE-WAIT 0 0 {a} 127.0.0.1:2' for a in
      ['*:*', '0.0.0.0:1', '[::]:1', '127.00.0.1:1', '127.0.0.1:0',
       '127.0.0.1:65536', '127.0.0.53%lo:1', '[2001:0db8::1]:1', '224.0.0.1:1']],
    'tcp SYN-SENT 0 0 127.0.0.1:1 *:*',
    'tcp SYN-RECV 0 0 127.0.0.1:1 0.0.0.0:2',
    'tcp SYN-RECV 0 0 [::1]:1 127.0.0.1:2',
    'tcp LAST-ACK 0 0 127.0.0.1:1 127.0.0.1:2 users:()',
    'tcp CLOSING 0 0 127.0.0.1:1 127.0.0.1:2 users:(("python3",pid=0,fd=3))',
    'tcp FIN-WAIT-1 0 0 127.0.0.1:1 127.0.0.1:2 users:(("python3",pid=1,fd=3)) extra',
    'tcp FIN-WAIT-1 0 0 127.0.0.1:1 127.0.0.1:2 users:(("python3",pid=1,fd=3),("python3",pid=1,fd=3))',
    'tcp LISTEN 0 0 0.0.0.0:22 0.0.0.0:*',
    'tcp ESTAB 0 0 198.51.100.3:22 203.0.113.8:49153',
])
def test_lifecycle_grammar_rejects_malformed_or_unattributed_active_rows(monkeypatch, row):
    collection, policy, admin, transport = _fixture(monkeypatch)
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(replace(collection, surface=replace(collection.surface,
            listeners_raw=collection.surface.listeners_raw + row + '\n')), policy, admin, transport)


def test_lifecycle_ipv6_does_not_relax_established_ssh_peer(monkeypatch):
    collection, policy, admin, transport = _fixture(monkeypatch)
    lifecycle = 'tcp SYN-SENT 0 0 [2001:db8::1]:49152 [2001:db8::2]:22\n'
    result = _verify(replace(collection, surface=replace(collection.surface,
        listeners_raw=collection.surface.listeners_raw + lifecycle)), policy, admin, transport)
    assert result.listeners[-1].bind_address == '2001:db8::1'
    bad = 'tcp ESTAB 0 0 198.51.100.3:22 203.0.113.8:49153 users:(("sshd",pid=10,fd=5))\n'
    with pytest.raises(interp.HostSurfaceInterpretationError, match='established management SSH'):
        _verify(replace(collection, surface=replace(collection.surface,
            listeners_raw=collection.surface.listeners_raw + lifecycle + bad)), policy, admin, transport)


@pytest.mark.parametrize('state', sorted(interp._TCP_LIFECYCLE_STATES))
def test_lifecycle_cannot_replace_linode_management_session(monkeypatch, state):
    captured, policy, admin, transport = _linode_fixture(monkeypatch)
    raw = captured.raw.surface.listeners_raw
    raw = ''.join(line for line in raw.splitlines(keepends=True) if ' ESTAB ' not in line)
    raw += f'tcp {state} 0 0 198.51.100.3:22 192.0.2.7:50000 users:(("sshd",pid=10,fd=5))\n'
    amended = replace(captured, raw=replace(captured.raw,
        surface=replace(captured.raw.surface, listeners_raw=raw)))
    with pytest.raises(interp.HostSurfaceInterpretationError, match='complete fresh-host'):
        _verify_linode(amended, policy, admin, transport)


_ACTUAL_APPLICATION_ROW = (
    'tcp ESTAB 0 0 143.198.98.178:35300 151.101.202.49:443 '
    'users:(("fwupdmgr",pid=7896,fd=11))\n')
_APPLICATION_ROW = (
    'tcp ESTAB 0 0 198.51.100.3:35300 203.0.113.49:443 '
    'users:(("client",pid=7896,fd=11))\n')


def test_actual_attributed_established_https_row_is_only_an_observation(monkeypatch):
    collection, _, _, _ = _fixture(monkeypatch)
    raw = collection.surface.listeners_raw + _ACTUAL_APPLICATION_ROW
    observed = interp._listeners(raw, SOURCE, '143.198.98.178')
    assert observed[-1] == interp.ObservedListener(
        'tcp', 'ESTAB', '143.198.98.178', 35300, ('fwupdmgr',))


@pytest.mark.parametrize('provider', ['digitalocean', 'linode'])
@pytest.mark.parametrize('row', [
    _APPLICATION_ROW,
    _APPLICATION_ROW.replace('35300', '1024').replace(':443 ', ':1 '),
    _APPLICATION_ROW.replace('35300', '65535').replace('client', 'other-agent'),
    _APPLICATION_ROW.replace('0 0 ', '4294967295 1 '),
])
def test_established_observations_preserve_connected_provider_proof(monkeypatch, provider, row):
    if provider == 'digitalocean':
        collection, policy, admin, transport = _fixture(monkeypatch)
        amended = replace(collection, surface=replace(collection.surface,
            listeners_raw=collection.surface.listeners_raw + row))
        result = _verify(amended, policy, admin, transport)
    else:
        collection, policy, admin, transport = _linode_fixture(monkeypatch)
        amended = replace(collection, raw=replace(collection.raw,
            surface=replace(collection.raw.surface,
                listeners_raw=collection.raw.surface.listeners_raw + row)))
        result = _verify_linode(amended, policy, admin, transport)
    assert result.listeners[-1].state == 'ESTAB'
    assert result.listeners[-1].process_names != ('sshd',)
    assert result.publication_eligible is False


@pytest.mark.parametrize('row', [
    _APPLICATION_ROW.replace('198.51.100.3', '198.51.100.4'),
    *[_APPLICATION_ROW.replace(':35300 ', f':{port} ') for port in
      ('0', '22', '443', '1023', '65536', '035300')],
    *[_APPLICATION_ROW.replace('203.0.113.49:443', endpoint) for endpoint in
      ('*:*', '0.0.0.0:443', '224.0.0.1:443', '127.0.0.1:443',
       '255.255.255.255:443', '[2001:db8::2]:443', '203.00.113.49:443',
       '203.0.113.49:0', '203.0.113.49:65536', '203.0.113.49:*')],
    *[_APPLICATION_ROW.replace('0 0 ', f'{queue} 0 ') for queue in
      ('-1', '+1', '00', '4294967296', '1.0', '1' * 100)],
    _APPLICATION_ROW.replace('client', 'sshd'),
    _APPLICATION_ROW.replace('users:(("client",pid=7896,fd=11))', ''),
    _APPLICATION_ROW.replace('pid=7896', 'pid=0'),
    _APPLICATION_ROW.replace('fd=11', 'fd=-1'),
    _APPLICATION_ROW.replace('))', '),("client",pid=7896,fd=11))'),
    _APPLICATION_ROW.replace('))', '),("sshd",pid=9,fd=1))'),
    _APPLICATION_ROW.replace('))', ')) extra'),
    _APPLICATION_ROW.replace('ESTAB', 'UNKNOWN'),
    _APPLICATION_ROW.replace('ESTAB', 'LISTEN'),
])
def test_established_observation_rejects_malformed_or_unauthorized_shape(monkeypatch, row):
    collection, policy, admin, transport = _fixture(monkeypatch)
    with pytest.raises(interp.HostSurfaceInterpretationError):
        _verify(replace(collection, surface=replace(collection.surface,
            listeners_raw=collection.surface.listeners_raw + row)), policy, admin, transport)


@pytest.mark.parametrize('missing', ['management', 'listener'])
def test_established_application_observation_cannot_replace_required_authority(monkeypatch, missing):
    collection, policy, admin, transport = _linode_fixture(monkeypatch)
    raw = collection.raw.surface.listeners_raw
    removed = (' ESTAB ' if missing == 'management' else '0.0.0.0:80 ')
    raw = ''.join(line for line in raw.splitlines(keepends=True) if removed not in line)
    amended = replace(collection, raw=replace(collection.raw,
        surface=replace(collection.raw.surface, listeners_raw=raw + _APPLICATION_ROW)))
    with pytest.raises(interp.HostSurfaceInterpretationError, match='complete fresh-host'):
        _verify_linode(amended, policy, admin, transport)
