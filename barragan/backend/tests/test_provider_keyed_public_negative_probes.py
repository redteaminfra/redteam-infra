# Copyright (c) 2026, Oracle and/or its affiliates.
"""Execute actual Inspector script functions with controlled DNS/socket responses."""
import ast
import errno
import ipaddress
import socket
import struct
from types import SimpleNamespace

import pytest

from app.services.observer_checks import _OBSERVER_SCRIPT, _observer_check_execution_timeout


class Clock:
    now = 0
    def monotonic(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


def script():
    names = {"run", "dns_record_probe", "_dns_name", "_dns_ip_response", "udp_absence_probe"}
    functions = [node for node in ast.parse(_OBSERVER_SCRIPT).body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    clock = Clock()
    namespace = {"socket": socket, "struct": struct, "ipaddress": ipaddress,
        "errno": errno, "time": clock, "DNS_RESOLVERS": ("1.1.1.1", "8.8.8.8"),
        "tcp_connect": lambda *_: (True, "")}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<inspector-negative>", "exec"), namespace)
    return namespace, clock


def dns_target(identifier="old", kind="A", previous="8.8.8.8"):
    return {"id": identifier, "type": "dns-record-absent", "host": "old.example",
            "recordType": kind, "previousAnswer": previous}


def test_dns_settles_cached_previous_answer_then_accepts_changed_valid_answer():
    namespace, clock = script()
    calls = []
    def lookup(*_):
        calls.append(1)
        return ["8.8.8.8"] if len(calls) <= 2 else ["9.9.9.9"]
    namespace["_dns_ip_lookup"] = lookup
    result = namespace["run"]({"dnsSettleSeconds": 10, "negative": [dns_target()]})
    assert result["ok"] is True and result["results"][0]["attemptCount"] == 2
    assert clock.now == 2


def test_dns_settling_budget_is_cumulative_across_names():
    namespace, clock = script()
    calls = []
    namespace["_dns_ip_lookup"] = lambda *_: (calls.append(1) or ["8.8.8.8"])
    result = namespace["run"]({"dnsSettleSeconds": 4,
                               "negative": [dns_target(), dns_target("sibling")]})
    assert result["ok"] is False
    assert clock.now == 4
    assert [row["attemptCount"] for row in result["results"]] == [3, 1]
    assert len(calls) == 8


@pytest.mark.parametrize("error", [TimeoutError, ValueError])
def test_dns_resolver_failure_stays_inconclusive_without_cache_wait(error):
    namespace, clock = script()
    namespace["_dns_ip_lookup"] = lambda *_: (_ for _ in ()).throw(error())
    result = namespace["run"]({"dnsSettleSeconds": 600, "negative": [dns_target()]})
    assert result["ok"] is False and clock.now == 0
    assert result["results"][0]["attemptCount"] == 1
    assert all(row["status"] == "inconclusive" for row in result["results"][0]["observed"].values())


@pytest.mark.parametrize("kind,answer", [(1, "8.8.8.8"), (28, "2606:4700:4700::1111"),
    (5, "previous.example"), (2, "ns.example"), (15, "10 mx.example"), (16, "public text")])
def test_actual_dns_packet_reader_matches_owned_rr_type_and_value(kind, answer):
    namespace, _ = script()
    def encoded_name(value):
        return b"".join(bytes([len(part)]) + part.encode() for part in value.split(".")) + b"\x00"
    question = encoded_name("old.example") + struct.pack("!HH", kind, 1)
    if kind == 1:
        data = socket.inet_aton(answer)
    elif kind == 28:
        data = socket.inet_pton(socket.AF_INET6, answer)
    elif kind == 16:
        data = bytes([len(answer)]) + answer.encode()
    elif kind == 15:
        data = struct.pack("!H", 10) + encoded_name("mx.example")
    else:
        data = encoded_name(answer)
    packet = struct.pack("!HHHHHH", 17, 0x8180, 1, 1, 0, 0) + question
    packet += b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 300, len(data)) + data
    assert namespace["_dns_ip_response"](packet, 17, b"old.example", kind) == [answer]
    with pytest.raises(ValueError):
        namespace["_dns_ip_response"](packet, 17, b"old.example", 28 if kind != 28 else 1)
    with pytest.raises(ValueError):
        namespace["_dns_ip_response"](packet[:2] + struct.pack("!H", 0x8182) + packet[4:], 17, b"old.example", kind)


@pytest.mark.parametrize("outcome,status", [(b"reply", "open"), (TimeoutError(), "inconclusive"),
                                          (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "closed")])
def test_udp_probe_does_not_call_silence_closed(outcome, status):
    namespace, _ = script()
    class Socket:
        def settimeout(self, _): pass
        def connect(self, _): pass
        def send(self, _): pass
        def close(self): pass
        def recv(self, _):
            if isinstance(outcome, Exception): raise outcome
            return outcome
    namespace["socket"] = SimpleNamespace(AF_INET=socket.AF_INET, SOCK_DGRAM=socket.SOCK_DGRAM,
                                            socket=lambda *_: Socket())
    actual, observed = namespace["udp_absence_probe"]("8.8.8.8", 40001, 4)
    assert actual == status and observed["status"] == status


def test_outer_ssh_deadline_accounts_for_one_cumulative_dns_window():
    spec = {"timeoutSeconds": 8, "dnsSettleSeconds": 630,
            "negative": [dns_target(), dns_target("second")]}
    assert _observer_check_execution_timeout(spec) == 60 + 630 + 2 * 16
