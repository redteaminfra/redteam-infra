# Copyright (c) 2026, Oracle and/or its affiliates.
import json

from app.integrations.linode_validation import (
    LinodeValidationError,
    validate_linode_sketch_create_destroy,
)


class FakeLinodeTransport:
    def __init__(self, fail_create: bool = False, cleanup_visible: bool = False):
        self.fail_create = fail_create
        self.cleanup_visible = cleanup_visible
        self.calls = []
        self.deleted = False
        self.bodies = []

    def request(self, method, path, token, body=None):
        self.calls.append((method, path, token))
        if body is not None:
            self.bodies.append(body)
        if token != "linode-token-sensitive-value":
            raise AssertionError("unexpected token")
        if method == "GET" and path == "/profile":
            return {"username": "operator"}
        if method == "GET" and path == "/regions":
            return {"data": [{"id": "us-sea"}]}
        if method == "GET" and path == "/linode/types":
            return {"data": [{"id": "g6-nanode-1"}]}
        if method == "POST" and path == "/linode/instances":
            if self.fail_create:
                raise LinodeValidationError("capacity exhausted")
            return _instance(status="provisioning")
        if method == "GET" and path == "/linode/instances/123":
            if self.deleted and not self.cleanup_visible:
                raise LinodeValidationError("Linode API GET /linode/instances/123 failed with HTTP 404: not found")
            return _instance(status="running")
        if method == "DELETE" and path == "/linode/instances/123":
            self.deleted = True
            return {}
        raise AssertionError(f"unexpected request {method} {path}")


def test_linode_validation_creates_inspects_destroys_and_redacts():
    transport = FakeLinodeTransport()

    result = validate_linode_sketch_create_destroy(
        token="linode-token-sensitive-value",
        credential_alias="linode-barragan",
        label="barragan-validation-test",
        root_pass="root-password-sensitive-value",
        transport=transport,
        poll_delay_seconds=0,
    )
    body = result.to_dict()
    encoded = json.dumps(body)

    assert body["ok"] is True
    assert body["cleanupVerified"] is True
    assert body["linodeId"] == 123
    assert body["publicIp"] == "203.0.113.10"
    assert ("POST", "/linode/instances", "linode-token-sensitive-value") in transport.calls
    assert ("DELETE", "/linode/instances/123", "linode-token-sensitive-value") in transport.calls
    assert transport.bodies[0]["root_pass"] == "root-password-sensitive-value"
    assert "linode-token-sensitive-value" not in encoded
    assert "root-password-sensitive-value" not in encoded


def test_linode_validation_reports_cleanup_failure():
    transport = FakeLinodeTransport(cleanup_visible=True)

    result = validate_linode_sketch_create_destroy(
        token="linode-token-sensitive-value",
        credential_alias="linode-barragan",
        label="barragan-validation-test",
        transport=transport,
        poll_attempts=1,
        poll_delay_seconds=0,
    )
    body = result.to_dict()

    assert body["ok"] is False
    assert body["cleanupVerified"] is False
    assert body["steps"][-1]["name"] == "verify_cleanup"
    assert body["steps"][-1]["status"] == "failed"


def _instance(status):
    return {
        "id": 123,
        "label": "barragan-validation-test",
        "region": "us-sea",
        "type": "g6-nanode-1",
        "status": status,
        "ipv4": ["203.0.113.10"],
    }
