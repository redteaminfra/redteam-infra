# Copyright (c) 2026, Oracle and/or its affiliates.
import json
from unittest.mock import patch

import pytest

from app.cli.digitalocean_sketch_validate import main as digitalocean_cli_main
from app.integrations.digitalocean_validation import (
    DigitalOceanValidationError,
    validate_digitalocean_sketch_create_destroy,
)


class FakeDigitalOceanTransport:
    def __init__(self, fail_create: bool = False, cleanup_visible: bool = False, account_forbidden: bool = False):
        self.fail_create = fail_create
        self.cleanup_visible = cleanup_visible
        self.account_forbidden = account_forbidden
        self.calls = []
        self.deleted = False
        self.bodies = []

    def request(self, method, path, token, body=None):
        self.calls.append((method, path, token))
        if body is not None:
            self.bodies.append(body)
        if token != "do-token-sensitive-value":
            raise AssertionError("unexpected token")
        if method == "GET" and path == "/account":
            if self.account_forbidden:
                raise DigitalOceanValidationError('DigitalOcean API GET /account failed with HTTP 403: {"id": "Forbidden"}')
            return {"account": {"email_verified": True}}
        if method == "GET" and path == "/regions":
            return {"regions": [{"slug": "sfo3", "available": True}]}
        if method == "GET" and path == "/sizes":
            return {"sizes": [{"slug": "s-1vcpu-1gb", "available": True}]}
        if method == "POST" and path == "/droplets":
            if self.fail_create:
                raise DigitalOceanValidationError("capacity exhausted")
            return {"droplet": _droplet(status="new")}
        if method == "GET" and path == "/droplets/123":
            if self.deleted and not self.cleanup_visible:
                raise DigitalOceanValidationError("DigitalOcean API GET /droplets/123 failed with HTTP 404: not found")
            return {"droplet": _droplet(status="active")}
        if method == "DELETE" and path == "/droplets/123":
            self.deleted = True
            return {}
        raise AssertionError(f"unexpected request {method} {path}")


def test_digitalocean_validation_creates_inspects_destroys_and_redacts():
    transport = FakeDigitalOceanTransport()

    result = validate_digitalocean_sketch_create_destroy(
        token="do-token-sensitive-value",
        credential_alias="do-barragan",
        name="barragan-validation-test",
        user_data="#cloud-config\nwrite_files:\n- content: user-data-sensitive-value\n",
        transport=transport,
        poll_delay_seconds=0,
    )
    body = result.to_dict()
    encoded = json.dumps(body)

    assert body["ok"] is True
    assert body["cleanupVerified"] is True
    assert body["dropletId"] == 123
    assert body["publicIp"] == "203.0.113.40"
    assert ("POST", "/droplets", "do-token-sensitive-value") in transport.calls
    assert ("DELETE", "/droplets/123", "do-token-sensitive-value") in transport.calls
    assert transport.bodies[0]["user_data"].endswith("user-data-sensitive-value\n")
    assert transport.bodies[0]["region"] == "sfo3"
    assert transport.bodies[0]["size"] == "s-1vcpu-1gb"
    assert "tags" not in transport.bodies[0]
    assert "do-token-sensitive-value" not in encoded
    assert "user-data-sensitive-value" not in encoded


def test_digitalocean_validation_does_not_require_account_read_scope():
    transport = FakeDigitalOceanTransport(account_forbidden=True)

    result = validate_digitalocean_sketch_create_destroy(
        token="do-token-sensitive-value",
        credential_alias="do-barragan",
        name="barragan-validation-test",
        transport=transport,
        poll_delay_seconds=0,
    )
    body = result.to_dict()

    assert body["ok"] is True
    assert body["cleanupVerified"] is True
    assert body["steps"][0]["name"] == "credential_check"
    assert body["steps"][0]["status"] == "skipped"
    assert ("POST", "/droplets", "do-token-sensitive-value") in transport.calls
    assert ("DELETE", "/droplets/123", "do-token-sensitive-value") in transport.calls


def test_digitalocean_validation_reports_cleanup_failure():
    transport = FakeDigitalOceanTransport(cleanup_visible=True)

    result = validate_digitalocean_sketch_create_destroy(
        token="do-token-sensitive-value",
        credential_alias="do-barragan",
        name="barragan-validation-test",
        transport=transport,
        poll_attempts=1,
        poll_delay_seconds=0,
    )
    body = result.to_dict()

    assert body["ok"] is False
    assert body["cleanupVerified"] is False
    assert body["steps"][-1]["name"] == "verify_cleanup"
    assert body["steps"][-1]["status"] == "failed"


def test_digitalocean_validation_reports_create_failure_without_secret_leak():
    transport = FakeDigitalOceanTransport(fail_create=True)

    result = validate_digitalocean_sketch_create_destroy(
        token="do-token-sensitive-value",
        credential_alias="do-barragan",
        name="barragan-validation-test",
        transport=transport,
        poll_delay_seconds=0,
    )
    body = result.to_dict()

    assert body["ok"] is False
    assert body["dropletId"] is None
    assert body["cleanupVerified"] is False
    assert body["steps"][-1]["name"] == "validation_failed"
    assert "do-token-sensitive-value" not in json.dumps(body)


def test_digitalocean_cli_requires_confirmation(capsys):
    with pytest.raises(SystemExit):
        digitalocean_cli_main([])
    captured = capsys.readouterr()
    assert "--confirm-create-destroy must be validate-digitalocean-sketch" in captured.err


def test_digitalocean_cli_runs_validation_with_resolved_credential(capsys):
    class Result:
        def to_dict(self):
            return {"ok": True, "credentialAlias": "do-barragan", "cleanupVerified": True}

    with patch("app.cli.digitalocean_sketch_validate.initialize_runtime") as initialize_runtime:
        with patch("app.cli.digitalocean_sketch_validate.runtime_context") as runtime_context:
            runtime_context.return_value.__enter__.return_value = None
            runtime_context.return_value.__exit__.return_value = None
            with patch("app.cli.digitalocean_sketch_validate.resolve_credential_secret", return_value="do-token-sensitive-value") as resolve:
                with patch("app.cli.digitalocean_sketch_validate.validate_digitalocean_sketch_create_destroy", return_value=Result()) as validate:
                    exit_code = digitalocean_cli_main([
                        "--confirm-create-destroy",
                        "validate-digitalocean-sketch",
                        "--name",
                        "barragan-validation-test",
                    ])

    captured = capsys.readouterr()
    body = json.loads(captured.out)
    assert exit_code == 0
    assert body["ok"] is True
    initialize_runtime.assert_called_once()
    resolve.assert_called_once_with("digitalocean", "do-barragan")
    validate.assert_called_once()
    assert validate.call_args.kwargs["token"] == "do-token-sensitive-value"
    assert validate.call_args.kwargs["name"] == "barragan-validation-test"
    assert "do-token-sensitive-value" not in captured.out


def _droplet(status):
    return {
        "id": 123,
        "name": "barragan-validation-test",
        "region": {"slug": "sfo3"},
        "size": {"slug": "s-1vcpu-1gb"},
        "status": status,
        "networks": {
            "v4": [
                {"type": "private", "ip_address": "10.0.0.2"},
                {"type": "public", "ip_address": "203.0.113.40"},
            ]
        },
    }
