# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess

from app.integrations.oci_read_validation import OciDevelopmentTarget
from app.integrations.ubuntu_image_inventory import (
    DIGITALOCEAN_IMAGE_SLUG,
    LINODE_IMAGE_ID,
    build_oci_image_list_command,
    collect_ubuntu_image_inventory,
)


class FakeImageTransport:
    def __init__(self):
        self.calls = []

    def get(self, url, token):
        self.calls.append((url, token))
        if "linode.com" in url:
            if "page=1" in url:
                return {"page": 1, "pages": 2, "data": [{"id": "linode/ubuntu22.04"}]}
            return {"page": 2, "pages": 2, "data": [{"id": LINODE_IMAGE_ID, "label": "Ubuntu 24.04 LTS", "regions": ["us-sea"], "vendor": "Ubuntu", "type": "manual", "created": "2026-01-01", "deprecated": False, "eol": "2036-04-01"}]}
        if "page=1" in url:
            return {"images": [{"slug": "ubuntu-22-04-x64"}], "links": {"pages": {"next": "https://api.digitalocean.com/v2/images?type=distribution&page=2&per_page=200"}}}
        return {"images": [{"slug": DIGITALOCEAN_IMAGE_SLUG, "name": "24.04 (LTS) x64", "distribution": "Ubuntu", "type": "distribution", "created": "2026-01-01", "status": "available", "regions": ["sfo3"], "min_disk_size": 7}], "links": {"pages": {}}}


def _runner(command):
    return subprocess.CompletedProcess(
        command,
        0,
        stdout=json.dumps({"data": [
            {"id": "minimal", "display-name": "Canonical-Ubuntu-24.04-Minimal-2026.01.01-0"},
            {"id": "arm", "display-name": "Canonical-Ubuntu-24.04-aarch64-2026.01.01-0"},
            {"id": "old", "display-name": "Canonical-Ubuntu-24.04-2025.12.01-0", "time-created": "2025-12-01T00:00:00Z", "lifecycle-state": "AVAILABLE", "operating-system": "Canonical Ubuntu", "operating-system-version": "24.04"},
            {"id": "new", "display-name": "Canonical-Ubuntu-24.04-2026.01.01-0", "time-created": "2026-01-01T00:00:00Z", "lifecycle-state": "AVAILABLE", "operating-system": "Canonical Ubuntu", "operating-system-version": "24.04"},
        ]}),
        stderr="",
    )


def test_inventory_selects_standard_ubuntu_and_fetches_all_sketch_pages(monkeypatch):
    monkeypatch.setattr("app.integrations.ubuntu_image_inventory.resolve_oci_cli", lambda **_kwargs: type("Resolution", (), {"ok": True, "command": "oci", "error": None})())
    transport = FakeImageTransport()

    inventory = collect_ubuntu_image_inventory(
        runner=_runner,
        transport=transport,
        credential_resolver=lambda provider, alias: f"{provider}-token-sensitive-value",
        alias_resolver=lambda _provider: "default-alias",
        env={"PATH": ""},
    ).to_dict()

    assert inventory["ok"] is True
    assert inventory["mutation"] is False
    assert inventory["providers"]["oci"]["candidate"]["id"] == "new"
    assert inventory["providers"]["linode"]["candidate"]["id"] == LINODE_IMAGE_ID
    assert inventory["providers"]["digitalocean"]["candidate"]["id"] == DIGITALOCEAN_IMAGE_SLUG
    assert len(transport.calls) == 4
    assert "token-sensitive-value" not in str(inventory)
    assert "default-alias" not in str(inventory)


def test_inventory_reports_missing_default_credential_without_running_provider_requests(monkeypatch):
    monkeypatch.setattr("app.integrations.ubuntu_image_inventory.resolve_oci_cli", lambda **_kwargs: type("Resolution", (), {"ok": True, "command": "oci", "error": None})())
    transport = FakeImageTransport()

    inventory = collect_ubuntu_image_inventory(
        runner=_runner,
        transport=transport,
        alias_resolver=lambda _provider: None,
    ).to_dict()

    assert inventory["ok"] is False
    assert inventory["providers"]["linode"]["error"] == "No active default linode credential is configured"
    assert transport.calls == []


def test_oci_command_is_read_only_and_scoped_to_testing():
    command = build_oci_image_list_command(OciDevelopmentTarget(), "oci")

    assert command[:6] == ["oci", "--auth", "instance_principal", "--region", "us-sanjose-1", "compute"]
    assert "image" in command and "list" in command
    assert "--compartment-id" in command
    assert "create" not in command and "delete" not in command and "update" not in command
