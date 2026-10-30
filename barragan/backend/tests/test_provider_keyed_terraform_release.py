# Copyright (c) 2026, Oracle and/or its affiliates.
"""The keyed pilot accepts only its separately reviewed Terraform release."""

import hashlib
import json
import subprocess

import pytest

import app.services.provider_keyed_terraform_release as service


@pytest.fixture
def reviewed_binary(tmp_path, monkeypatch):
    binary = tmp_path / "terraform"
    binary.write_bytes(b"reviewed Terraform fixture")
    binary.chmod(0o700)
    monkeypatch.setattr(service, "_REVIEWED_PATH", binary)
    monkeypatch.setattr(service, "_REVIEWED_SHA256", hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(service.platform, "system", lambda: "Linux")
    monkeypatch.setattr(service.platform, "machine", lambda: "x86_64")
    calls = []

    def version(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(
            args, 0, json.dumps({"terraform_version": "1.15.5", "platform": "linux_amd64"}), "",
        )

    monkeypatch.setattr(service.subprocess, "run", version)
    return binary, calls


def test_reviewed_release_is_fixed_in_source():
    assert service._REVIEWED_VERSION == "1.15.5"
    assert service._REVIEWED_PLATFORM == "linux_amd64"
    assert service._REVIEWED_SHA256 == "d42b544fbd42bfab4f0ddfe1bd8ec985fbd59fb4fb7ff339d5f134c73e177279"


def test_accepts_reviewed_binary(reviewed_binary):
    binary, calls = reviewed_binary
    result = service.require_devtest_terraform_release(environment="devtest", terraform=binary)
    assert result == service.ProviderKeyedTerraformRelease(
        binary, hashlib.sha256(binary.read_bytes()).hexdigest(), "1.15.5", "linux_amd64",
    )
    assert calls[0][0] == [str(binary), "version", "-json"]
    assert calls[0][1]["timeout"] == 10
    assert calls[0][1]["cwd"] == "/"
    assert calls[0][1]["env"] == {
        "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TF_CLI_CONFIG_FILE": "/dev/null",
    }


@pytest.mark.parametrize("environment", ["prod", "", "DevTest"])
def test_rejects_other_environments(reviewed_binary, environment):
    binary, calls = reviewed_binary
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="DevTest"):
        service.require_devtest_terraform_release(environment=environment, terraform=binary)
    assert calls == []


def test_rejects_unreviewed_path(reviewed_binary, tmp_path):
    _, calls = reviewed_binary
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="path"):
        service.require_devtest_terraform_release(environment="devtest", terraform=tmp_path / "other")
    assert calls == []


@pytest.mark.parametrize("system,machine", [("Darwin", "arm64"), ("Linux", "aarch64")])
def test_rejects_other_platform(reviewed_binary, monkeypatch, system, machine):
    binary, calls = reviewed_binary
    monkeypatch.setattr(service.platform, "system", lambda: system)
    monkeypatch.setattr(service.platform, "machine", lambda: machine)
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="linux_amd64"):
        service.require_devtest_terraform_release(environment="devtest", terraform=binary)
    assert calls == []


def test_rejects_different_digest(reviewed_binary):
    binary, calls = reviewed_binary
    binary.write_bytes(b"unreviewed replacement")
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="digest"):
        service.require_devtest_terraform_release(environment="devtest", terraform=binary)
    assert calls == []


def test_rejects_non_executable(reviewed_binary):
    binary, calls = reviewed_binary
    binary.chmod(0o600)
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="executable"):
        service.require_devtest_terraform_release(environment="devtest", terraform=binary)
    assert calls == []


def test_rejects_symlink(reviewed_binary, tmp_path, monkeypatch):
    binary, calls = reviewed_binary
    link = tmp_path / "terraform-link"
    link.symlink_to(binary)
    monkeypatch.setattr(service, "_REVIEWED_PATH", link)
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="symlink"):
        service.require_devtest_terraform_release(environment="devtest", terraform=link)
    assert calls == []


@pytest.mark.parametrize("version", [
    {"terraform_version": "1.15.4", "platform": "linux_amd64"},
    {"terraform_version": "1.15.5", "platform": "linux_arm64"},
    {},
])
def test_rejects_version_mismatch(reviewed_binary, monkeypatch, version):
    binary, _ = reviewed_binary
    monkeypatch.setattr(service.subprocess, "run", lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 0, json.dumps(version), ""))
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="version differs"):
        service.require_devtest_terraform_release(environment="devtest", terraform=binary)


def test_rejects_changed_binary_during_version(reviewed_binary, monkeypatch):
    binary, _ = reviewed_binary

    def changed(args, **kwargs):
        binary.write_bytes(b"mutated after digest")
        return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5","platform":"linux_amd64"}', "")

    monkeypatch.setattr(service.subprocess, "run", changed)
    with pytest.raises(service.ProviderKeyedTerraformReleaseError, match="changed"):
        service.require_devtest_terraform_release(environment="devtest", terraform=binary)
