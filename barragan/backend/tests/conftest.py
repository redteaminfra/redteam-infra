# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app import create_app
from app.core.config import TestConfig


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # API fixtures must never depend on a developer's /opt workspaces, state,
    # or shared lock directories. Each request client owns disposable paths.
    paths = {
        "BARRAGAN_DATA_DIR": tmp_path / "data",
        "BARRAGAN_ENGAGEMENT_REPOS_ROOT": tmp_path / "engagements",
        "BARRAGAN_TERRAFORM_STATE_ROOT": tmp_path / "terraform-state",
        "BARRAGAN_SKETCH_STATE_ROOT": tmp_path / "sketch-state",
        "BARRAGAN_DNS01_LOCK_DIR": tmp_path / "dns-locks",
        "BARRAGAN_CERTIFICATE_SCHEDULER_LOCK": tmp_path / "certificate.lock",
    }
    for name, path in paths.items():
        monkeypatch.setenv(name, str(path))
    paths["BARRAGAN_DATA_DIR"].mkdir()

    class IsolatedTestConfig(TestConfig):
        DATA_DIR = paths["BARRAGAN_DATA_DIR"]
        ENGAGEMENT_REPOS_ROOT = paths["BARRAGAN_ENGAGEMENT_REPOS_ROOT"]
        TERRAFORM_STATE_ROOT = paths["BARRAGAN_TERRAFORM_STATE_ROOT"]

    app = create_app(IsolatedTestConfig)
    return app.test_client()
