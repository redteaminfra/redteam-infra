# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

from fastapi.testclient import TestClient

from app.asgi import create_app
from app.core.config import TestConfig


def test_fastapi_health_uses_existing_database_status_shape():
    app = create_app(TestConfig)
    client = app.test_client()

    assert not hasattr(app.state, "flask_app")

    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "barragan-api"
    assert body["status"] == "ok"
    assert body["database"]["uriScheme"] == "sqlite"
    assert body["database"]["path"] == ":memory:"


def test_fastapi_boots_and_serves_health_without_flask_importable():
    script = dedent(
        """
        import importlib.abc
        import sys

        class BlockFlask(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "flask" or fullname.startswith("flask."):
                    raise ImportError("Flask intentionally unavailable")
                return None

        sys.meta_path.insert(0, BlockFlask())

        from fastapi.testclient import TestClient
        from app.asgi import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        response = TestClient(app).get("/api/health")
        assert response.status_code == 200, response.text
        assert response.json()["database"]["seedStatus"] == "seeded"
        assert not hasattr(app.state, "flask_app")
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_backend_runtime_has_no_flask_dependency_or_imports():
    backend_root = Path(__file__).resolve().parents[1]
    pyproject = (backend_root / "pyproject.toml").read_text(encoding="utf-8")
    runtime_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (backend_root / "app").rglob("*.py")
    )

    assert '"Flask' not in pyproject
    assert "flask_sqlalchemy" not in runtime_sources
    assert "from flask" not in runtime_sources
    assert "import flask" not in runtime_sources
    assert not (backend_root / "run.py").exists()
    assert not (backend_root / "app" / "core" / "app.py").exists()


def test_fastapi_templates_preserve_success_and_error_shapes():
    client = create_app(TestConfig).test_client()

    index = client.get("/api/templates")
    missing = client.get("/api/templates/not-a-template")

    assert index.status_code == 200
    assert "templates" in index.json()
    assert missing.status_code == 404
    assert missing.json() == {"error": "template not found"}


def test_fastapi_jobs_preserve_create_and_show_contracts():
    client = create_app(TestConfig).test_client()

    created = client.post(
        "/api/jobs",
        json={"action": "noop", "targetType": "system", "targetId": "runtime-test", "requestedBy": "pytest"},
    )

    assert created.status_code == 201
    job_id = created.json()["job"]["id"]

    shown = client.get(f"/api/jobs/{job_id}")
    missing = client.get("/api/jobs/job-missing")

    assert shown.status_code == 200
    assert shown.json()["job"]["id"] == job_id
    assert missing.status_code == 404
    assert missing.json() == {"error": "job not found"}


def test_fastapi_jobs_returns_validated_summary_pages():
    client = create_app(TestConfig).test_client()
    initial_total = client.get("/api/jobs?limit=1").json()["pagination"]["total"]
    for target_id in ("first", "second", "third"):
        response = client.post(
            "/api/jobs",
            json={"action": "noop", "targetType": "system", "targetId": target_id, "requestedBy": "pytest"},
        )
        assert response.status_code == 201

    page = client.get("/api/jobs?limit=1&offset=1")

    assert page.status_code == 200
    assert len(page.json()["jobs"]) == 1
    assert page.json()["pagination"] == {
        "total": initial_total + 3,
        "limit": 1,
        "offset": 1,
        "hasMore": True,
    }
    assert client.get("/api/jobs?limit=0").status_code == 422
    assert client.get("/api/jobs?limit=201").status_code == 422
    assert client.get("/api/jobs?offset=-1").status_code == 422
