# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
from pathlib import Path


class Config:
    BASE_DIR = Path(__file__).resolve().parents[2]
    ENVIRONMENT = os.environ.get("BARRAGAN_ENV", "local")
    HOST = os.environ.get("BARRAGAN_HOST", "127.0.0.1")
    PORT = int(os.environ.get("BARRAGAN_PORT", "5000"))
    DATA_DIR = Path(os.environ.get("BARRAGAN_DATA_DIR", BASE_DIR / ".data"))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ENGAGEMENT_REPOS_ROOT = Path(os.environ.get("BARRAGAN_ENGAGEMENT_REPOS_ROOT", "/opt/engagements"))
    OCI_COMPUTE_PROFILES_FILE = os.environ.get("BARRAGAN_OCI_COMPUTE_PROFILES_FILE", "")
    # Separate pinned v2 checkout; the split-v1 template root is unchanged.
    PROVIDER_KEYED_TEMPLATE_ROOT = os.environ.get("BARRAGAN_PROVIDER_KEYED_TEMPLATE_ROOT", "")
    PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = os.environ.get(
        "BARRAGAN_PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED", "0",
    ) == "1"
    PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED = os.environ.get(
        "BARRAGAN_PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED", "0",
    ) == "1"
    # A reviewed external Inspector control is required for the private
    # pending-build teardown; never choose an Internet target by default.
    PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = os.environ.get(
        "BARRAGAN_PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", "",
    ).strip()
    FRONTEND_DIST = Path(os.environ.get("BARRAGAN_FRONTEND_DIST", BASE_DIR.parent / "frontend" / "dist"))
    SERVE_FRONTEND = os.environ.get("BARRAGAN_SERVE_FRONTEND", "1" if ENVIRONMENT == "production" else "0") == "1"
    START_SCHEDULERS = os.environ.get(
        "BARRAGAN_START_SCHEDULERS",
        "1" if ENVIRONMENT == "production" else "0",
    ) == "1"

    # Authentication is deliberately opt-in until the account recovery CLI and
    # environment bootstrap have been exercised for the selected database.
    AUTH_REQUIRED = os.environ.get("BARRAGAN_AUTH_REQUIRED", "0") == "1"
    AUTH_SESSION_COOKIE_NAME = os.environ.get(
        "BARRAGAN_AUTH_SESSION_COOKIE_NAME",
        "barragan_session" if ENVIRONMENT == "production" else "barragan_devtest_session",
    )
    AUTH_COOKIE_SECURE = os.environ.get("BARRAGAN_AUTH_COOKIE_SECURE", "0") == "1"
    AUTH_SESSION_ABSOLUTE_SECONDS = int(
        os.environ.get("BARRAGAN_AUTH_SESSION_ABSOLUTE_SECONDS", str(12 * 60 * 60))
    )
    AUTH_SESSION_IDLE_SECONDS = int(
        os.environ.get("BARRAGAN_AUTH_SESSION_IDLE_SECONDS", str(2 * 60 * 60))
    )
    AUTH_SESSION_TOUCH_INTERVAL_SECONDS = int(
        os.environ.get("BARRAGAN_AUTH_SESSION_TOUCH_INTERVAL_SECONDS", str(5 * 60))
    )
    AUTH_FAILURE_LIMIT = int(os.environ.get("BARRAGAN_AUTH_FAILURE_LIMIT", "10"))
    AUTH_LOCKOUT_SECONDS = int(
        os.environ.get("BARRAGAN_AUTH_LOCKOUT_SECONDS", str(15 * 60))
    )
    AUTH_ARGON2_MEMORY_KIB = int(os.environ.get("BARRAGAN_AUTH_ARGON2_MEMORY_KIB", "19456"))
    AUTH_ARGON2_TIME_COST = int(os.environ.get("BARRAGAN_AUTH_ARGON2_TIME_COST", "2"))
    AUTH_ARGON2_PARALLELISM = int(os.environ.get("BARRAGAN_AUTH_ARGON2_PARALLELISM", "1"))

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "BARRAGAN_DATABASE_URL",
        f"sqlite:///{DATA_DIR / 'barragan.sqlite3'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SERVE_FRONTEND = False
    START_SCHEDULERS = False
    AUTH_REQUIRED = False
