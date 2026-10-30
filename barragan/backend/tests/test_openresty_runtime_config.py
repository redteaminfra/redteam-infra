# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_openresty_frontend_config_routes_static_and_all_api_to_fastapi():
    config = (ROOT / "ops" / "openresty" / "barragan.conf").read_text()

    assert "listen 127.0.0.1:5173;" in config
    assert "include       /etc/nginx/mime.types;" in config
    assert "root __BARRAGAN_ROOT__/frontend/dist;" in config
    assert "include __BARRAGAN_ROOT__/ops/openresty/proxy_params.conf;" in config
    assert "server 127.0.0.1:5002;" in config
    assert "server 127.0.0.1:5000;" not in config
    assert "barragan_flask" not in config
    assert "location /api/" in config
    assert "proxy_pass http://barragan_fastapi;" in config
    assert "try_files $uri $uri/ /index.html;" in config


def test_openresty_launcher_renders_the_selected_release_root():
    launcher = (ROOT / "scripts" / "run-barragan-openresty").read_text()

    assert 'RUNTIME_CONFIG=${PREFIX}/run/barragan.conf' in launcher
    assert 'sed "s|__BARRAGAN_ROOT__|${ROOT_FOR_SED}|g" "${CONFIG}" > "${RUNTIME_CONFIG}"' in launcher
    assert 'exec "${BIN}" -p "${PREFIX}" -c "${RUNTIME_CONFIG}" -g "daemon off;"' in launcher


def test_openresty_cache_policy_revalidates_shell_and_immutably_caches_assets():
    config = (ROOT / "ops" / "openresty" / "barragan.conf").read_text()

    assert "gzip on;" in config
    assert "gzip_vary on;" in config
    assert "location ^~ /assets/" in config
    assert 'add_header Cache-Control "public, max-age=31536000, immutable" always;' in config
    assert 'add_header Cache-Control "no-cache" always;' in config
    assert 'add_header Cache-Control "no-store" always;' in config


def test_systemd_and_admin_manage_fastapi_only_api_runtime():
    systemd = ROOT / "ops" / "systemd" / "system"
    production = (systemd / "barragan-fastapi.service").read_text()
    devtest = (systemd / "barragan-api-devtest.service").read_text()
    openresty = (systemd / "barragan-openresty.service").read_text()
    admin = (ROOT / "scripts" / "barragan-admin").read_text()

    assert not (systemd / "barragan-api.service").exists()
    assert "uvicorn app.asgi:app" in production
    assert "BARRAGAN_START_SCHEDULERS=1" in production
    assert "uvicorn app.asgi:app" in devtest
    assert "BARRAGAN_START_SCHEDULERS=0" in devtest
    assert "Wants=barragan-fastapi.service" in openresty
    assert "Wants=barragan-api.service" not in openresty
    assert "PROD_SERVICES=(barragan-fastapi.service barragan-openresty.service)" in admin
    assert "OBSOLETE_UNITS=(barragan-api.service)" in admin
