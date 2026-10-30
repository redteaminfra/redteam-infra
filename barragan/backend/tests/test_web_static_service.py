# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import os
from pathlib import Path
import subprocess

import pytest

from app.domain import JobEvent
from app.services.web_static_service import (
    WEB_STATIC_SERVICE_NAME,
    WebStaticCoreHost,
    WebStaticServiceValidationError,
    _shared_front_collision_preflight_command,
    _intent_from_body,
    apply_web_static_service,
    preview_web_static_service_apply,
    preview_web_static_service_remove,
    render_web_static_apply_workspace,
    render_web_static_remove_workspace,
    remove_web_static_service,
    start_web_static_service_apply,
    start_web_static_service_remove,
)
from app.storage.job_repository import StoredJobRun
from app.storage.service_repository import StoredEngagementService


@pytest.fixture(autouse=True)
def no_retained_https_gate(monkeypatch):
    monkeypatch.setattr("app.services.web_static_service._inspect_remote_content", lambda *_args, **_kwargs: {"state": "empty", "fingerprint": "a" * 64, "entryCount": 0, "bytes": 0})
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_https_request_header_gate_for_service",
        lambda *_args, **_kwargs: None,
    )


def test_renders_web_static_workspace_for_selected_proxy_only():
    workspace = render_web_static_apply_workspace(
        intent=_intent("ff10"),
        homebase=WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts"),
        proxy=WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts"),
    )

    body = workspace.to_dict()
    assert body["status"] == "Pending Service Apply"
    assert body["mutation"] is False
    assert workspace.inventory.target == "ansible/inventory.ini"
    assert "[selected_proxy]" in workspace.inventory.content
    assert "proxy01 ansible_host=192.168.2.11" in workspace.inventory.content
    assert "ProxyCommand='ssh -i /keys/core" in workspace.inventory.content
    assert "middle-" not in workspace.inventory.content
    assert "edge-" not in workspace.inventory.content

    assert workspace.playbook.target == "ansible/apply_web_static.yml"
    assert "hosts: selected_proxy" in workspace.playbook.content
    assert "Apply reviewed Static Web content policy" in workspace.playbook.content
    assert "../helpers/static_web_content.py" in workspace.playbook.content
    assert "docker-compose" in workspace.playbook.content
    assert "Refuse shared front TCP port collision" in workspace.playbook.content
    assert "ss -H -ltn '( sport = :80 or sport = :443 )'" in workspace.playbook.content
    assert "docker inspect proxy >/dev/null 2>&1" in workspace.playbook.content
    assert "docker top proxy >/dev/null 2>&1" in workspace.playbook.content
    assert 'docker port proxy 80/tcp 2>/dev/null' in workspace.playbook.content
    assert 'docker port proxy 443/tcp 2>/dev/null' in workspace.playbook.content
    assert "systemctl, is-active, nginx" not in workspace.playbook.content
    assert "Stop and disable legacy host nginx before production proxy adoption" not in workspace.playbook.content
    assert "name: nginx" not in workspace.playbook.content
    assert "argv: [docker, port, proxy, 443/tcp]" in workspace.playbook.content
    assert "Remove legacy front proxy without required host binding" in workspace.playbook.content
    assert "barragan_compose_argv + ['-f', compose_path, 'rm', '-s', '-f', 'reverse-proxy']" in workspace.playbook.content
    assert "front_proxy_container.rc != 0" in workspace.playbook.content
    assert "front_proxy_https_binding.stdout | trim | length == 0" in workspace.playbook.content
    assert "Remove existing shared front proxy before convergence" in workspace.playbook.content
    assert "argv: [docker, rm, -f, proxy]" in workspace.playbook.content
    assert "Converge production front proxy with required host listeners" in workspace.playbook.content
    assert "barragan_compose_argv + ['-f', compose_path, 'up', '-d', 'reverse-proxy']" in workspace.playbook.content
    assert "Wait for shared front proxy exec readiness" in workspace.playbook.content
    assert "until: front_proxy_exec_ready.rc == 0" in workspace.playbook.content
    assert "argv: [docker, exec, proxy, openresty, -t]" in workspace.playbook.content
    assert 'argv: [docker, exec, "barragan_web_ff10", openresty, -t]' in workspace.playbook.content
    assert "curl, -fsS" not in workspace.playbook.content
    assert "/opt/web/.barragan-stack.json" in workspace.playbook.content
    assert 'openresty/openresty:latest' in workspace.compose.content
    assert "external: true" not in workspace.compose.content
    assert "web_webnet:" in workspace.compose.content
    assert workspace.site_index.target == "files/opt/web/ff10/html/index.html"
    assert "hola ff10" in workspace.site_index.content
    assert workspace.site_config.target == "files/opt/web/ff10/conf/default.conf"
    assert workspace.site_observability_config.target == "files/opt/web/ff10/conf/00-barragan-observability.conf"
    assert "map $http_x_real_ip $barragan_original_client_ip" in workspace.site_observability_config.content
    assert '\"\" $remote_addr;' in workspace.site_observability_config.content
    assert "$proxy_protocol_addr" not in workspace.site_observability_config.content
    assert "access_log /dev/stdout barragan_site;" in workspace.site_observability_config.content
    assert "Authorization" not in workspace.site_observability_config.content
    assert "listen 8081;" in workspace.site_config.content
    assert "include /etc/nginx/conf.d/request-header-gate*.inc;" in workspace.site_config.content
    assert "/opt/web/ff10/conf:/etc/nginx/conf.d:ro" in workspace.site_compose.content
    assert "/opt/web/ff10/tls-conf:/etc/nginx/conf.d:ro" in workspace.site_compose.content
    assert "container_name: barragan_web_ff10_tls" in workspace.site_compose.content
    assert "00-request-header-gate-00-runtime.conf" in workspace.playbook.content
    assert "Write site request observability config" in workspace.playbook.content
    assert "map_hash_bucket_size 512;" not in workspace.playbook.content
    assert "Ensure retained request-header gate map hook exists" in workspace.playbook.content
    assert "force: false" in workspace.playbook.content
    assert 'content: "client_max_body_size 500000000;' in workspace.playbook.content
    server_hook_task = workspace.playbook.content.split(
        "- name: Ensure retained request-header gate server hook exists",
        1,
    )[1].split("- name:", 1)[0]
    assert "force: false" in server_hook_task
    assert '"80:80"' in workspace.compose.content
    assert '"443:443"' in workspace.compose.content
    assert '"8081"' in workspace.site_compose.content
    assert "ports:" not in workspace.site_compose.content
    assert "127.0.0.1:" not in workspace.site_compose.content
    assert workspace.site_compose.target == "files/opt/web/sites/ff10.compose.yml"
    assert workspace.front_route.content == "ff10.example.invalid web_ff10:8081;\n"
    assert "proxy_protocol on;" in workspace.front_http_config.content
    assert "map $host $barragan_http_backend" in workspace.front_http_config.content
    assert workspace.front_http_config.content.count("include /etc/openresty/tls/*.map;") == 1
    http_map = workspace.front_http_config.content.split("map $host $barragan_http_backend", 1)[1].split("server {", 1)[0]
    assert "/etc/openresty/tls" not in http_map
    assert "/etc/openresty/streams" not in http_map
    assert workspace.front_route.target == "files/opt/web/http/ff10.map"
    assert "Refuse a partial retained TLS sibling" in workspace.playbook.content
    assert "Start retained TLS sibling after Static Web reapply" in workspace.playbook.content
    assert "location / {" in workspace.front_http_config.content
    assert "client_max_body_size 10240000000;" in workspace.front_http_config.content
    assert "proxy_request_buffering off;" in workspace.front_http_config.content
    assert "proxy_pass http://$barragan_http_backend;" in workspace.front_http_config.content
    assert "return 301" not in workspace.front_http_config.content
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)


def test_static_web_collision_preflight_preserves_udp_only_host_nginx_and_runs_before_mutation():
    playbook = render_web_static_apply_workspace(
        intent=_intent("ff10"),
        homebase=WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts"),
        proxy=WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts"),
    ).playbook.content

    collision = playbook.index("- name: Refuse shared front TCP port collision")
    assert "ss -H -ltn '( sport = :80 or sport = :443 )'" in playbook
    assert "ss -H -lun" not in playbook
    assert "systemctl, is-active, nginx" not in playbook
    assert "name: nginx" not in playbook
    for mutation in (
        "- name: Ensure Docker service is running",
        "- name: Create Barragan web directories",
        "- name: Apply reviewed Static Web content policy",
        "- name: Write shared front OpenResty config",
        "- name: Record Barragan proxy-stack ownership",
        "- name: Remove existing shared front proxy before convergence",
        "- name: Converge production front proxy with required host listeners",
    ):
        assert collision < playbook.index(mutation)


def test_static_web_collision_preflight_recognizes_existing_owned_front_before_listener_check():
    playbook = render_web_static_apply_workspace(
        intent=_intent("ff10"),
        homebase=WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts"),
        proxy=WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts"),
    ).playbook.content
    preflight = playbook.split("- name: Refuse shared front TCP port collision", 1)[1].split(
        "- name: Ensure Docker service is running", 1
    )[0]

    assert preflight.index('[ -f "$stack_root/.barragan-stack.json" ]') < preflight.index("docker inspect proxy")
    assert preflight.index("docker inspect proxy") < preflight.index("docker top proxy")
    assert preflight.index("docker top proxy") < preflight.index("docker port proxy 80/tcp")
    assert preflight.index("docker port proxy 80/tcp") < preflight.index("docker port proxy 443/tcp")
    assert preflight.index("docker port proxy 443/tcp") < preflight.index("ss -H -ltn")
    assert "Unable to inspect TCP port 80/443 ownership" in preflight
    assert "Barragan will not stop it to start the shared OpenResty front" in preflight


@pytest.mark.parametrize(
    ("scenario", "settings", "marker", "expected_returncode", "expected_error"),
    [
        ("udp-only-free-tcp", {}, False, 0, ""),
        ("foreign-tcp", {"LISTEN_80": "1"}, False, 1, "foreign process owns TCP port 80"),
        (
            "running-full-owned",
            {"DOCKER_EXISTS": "1", "DOCKER_RUNNING": "1", "BIND_80": "1", "BIND_443": "1", "LISTEN_80": "1", "LISTEN_443": "1"},
            True,
            0,
            "",
        ),
        (
            "stopped-mapped-foreign",
            {"DOCKER_EXISTS": "1", "BIND_80": "1", "LISTEN_80": "1"},
            True,
            1,
            "foreign process owns TCP port 80",
        ),
        (
            "partial-owned-free-missing-port",
            {"DOCKER_EXISTS": "1", "DOCKER_RUNNING": "1", "BIND_443": "1", "LISTEN_443": "1"},
            True,
            0,
            "",
        ),
        ("ss-failure", {"SS_FAIL": "1"}, False, 1, "Unable to inspect TCP port 80/443 ownership"),
    ],
)
def test_static_web_collision_classification_stops_before_mutation(
    tmp_path: Path,
    scenario: str,
    settings: dict[str, str],
    marker: bool,
    expected_returncode: int,
    expected_error: str,
):
    stack_root = tmp_path / scenario / "web"
    if marker:
        stack_root.mkdir(parents=True)
        (stack_root / ".barragan-stack.json").write_text(
            '{"managedBy":"barragan","stackModel":"containerized-openresty-v1"}\n',
            encoding="utf-8",
        )
    fake_bin = tmp_path / scenario / "bin"
    fake_bin.mkdir(parents=True)
    docker = fake_bin / "docker"
    docker.write_text(
        """#!/bin/sh
case "$1" in
  inspect) [ "${DOCKER_EXISTS:-}" = 1 ] ;;
  top) [ "${DOCKER_RUNNING:-}" = 1 ] ;;
  port)
    case "$3" in
      80/tcp) [ "${BIND_80:-}" = 1 ] && echo '0.0.0.0:80' ;;
      443/tcp) [ "${BIND_443:-}" = 1 ] && echo '0.0.0.0:443' ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    ss = fake_bin / "ss"
    ss.write_text(
        """#!/bin/sh
[ "${SS_FAIL:-}" = 1 ] && { echo 'simulated ss failure' >&2; exit 42; }
[ "${LISTEN_80:-}" = 1 ] && echo 'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*'
[ "${LISTEN_443:-}" = 1 ] && echo 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*'
exit 0
""",
        encoding="utf-8",
    )
    ss.chmod(0o755)
    mutation_marker = tmp_path / scenario / "mutation-ran"
    command = "\n".join(
        [
            _shared_front_collision_preflight_command(str(stack_root)),
            f"printf mutated > {mutation_marker}",
        ]
    )
    result = subprocess.run(
        ["/bin/sh", "-c", command],
        capture_output=True,
        text=True,
        env={**os.environ, **settings, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
        check=False,
    )

    assert result.returncode == expected_returncode
    assert mutation_marker.exists() is (expected_returncode == 0)
    if expected_error:
        assert expected_error in result.stderr


def test_multiple_sites_share_stable_base_and_keep_independent_fragments():
    homebase = WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts")
    proxy = WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts")

    first = render_web_static_apply_workspace(intent=_intent("alpha"), homebase=homebase, proxy=proxy)
    second = render_web_static_apply_workspace(intent=_intent("bravo"), homebase=homebase, proxy=proxy)

    assert first.compose.content == second.compose.content
    assert first.front_http_config.content == second.front_http_config.content
    assert first.site_compose.target != second.site_compose.target
    assert "web_alpha" in first.site_compose.content and "web_bravo" not in first.site_compose.content
    assert "web_bravo" in second.site_compose.content and "web_alpha" not in second.site_compose.content
    assert first.front_route.content == "alpha.example.invalid web_alpha:8081;\n"
    assert second.front_route.content == "bravo.example.invalid web_bravo:8081;\n"
    assert "map_hash_bucket_size 512;" not in first.playbook.content
    assert "map_hash_bucket_size 512;" not in second.playbook.content
    assert "map_hash_bucket_size" not in first.front_http_config.content
    assert "map_hash_bucket_size" not in second.front_http_config.content
    assert 'site_root: "/opt/web/alpha"' in first.playbook.content
    assert 'site_root: "/opt/web/bravo"' in second.playbook.content
    assert 'dest: "{{ site_root }}/conf/00-request-header-gate-00-runtime.conf"' in first.playbook.content
    assert 'dest: "{{ site_root }}/conf/00-request-header-gate-00-runtime.conf"' in second.playbook.content


def test_static_web_reapply_preserves_gate_files_without_rendering_https_secrets():
    workspace = render_web_static_apply_workspace(
        intent=_intent("ff10"),
        homebase=WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts"),
        proxy=WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts"),
    )

    assert {artifact.target for artifact in workspace.sensitive_artifacts} == {"helpers/static_web_content.py", "helpers/apply.json", "helpers/check.json", "helpers/rollback.json"}
    playbook = workspace.playbook.content
    assert "Restore retained request-header gate" not in playbook
    for task_name in (
        "Ensure retained request-header gate map hook exists",
        "Ensure retained request-header gate server hook exists",
    ):
        task = playbook.split(f"- name: {task_name}", 1)[1].split("- name:", 1)[0]
        assert "force: false" in task
    assert "Snapshot exact selected runtime files" in playbook
    assert "Restore exact selected runtime files" in playbook


def test_static_web_reapply_migrates_legacy_tls_runtime_and_rolls_back_every_owned_path():
    workspace = render_web_static_apply_workspace(
        intent=_intent("ff10"),
        homebase=WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts"),
        proxy=WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts"),
    )
    playbook = workspace.playbook.content

    preflight = playbook.index("Validate current and legacy site runtime before mutation")
    snapshot = playbook.index("Snapshot exact selected runtime files")
    mutation = playbook.index("Ensure Docker service is running")
    assert preflight < snapshot < mutation
    assert "legacy Static Web route is not exact-owned" in playbook
    assert "plain_config.is_symlink()" in playbook
    assert "legacy Static Web TLS runtime does not match the persisted certificate binding" in playbook
    assert "Static Web HTTP route is not exact-owned" in playbook
    assert "Static Web TLS listener is not an exact Barragan certificate listener" in playbook
    assert "Migrate exact-owned legacy Static Web route" in playbook
    assert "mv /opt/web/ff10/conf/default.conf /opt/web/ff10/tls-conf/default.conf" in playbook
    assert "mv \"/opt/web/ff10/conf/$name\" \"/opt/web/ff10/tls-conf/$name\"" in playbook
    assert "ff10.example.invalid web_ff10_tls:8081;" in playbook
    assert "rm -f \"$legacy\"" in playbook
    for path in (
        "/opt/web/ff10",
        "/opt/web/http/ff10.map",
        "/opt/web/tls/ff10.map",
        "/opt/web/streams/ff10.map",
    ):
        assert path in playbook.split("Snapshot exact selected runtime files", 1)[1]
        assert path in playbook.split("Restore exact selected runtime files", 1)[1]


def test_static_web_reapply_correlates_retained_tls_to_exact_persisted_binding():
    from app.storage.certificate_repository import StoredCertificateBinding

    binding = StoredCertificateBinding(
        id="binding-ff10",
        engagement_id="eng-zy01",
        certificate_id="cert-ff10",
        service_id="web-ff10",
        channel_id="ff10-https",
        hostname="ff10.example.invalid",
        status="bound",
    )
    playbook = render_web_static_apply_workspace(
        intent=_intent("ff10"),
        homebase=WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts"),
        proxy=WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts"),
        retained_binding=binding,
    ).playbook.content

    assert "binding_hostname = 'ff10.example.invalid'" in playbook
    assert "binding_live = '/etc/letsencrypt/live/barragan/cert-ff10/current'" in playbook
    assert "ssl_certificate '+binding_live+'/fullchain.pem;'" in playbook
    assert "ssl_certificate_key '+binding_live+'/privkey.pem;'" in playbook
    assert "--force-recreate" not in playbook
    assert "Find renamed retained TLS Compose containers" in playbook
    assert "Require exact prior selected container state after rollback" in playbook


def test_static_web_apply_and_remove_select_compose_v2_then_v1_and_remove_legacy_route():
    intent = _intent("ff10")
    homebase = WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known_hosts")
    proxy = WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known_hosts")
    playbooks = (
        render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy).playbook.content,
        render_web_static_remove_workspace(intent=intent, homebase=homebase, proxy=proxy).playbook.content,
    )

    for playbook in playbooks:
        assert playbook.index("Detect Docker Compose v2") < playbook.index("Detect Docker Compose v1 fallback")
        assert "when: barragan_compose_v2.rc != 0" in playbook
        assert "['docker', 'compose'] if barragan_compose_v2.rc == 0 else ['docker-compose']" in playbook
        assert "barragan_compose_argv +" in playbook
    remove_playbook = playbooks[1]
    removal = remove_playbook.split("Remove Barragan generated static web config", 1)[1]
    assert "/opt/web/streams/ff10.map" in removal


def test_static_docker_go_templates_survive_ansible_jinja_rendering():
    import yaml
    from jinja2 import Environment, StrictUndefined
    intent = _intent('ff10')
    homebase = WebStaticCoreHost('homebase', '203.0.113.10', 'user', '/keys/core', '', '/tmp/known_hosts')
    proxy = WebStaticCoreHost('proxy01', '192.168.2.11', 'user', '/keys/core', 'user@203.0.113.10', '/tmp/known_hosts')
    playbook = render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy).playbook.content
    parsed = yaml.safe_load(playbook)
    commands = []
    def visit(value):
        if isinstance(value, dict):
            argv = value.get('ansible.builtin.command', {}).get('argv')
            if isinstance(argv, list) and argv[:4] == ['docker', 'inspect', '-f', '{% raw %}{{.State.Running}}{% endraw %}']:
                commands.append(argv)
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(parsed)
    assert len(commands) == 2  # initial snapshot and rollback verification
    environment = Environment(undefined=StrictUndefined)
    assert [environment.from_string(argv[3]).render() for argv in commands] == ['{{.State.Running}}'] * 2
    assert environment.from_string(commands[0][4]).render(item='proxy') == 'proxy'
    assert environment.from_string(commands[1][4]).render(item={'item': 'proxy'}) == 'proxy'


def test_web_static_site_name_separators_become_underscores_for_paths():
    assert _intent("static-web.com").site_name == "static-web_com"
    assert _intent("www.example.ai").site_name == "www_example_ai"
    assert _intent_from_body("zy01", {**_body("chat-redteam"), "siteName": "chat.redteam-example.com/path"}).site_name == "chat_redteam-example_com_path"


def test_preview_web_static_service_uses_latest_core_connection_details(monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    repo = _FakeJobRepository(_core_jobs())

    result = preview_web_static_service_apply(
        "eng-zy01",
        _body("ff10"),
        requested_by="operator",
        repository=repo,
    )

    assert result is not None
    assert result["service"]["serviceType"] == "web-static"
    assert result["service"]["config"]["contentPath"] == "/opt/web/ff10/html/"
    assert result["service"]["config"]["indexPath"] == "/opt/web/ff10/html/index.html"
    assert result["job"]["action"] == "web_static_service_apply_preview"
    event_data = result["job"]["events"][0]["data"]
    assert "servicePlacements" not in event_data
    assert "proxy01 ansible_host=192.168.2.11" in result["workspace"]["inventory"]["content"]
    assert "UserKnownHostsFile=/tmp/barragan-web-static-known-hosts/eng-zy01-job-core.known_hosts" in result["workspace"]["inventory"]["content"]
    assert "middle-" not in result["workspace"]["inventory"]["content"]
    assert "edge-" not in result["workspace"]["inventory"]["content"]


def test_preview_web_static_service_rejects_missing_core_connection_details(monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())

    with pytest.raises(WebStaticServiceValidationError) as exc:
        preview_web_static_service_apply("eng-zy01", _body("ff10"), repository=_FakeJobRepository([]))

    assert "latest core deployment connectionDetails must include homebase" in exc.value.errors


def test_web_static_service_default_index_html_is_neutral():
    from app.services.web_static_service import _intent_from_body

    body = _body("ff10")
    body.pop("indexHtml")

    intent = _intent_from_body("zy01", body)

    assert intent.index_html == "<html><body><h1>It works!</h1></body></html>\n"
    assert "Barragan" not in intent.index_html


def test_web_static_service_rejects_a_host_published_site_port():
    with pytest.raises(WebStaticServiceValidationError) as exc:
        _intent_from_body("zy01", {**_body("ff10"), "internalPort": "18080"})

    assert exc.value.errors == [
        "Static Web site containers use Docker-internal port 8081; the shared proxy front owns public ports 80 and 443"
    ]


def test_apply_web_static_service_writes_workspace_and_records_service(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository()
    commands = []

    def runner(command, cwd):
        commands.append((command, cwd))
        assert (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8").count("[selected_proxy]") == 1
        assert (cwd / "files" / "opt" / "web" / "ff10" / "html" / "index.html").read_text(encoding="utf-8") == "<html><body>hola ff10</body></html>\n"
        assert (cwd / "files" / "opt" / "web" / "docker-compose.yml").exists()
        site_compose = (cwd / "files" / "opt" / "web" / "sites" / "ff10.compose.yml").read_text(encoding="utf-8")
        assert '"8081"' in site_compose
        assert "127.0.0.1:" not in site_compose
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = apply_web_static_service(
        "eng-zy01",
        _body("ff10"),
        requested_by="operator",
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["job"]["input"]["contentAction"] == "publish"
    assert result["job"]["input"]["contentReviewJobId"] == ""
    final_data = result["job"]["events"][-1]["data"]
    assert final_data["contentAction"] == "publish"
    assert final_data["contentOutcome"] == "not-recorded"
    assert final_data["contentRollback"] == "not-recorded"
    assert result["status"] == "Configured"
    assert result["job"]["status"] == "succeeded"
    assert result["service"]["status"] == "Configured"
    assert len(commands) == 1
    assert commands[0][0] == [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/apply_web_static.yml"]
    assert service_repo.saved[-1].service_id == "web-ff10"
    assert service_repo.saved[-1].config["internalPort"] == 8081
    final_event = result["job"]["events"][-1]["data"]
    assert final_event["servicePlacements"][0]["service"] == WEB_STATIC_SERVICE_NAME
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(result)


def test_apply_web_static_service_does_not_copy_https_gate_into_plaintext_sibling(tmp_path, monkeypatch):
    token = "apply-token-123456"
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_https_request_header_gate_for_service",
        lambda engagement_id, service_id: {
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "updatedAt": "2026-08-19T00:00:00+00:00",
        },
    )
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    captured = {}

    def runner(command, cwd):
        captured["cwd"] = cwd
        gate_map = cwd / "files" / "opt" / "web" / "ff10" / "conf" / "00-request-header-gate-map.conf"
        assert not gate_map.exists()
        assert not (cwd / "files" / "opt" / "web" / "ff10" / "conf" / "request-header-gate.inc").exists()
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = apply_web_static_service(
        "eng-zy01",
        _body("ff10"),
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=_FakeServiceRepository(),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["status"] == "Configured"
    serialized = json.dumps(result, sort_keys=True)
    assert token not in serialized
    assert "Bearer " not in serialized
    assert not list((captured["cwd"] / "files" / "opt" / "web").glob("*/conf/*request-header-gate*"))


def test_apply_web_static_service_syncs_nested_content_files(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    body = {
        **_body("ff10"),
        "contentFiles": [
            {"path": "index.html", "content": "<html><body>asset test</body></html>\n", "encoding": "text"},
            {"path": "assets/site.css", "content": "body { color: #111; }\n", "encoding": "text"},
            {"path": "images/logo.txt", "contentBase64": "bG9nbwo=", "encoding": "base64"},
        ],
    }

    def runner(command, cwd):
        assert (cwd / "files" / "opt" / "web" / "ff10" / "html" / "index.html").read_text(encoding="utf-8") == "<html><body>asset test</body></html>\n"
        assert (cwd / "files" / "opt" / "web" / "ff10" / "html" / "assets" / "site.css").read_text(encoding="utf-8") == "body { color: #111; }\n"
        assert (cwd / "files" / "opt" / "web" / "ff10" / "html" / "images" / "logo.txt").read_bytes() == b"logo\n"
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = apply_web_static_service(
        "eng-zy01",
        body,
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=_FakeServiceRepository(),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["service"]["config"]["contentFiles"] == [
        {"path": "index.html", "encoding": "text", "bytes": 37},
        {"path": "assets/site.css", "encoding": "text", "bytes": 22},
        {"path": "images/logo.txt", "encoding": "base64", "bytes": 5},
    ]


def test_start_web_static_service_apply_returns_running_job_and_defers_runner(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository()
    commands = []
    tasks = []

    def runner(command, cwd):
        commands.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, "ok", "")

    result = start_web_static_service_apply(
        "eng-zy01",
        _body("ff10"),
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
        background_runner=tasks.append,
    )

    assert result is not None
    assert result["status"] == "Applying"
    assert result["job"]["status"] == "running"
    assert result["service"]["status"] == "Applying"
    assert commands == []
    assert len(tasks) == 1
    tasks[0]()
    assert commands
    assert service_repo.saved[-1].status == "Configured"


def test_start_web_static_service_apply_blocks_concurrent_same_proxy_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    token = "mutex-token-123456"
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_https_request_header_gate_for_service",
        lambda *_args, **_kwargs: {
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "updatedAt": "2026-08-19T00:00:00+00:00",
        },
    )
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    active_job = _running_web_static_job("job-active", "web_static_service_apply", "proxy01")
    job_repo = _FakeJobRepository([active_job, *_core_jobs()])
    workspace_root = tmp_path / "workspaces"

    with pytest.raises(WebStaticServiceValidationError) as exc:
        start_web_static_service_apply(
            "eng-zy01",
            _body("ff10"),
            repository=job_repo,
            service_repository=_FakeServiceRepository(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
            workspace_root=workspace_root,
            background_runner=lambda task: task(),
        )

    assert exc.value.errors == ["Static Web mutation already running on proxy01: job-active (web_static_service_apply)"]
    assert not workspace_root.exists() or not any(workspace_root.iterdir())
    serialized = json.dumps([job.to_detail().to_dict() for job in job_repo.jobs], sort_keys=True)
    assert token not in serialized
    assert "Bearer " not in serialized


def test_start_web_static_service_apply_scheduler_failure_scrubs_gate_and_restores_terminal_state(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    token = "failure-token-12345"
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_https_request_header_gate_for_service",
        lambda *_args, **_kwargs: {
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "updatedAt": "2026-08-19T00:00:00+00:00",
        },
    )
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    job_repo = _FakeJobRepository(_core_jobs())
    service_repo = _FakeServiceRepository()
    workspace_root = tmp_path / "workspaces"

    with pytest.raises(WebStaticServiceValidationError) as exc:
        start_web_static_service_apply(
            "eng-zy01",
            _body("ff10"),
            repository=job_repo,
            service_repository=service_repo,
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
            workspace_root=workspace_root,
            background_runner=lambda task: (_ for _ in ()).throw(RuntimeError("scheduler unavailable")),
        )

    assert "could not be started" in " ".join(exc.value.errors)
    assert job_repo.saved[-1].status == "failed"
    assert job_repo.saved[-1].events[-1].data["errorType"] == "RuntimeError"
    assert service_repo.saved[-1].status == "Failed"
    assert not workspace_root.exists() or not any(workspace_root.iterdir())
    serialized = json.dumps(job_repo.saved[-1].to_detail().to_dict(), sort_keys=True)
    assert token not in serialized
    assert "Bearer " not in serialized


def test_start_web_static_service_apply_fails_before_mutation_when_capability_prerequisite_fails(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    job_repo = _FakeJobRepository(_core_jobs())
    service_repo = _FakeServiceRepository()

    def fail_prerequisite():
        raise WebStaticServiceValidationError(["capability lock failed"])

    with pytest.raises(WebStaticServiceValidationError) as exc:
        start_web_static_service_apply(
            "eng-zy01",
            _body("ff10"),
            repository=job_repo,
            service_repository=service_repo,
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
            workspace_root=tmp_path / "workspaces",
            background_runner=lambda task: task(),
            before_start=fail_prerequisite,
        )

    assert exc.value.errors == ["capability lock failed"]
    assert service_repo.saved == []
    assert not (tmp_path / "workspaces").exists()
    assert all(job.action != "web_static_service_apply" for job in job_repo.saved)


def test_apply_web_static_service_records_failed_state(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository()

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 4, "", "docker unavailable")

    result = apply_web_static_service(
        "eng-zy01",
        _body("ff10"),
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["status"] == "Failed"
    assert result["job"]["status"] == "failed"
    assert result["service"]["status"] == "Failed"
    assert result["job"]["events"][-1]["data"]["servicePlacements"][0]["status"] == "Failed"
    assert result["job"]["input"]["proxyId"] == "proxy01"


def test_failed_static_web_reapply_restores_exact_prior_service_record(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    prior = _stored_service("eng-zy01", "ff10")
    service_repo = _FakeServiceRepository([prior])

    result = apply_web_static_service(
        "eng-zy01",
        {**_body("ff10"), "indexHtml": "replacement that must roll back"},
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
        certificate_repository=_FakeCertificateRepository(),
        runner=lambda command, cwd: subprocess.CompletedProcess(command, 4, "", "late validation failed"),
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["job"]["status"] == "failed"
    assert service_repo.get("eng-zy01", "web-ff10") == prior
    assert service_repo.saved[-1] == prior


def test_preview_web_static_service_remove_preserves_content_directory(monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    service_repo = _FakeServiceRepository([_stored_service("eng-zy01", "ff10")])

    result = preview_web_static_service_remove(
        "eng-zy01",
        "web-ff10",
        requested_by="operator",
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
    )

    assert result is not None
    assert result["confirmationToken"] == "remove-web-ff10"
    assert result["workspace"]["status"] == "Pending Service Removal"
    playbook = result["workspace"]["playbook"]["content"]
    assert "docker-compose" in playbook
    assert "/opt/web/sites/ff10.compose.yml" in playbook
    assert "/opt/web/ff10/html" in playbook
    assert 'state: absent' in playbook
    assert 'state: directory' in playbook
    assert "middle-" not in result["workspace"]["inventory"]["content"]
    assert "edge-" not in result["workspace"]["inventory"]["content"]


def test_remove_web_static_service_runs_proxy_only_ansible_and_records_removed(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository([_stored_service("eng-zy01", "ff10")])
    commands = []

    def runner(command, cwd):
        commands.append((command, cwd))
        assert (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8").count("[selected_proxy]") == 1
        playbook = (cwd / "ansible" / "remove_web_static.yml").read_text(encoding="utf-8")
        assert "/opt/web/ff10/conf/default.conf" in playbook
        assert "/opt/web/ff10/html" in playbook
        return subprocess.CompletedProcess(command, 0, "removed", "")

    result = remove_web_static_service(
        "eng-zy01",
        "web-ff10",
        {"confirmation": "remove-web-ff10"},
        requested_by="operator",
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
        certificate_repository=_FakeCertificateRepository(),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
    )

    assert result is not None
    assert result["status"] == "Removed"
    assert result["job"]["status"] == "succeeded"
    assert result["service"]["status"] == "Removed"
    assert commands[0][0] == [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/remove_web_static.yml"]
    assert service_repo.saved[-1].status == "Removed"
    assert result["job"]["events"][-1]["data"]["servicePlacements"][0]["status"] == "Removed"
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(result)


def test_start_web_static_service_remove_returns_running_job_and_defers_runner(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository([_stored_service("eng-zy01", "ff10")])
    commands = []
    tasks = []

    def runner(command, cwd):
        commands.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, "removed", "")

    result = start_web_static_service_remove(
        "eng-zy01",
        "web-ff10",
        {"confirmation": "remove-web-ff10"},
        repository=_FakeJobRepository(_core_jobs()),
        service_repository=service_repo,
        certificate_repository=_FakeCertificateRepository(),
        runner=runner,
        env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        workspace_root=tmp_path / "workspaces",
        background_runner=tasks.append,
    )

    assert result is not None
    assert result["status"] == "Removing"
    assert result["job"]["status"] == "running"
    assert result["service"]["status"] == "Removing"
    assert commands == []
    assert len(tasks) == 1
    tasks[0]()
    assert commands
    assert service_repo.saved[-1].status == "Removed"


def test_start_web_static_service_remove_blocks_concurrent_same_proxy_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    active_job = _running_web_static_job("job-active", "web_static_service_remove", "proxy01")

    with pytest.raises(WebStaticServiceValidationError) as exc:
        start_web_static_service_remove(
            "eng-zy01",
            "web-ff10",
            {"confirmation": "remove-web-ff10"},
            repository=_FakeJobRepository([active_job, *_core_jobs()]),
            service_repository=_FakeServiceRepository([_stored_service("eng-zy01", "ff10")]),
            certificate_repository=_FakeCertificateRepository(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
            workspace_root=tmp_path / "workspaces",
            background_runner=lambda task: task(),
        )

    assert exc.value.errors == ["Static Web mutation already running on proxy01: job-active (web_static_service_remove)"]


def test_remove_web_static_service_requires_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")
    service_repo = _FakeServiceRepository([_stored_service("eng-zy01", "ff10")])

    with pytest.raises(WebStaticServiceValidationError) as exc:
        remove_web_static_service(
            "eng-zy01",
            "web-ff10",
            {"confirmation": "wrong"},
            repository=_FakeJobRepository(_core_jobs()),
            service_repository=service_repo,
            certificate_repository=_FakeCertificateRepository(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        )

    assert 'confirmation must equal "remove-web-ff10"' in exc.value.errors


def test_remove_web_static_service_rejects_persisted_certificate_binding(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.web_static_service.get_engagement", lambda engagement_id: type("Engagement", (), {"name": "zy01"})())
    ansible_playbook = _executable(tmp_path, "ansible-playbook")

    with pytest.raises(WebStaticServiceValidationError) as exc:
        remove_web_static_service(
            "eng-zy01",
            "web-ff10",
            {"confirmation": "remove-web-ff10"},
            repository=_FakeJobRepository(_core_jobs()),
            service_repository=_FakeServiceRepository([_stored_service("eng-zy01", "ff10")]),
            certificate_repository=_FakeCertificateRepository(binding=object()),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible_playbook)},
        )

    assert exc.value.errors == ["remove the persisted certificate binding before removing this Static Web service"]


def _body(site_name):
    return {
        "proxyId": "proxy01",
        "siteName": site_name,
        "domain": f"{site_name}.example.invalid",
        "internalPort": "8081",
        "indexHtml": f"<html><body>hola {site_name}</body></html>\n",
    }


def _intent(site_name):
    from app.services.web_static_service import _intent_from_body

    return _intent_from_body("zy01", _body(site_name))


def _stored_service(engagement_id, site_name):
    return StoredEngagementService(
        engagement_id=engagement_id,
        service_id=f"web-{site_name}",
        service_type="web-static",
        name=site_name,
        proxy_id="proxy01",
        status="Configured",
        config={
            "siteName": site_name,
            "domain": f"{site_name}.example.invalid",
            "internalPort": 18080,
            "contentPath": f"/opt/web/{site_name}/html/",
            "indexPath": f"/opt/web/{site_name}/html/index.html",
            "contentFiles": [{"path": "index.html", "encoding": "text", "bytes": 46}],
            "siteConfigPath": f"/opt/web/{site_name}/conf/default.conf",
            "composePath": f"/opt/web/barragan-{site_name}.compose.yml",
        },
    )


def _core_jobs():
    return [
        StoredJobRun(
            id="job-core",
            action="pilot_standard_rti_guarded_execute",
            status="succeeded",
            target="oci-compartment:barragan-testing",
            target_type="oci_compartment",
            target_id="ocid1.compartment.oc1..testing",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-04T12:00:00+00:00",
            started_at="2026-06-04T12:01:00+00:00",
            finished_at="2026-06-04T12:05:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "operator inspection ready",
                    {
                        "connectionDetails": [
                            {
                                "role": "homebase",
                                "displayName": "homebase-zy01",
                                "publicIp": "203.0.113.10",
                                "privateIp": "192.168.0.10",
                                "sshUser": "user",
                            },
                            {
                                "role": "proxy",
                                "displayName": "proxy01-zy01",
                                "publicIp": "203.0.113.11",
                                "privateIp": "192.168.2.11",
                                "sshUser": "user",
                            },
                        ]
                    },
                )
            ],
        )
    ]


def _running_web_static_job(job_id, action, proxy_id):
    return StoredJobRun(
        id=job_id,
        action=action,
        status="running",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input={"engagementId": "eng-zy01", "serviceId": "web-active", "serviceType": "web-static", "proxyId": proxy_id, "mutation": True},
        artifact_refs=[],
        created_at="2026-07-23T00:00:00+00:00",
        started_at="2026-07-23T00:00:00+00:00",
        finished_at=None,
        events=[],
    )


def _executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class _FakeJobRepository:
    def __init__(self, jobs):
        self.jobs = list(jobs)
        self.saved = []

    def list(self):
        return list(self.jobs)

    def list_for_engagement(self, engagement_id):
        return [
            job
            for job in self.jobs
            if job.target_id == engagement_id
            or job.target == f"engagement:{engagement_id}"
            or job.input.get("engagementId") == engagement_id
        ]

    def get(self, job_id):
        for job in self.jobs:
            if job.id == job_id:
                return job
        return None

    def save(self, job):
        self.jobs = [existing for existing in self.jobs if existing.id != job.id]
        self.jobs.insert(0, job)
        self.saved.append(job)
        return job


class _FakeServiceRepository:
    def __init__(self, services=None):
        self.services = list(services or [])
        self.saved = []

    def list_for_engagement(self, engagement_id):
        return [service for service in self.services if service.engagement_id == engagement_id]

    def list_for_engagement_and_proxy(self, engagement_id, proxy_id):
        return [service for service in self.list_for_engagement(engagement_id) if service.proxy_id == proxy_id]

    def get(self, engagement_id, service_id):
        for service in self.services:
            if service.engagement_id == engagement_id and service.service_id == service_id:
                return service
        return None

    def save(self, service):
        self.services = [
            existing
            for existing in self.services
            if not (existing.engagement_id == service.engagement_id and existing.service_id == service.service_id)
        ]
        self.services.append(service)
        self.saved.append(service)
        return service


class _FakeCertificateRepository:
    def __init__(self, binding=None):
        self.binding = binding

    def get_binding_for_service(self, _engagement_id, _service_id):
        return self.binding
