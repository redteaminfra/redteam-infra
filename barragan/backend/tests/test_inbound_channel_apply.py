# Copyright (c) 2026, Oracle and/or its affiliates.
from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.services.redteam_infra_template import redteam_infra_path
from redteam_infra_test_fixtures import write_sketch_template_fixture
from app.services.inbound_channel_apply import (
    InboundChannelApplyValidationError,
    InboundResolvedRoute,
    InboundRouteTarget,
    preview_inbound_channel_apply,
    remove_inbound_channel,
    render_inbound_apply_workspace,
    render_inbound_remove_workspace,
    render_inbound_validation_workspace,
    _merged_inbound_channels,
    _proxy_runtime_registry_command,
    _render_apply_workspace_for_channel,
    _resolved_spec_from_channel,
    _save_managed_http_backend_site,
    _spec_from_channel,
    _run_command,
    validate_inbound_channel,
    _finish_inbound_apply_job_and_maybe_validate,
)
from app.domain import JobEvent
from app.storage.job_repository import StoredJobRun
from app.services.inbound_backend_authorization import InboundBackendAuthorization
from app.services.inbound_channel_artifacts import (
    InboundChannelArtifactSpec,
    compact_inbound_channel_from_spec,
    http_backend_service_name,
    render_inbound_channel_artifacts,
)


class InboundChannelApplyTests(unittest.TestCase):
    def test_automatic_validation_start_failure_is_durable_and_retryable(self):
        pending_channel = {
            "channelId": "route-1",
            "status": "Pending Validation",
            "validation": {"status": "Pending Validation"},
            "validationProfile": {"type": "udp-send-receive"},
        }
        applied = StoredJobRun(
            id="job-apply",
            action="inbound_channel_apply",
            status="succeeded",
            target="engagement:eng-1",
            target_type="engagement",
            target_id="eng-1",
            requested_by="operator",
            input={"engagementId": "eng-1", "channelId": "route-1"},
            artifact_refs=[],
            created_at="2026-09-15T00:00:00+00:00",
            started_at="2026-09-15T00:00:00+00:00",
            finished_at="2026-09-15T00:01:00+00:00",
            events=[JobEvent(1, "info", "inbound channel validation pending", {"inboundChannels": [pending_channel]})],
        )

        class Repository:
            def save(self, job):
                return job

        with (
            patch("app.services.inbound_channel_apply._finish_inbound_apply_job", return_value=applied),
            patch("app.services.inbound_channel_apply.try_enqueue_infra_orientation_refresh"),
            patch(
                "app.services.inbound_channel_apply.validate_inbound_channel",
                side_effect=InboundChannelApplyValidationError(["validation runner is unavailable"]),
            ),
        ):
            result = _finish_inbound_apply_job_and_maybe_validate(
                Repository(),
                applied,
                "eng-1",
                "route-1",
                [],
                Path("/tmp/unused"),
                lambda _command, _cwd: subprocess.CompletedProcess([], 0),
                pending_channel,
                "chain-1",
                "engagement-1",
                requested_by="operator",
                env=None,
                workspace_root=None,
                auto_validate=True,
            )

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.events[-1].level, "error")
        self.assertEqual(result.events[-1].message, "inbound channel automatic validation failed to start")
        self.assertEqual(result.events[-1].data["errors"], ["validation runner is unavailable"])
        self.assertEqual(result.events[-2].data["inboundChannels"][0]["status"], "Pending Validation")

    def test_preview_reports_missing_existing_channel_without_crashing(self):
        with (
            patch(
                "app.services.inbound_channel_apply.get_engagement",
                return_value=SimpleNamespace(id="eng-demo", name="demo"),
            ),
            patch(
                "app.services.inbound_channel_apply.get_operations_overview",
                return_value={"inboundChannels": []},
            ),
        ):
            with self.assertRaises(InboundChannelApplyValidationError) as caught:
                preview_inbound_channel_apply("eng-demo", "missing-channel")

        self.assertEqual(caught.exception.errors, ["inbound channel missing-channel was not found"])

    def test_resolves_duplicate_middle_hostname_by_recorded_chain_identity(self):
        overview, channel = _http_validation_overview()
        overview["sketchInfrastructure"].extend(
            [
                {"chainId": "proxy01-chain-002", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.120", "proxy": "proxy01"},
                {"chainId": "proxy01-chain-002", "hostname": "edge-zy01-us-sea-02", "role": "edge", "publicIp": "203.0.113.130", "proxy": "proxy01"},
            ]
        )
        channel.update({"chainId": "proxy01-chain-002", "edge": "edge-zy01-us-sea-02"})

        spec, route = _resolved_spec_from_channel("zy01", overview, channel)

        self.assertEqual(spec.sketch_chain_id, "proxy01-chain-002")
        self.assertEqual(route.middle.public_ip, "203.0.113.120")
        self.assertEqual(route.edge.public_ip, "203.0.113.130")

    def test_legacy_channel_rejects_ambiguous_same_named_edge(self):
        overview, channel = _http_validation_overview()
        overview["sketchInfrastructure"].extend(
            [
                {"chainId": "proxy01-chain-002", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.120", "proxy": "proxy01"},
                {"chainId": "proxy01-chain-002", "hostname": "edge-zy01-us-sea-01", "role": "edge", "publicIp": "203.0.113.130", "proxy": "proxy01"},
            ]
        )

        with self.assertRaises(InboundChannelApplyValidationError) as caught:
            _resolved_spec_from_channel("zy01", overview, channel)
        self.assertIn("ambiguous", " ".join(caught.exception.errors))

    def test_legacy_channel_with_unique_edge_recovers_its_chain_identity(self):
        overview, channel = _http_validation_overview()
        overview["sketchInfrastructure"].extend(
            [
                {"chainId": "proxy01-chain-002", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.120", "proxy": "proxy01"},
                {"chainId": "proxy01-chain-002", "hostname": "edge-zy01-us-sea-02", "role": "edge", "publicIp": "203.0.113.130", "proxy": "proxy01"},
            ]
        )
        channel["edge"] = "edge-zy01-us-sea-02"

        spec, route = _resolved_spec_from_channel("zy01", overview, channel)

        self.assertEqual(spec.sketch_chain_id, "proxy01-chain-002")
        self.assertEqual(route.middle.public_ip, "203.0.113.120")

    def test_status_updates_preserve_managed_service_binding_metadata(self):
        existing = {
            "channelId": "channel-443",
            "status": "Pending Apply",
            "serviceId": "web-shazbot-party",
            "serviceType": "web-static",
            "chainId": "proxy01-chain-001",
            "backendPort": "9999",
        }
        updated = {"channelId": "channel-443", "status": "Validated"}

        with patch(
            "app.services.inbound_channel_apply.get_operations_overview",
            return_value={"inboundChannels": [existing]},
        ):
            merged = _merged_inbound_channels("eng-demo", "channel-443", updated)

        self.assertEqual(merged[0]["status"], "Validated")
        self.assertEqual(merged[0]["serviceId"], "web-shazbot-party")
        self.assertEqual(merged[0]["serviceType"], "web-static")
        self.assertEqual(merged[0]["chainId"], "proxy01-chain-001")
        self.assertEqual(merged[0]["backendPort"], "9999")

    def test_run_command_sets_bash_shell_for_proxyjump_from_service_user(self):
        captured: dict[str, object] = {}

        class FakeProcess:
            returncode = 0

            def communicate(self, timeout=None):
                captured["timeout"] = timeout
                return "ok", ""

        def fake_popen(command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs
            return FakeProcess()

        with patch("app.services.inbound_channel_apply.subprocess.Popen", fake_popen):
            result = _run_command(["ansible-playbook", "--version"], Path("/tmp"))

        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        env = kwargs["env"]
        assert isinstance(env, dict)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(env["SHELL"], "/bin/sh")
        self.assertEqual(captured["timeout"], 900)
        self.assertTrue(kwargs["start_new_session"])

    def test_renders_apply_workspace_with_required_sketch_jump_paths(self):
        spec = _spec()
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)
        playbooks = {playbook.target: playbook.content for playbook in workspace.playbooks}
        preflight_playbook = playbooks["ansible/preflight_inbound_channel.yml"]
        prepare_playbook = playbooks["ansible/prepare_inbound_hosts.yml"]
        apply_playbook = playbooks["ansible/apply_inbound_channel.yml"]
        combined_playbooks = "\n".join(playbooks.values())

        self.assertEqual(
            list(playbooks),
            [
                "ansible/preflight_inbound_channel.yml",
                "ansible/prepare_inbound_hosts.yml",
                "ansible/apply_inbound_channel.yml",
            ],
        )
        self.assertIn("[selected_proxy]", workspace.inventory.content)
        self.assertIn("[selected_middle]", workspace.inventory.content)
        self.assertIn("[selected_edge]", workspace.inventory.content)
        self.assertIn("middle01-zy01 ansible_host=middle01-zy01 ansible_user=root", workspace.inventory.content)
        self.assertIn("edge-zy01-us-sea-01 ansible_host=edge-zy01-us-sea-01 ansible_user=root", workspace.inventory.content)
        self.assertIn("-F ansible/ssh_config", workspace.inventory.content)
        self.assertIn("proxy01-zy01 ansible_host=proxy01-zy01", workspace.inventory.content)
        self.assertIn("middle01-zy01 ansible_host=middle01-zy01", workspace.inventory.content)
        self.assertIn("edge-zy01-us-sea-01 ansible_host=edge-zy01-us-sea-01", workspace.inventory.content)
        self.assertIn("ansible_ssh_private_key_file=/var/lib/barragan/sketch-keys/zy01-sketch", workspace.inventory.content)
        self.assertIn("Host proxy01-zy01", workspace.ssh_config.content)
        self.assertIn("    ProxyJump homebase", workspace.ssh_config.content)
        self.assertIn("Host middle01-zy01", workspace.ssh_config.content)
        self.assertEqual(workspace.ssh_config.content.count("    User root"), 2)
        self.assertNotIn("    User sketchssh", workspace.ssh_config.content)
        self.assertIn("    ProxyJump proxy01-zy01", workspace.ssh_config.content)
        self.assertIn("Host edge-zy01-us-sea-01", workspace.ssh_config.content)
        self.assertIn("    ProxyJump middle01-zy01", workspace.ssh_config.content)
        self.assertNotIn(" nc %h %p", workspace.inventory.content)
        self.assertNotIn(" nc %h %p", workspace.ssh_config.content)
        self.assertNotIn("/opt/ssh-proxy/keys/zy01-sketch", prepare_playbook)
        self.assertNotIn("Stage engagement sketch SSH key", prepare_playbook)
        self.assertIn("hosts: selected_edge", combined_playbooks)
        self.assertIn("hosts: selected_middle", combined_playbooks)
        self.assertIn("hosts: selected_proxy", combined_playbooks)
        self.assertIn("Preflight inbound management path for selected_proxy", preflight_playbook)
        self.assertIn("Preflight inbound management path for selected_middle", preflight_playbook)
        self.assertIn("Preflight inbound management path for selected_edge", preflight_playbook)
        self.assertIn("timeout: 420", preflight_playbook)
        self.assertNotIn("ansible.builtin.apt:", preflight_playbook)
        self.assertIn("/etc/nginx/streams/barragan-c2-primary-edge-443.conf", apply_playbook)
        self.assertIn("/etc/nginx/streams/barragan-c2-primary-middle-443.conf", apply_playbook)
        self.assertIn("/etc/nginx/streams/barragan-c2-primary-proxy-443.conf", apply_playbook)
        self.assertEqual(prepare_playbook.count("Disable distro default HTTP site on inbound stream host"), 3)
        self.assertIn("path: /etc/nginx/sites-enabled/default", prepare_playbook)
        self.assertNotIn("proxy_protocol on;", combined_playbooks)
        self.assertIn("ansible.builtin.command: nginx -t", prepare_playbook)
        self.assertIn("ansible.builtin.command: nginx -t", apply_playbook)
        self.assertIn("state: reloaded", apply_playbook)
        self.assertIn("ansible.builtin.lineinfile:", prepare_playbook)
        self.assertIn("ansible.builtin.blockinfile:", prepare_playbook)
        self.assertIn("Ensure existing nginx stream block includes Barragan stream directory", prepare_playbook)
        self.assertIn("insertafter: '^stream[[:space:]]*\\{'", prepare_playbook)
        self.assertIn("line: '    include streams/*.conf;'", prepare_playbook)
        self.assertNotIn("line: include modules-enabled/50-mod-stream.conf;", combined_playbooks)
        self.assertNotIn("dest: /etc/nginx/nginx.conf", combined_playbooks)
        self.assertIn("ansible.builtin.apt:", apply_playbook)
        self.assertLess(
            apply_playbook.index("Open inbound channel firewall paths"),
            apply_playbook.index("Prepare inbound nginx stream host selected_proxy"),
        )
        self.assertIn('barragan_transport_protocol: "tcp"', apply_playbook)
        self.assertIn("ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_edge_ip }}", apply_playbook)
        self.assertIn('when: "inventory_hostname in groups[\'selected_edge\'] and \'Status: active\' in barragan_ufw_status.stdout"', apply_playbook)
        self.assertIn('when: "inventory_hostname in groups[\'selected_middle\'] and \'Status: active\' in barragan_ufw_status.stdout"', apply_playbook)
        self.assertIn('when: "inventory_hostname in groups[\'selected_proxy\'] and \'Status: active\' in barragan_ufw_status.stdout"', apply_playbook)
        self.assertIn("source_arg='-s {{ barragan_edge_ip }}'", apply_playbook)
        self.assertIn("source_arg='-s {{ barragan_middle_ip }}'", apply_playbook)
        self.assertIn("comment=\"barragan-inbound-{{ barragan_channel_id }}-${rule_role}\"", apply_playbook)
        self.assertIn("Verify TCP inbound listener is bound", apply_playbook)
        self.assertIn("ss -H -ltn | awk '{print $4}'", apply_playbook)
        self.assertNotIn("Wait for TCP inbound listener", apply_playbook)
        self.assertIn('"directSketchAccessFromAppHost": false', workspace.manifest.content)
        self.assertIn('"playbook": "ansible/preflight_inbound_channel.yml"', workspace.manifest.content)
        self.assertNotIn('"playbook": "ansible/prepare_inbound_hosts.yml"', workspace.manifest.content)
        self.assertIn('"playbook": "ansible/apply_inbound_channel.yml"', workspace.manifest.content)
        self.assertIn('"resolvedRoute": {', workspace.manifest.content)
        self.assertIn('"proxyJump": "homebase->proxy"', workspace.manifest.content)
        self.assertIn('"proxyJump": "homebase->proxy->middle"', workspace.manifest.content)
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", str(workspace.to_dict()))
        self.assertNotIn("LINODE_TOKEN", str(workspace.to_dict()))
        self.assertNotIn("DIGITALOCEAN_TOKEN", str(workspace.to_dict()))

    def test_native_static_web_http_binding_reuses_its_owned_front_route(self):
        spec = _spec(
            protocol="HTTP",
            mode="http-openresty",
            external_port=80,
            internal_port=80,
            service="Static Web",
            service_id="web-campaign-site",
            service_type="web-static",
        )
        artifacts = render_inbound_channel_artifacts(spec)
        apply_workspace = render_inbound_apply_workspace(spec, artifacts)
        remove_workspace = render_inbound_remove_workspace(spec, artifacts)

        self.assertEqual(artifacts.proxy_stream.target, "/opt/web/http/campaign-site.map")
        self.assertIn("# Barragan-managed route", artifacts.proxy_stream.content)
        self.assertIn("owner: shared proxy-front OpenResty", artifacts.proxy_stream.content)
        self.assertIn("c2.example.invalid web_campaign_site:8081;", artifacts.proxy_stream.content)
        self.assertIn("Record sanitized Barragan-managed proxy routes", apply_workspace.playbook.content)
        self.assertIn(
            'target = Path("/var/lib/barragan/managed-runtime/barragan-routes.json")',
            apply_workspace.playbook.content,
        )
        self.assertIn("os.fchmod(fd, 0o644)", apply_workspace.playbook.content)
        self.assertIn("fcntl.flock(lock_fd, fcntl.LOCK_EX)", apply_workspace.playbook.content)
        self.assertIn("failed_when: false", apply_workspace.playbook.content)
        self.assertIn("path: /var/lib/barragan/managed-runtime", apply_workspace.playbook.content)
        self.assertNotIn("path: /opt/web\n        state: directory", apply_workspace.playbook.content)
        self.assertNotIn("Bind HTTP backend route on shared proxy OpenResty stack", apply_workspace.playbook.content)
        self.assertNotIn("Converge generic HTTP backend proxy", apply_workspace.playbook.content)
        self.assertIn("Prepare inbound nginx stream host selected_middle", apply_workspace.playbook.content)
        self.assertIn("Prepare inbound nginx stream host selected_edge", apply_workspace.playbook.content)
        self.assertNotIn("Remove HTTP backend route from shared proxy OpenResty stack", remove_workspace.playbook.content)
        self.assertIn("Remove selected route from sanitized proxy registry", remove_workspace.playbook.content)
        self.assertIn("fcntl.flock(lock_fd, fcntl.LOCK_EX)", remove_workspace.playbook.content)

    def test_native_static_web_https_binding_reuses_its_owned_front_route(self):
        spec = _spec(
            protocol="HTTPS",
            mode="https-openresty",
            external_port=443,
            internal_port=443,
            service="Static Web",
            service_id="web-campaign-site",
            service_type="web-static",
        )
        artifacts = render_inbound_channel_artifacts(spec)
        apply_workspace = render_inbound_apply_workspace(spec, artifacts)
        remove_workspace = render_inbound_remove_workspace(spec, artifacts)

        self.assertEqual(artifacts.proxy_stream.target, "/opt/web/tls/campaign-site.map")
        self.assertIn("# Barragan-managed route", artifacts.proxy_stream.content)
        self.assertIn("c2.example.invalid web_campaign_site_tls:8081;", artifacts.proxy_stream.content)
        self.assertIn("Record sanitized Barragan-managed proxy routes", apply_workspace.playbook.content)
        self.assertIn("Remove selected route from sanitized proxy registry", remove_workspace.playbook.content)

    def test_proxy_route_registry_serializes_concurrent_writers_and_recovers_malformed_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            registry = root / "barragan-routes.json"
            lock = root / ".barragan-routes.lock"

            def run_upsert(index: int) -> subprocess.CompletedProcess[str]:
                route_id = f"route-{index:02d}"
                command = _proxy_runtime_registry_command(
                    operation="upsert",
                    channel_id=route_id,
                    entry={"routeId": route_id, "mode": "tcp-forward"},
                    registry_path=str(registry),
                    lock_path=str(lock),
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
                return subprocess.run(["/bin/bash", "-c", command], capture_output=True, text=True, check=False)

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(run_upsert, range(24)))

            self.assertTrue(all(result.returncode == 0 for result in results), [result.stderr for result in results])
            document = json.loads(registry.read_text(encoding="utf-8"))
            self.assertEqual(document["schemaVersion"], 1)
            self.assertEqual(document["managedBy"], "barragan")
            self.assertEqual([row["routeId"] for row in document["routes"]], [f"route-{index:02d}" for index in range(24)])
            self.assertEqual(registry.stat().st_mode & 0o777, 0o644)

            registry.write_text("{malformed", encoding="utf-8")
            recovery_command = _proxy_runtime_registry_command(
                operation="remove",
                channel_id="route-00",
                registry_path=str(registry),
                lock_path=str(lock),
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            recovered = subprocess.run(
                ["/bin/bash", "-c", recovery_command], capture_output=True, text=True, check=False
            )

            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertIn("recovered", recovered.stdout)
            self.assertEqual(json.loads(registry.read_text(encoding="utf-8"))["routes"], [])

            victim = root / "victim"
            victim.write_text("do not replace", encoding="utf-8")
            registry.unlink()
            registry.symlink_to(victim)
            symlink_recovery = run_upsert(99)
            self.assertEqual(symlink_recovery.returncode, 0, symlink_recovery.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not replace")
            self.assertFalse(registry.is_symlink())

            lock.unlink()
            lock.symlink_to(victim)
            rejected_lock = run_upsert(100)
            self.assertNotEqual(rejected_lock.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not replace")

            lock.unlink()
            root.chmod(0o775)
            rejected_parent = run_upsert(101)
            self.assertNotEqual(rejected_parent.returncode, 0)
            self.assertIn("not owned and writable only", rejected_parent.stderr)
            root.chmod(0o700)

    def test_every_inbound_mode_uses_the_same_registry_lock_for_apply_and_remove(self):
        cases = (
            ("TCP", "tcp-forward", 8443),
            ("UDP", "udp-forward", 5353),
            ("HTTP", "http-openresty", 80),
            ("HTTPS", "https-openresty", 443),
        )

        for protocol, mode, external_port in cases:
            with self.subTest(mode=mode):
                overrides = {"protocol": protocol, "mode": mode, "external_port": external_port}
                if protocol == "UDP":
                    overrides["validation_profile"] = {
                        "type": "udp-send-receive",
                        "label": "UDP route check",
                        "requestText": "PING",
                        "expectedResponse": "PONG",
                    }
                spec = _spec(**overrides)
                artifacts = render_inbound_channel_artifacts(spec)
                apply_playbook = render_inbound_apply_workspace(spec, artifacts).playbook.content
                remove_playbook = render_inbound_remove_workspace(spec, artifacts).playbook.content

                for playbook in (apply_playbook, remove_playbook):
                    self.assertEqual(playbook.count("fcntl.flock(lock_fd, fcntl.LOCK_EX)"), 1)
                    self.assertIn(
                        'lock_path = Path("/var/lib/barragan/managed-runtime/.barragan-routes.lock")',
                        playbook,
                    )
                    self.assertIn("os.replace(temporary_name, target)", playbook)
                    self.assertIn("os.O_NOFOLLOW", playbook)
                    self.assertIn("stat.S_ISREG", playbook)
                    self.assertIn("os.fchown(fd, 0, 0)", playbook)
                    self.assertIn("failed_when: false", playbook)

    def test_apply_manifest_includes_allowed_core_proxy_ingress_assessment(self):
        spec = _spec(external_port=8001)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)
        manifest = json.loads(workspace.manifest.content)
        assessment = manifest["ingressAssessment"]
        checks = {check["scope"]: check for check in assessment["checks"]}

        self.assertIn("Barragan-managed route c2-primary; owner: dedicated proxy stream", artifacts.proxy_stream.content)
        self.assertIn('"routingOwner": "dedicated-stream"', workspace.playbook.content)

        self.assertEqual(assessment["status"], "allowed")
        self.assertTrue(assessment["applyAllowed"])
        self.assertEqual(assessment["protocol"], "tcp")
        self.assertEqual(assessment["proxyRelayPort"], 8001)
        self.assertEqual(checks["edgeProviderIngress"]["status"], "managed")
        self.assertEqual(checks["edgeHostFirewall"]["status"], "managed")
        self.assertEqual(checks["middleHostFirewall"]["status"], "managed")
        self.assertEqual(checks["proxyHostFirewall"]["status"], "managed")
        self.assertEqual(checks["coreProxyCloudIngress"]["status"], "allowed")
        self.assertEqual(checks["terminationListenerExpectation"]["status"], "unknown")
        self.assertIn("8001/tcp", checks["coreProxyCloudIngress"]["detail"])
        self.assertEqual(manifest["channel"]["ingressAssessment"], assessment)

    def test_apply_manifest_marks_blocked_core_proxy_relay_port(self):
        spec = _spec(external_port=2121)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)
        manifest = json.loads(workspace.manifest.content)
        assessment = manifest["ingressAssessment"]
        core_check = next(check for check in assessment["checks"] if check["scope"] == "coreProxyCloudIngress")

        self.assertEqual(assessment["status"], "blocked")
        self.assertFalse(assessment["applyAllowed"])
        self.assertEqual(assessment["blockedChecks"], ["core-proxy-cloud-ingress"])
        self.assertEqual(core_check["status"], "blocked")
        self.assertIn("selected core proxy relay port 2121/tcp is blocked", core_check["detail"])
        self.assertIn("Select an allowed relay port", core_check["correctiveAction"])

    def test_apply_manifest_blocks_generic_backflips_proxy_socket_collision(self):
        spec = _spec(
            external_port=2222,
            terminates_on="proxy01-zy01",
            service="SSH Backflips",
            internal_port=2222,
            purpose="ssh backflips",
        )
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)
        manifest = json.loads(workspace.manifest.content)
        assessment = manifest["ingressAssessment"]
        checks = {check["scope"]: check for check in assessment["checks"]}

        self.assertEqual(assessment["status"], "blocked")
        self.assertFalse(assessment["applyAllowed"])
        self.assertEqual(assessment["blockedChecks"], ["proxy-service-port-collision"])
        self.assertEqual(checks["proxyServiceSocket"]["status"], "blocked")
        self.assertIn("SSH Backflips owns proxy01-zy01:2222", checks["proxyServiceSocket"]["detail"])
        self.assertIn("generic inbound channel cannot also bind", checks["proxyServiceSocket"]["detail"])
        self.assertIn("SSH Backflips capability configuration", checks["proxyServiceSocket"]["correctiveAction"])

    def test_renders_core_jump_paths_with_recorded_non_root_users(self):
        spec = _spec()
        artifacts = render_inbound_channel_artifacts(spec)
        route = InboundResolvedRoute(
            homebase=InboundRouteTarget("homebase-zy01", "203.0.113.10", public_ip="203.0.113.10", private_ip="192.168.0.10", ssh_user="operator"),
            proxy=InboundRouteTarget("proxy01-zy01", "192.168.2.11", public_ip="203.0.113.11", private_ip="192.168.2.11", ssh_user="proxyop"),
            middle=InboundRouteTarget("middle01-zy01", "198.51.100.20", public_ip="198.51.100.20", chain_id="chain-1"),
            edge=InboundRouteTarget("edge-zy01-us-sea-01", "198.51.100.30", public_ip="198.51.100.30", chain_id="chain-1"),
            termination=InboundRouteTarget("homebase-zy01", "203.0.113.10", public_ip="203.0.113.10", private_ip="192.168.0.10", ssh_user="operator"),
        )

        workspace = render_inbound_apply_workspace(spec, artifacts, route=route)

        self.assertIn("proxy01-zy01 ansible_host=proxy01-zy01 ansible_user=proxyop", workspace.inventory.content)
        self.assertIn("Host proxy01-zy01", workspace.ssh_config.content)
        self.assertIn("    HostName 192.168.2.11", workspace.ssh_config.content)
        self.assertIn("    ProxyJump homebase-zy01", workspace.ssh_config.content)
        self.assertIn("Host middle01-zy01", workspace.ssh_config.content)
        self.assertIn("    HostName 198.51.100.20", workspace.ssh_config.content)
        self.assertIn("    ProxyJump proxy01-zy01", workspace.ssh_config.content)
        self.assertIn("Host edge-zy01-us-sea-01", workspace.ssh_config.content)
        self.assertIn("    HostName 198.51.100.30", workspace.ssh_config.content)
        self.assertIn("    ProxyJump middle01-zy01", workspace.ssh_config.content)
        self.assertNotIn(" nc %h %p", workspace.to_dict().__repr__())
        self.assertIn('"ansibleUser": "operator"', workspace.manifest.content)
        self.assertIn('"ansibleUser": "proxyop"', workspace.manifest.content)
        self.assertEqual(workspace.inventory.content.count("ansible_user=root"), 2)
        self.assertNotIn("ansible_user=sketchssh", workspace.inventory.content)

    def test_rejects_root_core_management_user(self):
        spec = _spec()
        artifacts = render_inbound_channel_artifacts(spec)
        route = InboundResolvedRoute(
            homebase=InboundRouteTarget("homebase-zy01", "203.0.113.10", ssh_user="root"),
            proxy=InboundRouteTarget("proxy01-zy01", "192.168.2.11", ssh_user="proxyop"),
            middle=InboundRouteTarget("middle01-zy01", "198.51.100.20"),
            edge=InboundRouteTarget("edge-zy01-us-sea-01", "198.51.100.30"),
            termination=InboundRouteTarget("homebase-zy01", "203.0.113.10", ssh_user="root"),
        )

        with self.assertRaises(InboundChannelApplyValidationError):
            render_inbound_apply_workspace(spec, artifacts, route=route)

    def test_generated_sketch_operator_templates_keep_root_ssh_limited_to_bootstrap_inventory(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            "os.environ",
            {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": temp_dir},
        ):
            write_sketch_template_fixture(Path(temp_dir), providers=("linode", "digitalocean"))
            inventory_paths = [
                redteam_infra_path("external", "sketch", "linode", "templates", "inventory.tftpl"),
                redteam_infra_path("external", "sketch", "digitalocean", "templates", "inventory.tftpl"),
            ]
            operator_paths = [
                redteam_infra_path("external", "sketch", "linode", "templates", "ssh-stanza.tftpl"),
                redteam_infra_path("external", "sketch", "digitalocean", "templates", "ssh-stanza.tftpl"),
                redteam_infra_path("external", "sketch", "tooling", "sketch-json-config.py"),
                redteam_infra_path("external", "sketch", "tooling", "README.md"),
            ]
            for path in inventory_paths:
                content = path.read_text(encoding="utf-8")
                with self.subTest(path=str(path)):
                    self.assertIn("ansible_ssh_user=", content)
                    self.assertNotIn("root@", content)
            for path in operator_paths:
                content = path.read_text(encoding="utf-8")
                with self.subTest(path=str(path)):
                    self.assertNotIn("User root", content)
                    self.assertNotIn("ansible_ssh_user=root", content)
                    self.assertNotIn("ansible_user=root", content)
                    self.assertNotIn("root@", content)

    def test_renders_remove_workspace_with_ufw_numbered_rule_parsing(self):
        spec = _spec()
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_remove_workspace(spec, artifacts)

        self.assertIn("grep 'barragan-inbound-{{ barragan_channel_id }}-edge'", workspace.playbook.content)
        self.assertIn("sed -n 's/^\\[[[:space:]]*\\([0-9][0-9]*\\)\\].*/\\1/p'", workspace.playbook.content)
        self.assertNotIn("gsub(/[][]/", workspace.playbook.content)

    def test_non_proxy_termination_receives_channel_specific_firewall_rules(self):
        spec = _spec(
            protocol="UDP",
            mode="udp-forward",
            external_port=53,
            relay_port=8053,
            internal_port=53053,
            validation_profile={
                "type": "udp-send-receive",
                "label": "UDP request response",
                "requestText": "PING",
                "expectedResponse": "PONG",
            },
        )
        artifacts = render_inbound_channel_artifacts(spec)
        route = InboundResolvedRoute(
            homebase=InboundRouteTarget("homebase-zy01", "203.0.113.10", public_ip="203.0.113.10", private_ip="192.168.0.10", ssh_user="operator"),
            proxy=InboundRouteTarget("proxy01-zy01", "192.168.2.11", public_ip="203.0.113.11", private_ip="192.168.2.11", ssh_user="operator"),
            middle=InboundRouteTarget("middle01-zy01", "198.51.100.20", public_ip="198.51.100.20", chain_id="chain-1"),
            edge=InboundRouteTarget("edge-zy01-us-sea-01", "198.51.100.30", public_ip="198.51.100.30", chain_id="chain-1"),
            termination=InboundRouteTarget("homebase-zy01", "203.0.113.10", public_ip="203.0.113.10", private_ip="192.168.0.10", ssh_user="operator"),
        )

        workspace = render_inbound_apply_workspace(spec, artifacts, route=route)
        apply_playbook = workspace.playbook.content
        manifest = json.loads(workspace.manifest.content)
        termination_check = next(check for check in manifest["ingressAssessment"]["checks"] if check["scope"] == "terminationHostFirewall")

        self.assertIn("[inbound_firewall_targets:children]\ninbound_channel_targets\ntermination_host", workspace.inventory.content)
        self.assertIn("hosts: inbound_firewall_targets", apply_playbook)
        self.assertEqual(apply_playbook.count("hosts: termination_host"), 0)
        self.assertIn('barragan_transport_protocol: "udp"', apply_playbook)
        self.assertIn("barragan_termination_listen_port: 53053", apply_playbook)
        self.assertIn('barragan_proxy_ip: "192.168.2.11"', apply_playbook)
        termination_allow = "ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_proxy_ip }} to any port {{ barragan_termination_listen_port }} comment barragan-inbound-{{ barragan_channel_id }}-termination"
        self.assertIn(termination_allow, apply_playbook)
        termination_ufw_play = apply_playbook.split("Restrict termination listener to the selected proxy with UFW", 1)[1].split("Allow channel listener with iptables", 1)[0]
        termination_iptables_play = apply_playbook.split("Apply selected proxy termination allow with iptables", 1)[1].split("Persist iptables rules", 1)[0]
        self.assertNotIn("ufw insert 1 deny", termination_ufw_play)
        self.assertIn('for owned_comment in "${comment}" "${comment}-deny"', termination_iptables_play)
        self.assertIn('-e "--comment ${owned_comment} "', termination_iptables_play)
        self.assertIn('-e "--comment \\"${owned_comment}\\" "', termination_iptables_play)
        self.assertIn("grep -F -- '-A INPUT '", termination_iptables_play)
        self.assertLess(termination_iptables_play.index('iptables -D INPUT "${rule_number}"'), termination_iptables_play.index("iptables -I INPUT 1 -s {{ barragan_proxy_ip }}"))
        self.assertIn("-j ACCEPT", termination_iptables_play)
        self.assertNotIn("-j DROP", termination_iptables_play)
        self.assertEqual(termination_check["status"], "managed")
        self.assertEqual(termination_check["host"], "homebase-zy01")
        self.assertEqual(termination_check["port"], 53053)
        self.assertEqual(termination_check["protocol"], "udp")
        self.assertEqual(termination_check["source"], "192.168.2.11")

    def test_termination_firewall_requires_restrictive_shared_input_baseline(self):
        spec = _spec(internal_port=53053)
        artifacts = render_inbound_channel_artifacts(spec)
        apply_playbook = render_inbound_apply_workspace(spec, artifacts).playbook.content
        baseline_play = apply_playbook.split("Require restrictive termination host input baseline", 1)[1].split("Allow public edge listener", 1)[0]

        self.assertIn("ufw status verbose", baseline_play)
        self.assertIn("^Default: (deny|reject) \\(incoming\\)", baseline_play)
        self.assertIn("-P INPUT DROP", baseline_play)
        self.assertIn("^-A INPUT -j (DROP|REJECT)", baseline_play)
        self.assertNotIn("failed_when: false", baseline_play)

    def test_remove_clears_only_termination_firewall_rule_without_assuming_port_exclusivity(self):
        spec = _spec(internal_port=53053)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_remove_workspace(spec, artifacts)
        firewall_play = workspace.playbook.content

        self.assertIn("hosts: inbound_firewall_targets", firewall_play)
        self.assertIn("barragan-inbound-{{ barragan_channel_id }}-termination", firewall_play)
        termination_ufw_remove = firewall_play.split("Delete proxy to termination UFW rule", 1)[1].split("Delete channel iptables rule", 1)[0]
        self.assertNotIn("grep -v", termination_ufw_remove)
        self.assertIn("Delete selected proxy termination allow with iptables", firewall_play)
        self.assertIn('for owned_comment in "${comment}" "${comment}-deny"', firewall_play)
        self.assertIn('-e "--comment ${owned_comment} "', firewall_play)
        self.assertIn('-e "--comment \\"${owned_comment}\\" "', firewall_play)
        termination_iptables_remove = firewall_play.split("Delete selected proxy termination allow with iptables", 1)[1].split("Persist iptables rules", 1)[0]
        self.assertIn("${comment}-deny", termination_iptables_remove)
        self.assertNotIn("Verify removed inbound channel listeners are absent", firewall_play)
        self.assertNotIn("Verify removed TCP listener is absent", firewall_play)
        self.assertNotIn("Verify removed UDP listener is absent", firewall_play)
        self.assertNotIn("state: stopped", firewall_play)

    def test_renders_proxy_local_termination_without_extra_termination_inventory_group(self):
        spec = _spec(terminates_on="proxy01-zy01", service="SSH Backflips", internal_port=8001)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)

        self.assertNotIn("[termination_host]", workspace.inventory.content)
        self.assertNotIn("hosts: termination_host", workspace.playbook.content)
        self.assertNotIn("barragan-inbound-{{ barragan_channel_id }}-termination", workspace.playbook.content)
        self.assertNotIn("rule_role='termination'", workspace.playbook.content)
        self.assertNotIn("barragan_termination_listen_port", workspace.playbook.content)
        manifest = json.loads(workspace.manifest.content)
        self.assertNotIn("terminationHostFirewall", {check["scope"] for check in manifest["ingressAssessment"]["checks"]})
        self.assertIn("proxy_pass 127.0.0.1:8001;", workspace.playbook.content)

    def test_https_openresty_apply_uses_proxy_protocol_only_on_edge(self):
        spec = _spec(mode="https-openresty")
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)

        self.assertEqual(artifacts.route_family, "shared-web-ingress")
        self.assertIn("proxy_protocol on;", artifacts.edge_stream.content)
        self.assertNotIn("proxy_protocol on;", artifacts.middle_stream.content)
        self.assertNotIn("proxy_protocol on;", artifacts.proxy_stream.content)
        self.assertEqual(artifacts.edge_stream.target, "/etc/nginx/streams/barragan-web-edge-to-middle01-zy01-443.conf")
        self.assertEqual(artifacts.middle_stream.target, "/etc/nginx/streams/barragan-web-middle-to-proxy01-zy01-443.conf")
        self.assertEqual(workspace.playbook.content.count("proxy_protocol on;"), 1)
        self.assertNotIn("Apply inbound channel stream on selected_proxy", workspace.playbook.content)
        self.assertIn(artifacts.proxy_stream.target, workspace.playbook.content)
        prepare = next(item.content for item in workspace.playbooks if item.target.endswith("prepare_inbound_hosts.yml"))
        self.assertNotIn("Prepare inbound nginx stream host selected_proxy", prepare)
        remove = render_inbound_remove_workspace(spec, artifacts)
        self.assertIn("barragan_shared_https_front: true", remove.playbook.content)
        self.assertNotIn("Verify removed inbound channel listeners are absent", remove.playbook.content)

    def test_http_openresty_converges_generic_proxy_owned_backend_route(self):
        spec = _spec(protocol="HTTP", mode="http-openresty", external_port=80, internal_port=9999)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)
        playbook = workspace.playbook.content

        self.assertIn("Bind HTTP backend route on shared proxy OpenResty stack", playbook)
        self.assertLess(playbook.index("Refuse to mutate an unowned shared front stack"), playbook.index("Write shared front OpenResty config"))
        self.assertIn("Refuse shared front TCP port collision", playbook)
        self.assertIn("ss -H -ltn '( sport = :80 or sport = :443 )'", playbook)
        self.assertIn("Barragan will not stop it to start the shared OpenResty front", playbook)
        self.assertLess(playbook.index("Refuse shared front TCP port collision"), playbook.index("Verify upstream Docker Compose runtime"))
        self.assertLess(playbook.index("Refuse shared front TCP port collision"), playbook.index("Converge shared front OpenResty"))
        self.assertIn(
            "argv: [docker, compose, -f, /opt/web/docker-compose.yml, exec, -T, reverse-proxy, openresty, -t]",
            playbook,
        )
        shared_front = playbook.split("- name: Bind HTTP backend route on shared proxy OpenResty stack", 1)[1].split(
            "- name: Prepare inbound nginx stream host selected_middle", 1
        )[0]
        self.assertNotIn("Stop host nginx before shared front convergence", shared_front)
        self.assertNotIn("name: nginx", shared_front)
        self.assertIn("Wait for selected backend listener", playbook)
        self.assertIn("proxy_pass http://homebase-zy01:9999;", playbook)
        self.assertIn("- /opt/web/http:/etc/openresty/http:ro", playbook)
        self.assertIn("- certbot-etc:/etc/letsencrypt", playbook)
        self.assertIn("include /etc/openresty/http/*.map;", playbook)
        self.assertIn("client_max_body_size 10240000000;", playbook)
        self.assertIn("client_max_body_size 500000000;", playbook)
        self.assertIn("proxy_request_buffering off;", playbook)
        self.assertIn("Write HTTP backend request-header gate runtime", playbook)
        self.assertIn("00-request-header-gate-00-runtime.conf", playbook)
        self.assertIn("Inspect selected HTTP backend proxy mounts", playbook)
        self.assertIn("from_json", playbook)
        self.assertIn("selectattr('Source', 'equalto'", playbook)
        self.assertIn("selectattr('Destination', 'equalto', '/etc/nginx/conf.d')", playbook)
        self.assertIn("/opt/web/inbound/c2_primary/conf:/etc/nginx/conf.d:ro", playbook)
        self.assertIn("Require selected HTTP request-body policy in effective configuration", playbook)
        self.assertIn("no_log: true", playbook)
        self.assertLess(
            playbook.index("Validate generic HTTP backend proxy"),
            playbook.index("Inspect selected HTTP backend proxy mounts"),
        )
        self.assertLess(
            playbook.index("Require selected HTTP request-body policy in effective configuration"),
            playbook.index("Reload generic HTTP backend proxy"),
        )
        tls_map = playbook.split("map $ssl_preread_server_name", 1)[1].split("- name: Write shared front compose file", 1)[0]
        self.assertNotIn("/etc/openresty/http", tls_map)
        self.assertIn(artifacts.proxy_stream.target, playbook)
        self.assertIn(http_backend_service_name("c2-primary"), playbook)
        self.assertNotIn("barragan_inbound_c2_primary", playbook)
        self.assertNotIn("Apply inbound channel stream on selected_proxy", playbook)
        remove = render_inbound_remove_workspace(spec, artifacts).playbook.content
        self.assertIn("Classify shared front ownership before route removal", remove)
        self.assertIn("No shared front stack exists; this failed route made no proxy-side web changes to remove.", remove)
        self.assertIn("barragan_front_ownership.rc in [0, 2]", remove)
        self.assertIn("Refuse to mutate an existing unowned shared front stack", remove)
        self.assertIn("when: barragan_front_ownership.rc == 0", remove)
        self.assertIn("Remove generic HTTP backend proxy", remove)
        self.assertIn("Remove HTTP Host route", remove)
        self.assertNotIn("Remove inbound nginx stream on selected_edge", remove)
        self.assertNotIn("Remove inbound nginx stream on selected_middle", remove)

    def test_shared_https_record_only_remove_runs_registry_cleanup_and_retains_baseline_plumbing(self):
        saved_jobs = []

        class FakeRepo:
            def list(self):
                return []

            def save(self, job):
                saved_jobs.append(job)
                return job

        channel = {
            "channelId": "edge-zy01-us-sea-01-443-to-proxy01-443",
            "domain": "www.example.invalid",
            "protocol": "HTTPS",
            "mode": "https-openresty",
            "externalPort": "443",
            "edge": "edge-zy01-us-sea-01",
            "middle": "middle01-zy01",
            "proxy": "proxy01-zy01",
            "terminatesOn": "proxy01-zy01",
            "service": "OpenResty",
            "internalPort": "443",
            "purpose": "web ingress",
            "status": "Validated",
            "validationProfile": {"type": "tcp-connect", "label": "TLS route check"},
        }
        overview = {
            "coreInfrastructure": [
                {"hostname": "homebase-zy01", "role": "homebase", "publicIp": "198.51.100.10", "sshUser": "user"},
                {"hostname": "proxy01-zy01", "role": "proxy", "privateIp": "192.0.2.11", "publicIp": "198.51.100.11", "sshUser": "user"},
            ],
            "sketchInfrastructure": [
                {"chainId": "proxy01-chain-001", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.20", "proxy": "proxy01"},
                {"chainId": "proxy01-chain-001", "hostname": "edge-zy01-us-sea-01", "role": "edge", "publicIp": "203.0.113.30", "proxy": "proxy01"},
            ],
            "inboundChannels": [channel],
        }

        commands = []
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.inbound_channel_apply.get_engagement", return_value=type("Engagement", (), {"name": "ZY01"})()):
                with patch("app.services.inbound_channel_apply.get_operations_overview", return_value=overview):
                    with patch("app.services.inbound_channel_apply.resolve_ansible_playbook", return_value=SimpleNamespace(ok=True, command="ansible-playbook", error="")):
                        with patch(
                            "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
                            return_value=(str(Path(temp_dir) / "keys" / "admin"), str(Path(temp_dir) / "keys" / "admin.pub")),
                        ):
                            result = remove_inbound_channel(
                                "eng-zy01",
                                channel["channelId"],
                                confirmation=f"remove-inbound-{channel['channelId']}",
                                repository=FakeRepo(),
                                workspace_root=Path(temp_dir),
                                runner=lambda command, cwd: (
                                    commands.append((command, cwd, (cwd / "ansible/remove_inbound_channel.yml").read_text(encoding="utf-8")))
                                    or subprocess.CompletedProcess(command, 0, stdout="registry removed", stderr="")
                                ),
                            )

        self.assertEqual(result["status"], "Removed")
        self.assertEqual(len(commands), 1)
        self.assertIn("Remove selected route from sanitized proxy registry", commands[0][2])
        self.assertNotIn("Close inbound channel firewall paths", commands[0][2])
        self.assertNotIn("Remove inbound nginx stream", commands[0][2])
        self.assertTrue(saved_jobs[0].input["mutation"])
        removed = saved_jobs[-1].events[-1].data["inboundChannels"][0]
        self.assertEqual(removed["status"], "Removed")
        self.assertTrue(removed["sharedWebIngress"])
        self.assertIn("baseline edge/middle web pass-through", removed["validation"]["detail"])

    def test_managed_gosus_tls_remove_runs_the_full_teardown(self):
        saved_jobs = []

        class FakeRepo:
            def list(self):
                return saved_jobs

            def save(self, job):
                saved_jobs.append(job)
                return job

        channel = {
            "channelId": "edge-zy01-us-sea-01-443-to-proxy01-443-upload-example-invalid",
            "domain": "upload.example.invalid",
            "protocol": "HTTPS",
            "mode": "https-openresty",
            "externalPort": "443",
            "edge": "edge-zy01-us-sea-01",
            "middle": "middle01-zy01",
            "proxy": "proxy01-zy01",
            "terminatesOn": "proxy01-zy01",
            "service": "Go Simple Upload Server",
            "serviceId": "http-site-0123456789abcdef",
            "serviceType": "web-http-backend",
            "internalPort": "443",
            "backendPort": "9999",
            "purpose": "upload ingress",
            "status": "Validated",
            "validationProfile": {"type": "manual", "label": "Bind TLS certificate, then validate HTTPS upload from Inspector"},
        }
        overview = {
            "coreInfrastructure": [
                {"hostname": "homebase-zy01", "role": "homebase", "publicIp": "198.51.100.10", "privateIp": "192.168.0.10", "sshUser": "user"},
                {"hostname": "proxy01-zy01", "role": "proxy", "privateIp": "192.0.2.11", "publicIp": "198.51.100.11", "sshUser": "user"},
            ],
            "sketchInfrastructure": [
                {"chainId": "proxy01-chain-001", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.20", "proxy": "proxy01"},
                {"chainId": "proxy01-chain-001", "hostname": "edge-zy01-us-sea-01", "role": "edge", "publicIp": "203.0.113.30", "proxy": "proxy01"},
            ],
            "inboundChannels": [channel],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.inbound_channel_apply.get_engagement", return_value=type("Engagement", (), {"name": "ZY01"})()):
                with patch("app.services.inbound_channel_apply.get_operations_overview", return_value=overview):
                    with patch("app.services.inbound_channel_apply.resolve_ansible_playbook", return_value=SimpleNamespace(ok=True, command="ansible-playbook", error="")):
                        with patch(
                            "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
                            return_value=(str(Path(temp_dir) / "keys" / "admin"), str(Path(temp_dir) / "keys" / "admin.pub")),
                        ):
                            result = remove_inbound_channel(
                                "eng-zy01", channel["channelId"], confirmation=f"remove-inbound-{channel['channelId']}",
                                repository=FakeRepo(), workspace_root=Path(temp_dir),
                                runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
                            )

        self.assertEqual(result["status"], "Removed")
        self.assertTrue(saved_jobs[0].input["mutation"])
        workspace_evidence = saved_jobs[0].events[0].data["workspaceEvidence"]
        self.assertIn("Close managed HTTP backend Homebase firewall path", workspace_evidence["playbook"]["content"])
        self.assertTrue(any(event.message == "inbound channel Ansible remove succeeded" for job in saved_jobs for event in job.events))

    def test_native_static_web_https_remove_runs_registry_cleanup_service_path(self):
        saved_jobs = []
        commands = []

        class FakeRepo:
            def list(self):
                return saved_jobs

            def save(self, job):
                saved_jobs.append(job)
                return job

        spec = _spec(
            protocol="HTTPS",
            mode="https-openresty",
            external_port=443,
            internal_port=443,
            service="Static Web",
            service_id="web-campaign-site",
            service_type="web-static",
        )
        artifacts = render_inbound_channel_artifacts(spec)
        route = InboundResolvedRoute(
            homebase=InboundRouteTarget("homebase-zy01", "192.168.0.10", private_ip="192.168.0.10", ssh_user="user"),
            proxy=InboundRouteTarget("proxy01-zy01", "192.168.2.11", private_ip="192.168.2.11", ssh_user="user"),
            middle=InboundRouteTarget("middle01-zy01", "203.0.113.20", public_ip="203.0.113.20", chain_id="chain-1"),
            edge=InboundRouteTarget("edge-zy01-us-sea-01", "203.0.113.30", public_ip="203.0.113.30", chain_id="chain-1"),
            termination=None,
        )
        channel = {
            **compact_inbound_channel_from_spec(spec, artifacts),
            "status": "Validated",
            "edge": route.edge.name,
            "middle": route.middle.name,
            "proxy": route.proxy.name,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                patch("app.services.inbound_channel_apply.get_engagement", return_value=type("Engagement", (), {"name": "ZY01"})()),
                patch("app.services.inbound_channel_apply.get_operations_overview", return_value={"inboundChannels": [channel]}),
                patch(
                    "app.services.inbound_channel_apply._render_channel_workspace",
                    return_value=(channel, spec, artifacts, None, route),
                ),
                patch(
                    "app.services.inbound_channel_apply.resolve_ansible_playbook",
                    return_value=SimpleNamespace(ok=True, command="ansible-playbook", error=""),
                ),
                patch(
                    "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
                    return_value=(str(root / "keys/admin"), str(root / "keys/admin.pub")),
                ),
            ):
                result = remove_inbound_channel(
                    "eng-zy01",
                    spec.channel_id,
                    confirmation=f"remove-inbound-{spec.channel_id}",
                    repository=FakeRepo(),
                    workspace_root=root,
                    runner=lambda command, cwd: (
                        commands.append((cwd / "ansible/remove_inbound_channel.yml").read_text(encoding="utf-8"))
                        or subprocess.CompletedProcess(command, 0, stdout="registry removed", stderr="")
                    ),
                )

        self.assertEqual(result["status"], "Removed")
        self.assertEqual(len(commands), 1)
        self.assertIn("Remove selected route from sanitized proxy registry", commands[0])
        self.assertNotIn("Close inbound channel firewall paths", commands[0])
        removed = saved_jobs[-1].events[-1].data["inboundChannels"][0]
        self.assertEqual(removed["serviceType"], "web-static")
        self.assertEqual(removed["status"], "Removed")

    def test_http_openresty_remove_and_reapply_preserve_shared_provider_ingress(self):
        saved_jobs = []

        class FakeRepo:
            def list(self):
                return saved_jobs

            def save(self, job):
                saved_jobs.append(job)
                return job

        channel = {
            "channelId": "edge-zy01-us-sea-01-80-to-homebase-9999-upload-example-invalid",
            "domain": "upload.example.invalid", "protocol": "HTTP", "mode": "http-openresty", "externalPort": "80",
            "edge": "edge-zy01-us-sea-01", "middle": "middle01-zy01", "proxy": "proxy01-zy01",
            "terminatesOn": "homebase-zy01", "service": "File service", "internalPort": "9999", "purpose": "upload ingress",
            "status": "Validated", "validationProfile": {"type": "http", "label": "HTTP route check", "expectedResponse": "HTTP status below 500"},
        }
        overview = {
            "coreInfrastructure": [
                {"hostname": "homebase-zy01", "role": "homebase", "publicIp": "198.51.100.10", "privateIp": "192.168.0.10", "sshUser": "user"},
                {"hostname": "proxy01-zy01", "role": "proxy", "privateIp": "192.0.2.11", "publicIp": "198.51.100.11", "sshUser": "user"},
            ],
            "sketchInfrastructure": [
                {"chainId": "proxy01-chain-001", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.20", "proxy": "proxy01"},
                {"chainId": "proxy01-chain-001", "hostname": "edge-zy01-us-sea-01", "role": "edge", "publicIp": "203.0.113.30", "proxy": "proxy01"},
            ],
            "inboundChannels": [channel],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.inbound_channel_apply.get_engagement", return_value=type("Engagement", (), {"name": "ZY01"})()):
                with patch("app.services.inbound_channel_apply.get_operations_overview", return_value=overview):
                    with patch("app.services.inbound_channel_apply.resolve_ansible_playbook", return_value=SimpleNamespace(ok=True, command="ansible-playbook", error="")):
                        with patch(
                            "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
                            return_value=(str(Path(temp_dir) / "keys" / "admin"), str(Path(temp_dir) / "keys" / "admin.pub")),
                        ):
                            with patch("app.services.inbound_channel_apply.sync_provider_ingress_for_inbound_channel", side_effect=AssertionError("shared provider ingress must be retained")):
                                result = remove_inbound_channel(
                                    "eng-zy01", channel["channelId"], confirmation=f"remove-inbound-{channel['channelId']}",
                                    repository=FakeRepo(), workspace_root=Path(temp_dir),
                                    runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
                                )

        self.assertEqual(result["status"], "Removed")
        workspace_evidence = saved_jobs[0].events[0].data["workspaceEvidence"]
        self.assertIn("Remove HTTP Host route", workspace_evidence["playbook"]["content"])
        self.assertTrue(any(job.status == "succeeded" for job in saved_jobs))

    def test_udp_forward_apply_remove_use_udp_relay_ports_and_edge_local_validation(self):
        spec = _spec(
            protocol="UDP",
            mode="udp-forward",
            external_port=53,
            relay_port=8053,
            internal_port=18080,
            validation_profile={
                "type": "udp-send-receive",
                "label": "UDP request response",
                "requestText": "PING",
                "expectedResponse": "FF0000",
            },
        )
        artifacts = render_inbound_channel_artifacts(spec)
        apply_workspace = render_inbound_apply_workspace(spec, artifacts)
        remove_workspace = render_inbound_remove_workspace(spec, artifacts)
        validation_workspace = render_inbound_validation_workspace(spec, artifacts)
        apply_playbook = apply_workspace.playbook.content
        remove_playbook = remove_workspace.playbook.content
        manifest = json.loads(apply_workspace.manifest.content)

        self.assertIn("listen 53 udp reuseport;", artifacts.edge_stream.content)
        self.assertIn("proxy_pass middle01-zy01:8053;", artifacts.edge_stream.content)
        self.assertIn("listen 8053 udp reuseport;", artifacts.middle_stream.content)
        self.assertIn("proxy_pass proxy01-zy01:8053;", artifacts.middle_stream.content)
        self.assertIn("listen 8053 udp reuseport;", artifacts.proxy_stream.content)
        self.assertIn("proxy_pass homebase-zy01:18080;", artifacts.proxy_stream.content)
        self.assertNotIn("proxy_protocol on;", str(artifacts.to_dict()))
        self.assertIn('barragan_transport_protocol: "udp"', apply_playbook)
        self.assertIn("barragan_edge_listen_port: 53", apply_playbook)
        self.assertIn("barragan_middle_listen_port: 8053", apply_playbook)
        self.assertIn("barragan_proxy_listen_port: 8053", apply_playbook)
        self.assertIn("ufw allow proto {{ barragan_transport_protocol }} to any port {{ barragan_edge_listen_port }}", apply_playbook)
        self.assertIn("ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_edge_ip }} to any port {{ barragan_middle_listen_port }}", apply_playbook)
        self.assertIn("ufw insert 1 allow proto {{ barragan_transport_protocol }} from {{ barragan_middle_ip }} to any port {{ barragan_proxy_listen_port }}", apply_playbook)
        self.assertIn("ufw insert 1 deny proto {{ barragan_transport_protocol }} to any port {{ barragan_middle_listen_port }}", apply_playbook)
        self.assertIn("ufw insert 1 deny proto {{ barragan_transport_protocol }} to any port {{ barragan_proxy_listen_port }}", apply_playbook)
        self.assertLess(apply_playbook.index("Open inbound channel firewall paths"), apply_playbook.index("Prepare inbound nginx stream host selected_proxy"))
        self.assertIn("-p {{ barragan_transport_protocol }} --dport ${rule_port}", apply_playbook)
        self.assertIn("Verify UDP inbound listener", apply_playbook)
        self.assertIn("for attempt in $(seq 1 10); do", apply_playbook)
        self.assertIn("ss -H -lun | awk '{print $4}'", apply_playbook)
        self.assertNotIn("ss -lun | awk '{print $5}'", apply_playbook)
        self.assertIn("when: barragan_transport_protocol == 'udp'", apply_playbook)
        self.assertIn("-p {{ barragan_transport_protocol }} --dport ${rule_port}", remove_playbook)
        self.assertIn('--comment "${deny_comment}" -j DROP', remove_playbook)
        self.assertNotIn("Verify removed UDP listener is absent", remove_playbook)
        self.assertNotIn("state: stopped", remove_playbook)
        self.assertEqual(manifest["ingressAssessment"]["protocol"], "udp")
        self.assertEqual(manifest["ingressAssessment"]["externalPort"], 53)
        self.assertEqual(manifest["ingressAssessment"]["relayPort"], 8053)
        self.assertEqual(manifest["ingressAssessment"]["middleRelayPort"], 8053)
        self.assertEqual(manifest["ingressAssessment"]["proxyRelayPort"], 8053)
        self.assertEqual(manifest["ingressAssessment"]["terminationPort"], 18080)
        core_check = next(check for check in manifest["ingressAssessment"]["checks"] if check["scope"] == "coreProxyCloudIngress")
        self.assertEqual(core_check["status"], "allowed")
        self.assertEqual(core_check["port"], 8053)
        self.assertIn("8000-8080/udp", core_check["detail"])
        self.assertIn("Send UDP validation probe from selected edge through inbound route", validation_workspace.playbook.content)
        self.assertNotIn("hosts: localhost", validation_workspace.playbook.content)
        self.assertNotIn("barragan-app", str(validation_workspace.to_dict()))

    def test_udp_forward_marks_blocked_core_proxy_relay_port(self):
        spec = _spec(
            protocol="UDP",
            mode="udp-forward",
            external_port=53,
            relay_port=2121,
            internal_port=18080,
            validation_profile={
                "type": "udp-send-receive",
                "label": "UDP request response",
                "requestText": "PING",
                "expectedResponse": "FF0000",
            },
        )
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_apply_workspace(spec, artifacts)
        manifest = json.loads(workspace.manifest.content)
        assessment = manifest["ingressAssessment"]
        core_check = next(check for check in assessment["checks"] if check["scope"] == "coreProxyCloudIngress")

        self.assertEqual(assessment["status"], "blocked")
        self.assertFalse(assessment["applyAllowed"])
        self.assertEqual(assessment["blockedChecks"], ["core-proxy-cloud-ingress"])
        self.assertEqual(core_check["status"], "blocked")
        self.assertIn("selected core proxy relay port 2121/udp is blocked", core_check["detail"])
        self.assertIn("Select an allowed UDP relay port", core_check["correctiveAction"])

    def test_renders_validation_workspace_with_temporary_listener_and_edge_probe(self):
        spec = _spec()
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_validation_workspace(spec, artifacts)

        self.assertIn("[selected_edge]", workspace.inventory.content)
        self.assertIn("[termination_host]", workspace.inventory.content)
        self.assertIn("proxy01-zy01 ansible_host=proxy01-zy01", workspace.inventory.content)
        self.assertIn("middle01-zy01 ansible_host=middle01-zy01", workspace.inventory.content)
        self.assertIn("edge-zy01-us-sea-01 ansible_host=edge-zy01-us-sea-01", workspace.inventory.content)
        self.assertIn("-F ansible/ssh_config", workspace.inventory.content)
        self.assertIn("    ProxyJump middle01-zy01", workspace.ssh_config.content)
        self.assertNotIn(" nc %h %p", workspace.inventory.content)
        self.assertNotIn(" nc %h %p", workspace.ssh_config.content)
        self.assertIn("hosts: termination_host", workspace.playbook.content)
        self.assertIn("hosts: selected_edge", workspace.playbook.content)
        self.assertNotIn("hosts: localhost", workspace.playbook.content)
        self.assertNotIn("connection: local", workspace.playbook.content)
        self.assertIn("python3 -c", workspace.playbook.content)
        self.assertIn("while time.time()<deadline", workspace.playbook.content)
        self.assertIn("if data:", workspace.playbook.content)
        self.assertIn("matched=expected in data", workspace.playbook.content)
        self.assertIn("Wait for temporary listener port", workspace.playbook.content)
        self.assertIn("port: 7443", workspace.playbook.content)
        self.assertIn("Send validation marker from selected edge through inbound route", workspace.playbook.content)
        self.assertIn("127.0.0.1", workspace.playbook.content)
        self.assertIn("register: inbound_validation_probe", workspace.playbook.content)
        self.assertIn("Show validation probe evidence", workspace.playbook.content)
        self.assertIn("/tmp/barragan-inbound-c2-primary.marker", workspace.playbook.content)
        self.assertIn('"directSketchAccessFromAppHost": false', workspace.manifest.content)
        self.assertIn('"directEdgeProbeFromAppHost": false', workspace.manifest.content)
        self.assertIn('"probeOrigin": "selected_edge"', workspace.manifest.content)
        self.assertIn('"validationScope": "edge-local ingress route"', workspace.manifest.content)
        self.assertIn('"externalIngressVerified": false', workspace.manifest.content)
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", str(workspace.to_dict()))
        self.assertNotIn("barragan-app", str(workspace.to_dict()))

    def test_renders_tcp_send_receive_validation_without_temporary_listener(self):
        spec = _spec(
            validation_profile={
                "type": "tcp-send-receive",
                "label": "Raw TCP banner",
                "requestText": "PING",
                "expectedResponse": "PONG",
            }
        )
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_validation_workspace(spec, artifacts)

        self.assertEqual(artifacts.validation.profile_type, "tcp-send-receive")
        self.assertEqual(artifacts.validation.expected_response, "PONG")
        self.assertNotIn("Start temporary inbound validation listener", workspace.playbook.content)
        self.assertNotIn("Wait for temporary listener port", workspace.playbook.content)
        self.assertNotIn("hosts: termination_host", workspace.playbook.content)
        self.assertIn("hosts: selected_edge", workspace.playbook.content)
        self.assertNotIn("hosts: localhost", workspace.playbook.content)
        self.assertNotIn("connection: local", workspace.playbook.content)
        self.assertIn("Send TCP validation probe from selected edge through inbound route", workspace.playbook.content)
        self.assertIn("python3 -c", workspace.playbook.content)
        self.assertIn("127.0.0.1", workspace.playbook.content)
        self.assertNotIn("shutdown(socket.SHUT_WR)", workspace.playbook.content)
        self.assertIn("barragan_expected_response in inbound_validation_probe.stdout", workspace.playbook.content)
        self.assertIn('"profileType": "tcp-send-receive"', workspace.manifest.content)
        self.assertIn('"expectedResponse": "PONG"', workspace.manifest.content)
        self.assertIn('"probeOrigin": "selected_edge"', workspace.manifest.content)
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", str(workspace.to_dict()))
        self.assertNotIn("barragan-app", str(workspace.to_dict()))

    def test_renders_http_validation_as_service_neutral_non_5xx_check(self):
        spec = _spec(
            protocol="HTTP",
            mode="http-openresty",
            external_port=80,
            internal_port=9999,
            validation_profile={
                "type": "http",
                "label": "HTTP route check",
                "requestText": "GET / HTTP/1.1\r\nHost: upload.example.invalid\r\nConnection: close\r\n\r\n",
                "expectedResponse": "HTTP status below 500",
            },
        )
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_validation_workspace(spec, artifacts)

        self.assertIn("Verify non-5xx HTTP response", workspace.playbook.content)
        self.assertIn("^HTTP/[0-9]+\\.[0-9]+ [1-4][0-9]{2}(?:[ \\r\\n]|$)", workspace.playbook.content)
        self.assertIn("regex_search('^HTTP/[0-9]+\\.[0-9]+ [1-4][0-9]{2}(?:[ \\r\\n]|$)') is not none", workspace.playbook.content)
        self.assertNotIn("barragan_expected_response in inbound_validation_probe.stdout", workspace.playbook.content)
        self.assertIn('"expectedResponse": "HTTP status below 500"', workspace.manifest.content)

    def test_renders_gosus_tls_site_as_tls_only_front_route(self):
        spec = _spec(
            protocol="HTTPS",
            mode="https-openresty",
            external_port=443,
            terminates_on="proxy01-zy01",
            internal_port=443,
            backend_port=9999,
            domain="files.example.invalid",
            service="Go Simple Upload Server",
            service_id="http-site-0123456789abcdef",
            service_type="web-http-backend",
        )
        artifacts = render_inbound_channel_artifacts(spec)
        route = InboundResolvedRoute(
            homebase=InboundRouteTarget("homebase-zy01", "192.168.0.10", private_ip="192.168.0.10", ssh_user="operator"),
            proxy=InboundRouteTarget("proxy01-zy01", "192.168.2.11", private_ip="192.168.2.11", ssh_user="operator"),
            middle=InboundRouteTarget("middle01-zy01", "198.51.100.20"),
            edge=InboundRouteTarget("edge-zy01-us-sea-01", "198.51.100.30"),
            termination=None,
        )
        workspace = render_inbound_apply_workspace(spec, artifacts, route=route)
        apply_playbook = next(playbook.content for playbook in workspace.playbooks if playbook.target == "ansible/apply_inbound_channel.yml")
        remove_workspace = render_inbound_remove_workspace(spec, artifacts, route=route)
        manifest = json.loads(workspace.manifest.content)

        self.assertEqual(artifacts.proxy_stream.target, "/opt/web/tls/0123456789abcdef.map")
        self.assertIn("files.example.invalid barragan-inbound-c2-primary-", artifacts.proxy_stream.content)
        self.assertIn("/opt/web/tls", apply_playbook)
        self.assertIn("/etc/openresty/tls/*.map", apply_playbook)
        self.assertIn("/opt/web/inbound/0123456789abcdef/conf/default.conf.barragan-unbound", apply_playbook)
        self.assertNotIn("/opt/web/http/0123456789abcdef.map", apply_playbook)
        self.assertIn('host: "192.168.0.10"', apply_playbook)
        self.assertIn("port: 9999", apply_playbook)
        self.assertIn("proxy_pass http://192.168.0.10:9999;", apply_playbook)
        self.assertIn("listen 8081;", apply_playbook)
        self.assertNotIn("listen 8081 proxy_protocol;", apply_playbook)
        self.assertIn("if [ -f /opt/web/.barragan-stack.json ]; then", apply_playbook)
        self.assertIn("[homebase_backend]", workspace.inventory.content)
        self.assertIn("homebase_backend", workspace.inventory.content.split("[inbound_firewall_targets:children]", 1)[1])
        self.assertIn("Preflight inbound management path for homebase_backend", workspace.playbooks[0].content)
        self.assertIn("Open managed HTTP backend Homebase firewall path", apply_playbook)
        self.assertIn("Require restrictive managed HTTP backend Homebase input baseline", apply_playbook)
        self.assertIn('barragan_backend_proxy_ip: "192.168.2.11"', apply_playbook)
        self.assertIn("-p tcp --dport {{ barragan_backend_listen_port }}", apply_playbook)
        self.assertIn("barragan-inbound-{{ barragan_channel_id }}-backend", apply_playbook)
        self.assertIn("Persist managed HTTP backend Homebase iptables rules", apply_playbook)
        self.assertIn("Close managed HTTP backend Homebase firewall path", remove_workspace.playbook.content)
        self.assertIn("Delete selected proxy managed HTTP backend allow with iptables", remove_workspace.playbook.content)
        self.assertIn("Persist managed HTTP backend Homebase iptables removal", remove_workspace.playbook.content)
        self.assertIn("Record sanitized Barragan-managed proxy routes", apply_playbook)
        self.assertIn("/var/lib/barragan/managed-runtime/barragan-routes.json", apply_playbook)
        self.assertIn('"routingOwner": "shared-web-ingress"', apply_playbook)
        self.assertIn('"hostRole": "homebase"', apply_playbook)
        self.assertNotIn("requestGateToken", apply_playbook)
        self.assertIn("Remove selected route from sanitized proxy registry", remove_workspace.playbook.content)
        self.assertIn('routes = [row for row in routes if row["routeId"] != route_id]', remove_workspace.playbook.content)
        backend_check = next(check for check in manifest["ingressAssessment"]["checks"] if check["scope"] == "managedHttpBackendHomebaseFirewall")
        self.assertEqual(backend_check["host"], "homebase-zy01")
        self.assertEqual(backend_check["source"], "192.168.2.11")
        self.assertEqual(backend_check["protocol"], "tcp")
        self.assertEqual(backend_check["port"], 9999)
        public_only_proxy_route = InboundResolvedRoute(
            homebase=route.homebase,
            proxy=InboundRouteTarget("proxy01-zy01", "198.51.100.11", public_ip="198.51.100.11", ssh_user="operator"),
            middle=route.middle,
            edge=route.edge,
            termination=None,
        )
        with self.assertRaises(InboundChannelApplyValidationError) as caught:
            render_inbound_apply_workspace(spec, artifacts, route=public_only_proxy_route)
        self.assertIn("literal private IP", " ".join(caught.exception.errors))
        compact = compact_inbound_channel_from_spec(spec, artifacts)
        self.assertEqual(compact["serviceId"], "http-site-0123456789abcdef")
        self.assertEqual(compact["serviceType"], "web-http-backend")
        self.assertEqual(compact["backendPort"], "9999")

    def test_legacy_gosus_tls_channel_recovers_its_private_backend_port(self):
        _overview, channel = _http_validation_overview()
        channel.update(
            {
                "protocol": "HTTPS",
                "mode": "https-openresty",
                "externalPort": "443",
                "terminatesOn": "proxy01-zy01",
                "internalPort": "443",
                "service": "Go Simple Upload Server",
                "serviceId": "http-site-0123456789abcdef",
                "serviceType": "web-http-backend",
            }
        )
        channel.pop("backendPort", None)

        spec = _spec_from_channel("zy01", channel)

        self.assertEqual(spec.backend_port, 9999)

    def test_legacy_generic_https_channel_normalizes_to_managed_tls_site_on_reapply(self):
        _overview, channel = _http_validation_overview()
        channel.update(
            {
                "channelId": "edge-zy01-us-sea-01-443-to-homebase-18086",
                "domain": "nb.example.invalid",
                "protocol": "HTTPS",
                "mode": "https-openresty",
                "externalPort": "443",
                "terminatesOn": "homebase-zy01",
                "internalPort": "18086",
                "service": "NetBird",
            }
        )
        channel.pop("serviceId", None)
        channel.pop("serviceType", None)
        channel.pop("backendPort", None)

        spec = _spec_from_channel("zy01", channel)
        artifacts = render_inbound_channel_artifacts(spec)
        compact = compact_inbound_channel_from_spec(spec, artifacts)

        self.assertEqual(spec.terminates_on, "proxy01-zy01")
        self.assertEqual(spec.internal_port, 443)
        self.assertEqual(spec.backend_port, 18086)
        self.assertEqual(spec.service_type, "web-http-backend")
        self.assertRegex(spec.service_id, r"^http-site-[a-f0-9]{16}$")
        self.assertEqual(spec.validation_profile.profile_type, "manual")
        self.assertEqual(compact["backendPort"], "18086")
        self.assertEqual(compact["terminatesOn"], "proxy01-zy01")
        self.assertEqual(compact["internalPort"], "443")
        self.assertEqual(artifacts.proxy_stream.target, f"/opt/web/tls/{spec.service_id.removeprefix('http-site-')}.map")

    def test_generic_https_site_persistence_names_the_backend_without_assigning_it_tls(self):
        saved = []
        repository = SimpleNamespace(save=lambda service: saved.append(service) or service)
        channel = {
            "channelId": "edge-zy01-us-sea-01-443-to-proxy01-443-nb-example-invalid",
            "domain": "nb.example.invalid",
            "proxy": "proxy01-zy01",
            "service": "NetBird",
            "serviceId": "http-site-0123456789abcdef",
            "serviceType": "web-http-backend",
        }

        with patch(
            "app.services.inbound_channel_apply.SqlAlchemyEngagementServiceRepository",
            return_value=repository,
        ):
            service = _save_managed_http_backend_site("eng-zy01", channel, "job-apply")

        self.assertIsNotNone(service)
        self.assertEqual(len(saved), 1)
        self.assertEqual(service.name, "NetBird HTTPS site")
        self.assertEqual(service.service_type, "web-http-backend")
        self.assertEqual(service.config["siteConfigPath"], "/opt/web/inbound/0123456789abcdef/conf/default.conf")
        self.assertEqual(service.config["channelId"], channel["channelId"])

    def test_legacy_generic_https_reapply_renders_private_http_backend_without_gosus_authorization(self):
        overview, channel = _http_validation_overview()
        channel.update(
            {
                "channelId": "edge-zy01-us-sea-01-443-to-homebase-18086",
                "domain": "nb.example.invalid",
                "protocol": "HTTPS",
                "mode": "https-openresty",
                "externalPort": "443",
                "terminatesOn": "homebase-zy01",
                "internalPort": "18086",
                "service": "NetBird",
            }
        )
        channel.pop("serviceId", None)
        channel.pop("serviceType", None)
        channel.pop("backendPort", None)
        overview["inboundChannels"] = [channel]

        with (
            patch(
                "app.services.inbound_channel_apply.resolve_selected_inbound_backend_authorization",
                return_value=None,
            ),
            patch(
                "app.services.inbound_request_header_gate.load_active_request_header_gate",
                return_value=None,
            ),
        ):
            spec, _artifacts, workspace, route = _render_apply_workspace_for_channel(
                "ZY01",
                "eng-zy01",
                channel,
                overview,
                include_request_header_gate=True,
                local_sketch_key_file="/tmp/sketch-key",
            )

        playbook = next(
            item.content for item in workspace.playbooks if item.target == "ansible/apply_inbound_channel.yml"
        )
        self.assertIsNone(route.termination)
        self.assertEqual(spec.backend_port, 18086)
        self.assertIn("proxy_pass http://192.168.0.10:18086;", playbook)
        self.assertIn("listen 8081;", playbook)
        self.assertIn("/opt/web/tls/", playbook)
        self.assertNotIn("Load private backend authorization", playbook)
        self.assertNotIn("proxy_set_header Authorization", playbook)

    def test_staged_http_capability_route_renders_private_backend_authorization(self):
        overview, channel = _http_validation_overview()
        overview["inboundChannels"] = []  # Browser initial creation has not persisted the route yet.
        adapter = InboundBackendAuthorization(
            capability_id="go-simple-upload-server",
            host_class="homebase",
            port=9999,
            max_request_body_bytes=500_000_000,
            header_name="Authorization",
            scheme="Bearer",
            config_path="/etc/go-simple-upload-server/config.json",
            array_field="read_write_tokens",
            array_index=0,
        )
        gate = {
            "enabled": True,
            "headerName": "Authorization",
            "token": "public-route-token",
            "maxRequestBodyMb": 500,
        }

        with patch("app.services.inbound_channel_apply.resolve_selected_inbound_backend_authorization", return_value=adapter):
            with patch("app.services.inbound_request_header_gate.load_active_request_header_gate", return_value=gate):
                _spec_value, _artifacts, workspace, _route = _render_apply_workspace_for_channel(
                    "ZY01",
                    "eng-zy01",
                    channel,
                    overview,
                    include_request_header_gate=True,
                )

        apply_playbook = next(playbook.content for playbook in workspace.playbooks if playbook.target == "ansible/apply_inbound_channel.yml")
        self.assertIn("Load private backend authorization for go-simple-upload-server", apply_playbook)
        self.assertIn(
            "proxy_set_header Authorization \"{{ hostvars[groups['termination_host'][0]].barragan_inbound_backend_authorization }}\";",
            apply_playbook,
        )
        self.assertIn('"Bearer public-route-token" 1;', apply_playbook)
        self.assertIn("/etc/go-simple-upload-server/config.json", apply_playbook)
        self.assertIn("no_log: true", apply_playbook)

    def test_staged_gosus_route_enforces_the_resolved_client_value_without_a_second_gate(self):
        overview, channel = _http_validation_overview()
        overview["inboundChannels"] = []
        adapter = InboundBackendAuthorization(
            capability_id="go-simple-upload-server",
            host_class="homebase",
            port=9999,
            max_request_body_bytes=500_000_000,
            header_name="Authorization",
            scheme="Bearer",
            config_path="/etc/go-simple-upload-server/config.json",
            array_field="read_write_tokens",
            array_index=0,
        )
        with patch("app.services.inbound_channel_apply.resolve_selected_inbound_backend_authorization", return_value=adapter), patch(
            "app.services.inbound_request_header_gate.load_active_request_header_gate", return_value=None
        ), patch(
            "app.services.inbound_request_header_gate.request_header_gate_policy_path",
            return_value=Path("/opt/engagements/ZY01/barragan/inbound-channels/upload-http/request-header-gate.json"),
        ):
            _spec_value, _artifacts, workspace, _route = _render_apply_workspace_for_channel(
                "ZY01", "eng-zy01", channel, overview, include_request_header_gate=True
            )
        playbook = next(item.content for item in workspace.playbooks if item.target == "ansible/apply_inbound_channel.yml")
        self.assertIn('map $http_authorization $barragan_request_header_gate', playbook)
        self.assertIn('"{{ hostvars[groups[\'termination_host\'][0]].barragan_inbound_backend_authorization }}" 1;', playbook)
        self.assertIn('if ($barragan_request_header_gate = 0)', playbook)
        self.assertIn("Retain GoSUS request gate for operator use", playbook)
        self.assertIn("Require retained GoSUS request gate", playbook)
        self.assertIn('"engagementId": "eng-zy01"', playbook)
        self.assertIn('"token": "{{ hostvars[groups[\'termination_host\'][0]].barragan_inbound_backend_authorization | regex_replace(\'^Bearer \', \'\') }}"', playbook)
        self.assertIn("no_log: true", playbook)

    def test_retained_gosus_https_gate_stays_in_route_transaction_without_site_record(self):
        overview, channel = _http_validation_overview()
        channel.update(
            {
                "mode": "https-openresty",
                "protocol": "HTTPS",
                "externalPort": "8080",
                "terminatesOn": "homebase-zy01",
                "service": "Go Simple Upload Server",
                "serviceId": "http-site-0123456789abcdef",
                "serviceType": "web-http-backend",
                "internalPort": "9999",
            }
        )
        adapter = InboundBackendAuthorization(
            capability_id="go-simple-upload-server",
            host_class="homebase",
            port=9999,
            max_request_body_bytes=500_000_000,
            header_name="Authorization",
            scheme="Bearer",
            config_path="/etc/go-simple-upload-server/config.json",
            array_field="read_write_tokens",
            array_index=0,
        )
        retained_gate = {
            "enabled": True,
            "headerName": "Authorization",
            "token": "retained-value",
            "maxRequestBodyMb": 500,
        }
        with patch("app.services.inbound_channel_apply.resolve_selected_inbound_backend_authorization", return_value=adapter), patch(
            "app.services.inbound_request_header_gate.load_active_request_header_gate", return_value=retained_gate
        ), patch(
            "app.services.inbound_request_header_gate.render_retained_https_request_header_gate_playbook",
            side_effect=AssertionError("typed GoSUS must not invoke a second HTTPS gate workflow"),
        ):
            _spec_value, _artifacts, workspace, _route = _render_apply_workspace_for_channel(
                "ZY01", "eng-zy01", channel, overview, include_request_header_gate=True
            )

        targets = [playbook.target for playbook in workspace.playbooks]
        apply_playbook = next(playbook.content for playbook in workspace.playbooks if playbook.target == "ansible/apply_inbound_channel.yml")
        self.assertNotIn("ansible/apply_request_header_gate.yml", targets)
        self.assertIn('"Bearer retained-value" 1;', apply_playbook)

    def test_http_validation_accepts_405_and_persists_service_neutral_evidence(self):
        overview, channel = _http_validation_overview()
        saved_jobs = []

        class FakeRepo:
            def list(self):
                return saved_jobs

            def save(self, job):
                saved_jobs.append(job)
                return job

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.inbound_channel_apply.get_engagement", return_value=SimpleNamespace(name="ZY01")):
                with patch("app.services.inbound_channel_apply.get_operations_overview", return_value=overview):
                    with patch("app.services.inbound_channel_apply.resolve_ansible_playbook", return_value=SimpleNamespace(ok=True, command="ansible-playbook", error="")):
                        with patch(
                            "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
                            return_value=(str(Path(temp_dir) / "keys" / "admin"), str(Path(temp_dir) / "keys" / "admin.pub")),
                        ):
                            with patch("app.services.inbound_channel_apply.try_enqueue_infra_orientation_refresh"):
                                result = validate_inbound_channel(
                                    "eng-zy01",
                                    channel["channelId"],
                                    confirmation=f"validate-inbound-{channel['channelId']}",
                                    repository=FakeRepo(),
                                    workspace_root=Path(temp_dir),
                                    runner=lambda command, cwd: subprocess.CompletedProcess(
                                        command,
                                        0,
                                        stdout="HTTP/1.1 405 Method Not Allowed\r\nAllow: POST, PUT\r\n",
                                        stderr="",
                                    ),
                                )

        self.assertEqual(result["status"], "Validated")
        self.assertEqual(saved_jobs[-1].status, "succeeded")
        evidence = saved_jobs[-1].events[-1].data["validationEvidence"]
        self.assertEqual(evidence["expectedResponse"], "HTTP status below 500")
        self.assertEqual(evidence["observedResponse"], "Observed a non-5xx HTTP response.")
        self.assertIn("Observed a non-5xx HTTP response", evidence["detail"])
        persisted = saved_jobs[-1].events[-1].data["inboundChannels"][0]
        self.assertEqual(persisted["status"], "Validated")
        self.assertEqual(persisted["validation"]["status"], "Validated")

    def test_http_validation_rejects_502_assertion_failure_and_persists_failure(self):
        overview, channel = _http_validation_overview()
        saved_jobs = []

        class FakeRepo:
            def list(self):
                return saved_jobs

            def save(self, job):
                saved_jobs.append(job)
                return job

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.inbound_channel_apply.get_engagement", return_value=SimpleNamespace(name="ZY01")):
                with patch("app.services.inbound_channel_apply.get_operations_overview", return_value=overview):
                    with patch("app.services.inbound_channel_apply.resolve_ansible_playbook", return_value=SimpleNamespace(ok=True, command="ansible-playbook", error="")):
                        with patch(
                            "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
                            return_value=(str(Path(temp_dir) / "keys" / "admin"), str(Path(temp_dir) / "keys" / "admin.pub")),
                        ):
                            result = validate_inbound_channel(
                                "eng-zy01",
                                channel["channelId"],
                                confirmation=f"validate-inbound-{channel['channelId']}",
                                repository=FakeRepo(),
                                workspace_root=Path(temp_dir),
                                runner=lambda command, cwd: subprocess.CompletedProcess(
                                    command,
                                    2,
                                    stdout="HTTP/1.1 502 Bad Gateway\r\n",
                                    stderr="non-5xx assertion failed",
                                ),
                            )

        self.assertEqual(result["status"], "Validation Failed")
        self.assertEqual(saved_jobs[-1].status, "failed")
        evidence = saved_jobs[-1].events[-1].data["validationEvidence"]
        self.assertEqual(evidence["expectedResponse"], "HTTP status below 500")
        self.assertEqual(evidence["observedResponse"], "A non-5xx HTTP response was not observed.")
        self.assertIn("was not observed", evidence["detail"])
        persisted = saved_jobs[-1].events[-1].data["inboundChannels"][0]
        self.assertEqual(persisted["status"], "Validation Failed")
        self.assertEqual(persisted["validation"]["status"], "Validation Failed")

    def test_renders_udp_send_receive_validation_without_temporary_listener(self):
        spec = _spec(
            validation_profile={
                "type": "udp-send-receive",
                "label": "UDP request response",
                "requestText": "PING",
                "expectedResponse": "FF0000",
            }
        )
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_validation_workspace(spec, artifacts)

        self.assertEqual(artifacts.validation.profile_type, "udp-send-receive")
        self.assertNotIn("Start temporary inbound validation listener", workspace.playbook.content)
        self.assertNotIn("Wait for temporary listener port", workspace.playbook.content)
        self.assertIn("python3 -c", workspace.playbook.content)
        self.assertIn("hosts: selected_edge", workspace.playbook.content)
        self.assertNotIn("hosts: localhost", workspace.playbook.content)
        self.assertNotIn("connection: local", workspace.playbook.content)
        self.assertIn("Send UDP validation probe from selected edge through inbound route", workspace.playbook.content)
        self.assertIn("127.0.0.1", workspace.playbook.content)
        self.assertNotIn("nc -N -w 5 edge-zy01-us-sea-01 443", workspace.playbook.content)
        self.assertIn('"profileType": "udp-send-receive"', workspace.manifest.content)
        self.assertIn('"expectedResponse": "FF0000"', workspace.manifest.content)
        self.assertIn('"probeOrigin": "selected_edge"', workspace.manifest.content)

    def test_renders_validation_workspace_for_proxy_termination_without_extra_group(self):
        spec = _spec(terminates_on="proxy01-zy01", service="SSH Backflips", internal_port=8001)
        artifacts = render_inbound_channel_artifacts(spec)
        workspace = render_inbound_validation_workspace(spec, artifacts)

        self.assertNotIn("[termination_host]", workspace.inventory.content)
        self.assertIn("hosts: selected_proxy", workspace.playbook.content)
        self.assertIn("python3 -c", workspace.playbook.content)
        self.assertIn("port: 8001", workspace.playbook.content)


def _spec(**overrides):
    values = {
        "engagement": "zy01",
        "channel_id": "c2-primary",
        "domain": "c2.example.invalid",
        "protocol": "TCP",
        "mode": "tcp-forward",
        "external_port": 443,
        "edge_hostname": "edge-zy01-us-sea-01",
        "middle_hostname": "middle01-zy01",
        "proxy_hostname": "proxy01-zy01",
        "terminates_on": "homebase-zy01",
        "service": "Mythic",
        "internal_port": 7443,
        "purpose": "C2 ingress",
    }
    values.update(overrides)
    return InboundChannelArtifactSpec(**values)


def _http_validation_overview():
    channel = {
        "channelId": "edge-zy01-us-sea-01-80-to-homebase-9999-upload-example-invalid",
        "domain": "upload.example.invalid",
        "protocol": "HTTP",
        "mode": "http-openresty",
        "externalPort": "80",
        "edge": "edge-zy01-us-sea-01",
        "middle": "middle01-zy01",
        "proxy": "proxy01-zy01",
        "terminatesOn": "homebase-zy01",
        "service": "File service",
        "internalPort": "9999",
        "purpose": "upload ingress",
        "status": "Pending Validation",
        "validationProfile": {
            "type": "http",
            "label": "HTTP route check",
            "requestText": "GET / HTTP/1.1\r\nHost: upload.example.invalid\r\nConnection: close\r\n\r\n",
            "expectedResponse": "HTTP status below 500",
        },
    }
    return {
        "coreInfrastructure": [
            {"hostname": "homebase-zy01", "role": "homebase", "publicIp": "198.51.100.10", "privateIp": "192.168.0.10", "sshUser": "user"},
            {"hostname": "proxy01-zy01", "role": "proxy", "publicIp": "198.51.100.11", "privateIp": "192.168.2.11", "sshUser": "user"},
        ],
        "sketchInfrastructure": [
            {"chainId": "proxy01-chain-001", "hostname": "middle01-zy01", "role": "middle", "publicIp": "203.0.113.20", "proxy": "proxy01"},
            {"chainId": "proxy01-chain-001", "hostname": "edge-zy01-us-sea-01", "role": "edge", "publicIp": "203.0.113.30", "proxy": "proxy01"},
        ],
        "inboundChannels": [channel],
    }, channel


if __name__ == "__main__":
    unittest.main()
