# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.services.inbound_channel_artifacts import (
    compact_inbound_channel_from_spec,
    InboundChannelArtifactSpec,
    InboundChannelArtifactValidationError,
    http_backend_service_name,
    render_inbound_channel_artifacts,
)


class InboundChannelArtifactTests(unittest.TestCase):
    def test_raw_route_renders_distinct_middle_and_proxy_relay_ports(self):
        spec = _spec(middle_relay_port=8002, proxy_relay_port=8007, relay_port=8007)
        artifacts = render_inbound_channel_artifacts(spec)

        self.assertIn("listen 8002", artifacts.middle_stream.content)
        self.assertIn("proxy_pass proxy01-zy01:8007", artifacts.middle_stream.content)
        self.assertIn("listen 8007", artifacts.proxy_stream.content)
        compact = compact_inbound_channel_from_spec(spec, artifacts)
        self.assertEqual(compact["middleRelayPort"], "8002")
        self.assertEqual(compact["proxyRelayPort"], "8007")

    def test_renders_tcp_forward_artifacts_and_safe_validation_plan(self):
        artifacts = render_inbound_channel_artifacts(_spec())
        body = artifacts.to_dict()

        self.assertEqual(body["validation"]["profileLabel"], "Temporary TCP listener")
        self.assertIn("/etc/nginx/streams/barragan-c2-primary-edge-443.conf", body["edgeStream"]["target"])
        self.assertIn("proxy_pass middle01-zy01:443;", body["edgeStream"]["content"])
        self.assertNotIn("proxy_protocol on;", body["edgeStream"]["content"])
        self.assertIn("proxy_pass proxy01-zy01:443;", body["middleStream"]["content"])
        self.assertNotIn("proxy_protocol on;", body["middleStream"]["content"])
        self.assertIn("proxy_pass homebase-zy01:7443;", body["proxyStream"]["content"])
        self.assertEqual(body["validation"]["listenerOrigin"], "homebase-zy01")
        self.assertEqual(body["validation"]["probeOrigin"], "selected_edge")
        self.assertEqual(body["validation"]["validationScope"], "edge-local ingress route")
        self.assertFalse(body["validation"]["externalIngressVerified"])
        self.assertIn("nc -l 0.0.0.0 7443", body["validation"]["listenerShellDisplay"])
        self.assertIn("nc -w 5 127.0.0.1 443", body["validation"]["probeShellDisplay"])
        self.assertEqual(body["validation"]["expectedMarker"], "barragan-inbound-c2-primary")
        self.assertIn("per-channel TCP forward", body["sketchNodeBoundary"]["reason"])
        self.assertEqual(body["sketchNodeBoundary"]["edgeNodeArtifacts"][0]["target"], body["edgeStream"]["target"])
        self.assertEqual(body["sketchNodeBoundary"]["middleNodeArtifacts"][0]["target"], body["middleStream"]["target"])

    def test_proxy_termination_routes_to_loopback_on_selected_proxy(self):
        artifacts = render_inbound_channel_artifacts(
            _spec(terminates_on="proxy01-zy01", service="SSH Backflips", internal_port=8001)
        )

        self.assertIn("proxy_pass 127.0.0.1:8001;", artifacts.proxy_stream.content)

    def test_https_openresty_mode_emits_single_proxy_protocol_header_at_edge_only(self):
        artifacts = render_inbound_channel_artifacts(_spec(protocol="HTTPS", mode="https-openresty"))
        body = artifacts.to_dict()

        self.assertIn("proxy_protocol on;", artifacts.edge_stream.content)
        self.assertNotIn("proxy_protocol on;", artifacts.middle_stream.content)
        self.assertNotIn("proxy_protocol on;", artifacts.proxy_stream.content)
        self.assertEqual(body["routeFamily"], "shared-web-ingress")
        self.assertTrue(body["sharedWebIngress"])
        self.assertEqual(body["edgeStream"]["target"], "/etc/nginx/streams/barragan-web-edge-to-middle01-zy01-443.conf")
        self.assertEqual(body["middleStream"]["target"], "/etc/nginx/streams/barragan-web-middle-to-proxy01-zy01-443.conf")
        self.assertEqual(body["proxyStream"]["target"], "/opt/web/streams/barragan-web-front-443.conf")
        self.assertIn("proxy front OpenResty", body["proxyStream"]["content"])
        self.assertIn("reusable shared web pass-through", body["sketchNodeBoundary"]["reason"])

    def test_two_https_edges_on_one_middle_share_baseline_web_targets_without_channel_collision(self):
        first = render_inbound_channel_artifacts(
            _spec(
                channel_id="edge-one-443-to-proxy-front",
                protocol="HTTPS",
                mode="https-openresty",
                edge_hostname="edge-zy01-us-sea-01",
            )
        ).to_dict()
        second = render_inbound_channel_artifacts(
            _spec(
                channel_id="edge-two-443-to-proxy-front",
                protocol="HTTPS",
                mode="https-openresty",
                edge_hostname="edge-zy01-us-sea-02",
            )
        ).to_dict()

        self.assertEqual(first["edgeStream"]["target"], "/etc/nginx/streams/barragan-web-edge-to-middle01-zy01-443.conf")
        self.assertEqual(second["edgeStream"]["target"], "/etc/nginx/streams/barragan-web-edge-to-middle01-zy01-443.conf")
        self.assertEqual(first["middleStream"]["target"], "/etc/nginx/streams/barragan-web-middle-to-proxy01-zy01-443.conf")
        self.assertEqual(second["middleStream"]["target"], "/etc/nginx/streams/barragan-web-middle-to-proxy01-zy01-443.conf")
        self.assertNotIn("edge-one-443-to-proxy-front-middle", first["middleStream"]["target"])
        self.assertNotIn("edge-two-443-to-proxy-front-middle", second["middleStream"]["target"])

    def test_http_openresty_keeps_backend_details_on_proxy_route(self):
        artifacts = render_inbound_channel_artifacts(
            _spec(protocol="HTTP", mode="http-openresty", external_port=80, internal_port=9999)
        )

        self.assertEqual(artifacts.route_family, "shared-web-ingress")
        self.assertIn("proxy_protocol on;", artifacts.edge_stream.content)
        self.assertEqual(artifacts.proxy_stream.target, "/opt/web/http/barragan-inbound-c2-primary.map")
        self.assertIn(
            f"c2.example.invalid {http_backend_service_name('c2-primary')}:8081;",
            artifacts.proxy_stream.content,
        )
        self.assertEqual(artifacts.validation.profile_type, "http")
        self.assertEqual(artifacts.validation.expected_response, "HTTP status below 500")
        for artifact in (artifacts.edge_stream, artifacts.middle_stream):
            self.assertNotIn("c2.example.invalid", artifact.content)
            self.assertNotIn("homebase-zy01", artifact.content)
            self.assertNotIn("9999", artifact.content)

    def test_http_backend_service_name_is_deterministic_and_dns_safe(self):
        channel_id = "edge-long_name.with.mixed-punctuation-" * 4
        service_name = http_backend_service_name(channel_id)

        self.assertEqual(service_name, http_backend_service_name(channel_id))
        self.assertLessEqual(len(service_name), 63)
        self.assertRegex(service_name, r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

    def test_http_openresty_requires_port_80(self):
        with self.assertRaises(InboundChannelArtifactValidationError) as exc:
            render_inbound_channel_artifacts(_spec(protocol="HTTP", mode="http-openresty"))

        self.assertIn("http-openresty mode requires externalPort 80", exc.exception.errors)

    def test_udp_forward_uses_udp_streams_and_relay_port_without_proxy_protocol(self):
        artifacts = render_inbound_channel_artifacts(
            _spec(
                protocol="UDP",
                mode="udp-forward",
                external_port=53,
                relay_port=5454,
                internal_port=18080,
                validation_profile={
                    "type": "udp-send-receive",
                    "label": "UDP request response",
                    "requestText": "PING",
                    "expectedResponse": "FF0000",
                },
            )
        )
        body = artifacts.to_dict()

        self.assertIn("/etc/nginx/streams/barragan-c2-primary-edge-53.conf", body["edgeStream"]["target"])
        self.assertIn("/etc/nginx/streams/barragan-c2-primary-middle-5454.conf", body["middleStream"]["target"])
        self.assertIn("/etc/nginx/streams/barragan-c2-primary-proxy-5454.conf", body["proxyStream"]["target"])
        self.assertIn("listen 53 udp reuseport;", body["edgeStream"]["content"])
        self.assertIn("proxy_pass middle01-zy01:5454;", body["edgeStream"]["content"])
        self.assertIn("listen 5454 udp reuseport;", body["middleStream"]["content"])
        self.assertIn("proxy_pass proxy01-zy01:5454;", body["middleStream"]["content"])
        self.assertIn("listen 5454 udp reuseport;", body["proxyStream"]["content"])
        self.assertIn("proxy_pass homebase-zy01:18080;", body["proxyStream"]["content"])
        self.assertEqual(
            (
                body["edgeStream"]["content"]
                + body["middleStream"]["content"]
                + body["proxyStream"]["content"]
            ).count("proxy_timeout 1s;"),
            3,
        )
        self.assertNotIn("proxy_protocol on;", str(body))
        self.assertIn("per-channel UDP forward", body["sketchNodeBoundary"]["reason"])
        self.assertEqual(body["validation"]["profileType"], "udp-send-receive")
        self.assertIn("nc -u -w 5 127.0.0.1 53", body["validation"]["probeShellDisplay"])

    def test_udp_forward_requires_udp_send_receive_validation_profile(self):
        with self.assertRaises(ValueError) as exc:
            render_inbound_channel_artifacts(_spec(protocol="UDP", mode="udp-forward", external_port=53))

        self.assertEqual(str(exc.exception), "udp-forward requires validationProfile.type udp-send-receive or manual")

    def test_rejects_unsupported_modes_until_product_behavior_is_defined(self):
        with self.assertRaises(InboundChannelArtifactValidationError) as exc:
            render_inbound_channel_artifacts(_spec(mode="udp-dns"))

        self.assertEqual(exc.exception.errors, ["mode must be tcp-forward, http-openresty, https-openresty, or udp-forward"])

    def test_rejects_placeholder_or_invalid_route_values(self):
        with self.assertRaises(InboundChannelArtifactValidationError) as exc:
            render_inbound_channel_artifacts(_spec(edge_hostname="Not Deployed", external_port=70000))

        self.assertIn("edge must be a hostname-like value", exc.exception.errors)
        self.assertIn("externalPort must be between 1 and 65535", exc.exception.errors)

    def test_artifacts_do_not_include_provider_tokens_or_private_keys(self):
        artifacts = render_inbound_channel_artifacts(_spec())
        body = str(artifacts.to_dict())

        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", body)
        self.assertNotIn("LINODE_TOKEN", body)
        self.assertNotIn("DIGITALOCEAN_TOKEN", body)
        self.assertNotIn("provider_token", body)

    def test_rejects_layer_7_validation_profile_types(self):
        with self.assertRaises(ValueError) as exc:
            render_inbound_channel_artifacts(
                _spec(
                    validation_profile={
                        "type": "http-body-match",
                        "label": "HTTP body match",
                        "expectedResponse": "hola",
                    }
                )
            )

        self.assertEqual(str(exc.exception), "validationProfile.type must be temporary-listener, tcp-send-receive, udp-send-receive, tcp-connect, http, or manual")


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


if __name__ == "__main__":
    unittest.main()
