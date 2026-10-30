# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.services.catalog import get_template, list_templates, validate_template_input


class StandardRtiCatalogTests(unittest.TestCase):
    def test_standard_rti_detail_contains_required_template_shape(self):
        template = get_template("standard-rti")

        self.assertIsNotNone(template)
        body = template.to_dict()
        self.assertEqual(body["providerConstraints"]["coreProvider"], "oci")
        self.assertEqual(body["routeDefaults"]["minimumIngressRoutes"], 1)
        self.assertTrue(body["routeDefaults"]["egressProfileListenerPortRequired"])
        self.assertEqual(body["reverseChannelDefaults"]["minimumReverseChannels"], 0)

    def test_template_list_includes_dev_infra(self):
        self.assertIn("dev-infra", [template.id for template in list_templates()])

    def test_small_dev_infra_is_a_distinct_one_proxy_no_elk_template(self):
        template = get_template("small-dev-infra")

        self.assertIsNotNone(template)
        body = template.to_dict()
        self.assertEqual(body["name"], "Small Dev Infra")
        self.assertEqual([group["count"] for group in body["nodeGroups"] if group["role"] == "proxy"], [1])
        self.assertNotIn("elkEnabled", [parameter["name"] for parameter in body["parameters"]])
        self.assertNotIn("elk", [group["role"] for group in body["nodeGroups"]])

        accepted = validate_template_input("small-dev-infra", {"engagementName": "small-dev"})
        rejected = validate_template_input(
            "small-dev-infra", {"engagementName": "small-dev", "proxyCount": 1, "elkEnabled": True}
        )

        self.assertTrue(accepted.valid)
        self.assertEqual(accepted.normalized["proxyCount"], 1)
        self.assertFalse(rejected.valid)
        self.assertTrue(any("does not support an ELK node" in error for error in rejected.errors))

    def test_dev_infra_detail_contains_one_proxy_shape(self):
        template = get_template("dev-infra")

        self.assertIsNotNone(template)
        body = template.to_dict()
        self.assertEqual(body["name"], "Dev Infra")
        self.assertEqual(body["routeDefaults"]["egressProfilePublicationRoots"], ["/opt/proxy01"])
        self.assertEqual(body["routeDefaults"]["minimumIngressRoutes"], 0)
        self.assertEqual([group["count"] for group in body["nodeGroups"] if group["role"] == "proxy"], [1])

    def test_dev_infra_validation_accepts_minimum_one_proxy_baseline(self):
        result = validate_template_input("dev-infra", {"engagementName": "sk02-dev"})

        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.normalized["proxyCount"], 1)
        self.assertEqual(result.normalized["sketchChains"], [])

    def test_dev_infra_validation_rejects_proxy02_chain(self):
        payload = {
            "engagementName": "sk02-dev",
            "proxyCount": 1,
            "sketchChains": [
                {
                    "id": "proxy02-sea-01",
                    "assignedProxy": "proxy02",
                    "middleProvider": "linode",
                    "edgeProvider": "linode",
                }
            ],
        }

        result = validate_template_input("dev-infra", payload)

        self.assertFalse(result.valid)
        self.assertTrue(any("assignedProxy" in error and "proxy01" in error for error in result.errors))

    def test_standard_rti_validation_accepts_minimum_supported_baseline(self):
        result = validate_template_input("standard-rti", valid_standard_rti_payload())

        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.normalized["sketchChains"][0]["middleRegion"], "us-sea")
        self.assertEqual(result.normalized["sketchChains"][0]["edgeRegion"], "sfo3")
        self.assertEqual(result.normalized["sketchChains"][0]["middleSize"], "g6-nanode-1")
        self.assertEqual(result.normalized["sketchChains"][0]["edgeSize"], "s-1vcpu-1gb")
        self.assertEqual(result.normalized["sketchChains"][0]["edgeCount"], 1)

    def test_standard_rti_validation_accepts_multiple_edges_per_middle(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"][0]["edgeCount"] = 2

        result = validate_template_input("standard-rti", payload)

        self.assertTrue(result.valid)
        self.assertEqual(result.normalized["sketchChains"][0]["edgeCount"], 2)

    def test_standard_rti_validation_rejects_oci_as_sketch_provider(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"][0]["middleProvider"] = "oci"

        result = validate_template_input("standard-rti", payload)

        self.assertFalse(result.valid)
        self.assertIn("sketchChains[0].middleProvider", result.errors[0])

    def test_standard_rti_validation_rejects_missing_route_chain_reference(self):
        payload = valid_standard_rti_payload()
        payload["ingressRoutes"][0]["sketchChainId"] = "missing-chain"

        result = validate_template_input("standard-rti", payload)

        self.assertFalse(result.valid)
        self.assertIn("ingressRoutes[0].sketchChainId", result.errors[0])

    def test_standard_rti_validation_requires_explicit_egress_listener_port(self):
        payload = valid_standard_rti_payload()
        payload["egressProfiles"][0].pop("listenerPort")

        result = validate_template_input("standard-rti", payload)

        self.assertFalse(result.valid)
        self.assertIn("egressProfiles[0].listenerPort", result.errors[0])

    def test_standard_rti_validation_rejects_duplicate_proxy_listener_port(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"].append(
            {
                "id": "chain-2",
                "assignedProxy": "proxy01",
                "middleProvider": "digitalocean",
                "edgeProvider": "linode",
                "middleCredentialAlias": "do-sketch-dev",
                "edgeCredentialAlias": "linode-sketch-dev",
            }
        )
        payload["egressProfiles"].append(
            {
                "name": "other-sketch-egress",
                "sketchChainId": "chain-2",
                "listenerPort": 3333,
            }
        )

        result = validate_template_input("standard-rti", payload)

        self.assertFalse(result.valid)
        self.assertIn("egressProfiles[1].listenerPort", result.errors[0])

    def test_standard_rti_validation_rejects_invalid_credential_alias(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"][0]["middleCredentialAlias"] = "Linode Token!"

        result = validate_template_input("standard-rti", payload)

        self.assertFalse(result.valid)
        self.assertIn("sketchChains[0].middleCredentialAlias", result.errors[0])

    def test_standard_rti_validation_rejects_invalid_sketch_region_and_size(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"][0]["middleRegion"] = "../bad"
        payload["sketchChains"][0]["edgeSize"] = "bad size"

        result = validate_template_input("standard-rti", payload)

        self.assertFalse(result.valid)
        self.assertTrue(any("sketchChains[0].middleRegion" in error for error in result.errors))
        self.assertTrue(any("sketchChains[0].edgeSize" in error for error in result.errors))


def valid_standard_rti_payload():
    return {
        "engagementName": "of02-dev",
        "proxyCount": 2,
        "elkEnabled": False,
        "sketchChains": [
            {
                "id": "chain-1",
                "assignedProxy": "proxy01",
                "middleProvider": "linode",
                "edgeProvider": "digitalocean",
                "middleCredentialAlias": "linode-sketch-dev",
                "edgeCredentialAlias": "do-sketch-dev",
                "middleRegion": "us-sea",
                "edgeRegion": "sfo3",
                "middleSize": "g6-nanode-1",
                "edgeSize": "s-1vcpu-1gb",
            }
        ],
        "egressProfiles": [
            {
                "name": "default-sketch-egress",
                "sketchChainId": "chain-1",
                "listenerPort": 3333,
            }
        ],
        "ingressRoutes": [
            {
                "name": "default-ingress",
                "sketchChainId": "chain-1",
                "domain": "example.invalid",
            }
        ],
        "reverseChannels": [],
    }


if __name__ == "__main__":
    unittest.main()
