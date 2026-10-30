# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app import create_app
from app.core.config import TestConfig
from app.integrations.provider_plans import (
    build_provider_plan_bundle,
    render_ansible_intent,
    render_terraform_intent,
)
from app.services.credentials import test_master_key as credential_test_master_key
from app.services.revision_compiler import compile_standard_rti_revision
from tests.test_catalog_service import valid_standard_rti_payload


class ProviderPlanTests(unittest.TestCase):
    def test_builds_dry_run_provider_plan_for_minimum_standard_rti(self):
        revision = compile_standard_rti_revision("eng-provider-test", valid_standard_rti_payload())
        bundle = build_provider_plan_bundle(revision)

        self.assertEqual(bundle.mode, "dry_run")
        self.assertEqual({resource.provider for resource in bundle.core}, {"oci"})
        self.assertEqual({resource.role for resource in bundle.core}, {"homebase", "proxy"})
        self.assertEqual({resource.provider for resource in bundle.sketch}, {"linode", "digitalocean"})
        self.assertEqual(bundle.warnings, [])
        middle = next(resource for resource in bundle.sketch if resource.role == "middle")
        edge = next(resource for resource in bundle.sketch if resource.role == "edge")
        self.assertEqual(middle.attributes["credentialRef"], "credential://linode/linode-sketch-dev")
        self.assertEqual(edge.attributes["credentialRef"], "credential://digitalocean/do-sketch-dev")
        self.assertEqual(middle.attributes["region"], "us-sea")
        self.assertEqual(edge.attributes["region"], "sfo3")
        self.assertEqual(middle.attributes["size"], "g6-nanode-1")
        self.assertEqual(edge.attributes["size"], "s-1vcpu-1gb")

    def test_renders_terraform_and_ansible_intent_without_mutation(self):
        revision = compile_standard_rti_revision("eng-provider-test", valid_standard_rti_payload())
        bundle = build_provider_plan_bundle(revision)

        terraform_intent = render_terraform_intent(bundle)
        ansible_intent = render_ansible_intent(revision, bundle)

        self.assertFalse(terraform_intent["mutation"])
        self.assertFalse(ansible_intent["mutation"])
        self.assertEqual(len(terraform_intent["providers"]["oci"]), 2)
        linode_variables = terraform_intent["providers"]["linode"][0]["attributes"]["terraformVariables"]
        digitalocean_variables = terraform_intent["providers"]["digitalocean"][0]["attributes"]["terraformVariables"]
        self.assertEqual(linode_variables["linode_api_token"]["envVar"], "TF_VAR_linode_api_token")
        self.assertEqual(linode_variables["middle_region"], "us-sea")
        self.assertEqual(linode_variables["middle_type"], "g6-nanode-1")
        self.assertEqual(digitalocean_variables["do_pat"]["credentialRef"], "credential://digitalocean/do-sketch-dev")
        self.assertEqual(digitalocean_variables["edge_regions"], ["sfo3"])
        self.assertEqual(digitalocean_variables["edge_size"], "s-1vcpu-1gb")
        self.assertNotIn("secret", str(terraform_intent).lower())
        self.assertNotIn("token-sensitive-value", str(terraform_intent))
        self.assertIn("homebase", ansible_intent["runbook"][2]["managementPaths"][0])
        self.assertEqual(ansible_intent["runbook"][3]["profiles"][0]["publicationPath"], "/opt/proxy01/default-sketch-egress-socks5.conf")

    def test_provider_plan_uses_operator_selected_region_and_size(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"][0]["middleRegion"] = "us-ord"
        payload["sketchChains"][0]["middleSize"] = "g6-standard-1"
        payload["sketchChains"][0]["edgeRegion"] = "nyc3"
        payload["sketchChains"][0]["edgeSize"] = "s-2vcpu-2gb"

        revision = compile_standard_rti_revision("eng-provider-test", payload)
        bundle = build_provider_plan_bundle(revision)
        terraform_intent = render_terraform_intent(bundle)

        linode = terraform_intent["providers"]["linode"][0]["attributes"]
        digitalocean = terraform_intent["providers"]["digitalocean"][0]["attributes"]
        self.assertEqual(linode["region"], "us-ord")
        self.assertEqual(linode["size"], "g6-standard-1")
        self.assertEqual(linode["terraformVariables"]["middle_region"], "us-ord")
        self.assertEqual(linode["terraformVariables"]["middle_type"], "g6-standard-1")
        self.assertEqual(digitalocean["region"], "nyc3")
        self.assertEqual(digitalocean["size"], "s-2vcpu-2gb")
        self.assertEqual(digitalocean["terraformVariables"]["edge_regions"], ["nyc3"])
        self.assertEqual(digitalocean["terraformVariables"]["edge_size"], "s-2vcpu-2gb")

    def test_missing_sketch_credential_aliases_warn_without_mutation(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"][0].pop("middleCredentialAlias")
        payload["sketchChains"][0].pop("edgeCredentialAlias")

        revision = compile_standard_rti_revision("eng-provider-test", payload)
        bundle = build_provider_plan_bundle(revision)
        terraform_intent = render_terraform_intent(bundle)

        self.assertEqual(len(bundle.warnings), 2)
        self.assertFalse(terraform_intent["mutation"])
        self.assertIsNone(terraform_intent["providers"]["linode"][0]["attributes"]["credentialRef"])

    def test_provider_plan_resolves_missing_aliases_from_global_defaults(self):
        app = create_app(TestConfig)
        with app.storage_context():
            client = app.test_client()
            with unittest.mock.patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key()}):
                linode = client.post(
                    "/api/credentials",
                    json={"provider": "linode", "alias": "linode-global-default", "secret": "linode-token", "isDefault": True},
                ).get_json()["credential"]
                digitalocean = client.post(
                    "/api/credentials",
                    json={"provider": "digitalocean", "alias": "do-global-default", "secret": "do-token", "isDefault": True},
                ).get_json()["credential"]

            self.assertTrue(linode["isDefault"])
            self.assertTrue(digitalocean["isDefault"])
            payload = valid_standard_rti_payload()
            payload["sketchChains"][0].pop("middleCredentialAlias")
            payload["sketchChains"][0].pop("edgeCredentialAlias")

            revision = compile_standard_rti_revision("eng-provider-test", payload)
            bundle = build_provider_plan_bundle(revision)
            terraform_intent = render_terraform_intent(bundle)

        self.assertEqual(bundle.warnings, [])
        linode_attrs = terraform_intent["providers"]["linode"][0]["attributes"]
        do_attrs = terraform_intent["providers"]["digitalocean"][0]["attributes"]
        self.assertEqual(linode_attrs["credentialRef"], "credential://linode/linode-global-default")
        self.assertEqual(do_attrs["credentialRef"], "credential://digitalocean/do-global-default")
        self.assertEqual(linode_attrs["credentialSource"], "provider_default")
        self.assertEqual(do_attrs["terraformVariables"]["do_pat"]["credentialSource"], "provider_default")
        self.assertNotIn("linode-token", str(terraform_intent))
        self.assertNotIn("do-token", str(terraform_intent))

    def test_mixed_provider_chains_stay_separated(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"].append(
            {
                "id": "chain-2",
                "assignedProxy": "proxy02",
                "middleProvider": "digitalocean",
                "edgeProvider": "linode",
                "middleCredentialAlias": "do-sketch-prod",
                "edgeCredentialAlias": "linode-sketch-prod",
            }
        )
        payload["egressProfiles"].append({"name": "second-egress", "sketchChainId": "chain-2", "listenerPort": 3334})
        payload["ingressRoutes"].append(
            {"name": "second-ingress", "sketchChainId": "chain-2", "domain": "second.example.invalid"}
        )
        payload["reverseChannels"].append({"name": "second-backflip", "sketchChainId": "chain-2"})

        revision = compile_standard_rti_revision("eng-provider-test", payload)
        bundle = build_provider_plan_bundle(revision)
        terraform_intent = render_terraform_intent(bundle)

        self.assertEqual(len(terraform_intent["providers"]["linode"]), 2)
        self.assertEqual(len(terraform_intent["providers"]["digitalocean"]), 2)


if __name__ == "__main__":
    unittest.main()
