# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.services.revision_compiler import compile_standard_rti_revision
from tests.test_catalog_service import valid_standard_rti_payload


class RevisionCompilerTests(unittest.TestCase):
    def test_compiles_minimum_standard_rti_baseline(self):
        revision = compile_standard_rti_revision("eng-test", valid_standard_rti_payload())
        body = revision.to_dict()

        self.assertEqual(body["status"], "compiled")
        self.assertEqual(body["templateId"], "standard-rti")
        self.assertEqual(len(body["resolvedTopology"]["sketchChains"]), 1)
        self.assertEqual(body["resolvedTopology"]["proxyStacks"][0]["domains"], ["example.invalid"])
        self.assertIn("homebase", body["resolvedTopology"]["sketchChains"][0]["managementPath"])
        egress_profile = body["resolvedTopology"]["egressProfiles"][0]
        self.assertEqual(egress_profile["details"]["listenerPort"], 3333)
        self.assertEqual(egress_profile["details"]["ownerProxy"], "proxy01")
        self.assertEqual(egress_profile["details"]["publicationPath"], "/opt/proxy01/default-sketch-egress-socks5.conf")
        self.assertEqual({gate["status"] for gate in body["validationGates"]}, {"passed"})
        self.assertIn("proxy-egress-profile-state", {gate["id"] for gate in body["validationGates"]})

    def test_compiles_dev_infra_with_one_proxy_and_multiple_edges(self):
        payload = valid_standard_rti_payload()
        payload["proxyCount"] = 1
        payload["sketchChains"][0]["edgeCount"] = 2
        payload["ingressRoutes"] = []

        revision = compile_standard_rti_revision("eng-test", payload, template_id="dev-infra")
        body = revision.to_dict()
        proxy_groups = [group for group in body["resolvedTopology"]["nodeGroups"] if group["role"] == "proxy"]
        edge_groups = [group for group in body["resolvedTopology"]["nodeGroups"] if group["role"] == "edge"]

        self.assertEqual(body["templateId"], "dev-infra")
        self.assertEqual(proxy_groups[0]["count"], 1)
        self.assertEqual(edge_groups[0]["count"], 2)
        self.assertEqual(body["resolvedTopology"]["sketchChains"][0]["edgeCount"], 2)
        self.assertEqual({gate["status"] for gate in body["validationGates"]}, {"passed"})
        core_gate = next(gate for gate in body["validationGates"] if gate["id"] == "core-topology")
        self.assertIn("Dev Infra", core_gate["message"])
        self.assertNotIn("two", core_gate["message"])

    def test_compiles_small_dev_infra_with_one_proxy_and_no_elk(self):
        payload = valid_standard_rti_payload()
        payload.update(
            {
                "engagementName": "small-dev",
                "proxyCount": 1,
                "elkEnabled": False,
                "egressProfiles": [],
                "ingressRoutes": [],
            }
        )

        revision = compile_standard_rti_revision("eng-small", payload, template_id="small-dev-infra")

        body = revision.to_dict()
        self.assertEqual(body["templateId"], "small-dev-infra")
        self.assertEqual(next(group["count"] for group in body["resolvedTopology"]["nodeGroups"] if group["role"] == "proxy"), 1)
        core_gate = next(gate for gate in body["validationGates"] if gate["id"] == "core-topology")
        self.assertIn("Small Dev Infra", core_gate["message"])

    def test_compiles_mixed_provider_multi_chain_topology(self):
        payload = valid_standard_rti_payload()
        payload["sketchChains"].append(
            {
                "id": "chain-2",
                "assignedProxy": "proxy02",
                "middleProvider": "digitalocean",
                "edgeProvider": "linode",
            }
        )
        payload["egressProfiles"].append({"name": "second-egress", "sketchChainId": "chain-2", "listenerPort": 3334})
        payload["ingressRoutes"].append(
            {"name": "second-ingress", "sketchChainId": "chain-2", "domain": "second.example.invalid"}
        )
        payload["reverseChannels"].append({"name": "second-backflip", "sketchChainId": "chain-2"})

        revision = compile_standard_rti_revision("eng-test", payload)
        topology = revision.to_dict()["resolvedTopology"]

        self.assertEqual(len(topology["sketchChains"]), 2)
        self.assertEqual({chain["assignedProxy"] for chain in topology["sketchChains"]}, {"proxy01", "proxy02"})
        self.assertEqual(len(topology["proxyStacks"]), 2)

    def test_validation_gates_are_deterministic_and_local(self):
        revision = compile_standard_rti_revision("eng-test", valid_standard_rti_payload())
        gates = revision.to_dict()["validationGates"]

        self.assertEqual(
            [gate["id"] for gate in gates],
            [
                "core-topology",
                "sketch-chain-topology",
                "route-chain-references",
                "sketch-management-opsec",
                "proxy-egress-profile-state",
                "plan-only-intent",
            ],
        )
        self.assertTrue(all(gate["severity"] == "info" for gate in gates))


if __name__ == "__main__":
    unittest.main()
