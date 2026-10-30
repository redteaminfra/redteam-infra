# Copyright (c) 2026, Oracle and/or its affiliates.
"""Local contract checks for the opt-in Sketch host firewall playbook."""

from pathlib import Path
import re
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


PLAYBOOK = Path(__file__).with_name("sketch-playbook.yml")


class SketchFirewallPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plays = yaml.safe_load(PLAYBOOK.read_text())
        cls.tasks = {task["name"]: task for play in cls.plays for task in play["tasks"]}
        cls.env = Environment(undefined=StrictUndefined)
        cls.env.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
        cls.env.filters["bool"] = bool

    def assert_rule_valid(self, task_name, item, expected):
        assertions = self.tasks[task_name]["assert"]["that"]
        actual = all(self.env.compile_expression(assertion)(item=item) for assertion in assertions)
        self.assertEqual(actual, expected, (task_name, item))

    def test_legacy_policy_is_gated_off_only_on_opt_in(self):
        for name in (
            "Store the IP of each host in its own variable",
            "Aggregate IPs from all hosts",
            "Allow all IPs in aggregated_ips to allow in ufw",
            "Open required ports",
            "Block incoming/outgoing ipv6",
        ):
            condition = self.env.compile_expression(self.tasks[name]["when"])
            self.assertTrue(condition())
            self.assertFalse(condition(sketch_firewall_v2_enabled=True))

    def test_ssh_accepts_only_single_ipv4_sources(self):
        name = "Validate this host's SSH sources"
        self.assert_rule_valid(name, "198.51.100.12/32", True)
        for source in ("0.0.0.0/0", "198.51.100.0/24", "0.0.0.0/32", "999.1.2.3/32", "::/0"):
            self.assert_rule_valid(name, source, False)

    def test_selected_traffic_requires_explicit_source_and_rejects_port_22(self):
        name = "Validate this host's traffic rules"
        self.assert_rule_valid(name, {"from_ip": "0.0.0.0/0", "port": 443, "proto": "tcp"}, True)
        self.assert_rule_valid(name, {"from_ip": "198.51.100.12/32", "port": 5353, "proto": "udp"}, True)
        for rule in (
            {"from_ip": "0.0.0.0/0", "port": 22, "proto": "tcp"},
            {"from_ip": "0.0.0.0/0", "port": 22, "proto": "udp"},
            {"port": 443, "proto": "tcp"},
            {"from_ip": "0.0.0.0/0", "port": 443, "proto": "icmp"},
            {"from_ip": "0.0.0.0/0", "port": 0, "proto": "tcp"},
        ):
            self.assert_rule_valid(name, rule, False)

    def test_active_policy_is_rejected_before_rules_are_replaced(self):
        names = list(self.tasks)
        self.assertLess(names.index("Refuse opt-in policy on a host with active UFW"),
                        names.index("Clear inactive UFW rules for the opt-in policy"))
        self.assertLess(names.index("Clear inactive UFW rules for the opt-in policy"),
                        names.index("Deny unsolicited incoming traffic for the opt-in policy"))
        self.assertLess(names.index("Allow this host's selected traffic"), names.index("Enable ufw"))
        self.assertEqual(self.tasks["Clear inactive UFW rules for the opt-in policy"]["ufw"]["state"], "reset")
        self.assertEqual(self.tasks["Deny unsolicited incoming traffic for the opt-in policy"]["ufw"]["default"], "deny")
        self.assertEqual(self.tasks["Allow this host's selected traffic"]["ufw"]["from_ip"], "{{ item.from_ip }}")

        # This first version is fresh-bootstrap-only, including on an already
        # active v2 host; append/reapply must use a separate reviewed path.
        active_check = self.tasks["Refuse opt-in policy on a host with active UFW"]["assert"]["that"][0]
        assert_inactive = self.env.compile_expression(active_check)
        self.assertTrue(assert_inactive(sketch_firewall_v2_status={"stdout": "Status: inactive"}))
        self.assertFalse(assert_inactive(sketch_firewall_v2_status={"stdout": "Status: active"}))


if __name__ == "__main__":
    unittest.main()
