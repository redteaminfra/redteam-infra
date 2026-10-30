# Copyright (c) 2026, Oracle and/or its affiliates.
"""Keep the opt-in firewall overlay identical to the manual root except IPv6 allows."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]

IPV6_INBOUND_ALLOW = '''  dynamic "inbound_rule" {
    // Block all IPv6 traffic inbound
    for_each = ["tcp", "udp", "icmp"]
    content {
      protocol         = inbound_rule.value
      port_range       = "1-65535"
      source_addresses = ["::/0"]
    }
  }

'''

IPV6_OUTBOUND_ALLOW = '''  dynamic "outbound_rule" {
    // Block all IPv6 traffic outbound
    for_each = ["tcp", "udp", "icmp"]
    content {
      protocol              = outbound_rule.value
      port_range            = "1-65535"
      destination_addresses = ["::/0"]
    }
  }

'''


class BarraganV2FirewallOverlayTest(unittest.TestCase):
    def test_only_ipv6_allow_rules_are_removed(self):
        manual = (ROOT / "firewall.tf").read_text()
        overlay = (ROOT / "barragan-v2" / "firewall.tf").read_text()

        for allow in (IPV6_INBOUND_ALLOW, IPV6_OUTBOUND_ALLOW):
            self.assertEqual(manual.count(allow), 1)
            self.assertNotIn(allow, overlay)

        expected = manual.replace(IPV6_INBOUND_ALLOW, "").replace(
            IPV6_OUTBOUND_ALLOW, ""
        )
        self.assertEqual(overlay, expected)
        self.assertNotIn('"::/0"', overlay)


if __name__ == "__main__":
    unittest.main()
