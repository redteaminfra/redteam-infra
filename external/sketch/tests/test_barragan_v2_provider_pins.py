# Copyright (c) 2026, Oracle and/or its affiliates.
"""Static checks for the opt-in provider files copied into keyed workspaces.

Terraform init/validate in a copied workspace is still required before use.
"""

from pathlib import Path
import re
import unittest


SKETCH = Path(__file__).resolve().parents[1]
VERSIONS = {
    "digitalocean": {
        "digitalocean/digitalocean": "2.103.0",
        "hashicorp/local": "2.9.1",
    },
    "linode": {
        "linode/linode": "4.5.0",
        "hashicorp/random": "3.9.1",
        "hashicorp/local": "2.9.1",
    },
}


class BarraganV2ProviderPinsTest(unittest.TestCase):
    def test_sidecars_preserve_manual_provider_configuration(self):
        for provider in VERSIONS:
            with self.subTest(provider=provider):
                root = (SKETCH / provider / "providers.tf").read_text()
                sidecar = (SKETCH / provider / "barragan-v2" / "providers.tf").read_text()
                # Only the required_providers block may differ: provider
                # credentials and the DigitalOcean key resource are inherited.
                self.assertEqual(
                    root.split("\n}\n\n", 1)[1].rstrip(),
                    sidecar.split("\n}\n\n", 1)[1].rstrip(),
                )

    def test_sidecar_versions_match_reviewed_lock_entries(self):
        for provider, versions in VERSIONS.items():
            with self.subTest(provider=provider):
                sidecar = (SKETCH / provider / "barragan-v2" / "providers.tf").read_text()
                lock = (SKETCH / provider / "barragan-v2" / ".terraform.lock.hcl").read_text()
                self.assertEqual(len(re.findall(r'^provider "registry\.terraform\.io/', lock, re.M)), len(versions))
                for source, version in versions.items():
                    name = source.split("/")[-1]
                    self.assertRegex(sidecar, rf'(?s)\b{name}\s*=\s*\{{[^}}]*source\s*=\s*"{re.escape(source)}"[^}}]*version\s*=\s*"{re.escape(version)}"')
                    entry = re.search(rf'(?s)provider "registry\.terraform\.io/{re.escape(source)}" \{{(.*?)\n\}}', lock)
                    self.assertIsNotNone(entry)
                    self.assertIn(f'version     = "{version}"', entry.group(1))
                    self.assertIn(f'constraints = "{version}"', entry.group(1))
                    self.assertIn('"h1:', entry.group(1))
                    self.assertGreaterEqual(entry.group(1).count('"zh:'), 10)


if __name__ == "__main__":
    unittest.main()
