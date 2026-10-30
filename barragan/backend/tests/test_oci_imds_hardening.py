# Copyright (c) 2026, Oracle and/or its affiliates.
from app.services.redteam_infra_template import redteam_infra_path


def test_checked_in_oci_instance_templates_disable_legacy_imds_endpoints():
    template_root = redteam_infra_path("external", "oci")
    terraform_files = sorted(template_root.glob("*.tf"))
    offenders: list[str] = []

    for terraform_file in terraform_files:
        content = terraform_file.read_text(encoding="utf-8")
        if 'resource "oci_core_instance"' not in content:
            continue
        resource_count = content.count('resource "oci_core_instance"')
        hardened_count = content.count("are_legacy_imds_endpoints_disabled = true")
        if hardened_count < resource_count:
            offenders.append(str(terraform_file))

    assert not offenders, f"OCI instance templates must disable legacy IMDS endpoints: {offenders}"
