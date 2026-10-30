# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path
from unittest.mock import patch

from app.services.redteam_infra_template import RedteamInfraTemplateSource, component_safe_sketch_templates_available


def _template(root: Path, provider: str, *, consumes_ordinals: bool) -> None:
    directory = root / "external" / "sketch" / provider
    directory.mkdir(parents=True)
    (directory / "variables.tf").write_text('variable "middle_ordinal" {}\nvariable "edge_ordinal" {}\n')
    (directory / "middle.tf").write_text('name = "middle-${var.middle_ordinal}"\n' if consumes_ordinals else 'name = "middle"\n')
    (directory / "edge.tf").write_text('name = "edge-${var.edge_ordinal}"\n' if consumes_ordinals else 'name = "edge"\n')
    (directory / "output.tf").write_text('output "middle_instance_ids" {}\noutput "edge_instance_ids" {}\n')
    if provider == "digitalocean":
        (directory / "providers.tf").write_text('data "digitalocean_ssh_keys" "matching_key" {}\n')


def test_component_template_capability_requires_ordinals_to_be_consumed_in_names(tmp_path):
    _template(tmp_path, "linode", consumes_ordinals=False)
    _template(tmp_path, "digitalocean", consumes_ordinals=True)
    source = RedteamInfraTemplateSource(tmp_path, "test")
    with patch("app.services.redteam_infra_template.resolve_redteam_infra_template_source", return_value=source):
        available, reason = component_safe_sketch_templates_available()
    assert not available
    assert "declares but does not use component ordinals" in reason


def test_component_template_capability_accepts_consumed_ordinals_and_correlatable_outputs(tmp_path):
    _template(tmp_path, "linode", consumes_ordinals=True)
    _template(tmp_path, "digitalocean", consumes_ordinals=True)
    source = RedteamInfraTemplateSource(tmp_path, "test")
    with patch("app.services.redteam_infra_template.resolve_redteam_infra_template_source", return_value=source):
        assert component_safe_sketch_templates_available() == (True, "")
