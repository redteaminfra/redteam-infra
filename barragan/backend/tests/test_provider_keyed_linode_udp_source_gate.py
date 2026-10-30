# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from app.services.provider_keyed_ingress_plan_gate import KeyedIngressRoute, require_keyed_ingress_saved_plan
from app.services import provider_keyed_ingress_plan_gate as ingress
from app.services.provider_keyed_linode_udp_source_gate import (
    _CANDIDATE_SOURCE_REVISION,
    require_candidate_linode_udp_workspace,
)
from app.services.provider_keyed_sketch import prepare_provider_keyed_workspace
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_ingress_plan_gate import _case, _linode_rule
from redteam_infra_test_fixtures import checkout_local_pinned_source


def _literal_source(tmp_path, revision):
    source = Path(os.environ.get(
        "BARRAGAN_TEST_REDTEAM_INFRA",
        str(Path(__file__).resolve().parents[3] / "redteam-infra"),
    )).resolve()
    if not (source / ".git").exists():
        pytest.skip("real Redteam-infra checkout required")
    return checkout_local_pinned_source(source, tmp_path / "literal-source", revision)


def test_candidate_linode_udp_ingress_requires_its_exact_source_and_union(monkeypatch):
    monkeypatch.setattr(ingress, 'require_candidate_linode_udp_workspace', lambda _: None)
    plan, args, _, field, _ = _case('linode')
    args['workspace'] = replace(args['workspace'], source_revision=_CANDIDATE_SOURCE_REVISION)
    edge = args['attached_node_addresses'][1]
    args['next_routes'] = (KeyedIngressRoute('channel-1', 'udp', 3478, edge),)
    args['observed_host_ports'][edge] = (('udp', 3478),)
    args['reviewed_variables']['allowed_tcp_ports'] = ['22', '80', '443', '2222']
    args['reviewed_variables']['allowed_udp_ports'] = ['3478']
    plan['variables'] = {key: {'value': value} for key, value in args['reviewed_variables'].items()}
    plan['resource_changes'][0]['change']['after'][field] = [
        _linode_rule('tcp', port) for port in (80, 443, 2222)
    ] + [_linode_rule('udp', 3478),
         plan['resource_changes'][0]['change']['after'][field][-1]]
    require_keyed_ingress_saved_plan(json.dumps(plan), **args)
    args['reviewed_variables']['allowed_udp_ports'] = []
    plan['variables']['allowed_udp_ports']['value'] = []
    with pytest.raises(TerraformPlanGateError, match='Terraform ports'):
        require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_literal_candidate_source_and_rendered_overlay(tmp_path):
    source = _literal_source(tmp_path, _CANDIDATE_SOURCE_REVISION)
    workspace = prepare_provider_keyed_workspace(
        'eng-1234567890ab', 'linode', 'connection-123456',
        template_root=source, source_revision=_CANDIDATE_SOURCE_REVISION,
        root=tmp_path, environment='devtest', deployment_target='barragan-testing',
    )
    require_candidate_linode_udp_workspace(workspace)
    rendered = (workspace.path / 'firewall.tf').read_text()
    assert 'for_each = var.allowed_udp_ports' in rendered
    (workspace.path / 'firewall.tf').write_text(rendered.replace('var.allowed_udp_ports', '[]'))
    with pytest.raises(TerraformPlanGateError, match='audit failed'):
        require_candidate_linode_udp_workspace(workspace)


@pytest.mark.parametrize('provider', ['linode', 'digitalocean'])
@pytest.mark.parametrize('historical', [False, True])
def test_active_and_historical_literal_workspaces_keep_exact_source_identity(
        tmp_path, provider, historical):
    import app.services.provider_keyed_initial_plan_gate as digitalocean
    import app.services.provider_keyed_linode_initial_plan_gate as linode
    from app.services.core_deployment_plans import KEYED_LINODE_SOURCE_SHA256
    from app.services.provider_keyed_core_source import require_keyed_core_source

    assert digitalocean._SOURCE_REVISION == linode._SOURCE_REVISION == _CANDIDATE_SOURCE_REVISION
    assert KEYED_LINODE_SOURCE_SHA256 == linode._SOURCE_SHA256
    revision = digitalocean._LEGACY_SOURCE_REVISION if historical else _CANDIDATE_SOURCE_REVISION
    source = _literal_source(tmp_path, revision)
    if not historical:
        assert require_keyed_core_source(source)['revision'] == revision
    workspace = prepare_provider_keyed_workspace(
        'eng-1234567890ab', provider, 'connection-123456',
        template_root=source, source_revision=revision,
        root=tmp_path / 'state', environment='devtest', deployment_target='barragan-testing')
    audit = linode._workspace if provider == 'linode' else digitalocean._verify_audited_workspace
    audit(workspace)
    expected_sha = (linode._LEGACY_SOURCE_SHA256 if historical else linode._SOURCE_SHA256
                    ) if provider == 'linode' else digitalocean._SOURCE_SHA256
    assert workspace.source_sha256 == expected_sha
    marker = workspace.path / '.barragan-provider-keyed-state.json'
    before = marker.read_bytes()
    assert json.loads(before)['source_revision'] == revision
    # A label change cannot upgrade historical source authority.
    foreign = replace(workspace, source_revision=(
        _CANDIDATE_SOURCE_REVISION if historical else digitalocean._LEGACY_SOURCE_REVISION))
    with pytest.raises(TerraformPlanGateError):
        audit(foreign)
    assert marker.read_bytes() == before
    with pytest.raises(ValueError, match='DevTest'):
        prepare_provider_keyed_workspace(
            'eng-1234567890ab', provider, 'connection-123456',
            template_root=source, source_revision=revision, root=tmp_path / 'production',
            environment='prod', deployment_target='barragan-testing')
