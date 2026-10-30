# Copyright (c) 2026, Oracle and/or its affiliates.
from unittest.mock import patch

import pytest

from app import create_app
from app.core.config import TestConfig
from app.integrations.provider_plans import build_provider_plan_bundle, render_terraform_intent
from app.services.catalog import validate_template_input
from app.services.revision_compiler import compile_standard_rti_revision
from tests.sketch_provider_matrix import SKETCH_PROVIDER_COMBINATIONS, sketch_chain_payload
from tests.test_catalog_service import valid_standard_rti_payload
from tests.test_sketch_chains import _create_chain, _create_engagement, _fake_provider_job


def _payload_for_combo(combo):
    payload = valid_standard_rti_payload()
    payload["sketchChains"] = [sketch_chain_payload(combo)]
    payload["egressProfiles"] = [{"name": "default-sketch-egress", "sketchChainId": "chain-1", "listenerPort": 3333}]
    payload["ingressRoutes"] = [{"name": "default-ingress", "sketchChainId": "chain-1", "domain": "example.invalid"}]
    payload["reverseChannels"] = []
    return payload


def _create_chain_for_combo(client, engagement_id, combo):
    return _create_chain(
        client,
        engagement_id,
        "proxy01",
        combo.edge_region,
        middle_provider=combo.middle_provider,
        middle_region=combo.middle_region,
        middle_size=combo.middle_size,
        edge_provider=combo.edge_provider,
        edge_size=combo.edge_size,
    )


def _test_client(tmp_path, monkeypatch):
    template = tmp_path / "redteam-infra"
    (template / "ansible").mkdir(parents=True)
    (template / "external").mkdir()
    (template / "ansible" / "site.yml").write_text("---\n", encoding="utf-8")
    monkeypatch.setenv("BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT", str(template))

    class SketchProviderCombinationTestConfig(TestConfig):
        ENGAGEMENT_REPOS_ROOT = tmp_path / "engagements"

    return create_app(SketchProviderCombinationTestConfig).test_client()


def test_sketch_provider_combination_matrix_is_complete_and_explicit():
    combos = {(combo.middle_provider, combo.edge_provider): combo for combo in SKETCH_PROVIDER_COMBINATIONS}

    assert set(combos) == {
        ("linode", "linode"),
        ("digitalocean", "digitalocean"),
        ("linode", "digitalocean"),
        ("digitalocean", "linode"),
    }
    assert {combo.combo_id for combo in SKETCH_PROVIDER_COMBINATIONS} == {
        "linode-linode",
        "digitalocean-digitalocean",
        "linode-digitalocean",
        "digitalocean-linode",
    }
    assert all(combo.notes for combo in SKETCH_PROVIDER_COMBINATIONS)


@pytest.mark.parametrize("combo", SKETCH_PROVIDER_COMBINATIONS, ids=[combo.combo_id for combo in SKETCH_PROVIDER_COMBINATIONS])
def test_catalog_and_provider_plan_accept_sketch_provider_combination(combo):
    payload = _payload_for_combo(combo)

    validation = validate_template_input("standard-rti", payload)
    assert validation.valid, validation.errors

    revision = compile_standard_rti_revision("eng-provider-combo-test", payload)
    bundle = build_provider_plan_bundle(revision)
    terraform_intent = render_terraform_intent(bundle)

    middle_resources = [resource for resource in bundle.sketch if resource.role == "middle"]
    edge_resources = [resource for resource in bundle.sketch if resource.role == "edge"]
    assert [resource.provider for resource in middle_resources] == [combo.middle_provider]
    assert [resource.provider for resource in edge_resources] == [combo.edge_provider]

    provider_resources = terraform_intent["providers"]
    assert any(
        resource["role"] == "middle" and resource["attributes"]["region"] == combo.middle_region
        for resource in provider_resources[combo.middle_provider]
    )
    assert any(
        resource["role"] == "edge" and resource["attributes"]["region"] == combo.edge_region
        for resource in provider_resources[combo.edge_provider]
    )
    assert "secret" not in str(terraform_intent).lower()


@pytest.mark.parametrize("combo", SKETCH_PROVIDER_COMBINATIONS, ids=[combo.combo_id for combo in SKETCH_PROVIDER_COMBINATIONS])
def test_sketch_chain_record_can_be_created_for_provider_combination(combo, tmp_path, monkeypatch):
    client = _test_client(tmp_path, monkeypatch)
    engagement_id = _create_engagement(client, f"PC-{combo.combo_id}")

    chain = _create_chain_for_combo(client, engagement_id, combo)

    assert chain["middleProvider"] == combo.middle_provider
    assert chain["edgeProvider"] == combo.edge_provider
    assert chain["middleRegion"] == combo.middle_region
    assert chain["edgeRegion"] == combo.edge_region
    assert chain["status"] == "pending"


@pytest.mark.parametrize(
    "combo",
    [combo for combo in SKETCH_PROVIDER_COMBINATIONS if combo.expected_deploy_adapter in {"linode", "digitalocean"}],
    ids=[combo.combo_id for combo in SKETCH_PROVIDER_COMBINATIONS if combo.expected_deploy_adapter in {"linode", "digitalocean"}],
)
def test_live_incremental_deploy_dispatches_supported_same_provider_combinations(combo, tmp_path, monkeypatch):
    client = _test_client(tmp_path, monkeypatch)
    engagement_id = _create_engagement(client, f"PD-{combo.combo_id}")
    chain = _create_chain_for_combo(client, engagement_id, combo)
    job = _fake_provider_job(chain["chainId"], provider=combo.expected_deploy_adapter)
    patch_target = f"app.services.sketch_chains.start_guarded_{combo.expected_deploy_adapter}_sketch_run"
    confirmation = f"mutate-{combo.expected_deploy_adapter}-sketch-testing"

    with patch(patch_target, return_value=job) as start_run:
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": confirmation},
        )

    assert response.status_code == 202
    start_run.assert_called_once()
    request_body = start_run.call_args.args[0]
    assert request_body["confirmMutation"] == confirmation
    assert request_body["middleRegion"] == combo.middle_region
    assert request_body["edgeRegion"] == combo.edge_region
    assert request_body["edgeCount"] == 1


@pytest.mark.parametrize(
    "combo",
    [combo for combo in SKETCH_PROVIDER_COMBINATIONS if combo.expected_deploy_adapter == "composed"],
    ids=[combo.combo_id for combo in SKETCH_PROVIDER_COMBINATIONS if combo.expected_deploy_adapter == "composed"],
)
def test_live_incremental_deploy_supports_required_mixed_provider_combinations(combo, tmp_path, monkeypatch):
    client = _test_client(tmp_path, monkeypatch)
    engagement_id = _create_engagement(client, f"PX-{combo.combo_id}")
    chain = _create_chain_for_combo(client, engagement_id, combo)
    job = _fake_provider_job(chain["chainId"], provider="mixed", action="mixed_provider_sketch_deploy")

    with patch("app.services.sketch_chains.start_guarded_mixed_sketch_run", return_value=job) as start_run:
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-mixed-provider-sketch-testing"},
        )

    assert response.status_code == 202
    start_run.assert_called_once()
    request_body = start_run.call_args.args[0]
    assert request_body["middleProvider"] == combo.middle_provider
    assert request_body["edgeProvider"] == combo.edge_provider
    assert request_body["confirmMutation"] == "mutate-mixed-provider-sketch-testing"
    body = response.get_json()
    assert body["chain"]["middleProvider"] == combo.middle_provider
    assert body["chain"]["edgeProvider"] == combo.edge_provider
    assert body["job"]["action"] == "mixed_provider_sketch_deploy"
