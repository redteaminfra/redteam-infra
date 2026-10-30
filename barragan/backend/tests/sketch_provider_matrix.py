# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SketchProviderCombination:
    """Reusable sketch middle/edge provider matrix for local and live tests."""

    combo_id: str
    middle_provider: str
    edge_provider: str
    middle_region: str
    edge_region: str
    middle_size: str
    edge_size: str
    middle_credential_alias: str
    edge_credential_alias: str
    expected_live_incremental_deploy: bool
    expected_deploy_adapter: str | None
    notes: str


SKETCH_PROVIDER_COMBINATIONS: tuple[SketchProviderCombination, ...] = (
    SketchProviderCombination(
        combo_id="linode-linode",
        middle_provider="linode",
        edge_provider="linode",
        middle_region="us-sea",
        edge_region="us-sea",
        middle_size="g6-nanode-1",
        edge_size="g6-nanode-1",
        middle_credential_alias="linode-sketch-dev",
        edge_credential_alias="linode-sketch-dev",
        expected_live_incremental_deploy=True,
        expected_deploy_adapter="linode",
        notes="Same-provider Linode chain; should dispatch to the Linode sketch adapter.",
    ),
    SketchProviderCombination(
        combo_id="digitalocean-digitalocean",
        middle_provider="digitalocean",
        edge_provider="digitalocean",
        middle_region="sfo3",
        edge_region="sfo3",
        middle_size="s-1vcpu-1gb",
        edge_size="s-1vcpu-1gb",
        middle_credential_alias="do-sketch-dev",
        edge_credential_alias="do-sketch-dev",
        expected_live_incremental_deploy=True,
        expected_deploy_adapter="digitalocean",
        notes="Same-provider DigitalOcean chain; should dispatch to the DigitalOcean sketch adapter.",
    ),
    SketchProviderCombination(
        combo_id="linode-digitalocean",
        middle_provider="linode",
        edge_provider="digitalocean",
        middle_region="us-sea",
        edge_region="sfo3",
        middle_size="g6-nanode-1",
        edge_size="s-1vcpu-1gb",
        middle_credential_alias="linode-sketch-dev",
        edge_credential_alias="do-sketch-dev",
        expected_live_incremental_deploy=True,
        expected_deploy_adapter="composed",
        notes="Mixed-provider chain; should be deployable through a composed cross-provider sketch deploy path.",
    ),
    SketchProviderCombination(
        combo_id="digitalocean-linode",
        middle_provider="digitalocean",
        edge_provider="linode",
        middle_region="sfo3",
        edge_region="us-sea",
        middle_size="s-1vcpu-1gb",
        edge_size="g6-nanode-1",
        middle_credential_alias="do-sketch-dev",
        edge_credential_alias="linode-sketch-dev",
        expected_live_incremental_deploy=True,
        expected_deploy_adapter="composed",
        notes="Mixed-provider chain; should be deployable through a composed cross-provider sketch deploy path.",
    ),
)


def sketch_chain_payload(
    combo: SketchProviderCombination,
    *,
    chain_id: str = "chain-1",
    assigned_proxy: str = "proxy01",
    edge_count: int = 1,
) -> dict[str, object]:
    return {
        "id": chain_id,
        "assignedProxy": assigned_proxy,
        "middleProvider": combo.middle_provider,
        "edgeProvider": combo.edge_provider,
        "middleCredentialAlias": combo.middle_credential_alias,
        "edgeCredentialAlias": combo.edge_credential_alias,
        "middleRegion": combo.middle_region,
        "edgeRegion": combo.edge_region,
        "middleSize": combo.middle_size,
        "edgeSize": combo.edge_size,
        "edgeCount": edge_count,
    }
