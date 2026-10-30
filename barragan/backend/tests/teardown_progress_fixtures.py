# Copyright (c) 2026, Oracle and/or its affiliates.
"""Complete initial-publication checkpoints for focused read-only display tests."""
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedInitialPublicationSource, MixedProviderState, MixedHostRow,
)
from app.services.provider_keyed_mixed_published_teardown_authority import PublishedMixedInitialTeardownReview
from app.services.provider_keyed_mixed_published_teardown_checkpoint import propose_published_mixed_initial_cleanup


def initial_checkpoint(core, order=("linode", "digitalocean")):
    plan = core.input["corePlanId"]
    chains = tuple(f"chain-{provider}" for provider in order)
    states = tuple(MixedProviderState(provider, "a" * 64, "lineage", 1, (), "b" * 64) for provider in order)
    hosts = tuple(MixedHostRow(chain, provider, role, f"{role}-{provider}", f"{provider}.{role}",
        str(index + 1), f"8.8.2.{index + 20}", "proxy01")
        for index, (provider, chain, role) in enumerate((provider, chain, role)
            for provider, chain in zip(order, chains) for role in ("middle", "edge")))
    source = MixedInitialPublicationSource(core.target_id, core.id, plan, "revision", "job-initial",
        tuple(order), chains, "c" * 64, "d" * 64, "e" * 64, states, hosts)
    scopes = tuple({"provider": provider, "coreJobId": core.id, "corePlanId": plan,
        "chainIds": [chain], "workspace": f"/private/tmp/test-{provider}",
        "resources": [{} for _ in range(6)]} for provider, chain in zip(order, chains))
    review = PublishedMixedInitialTeardownReview(source, scopes, "f" * 64, "a" * 64, 0, "b" * 64)
    scope = {"jobId": core.id, "planId": plan, "stateSha256": "a" * 64,
        "inventorySha256": "b" * 64, "proxyCount": 1,
        "targets": [{"id": f"tcp:{ip}:22", "type": "tcp-forbidden", "host": ip,
                     "port": 22, "targetGroup": "core-public-management"} for ip in ("8.8.8.8", "9.9.9.9")],
        "ownedInspectorRecordIds": ["inspector-instance", "inspector-firewall"]}
    return propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
