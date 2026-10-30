# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded keyed outbound bridge: authenticate publication, GET exact policy, no writes."""
from dataclasses import replace
import hashlib
from types import SimpleNamespace as NS
import pytest
from app.services import sketch_provider_firewall as m
from app.services import outbound_channel_apply as outbound


@pytest.mark.parametrize('nodes', [4, 6])
def test_transport_proves_both_current_policies_without_mutating(nodes, monkeypatch, tmp_path):
    chains = [NS(chain_id='a'), NS(chain_id='b')]
    jobs = NS(list_for_engagement=lambda _: (), get=lambda _: NS(id='initial'))
    sketches = NS(list_for_engagement=lambda _: chains)
    source = NS(chain_ids=('a', 'b'), core_job_id='core')
    policies = {'digitalocean': {'current': nodes}, 'linode': {'current': nodes}}

    for provider in policies:
        (tmp_path / provider).mkdir()
        (tmp_path / provider / 'terraform.tfstate').write_bytes(b'current-state')
    collection = NS(review=NS(source=source), workspaces={p: tmp_path / p for p in policies},
        observations={p: NS(classification=NS(state_sha256=hashlib.sha256(b'current-state').hexdigest())) for p in policies})
    monkeypatch.setattr(m, 'get_engagement', lambda _: NS(sketch_state_schema='provider-keyed-v2'))
    monkeypatch.setattr(m, '_keyed_transport_publication', lambda *args: collection)
    monkeypatch.setattr('app.services.provider_keyed_runtime_preflight._db_lease_lookup', lambda _: None)
    monkeypatch.setattr('app.services.provider_keyed_mixed_published_teardown_authority.published_review_policy',
                        lambda review, initial, provider: policies[provider])
    seen = []
    def prove(provider, policy, workspace, credentials, fence):
        assert fence() == 'keyed-transport-read-only'
        assert workspace.state_path == tmp_path / provider / 'terraform.tfstate'
        assert credentials == 'credentials'
        seen.append((provider, policy))
    monkeypatch.setattr('app.services.provider_keyed_channel_apply._prove_provider_generation', prove)
    monkeypatch.setattr(m, 'sync_provider_ingress_for_inbound_channel', lambda *a, **k: pytest.fail('write path'))
    result = m.sync_provider_ingress_for_transport('eng', 'name', 'a', overview={},
        job_repository=jobs, chain_repository=sketches, credential_repository='credentials')
    assert result.ok and seen == list(policies.items())
    assert result.events[0].data['mutation'] is False


@pytest.mark.parametrize('fault', ['source', 'proof', 'chain', 'fence', 'lease'])
def test_transport_fails_closed(fault, monkeypatch, tmp_path):
    rows = []
    (tmp_path / 'terraform.tfstate').write_bytes(b'current-state')
    jobs = NS(list_for_engagement=lambda _: tuple(rows), get=lambda _: NS())
    sketches = NS(list_for_engagement=lambda _: ())
    monkeypatch.setattr(m, 'get_engagement', lambda _: NS(sketch_state_schema='provider-keyed-v2'))
    monkeypatch.setattr('app.services.provider_keyed_runtime_preflight._db_lease_lookup',
                        lambda _: ('other', 'mutation') if fault == 'lease' else None)
    def publication(*args):
        if fault == 'source': raise ValueError('unauthenticated')
        if fault == 'fence': rows.append('changed')
        return NS(review=NS(source=NS(chain_ids=('a',), core_job_id='core')),
                  workspaces={'linode': tmp_path}, observations={'linode': NS(classification=NS(state_sha256=hashlib.sha256(b'current-state').hexdigest()))})
    monkeypatch.setattr(m, '_keyed_transport_publication', publication)
    monkeypatch.setattr('app.services.provider_keyed_mixed_published_teardown_authority.published_review_policy', lambda *a: {})
    def proof(*args):
        if fault == 'proof': raise ValueError('current union differs')
    monkeypatch.setattr('app.services.provider_keyed_channel_apply._prove_provider_generation', proof)
    result = m.sync_provider_ingress_for_transport('eng', 'name', 'wrong' if fault == 'chain' else 'a',
        overview={}, job_repository=jobs, chain_repository=sketches, credential_repository='credentials')
    assert not result.ok


def test_keyed_bootstrap_requires_authenticated_publication_without_legacy_event(monkeypatch):
    chain = NS(status='deployed', deploy_job_id='initial')
    jobs = NS(get=lambda _: NS(events=[]))
    sketches = NS(get=lambda *args: chain)
    monkeypatch.setattr(outbound, 'get_engagement', lambda _: NS(sketch_state_schema='provider-keyed-v2'))
    monkeypatch.setattr(m, '_keyed_transport_publication', lambda *args: NS(review=NS(source=NS(chain_ids=('a',)))))
    outbound._require_bootstrapped_chain(jobs, 'eng', 'a', chain_repository=sketches)
    monkeypatch.setattr(m, '_keyed_transport_publication', lambda *args: (_ for _ in ()).throw(ValueError('drift')))
    with pytest.raises(ValueError, match='drift'):
        outbound._require_bootstrapped_chain(jobs, 'eng', 'a', chain_repository=sketches)

# Real persisted initial seal/binding/60-event host-proof source, not a boolean bootstrap.
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_collector import _collect
from app.services.provider_keyed_mixed_published_teardown_collector import collect_published_mixed_initial_teardown, _empty_owned_bindings


def test_transport_reopens_real_published_four_after_completed_outbound(client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, args, _, kwargs = _collect(ready, tmp_path, monkeypatch)
        kwargs.pop('binding_inventory')
        kwargs['domain_repository'] = NS(list_assignments=lambda **_: [])
        jobs = ready.case.jobs
        original = jobs.list_for_engagement
        terminal = replace(original(source.engagement_id)[0], id='outbound-done',
            action='outbound_channel_apply', status='succeeded', finished_at='2026-10-19T00:00:00+00:00')
        jobs.list_for_engagement = lambda identifier: [*original(identifier), terminal]
        reviewed = collect_published_mixed_initial_teardown(source.engagement_id,
            source.core_job_id, read_only_transport=True, **kwargs)
        assert reviewed.review.source == source
        # The transport-specific allowance never becomes destructive authority.
        with pytest.raises(ValueError):
            _empty_owned_bindings(source.engagement_id, jobs, kwargs['domain_repository'])
        terminal = replace(terminal, status='running', finished_at=None)
        with pytest.raises(ValueError):
            collect_published_mixed_initial_teardown(source.engagement_id,
                source.core_job_id, read_only_transport=True, **kwargs)


@pytest.mark.parametrize('edges', [1, 2])
def test_durable_artifact_fallback_allocates_all_edge_profiles_consistently(edges, monkeypatch):
    chains = [NS(chain_id=f'chain-{i}', assigned_proxy=f'proxy0{i}', status='deployed', nodes=[
        {'role': 'middle', 'hostname': f'middle0{i}', 'publicIp': f'192.0.2.{i}'},
        *[{'role': 'edge', 'hostname': f'edge0{i}-0{j}', 'publicIp': f'198.51.100.{i*10+j}', 'edgeIndex': str(j)}
          for j in range(1, edges+1)]]) for i in (1, 2)]
    jobs = NS(list=lambda: [])
    sketches = NS(list_for_engagement=lambda _: chains)
    monkeypatch.setattr(outbound, 'SqlAlchemySketchChainRepository', lambda: sketches)
    monkeypatch.setattr(outbound, 'get_engagement', lambda _: NS(name='Opaque', sketch_state_schema='provider-keyed-v2'))
    monkeypatch.setattr(m, '_keyed_transport_publication', lambda *args: NS())
    from app.services.outbound_channel_artifacts import derive_pending_outbound_channels_from_sketch_rows
    expected = []
    for chain in chains:
        expected.extend(derive_pending_outbound_channels_from_sketch_rows('Opaque', chain.chain_id,
            [{**n, 'proxy': chain.assigned_proxy, 'assignedProxy': chain.assigned_proxy,
              'chainId': chain.chain_id, 'status': chain.status} for n in chain.nodes],
            existing_outbound_channels=expected))
    assert len(expected) == edges * 2
    for row in reversed(expected):
        actual = outbound._latest_outbound_channel_with_artifacts(jobs, 'eng', row['channelId'])
        assert actual == row
        assert actual['artifacts'] and actual['port'] == row['port']
