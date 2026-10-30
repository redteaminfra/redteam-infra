# Copyright (c) 2026, Oracle and/or its affiliates.
"""Normal preview/save reopens chain-local IDs through actual SQL Operations."""
from copy import deepcopy
from uuid import uuid4

import pytest

from app.domain import JobEvent
from app.services import inbound_channel_batch as batch
from app.services.engagement_operations import get_operations_overview
from app.services.inbound_channel_workflow import InboundChannelWorkflowValidationError
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from test_inbound_channel_workflow import _overview


@pytest.mark.parametrize('provider_order', [('linode', 'digitalocean'), ('digitalocean', 'linode')])
def test_sql_reviewed_create_allows_repeated_edge_and_middle_ids_on_independent_chains(client, monkeypatch, provider_order):
    with client.application.storage_context():
        engagement_id = 'eng-scoped-dns'
        SqlAlchemyEngagementRepository().save(StoredEngagement(
            engagement_id, 'ZY01', 'active', 'operator', 'small-dev-infra', None, {}))
        jobs = SqlAlchemyJobRepository()
        topology = deepcopy(_overview())
        for row in topology['coreInfrastructure']:
            row.update(displayName=row['hostname'], sshAlias=row['hostname'])
        for i, row in enumerate(topology['sketchInfrastructure']):
            row.update(componentId='middle-01' if row['role'] == 'middle' else 'edge-01',
                assignedProxyId='proxy01', proxy='proxy01', provider=provider_order[i // 2])
        jobs.save(StoredJobRun('job-core-scoped', 'pilot_standard_rti_guarded_execute', 'succeeded',
            'oci:example', 'oci_compartment', 'example', 'operator', {'engagementId': engagement_id, 'proxyCount': 2, 'resourceNames': {
                'homebase': 'homebase-zy01', 'proxy01': 'proxy01-zy01',
                'proxy02': 'proxy02-zy01', 'vcn': 'vcn-zy01'}}, [],
            '2026-10-29T01:00:00', '2026-10-29T01:00:00', '2026-10-29T01:01:00',
            [JobEvent(1, 'info', 'core deployed', {'connectionDetails': topology['coreInfrastructure']})]))
        jobs.save(StoredJobRun('job-sketch-scoped', 'mixed_provider_sketch_deploy', 'succeeded',
            f'engagement:{engagement_id}', 'engagement', engagement_id, 'operator', {'engagementId': engagement_id}, [],
            '2026-10-29T02:00:00', '2026-10-29T02:00:00', '2026-10-29T02:01:00',
            [JobEvent(1, 'info', 'sketch deployed', {'sketchInfrastructure': topology['sketchInfrastructure']})]))
        # External host/provider readiness checks are seams. Derivation, preview hash,
        # lease, durable prepare writer and Operations semantic reads are real.
        monkeypatch.setattr(batch, 'preflight_inbound_channel_apply', lambda _name, _ops, channel: channel)
        monkeypatch.setattr(batch, 'provider_ingress_preflight_errors', lambda *_args, **_kwargs: [])
        saved = []
        for i, edge in enumerate(('edge-zy01-us-sea-01', 'edge-zy01-us-ash-02')):
            body = {'edge': edge, 'chainId': topology['sketchInfrastructure'][i*2]['chainId'],
                'edgeComponentId': 'edge-01', 'protocol': 'UDP', 'externalPort': '53',
                'terminatesOn': 'homebase', 'internalPort': str(26053+i),
                'validationProfile': {'type': 'manual'}}
            submission = str(uuid4())
            preview = batch.preview_inbound_channel_batch(engagement_id, submission, [body])
            result = batch.prepare_reviewed_inbound_channel(engagement_id, submission,
                preview['previewFingerprint'], body, repository=jobs)
            saved.append(result['channel'])
        assert [row['middleRelayPort'] for row in saved] == ['8000', '8000']
        assert [row['proxyRelayPort'] for row in saved] == ['8000', '8001']
        actual = get_operations_overview(engagement_id, include_provider_findings=False)
        assert len(actual['inboundChannels']) == 2
        assert {row['edgeComponentId'] for row in actual['inboundChannels']} == {'edge-01'}
        assert {row['middleComponentId'] for row in actual['inboundChannels']} == {'middle-01'}
        assert all(row['rawRoutePlan']['infrastructureRevision']['chainId'] == row['chainId']
                   for row in actual['inboundChannels'])
        # A second request to the same physical public socket is still refused.
        with pytest.raises(InboundChannelWorkflowValidationError):
            batch.preview_inbound_channel_batch(engagement_id, str(uuid4()), [body])
