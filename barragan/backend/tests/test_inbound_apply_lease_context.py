# Copyright (c) 2026, Oracle and/or its affiliates.
"""Entry-point lease propagation with real SQL leases; preparation is isolated."""
from contextlib import nullcontext

import pytest

from app.domain import JobEvent
from app.services import inbound_channel_apply as apply
from app.services.inbound_mutation_fence import (
    active_inbound_mutation_owner, bind_inbound_batch,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


@pytest.mark.parametrize('entry', ['sync', 'async'])
@pytest.mark.parametrize('nested', [False, True])
def test_apply_entry_preserves_parent_or_acquires_and_releases_own_sql_lease(client, tmp_path, monkeypatch, entry, nested):
    with client.application.storage_context():
        jobs = SqlAlchemyJobRepository()
        leases = SqlAlchemyDeploymentPlanRepository()
        engagement = 'eng-context'
        parent = 'job-batch-parent'
        if nested:
            leases.acquire(engagement, parent, 'inbound_channel_batch_apply')
        observed = []
        tasks = []
        def check():
            owner = active_inbound_mutation_owner()
            assert owner
            assert _db_lease_lookup(engagement) == (owner, 'inbound_channel_batch_apply' if nested else 'inbound_channel_apply')
            if nested:
                assert owner == parent
            observed.append(owner)
        def sync(*args, **kwargs):
            check()
            return {'status': 'fixture'}
        def prepare(*args, **kwargs):
            check()
            job = jobs.save(StoredJobRun('job-child', 'inbound_channel_apply', 'running',
                f'engagement:{engagement}', 'engagement', engagement, 'operator',
                {'engagementId': engagement}, [], '2026-10-29T00:00:00', '2026-10-29T00:00:00', None,
                [JobEvent(1, 'info', 'prepared fixture', {})]))
            return jobs, job, [], tmp_path, None, {}, '', 'fixture'
        def finish(*args, **kwargs):
            check()
        monkeypatch.setattr(apply, '_apply_inbound_channel', sync)
        monkeypatch.setattr(apply, '_prepare_inbound_apply_job', prepare)
        monkeypatch.setattr(apply, '_finish_inbound_apply_job_and_maybe_validate', finish)
        with bind_inbound_batch(parent) if nested else nullcontext():
            if entry == 'sync':
                apply.apply_inbound_channel(engagement, 'channel')
            else:
                apply.start_inbound_channel_apply(engagement, 'channel', confirmation='fixture',
                    repository=jobs, background_runner=tasks.append)
        if entry == 'async':
            # Worker execution occurs after the preparation context has unwound.
            assert _db_lease_lookup(engagement) is not None
            tasks[0]()
        assert len(set(observed)) == 1
        assert active_inbound_mutation_owner() == ''
        assert _db_lease_lookup(engagement) == ((parent, 'inbound_channel_batch_apply') if nested else None)
        if nested:
            leases.release(engagement, parent)
