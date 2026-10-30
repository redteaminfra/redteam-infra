# Copyright (c) 2026, Oracle and/or its affiliates.
"""Actual SQL writer wrappers with operation-local verification captures.

Cloud observations/source audits retain the existing integration fixture seams.
The added command is a bounded fake Terraform witness, not cloud execution.
"""
import sqlite3
import time

import pytest
from sqlalchemy import event

from app.services import provider_keyed_channel_generation as generation
from app.services import provider_keyed_mixed_published_teardown_collector as collector
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from test_provider_keyed_channel_cleanup_observation import (
    case, failed_case, test_cleanup_observation_passes_actual_review_start_sql_seal_and_restart as _flow,
)
from test_provider_keyed_readonly_verification import command as _command


@pytest.fixture
def command(tmp_path):
    root = tmp_path / "command-witness"
    root.mkdir()
    return _command.__wrapped__(root)


@pytest.fixture
def client(tmp_path, monkeypatch):
    import conftest
    from app.core.config import TestConfig
    monkeypatch.setattr(TestConfig, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{tmp_path / 'capture.sqlite'}")
    return conftest.client.__wrapped__(tmp_path, monkeypatch)


class Sealed(Exception):
    pass


@pytest.mark.parametrize('failed_case', ['apply_intent:noop'], indirect=True)
@pytest.mark.parametrize('drift', ['none', 'plan', 'plugin', 'missing_capture'])
def test_actual_seal_primes_outside_writer_and_rechecks_inside(
        failed_case, client, tmp_path, monkeypatch, command, drift, record_property):
    run, calls, _, _, plan, plugin, raw_runner = command
    original_recheck = collector.recheck_published_six_collection_local
    original_seal = SqlAlchemyJobRepository.seal_published_mixed_initial_destroy_plans
    original_verify = generation._verify_channel_host_proof
    state = dict(armed=False, locked=False, rechecks=0, writer_rechecks=0,
                 interpretations=0, heartbeat=False, started=None, elapsed=None)

    def command_runner(*args, **kwargs):
        assert not state['locked'], 'command ran under writer'
        return raw_runner(*args, **kwargs)

    def verify(*args):
        assert not state['locked'], 'pure interpretation ran under writer'
        state['interpretations'] += 1
        return original_verify(*args)

    def recheck(*args, **kwargs):
        state['rechecks'] += 1
        if state['locked']:
            state['writer_rechecks'] += 1
        result = original_recheck(*args, **kwargs)
        if state['armed']:
            if not state['locked']:
                # A real independent SQLite writer can complete during prewarm.
                connection = sqlite3.connect(db.engine.url.database, timeout=.05)
                try:
                    connection.execute("UPDATE core_mutation_leases SET owner_id=owner_id")
                    connection.commit()
                    state['heartbeat'] = True
                finally:
                    connection.close()
            if drift != 'missing_capture' or state['locked']:
                run(runner=command_runner)
        return result

    def sql_boundary(conn, cursor, statement, parameters, context, executemany):
        if state['armed'] and statement.lstrip().upper().startswith('UPDATE DEPLOYMENT_PLANS SET STATUS = STATUS'):
            state['locked'] = True
            state['started'] = time.monotonic()
            if drift == 'plan':
                plan.write_bytes(b'changed plan')
            elif drift == 'plugin':
                plugin.write_bytes(b'changed provider')

    def seal(self, *args, **kwargs):
        state['armed'] = True
        event.listen(db.engine, 'before_cursor_execute', sql_boundary)
        try:
            value = original_seal(self, *args, **kwargs)
            assert value is not None
            raise Sealed()
        finally:
            state['elapsed'] = time.monotonic() - state['started'] if state['started'] else None
            state['locked'] = False
            event.remove(db.engine, 'before_cursor_execute', sql_boundary)

    monkeypatch.setattr(generation, '_verify_channel_host_proof', verify)
    monkeypatch.setattr(collector, 'recheck_published_six_collection_local', recheck)
    monkeypatch.setattr(SqlAlchemyJobRepository, 'seal_published_mixed_initial_destroy_plans', seal)
    if drift == 'none':
        with pytest.raises(Sealed):
            _flow(failed_case, client, tmp_path, monkeypatch, 1)
    else:
        with pytest.raises(ValueError, match='fresh seal'):
            _flow(failed_case, client, tmp_path, monkeypatch, 1)
    assert state['heartbeat'] and state['writer_rechecks'] == 1
    assert len(calls) == (0 if drift == 'missing_capture' else 1)
    assert state['interpretations'] > 0
    record_property('representative_writer_seconds', state['elapsed'])
    record_property('heartbeat_interval_seconds', 30)
    assert state['elapsed'] < 30

from test_provider_keyed_mixed_zero_apply_inspector_negative import (
    case as zero_case,
    test_sql_job_receipt_survives_repository_restart as _negative_flow,
)
from app.services.provider_keyed_host_proof_verdicts import require_host_proof_verdict


@pytest.mark.parametrize('drift', ['none', 'plan', 'missing_capture'])
def test_actual_negative_finish_rechecks_without_commands_or_interpreter_under_writer(
        zero_case, tmp_path, monkeypatch, command, drift, record_property):
    run, calls, _, _, plan, _, raw_runner = command
    original = SqlAlchemyJobRepository.finish_mixed_inspector_negative_if_running
    state = dict(locked=False, checks=0, interpretations=0, started=None)

    def command_runner(*args, **kwargs):
        assert not state['locked'], 'command ran under writer'
        return raw_runner(*args, **kwargs)

    def pure():
        assert not state['locked']
        state['interpretations'] += 1

    def finish(self, *args, **kwargs):
        authority = kwargs['authority_check']
        def checked():
            authority()  # Every original SQL/source/lease check still executes.
            state['checks'] += 1
            if drift != 'missing_capture' or state['locked']:
                run(runner=command_runner)
            require_host_proof_verdict(b'capture', b'complete expected inputs', ('fixture-verifier',), pure)
        kwargs['authority_check'] = checked
        def boundary(conn, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('UPDATE JOB_RUNS SET STATUS = STATUS'):
                state['locked'] = True
                state['started'] = time.monotonic()
                if drift == 'plan':
                    plan.write_bytes(b'changed at writer boundary')
        event.listen(db.engine, 'before_cursor_execute', boundary)
        try:
            return original(self, *args, **kwargs)
        finally:
            if state['started']:
                record_property('negative_writer_seconds', time.monotonic() - state['started'])
            event.remove(db.engine, 'before_cursor_execute', boundary)
            state['locked'] = False
    monkeypatch.setattr(SqlAlchemyJobRepository, 'finish_mixed_inspector_negative_if_running', finish)
    if drift == 'none':
        _negative_flow(zero_case, monkeypatch, tmp_path, 'none')
    else:
        from app.services.provider_keyed_mixed_zero_apply_inspector_negative import MixedZeroApplyInspectorNegativeAttention
        with pytest.raises(MixedZeroApplyInspectorNegativeAttention):
            _negative_flow(zero_case, monkeypatch, tmp_path, 'none')
    assert state['checks'] == 2
    assert len(calls) == (0 if drift == 'missing_capture' else 1)
    assert state['interpretations'] == 1
