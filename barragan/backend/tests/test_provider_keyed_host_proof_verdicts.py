# Copyright (c) 2026, Oracle and/or its affiliates.
"""Operation-local pure verdict reuse; authority and artifact reads stay fresh."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

import pytest

from app.services import provider_keyed_channel_generation as generation
from app.services.provider_keyed_host_proof_verdicts import (
    host_proof_verdict_scope, require_host_proof_verdict,
)
from test_provider_keyed_channel_generation import case, _advance, _real_host_proof


def _proof(case, monkeypatch):
    job, _, routes = _advance(case)
    path, job = _real_host_proof(case, job, routes, monkeypatch)
    proof = job.events[0].data['hostProof']
    return path, proof, routes


def test_41_fences_read_all_bytes_but_interpret_each_capture_once(case, monkeypatch):
    path, proof, routes = _proof(case, monkeypatch)
    reads, verified = [], []
    original_read, original_verify = generation._read, generation._verify_channel_host_proof
    def read(path, **options):
        reads.append(Path(path))
        return original_read(path, **options)
    def verify(raw, expected):
        verified.append((raw, expected))
        return original_verify(raw, expected)
    monkeypatch.setattr(generation, '_read', read)
    monkeypatch.setattr(generation, '_verify_channel_host_proof', verify)
    with host_proof_verdict_scope() as memo:
        generation.require_channel_host_proof(case['source'], proof, routes)
        memo.require_hits_only()
        for _ in range(40):
            generation.require_channel_host_proof(case['source'], proof, routes)
    assert len(verified) == 1
    assert reads.count(path) == 41
    assert len(reads) == 41 * 7  # proof plus all six trust-file reads, every time
    # A separate operation must interpret again, not borrow the prior verdict.
    with host_proof_verdict_scope():
        generation.require_channel_host_proof(case['source'], proof, routes)
    assert len(verified) == 2


@pytest.mark.parametrize('drift', ['raw_same_length', 'known_hosts', 'route', 'source',
                                  'policy_bool_int', 'verifier', 'mode', 'symlink'])
def test_hit_only_rejects_every_changed_consumed_input(case, monkeypatch, drift):
    path, proof, routes = _proof(case, monkeypatch)
    original_verify = generation._verify_channel_host_proof
    calls = []
    def verify(*args):
        calls.append(True)
        return original_verify(*args)
    monkeypatch.setattr(generation, '_verify_channel_host_proof', verify)
    source = case['source']
    with host_proof_verdict_scope() as memo:
        generation.require_channel_host_proof(source, proof, routes)
        memo.require_hits_only()
        if drift == 'raw_same_length':
            before = path.read_bytes()
            after = before.replace(b' ', b'\n', 1)
            assert len(after) == len(before) and json.loads(after) == json.loads(before)
            path.write_bytes(after)
            proof = {**proof, 'sha256': sha256(after).hexdigest()}
        elif drift == 'known_hosts':
            known = Path(source.workspace_paths[0]) / '.barragan-sketch-known-hosts'
            before = known.read_bytes()
            known.write_bytes(b'X' + before[1:])
        elif drift == 'route':
            routes = (replace(routes[0], external_port=routes[0].external_port + 1),)
        elif drift == 'source':
            source = replace(source, core_known_hosts_sha256='f' * 64)
        elif drift == 'policy_bool_int':
            from app.services import provider_keyed_ingress_route_ledger as ledger
            from copy import deepcopy
            original = ledger.render_keyed_route_projection
            def changed(*args):
                result = original(*args)
                policies = deepcopy(result.host_policies)
                first = next(iter(policies.values()))
                first['sketch_firewall_v2_enabled'] = 1
                return replace(result, host_policies=policies)
            monkeypatch.setattr(ledger, 'render_keyed_route_projection', changed)
        elif drift == 'verifier':
            monkeypatch.setattr(generation, '_verify_channel_host_proof', lambda *a: None)
        elif drift == 'mode':
            path.chmod(0o644)
        else:
            saved = path.with_suffix('.saved')
            path.rename(saved)
            path.symlink_to(saved)
        with pytest.raises(ValueError):
            generation.require_channel_host_proof(source, proof, routes)
        assert len(calls) == 1  # never reinterpret a changed key after sealing


@pytest.mark.parametrize('exception', [RuntimeError, asyncio.CancelledError])
def test_failed_verification_never_primes_and_exception_clears_scope(exception):
    calls = []
    def fail():
        calls.append(True)
        raise ValueError('invalid capture')
    with pytest.raises(exception):
        with host_proof_verdict_scope() as memo:
            for _ in range(2):
                with pytest.raises(ValueError):
                    require_host_proof_verdict(b'bad', b'expected', ('v1',), fail)
            memo.require_hits_only()
            with pytest.raises(ValueError, match='after priming'):
                require_host_proof_verdict(b'bad', b'expected', ('v1',), fail)
            raise exception('cancel operation')
    assert len(calls) == 2
    with host_proof_verdict_scope():
        with pytest.raises(ValueError, match='invalid capture'):
            require_host_proof_verdict(b'bad', b'expected', ('v1',), fail)
    assert len(calls) == 3


def test_nested_scope_preserves_hits_only_and_thread_task_isolation():
    calls = []
    def verify(): calls.append(True)
    def run():
        with host_proof_verdict_scope() as memo:
            require_host_proof_verdict(b'raw', b'expected', ('v1',), verify)
            memo.require_hits_only()
            with host_proof_verdict_scope() as nested:
                assert nested is memo
                require_host_proof_verdict(b'raw', b'expected', ('v1',), verify)
    with host_proof_verdict_scope() as outer:
        require_host_proof_verdict(b'raw', b'expected', ('v1',), verify)
        outer.require_hits_only()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(run).result()
        async def tasks():
            # These tasks inherit the ContextVar, but must create their own memo.
            async def task(): run()
            await asyncio.gather(task(), task())
        asyncio.run(tasks())
    assert len(calls) == 4


def test_writer_hit_and_miss_never_execute_interpreter_after_outside_prime(case, monkeypatch, tmp_path):
    _, proof, routes = _proof(case, monkeypatch)
    writer = sqlite3.connect(tmp_path / 'writer.sqlite')
    other = sqlite3.connect(tmp_path / 'writer.sqlite', timeout=0.01)
    writer.execute('create table heartbeat (value int)'); writer.commit()
    original = generation._verify_channel_host_proof
    def verify(raw, expected):
        # An independent connection can write during expensive outside priming.
        other.execute('insert into heartbeat values (1)'); other.commit()
        return original(raw, expected)
    monkeypatch.setattr(generation, '_verify_channel_host_proof', verify)
    try:
        with host_proof_verdict_scope() as memo:
            generation.require_channel_host_proof(case['source'], proof, routes)
            memo.require_hits_only()
            writer.execute('begin immediate')
            generation.require_channel_host_proof(case['source'], proof, routes)
            changed = replace(case['source'], core_known_hosts_sha256='f' * 64)
            with pytest.raises(ValueError, match='after priming'):
                generation.require_channel_host_proof(changed, proof, routes)
            writer.rollback()
        assert writer.execute('select count(*) from heartbeat').fetchone() == (1,)
    finally:
        writer.close(); other.close()


def test_malformed_raw_capture_never_becomes_a_success(case, monkeypatch):
    path, proof, routes = _proof(case, monkeypatch)
    value = json.loads(path.read_bytes())
    value['captures'][0]['unexpected_field'] = True
    path.write_text(json.dumps(value))
    proof = {**proof, 'sha256': sha256(path.read_bytes()).hexdigest()}
    original, calls = generation._verify_channel_host_proof, []
    def verify(*args):
        calls.append(True)
        return original(*args)
    monkeypatch.setattr(generation, '_verify_channel_host_proof', verify)
    with host_proof_verdict_scope() as memo:
        for _ in range(2):
            with pytest.raises(ValueError):
                generation.require_channel_host_proof(case['source'], proof, routes)
        memo.require_hits_only()
        with pytest.raises(ValueError, match='after priming'):
            generation.require_channel_host_proof(case['source'], proof, routes)
    assert len(calls) == 2


def test_restored_expected_inputs_cannot_borrow_transient_verification():
    # Validator consumes immutable B bytes. Restoring A after that validation
    # cannot turn its result into authority for A (endpoint ABA shortcut).
    calls = []
    with host_proof_verdict_scope() as memo:
        require_host_proof_verdict(b'capture-B', b'policy-B', ('schema',), lambda: calls.append(True))
        memo.require_hits_only()
        for raw, expected in [(b'capture-A', b'policy-B'), (b'capture-B', b'policy-A'),
                              (b'capture-B', b'{"enabled":true}'), (b'capture-B', b'{"enabled":1}')]:
            with pytest.raises(ValueError, match='after priming'):
                require_host_proof_verdict(raw, expected, ('schema',), lambda: calls.append(True))
    assert len(calls) == 1


def test_direct_inherited_scope_cannot_compute_in_foreign_thread_or_task():
    from contextvars import copy_context
    calls = []
    def verify(): calls.append(True)
    def inherited():
        with pytest.raises(ValueError, match='another execution'):
            require_host_proof_verdict(b'raw', b'expected', ('schema',), verify)
    with host_proof_verdict_scope() as memo:
        require_host_proof_verdict(b'raw', b'expected', ('schema',), verify)
        memo.require_hits_only()
        context = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(context.run, inherited).result()
        async def tasks():
            async def child(): inherited()
            await asyncio.create_task(child())
        asyncio.run(tasks())
    assert len(calls) == 1
