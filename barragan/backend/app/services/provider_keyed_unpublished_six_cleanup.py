# Copyright (c) 2026, Oracle and/or its affiliates.
"""Cleanup authority for applied append providers whose host proof failed.

This never publishes chains or resumes host contact. Review binds immutable
failure/plan evidence; historical reopening does not read destroyed states.
"""
from dataclasses import asdict
from pathlib import Path
import hashlib
import re

from app.services.provider_keyed_mixed_append_first_proof_job import _process_quiescent
from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id, ACTION
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read
from app.services.provider_keyed_mixed_initial_host_binding import _digest

SOURCE_KIND = 'unpublished-six-node-cleanup-v1'


def require_failed_host(source, append, host, *, process_quiescent=_process_quiescent):
    if (host is None or host.id != _child_id(append.id) or host.action != ACTION
            or host.status != 'failed' or host.started_at is None or host.finished_at is None
            or host.target_id != source.engagement_id or host.target != append.target
            or host.target_type != 'engagement' or host.requested_by != append.requested_by
            or host.input.get('parentJobId') != append.id or host.input.get('mutation') is not True
            or host.input.get('sourceSha256') != source.source_sha256
            or not host.input.get('claimOwner') or not host.input.get('claimToken')
            or any(host.input.get(key) != append.input.get(key) for key in ('claimOwner', 'claimToken'))
            or host.artifact_refs or len(host.events) < 3):
        raise ValueError('unpublished cleanup requires exact failed host child')
    rows = host.events
    if ([(row.sequence, row.level) for row in rows] != [
            (i, 'error' if i == len(rows) else 'info') for i in range(1, len(rows)+1)]
            or [(row.message, row.data) for row in rows[:2]] != [
                ('mixed append host proof reserved', {'sourceSha256': source.source_sha256}),
                ('mixed append host proof started', {'sourceSha256': source.source_sha256})]
            or rows[-1].message != 'mixed append host proof stopped; reconciliation required'
            or rows[-1].data != {}):
        raise ValueError('unpublished failed host journal differs')
    from app.services.provider_keyed_mixed_append_pair_host_proof import _PHASES, _recognize_commands
    from app.services.provider_keyed_mixed_initial_plan_parent import job_event_digest
    at, seen = 2, set()
    for index, provider in enumerate(source.provider_order):
        edge = source.chains[index].nodes[2]['terraformAddress']
        chain = source.chains[index].chain_id
        for message, data in (
            ('mixed append edge bootstrap intended', {'provider':provider, 'chainId':chain, 'edgeAddress':edge}),
            ('mixed append edge first contact fenced', {'provider':provider})):
            if rows[at].message != message or rows[at].data != data:
                raise ValueError('unpublished host bootstrap boundary differs')
            at += 1
        for phase, _ in _PHASES:
            at = _recognize_commands(rows, at, provider, phase, 'bootstrap', seen)
        if (rows[at].message != 'mixed append edge bootstrap completed'
                or rows[at].data != {'provider':provider, 'edgeAddress':edge,
                    'bootstrapJournalSha256':job_event_digest(rows[:at])}):
            raise ValueError('unpublished host bootstrap receipt differs')
        at += 1
        if (rows[at].message != 'mixed append edge raw proof intended'
                or rows[at].data != {'provider':provider, 'edgeAddress':edge}):
            raise ValueError('unpublished host raw boundary differs')
        at += 1
        if (rows[at].message != 'mixed append edge raw scratch intended'
                or rows[at].data.get('provider') != provider):
            raise ValueError('unpublished host scratch boundary differs')
        at += 1
        for phase in ('metadata', 'firewall_before', 'surface', 'firewall_after'):
            at = _recognize_commands(rows, at, provider, phase, 'probe', seen)
        if index == 0:
            if (rows[at].message != 'mixed append edge raw proof captured'
                    or rows[at].data.get('provider') != provider
                    or rows[at].data.get('edgeAddress') != edge
                    or re.fullmatch('[0-9a-f]{64}', str(rows[at].data.get('rawProbeSha256'))) is None):
                raise ValueError('unpublished first raw capture differs')
            at += 1
    if at != len(rows)-1:
        raise ValueError('unpublished cleanup requires failed final raw acceptance')
    for row in rows:
        if row.message.endswith('command started before GO'):
            data = row.data
            if (type(data.get('bootId')) is not str or not data['bootId']
                    or any(type(data.get(k)) is not int or data[k] <= 0 for k in ('pid','pgid','startTicks'))
                    or (process_quiescent is not None and process_quiescent(
                        data['bootId'], data['pid'], data['pgid'], data['startTicks']) is not True)):
                raise ValueError('unpublished host contact is not quiescent')
    return _digest(asdict(host))


def recovery_evidence(source, append, host, children, *, fresh=False):
    failed = require_failed_host(source, append, host, process_quiescent=_process_quiescent if fresh else None)
    artifacts = {}
    for index, provider in enumerate(source.provider_order):
        root = Path(source.workspace_paths[index])
        for suffix in ('plan-receipt.json', 'inputs.json', 'predecessor.tfstate', 'saved.tfplan', 'show.json', 'plan-journal.jsonl'):
            path = root / _name(provider, suffix)
            artifacts[str(path)] = hashlib.sha256(_read(path)).hexdigest()
        for suffix in ('.barragan-topology.json', '.terraform.lock.hcl', '.barragan-provider-keyed-state.json'):
            path = root / suffix
            artifacts[str(path)] = hashlib.sha256(_read(path, private=False)).hexdigest()
    return dict(schema=SOURCE_KIND, sourceSha256=source.source_sha256,
        failedHostSha256=failed, appendSha256=_digest(asdict(append)),
        providerChildrenSha256={p: _digest(asdict(c)) for p, c in children.items()}, artifacts=artifacts)


def historical_review(review, *, jobs, plans, sketches):
    from app.services.provider_keyed_mixed_published_six_source import derive_mixed_published_six_policies, same_published_chain
    from app.services.provider_keyed_mixed_published_six_journal import validate_mixed_published_six_journals
    from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_id
    from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_id
    from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
    from app.services.provider_keyed_mixed_append_pair_parent import _plan_child_id
    source = review.source.six_node_source
    append, initial = jobs.get(source.parent_id), jobs.get(review.source.parent_job_id)
    host = jobs.get(_child_id(append.id))
    children = dict(zip(source.provider_order, (jobs.get(first_id(append.id)), jobs.get(second_id(append.id)))))
    rows = reviewed_mixed_chain_rows(sketches.list_for_engagement(source.engagement_id), source.chain_ids, source.engagement_id)
    if ({r.chain_id for r in rows} != set(source.chain_ids)
            or any(not same_published_chain(row, next(c for c in source.before_chains if c.chain_id == row.chain_id)) for row in rows)
            or recovery_evidence(source, append, host, children) != review.unpublished_six_recovery
            or derive_mixed_published_six_policies(source, append, initial, unpublished_cleanup=True) != review.reviewed_policies):
        raise ValueError('unpublished cleanup immutable source changed')
    validate_mixed_published_six_journals(source, append, children, unpublished_cleanup=True)
    from app.services.provider_keyed_mixed_initial_apply_child import _child_id as initial_child_id
    from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
    from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
    from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_id
    initial_rows = [jobs.get(initial_child_id(source.core_job_id, p)) for p in source.provider_order]
    initial_rows += [jobs.get(f(source.core_job_id)) for f in (_binding_child_id, _worker_id, proof_id)]
    core, plan = jobs.get(source.core_job_id), plans.get(source.core_plan_id)
    return _digest(dict(source=asdict(source), recovery=review.unpublished_six_recovery,
        appendPlan=asdict(jobs.get(_plan_child_id(append.id))) if jobs.get(_plan_child_id(append.id)) is not None else None, initial=asdict(initial), initialRows=[asdict(r) if r is not None else None for r in initial_rows], core=asdict(core), plan={k:v for k,v in asdict(plan).items()
            if k not in {'created_at', 'updated_at', 'prepared_at'}}))
