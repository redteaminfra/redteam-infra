# Copyright (c) 2026, Oracle and/or its affiliates.
"""Cleanup-only observation of one failed ingress Apply, never publication/retry.

Preview reads saved evidence and current state. The normal teardown writer
accepts its hash-only observation; historical readers reopen immutable evidence
without requiring a provider state that teardown has since emptied.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
import fcntl
from hashlib import sha256
import json
import os
import re
from pathlib import Path
import stat
import subprocess

from app.core.command_environment import barragan_subprocess_env
from app.services.provider_keyed_channel_generation import (
    ChannelGeneration, EVENT, read_channel_generation, require_channel_host_proof,
)
from app.services.provider_keyed_core_destroy_preview import _terraform_quiescent
from app.services.provider_keyed_ingress_update import (
    KeyedIngressUpdate, _audit, _credential, _digest, _gate, _paths,
    _require_local_applied_state, _require_noop_state, _state_envelope, _sha,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import job_event_digest
from app.services.provider_keyed_readonly_verification import run_readonly_verification


HOST_EVENT = 'keyed channel isolated host policy proved'
SCHEMA = 'keyed-ingress-cleanup-observation-v1'


def _show(command, root, environment):
    return run_readonly_verification(command, cwd=root, env=dict(environment),
                          capture_output=True, text=True, check=False, timeout=60,
                          runner=subprocess.run)


@contextmanager
def _locks(workspaces):
    with ExitStack() as stack:
        for provider in sorted(workspaces):
            path = workspaces[provider].path / '.barragan-ingress.lock'
            # A provider with no ingress attempt has no ingress lock yet.
            if not path.exists() and not path.is_symlink():
                continue
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            stream = stack.enter_context(os.fdopen(descriptor, 'r+b'))
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('cleanup ingress lock is unsafe')
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def read_cleanup_channel_generation(source, append, initial, jobs, *, workspaces,
        saved_observation=None, require_current_state=True, credential_repository=None,
        release_validator=require_devtest_terraform_release, show_runner=_show,
        quiescence_check=_terraform_quiescent):
    """Return an observed generation ONLY for the existing teardown coordinator."""
    baseline = read_channel_generation(source, append, initial, jobs, require_current_state=False)
    hashes = dict(zip(source.provider_order, baseline.state_sha256s))
    if saved_observation is None and all(_sha(workspaces[p].state_path) == hashes[p]
                                         for p in source.provider_order):
        return baseline, None
    if not require_current_state and saved_observation is None:
        return baseline, None
    if require_current_state:
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        if _db_lease_lookup(source.engagement_id) not in {None, (source.core_plan_id, 'provider_keyed_teardown_fence')}:
            raise ValueError('cleanup ingress mutation lease is not retired')
    if require_current_state and quiescence_check() is not True:
        raise ValueError('cleanup ingress Terraform process may still run')
    # Locks are held across all current reads and the read-only saved-plan show.
    with _locks(workspaces) if require_current_state else ExitStack():
        try:
            return _observe(source, append, initial, jobs, baseline, workspaces,
                saved_observation, require_current_state,
                credential_repository or SqlAlchemyCredentialRepository(), release_validator,
                show_runner, quiescence_check)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('cleanup ingress evidence schema differs') from exc


def _observe(source, append, initial, jobs, baseline, workspaces, saved, current,
             credentials, release_validator, show_runner, quiescence_check):
    from app.services.provider_keyed_channel_apply import _topology
    from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent, render_keyed_route_projection
    hashes = dict(zip(source.provider_order, baseline.state_sha256s))
    candidates = []
    for job in jobs.list_for_engagement(source.engagement_id):
        if job.action != 'inbound_channel_apply':
            continue
        if re.fullmatch(r'job-[a-z0-9-]{1,76}', job.id) is None:
            raise ValueError('cleanup ingress job identity is invalid')
        for provider, workspace in workspaces.items():
            path = workspace.path / f'.barragan-ingress-{job.id}-status.json'
            if not path.exists() and not path.is_symlink():
                continue
            status = json.loads(_read(path))
            if status.get('phase') in {'apply_intent', 'apply_result'}:
                candidates.append((job, provider, status))
    if len(candidates) != 1:
        raise ValueError('cleanup requires one exact uncertain ingress attempt')
    job, provider, status = candidates[0]
    if (job.status != 'failed' or job.finished_at is None or job.started_at is None
            or job.target_id != source.engagement_id or job.target_type != 'engagement'
            or job.input.get('engagementId') != source.engagement_id
            or any(e.message == EVENT and e.data.get('provider') == provider for e in job.events)):
        raise ValueError('cleanup ingress job is not terminal and unpromoted')
    host_events = [e for e in job.events if e.message == HOST_EVENT]
    if len(host_events) != 1 or host_events[0].data.get('sourceSha256') != source.source_sha256:
        raise ValueError('cleanup ingress host proof is absent')
    host = host_events[0].data
    routes = tuple(KeyedRouteIntent(**{**r, 'public_sources': tuple(r['public_sources'])}) for r in host['routes'])
    if (host['hostProof'].get('path') != str(Path(source.workspace_paths[0]) /
            f'.barragan-channel-{job.id}-after.json')
            or len({r.channel_id for r in routes}) != len(routes)
            or sum(r.channel_id == job.input.get('channelId') for r in routes) != 1):
        raise ValueError('cleanup ingress route or proof identity differs')
    require_channel_host_proof(source, host['hostProof'], routes)
    topology, providers = _topology(source)
    projection = render_keyed_route_projection(topology, providers, routes)
    workspace = workspaces[provider]
    prefix = workspace.path / f'.barragan-ingress-{job.id}'
    before_raw = _read(Path(f'{prefix}-before.tfstate'))
    inputs_path = Path(f'{prefix}-inputs.json')
    inputs_raw = _read(inputs_path)
    inputs = json.loads(inputs_raw)
    before = json.loads(before_raw)
    policy = baseline.policies[provider]
    if ({k: v for k, v in inputs.items() if k not in {'allowed_tcp_ports', 'allowed_udp_ports'}}
            != {k: v for k, v in policy['nonsecret_varfile'].items() if k not in {'allowed_tcp_ports', 'allowed_udp_ports'}}):
        raise ValueError('cleanup ingress changed unrelated inputs')
    addresses = tuple(sorted(policy['nodes']))
    ports = {address: tuple(sorted({(rule['proto'], rule['port'])
        for rule in projection.host_policies[address]['sketch_firewall_v2_rules']
        if rule['port'] not in {80, 443, 2222}})) for address in addresses}
    v2 = status.get('schema') == 'keyed-ingress-update-v2'
    predecessor = baseline.receipt_heads[provider] if v2 else None
    if not v2 and any(row.get('provider') == provider and 'predecessorReceiptSha256' in row
                      for row in baseline.advances):
        raise ValueError('cleanup ingress receipt version downgraded')
    if v2 and status.get('predecessorReceiptSha256') != predecessor:
        raise ValueError('cleanup ingress predecessor receipt differs')
    update = KeyedIngressUpdate(workspace, job.id, job.input['channelId'], _state_resources(before),
        baseline.provider_routes[provider], projection.provider_routes[provider], addresses, ports,
        policy['nonsecret_varfile'], inputs, baseline.input_paths[provider],
        _sha(baseline.input_paths[provider]), hashes[provider],
        _digest(json.loads(_read(workspace.path / '.barragan-topology.json', private=False))),
        predecessor_receipt_sha256=predecessor)
    status_path, _, _, plan_path = _paths(update)
    release = release_validator(environment='devtest')
    _audit(workspace)
    credential_sha, updated, token = _credential(workspace, credentials)
    receipt = json.loads(_read(workspace.path / _name(provider, 'plan-receipt.json')))
    expected = dict(schema='keyed-ingress-update-v1', jobId=job.id, provider=provider,
        connectionId=policy['provider_connection_id'], sourceRevision=workspace.source_revision,
        sourceSha256=receipt['sourceSha256'], stateSha256=hashes[provider],
        topologySha256=update.topology_sha256, retainedInputSha256=update.retained_input_sha256,
        reviewedInputSha256=_digest(inputs), routeSha256=_digest({
            'prior': [vars(r) for r in update.prior_routes], 'next': [vars(r) for r in update.next_routes],
            'selected': update.selected_channel_id, 'hosts': ports}), credentialSha256=credential_sha,
        credentialUpdatedAt=updated, terraformSha256=release.sha256,
        lockfileSha256=_sha(workspace.path / '.terraform.lock.hcl'))
    if v2:
        expected.update(schema='keyed-ingress-update-v2', predecessorReceiptSha256=predecessor)
    extras = {'phase', 'planSha256', 'showSha256'} | (
        {'returnCode', 'postStateSha256'} if status.get('phase') == 'apply_result' else set())
    if (set(status) != set(expected) | extras or any(status.get(k) != v for k, v in expected.items())
            or credential_sha != policy['credential_secret_sha256']
            or updated != policy['credential_updated_at']
            or _sha(release.path) != release.sha256 or release.version != '1.15.5'
            or status.get('planSha256') != sha256(_read(plan_path)).hexdigest()
            or sha256(before_raw).hexdigest() != hashes[provider]
            or (status['phase'] == 'apply_result' and (type(status.get('returnCode')) is not int or status.get('returnCode') != 0))):
        raise ValueError('cleanup ingress retained plan identity differs')
    after_path = Path(f'{prefix}-after.tfstate')
    if status['phase'] == 'apply_result' and sha256(_read(after_path)).hexdigest() != status['postStateSha256']:
        raise ValueError('cleanup ingress saved result state differs')
    artifacts = {str(path): _sha(path) for path in (status_path, inputs_path, plan_path,
        Path(f'{prefix}-before.tfstate'), baseline.input_paths[provider],
        Path(host['hostProof']['path']), workspace.path / '.barragan-topology.json',
        workspace.path / '.terraform.lock.hcl', release.path)}
    if status['phase'] == 'apply_result':
        artifacts[str(after_path)] = _sha(after_path)
    shown = show_runner([str(release.path), 'show', '-json', str(plan_path)], workspace.path,
        {**barragan_subprocess_env(), 'TF_DATA_DIR': str(workspace.terraform_data_dir),
         'TF_CLI_CONFIG_FILE': '/dev/null'})
    if shown.returncode != 0 or sha256(shown.stdout.encode()).hexdigest() != status['showSha256']:
        raise ValueError('cleanup ingress saved binary show differs')
    _gate(shown.stdout, update, token, provider)
    firewall = f'{provider}_firewall.firewall'
    noop = next(row['change']['actions'] for row in json.loads(shown.stdout)['resource_changes']
                if row['address'] == firewall) == ['no-op']
    if noop and not v2:
        raise ValueError('cleanup no-op requires an anchored v2 receipt')
    observed = saved
    if current:
        raw = _read(workspace.state_path, private=False)
        if _require_local_applied_state(update, shown.stdout) != sha256(raw).hexdigest():
            raise ValueError('cleanup ingress current state changed')
        after = json.loads(raw)
        if noop:
            _require_noop_state(before_raw, raw)
        if (before.get('lineage') != after.get('lineage')
                or type(after.get('serial')) is not int or after['serial'] <= before['serial']
                or _state_envelope(before) != _state_envelope(after)
                or (noop and after['serial'] != before['serial'] + 1)
                or (status['phase'] == 'apply_result' and status['postStateSha256'] != sha256(raw).hexdigest())):
            raise ValueError('cleanup ingress state envelope differs')
        observed = dict(schema=SCHEMA, jobId=job.id, provider=provider,
            sourceSha256=source.source_sha256, stateSha256=sha256(raw).hexdigest(),
            lineage=after['lineage'], serial=after['serial'],
            resourceProjectionSha256=_digest(_state_resources(after)),
            artifactSha256=artifacts, jobSha256=_digest(asdict(job)))
    if (type(observed) is not dict or set(observed) != {
            'schema', 'jobId', 'provider', 'sourceSha256', 'stateSha256', 'lineage', 'serial',
            'resourceProjectionSha256', 'artifactSha256', 'jobSha256', 'evidenceSha256'} - ({'evidenceSha256'} if current else set())
            or observed.get('schema') != SCHEMA or observed.get('jobId') != job.id
            or observed.get('provider') != provider or observed.get('sourceSha256') != source.source_sha256
            or observed.get('artifactSha256') != artifacts or observed.get('jobSha256') != _digest(asdict(job))
            or observed.get('lineage') != before.get('lineage')
            or type(observed.get('serial')) is not int or observed['serial'] <= before['serial']
            or (noop and observed['serial'] != before['serial'] + 1)
            or any(re.fullmatch(r'[a-f0-9]{64}', observed.get(key, '')) is None
                   for key in ('stateSha256', 'resourceProjectionSha256'))):
        raise ValueError('cleanup ingress observation differs')
    evidence = _digest(dict(job=asdict(job), initial=job_event_digest(initial.events),
        append=job_event_digest(append.events), before=sha256(before_raw).hexdigest(),
        inputs=sha256(inputs_raw).hexdigest(), status=_sha(status_path), plan=_sha(plan_path),
        show=sha256(shown.stdout.encode()).hexdigest(), hostProof=host['hostProof'],
        observation={k: v for k, v in observed.items() if k != 'evidenceSha256'}))
    result = {**observed, 'evidenceSha256': evidence}
    if saved is not None and result != saved:
        raise ValueError('cleanup ingress saved observation changed')
    require_cleanup_observation_unchanged(result, jobs)
    if current and (quiescence_check() is not True or jobs.get(job.id) != job
            or _sha(workspace.state_path) != result['stateSha256']):
        raise ValueError('cleanup ingress source changed during observation')
    hashes[provider] = result['stateSha256']
    policies = {**baseline.policies, provider: {**policy, 'nonsecret_varfile': inputs}}
    paths = {**baseline.input_paths, provider: inputs_path}
    provider_routes = {**baseline.provider_routes, provider: projection.provider_routes[provider]}
    return ChannelGeneration(tuple(hashes[p] for p in source.provider_order), policies, paths,
        (*baseline.advances, {'cleanupObservationSha256': _digest(result)}), provider_routes, baseline.receipt_heads), result


def require_cleanup_observation_unchanged(observation, jobs):
    """Local-only fence: no Terraform command, provider request or file write."""
    if (_digest(asdict(jobs.get(observation['jobId']))) != observation['jobSha256']
            or any(_sha(Path(path)) != digest for path, digest in observation['artifactSha256'].items())):
        raise ValueError('cleanup ingress immutable evidence changed')
