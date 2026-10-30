# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json
import subprocess

import pytest

from app.domain import JobEvent
from app.services import inference_proxy_status as status
from app.services import inference_proxy_capability as capability
from app.storage.job_repository import StoredJobRun


class Jobs:
    def __init__(self, jobs):
        self.jobs = {job.id: job for job in jobs}
    def get(self, job_id):
        return self.jobs.get(job_id)
    def save(self, job):
        self.jobs[job.id] = job
        return job
    def list_for_engagement(self, engagement_id):
        return list(reversed(list(self.jobs.values())))
    def list(self):
        return list(self.jobs.values())


class Leases:
    def __init__(self):
        self.acquired, self.released = [], []
    def acquire(self, *args):
        self.acquired.append(args)
        return True
    def release(self, *args):
        self.released.append(args)


@pytest.fixture
def env(tmp_path, monkeypatch):
    workspace = tmp_path / 'core'
    (workspace / 'ssh').mkdir(parents=True)
    (workspace / 'ssh/known_hosts').write_text('192.0.2.1 ssh-ed25519 AAAA\n')
    core = StoredJobRun('core-1', status.CORE_DEPLOYMENT_ACTION, 'succeeded', 'engagement:eng-1', 'engagement', 'eng-1', 'operator',
        {'engagementId': 'eng-1', 'resourceNames': {'homebase': 'homebase-abc', 'proxy01': 'proxy01-abc', 'vcn': 'vcn-abc'}, 'proxyCount': 1,
         'target': {'compartmentId': 'ocid1.compartment.oc1..core', 'region': 'us-phoenix-1'}, 'sketchStateSchema': 'split-v1'}, [], '2026-10-30T00:00:00Z', None, None,
        [JobEvent(1, 'info', 'deployed', {'workspaceDir': str(workspace), 'mutationStatus': 'deployed', 'connectionDetails': [
            {'role': 'homebase', 'displayName': 'homebase-abc', 'sshAlias': 'homebase-abc', 'publicIp': '192.0.2.1'}]})])
    saved = SimpleNamespace(metadata={capability.CONFIGURATION_KEY: {'region': 'us-chicago-1', 'compartmentId': 'ocid1.compartment.oc1..models', 'port': 8787},
        capability.SOURCE_KEY: {'revision': capability.SOURCE_REVISION, 'sha256': 'a'*64}, 'capabilityApplyState': {'selectionFingerprint': 'selected'}}, selected=True)
    monkeypatch.setattr(status, 'get_engagement', lambda _: {})
    monkeypatch.setattr(status, 'load_prepared_engagement_workspace', lambda *a, **k: saved)
    monkeypatch.setattr(status, 'capability_overrides_for_workspace', lambda w: {'selectedOptionals': [{'id': 'inference-proxy', 'hostClass': 'homebase'}] if w.selected else []})
    jobs, leases = Jobs([core]), Leases()
    kwargs = {'root': tmp_path, 'repository': jobs, 'workspace_repository': object()}
    return SimpleNamespace(saved=saved, jobs=jobs, leases=leases, kwargs=kwargs, trust=workspace/'ssh/known_hosts', core=core)


def payload(env, discovery='catalog_available'):
    return {'proof': True, 'identity': {'id': 'ocid1.instance.oc1.phx.abc', 'displayName': 'homebase-abc', 'compartmentId': 'ocid1.compartment.oc1..core', 'region': 'us-phoenix-1'},
        'health': {'status': 'ready', 'region': 'us-chicago-1',
            'upstream': {'status': discovery, 'inference_verified_by_health': False},
            'catalog': {'models': 4 if discovery == 'catalog_available' else 0, 'last_refresh': '2026-10-30T00:00:00+00:00' if discovery in {'catalog_available', 'no_eligible_models'} else None,
                'last_error': 'oci_authorization_required' if discovery == 'discovery_unavailable' else None}}}


def start(env, runner, background=None):
    current = status.get_inference_proxy_status('eng-1', **env.kwargs)
    return status.start_inference_proxy_status('eng-1', {'bindingFingerprint': current['bindingFingerprint']}, **env.kwargs,
        lease_repository=env.leases, runner=runner, background_runner=background or (lambda task: task()))


def test_split_v1_receipt_is_bound_and_never_verifies_inference(env):
    result = start(env, lambda *a: payload(env))
    assert result['status'] == 'checked'
    assert result['homebaseIdentity'] == {'coreDeploymentId': 'core-1', 'instanceId': 'ocid1.instance.oc1.phx.abc'}
    assert result['observation']['inferenceVerified'] is False
    assert result['observation']['modelCount'] == 4
    assert env.leases.acquired[0][2] == status.ACTION
    assert env.leases.released == [('eng-1', result['job']['id'])]
    assert 'homebaseIp' not in json.dumps(result)


@pytest.mark.parametrize('discovery', ['discovering', 'catalog_available', 'no_eligible_models', 'discovery_unavailable'])
def test_discovery_classifications(env, discovery):
    result = start(env, lambda *a: payload(env, discovery))
    assert result['status'] == 'checked'
    assert result['observation']['discoveryStatus'] == discovery
    assert result['observation']['inferenceVerified'] is False


@pytest.mark.parametrize('change', ['config', 'deselect', 'core', 'trust', 'cleanup'])
def test_queued_job_rejects_drift_before_ssh(env, change):
    tasks, calls = [], []
    start(env, lambda *a: calls.append(a), tasks.append)
    if change == 'config':
        env.saved.metadata[capability.CONFIGURATION_KEY]['port'] = 9000
    elif change == 'deselect':
        env.saved.selected = False
    elif change == 'trust':
        env.trust.write_text('changed\n')
    elif change == 'cleanup':
        env.jobs.save(replace(env.core, events=[*env.core.events, JobEvent(2, 'info', 'cleaned', {'finalCleanupStatus': 'verified_clean'})]))
    else:
        env.jobs.save(replace(env.core, id='core-2'))
    tasks[0]()
    assert not calls
    assert next(job for job in env.jobs.list() if job.action == status.ACTION).status == 'failed'
    current = status.get_inference_proxy_status('eng-1', **env.kwargs)
    assert current['observation'] is None and current['homebaseIdentity'] is None
    assert env.leases.released


def test_result_is_rejected_if_configuration_changes_during_probe(env):
    def run(*args):
        env.saved.metadata[capability.CONFIGURATION_KEY]['port'] = 9000
        return payload(env)
    start(env, run)
    assert next(job for job in env.jobs.list() if job.action == status.ACTION).status == 'failed'
    assert status.get_inference_proxy_status('eng-1', **env.kwargs)['status'] == 'not_checked'


@pytest.mark.parametrize('bad', ['scope', 'name', 'instance', 'region', 'error', 'verified', 'proof', 'count', 'timestamp'])
def test_invalid_payload_is_sanitized_and_not_retained(env, bad):
    receipt = payload(env)
    if bad in {'scope', 'name', 'instance', 'region'}:
        receipt['identity'][{'scope': 'compartmentId', 'name': 'displayName', 'instance': 'id', 'region': 'region'}[bad]] = 'SECRET-DO-NOT-RETAIN'
    elif bad == 'error':
        receipt['health']['catalog']['last_error'] = 'SECRET-DO-NOT-RETAIN'
    elif bad == 'verified':
        receipt['health']['upstream']['inference_verified_by_health'] = True
    elif bad == 'proof':
        receipt['proof'] = False
    elif bad == 'count':
        receipt['health']['catalog']['models'] = True
    else:
        receipt['health']['catalog']['last_refresh'] = 'SECRET-DO-NOT-RETAIN'
    result = start(env, lambda *a: receipt)
    assert result['status'] == 'failed' and result['observation'] is None
    assert 'SECRET-DO-NOT-RETAIN' not in json.dumps(result)


def test_stale_request_and_conflict_fail_without_scheduling(env):
    with pytest.raises(status.InferenceProxyStatusError):
        status.start_inference_proxy_status('eng-1', {'bindingFingerprint': 'stale'}, **env.kwargs, lease_repository=env.leases)
    env.jobs.save(replace(env.core, id='teardown', action='engagement_comprehensive_teardown', status='running'))
    with pytest.raises(status.InferenceProxyStatusError):
        start(env, lambda *a: pytest.fail('no SSH'))
    assert not env.leases.acquired


def test_legacy_missing_trust_or_ambiguous_identity_is_blocked(env):
    env.trust.unlink()
    assert status.get_inference_proxy_status('eng-1', **env.kwargs)['status'] == 'blocked'


def test_restart_recovers_and_releases_status_lease(env):
    start(env, lambda *a: pytest.fail('not run'), lambda task: None)
    status.recover_interrupted_inference_proxy_status(repository=env.jobs, lease_repository=env.leases)
    assert status.get_inference_proxy_status('eng-1', **env.kwargs)['status'] == 'failed'
    assert len(env.leases.released) == 1


def test_probe_is_fixed_bounded_and_read_only():
    compile(status.PROBE_SCRIPT, '<probe>', 'exec')
    assert '/opc/v2/instance/' in status.PROBE_SCRIPT and '/identity/' not in status.PROBE_SCRIPT
    assert '/health/ready' in status.PROBE_SCRIPT
    assert 'ProxyHandler({})' in status.PROBE_SCRIPT and 'NoRedirect' in status.PROBE_SCRIPT
    assert 'model-refresh' not in status.PROBE_SCRIPT and 'inference-proxy-admin' not in status.PROBE_SCRIPT


def test_status_routes_wrap_and_report_errors(client, monkeypatch):
    state = {'status': 'not_checked', 'bindingFingerprint': 'abc', 'homebaseIdentity': None, 'observation': None, 'job': None, 'errors': []}
    monkeypatch.setattr('app.asgi.get_inference_proxy_status', lambda *a, **k: state)
    monkeypatch.setattr('app.asgi.start_inference_proxy_status', lambda *a, **k: state)
    path = '/api/engagements/eng-1/capabilities/inference-proxy/status'
    assert client.get(path).get_json() == {'inferenceProxyStatus': state}
    response = client.post(path, json={'bindingFingerprint': 'abc'})
    assert response.status_code == 202 and response.get_json() == {'inferenceProxyStatus': state}
    def bad(*a, **k):
        raise status.InferenceProxyStatusError('reload and retry')
    monkeypatch.setattr('app.asgi.start_inference_proxy_status', bad)
    response = client.post(path, json={})
    assert response.status_code == 400 and response.get_json() == {'errors': ['reload and retry']}


def test_false_lease_does_not_schedule(env):
    env.leases.acquire = lambda *a: False
    with pytest.raises(status.InferenceProxyStatusError):
        start(env, lambda *a: pytest.fail('must not run'))
    assert not env.leases.released


def test_teardown_hides_previous_status(env):
    assert start(env, lambda *a: payload(env))['status'] == 'checked'
    env.jobs.save(replace(env.core, id='teardown', action='engagement_comprehensive_teardown', status='running'))
    current = status.get_inference_proxy_status('eng-1', **env.kwargs)
    assert current['status'] == 'blocked' and current['homebaseIdentity'] is None and current['observation'] is None


def test_exception_output_is_never_retained(env):
    def runner(*a):
        raise subprocess.TimeoutExpired(['SECRET-COMMAND'], 40, output='SECRET-STDOUT', stderr='SECRET-STDERR')
    result = start(env, runner)
    assert result['status'] == 'failed'
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('fault', [None, 'wrong_pid', 'wildcard', 'extra_listener', 'bad_config', 'bad_artifact', 'wrong_user'])
def test_real_probe_script_proves_listener_config_artifact_and_strips_metadata(env, monkeypatch, capsys, tmp_path, fault):
    import base64
    import hashlib
    import io
    import os
    import pwd
    import sys
    import urllib.request
    binding, _ = status._binding('eng-1', env.kwargs['root'], env.jobs, env.kwargs['workspace_repository'])
    opt = tmp_path / 'opt/inference-proxy'
    etc = tmp_path / 'etc/inference-proxy'
    opt.mkdir(parents=True)
    etc.mkdir(parents=True)
    archive = b'only committed source'
    digest = hashlib.sha256(archive).hexdigest()
    binding['source']['sha256'] = digest
    (opt / '.installed-artifact').write_text(('b'*64 if fault == 'bad_artifact' else digest) + '\n')
    (opt / ('source-' + digest + '.tar.gz')).write_bytes(archive)
    config = '[server]\nhost="127.0.0.1"\nport=8787\n[oci]\nregion="us-chicago-1"\ncompartment_id="ocid1.compartment.oc1..models"\nauth="instance_principal"\n'
    if fault == 'bad_config':
        config = config.replace('8787', '9000')
    (etc / 'config.toml').write_text(config)
    original_fstat = os.fstat
    def fstat(fd):
        actual = original_fstat(fd)
        return SimpleNamespace(st_mode=actual.st_mode, st_uid=0, st_nlink=actual.st_nlink, st_size=actual.st_size)
    monkeypatch.setattr(os, 'fstat', fstat)
    monkeypatch.setattr(pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=os.getuid()))
    pid = os.getpid()
    original_stat = os.stat
    def proc_stat(path, *args, **kwargs):
        if str(path) == "/proc/" + str(pid):
            return SimpleNamespace(st_uid=os.getuid())
        return original_stat(path, *args, **kwargs)
    monkeypatch.setattr(os, "stat", proc_stat)
    def run(command, **kwargs):
        if command[0] == 'systemctl' and command[-1] == '--value':
            out = str(pid) + '\n'
        elif command[0] == 'systemctl':
            out = f'MainPID={pid}\nUser={"other" if fault == "wrong_user" else "inference-proxy"}\nActiveState=active\nSubState=running\nExecStart={{ path={opt}/venv/bin/inference-proxy-server ; argv[]=x ; }}\nEnvironment=INFERENCE_PROXY_CONFIG={etc}/config.toml\n'
        else:
            assert command == ['ss', '-H', '-ltnp', 'sport = :8787']
            out = f'LISTEN 0 2048 {"0.0.0.0" if fault == "wildcard" else "127.0.0.1"}:8787 0.0.0.0:* users:(("python",pid={pid+1 if fault == "wrong_pid" else pid},fd=6))\n'
            if fault == 'extra_listener':
                out += out
        return subprocess.CompletedProcess(command, 0, stdout=out)
    monkeypatch.setattr(subprocess, 'run', run)
    calls = []
    class Opener:
        def open(self, request, timeout):
            calls.append((request.full_url, dict(request.header_items()), timeout))
            if request.full_url.startswith('http://169.254.169.254/'):
                data = {**payload(env)['identity'], 'region': 'phx', 'regionInfo': {'regionIdentifier': 'us-phoenix-1'}, 'metadata': {'user_data': 'SECRET-USER-DATA'}}
            else:
                data = payload(env)['health']
                data['unexpected'] = 'SECRET-HEALTH-FIELD'
            return io.BytesIO(json.dumps(data).encode())
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a: Opener())
    monkeypatch.setattr(sys, 'argv', ['-', base64.b64encode(json.dumps(binding).encode()).decode()])
    script = status.PROBE_SCRIPT.replace('/opt/inference-proxy', str(opt)).replace('/etc/inference-proxy', str(etc))
    if fault:
        with pytest.raises(AssertionError):
            exec(compile(script, '<probe-fixture>', 'exec'), {})
        assert not calls
    else:
        exec(compile(script, '<probe-fixture>', 'exec'), {})
        output = capsys.readouterr().out
        receipt = status._sanitize(json.loads(output), binding)
        assert receipt['observation']['localReady'] is True
        assert 'SECRET' not in output
        assert [row[0] for row in calls] == ['http://169.254.169.254/opc/v2/instance/', 'http://127.0.0.1:8787/health/ready']


@pytest.mark.parametrize('mode', ['success', 'overflow', 'timeout', 'exit_failure'])
def test_ssh_wrapper_bounds_output_deadline_and_pins_management_user(env, monkeypatch, mode):
    import sys
    binding, known_hosts = status._binding('eng-1', env.kwargs['root'], env.jobs, env.kwargs['workspace_repository'])
    real_popen = subprocess.Popen
    captured = []
    code = {'success': 'import sys; sys.stdin.read(); print("{\\\"proof\\\": true}")',
            'overflow': 'import sys; sys.stdin.read(); print("x" * 32768)',
            'timeout': 'import sys,time; sys.stdin.read(); time.sleep(10)',
            'exit_failure': 'import sys; sys.stdin.read(); sys.exit(1)'}[mode]
    def popen(command, **kwargs):
        captured.append(command)
        return real_popen([sys.executable, '-c', code], **kwargs)
    monkeypatch.setattr(status.subprocess, 'Popen', popen)
    monkeypatch.setattr(status, 'PROBE_TIMEOUT_SECONDS', .2)
    if mode == 'success':
        assert status._probe(binding, known_hosts) == {'proof': True}
    else:
        with pytest.raises((TimeoutError, ValueError)):
            status._probe(binding, known_hosts)
    command = captured[0]
    assert command[-2] == 'user@192.0.2.1'
    assert 'StrictHostKeyChecking=yes' in command
    assert 'GlobalKnownHostsFile=/dev/null' in command
    assert '-F' in command and '/dev/null' in command
    assert any(item.startswith('UserKnownHostsFile=') and known_hosts not in item for item in command)
    assert command[-1].startswith('sudo -n timeout --kill-after=2s 30s /opt/inference-proxy/venv/bin/python - ')
