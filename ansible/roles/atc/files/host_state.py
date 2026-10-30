#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: Apache-2.0
"""Read-only convergence assessment. Never emit state, credentials or journals."""
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request

MARKERS = ('restore-intent.json', 'restore-journal.json', 'upgrade-intent.json',
           'upgrade-journal.json', 'upgrade-staging.json', 'fresh-access.pending')


def command(argv, *, allowed=(0,)):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, timeout=15, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'PYTHONDONTWRITEBYTECODE': '1'})
    if result.returncode not in allowed or len(result.stdout) > 65536:
        raise ValueError('required local command did not pass its bounded check')
    return result.stdout


def protected(path, *, directory=False, mode=None, missing=False, owner=0):
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise ValueError('ATC path must be absolute, normalized and free of symlinks')
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing:
            return False
        raise ValueError('required protected ATC path is missing') from None
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ValueError('ATC path has unsafe type, owner or permissions')
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise ValueError('ATC path has unexpected permissions')
    if not directory and info.st_nlink != 1:
        raise ValueError('ATC state must not use hard links')
    return True


def read_pairs(path, mode=0o600):
    protected(path, mode=mode)
    if Path(path).stat().st_size > 32768:
        raise ValueError('ATC installation state exceeds bounds')
    result = {}
    for line in Path(path).read_text().splitlines():
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*=[^\r\n]*', line):
            raise ValueError('ATC installation state is malformed')
        key, value = line.split('=', 1)
        if key in result:
            raise ValueError('ATC installation state contains duplicate keys')
        result[key] = value
    return result


def validate_configuration(config):
    required = {'root', 'python', 'port', 'operatorUser', 'engagementId', 'codename',
                'engagementStatus', 'operatorId', 'operatorName', 'version', 'revision',
                'sha256', 'postgresImage', 'migrationLevel'}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError('explicit ATC release and bootstrap settings are required')
    for name in required - {'port'}:
        if not isinstance(config[name], str) or not config[name] or any(c in config[name] for c in '\r\n\x00') or config[name] != config[name].strip():
            raise ValueError('ATC settings must be nonempty single-line strings without surrounding whitespace')
    if not re.fullmatch(r'/(?:opt|srv)/[A-Za-z0-9][A-Za-z0-9_./-]*', config['root']) or str(Path(config['root'])) != config['root'] or '..' in Path(config['root']).parts:
        raise ValueError('ATC root must be a normalized installation directory beneath /opt or /srv')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', config['python']) or '..' in Path(config['python']).parts:
        raise ValueError('ATC Python must be an absolute executable path')
    if type(config['port']) is not int or not 1024 <= config['port'] <= 65535 or config['port'] in {15432, 17474, 17687}:
        raise ValueError('ATC API requires an unprivileged non-datastore port')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', config['operatorUser']):
        raise ValueError('ATC operator OS user is invalid')
    for key in ('engagementId', 'operatorId'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', config[key]):
            raise ValueError('ATC engagement and operator IDs are invalid')
    for key in ('codename', 'operatorName'):
        if len(config[key]) > 128:
            raise ValueError('ATC display names exceed bounds')
    if config['engagementStatus'] not in {'planning', 'active', 'paused', 'closed'}:
        raise ValueError('ATC engagement status is invalid')
    for key, count in (('revision', 40), ('sha256', 64), ('migrationLevel', 64)):
        if not re.fullmatch('[0-9a-f]{' + str(count) + '}', config[key]):
            raise ValueError('ATC release identity is incomplete')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[._+-][A-Za-z0-9.-]+)?', config['version']):
        raise ValueError('ATC release version is invalid')
    if not re.fullmatch(r'docker\.io/library/postgres:16(?:[.-][A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}', config['postgresImage']):
        raise ValueError('ATC PostgreSQL image must be digest pinned')
    return config


def check_identity(state, config):
    expected = {'INSTALL_ROOT': config['root'], 'API_PORT': str(config['port']),
        'RELEASE_VERSION': config['version'], 'SOURCE_COMMIT': config['revision'],
        'POSTGRES_IMAGE': config['postgresImage'], 'MIGRATION_LEVEL': config['migrationLevel'],
        'OPERATOR_OS_USER': config['operatorUser'], 'ENGAGEMENT_ID': config['engagementId'],
        'ENGAGEMENT_CODENAME': config['codename'], 'ENGAGEMENT_STATUS': config['engagementStatus'],
        'TEAM_MEMBER_ID': config['operatorId'], 'TEAM_MEMBER_NAME': config['operatorName']}
    if any(state.get(key) != value for key, value in expected.items()):
        raise ValueError('existing ATC identity or settings differ; use an explicit app-owned migration')
    if state.get('PHASE') != 'healthy':
        raise ValueError('incomplete ATC installation requires the app-owned recovery procedure')


def ready(config):
    root, port = Path(config['root']), config['port']
    try:
        for path in ('atc', 'atc-mcp'):
            if Path('/usr/local/bin/' + path).resolve(strict=True) != root / 'venv/bin' / path:
                return False
        for path in ('atc-admin',):
            if Path('/usr/local/sbin/' + path).resolve(strict=True) != root / 'venv/bin' / path:
                return False
        for path in ('atc', 'atc-mcp', 'atc-admin', 'atc-api'):
            protected(root/'venv/bin'/path)
            if not os.access(root/'venv/bin'/path, os.X_OK):
                return False
        protected('/usr/local/sbin/atc-maintenance')
        props = command(['systemctl', 'show', 'atc-api.service', '--property=MainPID,User,ActiveState']).splitlines()
        props = dict(row.split('=', 1) for row in props if '=' in row)
        pid = int(props.get('MainPID', '0'))
        if pid <= 0 or props.get('User') != 'atc' or props.get('ActiveState') != 'active':
            return False
        if Path('/proc/' + str(pid)).stat().st_uid != pwd.getpwnam('atc').pw_uid:
            return False
        listeners = command(['ss', '-H', '-ltnp', 'sport = :' + str(port)]).splitlines()
        if len(listeners) != 1 or listeners[0].split()[3] != '127.0.0.1:' + str(port) or ('pid=' + str(pid) + ',') not in listeners[0]:
            return False
        spec = '{{json .Config.Image}}|{{json .Config.Labels}}|{{json .HostConfig.PortBindings}}|{{json .State.Running}}|{{json .State.Health.Status}}'
        image, labels, ports, running, health = [json.loads(value) for value in command(['docker', 'inspect', '--format', spec, 'atc-postgres']).strip().split('|')]
        if image != config['postgresImage'] or labels.get('io.atc.managed') != 'true' or labels.get('io.atc.release') != config['version'] or ports != {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '15432'}]} or running is not True or health != 'healthy':
            return False
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('ATC health redirect refused')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open('http://127.0.0.1:' + str(port) + '/healthz', timeout=3) as response:
            raw = response.read(4097)
        return len(raw) <= 4096 and json.loads(raw) == {'status': 'ok', 'version': config['version']}
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        return False


def _docker_ready():
    if shutil.which('docker') is None:
        raise ValueError('Docker engine is unavailable')
    command(['docker', 'info', '--format', '{{.ServerVersion}}'])


def _fresh_ports(config):
    for line in command(['ss', '-H', '-ltn']).splitlines():
        fields = line.split()
        if len(fields) < 4:
            raise ValueError('listener inventory is malformed')
        if fields[3].rsplit(':', 1)[-1] in {str(config['port']), '15432'}:
            raise ValueError('ATC fresh API or PostgreSQL listener conflicts with existing service')


def _capacity(root):
    for target in (root, Path('/var/lib/docker')):
        while not target.exists():
            target = target.parent
        if shutil.disk_usage(target).free < 4 * 1024**3:
            raise ValueError('ATC requires at least 4 GiB free beneath installation and Docker storage')


def assess(config, *, require_docker=True):
    validate_configuration(config)
    if os.geteuid() != 0:
        raise ValueError('ATC assessment requires root')
    for tool in ('git', 'openssl', 'flock', 'runuser', 'useradd', 'systemctl', 'ss', 'tar', 'sha256sum', 'find', 'awk', 'sed', 'timeout'):
        if shutil.which(tool) is None:
            raise ValueError('ATC prerequisite is missing; install the documented host tools first')
    if command([config['python'], '-c', 'import sys; print("%s.%s" % sys.version_info[:2])']).strip() != '3.10':
        raise ValueError('ATC release requires Python3.10; no host interpreter replacement is attempted')
    operator = pwd.getpwnam(config['operatorUser'])
    if operator.pw_uid == 0 or not operator.pw_dir.startswith('/'):
        raise ValueError('ATC requires a non-root existing operator account')
    root = Path(config['root'])
    for parent in reversed((root, *root.parents)):
        protected(parent, directory=True, missing=True)
    # Role cache and application root must both be safe before staging writes.
    for parent in (Path('/var/cache'), Path('/var/cache/atc')):
        protected(parent, directory=True, missing=True)
    protected(Path('/var/cache/atc/last-install-result.json'), mode=0o600, missing=True)
    _capacity(root)
    if not root.exists():
        _fresh_ports(config)
        if require_docker:
            _docker_ready()
        return {'mode': 'install', 'localReady': False}
    for name in MARKERS:
        if os.path.lexists(root/'recovery'/name):
            raise ValueError('ATC recovery is pending; preserve journals and use the app-owned recovery procedure')
    for optional in ('inference.env', 'topo.env'):
        if os.path.lexists(root/'config'/optional):
            raise ValueError('configured optional ATC workers require a separately reviewed convergence scope')
    state_path = root/'install-state.env'
    if not state_path.exists():
        if any(root.iterdir()):
            raise ValueError('unmanaged ATC material exists; automatic adoption is refused')
        _fresh_ports(config)
        if require_docker:
            _docker_ready()
        return {'mode': 'install', 'localReady': False}
    state = read_pairs(state_path)
    check_identity(state, config)
    runtime = read_pairs(root/'config/api.env', mode=0o440)
    managed = {'ATC_API_HOST': '127.0.0.1', 'ATC_API_PORT': str(config['port']),
        'ATC_DATABASE_URL': 'postgresql://atc@127.0.0.1:15432/atc',
        'ATC_DATABASE_PASSWORD_FILE': str(root/'config/database_password.api'),
        'ATC_CREDENTIAL_KEY_FILE': str(root/'config/credential_key.api'),
        'ATC_ARTIFACT_ROOT': str(root/'artifacts'),
        'ATC_WEB_DIST': str(root/'releases'/config['version']/'web-dist')}
    if any(runtime.get(key) != value for key, value in managed.items()):
        raise ValueError('existing ATC runtime settings differ; no implicit configuration migration is allowed')
    for subdir in ('source', 'source/.git', 'config', 'recovery', 'releases'):
        protected(root/subdir, directory=True)
    for secret in ('database_password', 'credential_key'):
        protected(root/'config'/secret, mode=0o600)
        if (root/'config'/secret).stat().st_size == 0:
            raise ValueError('ATC retained secret is empty; automatic regeneration is refused')
    if command(['git', '-C', str(root/'source'), 'rev-parse', 'HEAD']).strip() != config['revision'] or command(['git', '-C', str(root/'source'), 'status', '--porcelain', '--untracked-files=normal']).strip():
        raise ValueError('ATC source differs from the release; preserve and reconcile it before repair')
    receipt_path = root/'.ansible-release.json'
    has_receipt = protected(receipt_path, mode=0o600, missing=True)
    if has_receipt:
        if receipt_path.stat().st_size > 4096 or json.loads(receipt_path.read_text()) != {'sha256': config['sha256'], 'sourceRevision': config['revision'], 'version': config['version']}:
            raise ValueError('ATC role artifact differs; same-release artifact replacement requires explicit review')
    if not require_docker:
        return {'mode': 'preflight', 'localReady': False}
    _docker_ready()
    local_ready = ready(config)
    return {'mode': 'none' if local_ready and has_receipt else 'repair', 'localReady': local_ready}


if __name__ == '__main__':
    try:
        print(json.dumps(assess(json.loads(sys.argv[1]), require_docker='--before-docker' not in sys.argv[2:])))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('ATC preflight refused: check supported prerequisites, exact retained settings, protected state and app recovery status.') from None
