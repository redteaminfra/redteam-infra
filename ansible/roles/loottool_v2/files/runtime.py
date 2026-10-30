#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private fixed-root configuration; no subprocess, ingestion or service mutation."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import tempfile

ROOT = Path('/etc/loottool-v2')
INSTALL_ROOT = Path('/opt/loottool-v2')
STATE_ROOT = Path('/var/lib/loottool-v2')
SECRET_FIELDS = ('ELASTIC_PASSWORD', 'LOOTTOOL_ES_READER_PASSWORD', 'LOOTTOOL_ES_WRITER_PASSWORD')
STATE = {
    'LOOTTOOL_ES_DATA_ROOT': '/var/lib/loottool-v2/elasticsearch',
    'LOOTTOOL_CERTS_ROOT': '/var/lib/loottool-v2/certs',
    'LOOTTOOL_MANIFEST_ROOT': '/var/lib/loottool-v2/manifests',
    'LOOTTOOL_REVIEW_STATE_ROOT': '/var/lib/loottool-v2/reviews',
    'LOOTTOOL_EXPLORER_STATE_ROOT': '/var/lib/loottool-v2/explorer',
    'LOOTTOOL_ATC_OUTBOX_HOST_ROOT': '/var/lib/loottool-v2/atc-outbox',
}


def dotenv(values):
    # Restrict interpolation/quoting rather than treating dotenv as shell code.
    if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*', k) or not isinstance(v, str)
           or any(c in v for c in "\r\n\x00'$\\") for k, v in values.items()):
        raise ValueError('unsafe runtime mapping')
    return ''.join(f"{k}='{v}'\n" for k, v in sorted(values.items()))


def prepare(proposed, existing=None):
    values = dict(proposed)
    values.update(STATE)
    values['LOOTTOOL_API_LISTEN_HOST'] = values['LOOTTOOL_ANSWER_LISTEN_HOST'] = '127.0.0.1'
    if existing is not None:
        # Same-release repair only. Cross-release upgrades need a backup/run contract.
        for key, value in values.items():
            if existing.get(key) != value:
                raise ValueError('existing runtime identity differs; explicit migration required')
        values = dict(existing)
    else:
        values.update({key: secrets.token_hex(32) for key in SECRET_FIELDS})
    for key in SECRET_FIELDS:
        if not re.fullmatch(r'[A-Za-z0-9._~!@%+=:-]{32,}', values.get(key, '')):
            raise ValueError('invalid retained credentials')
    # Optional services are intentionally not activated by this role.
    if any(key.startswith(('LOOTTOOL_INFERENCE_', 'LOOTTOOL_ATC_TOKEN', 'COMPOSE_')) for key in values):
        raise ValueError('optional activation requires a separately reviewed contract')
    dotenv(values)
    return values


def check_paths(values):
    paths = [Path(values['LOOTTOOL_SOURCE_ROOT']), *(Path(v) for v in STATE.values()), ROOT,
             INSTALL_ROOT]
    for path in paths:
        if not path.is_absolute() or '..' in path.parts or path == Path('/'):
            raise ValueError('invalid target path')
        if any(p.is_symlink() for p in [path, *path.parents]):
            raise ValueError('symlink target path refused')
    source = paths[0]
    if not source.is_dir():
        raise ValueError('source directory must already exist')
    for state in paths[1:]:
        if source == state or source in state.parents or state in source.parents:
            raise ValueError('state and source overlap')
    # Baseline API queries Elasticsearch and has no original-loot mount.
    # Explicit ingestion needs a separately reviewed read-only permission path;
    # installation must not require reading or changing operator-owned loot.
    if shutil.disk_usage('/var/lib').free < 50 * 1024**3:
        raise ValueError('50 GiB free disk required')
    if int(Path('/proc/sys/vm/max_map_count').read_text()) < 1048576:
        raise ValueError('vm.max_map_count prerequisite not satisfied; operator action required')
    # A managed reapply is allowed to retain its running listener; final health
    # and Compose ownership checks must establish the actual service identity.
    if not (ROOT / 'runtime.json').exists():
        for key in ('LOOTTOOL_API_LISTEN_PORT', 'LOOTTOOL_ANSWER_LISTEN_PORT'):
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', int(values[key])))


def _check_private(path):
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('symlink configuration path refused')
    if path.exists():
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('configuration must be root-owned and private')


def guard_release(revision):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('invalid release revision')
    target = INSTALL_ROOT / 'releases' / revision
    for path in [target, *target.parents]:
        if path.is_symlink():
            raise ValueError('symlink release directory refused')
        if path.exists():
            info = path.stat()
            if not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('unprotected release directory refused')


def _atomic_write(directory, name, content):
    destination = directory / name
    _check_private(destination)
    if destination.exists() and destination.read_text() == content:
        return
    fd, temporary = tempfile.mkstemp(prefix='.' + name + '.tmp-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def configure(request):
    pending = ROOT.with_name('.' + ROOT.name + '.pending')
    for directory in (ROOT, pending):
        _check_private(directory)
        if directory.exists() and not directory.is_dir():
            raise ValueError('configuration directory has invalid type')
        for name in ('runtime.json', 'runtime.env'):
            _check_private(directory / name)
    guard_release(request['proposed'].get('LOOTTOOL_GIT_COMMIT', ''))
    # A pending directory is private role-owned installation intent. Its JSON is
    # published first and retains credentials across interrupted pair creation.
    directory = ROOT if ROOT.exists() else pending
    path = directory / 'runtime.json'
    existing = json.loads(path.read_text()) if path.exists() else None
    if ROOT.exists():
        if existing is None or (ROOT / 'runtime.env').read_text() != dotenv(existing):
            raise ValueError('retained env and configuration differ')
    elif existing is None and (STATE_ROOT.exists() or INSTALL_ROOT.exists()):
        raise ValueError('unmanaged installation requires reconciliation')
    values = prepare(request['proposed'], existing)
    check_paths(values)
    if request['action'] == 'inspect':
        return {'existing': existing, 'proposed': values}
    if request['action'] != 'write':
        raise ValueError('invalid action')
    if ROOT.exists():
        return {'changed': False}
    pending.mkdir(mode=0o700, exist_ok=True)
    # Random per-write temporary names cannot block recovery after SIGKILL.
    _atomic_write(pending, 'runtime.json', json.dumps(values, sort_keys=True)+'\n')
    _atomic_write(pending, 'runtime.env', dotenv(values))
    os.rename(pending, ROOT)
    return {'changed': True}


def main():
    print(json.dumps(configure(json.loads(sys.argv[1]))))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, OSError, KeyError):
        sys.exit('LootTool runtime validation failed; inspect deployment prerequisites and retained configuration')
