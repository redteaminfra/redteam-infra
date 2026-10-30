#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only absence fence; never install, start, repair or upgrade a daemon."""
import json
import os
import re
import shutil
import subprocess
import sys

EXECUTABLES = ('dockerd', 'containerd', 'containerd-shim', 'containerd-shim-runc-v2', 'runc', 'podman')
FOOTPRINTS = ('/run/docker.sock', '/var/run/docker.sock', '/run/containerd/containerd.sock',
              '/var/run/containerd/containerd.sock', '/etc/docker', '/var/lib/docker',
              '/etc/containerd', '/var/lib/containerd', '/run/containerd')
FAMILY = re.compile(r'^(?:docker(?:[.-].*)?|containerd(?:[.-].*)?|moby(?:[.-].*)?|runc|podman-docker)$')


def assess():
    if os.geteuid() != 0:
        raise ValueError('Docker prerequisite assessment requires root')
    # A client, including a broken/stopped engine, is never an installation
    # invitation. Existing-engine health/version gates run afterward.
    if shutil.which('docker'):
        return {'mode': 'existing'}
    if any(shutil.which(name) for name in EXECUTABLES) or any(os.path.lexists(path) for path in FOOTPRINTS):
        raise ValueError('existing container runtime requires operator reconciliation')
    packages = subprocess.run(['dpkg-query', '--show', '--showformat=${binary:Package}\t${db:Status-Status}\n'],
                              check=True, capture_output=True, text=True, timeout=15).stdout
    if len(packages) > 1024 * 1024:
        raise ValueError('package inventory exceeds bounds')
    for line in packages.splitlines():
        name, status = line.split('\t', 1)
        if FAMILY.fullmatch(name.split(':', 1)[0]) and status != 'not-installed':
            raise ValueError('existing container packages require operator reconciliation')
    # Pattern queries return status 1 on some supported systemd versions when
    # nothing matches. Read the full inventory instead; real query errors must
    # still fail closed rather than treating every status 1 as absence.
    units = subprocess.run(['systemctl', 'list-unit-files', '--no-pager', '--no-legend'],
                           check=True, capture_output=True, text=True, timeout=15).stdout
    if len(units) > 1024 * 1024:
        raise ValueError('service unit inventory exceeds bounds')
    for line in units.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 2:
            raise ValueError('service unit inventory is malformed')
        if fields[0].startswith(('docker', 'containerd', 'moby', 'podman')):
            raise ValueError('existing container service units require operator reconciliation')
    return {'mode': 'absent'}


if __name__ == '__main__':
    try:
        print(json.dumps(assess()))
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.exit('Docker prerequisite refused: existing, partial or unknown container runtime; reconcile without automatic upgrade')
