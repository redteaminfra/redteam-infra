#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Inspect project ownership and actual ports without emitting container secrets."""
import json
import subprocess
import sys


def validate(containers, port):
    by_service = {}
    for container in containers:
        config = container.get('Config', {})
        labels = config.get('Labels', {})
        if labels.get('com.docker.compose.project') != 'loottool-v2':
            raise ValueError('project mismatch')
        service = labels.get('com.docker.compose.service')
        if service in by_service or service not in {'api', 'elasticsearch', 'cert-setup', 'security-setup'}:
            raise ValueError('unexpected or duplicate activated service')
        by_service[service] = container
        ports = container.get('HostConfig', {}).get('PortBindings') or {}
        expected = {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]} if service == 'api' else {}
        if ports != expected or container.get('HostConfig', {}).get('NetworkMode') == 'host':
            raise ValueError('unexpected host listener/network')
        for mount in container.get('Mounts', []):
            if mount.get('Destination') == '/loot' or mount.get('Source') == '/engagement/loot':
                raise ValueError('baseline must not mount source loot')
    for service in ('api', 'elasticsearch'):
        container = by_service.get(service, {})
        if not container.get('State', {}).get('Running') or container.get('State', {}).get('Health', {}).get('Status') != 'healthy':
            raise ValueError('baseline service is not healthy')


if __name__ == '__main__':
    try:
        ids = subprocess.run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=loottool-v2'],
                             check=True, capture_output=True, text=True, timeout=15).stdout.split()
        if not ids:
            raise ValueError('missing baseline services')
        raw = subprocess.run(['docker', 'inspect', *ids], check=True, capture_output=True, timeout=15).stdout
        validate(json.loads(raw), int(sys.argv[1]))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit('LootTool baseline ownership/binding verification failed')
