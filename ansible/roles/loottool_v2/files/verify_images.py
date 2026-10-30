#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Verify actual image platform, repository digest and application revision."""
import json
import subprocess
import sys


def validate(image, reference, revision=None):
    if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64':
        raise ValueError('image platform mismatch')
    if reference.startswith('sha256:'):
        if image.get('Id') != reference:
            raise ValueError('local image ID mismatch')
    elif reference not in image.get('RepoDigests', []):
        raise ValueError('image repository digest mismatch')
    if revision and (image.get('Config') or {}).get('Labels', {}).get('org.opencontainers.image.revision') != revision:
        raise ValueError('application source revision label mismatch')


if __name__ == '__main__':
    try:
        app, elasticsearch, revision = sys.argv[1:]
        for reference, source_revision in [(app, revision), (elasticsearch, None)]:
            raw = subprocess.run(['docker', 'image', 'inspect', reference], check=True,
                                 capture_output=True, timeout=30).stdout
            validate(json.loads(raw)[0], reference, source_revision)
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        sys.exit('LootTool immutable image/platform verification failed')
