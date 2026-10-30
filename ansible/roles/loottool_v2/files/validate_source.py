#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Run the pinned application's own non-mutating preflight on the controller."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from verify_archive import verify


def main():
    archive, digest, revision = sys.argv[1:]
    verify(archive, digest, revision)
    request = json.load(sys.stdin)
    with tempfile.TemporaryDirectory(prefix='loottool-preflight-') as temporary:
        with tarfile.open(archive, 'r:gz') as source:
            # Archive members were bounded and links/traversal rejected above.
            source.extractall(temporary)
        env = dict(os.environ, PYTHONPATH=str(Path(temporary) / 'src'))
        result = subprocess.run([sys.executable, '-m', 'loottool.deployment'],
                                input=json.dumps(request), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, cwd=temporary, timeout=15)
        if result.returncode:
            raise ValueError('application deployment preflight rejected runtime')
        response = json.loads(result.stdout)
        if response.get('valid') is not True:
            raise ValueError('application deployment preflight did not pass')
    print('Pinned application runtime preflight passed')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError):
        sys.exit('LootTool artifact/runtime validation failed')
