#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Check retained release bytes before running its Compose/setup scripts."""
import hashlib
from pathlib import Path
import sys
import tarfile


def verify(archive, destination):
    root = Path(destination)
    for parent in [root, *root.parents]:
        stat = parent.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o022:
            raise ValueError('unprotected release directory')
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            target = root / member.name
            if any(p.is_symlink() for p in [target, *target.parents]):
                raise ValueError('symlink release path')
            if member.isfile():
                stat = target.stat()
                if stat.st_uid != 0 or stat.st_mode & 0o022 or stat.st_nlink != 1:
                    raise ValueError('unprotected release file')
                if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(source.extractfile(member).read()).digest():
                    raise ValueError('retained release bytes changed')


def verify_before_extract(archive, destination):
    """Permit only missing or exact root-owned members before scoped repair.

    Git archive's 0664/0775 modes are a bounded interrupted-install recovery
    exception here. Strict post-extraction verification remains unchanged.
    """
    root = Path(destination)
    for parent in [root, *root.parents]:
        if parent.is_symlink():
            raise ValueError('symlink release path')
        if parent.exists():
            info = parent.stat()
            if not parent.is_dir() or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
                raise ValueError('unprotected release directory')
    with tarfile.open(archive, 'r:gz') as source:
        members = {}
        for member in source:
            path = Path(member.name)
            if (path.is_absolute() or '..' in path.parts or '.git' in path.parts
                    or str(path) in members or not (member.isfile() or member.isdir())
                    or member.mode & 0o7002):
                raise ValueError('unsafe release archive member')
            members[str(path)] = member
        for name, member in members.items():
            target = root / name
            for parent in [target, *target.parents]:
                if parent == root:
                    break
                if parent.is_symlink():
                    raise ValueError('symlink retained release member')
                if not parent.exists():
                    continue
                info = parent.stat()
                declared = members.get(str(parent.relative_to(root)))
                allowed_git_mode = (declared.mode & 0o777 if declared is not None else None)
                mode = info.st_mode & 0o7777
                if info.st_uid != 0 or info.st_gid != 0 or mode & 0o7002:
                    raise ValueError('foreign or unsafe retained release member')
                if mode & 0o020 and not (mode == allowed_git_mode and mode in {0o664, 0o775}):
                    raise ValueError('unexpected writable retained release member')
                if parent == target:
                    if member.isdir() != parent.is_dir() or member.isfile() != parent.is_file():
                        raise ValueError('retained release member type differs')
                    if member.isfile() and info.st_nlink != 1:
                        raise ValueError('hardlinked retained release member')
                elif not parent.is_dir():
                    raise ValueError('retained release parent type differs')
            if target.exists() and member.isfile():
                if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(source.extractfile(member).read()).digest():
                    raise ValueError('retained release bytes changed')


if __name__ == '__main__':
    try:
        if sys.argv[1:2] == ['--before-extract']:
            verify_before_extract(*sys.argv[2:])
        else:
            verify(*sys.argv[1:])
    except (OSError, ValueError, tarfile.TarError):
        sys.exit('LootTool retained release verification failed')
