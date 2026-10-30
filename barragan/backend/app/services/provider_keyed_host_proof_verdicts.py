# Copyright (c) 2026, Oracle and/or its affiliates.
"""Successful pure host-proof verdicts confined to one explicit operation.

Callers still read safe artifact bytes and all current expected inputs. Nothing
here caches files, decoded objects, authority rows, failures or freshness.
"""
import asyncio
from threading import get_ident
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class _Verdicts:
    successes: set = field(default_factory=set)
    hit_only: bool = False
    owner: tuple = field(default_factory=lambda: _owner())

    def require_hits_only(self):
        self.hit_only = True


_current: ContextVar[_Verdicts | None] = ContextVar('keyed_host_proof_verdicts', default=None)


def _owner():
    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    return (get_ident(), task)


def _active():
    current = _current.get()
    return current if current is not None and current.owner == _owner() else None


@contextmanager
def host_proof_verdict_scope():
    """Create an isolated scope; explicitly seal it after complete priming."""
    existing = _active()
    if existing is not None:
        yield existing
        return
    verdicts = _Verdicts()
    token = _current.set(verdicts)
    try:
        yield verdicts
    finally:
        verdicts.successes.clear()
        _current.reset(token)


def require_host_proof_verdict(raw: bytes, expected: bytes, verifier_identity: tuple, verify):
    """Reuse only a successful None result for these exact consumed inputs."""
    current = _active()
    if current is None and _current.get() is not None:
        raise ValueError('keyed host proof scope belongs to another execution')
    key = (raw, expected, verifier_identity)
    if current is not None:
        if key in current.successes:
            return
        if current.hit_only:
            raise ValueError('keyed host proof inputs changed after priming')
    if verify() is not None:
        raise ValueError('keyed host proof verifier result differs')
    if current is not None:
        current.successes.add(key)
