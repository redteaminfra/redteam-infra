# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True)
class RequestIdentity:
    user_id: str
    username: str
    roles: tuple[str, ...]
    session_id: str


_current_identity: ContextVar[RequestIdentity | None] = ContextVar(
    "barragan_request_identity",
    default=None,
)


def current_request_identity() -> RequestIdentity | None:
    return _current_identity.get()


@contextmanager
def bind_request_identity(identity: RequestIdentity) -> Iterator[None]:
    token = _current_identity.set(identity)
    try:
        yield
    finally:
        _current_identity.reset(token)
