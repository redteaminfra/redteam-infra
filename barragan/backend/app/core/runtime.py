# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import logging
import threading
from typing import Any

from app.core.error_locations import sanitized_error_locations
from app.storage.database import DatabaseState, db


@dataclass(frozen=True)
class RuntimeState:
    config: type | Mapping[str, Any]
    database: DatabaseState


_current_runtime: ContextVar[RuntimeState | None] = ContextVar(
    "barragan_runtime_state",
    default=None,
)
_default_runtime: RuntimeState | None = None


def configure_runtime(
    config: type | Mapping[str, Any],
    database: DatabaseState,
    *,
    make_default: bool = False,
) -> RuntimeState:
    global _default_runtime
    state = RuntimeState(config=config, database=database)
    if make_default:
        _default_runtime = state
    return state


def initialize_runtime(
    config: type | Mapping[str, Any],
    *,
    make_default: bool = False,
) -> RuntimeState:
    from app.core.bootstrap import initialize_database

    database = initialize_database(config, make_default=make_default)
    return configure_runtime(config, database, make_default=make_default)


def current_runtime() -> RuntimeState:
    state = _current_runtime.get() or _default_runtime
    if state is None:
        raise RuntimeError("no Barragan runtime context is active")
    return state


def has_runtime_context() -> bool:
    return _current_runtime.get() is not None


def runtime_value(key: str, default: Any = None, *, state: RuntimeState | None = None) -> Any:
    config = (state or current_runtime()).config
    if isinstance(config, Mapping):
        return config.get(key, default)
    return getattr(config, key, default)


@contextmanager
def runtime_context(state: RuntimeState) -> Iterator[None]:
    token = _current_runtime.set(state)
    try:
        with db.bind(state.database):
            yield
    finally:
        _current_runtime.reset(token)


def start_runtime_task(
    task: Callable[[], None],
    *,
    name: str,
    synchronous_when_testing: bool = False,
) -> None:
    state = current_runtime()
    if synchronous_when_testing and bool(runtime_value("TESTING", False, state=state)):
        with runtime_context(state):
            task()
        return

    def run() -> None:
        try:
            with runtime_context(state):
                task()
        except Exception as error:
            logging.getLogger("barragan.background").error(
                "Background task failure locations: %s", sanitized_error_locations(error))
            logging.getLogger("barragan.background").exception("Background task %s failed", name)

    threading.Thread(target=run, name=name, daemon=True).start()
