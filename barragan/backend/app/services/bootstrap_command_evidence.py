# Copyright (c) 2026, Oracle and/or its affiliates.
"""Small, backward-compatible validation boundary for bootstrap timing metadata."""
from __future__ import annotations

import math
from typing import Any

TIMING_KEYS = {"executionTimeoutSeconds", "commandElapsedSeconds", "timedOut"}


def valid_number(value: Any, *, positive: bool = False) -> bool:
    try:
        return (type(value) in {int, float} and math.isfinite(value)
                and (value > 0 if positive else value >= 0))
    except OverflowError:
        return False


def valid_bootstrap_result_keys(data: Any, base_keys: set[str], *, success: bool = False) -> bool:
    """Accept only exact old, interim timeout, or complete timing-extended shapes."""
    if type(data) is not dict or set(data) not in (base_keys, base_keys | {"timedOut"}, base_keys | TIMING_KEYS):
        return False
    if "timedOut" in data and (type(data["timedOut"]) is not bool or success and data["timedOut"]):
        return False
    if "executionTimeoutSeconds" in data:
        return (valid_number(data["executionTimeoutSeconds"], positive=True)
                and valid_number(data["commandElapsedSeconds"]))
    return True


def bootstrap_command_timing(audit: Any) -> dict[str, int | float | bool]:
    data = {"timedOut": audit.timed_out}
    budget, elapsed = audit.execution_timeout_seconds, audit.command_elapsed_seconds
    if budget is not None or elapsed is not None:
        data.update(executionTimeoutSeconds=budget, commandElapsedSeconds=elapsed)
    if not valid_bootstrap_result_keys(data, set()):
        raise ValueError("bootstrap command timing metadata is invalid")
    return data


def without_bootstrap_timing(data: dict, *, success: bool = False) -> dict:
    base = set(data) - TIMING_KEYS
    if not valid_bootstrap_result_keys(data, base, success=success):
        raise ValueError("bootstrap command timing metadata is invalid")
    return {key: value for key, value in data.items() if key not in TIMING_KEYS}
