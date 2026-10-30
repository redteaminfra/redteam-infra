# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded exception locations for diagnostics without exception payloads."""

from pathlib import Path


_APP_ROOT = Path(__file__).resolve().parents[1]


def sanitized_error_locations(error: Exception) -> list:
    """Read types/locations only, including contexts suppressed by from None."""
    pending = [error]
    seen = set()
    locations = []
    while pending and len(seen) < 16:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        frames = []
        trace = current.__traceback__
        walked = 0
        while trace is not None and walked < 128:
            walked += 1
            filename = Path(trace.tb_frame.f_code.co_filename).resolve()
            if filename.is_relative_to(_APP_ROOT):
                frames.append((filename.name, trace.tb_lineno))
            trace = trace.tb_next
        locations.append((type(current).__name__, frames[-32:]))
        # __context__ remains useful even for `raise ... from None`.
        for linked in (current.__context__, current.__cause__):
            if linked is not None and id(linked) not in seen:
                pending.append(linked)
    return locations
