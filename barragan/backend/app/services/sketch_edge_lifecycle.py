# Copyright (c) 2026, Oracle and/or its affiliates.
"""Validated desired-state transitions for retained-middle edge operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class SketchEdgeLifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class EdgeTransition:
    retained_edges: list[dict[str, str]]
    removed_edge: dict[str, str] | None
    replacement_edge: dict[str, str] | None


def retire_final_edge(edges: list[dict[str, Any]], edge_id: str) -> EdgeTransition:
    normalized = _edges(edges)
    if len(normalized) < 2:
        raise SketchEdgeLifecycleError("a retained-middle operation requires at least two edges")
    if normalized[-1]["id"] != edge_id:
        raise SketchEdgeLifecycleError("only the final edge ordinal may be retired until upstream keyed topology is available")
    return EdgeTransition(normalized[:-1], normalized[-1], None)


def append_replacement_edge(edges: list[dict[str, Any]], *, region: str) -> EdgeTransition:
    normalized = _edges(edges)
    selected_region = str(region or "").strip()
    if not selected_region:
        raise SketchEdgeLifecycleError("replacement edge region is required")
    if selected_region in {edge["region"] for edge in normalized}:
        raise SketchEdgeLifecycleError("replacement edge must use a different region")
    provider = normalized[0]["provider"]
    size = normalized[0]["size"]
    next_id = f"edge-{len(normalized) + 1:02d}"
    replacement = {"id": next_id, "provider": provider, "region": selected_region, "size": size}
    return EdgeTransition([*normalized, replacement], None, replacement)


def _edges(values: list[dict[str, Any]]) -> list[dict[str, str]]:
    normalized = []
    for index, value in enumerate(values, start=1):
        edge = {field: str(value.get(field) or "").strip() for field in ("id", "provider", "region", "size")}
        if not all(edge.values()):
            raise SketchEdgeLifecycleError("each edge must include id, provider, region, and size")
        if edge["id"] != f"edge-{index:02d}":
            raise SketchEdgeLifecycleError("edge ids must remain ordered for the current count-based upstream module")
        normalized.append(edge)
    return normalized
