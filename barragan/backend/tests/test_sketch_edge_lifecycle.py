# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app.services.sketch_edge_lifecycle import SketchEdgeLifecycleError, append_replacement_edge, retire_final_edge


EDGES = [
    {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
    {"id": "edge-02", "provider": "linode", "region": "us-central", "size": "g6-nanode-1"},
]


def test_retires_only_last_edge_and_preserves_first():
    transition = retire_final_edge(EDGES, "edge-02")
    assert [edge["id"] for edge in transition.retained_edges] == ["edge-01"]
    assert transition.removed_edge["region"] == "us-central"


def test_rejects_reordering_or_non_final_retirement():
    with pytest.raises(SketchEdgeLifecycleError, match="final edge"):
        retire_final_edge(EDGES, "edge-01")


def test_appends_replacement_in_new_region_without_changing_retained_edge():
    transition = append_replacement_edge(EDGES[:1], region="us-dal")
    assert [(edge["id"], edge["region"]) for edge in transition.retained_edges] == [("edge-01", "us-sea"), ("edge-02", "us-dal")]


def test_rejects_same_region_replacement():
    with pytest.raises(SketchEdgeLifecycleError, match="different region"):
        append_replacement_edge(EDGES[:1], region="us-sea")
