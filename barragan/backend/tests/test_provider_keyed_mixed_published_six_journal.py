# Copyright (c) 2026, Oracle and/or its affiliates.
"""Historical grammar remains strict after journal/publication hashes are rebound."""

from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
from app.services.provider_keyed_mixed_published_six_journal import (
    MixedPublishedSixJournalAttention, validate_mixed_published_six_journals,
)
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_published_six_integration import persisted_six_case


def _rebind(case, provider, events):
    child = case["provider_children"][provider]
    if len(events) == 10:
        events[9] = replace(events[9], data={
            "proofJournalSha256": job_event_digest(events[:9])})
    case["provider_children"][provider] = replace(child, events=events)
    source = replace(case["source"], provider_proof_digests=tuple(
        job_event_digest(case["provider_children"][item].events)
        for item in case["source"].provider_order))
    parent = case["append_parent"]
    publication = parent.events[-1]
    case["source"] = source
    case["append_parent"] = replace(parent, events=[*parent.events[:-1], replace(
        publication, data={**publication.data,
            "sourceSha256": source.source_sha256,
            "source": json.loads(json.dumps(asdict(source))),
            "providerProofJournalSha256": dict(zip(
                source.provider_order, source.provider_proof_digests, strict=True))})])


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("drift", [
    "first_nonzero", "second_nonzero", "first_missing_result", "second_missing_result",
    "synthetic_first_history", "first_plan", "second_plan", "second_first_link",
    "first_result_link", "second_result_link", "first_invocation", "second_invocation",
    "first_public_ip", "second_public_ip",
    "approval", "show", "plan", "predecessor", "receipt",
])
def test_historical_provider_grammar_rejects_rehashed_drift(
        client, tmp_path, monkeypatch, reverse, drift):
    case = persisted_six_case(client, tmp_path, monkeypatch, reverse=reverse)
    source = case["source"]
    if drift in {"show", "plan", "predecessor", "receipt"}:
        suffix = {"show": "show.json", "plan": "saved.tfplan",
                  "predecessor": "predecessor.tfstate", "receipt": "plan-receipt.json"}[drift]
        path = Path(source.workspace_paths[0]) / _name(source.provider_order[0], suffix)
        path.write_bytes(path.read_bytes() + b" ")
    elif drift == "approval":
        parent = case["append_parent"]
        events = list(parent.events)
        events[-2] = replace(events[-2], data={"reviewSha256": parent.input["reviewSha256"]})
        case["append_parent"] = replace(parent, events=events)
    else:
        provider = source.provider_order[1 if drift.startswith("second_") else 0]
        events = list(case["provider_children"][provider].events)
        if drift.endswith("nonzero"):
            events[5] = replace(events[5], data={**events[5].data, "returnCode": 1})
        elif drift.endswith("missing_result"):
            events.pop(5)
        elif drift == "synthetic_first_history":
            events[:8] = [replace(event, message=f"stage {index}", data={})
                          for index, event in enumerate(events[:8], 1)]
        elif drift.endswith("plan"):
            events[2] = replace(events[2], data={**events[2].data, "planSha256": "f" * 64})
        elif drift.endswith("invocation"):
            events[5] = replace(events[5], data={**events[5].data, "invocationId": "foreign"})
        elif drift.endswith("public_ip"):
            events[8] = replace(events[8], data={**events[8].data,
                                               "newEdgePublicIp": "8.8.8.8"})
        else:
            key = "firstProofJournalSha256" if drift == "second_first_link" else "resultJournalSha256"
            events[8] = replace(events[8], data={**events[8].data, key: "f" * 64})
        _rebind(case, provider, events)
    with pytest.raises(MixedPublishedSixJournalAttention):
        validate_mixed_published_six_journals(
            case["source"], case["append_parent"], case["provider_children"])
