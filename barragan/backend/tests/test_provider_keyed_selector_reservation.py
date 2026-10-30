# Copyright (c) 2026, Oracle and/or its affiliates.
"""No live provider calls: one POST and complete post-reservation reads."""

from dataclasses import dataclass

import pytest

from app.services.provider_keyed_selector_reservation import (
    ReservationResponse, SelectorReservationError, reserve_and_verify_selector,
)


SELECTOR = "opaque-selector-a1"


@dataclass
class Post:
    response: ReservationResponse | None = None
    error: Exception | None = None
    calls: int = 0

    def create_tag(self, token, selector):
        self.calls += 1
        assert (token, selector) == ("secret", SELECTOR)
        if self.error:
            raise self.error
        return self.response or ReservationResponse(201, {"tag": {"name": SELECTOR}})


class Get:
    def __init__(self, *, attachment=None):
        self.attachment = attachment
        self.paths = []

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token == "secret"
        self.paths.append(path)
        if path == f"/tags/{SELECTOR}":
            return {"tag": {"name": SELECTOR, "resources": {"count": 0}}}
        kind = path.split("?", 1)[0][1:]
        key = "snapshots" if kind == "snapshots" else kind
        if kind == "firewalls" and self.attachment == "second_page_rule":
            if "page=1&" in path:
                return {"firewalls": [{"id": "1", "tags": [], "inbound_rules": None,
                                       "outbound_rules": None}],
                        "meta": {"total": 2}, "links": {"pages": {"next":
                        "https://api.digitalocean.com/v2/firewalls?page=2&per_page=200"}}}
            return {"firewalls": [{"id": "2", "tags": [], "inbound_rules": [
                    {"sources": {"tags": [SELECTOR]}}], "outbound_rules": None}],
                    "meta": {"total": 2}, "links": {"pages": {}}}
        row = None
        if self.attachment == kind:
            row = {"id": "1", "tags": [SELECTOR]}
            if kind == "images":
                row["private"] = True
            if kind == "snapshots":
                row["resource_type"] = "volume"
        if kind == "firewalls" and self.attachment in {"inbound_rule", "outbound_rule", "malformed_rule", "null_rules", "missing_rules"}:
            row = {"id": "1", "tags": [], "inbound_rules": [], "outbound_rules": []}
            if self.attachment == "inbound_rule":
                row["inbound_rules"] = [{"sources": {"tags": [SELECTOR]}}]
            elif self.attachment == "outbound_rule":
                row["outbound_rules"] = [{"destinations": {"tags": [SELECTOR]}}]
            else:
                if self.attachment == "malformed_rule":
                    row["inbound_rules"] = [{"sources": {"tags": "not-a-list"}}]
                elif self.attachment == "null_rules":
                    row["inbound_rules"] = None
                    row["outbound_rules"] = None
                elif self.attachment == "missing_rules":
                    del row["inbound_rules"]
        if kind == "firewalls" and row is not None and self.attachment != "missing_rules":
            row.setdefault("inbound_rules", [])
            row.setdefault("outbound_rules", [])
        return {key: [] if row is None else [row], "meta": {"total": 0 if row is None else 1},
                "links": {"pages": {}}}


def run(post, get):
    events = []
    readable = reserve_and_verify_selector(
        SELECTOR, "secret", fence=lambda: events.append("fence"),
        on_intent=lambda: events.append("intent"),
        on_receipt=lambda status, name: events.append(("receipt", status, name)),
        post_transport=post, get_transport=get,
    )
    return events, readable


def test_exact_201_receipt_precedes_complete_visibility():
    post, get = Post(), Get()
    events, readable = run(post, get)
    assert post.calls == 1
    assert events.index("intent") < events.index(("receipt", 201, SELECTOR))
    assert set(readable) == {"droplets", "gpu_droplets", "images", "volumes",
                             "volume_snapshots"}
    assert len(get.paths) == 7
    assert not any(path.startswith("/databases") for path in get.paths)
    assert get.paths[-1].startswith("/firewalls?")


def test_nullable_firewall_rules_are_empty_after_complete_read():
    _, readable = run(Post(), Get(attachment="null_rules"))
    assert "droplets" in readable


@pytest.mark.parametrize("response,error", [
    (ReservationResponse(200, {"tag": {"name": SELECTOR}}), None),
    (ReservationResponse(201, {"tag": {"name": "other-selector"}}), None),
    (ReservationResponse(409, {"message": "duplicate"}), None),
    (None, TimeoutError("secret-bearing timeout")),
])
def test_ambiguous_or_wrong_post_never_checks_membership(response, error):
    post, get = Post(response, error), Get()
    events = []
    with pytest.raises(SelectorReservationError) as exc:
        reserve_and_verify_selector(
            SELECTOR, "secret", fence=lambda: None,
            on_intent=lambda: events.append("intent"),
            on_receipt=lambda *_: events.append("receipt"),
            post_transport=post, get_transport=get,
        )
    assert events == ["intent"] and post.calls == 1 and get.paths == []
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("attachment", ["droplets", "firewalls", "inbound_rule",
                                             "outbound_rule", "malformed_rule", "missing_rules",
                                             "second_page_rule"])
def test_external_attachment_blocks_exclusive_visibility(attachment):
    post, get = Post(), Get(attachment=attachment)
    with pytest.raises(SelectorReservationError):
        run(post, get)
    assert post.calls == 1
