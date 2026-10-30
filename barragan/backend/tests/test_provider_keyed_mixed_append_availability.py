# Copyright (c) 2026, Oracle and/or its affiliates.
import hashlib
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_append_availability as availability


class Catalog:
    def __init__(self, body=None, error=None):
        self.body, self.error, self.calls = body, error, []

    def request(self, base, method, path, token):
        self.calls.append((method, path, token))
        if self.error:
            raise self.error
        return self.body


@pytest.fixture
def source(monkeypatch):
    credential = SimpleNamespace(id="retained-do", provider="digitalocean", status="active",
        is_default=True, encrypted_secret="encrypted", updated_at="original")
    repository = SimpleNamespace(get=lambda identifier: credential if identifier == credential.id else None,
                                 get_default=lambda provider: credential)
    monkeypatch.setattr(availability, "decrypt_secret_value", lambda value: "private-token")
    policy = {"provider_connection_id": credential.id, "credential_updated_at": credential.updated_at,
              "credential_secret_sha256": hashlib.sha256(b"encrypted").hexdigest()}
    return policy, credential, repository


def body(sizes):
    return {"regions": [{"slug": "nyc3", "available": True, "sizes": sizes}],
            "links": {}, "meta": {"total": 1}}


def test_exact_connection_live_catalog_and_only_new_edge(source):
    policy, _, repository = source
    catalog = Catalog(body(["inherited-size"]))
    availability.require_mixed_append_digitalocean_availability(policy, "nyc3", "inherited-size",
        credential_repository=repository, catalog_transport=catalog)
    assert catalog.calls == [("GET", "/regions?per_page=200", "private-token")]


@pytest.mark.parametrize("response,error", [
    (body([]), None), (body(["different-size"]), None),
    ({**body(["inherited-size"]), "meta": {"total": 2}}, None),
    ({**body(["inherited-size"]), "links": {"pages": {"next": "unread"}}}, None),
    (None, TimeoutError("sensitive provider detail")),
])
def test_unavailable_incomplete_and_failed_catalog_are_safe(source, response, error):
    policy, _, repository = source
    with pytest.raises(availability.MixedAppendAvailabilityAttention) as failure:
        availability.require_mixed_append_digitalocean_availability(policy, "nyc3", "inherited-size",
            credential_repository=repository, catalog_transport=Catalog(response, error))
    assert "no append started" in str(failure.value)
    assert "private-token" not in str(failure.value)
    assert "sensitive" not in str(failure.value)


@pytest.mark.parametrize("change", ["default", "snapshot", "inactive", "provider"])
def test_default_alias_or_snapshot_mismatch_never_uses_other_connection(source, change):
    policy, credential, repository = source
    if change == "default":
        repository.get_default = lambda _: SimpleNamespace(id="different-default")
    elif change == "snapshot":
        credential.updated_at = "rotated"
    elif change == "inactive":
        credential.status = "disabled"
    else:
        credential.provider = "linode"
    catalog = Catalog(body(["inherited-size"]))
    with pytest.raises(availability.MixedAppendAvailabilityAttention):
        availability.require_mixed_append_digitalocean_availability(policy, "nyc3", "inherited-size",
            credential_repository=repository, catalog_transport=catalog)
    assert catalog.calls == []


def test_connection_changed_during_read_is_rejected(source):
    policy, credential, repository = source
    class ChangingCatalog(Catalog):
        def request(self, *args):
            credential.updated_at = "rotated"
            return body(["inherited-size"])
    with pytest.raises(availability.MixedAppendAvailabilityAttention):
        availability.require_mixed_append_digitalocean_availability(policy, "nyc3", "inherited-size",
            credential_repository=repository, catalog_transport=ChangingCatalog())


def test_fresh_public_review_preserves_only_typed_availability_error(monkeypatch):
    from app.services import provider_keyed_mixed_append_review_runtime as review
    from app.services.provider_keyed_mixed_append_plan_context import MixedAppendAvailabilityContextAttention
    monkeypatch.setattr(review, "mixed_append_review_status", lambda *args, **kwargs: None)
    def unavailable(*args, **kwargs):
        raise MixedAppendAvailabilityContextAttention("DigitalOcean availability could not be verified; no append started.")
    monkeypatch.setattr(review, "derive_mixed_append_review_request", unavailable)
    monkeypatch.setattr(review.pair, "reserve_mixed_append_pair", lambda *args, **kwargs: pytest.fail("must not reserve"))
    with pytest.raises(review.MixedAppendReviewAttention, match="DigitalOcean availability could not be verified"):
        review.begin_mixed_append_review("eng-test", "job-core", {}, "operator", job_repository=SimpleNamespace())
    def arbitrary(*args, **kwargs):
        raise ValueError("sensitive provider response")
    monkeypatch.setattr(review, "derive_mixed_append_review_request", arbitrary)
    with pytest.raises(review.MixedAppendReviewAttention) as error:
        review.begin_mixed_append_review("eng-test", "job-core", {}, "operator", job_repository=SimpleNamespace())
    assert "sensitive" not in str(error.value)


def test_canonical_core_intent_is_not_an_independent_binding(client):
    from app.domain import JobEvent
    core = SimpleNamespace(action="pilot_standard_rti_guarded_execute", events=[
        JobEvent(1, "info", "core channel intent", {"outboundChannels": [{"name": "SSH intent"}]})])
    jobs = SimpleNamespace(list_for_engagement=lambda _: [core])
    domains = SimpleNamespace(list_assignments=lambda **kwargs: [])
    with client.application.storage_context():
        availability.require_no_independent_mixed_append_bindings("eng-pristine-intent", jobs=jobs,
            domain_repository=domains)
        domains.list_assignments = lambda **kwargs: ["owned-domain"]
        with pytest.raises(availability.MixedAppendAvailabilityAttention, match="before configuring independent"):
            availability.require_no_independent_mixed_append_bindings("eng-pristine-intent", jobs=jobs,
                domain_repository=domains)
        domains.list_assignments = lambda **kwargs: []
        jobs.list_for_engagement = lambda _: [SimpleNamespace(action="inbound_channel_apply")]
        with pytest.raises(availability.MixedAppendAvailabilityAttention):
            availability.require_no_independent_mixed_append_bindings("eng-pristine-intent", jobs=jobs,
                domain_repository=domains)
