# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network one-shot Inspector submit composition tests."""

from dataclasses import replace
import hashlib

import pytest

from app.services.observer_checks import InspectorCreateStage, InspectorStagedSubmission, _inspector_firewall_tag
from app.services.provider_keyed_inspector_create_intent import reserve_keyed_inspector_create_intent
from app.services.provider_keyed_inspector_submit import (
    ProviderKeyedInspectorSubmitAttention, submit_keyed_inspector_once,
)
from app.storage.job_repository import job_event_digest
from test_provider_keyed_inspector_create_intent import _case


def setup(tmp_path, provider="linode"):
    jobs, parent, scope, plans, child, settings, resources, credentials, key, options = _case(tmp_path)
    if provider == "digitalocean":
        settings.row = replace(settings.row, provider=provider, region="nyc3", size="s-1vcpu-1gb")
        credentials.rows[0] = replace(credentials.rows[0], provider=provider, alias="inspector-do")
    public = "ssh-ed25519 " + "A" * 68
    fingerprint = hashlib.sha256(public.encode()).hexdigest()
    key[0] = fingerprint
    receipt = reserve_keyed_inspector_create_intent(parent.id, **options)
    kw = dict(environment="devtest", job_repository=jobs, plan_repository=plans,
              settings_repository=settings, provider_resource_repository=resources,
              credential_repository=credentials, lease_lookup=options["lease_lookup"],
              public_key_reader=lambda: (public, key[0]), decrypt_secret=lambda encrypted: "test-token",
              now=options["now"])
    return jobs, parent, plans, settings, credentials, key, receipt, kw


class FakeProvider:
    def __init__(self, kind, source, *, fail_at=None, mismatch=False):
        self.kind = kind
        self.source = source
        self.fail_at = fail_at
        self.mismatch = mismatch
        self.calls = 0

    def submit_staged_inspector(self, *, token, name, region, size, public_key, stage_hook):
        self.calls += 1
        assert self.source == "8.8.8.8/32"
        assert token == "test-token" and public_key.startswith("ssh-ed25519 ")
        tag = _inspector_firewall_tag(name) if self.kind == "digitalocean" else ""
        firewall = "fw-42" if self.kind == "digitalocean" else "42"
        host = "456" if self.kind == "digitalocean" else "123"
        stages = ([InspectorCreateStage(self.kind, name, "firewall", "before_post"),
                   InspectorCreateStage(self.kind, name, "firewall", "response_received", resource_id=firewall),
                   InspectorCreateStage(self.kind, name, "instance", "before_post", firewall_id=firewall),
                   InspectorCreateStage(self.kind, name, "instance", "response_received", resource_id=host, firewall_id=firewall)]
                  if self.kind == "linode" else [
                   InspectorCreateStage(self.kind, name, "tag", "before_post", tag_name=tag),
                   InspectorCreateStage(self.kind, name, "tag", "response_received", tag_name=tag),
                   InspectorCreateStage(self.kind, name, "firewall", "before_post", tag_name=tag),
                   InspectorCreateStage(self.kind, name, "firewall", "response_received", resource_id=firewall, firewall_id=firewall, tag_name=tag),
                   InspectorCreateStage(self.kind, name, "droplet", "before_post", firewall_id=firewall, tag_name=tag),
                   InspectorCreateStage(self.kind, name, "droplet", "response_received", resource_id=host, firewall_id=firewall, droplet_id=host, tag_name=tag),
                   InspectorCreateStage(self.kind, name, "attachment", "before_post", firewall_id=firewall, droplet_id=host, tag_name=tag),
                   InspectorCreateStage(self.kind, name, "attachment", "response_received", firewall_id=firewall, droplet_id=host, tag_name=tag)])
        for index, stage in enumerate(stages):
            stage_hook(stage)
            if self.fail_at == index:
                raise RuntimeError("secret provider error")
        return InspectorStagedSubmission(self.kind, name, "999" if self.mismatch else host, firewall, tag, False)


def test_submit_once_records_complete_stages_and_returns_unverified(tmp_path):
    jobs, _parent, _plans, _settings, _credentials, _key, receipt, kw = setup(tmp_path)
    provider = FakeProvider("linode", "8.8.8.8/32")
    result = submit_keyed_inspector_once(receipt, provider_factory=lambda k, source: provider, **kw)
    assert result.status == "submitted_unverified"
    assert result.provider == "linode" and result.host_id == "123"
    assert len(jobs.get(receipt.coordinator_job_id).events) == 9
    assert provider.calls == 1
    assert "test-token" not in repr(result)
    assert "ENCRYPTED-SECRET" not in repr(result)


def test_forged_digitalocean_intent_cannot_submit_to_provider(tmp_path):
    jobs, _parent, _plans, settings, _credentials, _key, receipt, kw = setup(tmp_path)
    child = jobs.get(receipt.coordinator_job_id)
    last = child.events[-1]
    forged = replace(last, data={**last.data, "provider": "digitalocean"})
    jobs.save(replace(child, events=[*child.events[:-1], forged]))
    settings.row = replace(settings.row, provider="digitalocean")
    receipt = replace(receipt, event_digest=job_event_digest(jobs.get(child.id).events))
    provider = FakeProvider("digitalocean", "8.8.8.8/32")
    factories = []
    with pytest.raises(ProviderKeyedInspectorSubmitAttention):
        submit_keyed_inspector_once(receipt, provider_factory=lambda k, source: factories.append(k) or provider, **kw)
    assert factories == [] and provider.calls == 0


def test_provider_factory_settings_race_cannot_start_submission(tmp_path):
    jobs, _parent, _plans, settings, _credentials, _key, receipt, kw = setup(tmp_path)
    before = jobs.get(receipt.coordinator_job_id)
    provider = FakeProvider("linode", "8.8.8.8/32")

    def factory(kind, source):
        assert kind == "linode" and source == "8.8.8.8/32"
        settings.row = replace(settings.row, provider="digitalocean")
        return provider

    with pytest.raises(ProviderKeyedInspectorSubmitAttention):
        submit_keyed_inspector_once(receipt, provider_factory=factory, **kw)
    assert provider.calls == 0
    assert jobs.get(receipt.coordinator_job_id) == before


@pytest.mark.parametrize("drift", ["credential", "replaced_secret", "key", "claim", "decrypt"])
def test_preflight_veto_has_no_provider_call(drift, tmp_path):
    jobs, _parent, _plans, _settings, credentials, key, receipt, kw = setup(tmp_path)
    if drift == "credential":
        def change_after_snapshot(value):
            credentials.rows[0] = replace(credentials.rows[0], encrypted_secret="changed")
            return "test-token"
        kw["decrypt_secret"] = change_after_snapshot
    elif drift == "replaced_secret":
        credentials.rows[0] = replace(credentials.rows[0], encrypted_secret="replacement-ciphertext")
    elif drift == "key":
        key[0] = "f" * 64
    elif drift == "claim":
        row = jobs.get(receipt.coordinator_job_id)
        jobs.save(replace(row, input={**row.input, "claimToken": "b" * 32}))
    else:
        kw["decrypt_secret"] = lambda value: (_ for _ in ()).throw(ValueError("secret"))
    provider = FakeProvider("linode", "8.8.8.8/32")
    with pytest.raises(ProviderKeyedInspectorSubmitAttention) as error:
        submit_keyed_inspector_once(receipt, provider_factory=lambda k, source: provider, **kw)
    assert provider.calls == 0
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("fail_at,mismatch", [(0, False), (1, False), (None, True)])
def test_partial_or_mismatched_submission_is_attention_without_retry(fail_at, mismatch, tmp_path):
    jobs, _parent, _plans, _settings, _credentials, _key, receipt, kw = setup(tmp_path)
    provider = FakeProvider("linode", "8.8.8.8/32", fail_at=fail_at, mismatch=mismatch)
    with pytest.raises(ProviderKeyedInspectorSubmitAttention):
        submit_keyed_inspector_once(receipt, provider_factory=lambda k, source: provider, **kw)
    assert provider.calls == 1
    assert len(jobs.get(receipt.coordinator_job_id).events) >= 6
    with pytest.raises(ProviderKeyedInspectorSubmitAttention):
        submit_keyed_inspector_once(receipt, provider_factory=lambda k, source: provider, **kw)
    assert provider.calls == 1
