# Copyright (c) 2026, Oracle and/or its affiliates.
"""The mixed writer may trust only an exact one-shot four-host child receipt."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedHostRow, MixedInitialPublicationSource, MixedProviderState,
)
from app.services.provider_keyed_mixed_strict_host_receipt import (
    ACTION, MixedStrictHostProofAttention, MixedStrictHostReceipt, _sha,
    child_id, validate_receipt_child,
)
from app.services.provider_keyed_mixed_linode_host_probe import _sudo_hostname_warning
from app.storage.job_repository import StoredJobRun, job_event_digest


HASH = "a" * 64
TOKEN = "b" * 32


def _source() -> MixedInitialPublicationSource:
    hosts = tuple(MixedHostRow(
        f"chain-{provider}", provider, role, f"{provider}-{role}",
        f'{"linode_instance" if provider == "linode" else "digitalocean_droplet"}.{role}["{provider}"]',
        str(number), f"203.0.113.{number}", "proxy01",
    ) for provider, start in (("linode", 10), ("digitalocean", 20))
      for role, number in (("middle", start), ("edge", start + 1)))
    states = tuple(MixedProviderState(provider, HASH, "lineage", 1, (), HASH)
                   for provider in ("linode", "digitalocean"))
    return MixedInitialPublicationSource(
        "eng-test", "job-core", "plan-1", "rev-1", "job-parent",
        ("linode", "digitalocean"), ("chain-linode", "chain-digitalocean"),
        HASH, HASH, HASH, states, hosts)


def _child(source: MixedInitialPublicationSource) -> tuple[StoredJobRun, MixedStrictHostReceipt]:
    source_sha = _sha(__import__("dataclasses").asdict(source))
    events = [
        JobEvent(1, "info", "mixed strict host proof reserved", {"sourceSha256": source_sha}),
        JobEvent(2, "info", "mixed strict host proof started", {"sourceSha256": source_sha}),
    ]
    for host in source.host_rows:
        fields = {"provider": host.provider, "hostname": host.hostname,
                  "terraformAddress": host.terraform_address,
                  "providerInstanceId": host.provider_instance_id}
        scratch = f"/private/tmp/{host.hostname}"
        events.append(JobEvent(len(events) + 1, "info", "mixed strict host scratch intended",
                               {**fields, "scratchPath": scratch}))
        for index in range(4):
            invocation = f"{host.hostname}-{index}"
            events.extend([
                JobEvent(len(events) + 1, "info", "mixed strict host command intended",
                         {**fields, "invocationId": invocation, "argvSha256": HASH,
                          "scratchPath": scratch}),
                JobEvent(len(events) + 2, "info", "mixed strict host command started before GO",
                         {**fields, "invocationId": invocation, "bootId": "boot",
                          "pid": 10, "pgid": 10, "startTicks": 20}),
                JobEvent(len(events) + 3, "info", "mixed strict host command result fenced",
                         {**fields, "invocationId": invocation, "returnCode": 0,
                          "stdoutBytes": 123, "stderrBytes": 0,
                          "stdoutTruncated": False, "stderrTruncated": False}),
            ])
        events.append(JobEvent(len(events) + 1, "info", "mixed strict host capture completed",
                               {**fields, "collectionSha256": HASH}))
    evidence = "/private/tmp/private-proof.json"
    events.append(JobEvent(len(events) + 1, "info", "mixed strict host proof completed", {
        "sourceSha256": source_sha, "hostEvidenceSha256": HASH,
        "hostnames": [host.hostname for host in source.host_rows],
        "evidencePath": evidence,
    }))
    inputs = {
        "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
        "corePlanId": source.core_plan_id, "mixedParentId": source.parent_job_id,
        "handoffJournalSha256": source.parent_journal_sha256,
        "bindingJobId": "job-provider-keyed-mixed-host-binding-core",
        "bindingManifestSha256": source.binding_manifest_sha256,
        "bootstrapJobId": "job-provider-keyed-mixed-host-worker-core",
        "bootstrapJournalSha256": source.host_worker_journal_sha256,
        "mutation": False, "claimOwner": "owner", "claimToken": TOKEN,
        "claimClaimedAt": "2026-10-19T00:00:00+00:00",
        "claimHeartbeatAt": "2026-10-19T00:00:00+00:00",
        "claimExpiresAt": "2026-10-19T01:00:00+00:00",
    }
    child = StoredJobRun(
        child_id(source.core_job_id), ACTION, "running", f"engagement:{source.engagement_id}",
        "engagement", source.engagement_id, "example_operator_three", inputs, [],
        datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(),
        None, events)
    receipt = MixedStrictHostReceipt(
        source, child.id, job_event_digest(events), HASH,
        tuple(row.hostname for row in source.host_rows),
        tuple(row.provider_instance_id for row in source.host_rows),
        evidence, "owner", TOKEN, HASH, HASH)
    return child, receipt


def test_exact_four_host_journal_is_valid_for_writer() -> None:
    source = _source()
    child, receipt = _child(source)
    validate_receipt_child(source, child, receipt)


def test_source_drift_is_rejected() -> None:
    source = _source()
    child, receipt = _child(source)
    changed = replace(source, parent_journal_sha256="c" * 64)
    with pytest.raises(MixedStrictHostProofAttention):
        validate_receipt_child(changed, child, receipt)


def test_host_two_failed_command_is_not_complete() -> None:
    source = _source()
    child, receipt = _child(source)
    events = list(child.events)
    second_host_result = 2 + 14 + 1 + 2
    events[second_host_result] = replace(
        events[second_host_result], data={**events[second_host_result].data, "returnCode": 1})
    changed = replace(child, events=events)
    changed_receipt = replace(receipt, child_event_sha256=job_event_digest(events))
    with pytest.raises(MixedStrictHostProofAttention):
        validate_receipt_child(source, changed, changed_receipt)


def test_uncertain_started_command_is_not_complete() -> None:
    source = _source()
    child, receipt = _child(source)
    events = list(child.events)
    del events[5]
    events = [replace(event, sequence=index) for index, event in enumerate(events, 1)]
    changed = replace(child, events=events)
    changed_receipt = replace(receipt, child_event_sha256=job_event_digest(events))
    with pytest.raises(MixedStrictHostProofAttention):
        validate_receipt_child(source, changed, changed_receipt)


def test_digitalocean_warning_is_not_allowed() -> None:
    source = _source()
    child, receipt = _child(source)
    events = list(child.events)
    do_result = 2 + 14 * 2 + 3
    events[do_result] = replace(events[do_result],
                                data={**events[do_result].data, "stderrBytes": 49})
    changed = replace(child, events=events)
    changed_receipt = replace(receipt, child_event_sha256=job_event_digest(events))
    with pytest.raises(MixedStrictHostProofAttention):
        validate_receipt_child(source, changed, changed_receipt)


def test_only_exact_linode_sudo_warning_length_is_allowed() -> None:
    source = _source()
    child, receipt = _child(source)
    events = list(child.events)
    index = 2 + 1 + 3 + 2  # first Linode host, firewall-before result
    expected = len(_sudo_hostname_warning(source.host_rows[0].hostname).encode())
    events[index] = replace(events[index],
                            data={**events[index].data, "stderrBytes": expected})
    changed = replace(child, events=events)
    changed_receipt = replace(receipt, child_event_sha256=job_event_digest(events))
    validate_receipt_child(source, changed, changed_receipt)
    events[index] = replace(events[index],
                            data={**events[index].data, "stderrBytes": expected + 1})
    changed = replace(child, events=events)
    changed_receipt = replace(receipt, child_event_sha256=job_event_digest(events))
    with pytest.raises(MixedStrictHostProofAttention):
        validate_receipt_child(source, changed, changed_receipt)


def test_existing_deterministic_child_blocks_host_contact() -> None:
    from app.services.provider_keyed_mixed_initial_host_proof import (
        collect_mixed_initial_strict_host_proof,
    )

    class ExistingChild:
        status = "succeeded"

    class Jobs:
        def get(self, job_id):
            if job_id == child_id("job-core"):
                return ExistingChild()
            raise AssertionError("the worker must stop before reading any other row")

    def never_contact(**_kwargs):
        raise AssertionError("host contact must not occur")

    with pytest.raises(MixedStrictHostProofAttention, match="no host contact"):
        collect_mixed_initial_strict_host_proof(
            "eng-test", "job-core", environment="devtest", job_repository=Jobs(),
            linode_collector=never_contact,
            digitalocean_middle_collector=never_contact,
            digitalocean_edge_collector=never_contact)
