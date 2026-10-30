# Copyright (c) 2026, Oracle and/or its affiliates.
"""Test-only reseal of a complete synthetic append after review receipt changes."""

from dataclasses import asdict, replace
import hashlib
import json

from test_provider_keyed_host_policy_interpreter import _fixture as firewall_fixture, PREDECESSOR
from test_provider_keyed_host_surface_interpreter import (
    _fixture as surface_fixture, _versioned_proof,
)
from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection

from app.domain import JobEvent
from app.storage.job_repository import job_event_digest


def strict_edge_raw_fixture(monkeypatch, *, manifest_sha, chain_id, address,
                            provider_id, region, public_ip, hostname, middle_ip,
                            admin_public_key, transport_public_key):
    """Compose real interpreter fixtures; pin their synthetic Ubuntu baseline."""
    firewall, _policy, _outputs = firewall_fixture(monkeypatch)
    surface, _surface_policy, _admin, _transport = surface_fixture(monkeypatch, role="edge")
    surface = _versioned_proof(surface).surface
    identity = replace(firewall.identity,
        manifest_sha256=manifest_sha, chain_id=chain_id,
        terraform_address=address, provider_instance_id=provider_id,
        region=region, public_ipv4=public_ip, hostname=hostname)

    def snapshot(value):
        commands = []
        for item in value.commands:
            output = item.raw_output.replace(PREDECESSOR, middle_ip)
            commands.append(replace(item, raw_output=output,
                sha256=hashlib.sha256(output.encode()).hexdigest(),
                byte_count=len(output.encode())))
        return replace(value, identity=identity, commands=tuple(commands))

    accounts = tuple(replace_account(row, admin_public_key, transport_public_key)
                     for row in surface.accounts)
    surface = replace(surface, identity=identity, boot_id=identity.boot_id,
        predecessor_ipv4=middle_ip,
        ssh_connection=(middle_ip, 50000, public_ip, 22), accounts=accounts)
    collection = DigitalOceanRawHostCollection(
        identity, snapshot(firewall.firewall_before), surface,
        snapshot(firewall.firewall_after))
    return json.dumps(asdict(collection), sort_keys=True, separators=(",", ":")).encode()


def replace_account(row, admin_public_key, transport_public_key):
    name = row[0]
    key = admin_public_key if name == "user" else transport_public_key
    return (name, key.strip() + "\n", *row[2:])


def reseal_completed_append_after_plan_change(jobs, parent_id="job-append"):
    """Keep exact Apply reservation and parent child hashes after a plan edit."""
    parent = jobs.get(parent_id)
    plan = jobs.get(parent.input["planJobId"])
    apply = jobs.get(parent.input["applyJobId"])
    plan_sha = job_event_digest(plan.events)
    receipt = plan.events[-1].data
    def reseal(event):
        if event.message != "provider append command intent fenced":
            return event
        phase = event.data["phase"]
        argv = [receipt["terraformBinaryPath"],
                *(["show", "-json", receipt["planPath"]] if phase == "show" else
                  ["apply", "-input=false", "-lock=true", "-no-color",
                   receipt["planPath"]])]
        return replace(event, data={**event.data, "argvSha256": hashlib.sha256(
            json.dumps(argv, separators=(",", ":")).encode()).hexdigest()})
    new_apply = jobs.save(replace(apply, events=[
        replace(apply.events[0], data={**apply.events[0].data,
                                       "planJournalSha256": plan_sha}),
        *(reseal(event) for event in apply.events[1:]),
    ]))
    seal = dict(parent.events[-2].data)
    seal["planJournalSha256"] = plan_sha
    seal["applyJournalSha256"] = job_event_digest(new_apply.events)
    return jobs.save(replace(parent,
        input={**parent.input, "planJournalSha256": plan_sha},
        events=[*parent.events[:-2],
                JobEvent(parent.events[-2].sequence, "info",
                         "strict append host proof completed", seal),
                parent.events[-1]]))
