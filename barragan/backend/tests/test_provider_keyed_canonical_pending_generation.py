# Copyright (c) 2026, Oracle and/or its affiliates.
"""One persisted keyed generation, from reviewed core intent toward teardown.

This fixture uses a disposable SQLite file and local upstream Git checkout.
Only Terraform, provider API, and host command transports may be simulated.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
from uuid import uuid4

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import (
    _fingerprint, preview_engagement_teardown, start_engagement_teardown,
)
from app.services import core_deployment_plans as core_review
from app.services import provider_keyed_initial_plan_gate as plan_gate
from app.services import provider_keyed_saved_plan_runner as terraform_runner
from app.services import provider_keyed_postapply_preflight as postapply
from app.services.provider_keyed_initial_apply_job import (
    ProviderKeyedInitialApplyJobError, run_fresh_digitalocean_initial_apply_job,
)
from app.services.provider_keyed_initial_attachment_adapter import (
    derive_digitalocean_initial_attachment_intent,
)
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentError, reconcile_digitalocean_initial_attachment,
    require_digitalocean_pre_destroy_membership,
)
from app.services.provider_keyed_host_binding import bind_initial_digitalocean_host_identity
from app.services.provider_keyed_initial_bootstrap import (
    ProviderKeyedInitialBootstrapError, bootstrap_initial_digitalocean_chains,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_postapply_preflight import (
    ProviderKeyedPostapplyPreflightError, read_applied_digitalocean_provider_for_teardown,
)
from app.services.provider_keyed_selector_reservation import ReservationResponse
from app.services.provider_keyed_comprehensive_teardown import (
    ProviderKeyedComprehensiveTeardownAttention, ProviderKeyedComprehensiveTeardownError, _boundary,
    run_provider_keyed_comprehensive_handoff, run_provider_keyed_destroy_preview_from_ready,
    publish_provider_keyed_destroy_absence, recognize_provider_keyed_destroy_absence,
)
from app.services.provider_keyed_pending_retirement import (
    retire_pending_keyed_group_after_absence, recognize_pending_keyed_group_retired,
)
from app.services.provider_keyed_core_destroy_preview import (
    ACTION as CORE_DESTROY_PREVIEW_ACTION, KeyedCoreDestroyPreviewAttention,
    preview_pending_keyed_oci_core_destroy,
)
from app.services.provider_keyed_destroy_apply_continuation import (
    continue_digitalocean_keyed_destroy_apply, prove_live_keyed_inspector_before_destroy_go,
)
from app.services.provider_keyed_destroy_absence_preflight import (
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services import provider_keyed_initial_destroy_plan_job as destroy_preview_service
from app.services.provider_keyed_initial_destroy_plan_job import (
    ACTION as DESTROY_PREVIEW_ACTION, run_digitalocean_initial_destroy_plan_job,
)
from app.services.provider_keyed_initial_destroy_apply_job import (
    preflight_digitalocean_initial_destroy_apply, run_digitalocean_initial_destroy_apply_job,
)
from app.services.provider_keyed_initial_teardown import (
    ProviderKeyedTeardownPreviewUncertainError, _remove_staging_checked,
    _stage_at_reviewed_path, _state_resources,
)
from app.services.provider_keyed_inspector_preflight import (
    ProviderKeyedInspectorPreflightRequired, inspect_prepared_keyed_teardown_inspector,
)
from app.services import provider_keyed_inspector_create_intent as inspector_intent
from app.services.provider_keyed_inspector_create_intent import (
    ProviderKeyedInspectorCreateAttention, ProviderKeyedInspectorCreateIntentError,
    recorded_keyed_inspector_intent, reserve_keyed_inspector_create_intent,
)
from app.services import provider_keyed_inspector_submit as inspector_submit
from app.services.provider_keyed_inspector_submit import (
    ProviderKeyedInspectorSubmitAttention, submit_keyed_inspector_once,
)
from app.services.provider_keyed_inspector_settlement import settle_submitted_keyed_inspector
from app.services.provider_keyed_inspector_materialize import (
    materialize_proved_keyed_inspector, recover_materialized_keyed_inspector,
)
from app.services.provider_keyed_inspector_prepare_intent import (
    InspectorPreparationCapability, InspectorPreparationIntentAttention,
    begin_keyed_inspector_preparation,
)
from app.services.provider_keyed_inspector_prepare_execute import (
    InspectorPreparationExecutionAttention, execute_reserved_keyed_inspector_preparation,
)
from app.services.provider_keyed_inspector_preparation_proof import (
    InspectorSupportHostProofCapability, prove_prepared_keyed_inspector_support_host,
)
from app.services.provider_keyed_inspector_readiness_publish import (
    InspectorReadinessPublicationAttention, publish_proved_keyed_inspector_readiness,
    recognize_published_keyed_inspector_readiness,
)
from app.services import provider_keyed_inspector_prepare_binder as inspector_binder
from app.services import observer_checks
from app.services.observer_checks import (
    INSPECTOR_RESOURCE_SOURCE, LinodeObserverProvider, _inspector_firewall_label,
)
from app.services.credentials import encrypt_secret_value, test_master_key as fixture_master_key
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION
from app.services.provider_keyed_initial_continuation import (
    _new_job, _job_ids, start_fresh_digitalocean_initial_continuation,
)
from app.services.provider_keyed_initial_plan_job import (
    ACTION as PLAN_ACTION, ProviderKeyedInitialPlanJobError, _expected_inventory, _local_file,
    run_fresh_digitalocean_initial_plan_job,
)
from app.services.provider_keyed_planned_state_preflight import (
    ProviderKeyedPlannedStatePreflightError, preflight_planned_digitalocean_provider,
)
from app.services.provider_keyed_runtime_preflight import (
    _db_lease_lookup, preflight_fresh_digitalocean_provider,
)
from app.services.provider_keyed_teardown_quiescence import (
    ProviderKeyedTeardownQuiescenceError, audit_pending_provider_keyed_bootstrap,
    audit_terminal_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.provider_keyed_sketch import prepare_provider_keyed_workspace, reserve_provider_topology
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key, retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import (
    ensure_sketch_transport_ssh_key, retrieve_sketch_transport_ssh_key,
)
from app.storage.credential_repository import SqlAlchemyCredentialRepository, StoredCredential
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.observer_settings_repository import (
    SqlAlchemyObserverSettingsRepository, StoredInspectorSettings,
)
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository
from redteam_infra_test_fixtures import checkout_local_pinned_source
from test_provider_keyed_persisted_intent import _inputs
from test_provider_keyed_digitalocean_attachment import (
    Transport as _AttachmentTransport, prepared as attachment_prepared,
)


def _upstream_checkout(tmp_path: Path) -> Path:
    source = Path(os.environ.get(
        "BARRAGAN_TEST_REDTEAM_INFRA",
        str(Path(__file__).resolve().parents[3] / "redteam-infra"),
    )).resolve()
    if not (source / ".git").exists():
        pytest.skip("local redteam-infra checkout is unavailable")
    target = tmp_path / "reviewed-upstream"
    checkout_local_pinned_source(source, target, _SOURCE_REVISION)
    return target


def _review_scope(chains):
    return {"chains": [{
        "id": chain.chain_id,
        "assignedProxy": chain.assigned_proxy,
        "middle": {"region": chain.middle_region},
        "edges": [{key: edge[key] for key in ("id", "provider", "region")}
                  for edge in chain.edge_intents],
    } for chain in chains]}


def _seed_reviewed_generation(tmp_path: Path, monkeypatch, *, core_known_hosts=False,
                              core_artifact_hook=None):
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    monkeypatch.setenv("BARRAGAN_SKETCH_STATE_ROOT", str(state_root))
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", fixture_master_key())
    upstream = _upstream_checkout(tmp_path)
    state = db.configure(f"sqlite:///{tmp_path / 'canonical.sqlite'}")
    engagement, chains, core, plan, _profile = _inputs()
    target = engagement.input_parameters["deploymentTarget"]
    core = replace(
        core, target=f"oci-compartment:{target['name']}",
        target_type="oci_compartment", target_id=target["compartmentId"],
        created_at="2026-10-07T00:00:00+00:00",
        started_at="2026-10-07T00:00:01+00:00",
        finished_at="2026-10-07T00:01:00+00:00",
    )
    if core_known_hosts:
        # This fixture starts after core deployment. It models a safe pinned
        # core workspace; it does not claim to run the core deployment writer.
        core_root = tmp_path / "core-workspace"
        ssh_root = core_root / "ssh"
        ssh_root.mkdir(parents=True, mode=0o700)
        core_root.chmod(0o700)
        ssh_root.chmod(0o700)
        known_hosts = ssh_root / "known_hosts"
        known_hosts.write_text("8.8.8.8 ssh-ed25519 pinned-core-fixture-key\n", encoding="utf-8")
        known_hosts.chmod(0o600)
        connection_event = core.events[0]
        core = replace(core, input={**core.input, "workspaceDir": str(core_root)},
                       events=[replace(connection_event, data={
            **connection_event.data,
            "connectionDetails": [{
                "role": "homebase", "displayName": "homebase-m4t8q2z7",
                "sshAlias": "homebase-m4t8q2z7", "publicIp": "1.1.1.1",
                "sshUser": "user",
            }, *connection_event.data["connectionDetails"]],
        }), JobEvent(
            len(core.events) + 1, "info", "core workspace fixture", {"workspaceDir": str(core_root)},
        )])
    credential = StoredCredential(
        id="credential-opaque", provider="digitalocean", alias="team",
        status="active", description="", encrypted_secret=encrypt_secret_value("fixture-token"),
        is_default=True, created_at="2026-10-07T00:00:00+00:00",
        updated_at="2026-10-07T00:00:00+00:00",
    )
    with db.bind(state):
        db.create_all()
        engagements = SqlAlchemyEngagementRepository()
        sketches = SqlAlchemySketchChainRepository()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        credentials = SqlAlchemyCredentialRepository()
        engagements.save(engagement)
        for chain in chains:
            sketches.save(chain)
        credentials.save(credential)
        fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in chains}
        authorization = core_review._reviewed_keyed_sketch_authorization(
            engagement.id, _review_scope(chains), fingerprints, "ubuntu-22-04-x64",
        )
        current_credential = credentials.get(credential.id)
        plan = replace(plan,
            review={"sketchStateSchema": "provider-keyed-v2", "reviewedConfiguration": {
                "sketchAuthorization": authorization, "digitaloceanImage": "ubuntu-22-04-x64"}},
            evidence={**plan.evidence, "sketchAuthorization": authorization,
                      "keyedProviderCredentialSnapshot": {
                          "encryptedSecretSha256": hashlib.sha256(
                              current_credential.encrypted_secret.encode()).hexdigest(),
                          "updatedAt": current_credential.updated_at,
                      }},
        )
        if core_artifact_hook is not None:
            core, plan = core_artifact_hook(core, plan, engagement, tmp_path)
        jobs.save(core)
        plans.save(plan)
        assert plans.acquire(engagement.id, plan.id, "provider_keyed_initial")
    return state, state_root, upstream, engagement.id, core.id, plan.id, credential.id


def _created(address, after, unknown, sensitive):
    return {"address": address, "change": {
        "actions": ["create"], "before": None, "before_sensitive": False,
        "after": after, "after_unknown": unknown, "after_sensitive": sensitive,
    }}


def _shown_plan(intent, workspace, public_key, local_files):
    """Construct Terraform's external show result; the real gate judges it."""
    policy = intent.firewall
    ingress = [plan_gate._inbound_unknown_peer(protocol)
               for protocol in ("icmp", "tcp", "udp")]
    ingress += [plan_gate._inbound("tcp", "22", list(policy.trusted_ssh_cidrs))]
    ingress += [plan_gate._inbound("tcp", port, ["0.0.0.0/0"])
                for port in ("2222", "443", "80")]
    egress = [plan_gate._outbound(protocol, "" if protocol == "icmp" else "1-65535", "0.0.0.0/0")
              for protocol in ("icmp", "tcp", "udp")]
    ingress_unknown = [{**plan_gate._INBOUND_SOURCE_UNKNOWN,
                        "source_addresses": True if "source_addresses" not in rule else [False]}
                       for rule in ingress]
    ingress_sensitive = [{**plan_gate._INBOUND_SOURCE_UNKNOWN,
                          "source_addresses": [] if "source_addresses" not in rule else [False]}
                         for rule in ingress]
    egress_meta = [{**plan_gate._OUTBOUND_DEST_UNKNOWN, "destination_addresses": [False]}
                   for _ in egress]
    resources = []
    for address, node in intent.nodes.items():
        resources.append(_created(address, {
            **plan_gate._NODE_KNOWN_DEFAULTS, "name": node.name,
            "image": node.image, "size": node.size, "region": node.region,
            "tags": [intent.selector_tag],
        }, plan_gate._NODE_UNKNOWN, {
            "backup_policy": [], "ssh_keys": [], "tags": [False], "volume_ids": [],
        }))
    resources.append(_created("digitalocean_ssh_key.key", {
        "name": "do-key", "public_key": public_key.strip(), "timeouts": None,
    }, plan_gate._KEY_UNKNOWN, {}))
    resources.append(_created("digitalocean_firewall.firewall", {
        "name": policy.name, "tags": [intent.selector_tag], "droplet_ids": None,
        "inbound_rule": ingress, "outbound_rule": egress,
    }, {**plan_gate._COMPUTED_FIREWALL, "inbound_rule": ingress_unknown,
        "outbound_rule": egress_meta}, {
            "inbound_rule": ingress_sensitive, "outbound_rule": egress_meta,
            "pending_changes": [], "tags": [False],
        }))
    for address, after in local_files.items():
        resources.append(_created(address, after, {
            **plan_gate._COMPUTED_LOCAL,
            **({"content": True} if address.endswith("ssh_stanza[0]") else {}),
        }, {"sensitive_content": True}))
    topology = intent.topology
    return {
        "format_version": "1.2", "terraform_version": "1.15.5",
        "applyable": True, "complete": True, "errored": False,
        "prior_state": {"values": {"root_module": {}, "outputs": {}}},
        "resource_changes": resources,
        "variables": {
            "middles": {"value": topology["middles"]},
            "edge_groups": {"value": {
                key: {**group, "count": None, "ordinal_start": 1}
                for key, group in topology["edge_groups"].items()
            }},
        },
    }


def test_reviewed_generation_has_one_real_persisted_preflight(tmp_path, monkeypatch):
    state, state_root, upstream, engagement_id, core_id, plan_id, credential_id = (
        _seed_reviewed_generation(tmp_path, monkeypatch)
    )
    with db.bind(state):
        intent = preflight_fresh_digitalocean_provider(
            engagement_id, core_id, lease_owner=plan_id,
            environment="devtest", state_root=state_root,
        )
        assert intent.core_plan_id == plan_id
        assert SqlAlchemyCredentialRepository().get_default("digitalocean").id == credential_id
        assert len(intent.nodes) == 7
        workspace = prepare_provider_keyed_workspace(
            engagement_id, "digitalocean", credential_id,
            template_root=upstream, source_revision=_SOURCE_REVISION,
            root=state_root, environment="devtest", deployment_target="barragan-testing",
        )
        assert reserve_provider_topology(
            workspace, intent.topology["middles"], intent.topology["edge_groups"],
        ) == intent.topology
        keys = SqlAlchemySketchSshKeyRepository()
        ensure_sketch_ssh_key(engagement_id, keys)
        material = retrieve_sketch_ssh_key(engagement_id, keys)
        private = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "admin-private"
        output_dir = private.parent / "ssh-output"
        local_files = {
            "local_file.ansible_inventory[0]": _local_file(
                "inventory.ini", _expected_inventory(intent, private)),
            "local_file.ssh_stanza[0]": _local_file(
                str(output_dir / f"{intent.engagement_name}-sketch"), None),
        }
        plan_gate.require_digitalocean_keyed_initial_full_plan(
            json.dumps(_shown_plan(intent, workspace, material.public_key, local_files)),
            workspace=workspace, expected_nodes=intent.nodes,
            expected_ssh_key_name="do-key", expected_ssh_public_key=material.public_key.strip(),
            expected_firewall=intent.firewall, expected_local_files=local_files,
        )


def test_applied_phase_marker_accepts_only_owner_or_exact_collaborator_group(tmp_path, monkeypatch):
    marker = tmp_path / ".barragan-apply-phase.json"
    expected = {"schema": "provider-keyed-v2", "phase": "applied"}
    marker.write_text(json.dumps(expected), encoding="utf-8")
    marker.chmod(0o600)
    monkeypatch.setattr(postapply, "_collaborator_group_gid", lambda: None)
    assert postapply._applied_phase_marker(marker) == expected
    marker.chmod(0o640)
    with pytest.raises(ValueError):
        postapply._applied_phase_marker(marker)
    monkeypatch.setattr(postapply, "_collaborator_group_gid", lambda: os.getgid())
    assert postapply._applied_phase_marker(marker) == expected
    with pytest.raises(ValueError):
        postapply._json_file(marker, private=True)  # owner marker remains 0600-only
    monkeypatch.setattr(postapply, "_collaborator_group_gid", lambda: os.getgid() + 1)
    with pytest.raises(ValueError):
        postapply._applied_phase_marker(marker)
    marker.chmod(0o644)
    monkeypatch.setattr(postapply, "_collaborator_group_gid", lambda: os.getgid())
    with pytest.raises(ValueError):
        postapply._applied_phase_marker(marker)


def _write_real_initial_plan(tmp_path, monkeypatch):
    state, state_root, upstream, engagement_id, core_id, plan_id, credential_id = (
        _seed_reviewed_generation(tmp_path, monkeypatch)
    )
    commands = []
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        keys = SqlAlchemySketchSshKeyRepository()
        core = jobs.get(core_id)
        plan_job_id = _job_ids(core_id)[1]
        jobs.save(_new_job(plan_job_id, PLAN_ACTION, core, engagement_id, {
            "engagementId": engagement_id, "coreJobId": core_id, "mutation": False,
        }))
        intent = preflight_fresh_digitalocean_provider(
            engagement_id, core_id, lease_owner=plan_id,
            environment="devtest", state_root=state_root,
        )
        ensure_sketch_ssh_key(engagement_id, keys)
        material = retrieve_sketch_ssh_key(engagement_id, keys)
        fingerprint = hashlib.sha256(f"digitalocean\0{credential_id}".encode()).hexdigest()
        workspace_path = state_root / engagement_id / "provider-keyed-v2" / "digitalocean" / fingerprint
        private = workspace_path.parents[1] / ".plan-material" / "digitalocean" / "admin-private"
        output = private.parent / "ssh-output"
        local_files = {
            "local_file.ansible_inventory[0]": _local_file(
                "inventory.ini", _expected_inventory(intent, private)),
            "local_file.ssh_stanza[0]": _local_file(
                str(output / f"{intent.engagement_name}-sketch"), None),
        }
        shown = json.dumps(_shown_plan(intent, None, material.public_key, local_files))
        assert retrieve_sketch_transport_ssh_key(engagement_id) is None

        def command(args, cwd, env):
            assert cwd == workspace_path
            assert args[0] == "/usr/bin/terraform"
            phase = args[1]
            commands.append(phase)
            if phase == "version":
                return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
            if phase == "plan":
                plan_path = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("-out=")))
                # The real writer created this exact inode with O_EXCL.
                with plan_path.open("wb") as stream:
                    stream.write(b"opaque reviewed binary plan fixture")
            return subprocess.CompletedProcess(args, 0, shown if phase == "show" else "", "")

        monkeypatch.setattr(terraform_runner, "_run_command", command)
        saved = run_fresh_digitalocean_initial_plan_job(
            plan_job_id, lease_owner=plan_id, environment="devtest",
            state_root=state_root, template_root=upstream,
        )
        assert saved.status == "succeeded"
        assert commands == ["version", "init", "plan", "show"]
        assert [event.message for event in saved.events].count("reviewed provider plan saved") == 1
        transport = retrieve_sketch_transport_ssh_key(engagement_id)
        assert transport is not None and transport.private_key and transport.public_key
        assert transport.metadata.fingerprint != material.metadata.fingerprint
        assert transport.public_key not in shown
        assert transport.public_key not in json.dumps(saved.events[-1].data)
    return (state, state_root, engagement_id, core_id, plan_id, credential_id,
            plan_job_id, intent, shown, saved, commands)


def _applied_state(intent):
    resources = []
    for index, (address, node) in enumerate(sorted(intent.nodes.items()), 101):
        resource_type, remainder = address.split(".", 1)
        resource_name, key_json = remainder.split("[", 1)
        key = json.loads("[" + key_json)[0]
        resources.append({"mode": "managed", "type": resource_type, "name": resource_name,
                          "instances": [{"index_key": key, "attributes": {
                              "id": str(index), "name": node.name, "region": node.region,
                              "image": node.image, "size": node.size,
                              # Locally simulated only: DNS teardown binding
                              # requires globally routable edge addresses.
                              "ipv4_address": f"45.79.200.{index - 90}",
                              "tags": [intent.selector_tag],
                          }}]})
    resources.extend([
        {"mode": "managed", "type": "digitalocean_firewall", "name": "firewall",
         "instances": [{"attributes": {
             "id": "bb4b2611-3d72-467b-8602-280330ecd65c",
             "name": intent.firewall.name, "tags": [intent.selector_tag],
         }}]},
        {"mode": "managed", "type": "digitalocean_ssh_key", "name": "key",
         "instances": [{"attributes": {"id": "501"}}]},
        {"mode": "managed", "type": "local_file", "name": "ansible_inventory",
         "instances": [{"index_key": 0, "attributes": {"id": "/private/inventory"}}]},
        {"mode": "managed", "type": "local_file", "name": "ssh_stanza",
         "instances": [{"index_key": 0, "attributes": {"id": "/private/ssh-stanza"}}]},
    ])
    return {"version": 4, "serial": 1, "terraform_version": "1.15.5",
            "lineage": "11111111-1111-4111-8111-111111111111", "resources": resources}


class _EmptySelectorCatalog:
    """DigitalOcean GET responses only, before any infrastructure exists."""

    def __init__(self, selector):
        self.selector = selector
        self.paths = []

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token == "fixture-token"
        self.paths.append(path)
        if path == f"/tags/{self.selector}":
            return {"tag": {"name": self.selector, "resources": {"count": 0}}}
        kind = path.split("?", 1)[0].lstrip("/")
        key = "snapshots" if kind == "snapshots" else kind
        return {key: [], "meta": {"total": 0}, "links": {"pages": {}}}


class _SelectorPost:
    def __init__(self):
        self.calls = 0

    def create_tag(self, token, selector):
        assert token == "fixture-token"
        self.calls += 1
        return ReservationResponse(201, {"tag": {"name": selector}})


class _AttachmentCatalog:
    """Exact DO GET responses from the retained state-derived attachment intent."""

    def __init__(self, intent):
        self.intent = intent
        self.paths = []
        selector = intent.selector_tag
        firewall_id = intent.firewall_id

        def rule(protocol, ports, addresses, side="sources"):
            return {"protocol": protocol, "ports": ports, "action": "allow",
                    side: {"addresses": list(addresses)}}

        peers = tuple(sorted(f"{node.public_ipv4}/32" for node in intent.nodes))
        ingress = [rule("tcp", port, ("0.0.0.0/0",)) for port in ("80", "443", "2222")]
        ingress.append(rule("tcp", "22", intent.trusted_ssh_cidrs))
        ingress.extend(rule(protocol, "1-65535", peers)
                       for protocol in ("tcp", "udp", "icmp"))
        egress = [rule(protocol, "0" if protocol == "icmp" else "1-65535",
                       ("0.0.0.0/0",), "destinations")
                  for protocol in ("tcp", "udp", "icmp")]
        self.responses = {
            f"/firewalls/{firewall_id}": {"firewall": {
                "id": firewall_id, "name": intent.firewall_name,
                "status": "succeeded", "pending_changes": [],
                "tags": [selector], "droplet_ids": [],
                "inbound_rules": ingress, "outbound_rules": egress,
            }},
            f"/droplets?page=1&per_page=200&tag_name={selector}": {
                "droplets": [{"id": int(node.droplet_id), "tags": [selector]}
                             for node in intent.nodes],
                "meta": {"total": len(intent.nodes)}, "links": {},
            },
            "/droplets?page=1&per_page=200&type=gpus": {
                "droplets": [], "meta": {"total": 0}, "links": {},
            },
        }
        for node in intent.nodes:
            self.responses[f"/droplets/{node.droplet_id}"] = {"droplet": {
                "id": int(node.droplet_id), "name": node.name,
                "region": {"slug": node.region}, "tags": [selector], "status": "active",
            }}
            self.responses[f"/droplets/{node.droplet_id}/firewalls?page=1&per_page=200"] = {
                "firewalls": [{"id": firewall_id}], "meta": {"total": 1}, "links": {},
            }

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token == "fixture-token"
        self.paths.append(path)
        return json.loads(json.dumps(self.responses[path]))


class _AbsentCatalog:
    """External complete DO GET inventories after a simulated full destroy."""

    def __init__(self, selector):
        self.selector = selector
        self.paths = []

    def request(self, origin, method, path, token):
        assert origin == "https://api.digitalocean.com/v2"
        assert method == "GET" and token == "fixture-token"
        self.paths.append(path)
        key = {
            "/droplets": "droplets", "/firewalls": "firewalls",
            "/account/keys": "ssh_keys", "/tags": "tags",
        }[path.split("?", 1)[0]]
        rows = ([{"name": self.selector, "resources": {"count": 0}}]
                if key == "tags" else [])
        return {key: rows, "meta": {"total": len(rows)}, "links": {}}


def _gated_terraform(shown, state):
    calls = []

    def run(args, *, scratch_path, intent_callback, started_callback,
            heartbeat_callback, result_callback, **_kwargs):
        phase = args[1]
        assert phase in {"show", "apply"}
        calls.append(phase)
        intent = CommandIntent(
            f"fixture-{phase}", str(scratch_path),
            hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
        )
        started = StartedCommand(intent, ProcessIdentity("fixture-boot", 1001, 1001, 42))
        intent_callback(intent)
        started_callback(started)
        heartbeat_callback(started)
        payload = shown if phase == "show" else ""
        if phase == "apply":
            path = scratch_path / "terraform.tfstate"
            path.write_text(json.dumps(state), encoding="utf-8")
            path.chmod(0o600)
        result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
        return CommandResult(started, 0, payload, "", False, False)

    return run, calls


def _destroy_shown_plan(workspace_path: Path) -> str:
    """External Terraform `show -json` fixture derived from the retained state."""
    state = json.loads((workspace_path / "terraform.tfstate").read_text(encoding="utf-8"))
    topology = json.loads((workspace_path / ".barragan-topology.json").read_text(encoding="utf-8"))
    resources = _state_resources(state)
    prior = [{"address": address, "mode": "managed", "values": values}
             for address, values in sorted(resources.items())]
    return json.dumps({
        "format_version": "1.2", "terraform_version": "1.15.5",
        "applyable": True, "complete": True, "errored": False,
        "resource_changes": [{"address": address, "change": {
            "actions": ["delete"], "before": values, "after": None,
        }} for address, values in sorted(resources.items())],
        "prior_state": {"values": {"root_module": {"resources": prior}}},
        "planned_values": {"root_module": {"resources": []}},
        "variables": {
            "middles": {"value": topology["middles"]},
            "edge_groups": {"value": topology["edge_groups"]},
        },
    })


def test_destroy_preview_phase_digest_accepts_only_exact_collaborator_file(tmp_path, monkeypatch):
    marker = tmp_path / ".barragan-apply-phase.json"
    marker.write_bytes(b'{"schema":"provider-keyed-v2","phase":"applied"}')
    expected = hashlib.sha256(marker.read_bytes()).hexdigest()
    marker.chmod(0o600)
    assert destroy_preview_service._private_file_digest(marker) == expected
    assert destroy_preview_service._private_file_digest(
        marker, allow_collaborator_group=True,
    ) == expected

    marker.chmod(0o640)
    monkeypatch.setattr(destroy_preview_service, "_collaborator_group_gid", lambda: marker.stat().st_gid)
    assert destroy_preview_service._private_file_digest(
        marker, allow_collaborator_group=True,
    ) == expected
    with pytest.raises(ValueError):
        destroy_preview_service._private_file_digest(marker)

    monkeypatch.setattr(destroy_preview_service, "_collaborator_group_gid",
                        lambda: marker.stat().st_gid + 1)
    with pytest.raises(ValueError):
        destroy_preview_service._private_file_digest(marker, allow_collaborator_group=True)

    monkeypatch.setattr(destroy_preview_service, "_collaborator_group_gid", lambda: marker.stat().st_gid)
    for mode in (0o644, 0o660, 0o400):
        marker.chmod(mode)
        with pytest.raises(ValueError):
            destroy_preview_service._private_file_digest(marker, allow_collaborator_group=True)


def test_destroy_membership_phase_is_explicit_and_still_reads_exact_provider(
        attachment_prepared):
    workspace, attachment, credentials, responses = attachment_prepared
    marker = workspace.path / ".barragan-apply-phase.json"

    def check(*, expected_phase=None):
        transport = _AttachmentTransport(responses)
        options = {"expected_phase": expected_phase} if expected_phase is not None else {}
        require_digitalocean_pre_destroy_membership(
            workspace, attachment, environment="devtest",
            deployment_target="barragan-testing", credential_repository=credentials,
            transport=transport, **options,
        )
        return [path for _origin, method, path, _token in transport.requests
                if method == "GET"]

    assert check() == [
        f"/droplets?page=1&per_page=200&tag_name={attachment.selector_tag}",
        "/droplets?page=1&per_page=200&type=gpus",
        f"/firewalls/{attachment.firewall_id}",
    ]
    marker.write_text('{"schema":"provider-keyed-v2","phase":"destroy_started"}')
    with pytest.raises(DigitalOceanAttachmentError):
        check()
    assert check(expected_phase="destroy_started") == [
        f"/droplets?page=1&per_page=200&tag_name={attachment.selector_tag}",
        "/droplets?page=1&per_page=200&type=gpus",
        f"/firewalls/{attachment.firewall_id}",
    ]
    with pytest.raises(DigitalOceanAttachmentError):
        check(expected_phase="destroy_applied")
    marker.write_text('{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
    with pytest.raises(DigitalOceanAttachmentError):
        check(expected_phase="destroy_started")


@pytest.mark.skipif(sys.platform != "linux", reason="SGID inheritance regression is Linux-specific")
def test_destroy_preview_staging_under_sgid_workspace_cleans_only_owned_path(tmp_path):
    workspace = tmp_path / "shared-workspace"
    workspace.mkdir()
    workspace.chmod(0o2700)
    source = tmp_path / "reviewed-input.json"
    source.write_bytes(b'{"reviewed":true}')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    inputs = ((str(source), digest),)
    staged_path = workspace / f".barragan-destroy-inputs-{uuid4().hex}"

    staged, files, hashes, identity = _stage_at_reviewed_path(
        workspace, inputs, [source], staged_path,
    )
    assert staged == staged_path
    assert staged.stat().st_mode & 0o7777 == 0o700
    assert files == (staged / "input-0.json",)
    assert hashes == ((str(files[0]), digest),)
    _remove_staging_checked(staged, identity, frozenset({files[0].name}))
    assert not staged.exists()

    # A path with the same name but a different inode must never be removed.
    replacement_path = workspace / f".barragan-destroy-inputs-{uuid4().hex}"
    original, files, _hashes, identity = _stage_at_reviewed_path(
        workspace, inputs, [source], replacement_path,
    )
    moved = workspace / "held-owned-staging"
    original.rename(moved)
    replacement_path.mkdir(mode=0o700)
    replacement_path.chmod(0o700)
    with pytest.raises(ProviderKeyedTeardownPreviewUncertainError):
        _remove_staging_checked(replacement_path, identity, frozenset({files[0].name}))
    assert replacement_path.exists()
    assert (moved / "input-0.json").read_bytes() == source.read_bytes()


def _canonical_applied_generation(
        tmp_path, monkeypatch, instance_response_lost, *, core_artifact_hook=None):
    """The controller owns the parent and both child writers in one generation."""
    state, state_root, upstream, engagement_id, core_id, plan_id, credential_id = (
        _seed_reviewed_generation(tmp_path, monkeypatch, core_known_hosts=True,
                                  core_artifact_hook=core_artifact_hook)
    )
    with db.bind(state):
        intent = preflight_fresh_digitalocean_provider(
            engagement_id, core_id, lease_owner=plan_id,
            environment="devtest", state_root=state_root,
        )
        keys = SqlAlchemySketchSshKeyRepository()
        ensure_sketch_ssh_key(engagement_id, keys)
        material = retrieve_sketch_ssh_key(engagement_id, keys)
        fingerprint = hashlib.sha256(f"digitalocean\0{credential_id}".encode()).hexdigest()
        workspace_path = state_root / engagement_id / "provider-keyed-v2" / "digitalocean" / fingerprint
        private = workspace_path.parents[1] / ".plan-material" / "digitalocean" / "admin-private"
        output = private.parent / "ssh-output"
        local_files = {
            "local_file.ansible_inventory[0]": _local_file(
                "inventory.ini", _expected_inventory(intent, private)),
            "local_file.ssh_stanza[0]": _local_file(
                str(output / f"{intent.engagement_name}-sketch"), None),
        }
        shown = json.dumps(_shown_plan(intent, None, material.public_key, local_files))
        terraform_commands = []

        def terraform_command(args, cwd, env):
            assert cwd == workspace_path and args[0] == "/usr/bin/terraform"
            phase = args[1]
            terraform_commands.append(phase)
            if phase == "version":
                return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
            if phase == "plan":
                plan_path = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("-out=")))
                with plan_path.open("wb") as stream:
                    stream.write(b"opaque reviewed binary plan fixture")
            return subprocess.CompletedProcess(args, 0, shown if phase == "show" else "", "")

        monkeypatch.setattr(terraform_runner, "_run_command", terraform_command)
        selector_catalog = _EmptySelectorCatalog(intent.selector_tag)
        selector_post = _SelectorPost()
        gated, apply_commands = _gated_terraform(shown, _applied_state(intent))
        attachment_catalogs = []

        def apply_writer(job_id, **kwargs):
            return run_fresh_digitalocean_initial_apply_job(
                job_id, **kwargs, selector_transport=selector_catalog,
                selector_reservation_transport=selector_post, gated_command_runner=gated,
            )

        def attachment_reader(workspace, attachment_intent, **kwargs):
            catalog = _AttachmentCatalog(attachment_intent)
            attachment_catalogs.append(catalog)
            return reconcile_digitalocean_initial_attachment(
                workspace, attachment_intent, **{**kwargs, "max_attempts": 1,
                                               "poll_interval_seconds": 0}, transport=catalog,
            )

        parent = start_fresh_digitalocean_initial_continuation(
            core_id, environment="devtest", state_root=state_root, template_root=upstream,
            apply_runner=apply_writer, attachment_reconciler=attachment_reader,
        )
        assert parent.status == "running" and parent.input["phase"] == "awaiting_host_proof"
        assert [event.message for event in parent.events] == [
            "provider continuation job queued", "provider plan child starting",
            "provider plan child queued", "provider plan child succeeded",
            "provider apply preflight passed", "provider apply child queued",
            "provider attachment proof started", "provider attachment proven; host proof pending",
        ]
        parent_id, plan_job_id, apply_job_id = _job_ids(core_id)
        assert parent.id == parent_id
        jobs = SqlAlchemyJobRepository()
        assert jobs.get(plan_job_id).status == "succeeded"
        assert jobs.get(apply_job_id).status == "succeeded"
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"]
        assert selector_post.calls == 1
        assert len(attachment_catalogs) == 1
        assert set(parent.events[-1].data["verifiedDropletIds"]) == {
            node.droplet_id for node in attachment_catalogs[0].intent.nodes
        }

    reopened = db.configure(state.uri)
    with db.bind(reopened):
        persisted = SqlAlchemyJobRepository().get(parent_id)
        assert persisted == parent
        restarted = start_fresh_digitalocean_initial_continuation(
            core_id, environment="devtest", state_root=state_root, template_root=upstream,
            apply_runner=apply_writer, attachment_reconciler=attachment_reader,
        )
        assert restarted == persisted
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"]
        assert selector_post.calls == 1
        assert len(attachment_catalogs) == 1

        # The next gate performs only fresh provider GETs and local file/row
        # checks. It binds state-derived nodes to the still-pending chains.
        bound = bind_initial_digitalocean_host_identity(
            parent_id, environment="devtest", state_root=state_root,
            attachment_reconciler=attachment_reader,
        )
        assert bound.status == "running" and bound.input["phase"] == "host_identity_bound"
        assert [event.message for event in bound.events[-2:]] == [
            "provider host identity binding intended", "provider host identity bound",
        ]
        manifest = bound.events[-2].data
        assert manifest["coreJobId"] == core_id and manifest["corePlanId"] == plan_id
        assert manifest["providerConnectionId"] == credential_id
        assert manifest["stateSha256"] == parent.events[-1].data["stateSha256"]
        assert len(manifest["nodes"]) == 7
        assert {row["terraformAddress"] for row in manifest["nodes"]} == set(intent.nodes)
        assert len(manifest["chainFingerprints"]) == 2
        assert len(manifest["hostPolicies"]) == 2
        assert sum(len(row["hosts"]) for row in manifest["hostPolicies"]) == 7
        sketch_hosts = Path(manifest["sketchKnownHostsPath"])
        assert sketch_hosts.read_bytes() == b""
        assert sketch_hosts.stat().st_mode & 0o777 == 0o600
        assert Path(manifest["coreKnownHostsPath"]).read_text() == (
            "8.8.8.8 ssh-ed25519 pinned-core-fixture-key\n"
        )
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"]
        assert selector_post.calls == 1

    final_session = db.configure(state.uri)
    with db.bind(final_session):
        assert SqlAlchemyJobRepository().get(parent_id) == bound
        assert Path(manifest["sketchKnownHostsPath"]).read_bytes() == b""
        assert len(attachment_catalogs) == 2

        host_commands = []
        pinned_chains = set()

        def host_process(command, *, scratch_path, intent_callback, started_callback,
                         heartbeat_callback, result_callback, provider_keyed_v2, env):
            assert provider_keyed_v2 is True and scratch_path.is_dir()
            assert command[0] == sys.executable
            phase = next((name for name, suffix in (
                ("root_management_readiness", "wait_for_sketch_readiness.yml"),
                ("upstream_root_bootstrap", "upstream-sketch-playbook.compat.yml"),
                ("user_readiness", "wait_for_sketch_user_readiness.yml"),
                ("transport_install", "install_sketch_transport.yml"),
            ) if any(str(part).endswith(suffix) for part in command)), None)
            assert phase is not None
            host_commands.append((scratch_path, phase))
            invocation = CommandIntent(
                uuid4().hex, str(scratch_path),
                hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
            )
            number = 2000 + len(host_commands)
            started = StartedCommand(invocation, ProcessIdentity(str(uuid4()), number, number, number))
            intent_callback(invocation)
            started_callback(started)
            heartbeat_callback(started)
            if phase == "root_management_readiness":
                prepared = next(event.data for event in SqlAlchemyJobRepository().get(parent_id).events
                                if event.message == "provider bootstrap preparation fenced")
                chain_id = prepared["chainIds"][prepared["scratchPaths"].index(str(scratch_path))]
                assert chain_id not in pinned_chains
                with sketch_hosts.open("a", encoding="utf-8") as stream:
                    for node in manifest["nodes"]:
                        if node["chainId"] == chain_id:
                            stream.write(f"barragan-bootstrap-sketch-{node['name']} "
                                         f"ssh-ed25519 pinned-{node['name']}\n")
                pinned_chains.add(chain_id)
            result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
            return CommandResult(started, 0, "", "", False, False)

        bootstrap = bootstrap_initial_digitalocean_chains(
            parent_id, environment="devtest", state_root=state_root,
            bootstrap_env={TEMPLATE_ROOT_ENV: str(upstream), "ANSIBLE_PLAYBOOK_BIN": sys.executable},
            attachment_reconciler=attachment_reader,
            gated_command_runner=host_process,
        )
        assert bootstrap.status == "running" and bootstrap.input["phase"] == "awaiting_strict_host_proof"
        assert [phase for _path, phase in host_commands] == [
            "root_management_readiness", "upstream_root_bootstrap",
            "user_readiness", "transport_install",
        ] * 2
        assert len({path for path, _phase in host_commands}) == 2
        assert pinned_chains == set(bootstrap.events[-1].data["chainIds"])
        assert len(sketch_hosts.read_text().splitlines()) == 7
        prepared = next(event.data for event in bootstrap.events
                        if event.message == "provider bootstrap preparation fenced")
        assert len(prepared["scratchPaths"]) == 2
        for raw_path in prepared["scratchPaths"]:
            scratch = Path(raw_path)
            assert scratch.is_dir() and scratch.stat().st_mode & 0o7777 == 0o700
            assert not (scratch / "keys").exists()
        assert [event.message for event in bootstrap.events].count(
            "provider bootstrap command result fenced") == 8
        assert [event.message for event in bootstrap.events].count(
            "provider chain bootstrap completed; host proof pending") == 2
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"] and selector_post.calls == 1

    values = locals()
    return {name: values[name] for name in (
        "state", "state_root", "upstream", "engagement_id", "core_id", "plan_id",
        "credential_id", "intent", "shown", "terraform_commands", "apply_commands",
        "selector_post", "attachment_catalogs", "parent", "parent_id", "plan_job_id",
        "apply_job_id", "bound", "manifest", "sketch_hosts", "host_commands",
        "pinned_chains", "bootstrap", "attachment_reader", "host_process", "workspace_path",
    )}


@pytest.mark.skipif(sys.platform != "linux", reason="reviewed Terraform release is Linux-only")
@pytest.mark.parametrize("instance_response_lost", [False, True], ids=["submitted", "instance-response-lost"])
def test_real_initial_continuation_persists_attachment_and_does_not_replay(
        tmp_path, monkeypatch, instance_response_lost):
    """The controller owns the parent and both child writers in one generation."""
    generation = _canonical_applied_generation(tmp_path, monkeypatch, instance_response_lost)
    (state, state_root, upstream, engagement_id, core_id, plan_id, intent,
     terraform_commands, apply_commands, selector_post, attachment_catalogs,
     parent_id, bootstrap, manifest, host_commands, attachment_reader, host_process,
     workspace_path) = (
        generation[name] for name in (
            "state", "state_root", "upstream", "engagement_id", "core_id", "plan_id",
            "intent", "terraform_commands", "apply_commands", "selector_post",
            "attachment_catalogs", "parent_id", "bootstrap", "manifest", "host_commands",
            "attachment_reader", "host_process", "workspace_path",
        )
    )

    audit_session = db.configure(state.uri)
    with db.bind(audit_session):
        assert SqlAlchemyJobRepository().get(parent_id) == bootstrap
        scope = build_digitalocean_keyed_teardown_scope(
            engagement_id, core_id, environment="devtest", state_root=state_root,
        )
        evidence = audit_terminal_provider_keyed_bootstrap(
            core_id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
        )
        assert evidence.parent_job_id == parent_id and evidence.command_count == 8
        residual_keys = Path(evidence.scratch_paths[0]) / "keys"
        residual_keys.mkdir(mode=0o700)
        with pytest.raises(ProviderKeyedTeardownQuiescenceError):
            audit_terminal_provider_keyed_bootstrap(
                core_id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
            )
        assert _db_lease_lookup(engagement_id) == (plan_id, "provider_keyed_initial")
        residual_keys.rmdir()
        assert audit_terminal_provider_keyed_bootstrap(
            core_id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
        ) == evidence
        with pytest.raises(ProviderKeyedInitialBootstrapError):
            bootstrap_initial_digitalocean_chains(
                parent_id, environment="devtest", state_root=state_root,
                bootstrap_env={TEMPLATE_ROOT_ENV: str(upstream), "ANSIBLE_PLAYBOOK_BIN": sys.executable},
                attachment_reconciler=attachment_reader,
                gated_command_runner=host_process,
            )
        assert len(host_commands) == 8

        preview = preview_engagement_teardown(core_id)
        assert preview is not None and preview["snapshotId"]
        assert preview["engagementId"] == engagement_id
        reviewed_parent = start_engagement_teardown(
            core_id, {"confirmation": preview["confirmationPhrase"],
                      "snapshotId": preview["snapshotId"]},
            provider_keyed_environment="devtest",
            provider_keyed_coordinator=lambda queued_id: run_provider_keyed_comprehensive_handoff(
                queued_id, environment="devtest", state_root=state_root,
            ),
        )
        assert reviewed_parent.status == "queued" and reviewed_parent.input["phase"] == "queued"
        assert reviewed_parent.input["scopeSnapshot"]["providerScopes"] == [scope]
        coordinator_id = f"job-provider-keyed-comprehensive-teardown-{core_id.removeprefix('job-')}"
        coordinator = SqlAlchemyJobRepository().get(coordinator_id)
        assert coordinator.status == "running"
        assert coordinator.input["phase"] == "awaiting_inspector_preflight"
        assert _db_lease_lookup(engagement_id) == (plan_id, "provider_keyed_teardown_fence")
        handed_off = SqlAlchemyJobRepository().get(parent_id)
        assert handed_off.input["phase"] == "teardown_handoff_pending"
        assert handed_off.events[-1].message == "provider bootstrap claim fenced for teardown handoff"
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"] and selector_post.calls == 1
        assert len(host_commands) == 8

    source_session = db.configure(state.uri)
    with db.bind(source_session):
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        current_parent, current_core, snapshot, operation = _boundary(
            reviewed_parent.id, jobs, plans, _db_lease_lookup,
        )
        assert current_parent == reviewed_parent and current_core.id == core_id
        assert operation == "provider_keyed_teardown_fence"
        assert snapshot["providerScopes"] == [scope]
        source = load_keyed_teardown_source(
            reviewed_parent.id, phase="pre_go", environment="devtest", state_root=state_root,
        )
        assert source.variant == "pending_handoff"
        assert source.initial_job_id == parent_id
        assert source.snapshot_id == snapshot["snapshotId"]
        assert audit_pending_provider_keyed_bootstrap(
            core_id, confirmed_scope=scope,
            confirmed_scope_sha256=_fingerprint(snapshot),
            workspace_root=Path(scope["workspace"]),
        ).command_count == 8
        assert run_provider_keyed_comprehensive_handoff(
            reviewed_parent.id, environment="devtest", state_root=state_root,
        ) == jobs.get(coordinator_id)
        assert len([row for row in jobs.list_for_engagement(engagement_id)
                    if row.action == "provider_keyed_comprehensive_teardown"]) == 1
        sealed = (jobs.get(reviewed_parent.id), jobs.get(coordinator_id),
                  jobs.get(parent_id), _db_lease_lookup(engagement_id))
        with pytest.raises(ProviderKeyedInspectorPreflightRequired):
            inspect_prepared_keyed_teardown_inspector(
                reviewed_parent.id, environment="devtest",
            )
        assert (jobs.get(reviewed_parent.id), jobs.get(coordinator_id),
                jobs.get(parent_id), _db_lease_lookup(engagement_id)) == sealed
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"] and selector_post.calls == 1
        assert len(host_commands) == 8

    inspector_restart = db.configure(state.uri)
    with db.bind(inspector_restart):
        jobs = SqlAlchemyJobRepository()
        assert (jobs.get(reviewed_parent.id), jobs.get(coordinator_id),
                jobs.get(parent_id), _db_lease_lookup(engagement_id)) == sealed
        with pytest.raises(ProviderKeyedInspectorPreflightRequired):
            inspect_prepared_keyed_teardown_inspector(
                reviewed_parent.id, environment="devtest",
            )
        assert (jobs.get(reviewed_parent.id), jobs.get(coordinator_id),
                jobs.get(parent_id), _db_lease_lookup(engagement_id)) == sealed
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"] and selector_post.calls == 1
        assert len(host_commands) == 8

        assert reviewed_parent.input["scopeSnapshot"]["inspector"]["tracked"] is False
        assert reviewed_parent.input["scopeSnapshot"]["inspector"]["ownedProviderRecordIds"] == []
        settings = SqlAlchemyObserverSettingsRepository().save(StoredInspectorSettings(
            engagement_id=engagement_id, enabled=True, provider="linode",
            region="us-east", size="g6-nanode-1", mode="continuous",
            schedule_weekdays=[], schedule_time_utc="00:00", check_families=[],
            forbidden_tcp_ports=[], port_scan_profiles=[], current_host={},
            idle_retention_until="", last_scheduled_slot="", last_mutation_job_inspected="",
            created_at="2026-10-08T00:00:00+00:00", updated_at="2026-10-08T00:00:00+00:00",
        ))
        key_dir = tmp_path / "inspector-keys"
        monkeypatch.setattr(inspector_intent, "_inspector_key_dir", lambda: key_dir)
        source_reader = lambda: "8.8.8.8/32"  # External egress-reflector response only.
        with pytest.raises(ProviderKeyedInspectorCreateIntentError):
            reserve_keyed_inspector_create_intent(
                reviewed_parent.id, environment="devtest",
                management_source_resolver=source_reader,
            )
        assert jobs.get(coordinator_id) == sealed[1]

        selected = SqlAlchemyCredentialRepository().save(StoredCredential(
            id="credential-inspector-opaque", provider="linode", alias="inspector",
            status="active", description="", encrypted_secret=encrypt_secret_value("fixture-linode-token"),
            is_default=True, created_at="2026-10-08T00:00:00+00:00",
            updated_at="2026-10-08T00:00:00+00:00",
        ))
        with pytest.raises(ProviderKeyedInspectorCreateIntentError):
            reserve_keyed_inspector_create_intent(
                reviewed_parent.id, environment="devtest",
                management_source_resolver=source_reader,
            )
        assert jobs.get(coordinator_id) == sealed[1]

        key_dir.mkdir(mode=0o700)
        subprocess.run([
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "",
            "-f", str(key_dir / "id_ed25519"),
        ], check=True, capture_output=True)
        fingerprint = hashlib.sha256(
            (key_dir / "id_ed25519.pub").read_bytes().strip(),
        ).hexdigest()
        assert inspector_intent._existing_key_fingerprint() == fingerprint
        receipt = reserve_keyed_inspector_create_intent(
            reviewed_parent.id, environment="devtest",
            management_source_resolver=source_reader,
        )
        assert receipt.provider_create_authorized is False
        assert receipt.coordinator_job_id == coordinator_id
        assert receipt.scope_snapshot_id == reviewed_parent.input["scopeSnapshot"]["snapshotId"]
        created_intent = jobs.get(coordinator_id)
        assert created_intent.input["phase"] == "inspector_create_started"
        assert len(created_intent.events) == 5
        assert created_intent.events[-1].message == "inspector_create_started"
        assert created_intent.events[-1].data["credentialId"] == selected.id
        assert created_intent.events[-1].data["credentialUpdatedAt"] == selected.updated_at
        assert created_intent.events[-1].data["credentialSha256"] == hashlib.sha256(
            selected.encrypted_secret.encode("utf-8"),
        ).hexdigest()
        assert created_intent.events[-1].data["keyFingerprintSha256"] == fingerprint
        assert created_intent.events[-1].data["managementSourceCidr"] == "8.8.8.8/32"
        assert "fixture-linode-token" not in str(created_intent)
        assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == settings
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == []
        assert receipt.event_digest == job_event_digest(created_intent.events)
        assert (jobs.get(reviewed_parent.id), jobs.get(core_id), jobs.get(parent_id),
                _db_lease_lookup(engagement_id)) == (
            sealed[0], current_core, sealed[2], sealed[3],
        )

    intent_restart = db.configure(state.uri)
    with db.bind(intent_restart):
        jobs = SqlAlchemyJobRepository()
        parent, core, snapshot, operation = _boundary(
            reviewed_parent.id, jobs, SqlAlchemyDeploymentPlanRepository(), _db_lease_lookup,
        )
        assert operation == "provider_keyed_teardown_fence"
        persisted_intent = jobs.get(coordinator_id)
        assert persisted_intent == created_intent
        assert recorded_keyed_inspector_intent(persisted_intent, parent, core, snapshot)
        assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == settings
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == []
        with pytest.raises(ProviderKeyedInspectorCreateAttention):
            reserve_keyed_inspector_create_intent(
                reviewed_parent.id, environment="devtest",
                management_source_resolver=source_reader,
            )
        with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
            run_provider_keyed_comprehensive_handoff(
                reviewed_parent.id, environment="devtest", state_root=state_root,
            )
        assert jobs.get(coordinator_id) == persisted_intent
        assert (jobs.get(reviewed_parent.id), jobs.get(core_id), jobs.get(parent_id),
                _db_lease_lookup(engagement_id)) == (
            sealed[0], current_core, sealed[2], sealed[3],
        )
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"] and selector_post.calls == 1
        assert len(host_commands) == 8

        class LinodeSubmissionTransport:
            def __init__(self):
                self.calls = []

            def request(self, method, path, token, body=None):
                self.calls.append((method, path))
                assert method == "POST" and token == "fixture-linode-token"
                assert isinstance(body, dict)
                if path == "/networking/firewalls":
                    assert self.calls == [("POST", "/networking/firewalls")]
                    assert body["rules"]["inbound"] == [{
                        "action": "ACCEPT", "protocol": "TCP", "ports": "22",
                        "addresses": {"ipv4": ["8.8.8.8/32"]},
                    }]
                    return {"id": 71234567}
                assert path == "/linode/instances"
                assert self.calls == [
                    ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
                ]
                assert body["label"] == receipt.resource_name
                assert body["region"] == settings.region and body["type"] == settings.size
                assert body["firewall_id"] == 71234567
                assert body["authorized_keys"] == [
                    (key_dir / "id_ed25519.pub").read_text().strip(),
                ]
                if instance_response_lost:
                    raise RuntimeError("simulated external instance response loss")
                return {"id": 81234567}

        provider_transport = LinodeSubmissionTransport()
        factory_calls = []

        def provider_factory(provider, source):
            factory_calls.append((provider, source))
            assert (provider, source) == ("linode", "8.8.8.8/32")
            return LinodeObserverProvider(
                transport=provider_transport, management_source_resolver=lambda: source,
            )

        monkeypatch.setattr(inspector_submit, "_inspector_key_dir", lambda: key_dir)
        if instance_response_lost:
            with pytest.raises(ProviderKeyedInspectorSubmitAttention):
                submit_keyed_inspector_once(
                    receipt, environment="devtest", provider_factory=provider_factory,
                )
        else:
            submitted = submit_keyed_inspector_once(
                receipt, environment="devtest", provider_factory=provider_factory,
            )
            assert submitted.status == "submitted_unverified"
            assert (submitted.host_id, submitted.firewall_id) == ("81234567", "71234567")
        assert provider_transport.calls == [
            ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
        ]
        assert factory_calls == [("linode", "8.8.8.8/32")]
        staged = jobs.get(coordinator_id)
        assert staged.status == "running" and staged.input["phase"] == "inspector_create_started"
        assert len(staged.events) == (8 if instance_response_lost else 9)
        assert [(event.data["stage"], event.data["point"], event.data["resourceId"],
                 event.data["firewallId"]) for event in staged.events[5:]] == ([
            ("firewall", "before_post", "", ""),
            ("firewall", "response_received", "71234567", ""),
            ("instance", "before_post", "", "71234567"),
        ] if instance_response_lost else [
            ("firewall", "before_post", "", ""),
            ("firewall", "response_received", "71234567", ""),
            ("instance", "before_post", "", "71234567"),
            ("instance", "response_received", "81234567", "71234567"),
        ])
        assert [event.message for event in staged.events[5:]] == [
            "inspector_create_stage",
        ] * (3 if instance_response_lost else 4)
        if not instance_response_lost:
            assert submitted.event_digest == job_event_digest(staged.events)
        assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == []
        assert (jobs.get(reviewed_parent.id), jobs.get(core_id), jobs.get(parent_id),
                _db_lease_lookup(engagement_id)) == (
            sealed[0], current_core, sealed[2], sealed[3],
        )

    submit_restart = db.configure(state.uri)
    with db.bind(submit_restart):
        jobs = SqlAlchemyJobRepository()
        assert jobs.get(coordinator_id) == staged
        with pytest.raises(ProviderKeyedInspectorSubmitAttention):
            submit_keyed_inspector_once(
                receipt, environment="devtest", provider_factory=provider_factory,
            )
        if instance_response_lost:
            with pytest.raises(ProviderKeyedComprehensiveTeardownError):
                run_provider_keyed_comprehensive_handoff(
                    reviewed_parent.id, environment="devtest", state_root=state_root,
                )
        assert jobs.get(coordinator_id) == staged
        assert provider_transport.calls == [
            ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
        ]
        assert factory_calls == [("linode", "8.8.8.8/32")]
        assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == []
        assert (jobs.get(reviewed_parent.id), jobs.get(core_id), jobs.get(parent_id),
                _db_lease_lookup(engagement_id)) == (
            sealed[0], current_core, sealed[2], sealed[3],
        )
        assert terraform_commands == ["version", "init", "plan", "show"]
        assert apply_commands == ["show", "apply"] and selector_post.calls == 1
        assert len(host_commands) == 8

        if not instance_response_lost:
            class LinodeSettlementTransport:
                def __init__(self):
                    self.calls = []

                def request(self, method, path, token, body=None):
                    self.calls.append((method, path))
                    assert method == "GET" and body is None
                    assert token == "fixture-linode-token"
                    if path == "/linode/instances/81234567":
                        pending = self.calls.count((method, path)) == 1
                        return {
                            "id": 81234567, "label": receipt.resource_name,
                            "region": settings.region, "type": settings.size,
                            "status": "booting" if pending else "running",
                            "ipv4": [] if pending else ["45.79.201.25"],
                            "tags": ["barragan", "inspector"],
                        }
                    if path == "/networking/firewalls/71234567":
                        return {"id": 71234567, "label": _inspector_firewall_label(
                            "linode", receipt.resource_name), "status": "enabled"}
                    if path == "/networking/firewalls/71234567/rules":
                        return {"inbound_policy": "DROP", "outbound_policy": "ACCEPT",
                                "inbound": [{"action": "ACCEPT", "protocol": "TCP", "ports": "22",
                                             "addresses": {"ipv4": ["8.8.8.8/32"]}}],
                                "outbound": []}
                    assert path == "/networking/firewalls/71234567/devices?page=1&page_size=100"
                    return {"page": 1, "pages": 1, "results": 1,
                            "data": [{"entity": {"type": "linode", "id": 81234567}}]}

            settlement_transport = LinodeSettlementTransport()
            settlement_clock = {"elapsed": 0.0, "sleeps": []}
            settlement_start = datetime.now(timezone.utc)

            def settle_sleep(seconds):
                settlement_clock["sleeps"].append(seconds)
                settlement_clock["elapsed"] += seconds

            proved = settle_submitted_keyed_inspector(
                receipt, submitted, environment="devtest",
                transport_factory=lambda provider: (
                    settlement_transport if provider == "linode" else pytest.fail("wrong provider")),
                now=lambda: settlement_start + timedelta(seconds=settlement_clock["elapsed"]),
                monotonic=lambda: settlement_clock["elapsed"], sleep=settle_sleep,
            )
            assert settlement_clock["sleeps"] == [10.0]
            assert settlement_transport.calls == [
                ("GET", "/linode/instances/81234567"),
                ("GET", "/networking/firewalls/71234567"),
                ("GET", "/networking/firewalls/71234567/rules"),
                ("GET", "/networking/firewalls/71234567/devices?page=1&page_size=100"),
                ("GET", "/linode/instances/81234567"),
                ("GET", "/networking/firewalls/71234567"),
                ("GET", "/networking/firewalls/71234567/rules"),
                ("GET", "/networking/firewalls/71234567/devices?page=1&page_size=100"),
            ]
            assert (proved.host.provider, proved.host.resource_id,
                    proved.host.public_ip, proved.firewall_id, proved.management_cidr) == (
                "linode", "81234567", "45.79.201.25", "71234567", "8.8.8.8/32",
            )
            assert proved.host.metadata["providerFirewall"]["managementSourceCidr"] == "8.8.8.8/32"
            settled = jobs.get(coordinator_id)
            assert settled.events == staged.events
            assert settled.input["claimHeartbeatAt"] != staged.input["claimHeartbeatAt"]
            assert settled.input["phase"] == "inspector_create_started"
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == []
            assert (jobs.get(reviewed_parent.id), jobs.get(core_id), jobs.get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]

            def settle_again(original_receipt, original_submission, **options):
                return settle_submitted_keyed_inspector(
                    original_receipt, original_submission, **options,
                    transport_factory=lambda provider: (
                        settlement_transport if provider == "linode" else pytest.fail("wrong provider")),
                    now=lambda: settlement_start + timedelta(seconds=settlement_clock["elapsed"]),
                    monotonic=lambda: settlement_clock["elapsed"], sleep=settle_sleep,
                )

            materialized = materialize_proved_keyed_inspector(
                receipt, submitted, environment="devtest", settler=settle_again,
                now=lambda: settlement_start + timedelta(seconds=settlement_clock["elapsed"]),
            )
            assert materialized.status == "preparation_required"
            assert materialized.cleanup_required is True
            assert (materialized.host_record_id, materialized.firewall_record_id) == (
                "linode:inspector:81234567", "linode:inspector-firewall:71234567",
            )
            assert settlement_clock["sleeps"] == [10.0]
            assert settlement_transport.calls[8:] == [
                ("GET", "/linode/instances/81234567"),
                ("GET", "/networking/firewalls/71234567"),
                ("GET", "/networking/firewalls/71234567/rules"),
                ("GET", "/networking/firewalls/71234567/devices?page=1&page_size=100"),
            ]
            assert len(settlement_transport.calls) == 12
            owned = SqlAlchemyProviderResourceRepository()
            host_record = owned.get(materialized.host_record_id)
            firewall_record = owned.get(materialized.firewall_record_id)
            assert {row.id for row in owned.list_for_engagement(engagement_id)} == {
                materialized.host_record_id, materialized.firewall_record_id,
            }
            assert host_record.provider == firewall_record.provider == "linode"
            assert host_record.source == firewall_record.source == INSPECTOR_RESOURCE_SOURCE
            assert host_record.adoption_job_id == firewall_record.adoption_job_id == coordinator_id
            assert host_record.resource_type == "inspector_instance"
            assert host_record.resource_id == "81234567"
            assert firewall_record.resource_type == "inspector_firewall"
            assert firewall_record.resource_id == "71234567"
            assert host_record.status == firewall_record.status == "preparation_required"
            assert host_record.metadata["barraganOwned"] is True
            assert firewall_record.metadata["barraganOwned"] is True
            assert host_record.metadata["cleanupRequired"] is True
            assert firewall_record.metadata["cleanupRequired"] is True
            assert host_record.metadata["providerFirewall"]["resourceId"] == "71234567"
            assert host_record.metadata["providerFirewall"]["managementSourceCidr"] == "8.8.8.8/32"
            assert firewall_record.metadata["inspectorHostResourceId"] == "81234567"
            owned_child = jobs.get(coordinator_id)
            assert owned_child.input["phase"] == "inspector_owned_unprepared"
            assert len(owned_child.events) == 10
            assert owned_child.events[-1].message == "inspector_owned_unprepared"
            assert owned_child.events[-1].data["stageJournalSha256"] == submitted.event_digest
            assert owned_child.events[-1].data["hostRecordId"] == host_record.id
            assert owned_child.events[-1].data["firewallRecordId"] == firewall_record.id
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            assert (jobs.get(reviewed_parent.id), jobs.get(core_id), jobs.get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]

    if not instance_response_lost:
        ownership_restart = db.configure(state.uri)
        with db.bind(ownership_restart):
            assert recover_materialized_keyed_inspector(
                coordinator_id, engagement_id, environment="devtest",
            ) == materialized
            assert SqlAlchemyJobRepository().get(coordinator_id) == owned_child
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            prior_rows = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
            monkeypatch.setattr(inspector_binder, "_inspector_key_dir", lambda: key_dir)
            binder_options = {
                "transport_factory": lambda provider: (
                    settlement_transport if provider == "linode" else pytest.fail("wrong provider")),
                "now": lambda: settlement_start + timedelta(seconds=settlement_clock["elapsed"]),
                "monotonic": lambda: settlement_clock["elapsed"],
                "sleep": settle_sleep,
            }
            capability = begin_keyed_inspector_preparation(
                coordinator_id, engagement_id, environment="devtest",
                binder_options=binder_options,
            )
            assert settlement_transport.calls[12:] == [
                ("GET", "/linode/instances/81234567"),
                ("GET", "/networking/firewalls/71234567"),
                ("GET", "/networking/firewalls/71234567/rules"),
                ("GET", "/networking/firewalls/71234567/devices?page=1&page_size=100"),
            ]
            assert len(settlement_transport.calls) == 16
            assert settlement_clock["sleeps"] == [10.0]
            prepared = SqlAlchemyJobRepository().get(coordinator_id)
            assert prepared.input["phase"] == "inspector_prepare_started"
            assert len(prepared.events) == 11
            assert prepared.events[-1].message == "inspector_prepare_started"
            assert prepared.events[-1].data["sourceJournalSha256"] == job_event_digest(
                owned_child.events,
            )
            assert prepared.events[-1].data["keyFingerprintSha256"] == fingerprint
            assert prepared.events[-1].data["hostRecordId"] == materialized.host_record_id
            assert prepared.events[-1].data["firewallRecordId"] == materialized.firewall_record_id
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == prior_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )
            # Keep the process-local capability for the next real executor slice.
            assert type(capability) is InspectorPreparationCapability
            assert repr(capability) == "<InspectorPreparationCapability one-shot>"
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]
            assert terraform_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"] and selector_post.calls == 1
            assert len(host_commands) == 8

        preparation_restart = db.configure(state.uri)
        with db.bind(preparation_restart):
            with pytest.raises(InspectorPreparationIntentAttention):
                begin_keyed_inspector_preparation(
                    coordinator_id, engagement_id, environment="devtest",
                    binder_options=binder_options,
                )
            assert SqlAlchemyJobRepository().get(coordinator_id) == prepared
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == prior_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            assert len(settlement_transport.calls) == 16

            inspector_commands = []
            preparation_heartbeats = []
            original_run = subprocess.run
            original_heartbeat = (
                SqlAlchemyJobRepository.heartbeat_keyed_inspector_preparation_if_running_claimed
            )

            def supervised_process(command, **kwargs):
                if command[:2] == ["/usr/bin/ssh-keygen", "-y"]:
                    return original_run(command, **kwargs)
                if command[0] not in {"ssh", "/usr/bin/ansible-playbook"}:
                    pytest.fail(f"unexpected Inspector preparation command: {command[0]}")
                inspector_commands.append(tuple(command))
                assert kwargs["timeout"] == 120
                if command[0] == "ssh":
                    assert command[command.index("-i") + 1] == str(key_dir / "id_ed25519")
                    assert any(part in {"barragan@45.79.201.25", "root@45.79.201.25"}
                               for part in command)
                else:
                    inventory = Path(kwargs["cwd"]) / command[command.index("-i") + 1]
                    rendered_inventory = inventory.read_text(encoding="utf-8")
                    assert "ansible_host=45.79.201.25" in rendered_inventory
                    assert "ansible_user=barragan" in rendered_inventory
                    assert f"ansible_ssh_private_key_file={key_dir / 'id_ed25519'}" in rendered_inventory
                if command[0] == "ssh" and "/usr/sbin/sshd" in command:
                    return subprocess.CompletedProcess(command, 0,
                        "permitrootlogin no\npasswordauthentication no\n"
                        "kbdinteractiveauthentication no\n", "")
                if command[0] == "ssh" and any(part == "root@45.79.201.25" for part in command):
                    return subprocess.CompletedProcess(command, 255, "",
                                                       "Permission denied (publickey).")
                return subprocess.CompletedProcess(command, 0, "", "")

            def recorded_heartbeat(self, *args, **kwargs):
                preparation_heartbeats.append(kwargs["expected_event_digest"])
                return original_heartbeat(self, *args, **kwargs)

            monkeypatch.setattr(observer_checks.subprocess, "run", supervised_process)
            monkeypatch.setattr(observer_checks, "resolve_ansible_playbook",
                            lambda: type("Resolution", (), {
                                "ok": True, "command": "/usr/bin/ansible-playbook",
                            })())
            monkeypatch.setattr(SqlAlchemyJobRepository,
                                "heartbeat_keyed_inspector_preparation_if_running_claimed",
                                recorded_heartbeat)
            prepared_unverified = execute_reserved_keyed_inspector_preparation(
                capability, environment="devtest",
                now=lambda: settlement_start + timedelta(seconds=settlement_clock["elapsed"]),
            )
            assert prepared_unverified.status == "prepared_unverified"
            assert prepared_unverified.coordinator_job_id == coordinator_id
            assert prepared_unverified.preparation_journal_sha256 == job_event_digest(prepared.events)
            assert len(inspector_commands) == 6
            assert [command[0] for command in inspector_commands] == [
                "ssh", "/usr/bin/ansible-playbook", "ssh", "ssh", "ssh",
                "/usr/bin/ansible-playbook",
            ]
            assert all("sudo" in inspector_commands[index] and "true" in inspector_commands[index]
                       for index in (0, 2))
            assert any(part.endswith("harden_inspector_ssh.yml") for part in inspector_commands[1])
            assert "/usr/sbin/sshd" in inspector_commands[3] and "-T" in inspector_commands[3]
            assert "root@45.79.201.25" in inspector_commands[4]
            assert any(part.endswith("prepare_inspector.yml") for part in inspector_commands[5])
            assert len(preparation_heartbeats) >= 15
            assert set(preparation_heartbeats) == {job_event_digest(prepared.events)}
            assert SqlAlchemyJobRepository().get(coordinator_id).events == prepared.events
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == prior_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )
            with pytest.raises(InspectorPreparationExecutionAttention):
                execute_reserved_keyed_inspector_preparation(
                    capability, environment="devtest",
                )
            assert len(inspector_commands) == 6

            proof_commands = []
            proof_ssh_timeout = 120

            def read_only_ssh(command, **kwargs):
                if command[:2] == ["/usr/bin/ssh-keygen", "-y"]:
                    return original_run(command, **kwargs)
                assert command[0] == "ssh"
                assert kwargs["timeout"] == proof_ssh_timeout
                assert command[command.index("-i") + 1] == str(key_dir / "id_ed25519")
                assert any(part in {"barragan@45.79.201.25", "root@45.79.201.25"}
                           for part in command)
                proof_commands.append(tuple(command))
                if command[-2:] == ["/usr/bin/printenv", "SSH_CONNECTION"]:
                    return subprocess.CompletedProcess(
                        command, 0, "8.8.8.8 55444 45.79.201.25 22\n", "",
                    )
                if "/usr/sbin/sshd" in command:
                    return subprocess.CompletedProcess(
                        command, 0,
                        "permitrootlogin no\npasswordauthentication no\n"
                        "kbdinteractiveauthentication no\n", "",
                    )
                if "root@45.79.201.25" in command:
                    return subprocess.CompletedProcess(
                        command, 255, "", "Permission denied (publickey).",
                    )
                if command[-2:] == ["/usr/bin/nmap", "--version"]:
                    return subprocess.CompletedProcess(
                        command, 0, "Nmap version 7.94 ( https://nmap.org )\n", "",
                    )
                assert command[-3:] == ["sudo", "-n", "true"]
                return subprocess.CompletedProcess(command, 0, "", "")

            monkeypatch.setattr(observer_checks.subprocess, "run", read_only_ssh)
            heartbeats_before_proof = len(preparation_heartbeats)
            proof_capability = prove_prepared_keyed_inspector_support_host(
                prepared_unverified, engagement_id, environment="devtest",
                transport_factory=lambda provider: (
                    settlement_transport if provider == "linode" else pytest.fail("wrong provider")),
                now=lambda: settlement_start + timedelta(seconds=settlement_clock["elapsed"]),
            )
            assert type(proof_capability) is InspectorSupportHostProofCapability
            # Leave the one-shot proof available for the publication continuation.
            support_evidence = proof_capability.evidence
            assert support_evidence.status == "support_host_proved_unpublished"
            assert support_evidence.settings_published is False
            assert support_evidence.coordinator_job_id == coordinator_id
            assert support_evidence.host_record_id == materialized.host_record_id
            assert support_evidence.firewall_record_id == materialized.firewall_record_id
            assert support_evidence.provider == "linode"
            assert (support_evidence.host_id, support_evidence.public_ip) == (
                "81234567", "45.79.201.25",
            )
            assert support_evidence.preparation_journal_sha256 == job_event_digest(prepared.events)
            assert support_evidence.provider_proof_sha256 == prepared.events[-2].data["proofSha256"]
            assert support_evidence.ssh_policy_sha256 == hashlib.sha256(
                b"permitrootlogin no\npasswordauthentication no\n"
                b"kbdinteractiveauthentication no\n",
            ).hexdigest()
            assert support_evidence.nmap_version.startswith("Nmap version 7.94")
            assert settlement_transport.calls[16:] == [
                ("GET", "/linode/instances/81234567"),
                ("GET", "/networking/firewalls/71234567"),
                ("GET", "/networking/firewalls/71234567/rules"),
                ("GET", "/networking/firewalls/71234567/devices?page=1&page_size=100"),
            ]
            assert prepared.events[4].data["managementSourceCidr"] == "8.8.8.8/32"
            assert len(proof_commands) == 5
            assert proof_commands[0][-3:] == ("sudo", "-n", "true")
            assert proof_commands[1][-2:] == ("/usr/bin/printenv", "SSH_CONNECTION")
            assert proof_commands[2][-3:] == (
                "-T", "-C", "user=root,addr=8.8.8.8,host=8.8.8.8",
            )
            assert proof_commands[3][-2:] == ("root@45.79.201.25", "true")
            assert proof_commands[4][-2:] == ("/usr/bin/nmap", "--version")
            assert len(preparation_heartbeats) - heartbeats_before_proof >= 15
            assert set(preparation_heartbeats[heartbeats_before_proof:]) == {
                job_event_digest(prepared.events),
            }
            assert len(inspector_commands) == 6
            assert SqlAlchemyJobRepository().get(coordinator_id).events == prepared.events
            assert SqlAlchemyJobRepository().get(coordinator_id).input["phase"] == "inspector_prepare_started"
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == prior_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id).current_host == {}
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )
            published_host = publish_proved_keyed_inspector_readiness(
                proof_capability, engagement_id, environment="devtest",
            )
            ready_child = SqlAlchemyJobRepository().get(coordinator_id)
            ready_rows = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
            ready_settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)
            assert published_host.provider == "linode"
            assert published_host.resource_id == "81234567"
            assert published_host.public_ip == "45.79.201.25"
            assert published_host.ssh_user == "barragan"
            assert published_host.metadata["cleanupRequired"] is True
            assert published_host.metadata["adminIdentityVersion"] == 1
            assert published_host.metadata["rootLoginDisabled"] is True
            assert published_host.metadata["supportPreparationVersion"] == 1
            assert ready_settings.current_host == published_host.to_dict()
            assert {row.id for row in ready_rows} == {
                materialized.host_record_id, materialized.firewall_record_id,
            }
            assert all(row.status == row.lifecycle_state == "active"
                       and row.metadata["cleanupRequired"] is True for row in ready_rows)
            assert SqlAlchemyProviderResourceRepository().get(materialized.host_record_id).metadata == (
                published_host.metadata
            )
            assert ready_child.status == "running" and ready_child.input["phase"] == "inspector_ready"
            assert ready_child.input["claimOwner"] == "provider-keyed-inspector-ready-handoff"
            assert ready_child.input["claimToken"] != prepared.input["claimToken"]
            assert ready_child.input["claimClaimedAt"] == ready_child.input["claimHeartbeatAt"]
            assert ready_child.input["claimExpiresAt"] == ready_child.input["claimClaimedAt"]
            assert ready_child.events[:-1] == prepared.events
            assert ready_child.events[-1].message == "inspector selected-source proof published"
            assert ready_child.events[-1].data["supportProofSha256"] == hashlib.sha256(
                json.dumps(support_evidence.__dict__, sort_keys=True,
                           separators=(",", ":")).encode(),
            ).hexdigest()
            assert ready_child.events[-1].data["settingsPublished"] is True
            assert ready_child.events[-1].data["hostRecordId"] == materialized.host_record_id
            assert ready_child.events[-1].data["firewallRecordId"] == materialized.firewall_record_id
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]
            assert terraform_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"] and selector_post.calls == 1
            assert len(host_commands) == 8

        published_restart = db.configure(state.uri)
        with db.bind(published_restart):
            recognized = recognize_published_keyed_inspector_readiness(
                coordinator_id, engagement_id, environment="devtest",
            )
            assert recognized.status == "inspector_ready"
            assert recognized.coordinator_job_id == coordinator_id
            assert recognized.host_record_id == materialized.host_record_id
            assert recognized.firewall_record_id == materialized.firewall_record_id
            assert recognized.support_proof_sha256 == ready_child.events[-1].data["supportProofSha256"]
            assert SqlAlchemyJobRepository().get(coordinator_id) == ready_child
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == ready_settings
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == ready_rows
            with pytest.raises(InspectorReadinessPublicationAttention):
                publish_proved_keyed_inspector_readiness(
                    proof_capability, engagement_id, environment="devtest",
                )
            assert SqlAlchemyJobRepository().get(coordinator_id) == ready_child
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == ready_settings
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == ready_rows
            assert len(proof_commands) == 5
            assert len(settlement_transport.calls) == 20
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]

            # The release gate checks the actual pinned Terraform executable.
            # Restore subprocess.run after the simulated external SSH responses.
            monkeypatch.setattr(observer_checks.subprocess, "run", original_run)
            phase_marker = workspace_path / ".barragan-apply-phase.json"
            assert phase_marker.stat().st_mode & 0o777 == 0o640
            assert phase_marker.stat().st_gid == destroy_preview_service._collaborator_group_gid()
            assert destroy_preview_service._private_file_digest(
                phase_marker, allow_collaborator_group=True,
            ) == hashlib.sha256(phase_marker.read_bytes()).hexdigest()
            destroy_shown = _destroy_shown_plan(workspace_path)
            destroy_commands = []

            def destroy_command(args, *, scratch_path, provider_keyed_v2,
                                intent_callback, started_callback,
                                heartbeat_callback, result_callback, **_kwargs):
                phase = args[1]
                assert args[0] == "/usr/bin/terraform"
                assert phase in {"version", "init", "plan", "show"}
                assert provider_keyed_v2 is True and scratch_path == workspace_path
                destroy_commands.append(phase)
                invocation = CommandIntent(
                    str(uuid4()), str(scratch_path),
                    hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                )
                process_id = 3000 + len(destroy_commands)
                started = StartedCommand(invocation, ProcessIdentity(
                    str(uuid4()), process_id, process_id, process_id,
                ))
                intent_callback(invocation)
                started_callback(started)
                heartbeat_callback(started)
                if phase == "plan":
                    plan_path = Path(next(arg[5:] for arg in args if arg.startswith("-out=")))
                    assert plan_path.is_file()
                    plan_path.write_bytes(b"opaque complete destroy plan fixture")
                payload = (json.dumps({"terraform_version": "1.15.5"}) if phase == "version"
                           else destroy_shown if phase == "show" else "")
                result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
                return CommandResult(started, 0, payload, "", False, False)

            membership_catalog = _AttachmentCatalog(attachment_catalogs[-1].intent)

            def write_destroy_preview(parent_job_id, **options):
                return run_digitalocean_initial_destroy_plan_job(
                    parent_job_id, **options, gated_command_runner=destroy_command,
                )

            def read_destroy_preview(parent_job_id, **options):
                return preflight_digitalocean_initial_destroy_apply(
                    parent_job_id, **options, membership_transport=membership_catalog,
                )

            preview_options = {
                "environment": "devtest", "state_root": state_root,
                "preview_runner": write_destroy_preview,
                "preview_recognizer": read_destroy_preview,
            }
            destroy_preview = run_provider_keyed_destroy_preview_from_ready(
                reviewed_parent.id, **preview_options,
            )
            assert destroy_preview.action == DESTROY_PREVIEW_ACTION
            assert destroy_preview.status == "succeeded"
            assert destroy_preview.id == (
                f"job-provider-keyed-initial-destroy-plan-{core_id.removeprefix('job-')}"
            )
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert len(destroy_preview.events) == 16
            assert destroy_preview.events[-1].message == (
                "reviewed full-state provider destroy plan saved"
            )
            destroy_plan_path = workspace_path / ".barragan-initial-destroy.tfplan"
            assert destroy_preview.artifact_refs == [str(destroy_plan_path)]
            assert destroy_plan_path.read_bytes() == b"opaque complete destroy plan fixture"
            assert hashlib.sha256(destroy_plan_path.read_bytes()).hexdigest() == (
                destroy_preview.events[-1].data["planSha256"]
            )
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    SqlAlchemyJobRepository().get(coordinator_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], ready_child, sealed[3],
            )
            assert not any(row.action == "provider_keyed_initial_destroy_apply"
                           for row in SqlAlchemyJobRepository().list_for_engagement(engagement_id))
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]

        preview_restart = db.configure(state.uri)
        with db.bind(preview_restart):
            saved_boundary = read_destroy_preview(reviewed_parent.id,
                                                  environment="devtest", state_root=state_root)
            assert saved_boundary.preview_job_id == destroy_preview.id
            assert saved_boundary.preview.plan_path == destroy_plan_path
            assert saved_boundary.preview.plan_sha256 == destroy_preview.events[-1].data["planSha256"]
            assert run_provider_keyed_destroy_preview_from_ready(
                reviewed_parent.id, **preview_options,
            ) == destroy_preview
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert SqlAlchemyJobRepository().get(destroy_preview.id) == destroy_preview
            assert SqlAlchemyJobRepository().get(coordinator_id) == ready_child
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == ready_settings
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == ready_rows
            assert _db_lease_lookup(engagement_id) == sealed[3]

        apply_restart = db.configure(state.uri)
        with db.bind(apply_restart):
            absent_catalog = _AbsentCatalog(intent.selector_tag)
            apply_commands = []
            live_proofs = []
            proof_ssh_timeout = 25
            monkeypatch.setattr(observer_checks.subprocess, "run", read_only_ssh)

            def live_inspector_proof(parent_job_id, **options):
                result = prove_live_keyed_inspector_before_destroy_go(
                    parent_job_id, **options,
                    source_resolver=lambda: "8.8.8.8/32",
                    transport_factory=lambda provider: (
                        settlement_transport if provider == "linode"
                        else pytest.fail("wrong Inspector provider")),
                )
                live_proofs.append(parent_job_id)
                return result

            def apply_command(args, *, scratch_path, provider_keyed_v2,
                              intent_callback, started_callback,
                              heartbeat_callback, result_callback, **_kwargs):
                phase = args[1]
                assert phase in {"show", "apply"}
                assert args[0] == "/usr/bin/terraform"
                assert provider_keyed_v2 is True and scratch_path == workspace_path
                apply_commands.append(phase)
                invocation = CommandIntent(
                    str(uuid4()), str(scratch_path),
                    hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                )
                process_id = 4000 + len(apply_commands)
                started = StartedCommand(invocation, ProcessIdentity(
                    str(uuid4()), process_id, process_id, process_id,
                ))
                intent_callback(invocation)
                started_callback(started)
                heartbeat_callback(started)
                if phase == "apply":
                    # The real live Inspector proof must finish before this
                    # simulated external Terraform result changes retained state.
                    assert live_proofs == [reviewed_parent.id]
                    state_path = workspace_path / "terraform.tfstate"
                    before_state = json.loads(state_path.read_text(encoding="utf-8"))
                    assert before_state["resources"]
                    state_path.write_text(json.dumps({
                        **before_state, "serial": before_state["serial"] + 1,
                        "resources": [],
                    }), encoding="utf-8")
                    state_path.chmod(0o600)
                payload = destroy_shown if phase == "show" else ""
                result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
                return CommandResult(started, 0, payload, "", False, False)

            def run_destroy_apply(parent_job_id, **options):
                return run_digitalocean_initial_destroy_apply_job(
                    parent_job_id, **options,
                    membership_transport=membership_catalog,
                    live_inspector_prover=live_inspector_proof,
                    gated_command_runner=apply_command,
                    command_environment={},
                )

            def read_absence(parent_job_id, **options):
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_job_id, **options, transport=absent_catalog,
                    max_attempts=1, poll_interval_seconds=0,
                )

            continued = continue_digitalocean_keyed_destroy_apply(
                reviewed_parent.id, environment="devtest", state_root=state_root,
                preview_recognizer=read_destroy_preview,
                apply_runner=run_destroy_apply,
                absence_reconciler=read_absence,
            )
            destroy_apply = SqlAlchemyJobRepository().get(
                f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}"
            )
            assert destroy_apply.status == "succeeded"
            assert destroy_apply.action == "provider_keyed_initial_destroy_apply"
            assert len(destroy_apply.events) == 12
            assert destroy_apply.events[-1].message == (
                "provider destroy apply completed; absence proof pending"
            )
            assert apply_commands == ["show", "apply"]
            assert live_proofs == [reviewed_parent.id]
            retained_empty = json.loads((workspace_path / "terraform.tfstate").read_text())
            assert retained_empty["resources"] == []
            assert retained_empty["lineage"] == _applied_state(intent)["lineage"]
            assert retained_empty["serial"] > _applied_state(intent)["serial"]
            assert json.loads((workspace_path / ".barragan-apply-phase.json").read_text()) == {
                "schema": "provider-keyed-v2", "phase": "destroy_applied",
            }
            assert (workspace_path / ".barragan-apply-phase.json").stat().st_mode & 0o777 == 0o640
            assert continued.empty_state_sha256 == hashlib.sha256(
                (workspace_path / "terraform.tfstate").read_bytes(),
            ).hexdigest()
            assert continued.selector_tag_cleanup_pending is True
            assert absent_catalog.paths == [
                "/droplets?page=1&per_page=200",
                "/droplets?page=1&per_page=200&type=gpus",
                "/firewalls?page=1&per_page=200",
                "/account/keys?page=1&per_page=200",
                "/tags?page=1&per_page=200",
            ]
            assert settlement_transport.calls[20:] == [
                ("GET", "/linode/instances/81234567"),
                ("GET", "/networking/firewalls/71234567"),
                ("GET", "/networking/firewalls/71234567/rules"),
                ("GET", "/networking/firewalls/71234567/devices?page=1&page_size=100"),
            ] * 2
            assert len(proof_commands) == 10
            assert proof_commands[5][-3:] == ("sudo", "-n", "true")
            assert proof_commands[6][-2:] == ("/usr/bin/printenv", "SSH_CONNECTION")
            assert proof_commands[7][-3:] == (
                "-T", "-C", "user=root,addr=8.8.8.8,host=8.8.8.8",
            )
            assert proof_commands[8][-2:] == ("root@45.79.201.25", "true")
            assert proof_commands[9][-2:] == ("/usr/bin/nmap", "--version")
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    SqlAlchemyJobRepository().get(coordinator_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], ready_child, sealed[3],
            )
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]

        absence_publish_restart = db.configure(state.uri)
        with db.bind(absence_publish_restart):
            inventory_paths = [
                "/droplets?page=1&per_page=200",
                "/droplets?page=1&per_page=200&type=gpus",
                "/firewalls?page=1&per_page=200",
                "/account/keys?page=1&per_page=200",
                "/tags?page=1&per_page=200",
            ]
            assert absent_catalog.paths == inventory_paths

            def prove_absence(parent_job_id, **options):
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_job_id, **options, transport=absent_catalog,
                    poll_interval_seconds=0,
                )

            published_absence = publish_provider_keyed_destroy_absence(
                reviewed_parent.id, environment="devtest", state_root=state_root,
                absence_preflight=prove_absence,
            )
            assert published_absence.id == coordinator_id
            assert published_absence.status == "running"
            assert published_absence.input["phase"] == "provider_absent"
            assert published_absence.events[:-1] == ready_child.events
            assert published_absence.events[-1].message == "provider_absent"
            assert published_absence.events[-1].data["applyJobId"] == destroy_apply.id
            assert published_absence.events[-1].data["previewJobId"] == destroy_preview.id
            assert published_absence.events[-1].data["selectorTagCleanupPending"] is True
            absence_event = published_absence.events[-1].data
            assert absence_event["readyJournalSha256"] == job_event_digest(ready_child.events)
            assert absence_event["previewJournalSha256"] == job_event_digest(destroy_preview.events)
            assert absence_event["applyJournalSha256"] == job_event_digest(destroy_apply.events)
            assert absence_event["verifiedAbsentDropletIds"] == list(
                continued.verified_absent_droplet_ids,
            )
            assert absence_event["verifiedAbsentFirewallId"] == continued.verified_absent_firewall_id
            assert absence_event["verifiedAbsentSshKeyId"] == continued.verified_absent_ssh_key_id
            assert (datetime.fromisoformat(absence_event["confirmationExpiresAt"])
                    - datetime.fromisoformat(absence_event["confirmationCompletedAt"])) == timedelta(seconds=30)
            assert absent_catalog.paths == inventory_paths * 3
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"]
            assert len(proof_commands) == 10 and len(host_commands) == 8
            assert len(settlement_transport.calls) == 28
            assert SqlAlchemyJobRepository().get(destroy_apply.id) == destroy_apply
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == ready_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == ready_settings
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )

        absence_recognition_restart = db.configure(state.uri)
        with db.bind(absence_recognition_restart):
            assert recognize_provider_keyed_destroy_absence(
                reviewed_parent.id, environment="devtest", state_root=state_root,
            ) == published_absence
            assert absent_catalog.paths == inventory_paths * 3
            with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
                publish_provider_keyed_destroy_absence(
                    reviewed_parent.id, environment="devtest", state_root=state_root,
                    absence_preflight=prove_absence,
                )
            assert SqlAlchemyJobRepository().get(coordinator_id) == published_absence
            assert SqlAlchemyJobRepository().get(destroy_apply.id) == destroy_apply
            assert absent_catalog.paths == inventory_paths * 3
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"]
            assert len(proof_commands) == 10 and len(host_commands) == 8
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]

        group_retirement_restart = db.configure(state.uri)
        with db.bind(group_retirement_restart):
            engagements = SqlAlchemyEngagementRepository()
            plans = SqlAlchemyDeploymentPlanRepository()
            chains = SqlAlchemySketchChainRepository()
            desired_engagement = engagements.get(engagement_id)
            desired_plan = plans.get(plan_id)
            pending_rows = tuple(sorted(chains.list_for_engagement(engagement_id),
                                        key=lambda row: row.chain_id))
            retained_state = (workspace_path / "terraform.tfstate").read_bytes()
            assert len(pending_rows) == 2
            assert all(row.status == "pending" and row.nodes == []
                       and not row.deploy_job_id and not row.terraform_working_directory
                       for row in pending_rows)
            scope_addresses = {row["address"] for row in scope["resources"]}
            assert scope_addresses == {
                "digitalocean_ssh_key.key", "digitalocean_firewall.firewall",
                "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
                *(node["terraformAddress"] for node in manifest["nodes"]),
            }

            retired_rows = retire_pending_keyed_group_after_absence(
                reviewed_parent.id, environment="devtest", state_root=state_root,
                absence_preflight=prove_absence,
            )
            retired_coordinator = SqlAlchemyJobRepository().get(coordinator_id)
            assert retired_coordinator.status == "running"
            assert retired_coordinator.input["phase"] == "pending_group_retired"
            assert retired_coordinator.events[:-1] == published_absence.events
            assert retired_coordinator.events[-1].message == "keyed_pending_provider_group_retired"
            assert retired_coordinator.events[-1].data["chainIds"] == sorted(
                row.chain_id for row in pending_rows
            )
            assert retired_coordinator.events[-1].data["chainFingerprints"] == {
                row.chain_id: sketch_chain_intent_fingerprint(row) for row in pending_rows
            }
            assert retired_coordinator.events[-1].data["retiredRecordIds"] == []
            assert absent_catalog.paths == inventory_paths * 4
            assert retired_rows == tuple(sorted(chains.list_for_engagement(engagement_id),
                                                key=lambda row: row.chain_id))
            for previous, retired in zip(pending_rows, retired_rows, strict=True):
                assert retired.status == "destroyed"
                assert retired.nodes == []
                assert retired.teardown_job_id == destroy_apply.id
                assert retired == replace(
                    previous, status="destroyed", nodes=[], teardown_job_id=destroy_apply.id,
                    updated_at=retired.updated_at,
                )
            assert engagements.get(engagement_id) == desired_engagement
            assert plans.get(plan_id) == desired_plan
            assert (workspace_path / "terraform.tfstate").read_bytes() == retained_state
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == ready_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == ready_settings
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    SqlAlchemyJobRepository().get(parent_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[2], sealed[3],
            )

        group_recognition_restart = db.configure(state.uri)
        with db.bind(group_recognition_restart):
            assert recognize_pending_keyed_group_retired(
                reviewed_parent.id, environment="devtest", state_root=state_root,
            ) == retired_rows
            assert absent_catalog.paths == inventory_paths * 4
            with pytest.raises(ProviderKeyedComprehensiveTeardownAttention):
                retire_pending_keyed_group_after_absence(
                    reviewed_parent.id, environment="devtest", state_root=state_root,
                    absence_preflight=prove_absence,
                )
            assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
            assert absent_catalog.paths == inventory_paths * 4
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"]
            assert len(proof_commands) == 10 and len(host_commands) == 8
            assert provider_transport.calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
            ]
            # This fixture has a synthetic succeeded core job, not a saved OCI
            # state seal. The real preview must stop before reserving a child
            # or contacting Terraform; a later fixture must run the core writer.
            core_preview_commands = []
            def forbidden_core_command(*args):
                core_preview_commands.append(args)
                pytest.fail("unsealed core must not reach Terraform")
            with pytest.raises(KeyedCoreDestroyPreviewAttention):
                preview_pending_keyed_oci_core_destroy(
                    reviewed_parent.id, environment="devtest", state_root=state_root,
                    command_runner=forbidden_core_command,
                )
            assert core_preview_commands == []
            assert not [job for job in SqlAlchemyJobRepository().list_for_engagement(engagement_id)
                        if job.action == CORE_DESTROY_PREVIEW_ACTION]
            assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
            assert SqlAlchemySketchChainRepository().list_for_engagement(engagement_id) == list(retired_rows)
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id) == ready_rows
            assert SqlAlchemyObserverSettingsRepository().get(engagement_id) == ready_settings
            assert (SqlAlchemyJobRepository().get(reviewed_parent.id),
                    SqlAlchemyJobRepository().get(core_id),
                    _db_lease_lookup(engagement_id)) == (
                sealed[0], current_core, sealed[3],
            )

@pytest.mark.skipif(sys.platform != "linux", reason="reviewed Terraform release is Linux-only")
def test_real_initial_plan_writer_survives_restart_and_rejects_input_tamper(tmp_path, monkeypatch):
    (state, state_root, engagement_id, core_id, plan_id, _credential_id,
     plan_job_id, _intent, _shown, saved, commands) = _write_real_initial_plan(tmp_path, monkeypatch)

    # A new SQLAlchemy state reads the same file and re-runs every source,
    # credential, plan, and workspace authority check without replaying plan.
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        transport = retrieve_sketch_transport_ssh_key(engagement_id)
        assert transport is not None
        identity = (transport.metadata.fingerprint, transport.public_key)
        decoded = preflight_planned_digitalocean_provider(
            engagement_id, core_id, plan_job_id, lease_owner=plan_id,
            environment="devtest", state_root=state_root,
        )
        assert decoded[0].core_plan_id == plan_id
        assert ensure_sketch_transport_ssh_key(engagement_id).fingerprint == identity[0]
        assert (retrieve_sketch_transport_ssh_key(engagement_id).metadata.fingerprint,
                retrieve_sketch_transport_ssh_key(engagement_id).public_key) == identity
        with pytest.raises(ProviderKeyedInitialPlanJobError):
            run_fresh_digitalocean_initial_plan_job(
                plan_job_id, lease_owner=plan_id, environment="devtest",
                state_root=state_root, template_root=tmp_path / "reviewed-upstream",
            )
        assert (retrieve_sketch_transport_ssh_key(engagement_id).metadata.fingerprint,
                retrieve_sketch_transport_ssh_key(engagement_id).public_key) == identity
        assert commands == ["version", "init", "plan", "show"]
        input_path = Path(saved.events[-1].data["inputSha256"][0][0])
        retained_input = input_path.read_bytes()
        input_path.write_bytes(retained_input + b"\n")
        with pytest.raises(ProviderKeyedPlannedStatePreflightError):
            preflight_planned_digitalocean_provider(
                engagement_id, core_id, plan_job_id, lease_owner=plan_id,
                environment="devtest", state_root=state_root,
            )
        input_path.write_bytes(retained_input)
        topology_path = decoded[1].path / ".barragan-topology.json"
        retained_topology = topology_path.read_bytes()
        topology_path.write_bytes(retained_topology + b"\n")
        with pytest.raises(ProviderKeyedPlannedStatePreflightError):
            preflight_planned_digitalocean_provider(
                engagement_id, core_id, plan_job_id, lease_owner=plan_id,
                environment="devtest", state_root=state_root,
            )


@pytest.mark.skipif(sys.platform != "linux", reason="reviewed Terraform release is Linux-only")
def test_real_initial_apply_writer_survives_restart_without_replaying_post(tmp_path, monkeypatch):
    (state, state_root, engagement_id, core_id, plan_id, _credential_id,
     plan_job_id, intent, shown, _saved, plan_commands) = _write_real_initial_plan(
         tmp_path, monkeypatch)
    selector_catalog = _EmptySelectorCatalog(intent.selector_tag)
    selector_post = _SelectorPost()
    gated, apply_commands = _gated_terraform(shown, _applied_state(intent))
    apply_id = _job_ids(core_id)[2]
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        jobs.save(_new_job(apply_id, "provider_keyed_initial_apply", jobs.get(core_id), engagement_id, {
            "engagementId": engagement_id, "coreJobId": core_id, "corePlanId": plan_id,
            "planJobId": plan_job_id, "mutation": True,
        }))
        applied = run_fresh_digitalocean_initial_apply_job(
            apply_id, environment="devtest", state_root=state_root,
            selector_transport=selector_catalog,
            selector_reservation_transport=selector_post,
            gated_command_runner=gated,
        )
        assert applied.status == "succeeded"
        assert apply_commands == ["show", "apply"]
        assert selector_post.calls == 1
        assert [event.message for event in applied.events].count(
            "provider selector creation 201 received") == 1
        assert plan_commands == ["version", "init", "plan", "show"]

    reopened = db.configure(state.uri)
    with db.bind(reopened):
        schema_root = state_root / engagement_id / "provider-keyed-v2"
        assert (schema_root / "regional-ordinals.json").is_file()
        assert not (schema_root / ".regional-ordinals.json").exists()
        phase_path = schema_root / "digitalocean" / hashlib.sha256(
            f"digitalocean\0{_credential_id}".encode()).hexdigest() / ".barragan-apply-phase.json"
        if postapply._collaborator_group_gid() is not None:
            assert phase_path.stat().st_mode & 0o777 == 0o640
        reviewed = read_applied_digitalocean_provider_for_teardown(
            engagement_id, core_id, environment="devtest", state_root=state_root,
            mode="applied_read",
        )
        assert reviewed[0].selector_tag == intent.selector_tag
        assert reviewed[3].id == apply_id
        attachment = derive_digitalocean_initial_attachment_intent(*reviewed)
        assert len(attachment.nodes) == len(intent.nodes) == 7
        catalog = _AttachmentCatalog(attachment)
        proof = reconcile_digitalocean_initial_attachment(
            reviewed[1], attachment, environment="devtest",
            deployment_target="barragan-testing",
            credential_repository=SqlAlchemyCredentialRepository(),
            transport=catalog, max_attempts=1, poll_interval_seconds=0,
        )
        assert proof.state_sha256 == applied.events[-1].data["stateSha256"]
        assert set(proof.verified_droplet_ids) == {node.droplet_id for node in attachment.nodes}
        assert len([path for path in catalog.paths if path.startswith("/droplets/")]) == 14

    # Restart the database session and rederive the exact attachment authority;
    # no Terraform command or selector POST can be repeated by these reads.
    again = db.configure(state.uri)
    with db.bind(again):
        reread = read_applied_digitalocean_provider_for_teardown(
            engagement_id, core_id, environment="devtest", state_root=state_root,
            mode="applied_read",
        )
        assert derive_digitalocean_initial_attachment_intent(*reread) == attachment
        assert reconcile_digitalocean_initial_attachment(
            reread[1], attachment, environment="devtest",
            deployment_target="barragan-testing",
            credential_repository=SqlAlchemyCredentialRepository(),
            transport=_AttachmentCatalog(attachment), max_attempts=1, poll_interval_seconds=0,
        ) == proof
        with pytest.raises(ProviderKeyedInitialApplyJobError):
            run_fresh_digitalocean_initial_apply_job(
                apply_id, environment="devtest", state_root=state_root,
                selector_transport=selector_catalog,
                selector_reservation_transport=selector_post,
                gated_command_runner=gated,
            )
        assert apply_commands == ["show", "apply"]
        assert selector_post.calls == 1
        state_path = reread[1].state_path
        retained_state = state_path.read_bytes()
        state_path.write_bytes(retained_state + b"\n")
        with pytest.raises(ProviderKeyedPostapplyPreflightError):
            read_applied_digitalocean_provider_for_teardown(
                engagement_id, core_id, environment="devtest", state_root=state_root,
                mode="applied_read",
            )
