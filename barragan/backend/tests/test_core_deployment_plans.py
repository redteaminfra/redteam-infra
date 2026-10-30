# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import pytest
from dataclasses import replace
from types import SimpleNamespace

from app.domain.deployment_plan import DeploymentPlan
from app.integrations.oci_read_validation import OciDevelopmentTarget
from app.integrations.oci_compute_profiles import canonical_oci_compute_profiles
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.integrations.pilot_standard_rti import (
    OCI_CORE_INSTANCE_AGENT_POLICY,
    OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
    build_pilot_execution_commands,
    build_pilot_standard_rti_workspace,
)
from app.services.core_deployment_plans import (
    CoreDeploymentPlanError,
    _safe_cidrs,
    _reviewed_post_core_scope,
    _assert_reviewable_sketch_schema,
    _invalidate_if_configuration_changed,
    _reviewed_keyed_image_matches,
    _reviewed_keyed_sketch_authorization,
    _reviewed_keyed_credential_snapshot,
    finish_core_deployment_plan_apply,
    begin_core_deployment_plan_apply,
    parse_terraform_plan_json,
    recover_interrupted_core_deployment_plans,
    sanitize_terraform_plan_text,
    start_core_deployment_plan,
    _validate_oci_core_instance_baseline,
    _public_compute_profile,
    _verify_plan_evidence,
)
from app.storage.deployment_plan_repository import DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import StoredSketchChain


def test_plan_json_actions_are_classified_without_exposing_change_values() -> None:
    payload = {
        "resource_changes": [
            _change("oci_core_instance.add", ["create"]),
            _change("oci_core_instance.update", ["update"]),
            _change("oci_core_instance.remove", ["delete"]),
            _change("oci_core_instance.replace_a", ["delete", "create"]),
            _change("oci_core_instance.replace_b", ["create", "delete"]),
            _change("oci_core_instance.read", ["read"]),
            _change("oci_core_instance.same", ["no-op"]),
        ],
        "output_changes": {
            "public_ip": {"actions": ["update"], "before": "secret-before", "after": "secret-after"},
            "unchanged": {"actions": ["no-op"]},
        },
    }

    counts, rows = parse_terraform_plan_json(payload)

    assert counts == {"add": 1, "update": 1, "replace": 2, "remove": 1, "read": 1, "output": 1}
    assert [row["action"] for row in rows] == ["add", "update", "remove", "replace", "replace", "read", "no_op"]
    assert all(set(row) == {"action", "address", "type", "provider", "displayName", "group"} for row in rows)


def test_planned_oci_core_instances_require_agent_and_proxy_vnic_baselines() -> None:
    payload = _planned_core_instances(proxy_count=2, elk_enabled=True)
    _validate_oci_core_instance_baseline(payload, proxy_count=2, elk_enabled=True)

    regressions = (
        ("missing homebase agent config", "oci_core_instance.homebase", "agent_config", None),
        ("monitoring enabled on proxy", "oci_core_instance.proxy01", "is_monitoring_disabled", False),
        ("ELK monitoring plugin enabled", "oci_core_instance.elk", "desired_state", "ENABLED"),
        ("extra enabled plugin", "oci_core_instance.homebase", "extra_plugin", "ENABLED"),
        ("proxy source checks enabled", "oci_core_instance.proxy02", "skip_source_dest_check", False),
    )
    for label, address, field, weakened in regressions:
        candidate = json.loads(json.dumps(payload))
        resource = next(row for row in candidate["planned_values"]["root_module"]["resources"] if row["address"] == address)
        if field == "agent_config":
            resource["values"].pop("agent_config")
        elif field == "extra_plugin":
            resource["values"]["agent_config"][0]["plugins_config"].append(
                {"name": "Vulnerability Scanning", "desired_state": weakened}
            )
        elif field == "desired_state":
            resource["values"]["agent_config"][0]["plugins_config"][0][field] = weakened
        elif field == "skip_source_dest_check":
            resource["values"]["create_vnic_details"][0][field] = weakened
        else:
            resource["values"]["agent_config"][0][field] = weakened
        with pytest.raises(CoreDeploymentPlanError) as error:
            _validate_oci_core_instance_baseline(candidate, proxy_count=2, elk_enabled=True)
        assert "missing or weakened" in error.value.errors[0], label

    missing_proxy = _planned_core_instances(proxy_count=1, elk_enabled=False)
    with pytest.raises(CoreDeploymentPlanError) as missing_error:
        _validate_oci_core_instance_baseline(missing_proxy, proxy_count=2, elk_enabled=False)
    assert "oci_core_instance.proxy02" in missing_error.value.errors[0]

    missing_dhcp = json.loads(json.dumps(payload))
    missing_dhcp["planned_values"]["root_module"]["resources"] = [
        resource for resource in missing_dhcp["planned_values"]["root_module"]["resources"]
        if resource["type"] != "oci_core_default_dhcp_options"
    ]
    with pytest.raises(CoreDeploymentPlanError) as missing_dhcp_error:
        _validate_oci_core_instance_baseline(missing_dhcp, proxy_count=2, elk_enabled=True)
    assert "default DHCP DNS policy is missing" in missing_dhcp_error.value.errors[0]

    weakened_dhcp = json.loads(json.dumps(payload))
    dhcp = next(
        resource
        for resource in weakened_dhcp["planned_values"]["root_module"]["resources"]
        if resource["type"] == "oci_core_default_dhcp_options"
    )
    dhcp["values"]["options"][0]["custom_dns_servers"] = ["169.254.169.254"]
    with pytest.raises(CoreDeploymentPlanError) as weakened_dhcp_error:
        _validate_oci_core_instance_baseline(weakened_dhcp, proxy_count=2, elk_enabled=True)
    assert "default DHCP DNS policy is missing or weakened" in weakened_dhcp_error.value.errors[0]


def test_saved_plan_apply_command_reuses_state_without_planning_variables() -> None:
    workspace = build_pilot_standard_rti_workspace(OciDevelopmentTarget())

    commands = build_pilot_execution_commands(
        workspace,
        terraform_state_path="/private/state.tfstate",
        terraform_data_dir="/private/tf-data",
        saved_plan_path="/private/core.tfplan",
    )

    apply = commands[1]
    assert apply[-1] == "/private/core.tfplan"
    assert "-state=/private/state.tfstate" in apply
    assert "-var" not in apply
    assert apply[:3] == ["env", "TF_DATA_DIR=/private/tf-data", "terraform"]


def test_keyed_plan_scope_requires_devtest_two_digitalocean_chains(monkeypatch) -> None:
    import app.services.engagements as engagements

    monkeypatch.setattr(engagements, "runtime_value", lambda *_args, **_kwargs: "devtest")
    engagement = SimpleNamespace(sketch_state_schema="provider-keyed-v2")
    chains = [
        {"middleProvider": "digitalocean", "edgeProvider": "digitalocean"},
        {"middleProvider": "digitalocean", "edgeProvider": "digitalocean"},
    ]
    revision = {"inputParameters": {"sketchChains": chains}}
    _assert_reviewable_sketch_schema(engagement, revision)
    with pytest.raises(CoreDeploymentPlanError) as one_chain:
        _assert_reviewable_sketch_schema(engagement, {"inputParameters": {"sketchChains": chains[:1]}})
    assert "exactly two" in one_chain.value.errors[0]
    with pytest.raises(CoreDeploymentPlanError) as wrong_target:
        _assert_reviewable_sketch_schema(engagement, {"inputParameters": {
            "sketchChains": chains, "deploymentTarget": "sk02-dev",
        }})
    assert "barragan-testing" in wrong_target.value.errors[0]
    monkeypatch.setattr(engagements, "runtime_value", lambda *_args, **_kwargs: "production")
    with pytest.raises(CoreDeploymentPlanError) as wrong_environment:
        _assert_reviewable_sketch_schema(engagement, revision)
    assert "DevTest" in wrong_environment.value.errors[0]


def test_keyed_core_apply_stops_before_split_continuation_or_job(monkeypatch) -> None:
    import app.services.core_deployment_plans as service

    plan = DeploymentPlan(
        "dpl-keyed", "eng-keyed", "rev-keyed", "ready", "ready",
        evidence={"sketchStateSchema": "provider-keyed-v2"},
    )
    monkeypatch.setattr("app.services.engagement_teardown.assert_core_creation_allowed", lambda _id: None)
    monkeypatch.setattr(service, "get_core_deployment_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(service, "_verify_plan_evidence", lambda _plan: None)
    started = []
    with pytest.raises(CoreDeploymentPlanError) as blocked:
        begin_core_deployment_plan_apply(
            plan.engagement_id, plan.id, {}, job_starter=lambda *_args, **_kwargs: started.append(True),
        )
    assert "provider-scoped rollout and teardown" in blocked.value.errors[0]
    assert started == []


def test_keyed_plan_binds_exact_digitalocean_image_not_only_profile_name() -> None:
    profile = managed_host_image_profile_named("ubuntu-24.04")
    evidence = {
        "sketchStateSchema": "provider-keyed-v2",
        "managedHostImageProfile": profile.name,
        "digitaloceanImage": profile.digitalocean_image,
    }
    assert _reviewed_keyed_image_matches(evidence)
    assert not _reviewed_keyed_image_matches({**evidence, "digitaloceanImage": "ubuntu-20-04-x64"})
    assert not _reviewed_keyed_image_matches({**evidence, "digitaloceanImage": None})
    assert _reviewed_keyed_image_matches({"sketchStateSchema": "split-v1"})


def test_keyed_plan_response_exposes_reviewed_image_slug() -> None:
    profile = managed_host_image_profile_named("ubuntu-24.04")
    plan = DeploymentPlan(
        "dpl-keyed", "eng-keyed", "rev-keyed", "ready", "ready",
        review={"reviewedConfiguration": {"digitaloceanImage": profile.digitalocean_image}},
    )
    assert plan.to_dict()["reviewedConfiguration"]["digitaloceanImage"] == profile.digitalocean_image


def test_keyed_review_authorizes_two_persisted_chains_without_unknown_proxy_ips(monkeypatch) -> None:
    from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
    from app.services.sketch_chains import _template_chain_intent
    from app.services import provider_keyed_sketch

    monkeypatch.setattr("app.services.sketch_chains._validate_allowed_regions", lambda *_args: None)
    first = replace(_template_chain_intent("eng-keyed", {
        "assignedProxy": "proxy01", "middleProvider": "digitalocean", "middleRegion": "sfo3",
        "middleSize": "s-1vcpu-1gb", "edgeProvider": "digitalocean", "edgeRegion": "nyc3",
        "edgeSize": "s-1vcpu-1gb", "edgeCount": 1,
    }), chain_id="chain-a")
    second = replace(_template_chain_intent("eng-keyed", {
        "assignedProxy": "proxy02", "middleProvider": "digitalocean", "middleRegion": "sea1",
        "middleSize": "s-1vcpu-1gb", "edgeProvider": "digitalocean", "edgeRegion": "sfo3",
        "edgeSize": "s-1vcpu-1gb", "edgeCount": 1,
    }), chain_id="chain-b")
    records = [first, second]
    monkeypatch.setattr("app.services.core_deployment_plans.SqlAlchemySketchChainRepository",
                        lambda: SimpleNamespace(list_for_engagement=lambda _id: records))
    connection = {"id": "cred-shared-team"}
    monkeypatch.setattr(provider_keyed_sketch, "resolve_default_provider_connection",
                        lambda provider: connection["id"])
    scope = {"chains": [
        {"id": record.chain_id, "assignedProxy": record.assigned_proxy,
         "middle": {"region": record.middle_region},
         "edges": [{"id": edge["id"], "provider": edge["provider"], "region": edge["region"]}
                   for edge in record.edge_intents]}
        for record in records
    ]}
    fingerprints = {record.chain_id: sketch_chain_intent_fingerprint(record) for record in records}

    reviewed = _reviewed_keyed_sketch_authorization("eng-keyed", scope, fingerprints, "ubuntu-24-04-x64")

    assert reviewed["providerConnectionId"] == "cred-shared-team"
    assert [chain["id"] for chain in reviewed["chains"]] == ["chain-a", "chain-b"]
    assert [chain["assignedProxy"] for chain in reviewed["chains"]] == ["proxy01", "proxy02"]
    assert reviewed["chains"][0]["middle"]["size"] == "s-1vcpu-1gb"
    assert reviewed["chains"][1]["edges"][0]["region"] == "sfo3"
    assert reviewed["firewall"] == {
        "publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
        "publicIpv6Allowed": False,
        "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                          "proxyNames": ["proxy01", "proxy02"]},
        "peerIngress": {"protocols": ["tcp", "udp", "icmp"], "portRange": "1-65535",
                        "sourceRule": "all-created-middle-and-edge-public-ipv4-32"},
        "outboundIpv4": [
            {"protocol": "tcp", "portRange": "1-65535", "destination": "0.0.0.0/0"},
            {"protocol": "udp", "portRange": "1-65535", "destination": "0.0.0.0/0"},
            {"protocol": "icmp", "destination": "0.0.0.0/0"},
        ],
    }
    assert reviewed["source"] == {
        "revision": "cae68e63b8495f0e6d31dfa4a991f4024f18e58b",
        "templateSha256": "0fcadb0560b4f765ae521788e0d2db55cdba0147d6eacc5a933235ee23c98f60",
        "providerLock": {
            "path": "barragan-v2/.terraform.lock.hcl",
            "sha256": "0e6a4207cca9db67bba23b918748e02c4d32c1c504e09bad54e5d37751d99736",
            "digitaloceanVersion": "2.103.0",
        },
    }
    assert "192." not in repr(reviewed)
    assert "token" not in repr(reviewed)
    assert reviewed["fingerprint"]

    # Rotating a secret on the same connection leaves the review stable;
    # switching the default connection or changing a chain requires review.
    assert _reviewed_keyed_sketch_authorization("eng-keyed", scope, fingerprints,
                                                 "ubuntu-24-04-x64") == reviewed
    connection["id"] = "cred-other-team"
    assert _reviewed_keyed_sketch_authorization("eng-keyed", scope, fingerprints,
                                                 "ubuntu-24-04-x64") != reviewed
    connection["id"] = "cred-shared-team"
    records[1] = replace(second, edge_size="s-2vcpu-2gb")
    with pytest.raises(CoreDeploymentPlanError):
        _reviewed_keyed_sketch_authorization("eng-keyed", scope, fingerprints, "ubuntu-24-04-x64")


def test_mixed_keyed_review_seals_both_provider_states_and_rejects_stale_intent(
    monkeypatch,
) -> None:
    from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
    from app.services.sketch_chains import _template_chain_intent
    from app.services import provider_keyed_sketch

    monkeypatch.setattr("app.services.sketch_chains._validate_allowed_regions", lambda *_args: None)
    records = [
        replace(_template_chain_intent("eng-keyed", {
            "assignedProxy": "proxy01", "middleProvider": "linode", "middleRegion": "us-east",
            "middleSize": "g6-nanode-1", "edgeProvider": "linode", "edgeRegion": "us-west",
            "edgeSize": "g6-nanode-1", "edgeCount": 1,
        }), chain_id="chain-linode"),
        replace(_template_chain_intent("eng-keyed", {
            "assignedProxy": "proxy01", "middleProvider": "digitalocean", "middleRegion": "sfo3",
            "middleSize": "s-1vcpu-1gb", "edgeProvider": "digitalocean", "edgeRegion": "nyc3",
            "edgeSize": "s-1vcpu-1gb", "edgeCount": 1,
        }), chain_id="chain-digitalocean"),
    ]
    monkeypatch.setattr("app.services.core_deployment_plans.SqlAlchemySketchChainRepository",
                        lambda: SimpleNamespace(list_for_engagement=lambda _id: records))
    connections = {"linode": "cred-linode", "digitalocean": "cred-digitalocean"}
    monkeypatch.setattr(provider_keyed_sketch, "resolve_default_provider_connection",
                        lambda provider: connections[provider])
    scope = {"chains": [{
        "id": record.chain_id, "assignedProxy": record.assigned_proxy,
        "middle": {"provider": record.middle_provider, "region": record.middle_region},
        "edges": [{"id": edge["id"], "provider": edge["provider"],
                   "region": edge["region"]} for edge in record.edge_intents],
    } for record in records]}
    fingerprints = {record.chain_id: sketch_chain_intent_fingerprint(record)
                    for record in records}
    profile = managed_host_image_profile_named("ubuntu-24.04")
    reviewed = _reviewed_keyed_sketch_authorization(
        "eng-keyed", scope, fingerprints, profile.digitalocean_image, profile.linode_image)
    assert reviewed["kind"] == "bounded-mixed-post-core-v1"
    assert [row["provider"] for row in reviewed["providerScopes"]] == ["digitalocean", "linode"]
    assert {row["provider"]: row["image"] for row in reviewed["providerScopes"]} == {
        "digitalocean": profile.digitalocean_image, "linode": profile.linode_image}
    assert {row["provider"]: row["providerConnectionId"] for row in reviewed["providerScopes"]} == connections
    assert {row["provider"]: row["source"]["templateSha256"]
            for row in reviewed["providerScopes"]} == {
        "digitalocean": "0fcadb0560b4f765ae521788e0d2db55cdba0147d6eacc5a933235ee23c98f60",
        "linode": "d0f3292ede53e09766f2710df3bc040410eaad24edd5f2f0d14b0dc8cf65d7ef",
    }
    assert {row["provider"]: row["source"]["providerLock"]["sha256"]
            for row in reviewed["providerScopes"]} == {
        "digitalocean": "0e6a4207cca9db67bba23b918748e02c4d32c1c504e09bad54e5d37751d99736",
        "linode": "40e181997472ad02b0a68ef1b826c745f2d69c41426ab2a6d7000f9261399a49",
    }
    assert all(row["firewall"]["publicTcpPorts"] == ["80", "443", "2222"]
               and row["firewall"]["managementSsh"]["sourceRule"] ==
               "selected-proxy-public-ipv4-32" for row in reviewed["providerScopes"])
    assert "token" not in repr(reviewed)
    assert _reviewed_keyed_sketch_authorization(
        "eng-keyed", scope, fingerprints, profile.digitalocean_image, profile.linode_image) == reviewed
    connections["linode"] = "other-connection"
    assert _reviewed_keyed_sketch_authorization(
        "eng-keyed", scope, fingerprints, profile.digitalocean_image, profile.linode_image) != reviewed
    connections["linode"] = "cred-linode"
    records[0] = replace(records[0], edge_size="g6-standard-1")
    with pytest.raises(CoreDeploymentPlanError):
        _reviewed_keyed_sketch_authorization(
            "eng-keyed", scope, fingerprints, profile.digitalocean_image,
            profile.linode_image)


@pytest.mark.parametrize("drift", ["connection", "secret_rotation"])
def test_keyed_plan_invalidates_when_provider_authorization_changes(monkeypatch, drift: str) -> None:
    import app.services.core_deployment_plans as service

    revision = {"id": "rev-keyed", "templateId": "standard-rti", "inputParameters": {}}
    standard = canonical_oci_compute_profiles()["standard-rti"]
    image_profile = managed_host_image_profile_named("ubuntu-24.04")
    engagement = SimpleNamespace(active_revision="rev-keyed", template_id="standard-rti",
                                 sketch_state_schema="provider-keyed-v2")
    target = SimpleNamespace(name="barragan-testing", region="us-sanjose-1", compartment_id="ocid")
    authorization = {"providerConnectionId": "cred-original", "fingerprint": "original"}
    evidence = {
        "sketchStateSchema": "provider-keyed-v2",
        "revisionFingerprint": service._json_hash(revision),
        "capabilitySelectionFingerprint": service._json_hash({}),
        "targetFingerprint": service._json_hash({"name": target.name, "region": target.region,
                                                 "compartmentId": target.compartment_id}),
        "sketchIntentFingerprint": "same",
        "computeProfileFingerprint": standard.fingerprint,
        "computeProfileSnapshot": standard.to_dict(),
        "ociCoreInstanceBaselineFingerprint": OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
        "managedHostImageProfile": image_profile.name,
        "digitaloceanImage": image_profile.digitalocean_image,
        "sketchAuthorization": authorization,
        "keyedProviderCredentialSnapshot": {"generation": "original"},
    }
    plan = DeploymentPlan("dpl-keyed", "eng-keyed", "rev-keyed", "ready", "ready",
                          review={"reviewedConfiguration": {"sketchAuthorization": authorization}},
                          evidence=evidence)
    monkeypatch.setattr(service, "get_engagement", lambda _id: engagement)
    monkeypatch.setattr(service, "get_revision", lambda _id: revision)
    monkeypatch.setattr(service, "_assert_reviewable_sketch_schema", lambda *_args: None)
    monkeypatch.setattr(service, "_reviewed_post_core_scope", lambda *_args: ({}, [], "same", {}))
    monkeypatch.setattr(service, "_reviewed_keyed_sketch_authorization",
                        lambda *_args: {**authorization, "providerConnectionId": "cred-other"}
                        if drift == "connection" else authorization)
    monkeypatch.setattr(service, "_reviewed_keyed_credential_snapshot",
                        lambda *_args: {"generation": "rotated"}
                        if drift == "secret_rotation" else {"generation": "original"})
    monkeypatch.setattr(service, "_cleanup_unapplied_plan_artifacts", lambda _plan: None)
    monkeypatch.setattr("app.services.guarded_test_deployment._target_for_engagement",
                        lambda _engagement: target)
    monkeypatch.setattr(
        "app.storage.engagement_workspace_repository.SqlAlchemyEngagementWorkspaceRepository.get",
        lambda _repo, _id: SimpleNamespace(metadata={}),
    )

    result = _invalidate_if_configuration_changed(plan, SimpleNamespace(save=lambda updated: updated))

    assert result.status == "invalidated"
    assert "prepare a new plan" in result.error


def test_keyed_credential_snapshot_is_private_and_detects_same_connection_rotation(monkeypatch) -> None:
    from app.storage.credential_repository import StoredCredential
    from app.storage import credential_repository

    record = StoredCredential(
        id="cred-shared", provider="digitalocean", alias="shared", status="active",
        description="", encrypted_secret="encrypted-generation-one", is_default=True,
        created_at="2026-10-01T00:00:00+00:00", updated_at="2026-10-01T00:00:00+00:00",
    )
    current = {"record": record}
    monkeypatch.setattr(credential_repository, "SqlAlchemyCredentialRepository",
                        lambda: SimpleNamespace(get=lambda _id: current["record"],
                                                get_default=lambda _provider: current["record"]))

    before = _reviewed_keyed_credential_snapshot("cred-shared")
    assert set(before) == {"encryptedSecretSha256", "updatedAt"}
    assert "encrypted-generation-one" not in repr(before)
    current["record"] = replace(record, encrypted_secret="encrypted-generation-two",
                                updated_at="2026-10-02T00:00:00+00:00")
    after = _reviewed_keyed_credential_snapshot("cred-shared")
    assert after != before
    with pytest.raises(CoreDeploymentPlanError):
        _reviewed_keyed_credential_snapshot("cred-other")


def test_mixed_keyed_plan_persists_both_credential_generations_and_restart_detects_rotation(
    client, monkeypatch,
) -> None:
    import app.services.core_deployment_plans as service
    from app.storage.credential_repository import StoredCredential
    from app.storage import credential_repository

    records = {provider: StoredCredential(
        id=f"cred-{provider}", provider=provider, alias="shared", status="active",
        description="", encrypted_secret=f"encrypted-{provider}-one", is_default=True,
        created_at="2026-10-01T00:00:00+00:00", updated_at="2026-10-01T00:00:00+00:00",
    ) for provider in ("digitalocean", "linode")}
    monkeypatch.setattr(credential_repository, "SqlAlchemyCredentialRepository",
                        lambda: SimpleNamespace(
                            get=lambda identifier: next((row for row in records.values()
                                if row.id == identifier), None),
                            get_default=lambda provider: records.get(provider)))
    scopes = [{"provider": provider, "providerConnectionId": f"cred-{provider}",
               "source": {"revision": "pinned", "providerLock": {"sha256": "pinned"}},
               "firewall": {"managementSsh": "selected-proxy"}}
              for provider in ("digitalocean", "linode")]
    authorization = {"kind": "bounded-mixed-post-core-v1", "providerScopes": scopes}
    revision = {"id": "rev-1", "templateId": "standard-rti", "inputParameters": {}}
    compute = canonical_oci_compute_profiles()["standard-rti"]
    target = SimpleNamespace(name="barragan-testing", region="us-sanjose-1",
                             compartment_id="ocid")
    evidence = {
        "sketchStateSchema": "provider-keyed-v2",
        "revisionFingerprint": service._json_hash(revision),
        "capabilitySelectionFingerprint": service._json_hash({}),
        "targetFingerprint": service._json_hash({
            "name": target.name, "region": target.region,
            "compartmentId": target.compartment_id}),
        "sketchIntentFingerprint": "same",
        "computeProfileFingerprint": compute.fingerprint,
        "computeProfileSnapshot": compute.to_dict(),
        "ociCoreInstanceBaselineFingerprint": OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
        "managedHostImageProfile": "ubuntu-24.04",
        "linodeImage": managed_host_image_profile_named("ubuntu-24.04").linode_image,
        "digitaloceanImage": managed_host_image_profile_named("ubuntu-24.04").digitalocean_image,
        "sketchAuthorization": authorization,
        "keyedProviderCredentialSnapshots": {
            scope["provider"]: _reviewed_keyed_credential_snapshot(
                scope["providerConnectionId"], scope["provider"])
            for scope in scopes},
    }
    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.save(DeploymentPlan("dpl-mixed-review", "eng-of02-dev", "rev-1",
                                    "ready", "ready", evidence=evidence,
                                    review={"reviewedConfiguration": {
                                        "sketchAuthorization": authorization}}))
    engagement = SimpleNamespace(active_revision="rev-1", template_id="standard-rti",
                                 sketch_state_schema="provider-keyed-v2")
    monkeypatch.setattr(service, "get_engagement", lambda _id: engagement)
    monkeypatch.setattr(service, "get_revision", lambda _id: revision)
    monkeypatch.setattr(service, "_assert_reviewable_sketch_schema", lambda *_args: None)
    monkeypatch.setattr(service, "_reviewed_post_core_scope",
                        lambda *_args: ({}, [], "same", {}))
    monkeypatch.setattr(service, "_reviewed_keyed_sketch_authorization",
                        lambda *_args: authorization)
    monkeypatch.setattr(service, "_cleanup_unapplied_plan_artifacts", lambda _plan: None)
    monkeypatch.setattr("app.services.guarded_test_deployment._target_for_engagement",
                        lambda _engagement: target)
    monkeypatch.setattr(
        "app.storage.engagement_workspace_repository.SqlAlchemyEngagementWorkspaceRepository.get",
        lambda _repo, _id: SimpleNamespace(metadata={}))
    reopened = SqlAlchemyDeploymentPlanRepository().get(plan.id)
    assert reopened is not None and service._reviewed_keyed_credentials_match(reopened.evidence)
    assert service.get_core_deployment_plan(plan.engagement_id, plan.id).status == "ready"
    stale_authorization = json.loads(json.dumps(authorization))
    stale_authorization["providerScopes"][1]["firewall"]["managementSsh"] = "public"
    stale = repo.save(DeploymentPlan("dpl-mixed-stale", "eng-of02-dev", "rev-1",
        "ready", "ready", evidence={**evidence, "sketchAuthorization": stale_authorization},
        review={"reviewedConfiguration": {"sketchAuthorization": stale_authorization}}))
    assert service.get_core_deployment_plan(stale.engagement_id, stale.id).status == "invalidated"
    assert _reviewed_keyed_image_matches(reopened.evidence)
    assert "encrypted-digitalocean-one" not in repr(reopened.evidence)
    assert "encrypted-linode-one" not in repr(reopened.evidence)
    records["linode"] = replace(records["linode"], encrypted_secret="encrypted-linode-two",
                                updated_at="2026-10-02T00:00:00+00:00")
    assert not service._reviewed_keyed_credentials_match(
        SqlAlchemyDeploymentPlanRepository().get(plan.id).evidence)
    assert service.get_core_deployment_plan(plan.engagement_id, plan.id).status == "invalidated"
    assert not _reviewed_keyed_image_matches({**evidence, "linodeImage": "old-image"})


def test_malformed_mixed_keyed_private_apply_rejects_before_mutation(client, monkeypatch) -> None:
    import app.services.core_deployment_plans as service
    from app.services import guarded_test_deployment

    plan = DeploymentPlan("dpl-mixed", "eng-of02-dev", "rev-1", "ready", "ready",
        evidence={"sketchStateSchema": "provider-keyed-v2", "sketchAuthorization": {
            "kind": "bounded-mixed-post-core-v1"}})
    engagement = SimpleNamespace(sketch_state_schema="provider-keyed-v2", active_revision="rev-1")
    monkeypatch.setattr(service, "runtime_value", lambda *_args: "devtest")
    monkeypatch.setattr(service, "get_engagement", lambda _id: engagement)
    monkeypatch.setattr(service, "get_core_deployment_plan", lambda *_args, **_kw: plan)
    monkeypatch.setattr(service, "_verify_plan_evidence", lambda _plan: None)
    monkeypatch.setattr(guarded_test_deployment, "_target_for_engagement",
                        lambda _engagement: SimpleNamespace(name="barragan-testing"))
    monkeypatch.setattr("app.services.engagement_teardown.assert_core_creation_allowed",
                        lambda _id: None)
    with pytest.raises(CoreDeploymentPlanError) as stopped:
        service._begin_private_devtest_keyed_core_plan_apply("eng-of02-dev", plan.id)
    assert "reviewed mixed Small Dev scope differs" in stopped.value.errors[0]


def test_core_plan_invalidates_if_persisted_schema_changes_after_review(monkeypatch) -> None:
    import app.services.core_deployment_plans as service

    revision = {"id": "rev-1", "templateId": "standard-rti", "inputParameters": {}}
    standard = canonical_oci_compute_profiles()["standard-rti"]
    engagement = SimpleNamespace(active_revision="rev-1", template_id="standard-rti", sketch_state_schema="provider-keyed-v2")
    target = SimpleNamespace(name="barragan-testing", region="us-sanjose-1", compartment_id="ocid")
    evidence = {
        "sketchStateSchema": "split-v1",
        "revisionFingerprint": service._json_hash(revision),
        "capabilitySelectionFingerprint": service._json_hash({}),
        "targetFingerprint": service._json_hash({"name": target.name, "region": target.region, "compartmentId": target.compartment_id}),
        "sketchIntentFingerprint": "same",
        "computeProfileFingerprint": standard.fingerprint,
        "computeProfileSnapshot": standard.to_dict(),
        "ociCoreInstanceBaselineFingerprint": OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
    }
    plan = DeploymentPlan("dpl-1", "eng-1", "rev-1", "ready", "ready", evidence=evidence)
    monkeypatch.setattr(service, "get_engagement", lambda _id: engagement)
    monkeypatch.setattr(service, "get_revision", lambda _id: revision)
    monkeypatch.setattr(service, "_reviewed_post_core_scope", lambda *_args: ({}, [], "same", {}))
    monkeypatch.setattr(service, "_cleanup_unapplied_plan_artifacts", lambda _plan: None)
    monkeypatch.setattr(
        "app.services.guarded_test_deployment._target_for_engagement", lambda _engagement: target,
    )
    monkeypatch.setattr(
        "app.storage.engagement_workspace_repository.SqlAlchemyEngagementWorkspaceRepository.get",
        lambda _repo, _id: SimpleNamespace(metadata={}),
    )
    repository = SimpleNamespace(save=lambda updated: updated)
    invalidated = _invalidate_if_configuration_changed(plan, repository)
    assert invalidated.status == "invalidated"
    assert "prepare a new plan" in invalidated.error


def test_public_plan_shape_never_serializes_private_evidence() -> None:
    plan = DeploymentPlan(
        id="dpl-opaque",
        engagement_id="eng-of02-dev",
        revision_id="rev-1",
        status="ready",
        stage="ready",
        review={"counts": {"add": 1}, "terraformFiles": [{"path": "main.tf", "content": "resource {}"}]},
        evidence={"planPath": "/private/core.tfplan", "sshPrivateKeyPath": "/private/id_ed25519", "raw": {"secret": "x"}},
    )

    body = plan.to_dict()

    assert "evidence" not in body
    assert "/private" not in repr(body)
    assert "secret" not in repr(body)


def test_public_compute_profile_uses_stable_sanitized_contract() -> None:
    profile = canonical_oci_compute_profiles()["standard-rti"]
    snapshot = _public_compute_profile(profile, "Standard RTI", 2, True)

    assert snapshot == {
        "id": "standard-rti",
        "name": "Standard RTI",
        "fingerprint": profile.fingerprint,
        "bootVolumeSizeGiB": 512,
        "roles": [
            {"role": "homebase", "label": "Homebase", "nodeCount": 1, "shape": "BM.Standard3.64", "ocpus": 64, "memoryGiB": 1024},
            {"role": "proxy", "label": "Proxy", "nodeCount": 2, "shape": "VM.Standard.E4.Flex", "ocpus": 2, "memoryGiB": 32},
            {"role": "elk", "label": "ELK", "nodeCount": 1, "shape": "VM.Standard.E4.Flex", "ocpus": 2, "memoryGiB": 32},
        ],
    }


@pytest.mark.parametrize("profile_evidence", ["changed", "legacy-missing"])
def test_prepared_plan_compute_profile_integrity_fails_closed(monkeypatch, profile_evidence) -> None:
    import app.services.core_deployment_plans as service

    revision = {"id": "rev-profile", "templateId": "standard-rti", "inputParameters": {}}
    standard = canonical_oci_compute_profiles()["standard-rti"]
    evidence = {
        "planPath": "/protected/core.tfplan",
        "planFingerprint": "same",
        "runDirectory": "/protected/run",
        "sourceFingerprint": "same",
        "bundleFingerprint": "same",
        "providerLockFingerprint": "same",
        "terraformStatePath": "/protected/state",
        "stateFingerprint": "same",
        "sshPublicKeyPath": "/protected/public",
        "publicKeyFingerprint": "same",
        "sshPrivateKeyPath": "/protected/private",
        "privateKeyFingerprint": "same",
        "terraformDataDir": "/protected/data",
        "terraformFingerprint": "same",
        "sshSourceCidrs": ["192.0.2.0/24"],
        "inputFingerprint": service._json_hash({"revisionId": "rev-profile", "cidrs": ["192.0.2.0/24"]}),
        "revisionFingerprint": service._json_hash(revision),
        "capabilitySelectionFingerprint": service._json_hash({}),
        "targetFingerprint": service._json_hash({"name": "testing", "region": "region-1", "compartmentId": "ocid"}),
        "sketchIntentFingerprint": "sketch",
    }
    if profile_evidence == "changed":
        evidence.update(
            computeProfileSnapshot=standard.to_dict(),
            computeProfileFingerprint=standard.fingerprint,
            ociCoreInstanceBaselineFingerprint=OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
        )

    monkeypatch.setattr(service, "_file_hash", lambda _path: "same")
    monkeypatch.setattr(service, "_tree_hash", lambda *_args, **_kwargs: "same")
    monkeypatch.setattr(service, "_terraform_version", lambda *_args, **_kwargs: "same")
    monkeypatch.setattr(service, "get_engagement", lambda _id: SimpleNamespace(active_revision="rev-profile", template_id="standard-rti"))
    monkeypatch.setattr(service, "get_revision", lambda _id: revision)
    monkeypatch.setattr(service, "_reviewed_post_core_scope", lambda *_args: ({}, [], "sketch", {}))
    monkeypatch.setattr(service, "resolve_terraform", lambda: SimpleNamespace(command="terraform"))
    monkeypatch.setattr(
        "app.services.guarded_test_deployment._target_for_engagement",
        lambda _engagement: SimpleNamespace(name="testing", region="region-1", compartment_id="ocid"),
    )
    monkeypatch.setattr(
        "app.storage.engagement_workspace_repository.SqlAlchemyEngagementWorkspaceRepository.get",
        lambda _repo, _id: SimpleNamespace(metadata={}),
    )
    if profile_evidence == "changed":
        monkeypatch.setattr(service, "resolve_oci_compute_profile", lambda _id: canonical_oci_compute_profiles()["dev-infra"])

    plan = DeploymentPlan("dpl-profile", "eng-profile", "rev-profile", "ready", "ready", evidence=evidence)
    with pytest.raises(CoreDeploymentPlanError) as exc_info:
        _verify_plan_evidence(plan)
    assert "compute profile" in exc_info.value.errors[0]
    if profile_evidence == "legacy-missing":
        assert "OCI core instance baseline" in exc_info.value.errors[0]


def test_real_terraform_text_sanitizer_preserves_structure_and_removes_values() -> None:
    raw = '''Terraform will perform the following actions:

  # oci_core_instance.homebase will be created
  + resource "oci_core_instance" "homebase" {
      + display_name = "opaque-host"
      + private_key_path = "/private/id_ed25519"
      + user_data = "super-secret"
      + metadata = {
          + "ssh_authorized_keys" = <<-EOT
                ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjt263qblNJ3I1Spf1mw+b3c1JLg4OB2dTMNEzwzEo2 disposable
            EOT
        }
      + allowed_cidrs = [
          + "198.51.100.4/32",
        ]
      + id = (known after apply)
    }
'''

    sanitized = sanitize_terraform_plan_text(raw)

    assert "Terraform will perform" in sanitized
    assert "oci_core_instance.homebase" in sanitized
    assert "opaque-host" not in sanitized
    assert "/private" not in sanitized
    assert "super-secret" not in sanitized
    assert "198.51.100.4" not in sanitized
    assert "ssh-ed25519" not in sanitized
    assert "AAAAC3" not in sanitized
    assert "disposable" not in sanitized
    assert "<sensitive attribute redacted>" in sanitized


def test_trusted_cidrs_are_normalized_and_public_internet_is_rejected() -> None:
    assert _safe_cidrs(["192.0.2.4/24", "192.0.2.0/24"]) == ["192.0.2.0/24"]
    with pytest.raises(CoreDeploymentPlanError) as public_error:
        _safe_cidrs(["0.0.0.0/0"])
    assert "must not include" in public_error.value.errors[0]
    with pytest.raises(CoreDeploymentPlanError) as invalid_error:
        _safe_cidrs(["not-a-cidr"])
    assert "invalid trusted SSH CIDR" in invalid_error.value.errors[0]


def test_lease_excludes_parallel_core_mutations_and_recovery_fails_closed(client) -> None:
    repo = SqlAlchemyDeploymentPlanRepository()
    first = repo.save(DeploymentPlan("dpl-first", "eng-of02-dev", "rev-1", "preparing", "terraform_plan"))
    repo.acquire(first.engagement_id, first.id, "prepare")

    with pytest.raises(DeploymentPlanConflictError):
        repo.acquire(first.engagement_id, "dpl-second", "apply")

    recover_interrupted_core_deployment_plans()
    recovered = repo.get(first.id)
    assert recovered is not None
    assert recovered.status == "failed"
    assert "interrupted" in recovered.error
    repo.acquire(first.engagement_id, "dpl-second", "apply")
    repo.release(first.engagement_id, "dpl-second")


def test_api_plan_response_is_sanitized_and_engagement_scoped(client) -> None:
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.save(
        DeploymentPlan(
            "dpl-api",
            "eng-of02-dev",
            "rev-1",
            "ready",
            "ready",
            review={"counts": {"add": 1}, "sanitizedText": "ADD oci_core_instance.homebase"},
            evidence={"planPath": "/private/core.tfplan", "rawPlan": {"sensitive": True}},
        )
    )

    response = client.get("/api/engagements/eng-of02-dev/deployment-plans/dpl-api")

    assert response.status_code == 200
    body = response.get_json()
    assert body["plan"]["id"] == "dpl-api"
    assert body["plan"]["status"] == "invalidated"
    assert body["plan"]["sanitizedTextKind"] == "summary"
    assert "/private" not in repr(body)
    assert client.get("/api/engagements/another/deployment-plans/dpl-api").status_code == 404


def test_legacy_direct_core_run_rejects_ordinary_deployment_without_saved_plan(client) -> None:
    readiness = client.get(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness",
        query_string={"engagementId": "eng-of02-dev"},
    ).get_json()["readiness"]

    response = client.post(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/runs",
        json={
            "engagementId": "eng-of02-dev",
            "confirmMutation": readiness["confirmationToken"],
            "sshSourceCidrs": ["192.0.2.0/24"],
        },
    )

    assert response.status_code == 400
    assert "corePlanId is required" in response.get_json()["error"]


def test_legacy_direct_core_run_maps_teardown_recovery_fence_to_409(client, monkeypatch) -> None:
    from app.services.engagement_teardown import EngagementTeardownValidationError

    monkeypatch.setattr(
        "app.asgi.run_guarded_pilot_standard_rti",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            EngagementTeardownValidationError([
                "engagement cleanup recovery is required through comprehensive teardown job-parent before creating core infrastructure"
            ])
        ),
    )
    response = client.post(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/run",
        json={"engagementId": "eng-of02-dev"},
    )

    assert response.status_code == 409
    assert response.get_json() == {"errors": [
        "engagement cleanup recovery is required through comprehensive teardown job-parent before creating core infrastructure"
    ]}


def test_malformed_comprehensive_teardown_preview_maps_to_controlled_400(client, monkeypatch) -> None:
    from app.services.engagement_teardown import EngagementTeardownValidationError

    monkeypatch.setattr(
        "app.asgi.preview_engagement_teardown",
        lambda _job_id: (_ for _ in ()).throw(
            EngagementTeardownValidationError(["comprehensive teardown recovery boundary is invalid"])
        ),
    )
    response = client.get(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-malformed/teardown"
    )

    assert response.status_code == 400
    assert response.get_json() == {"errors": ["comprehensive teardown recovery boundary is invalid"]}


def test_public_core_run_cannot_forge_private_prepared_plan_evidence(client) -> None:
    readiness = client.get(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness",
        query_string={"engagementId": "eng-of02-dev"},
    ).get_json()["readiness"]
    with client.application.storage_context():
        before = len(SqlAlchemyJobRepository().list())

    response = client.post(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/runs",
        json={
            "engagementId": "eng-of02-dev",
            "confirmMutation": readiness["confirmationToken"],
            "sshSourceCidrs": ["192.0.2.0/24"],
            "corePlanId": "dpl-forged",
            "preparedCoreRun": {
                "runDirectory": "/tmp/attacker-run",
                "planPath": "/tmp/attacker-run/core.tfplan",
                "terraformDataDir": "/tmp/attacker-tf-data",
                "terraformStatePath": "/tmp/attacker.tfstate",
            },
            "workspaceDir": "/tmp/attacker-workspace",
        },
    )

    assert response.status_code == 400
    assert "server-managed" in response.get_json()["error"]
    with client.application.storage_context():
        assert len(SqlAlchemyJobRepository().list()) == before


def test_allowed_legacy_recreate_still_obeys_shared_core_lease(client) -> None:
    readiness = client.get(
        "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness",
        query_string={"engagementId": "eng-of02-dev"},
    ).get_json()["readiness"]
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.acquire("eng-of02-dev", "plan-in-progress", "prepare")
    try:
        response = client.post(
            "/api/orchestrator/barragan-testing/pilot-standard-rti/runs",
            json={
                "engagementId": "eng-of02-dev",
                "confirmMutation": readiness["confirmationToken"],
                "sshSourceCidrs": ["192.0.2.0/24"],
                "recreateCore": True,
            },
        )
    finally:
        repo.release("eng-of02-dev", "plan-in-progress")

    assert response.status_code == 400
    assert "another core mutation" in response.get_json()["error"]


def test_core_plan_lease_blocks_public_sketch_intent_mutation(client) -> None:
    from app.services.sketch_chains import SketchChainValidationError, update_sketch_chain
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    with client.application.storage_context():
        sketches = SqlAlchemySketchChainRepository()
        sketches.save(
            StoredSketchChain(
                chain_id="chain-fenced",
                engagement_id="eng-of02-dev",
                assigned_proxy="proxy01",
                middle_provider="linode",
                middle_region="us-sea",
                middle_size="g6-nanode-1",
                edge_provider="digitalocean",
                edge_region="sfo3",
                edge_size="s-1vcpu-1gb",
                edge_count=1,
                edge_intents=[{"id": "edge-01", "provider": "digitalocean", "region": "sfo3", "size": "s-1vcpu-1gb"}],
                status="pending",
                burned=False,
                burned_note="",
                deploy_job_id="",
                teardown_job_id="",
                terraform_working_directory="",
                nodes=[],
                created_at="2026-08-05T00:00:00+00:00",
                updated_at="2026-08-05T00:00:00+00:00",
            )
        )
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.acquire("eng-of02-dev", "dpl-fence", "apply")
        try:
            with pytest.raises(SketchChainValidationError) as exc_info:
                update_sketch_chain(
                    "eng-of02-dev",
                    "chain-fenced",
                    {"edgeRegion": "nyc3"},
                    repository=sketches,
                )
            assert "temporarily locked" in exc_info.value.errors[0]
        finally:
            plans.release("eng-of02-dev", "dpl-fence")


def test_successful_apply_deletes_single_use_binary_but_retains_run_data(client, tmp_path) -> None:
    run_directory = tmp_path / "core-run"
    run_directory.mkdir()
    plan_path = run_directory / "core.tfplan"
    plan_path.write_bytes(b"saved-plan")
    retained = run_directory / "main.tf"
    retained.write_text("resource {}", encoding="utf-8")
    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.save(
        DeploymentPlan(
            "dpl-applied",
            "eng-of02-dev",
            "rev-1",
            "applying",
            "terraform_apply",
            evidence={"runDirectory": str(run_directory), "planPath": str(plan_path)},
        )
    )
    repo.acquire(plan.engagement_id, plan.id, "apply")

    finish_core_deployment_plan_apply(plan.id, succeeded=True)

    assert repo.get(plan.id).status == "applied"
    assert not plan_path.exists()
    assert retained.exists()


@pytest.mark.parametrize(("schema", "operation"), [
    ("provider-keyed-v2", "provider_keyed_initial"),
    ("split-v1", "post_core"),
])
def test_successful_core_completion_keeps_plan_owned_sketch_lease(client, schema, operation) -> None:
    from app.storage.models import CoreMutationLeaseModel

    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.save(DeploymentPlan(
        "dpl-sketch-complete", "eng-of02-dev", "rev-1", "applying", "terraform_apply",
        evidence={
            "sketchStateSchema": schema,
            "pendingSketchChainIds": ["chain-a", "chain-b"],
        },
    ))
    repo.acquire(plan.engagement_id, plan.id, "apply")

    finish_core_deployment_plan_apply(plan.id, succeeded=True)

    assert repo.get(plan.id).status == "applied"
    lease = CoreMutationLeaseModel.query.get(plan.engagement_id)
    assert lease is not None
    assert (lease.owner_id, lease.operation) == (plan.id, operation)


@pytest.mark.parametrize("schema", ["provider-keyed-v2", "split-v1"])
def test_failed_core_completion_preserves_keyed_fence_only(client, schema) -> None:
    from app.storage.models import CoreMutationLeaseModel

    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.save(DeploymentPlan(
        "dpl-failed-core", "eng-of02-dev", "rev-1", "applying", "terraform_apply",
        evidence={"sketchStateSchema": schema, "pendingSketchChainIds": ["chain-a"]},
        apply_job_id="job-bound-core" if schema == "provider-keyed-v2" else "",
    ))
    repo.acquire(plan.engagement_id, plan.id, "apply")

    finish_core_deployment_plan_apply(plan.id, succeeded=False)

    assert repo.get(plan.id).status == "reconciliation_required"
    lease = CoreMutationLeaseModel.query.get(plan.engagement_id)
    if schema == "provider-keyed-v2":
        assert lease is not None and (lease.owner_id, lease.operation) == (plan.id, "apply")
    else:
        assert lease is None


def test_core_completion_does_not_commit_applied_status_without_owned_apply_lease(client) -> None:
    from app.storage.models import CoreMutationLeaseModel

    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.save(DeploymentPlan(
        "dpl-atomic-complete", "eng-of02-dev", "rev-1", "applying", "terraform_apply",
        evidence={"sketchStateSchema": "provider-keyed-v2", "pendingSketchChainIds": ["chain-a"]},
    ))
    repo.acquire(plan.engagement_id, plan.id, "apply")
    repo.retag(plan.engagement_id, plan.id, "provider_keyed_initial")

    with pytest.raises(DeploymentPlanConflictError):
        finish_core_deployment_plan_apply(plan.id, succeeded=True)

    assert repo.get(plan.id).status == "applying"
    lease = CoreMutationLeaseModel.query.get(plan.engagement_id)
    assert lease is not None
    assert (lease.owner_id, lease.operation) == (plan.id, "provider_keyed_initial")


def test_core_recovery_releases_only_interrupted_plan_owned_leases(client) -> None:
    from app.storage.database import db
    from app.storage.models import CoreMutationLeaseModel, EngagementModel

    repo = SqlAlchemyDeploymentPlanRepository()
    cases = (
        ("recover-preparing", "preparing", "prepare"),
        ("recover-applying", "applying", "apply"),
        ("retain-other-owner", "applying", "post_core"),
        ("retain-continuation-operation", "applying", "provider_keyed_initial"),
        ("retain-post-core", "applied", "post_core"),
        ("retain-keyed", "applied", "provider_keyed_initial"),
    )
    for engagement_id, status, operation in cases:
        db.session.add(EngagementModel(
            id=engagement_id, name=engagement_id, status="deployed", owner="test",
            template_id="standard-rti", input_parameters={},
        ))
    db.session.commit()
    for engagement_id, status, operation in cases:
        plan_id = f"dpl-{engagement_id}"
        repo.save(DeploymentPlan(plan_id, engagement_id, "rev-1", status, status))
        repo.acquire(engagement_id, "another-owner" if engagement_id == "retain-other-owner" else plan_id,
                     operation)

    recover_interrupted_core_deployment_plans()

    assert repo.get("dpl-recover-preparing").status == "failed"
    assert repo.get("dpl-recover-applying").status == "reconciliation_required"
    for engagement_id in ("recover-preparing", "recover-applying"):
        assert CoreMutationLeaseModel.query.get(engagement_id) is None
    unrelated = CoreMutationLeaseModel.query.get("retain-other-owner")
    assert unrelated is not None
    assert (unrelated.owner_id, unrelated.operation) == ("another-owner", "post_core")
    for engagement_id, _, operation in cases[3:]:
        lease = CoreMutationLeaseModel.query.get(engagement_id)
        assert lease is not None
        assert (lease.owner_id, lease.operation) == (f"dpl-{engagement_id}", operation)


def test_synchronous_apply_worker_cannot_regress_terminal_plan_to_applying(client, monkeypatch) -> None:
    from types import SimpleNamespace

    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.save(DeploymentPlan("dpl-sync", "eng-of02-dev", "rev-1", "ready", "ready"))
    monkeypatch.setattr("app.services.core_deployment_plans._verify_plan_evidence", lambda _plan: None)

    def starter(_body, **_kwargs):
        finish_core_deployment_plan_apply(plan.id, succeeded=True)
        return SimpleNamespace(id="job-sync")

    finished, job = begin_core_deployment_plan_apply(
        plan.engagement_id,
        plan.id,
        {"confirmMutation": "confirmed"},
        repository=repo,
        job_starter=starter,
    )

    assert job.id == "job-sync"
    assert finished.status == "applied"
    assert finished.apply_job_id == "job-sync"
    assert repo.get(plan.id).status == "applied"


def test_core_plan_apply_recovery_fence_stops_job_dispatch(monkeypatch) -> None:
    from app.services.engagement_teardown import EngagementTeardownValidationError

    calls = []
    monkeypatch.setattr(
        "app.services.engagement_teardown.assert_core_creation_allowed",
        lambda _engagement_id: (_ for _ in ()).throw(
            EngagementTeardownValidationError([
                "engagement cleanup recovery is required through comprehensive teardown job-parent before creating core infrastructure"
            ])
        ),
    )

    with pytest.raises(EngagementTeardownValidationError):
        begin_core_deployment_plan_apply(
            "eng-1", "dpl-1", {"confirmMutation": "confirmed"},
            job_starter=lambda *_args, **_kwargs: calls.append(True),
        )

    assert calls == []


def test_core_plan_prepare_recovery_fence_stops_terraform_runner(monkeypatch) -> None:
    from app.services.engagement_teardown import EngagementTeardownValidationError

    calls = []
    monkeypatch.setattr(
        "app.services.engagement_teardown.assert_core_creation_allowed",
        lambda _engagement_id: (_ for _ in ()).throw(
            EngagementTeardownValidationError([
                "engagement cleanup recovery is required through comprehensive teardown job-parent before creating core infrastructure"
            ])
        ),
    )

    with pytest.raises(EngagementTeardownValidationError):
        start_core_deployment_plan("eng-1", {}, command_runner=lambda *_args, **_kwargs: calls.append(True))

    assert calls == []


def test_reseeding_changed_intent_retires_only_stale_pending_chain(monkeypatch) -> None:
    from app.services.sketch_chains import seed_template_sketch_chains

    class Repository:
        def __init__(self):
            self.rows: dict[str, StoredSketchChain] = {}

        def list_for_engagement(self, engagement_id):
            return [row for row in self.rows.values() if row.engagement_id == engagement_id]

        def save(self, row):
            self.rows[row.chain_id] = row
            return row

    repo = Repository()
    monkeypatch.setattr("app.services.sketch_chains.get_engagement", lambda _id: object())
    monkeypatch.setattr("app.services.sketch_chains._validate_allowed_regions", lambda *_args, **_kwargs: None)
    intent_a = _sketch_intent("us-sea", "sfo3")
    [a] = seed_template_sketch_chains("eng-scope", {"sketchChains": [intent_a]}, repository=repo)
    a_row = repo.rows[a["chainId"]]
    historical = replace(a_row, chain_id="historical-deployed", status="deployed", deploy_job_id="job-old")
    repo.save(historical)

    [b] = seed_template_sketch_chains(
        "eng-scope", {"sketchChains": [_sketch_intent("us-east", "nyc3")]}, repository=repo
    )

    assert repo.rows[a["chainId"]].status == "aborted"
    assert repo.rows[b["chainId"]].status == "pending"
    assert repo.rows["historical-deployed"].status == "deployed"


def test_reviewed_post_core_scope_uses_exact_matching_persisted_chain_id(monkeypatch) -> None:
    from app.services.sketch_chains import _template_chain_intent

    monkeypatch.setattr("app.services.sketch_chains._validate_allowed_regions", lambda *_args, **_kwargs: None)
    body = _sketch_intent("us-sea", "sfo3")
    record = replace(_template_chain_intent("eng-scope", body), chain_id="proxy01-sea-07")

    class Repository:
        def list_for_engagement(self, _engagement_id):
            return [record]

    monkeypatch.setattr("app.services.core_deployment_plans.SqlAlchemySketchChainRepository", Repository)
    revision = {
        "inputParameters": {"sketchChains": [body]},
        "resolvedTopology": {
            "sketchChains": [{
                "id": "logical-chain-b",
                "assignedProxy": "proxy01",
                "middleProvider": "linode",
                "middleRegion": "us-sea",
                "edgeProvider": "digitalocean",
                "edgeRegion": "sfo3",
                "edgeCount": 1,
            }]
        },
    }

    scope, pending_ids, fingerprint, chain_fingerprints = _reviewed_post_core_scope("eng-scope", revision)

    assert pending_ids == ["proxy01-sea-07"]
    assert scope["chains"][0]["id"] == "proxy01-sea-07"
    assert scope["chains"][0]["intentId"] == "logical-chain-b"
    assert fingerprint
    assert chain_fingerprints["proxy01-sea-07"]


def _planned_core_instances(*, proxy_count: int, elk_enabled: bool) -> dict:
    addresses = ["oci_core_instance.homebase", "oci_core_instance.proxy01"]
    if proxy_count == 2:
        addresses.append("oci_core_instance.proxy02")
    if elk_enabled:
        addresses.append("oci_core_instance.elk")
    policy = OCI_CORE_INSTANCE_AGENT_POLICY
    return {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": address,
                        "type": "oci_core_instance",
                        "values": {
                            "agent_config": [
                                {
                                    "are_all_plugins_disabled": policy["are_all_plugins_disabled"],
                                    "is_monitoring_disabled": policy["is_monitoring_disabled"],
                                    "plugins_config": [dict(policy["plugins_config"])],
                                }
                            ],
                            "create_vnic_details": [
                                {"skip_source_dest_check": True if ".proxy" in address else False}
                            ],
                        },
                    }
                    for address in addresses
                ]
                + [
                    {
                        "address": "oci_core_default_dhcp_options.pilot",
                        "type": "oci_core_default_dhcp_options",
                        "values": {
                            "options": [
                                {
                                    "type": "DomainNameServer",
                                    "server_type": "CustomDnsServer",
                                    "custom_dns_servers": ["8.8.8.8", "1.1.1.1"],
                                }
                            ]
                        },
                    }
                ]
            }
        }
    }


def _sketch_intent(middle_region: str, edge_region: str) -> dict:
    return {
        "assignedProxy": "proxy01",
        "middleProvider": "linode",
        "middleRegion": middle_region,
        "middleSize": "g6-nanode-1",
        "edgeProvider": "digitalocean",
        "edgeRegion": edge_region,
        "edgeSize": "s-1vcpu-1gb",
        "edgeCount": 1,
    }


def _change(address: str, actions: list[str]) -> dict:
    return {
        "address": address,
        "type": "oci_core_instance",
        "provider_name": "registry.terraform.io/oracle/oci",
        "change": {"actions": actions, "before": {"password": "before"}, "after": {"password": "after"}},
    }
