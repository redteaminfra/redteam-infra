# Copyright (c) 2026, Oracle and/or its affiliates.
from app.services.authorization import ActionClass, action_for_request, authorize


def test_action_registry_is_default_deny_for_unknown_roles():
    decision = authorize(["made-up-role"], "GET", "/api/engagements")
    assert not decision.allowed
    assert decision.action == ActionClass.VIEW


def test_administrator_can_use_every_action_class():
    assert authorize(["administrator"], "GET", "/api/engagements").allowed
    assert authorize(["administrator"], "POST", "/api/engagements").allowed
    assert authorize(["administrator"], "DELETE", "/api/engagements/eng-1").allowed
    assert authorize(["administrator"], "PATCH", "/api/team/user-1").allowed


def test_narrow_roles_are_ready_for_later_rollout():
    assert authorize(["viewer"], "GET", "/api/engagements").allowed
    assert not authorize(["viewer"], "POST", "/api/engagements").allowed
    assert authorize(["operator"], "POST", "/api/engagements").allowed
    assert authorize(["operator"], "PATCH", "/api/engagements/eng-1").allowed
    assert not authorize(["operator"], "DELETE", "/api/engagements/eng-1").allowed
    assert authorize(["approver"], "DELETE", "/api/engagements/eng-1").allowed
    assert not authorize(["service_account"], "GET", "/api/engagements").allowed


def test_plaintext_request_gate_detail_requires_operate_even_on_get():
    path = "/api/engagements/eng-1/inbound-channels/channel-1/request-header-gate"
    assert action_for_request("GET", path) == ActionClass.OPERATE
    assert not authorize(["viewer"], "GET", path).allowed
    assert authorize(["operator"], "GET", path).allowed


def test_sensitive_roster_and_credential_mutations_are_administer_actions():
    assert action_for_request("PATCH", "/api/team/user-1") == ActionClass.ADMINISTER
    assert action_for_request("POST", "/api/credentials") == ActionClass.ADMINISTER
    assert action_for_request("GET", "/api/credentials") == ActionClass.ADMINISTER
    assert action_for_request("GET", "/api/engagements/eng-1/sketch-ssh-key/material") == ActionClass.ADMINISTER
    assert action_for_request("POST", "/api/engagements/eng-1/team") == ActionClass.ADMINISTER


def test_digitalocean_settings_and_live_provider_smoke_are_administrator_only():
    routes = (
        "/api/provider-catalog/sketch/digitalocean/preflight",
        "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs",
    )
    for route in routes:
        assert action_for_request("POST", route) == ActionClass.ADMINISTER
        assert authorize(["administrator"], "POST", route).allowed
        assert not authorize(["operator"], "POST", route).allowed


def test_stop_release_cancel_and_orphan_recovery_are_destructive():
    assert action_for_request("POST", "/api/domains/domain-1/release") == ActionClass.APPROVE_DESTRUCTIVE
    assert action_for_request("POST", "/api/engagements/eng-1/sketch-chains/chain-1/stop") == ActionClass.APPROVE_DESTRUCTIVE
    assert action_for_request("POST", "/api/engagements/eng-1/sketch-ssh-key/rotate") == ActionClass.APPROVE_DESTRUCTIVE
    assert action_for_request("POST", "/api/dashboard/orphan-candidates/actions") == ActionClass.APPROVE_DESTRUCTIVE


def test_discarding_unapplied_edge_plan_is_operator_action():
    path = "/api/engagements/eng-1/sketch-chains/chain-1/edges/append/plan/discard"
    assert action_for_request("POST", path) == ActionClass.OPERATE
    assert authorize(["operator"], "POST", path).allowed
    assert not authorize(["viewer"], "POST", path).allowed
