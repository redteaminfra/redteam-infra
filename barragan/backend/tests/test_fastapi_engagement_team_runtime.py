# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.models import TeamMemberModel, TeamMemberSshKeyModel
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-team"
MEMBER_ID = "user-fastapi-engagement-team"
PUBLIC_KEY = "ssh-ed25519 ZW5nYWdlbWVudC10ZWFtLWZhc3RhcGk= engagement-team-fastapi"
FINGERPRINT = "SHA256:a7QXk2PwTKx0FHt+ETAbHG6xlc/u0GCKtslG1MWh1xs"


def test_fastapi_engagement_team_read_route_matches_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_fixture(reference_app, fastapi_app)

    for path in (
        f"/api/engagements/{ENGAGEMENT_ID}/team",
        "/api/engagements/eng-missing/team",
    ):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert _workspace_without_volatile_fields(fastapi_response.json()) == _workspace_without_volatile_fields(reference_response.get_json())


def test_fastapi_engagement_team_enroll_update_and_remove_match_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_fixture(reference_app, fastapi_app)

    payload = {"memberId": MEMBER_ID, "appPrivileges": ["view", "operate"], "infraGroupsOverride": ["redteam", "core"]}
    reference_enrolled = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team", json=payload)
    fastapi_enrolled = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team", json=payload)
    reference_membership = reference_enrolled.get_json()["membership"]
    fastapi_membership = fastapi_enrolled.json()["membership"]

    assert fastapi_enrolled.status_code == reference_enrolled.status_code == 201
    assert _membership_without_ids(fastapi_membership) == _membership_without_ids(reference_membership)

    update = {"appPrivileges": ["view", "administer"], "inheritInfraGroups": True}
    reference_updated = reference_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/team/{reference_membership['id']}",
        json=update,
    )
    fastapi_updated = fastapi_client.patch(
        f"/api/engagements/{ENGAGEMENT_ID}/team/{fastapi_membership['id']}",
        json=update,
    )

    assert fastapi_updated.status_code == reference_updated.status_code == 200
    assert _membership_without_ids(fastapi_updated.json()["membership"]) == _membership_without_ids(reference_updated.get_json()["membership"])

    reference_removed = reference_client.delete(f"/api/engagements/{ENGAGEMENT_ID}/team/{reference_membership['id']}")
    fastapi_removed = fastapi_client.delete(f"/api/engagements/{ENGAGEMENT_ID}/team/{fastapi_membership['id']}")

    assert fastapi_removed.status_code == reference_removed.status_code == 200
    assert _membership_without_ids(fastapi_removed.json()["membership"]) == _membership_without_ids(reference_removed.get_json()["membership"])


def test_fastapi_engagement_team_validation_and_missing_shapes_match_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_fixture(reference_app, fastapi_app)

    for path, method, body in (
        (f"/api/engagements/{ENGAGEMENT_ID}/team", "post", {"memberId": "user-missing"}),
        ("/api/engagements/eng-missing/team", "post", {"memberId": MEMBER_ID}),
        (f"/api/engagements/{ENGAGEMENT_ID}/team/membership-missing", "patch", {"appPrivileges": ["view"]}),
        (f"/api/engagements/{ENGAGEMENT_ID}/team/membership-missing", "delete", {}),
        ("/api/engagements/eng-missing/team/access-plan", "post", {}),
        ("/api/engagements/eng-missing/team/access-apply", "post", {"requestedBy": "pytest"}),
    ):
        if method == "delete":
            reference_response = reference_client.delete(path)
            fastapi_response = fastapi_client.delete(path)
        else:
            reference_response = getattr(reference_client, method)(path, json=body)
            fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_engagement_team_access_plan_matches_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_fixture(reference_app, fastapi_app)
    reference_membership = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team", json={"memberId": MEMBER_ID}).get_json()["membership"]
    fastapi_membership = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team", json={"memberId": MEMBER_ID}).json()["membership"]

    reference_response = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team/access-plan")
    fastapi_response = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team/access-plan")

    assert fastapi_response.status_code == reference_response.status_code == 201
    assert _plan_without_membership_ids(fastapi_response.json()["plan"]) == _plan_without_membership_ids(reference_response.get_json()["plan"])
    assert fastapi_response.json()["plan"]["coreUsers"][0]["membershipId"] == fastapi_membership["id"]
    assert reference_response.get_json()["plan"]["coreUsers"][0]["membershipId"] == reference_membership["id"]


def test_fastapi_engagement_team_access_apply_validation_matches_reference_contract(tmp_path):
    reference_app, fastapi_app, reference_client, fastapi_client = _clients(tmp_path)
    _seed_fixture(reference_app, fastapi_app)
    reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team", json={"memberId": MEMBER_ID})
    fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team", json={"memberId": MEMBER_ID})

    reference_response = reference_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team/access-apply", json={"requestedBy": "pytest"})
    fastapi_response = fastapi_client.post(f"/api/engagements/{ENGAGEMENT_ID}/team/access-apply", json={"requestedBy": "pytest"})

    assert fastapi_response.status_code == reference_response.status_code == 400
    assert fastapi_response.json() == reference_response.get_json()
    assert "connectionDetails" in fastapi_response.json()["errors"][0] or "ansible-playbook" in fastapi_response.json()["errors"][0]


def _clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app, fastapi_app.state.database, reference_app.test_client(), fastapi_app.test_client()


def _seed_fixture(reference_app, fastapi_reference_app) -> None:
    _seed_app(reference_app)
    _seed_app(fastapi_reference_app)


def _seed_app(app) -> None:
    with storage_context(app):
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=ENGAGEMENT_ID,
                name="FET01",
                status="draft",
                owner="operator",
                template_id="",
                active_revision=None,
                input_parameters={},
                description="FastAPI engagement Team fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.add(
            TeamMemberModel(
                id=MEMBER_ID,
                username="engteamfastapi",
                display_name="Engagement Team FastAPI",
                email="engteamfastapi@example.invalid",
                status="active",
                default_infra_groups=["redteam", "volunteer"],
                global_roles=["operator"],
            )
        )
        db.session.add(
            TeamMemberSshKeyModel(
                id="key-fastapi-engagement-team",
                member_id=MEMBER_ID,
                label="primary",
                public_key=PUBLIC_KEY,
                fingerprint=FINGERPRINT,
                status="active",
            )
        )
        db.session.commit()
        db.session.remove()


def _membership_without_ids(membership: dict) -> dict:
    cleaned = {
        key: value
        for key, value in membership.items()
        if key not in {"id", "createdAt", "updatedAt", "removedAt", "applyJobId"}
    }
    if "member" in cleaned:
        cleaned["member"] = _member_without_volatile_fields(cleaned["member"])
    return cleaned


def _workspace_without_volatile_fields(workspace: dict) -> dict:
    cleaned = dict(workspace)
    cleaned["availableMembers"] = [_member_without_volatile_fields(member) for member in workspace.get("availableMembers", [])]
    cleaned["memberships"] = [_membership_without_ids(membership) for membership in workspace.get("memberships", [])]
    return cleaned


def _member_without_volatile_fields(member: dict) -> dict:
    return {
        key: value
        for key, value in member.items()
        if key not in {"createdAt", "updatedAt", "deactivatedAt", "sshKeys"}
    }


def _plan_without_membership_ids(plan: dict) -> dict:
    cleaned = dict(plan)
    cleaned["coreUsers"] = [_user_without_membership_id(user) for user in plan["coreUsers"]]
    cleaned["disabledUsers"] = [_user_without_membership_id(user) for user in plan["disabledUsers"]]
    return cleaned


def _user_without_membership_id(user: dict) -> dict:
    return {key: value for key, value in user.items() if key != "membershipId"}
