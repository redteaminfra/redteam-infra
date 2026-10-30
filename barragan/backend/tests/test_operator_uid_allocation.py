# Copyright (c) 2026, Oracle and/or its affiliates.
"""Durable UID assignments; no host or provider operations are performed."""
import json
import multiprocessing

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.services.team_access import (
    TeamAccessValidationError, apply_team_import, create_team_member,
    preview_team_import, update_team_member,
)
from app.storage.database import db, _ensure_operator_uid_allocation
from app.storage.models import AccessAuditEventModel, OperatorUidAllocationModel, TeamMemberModel


def _import(*records):
    return {"format": "json", "content": json.dumps({"users": list(records)})}


@pytest.fixture
def uid_store(tmp_path):
    uri = f"sqlite:///{tmp_path / 'operators.sqlite'}"
    state = db.configure(uri)
    with db.bind(state):
        db.create_all()
        _ensure_operator_uid_allocation()
        yield uri
    state.engine.dispose()


def _high_water():
    return db.session.get(OperatorUidAllocationModel, 1).high_water_uid


def test_blank_creates_allocate_and_blank_edits_preserve(uid_store):
    for index, body in enumerate(({}, {"desiredUid": None}, {"desiredUid": ""}, {"desiredUid": "  "})):
        member = create_team_member({"username": f"operator{index}", **body})["member"]
        assert member["desiredUid"] == 6000 + index
        for blank in (None, "", "  "):
            assert update_team_member(member["id"], {"desiredUid": blank})["member"]["desiredUid"] == 6000 + index
    audit = AccessAuditEventModel.query.filter_by(action="team_member_created").first()
    assert audit.metadata_json["desiredUid"] == 6000
    assert _high_water() == 6003


@pytest.mark.parametrize("invalid", [True, False, 6000.0, 6000.5, "6000.5", [], 5999, 65000])
def test_strict_invalid_uids_do_not_consume_reservations(uid_store, invalid):
    with pytest.raises(TeamAccessValidationError):
        create_team_member({"username": "invalid", "desiredUid": invalid})
    assert TeamMemberModel.query.count() == AccessAuditEventModel.query.count() == 0
    assert _high_water() == 5999


def test_validation_after_reservation_rolls_back_everything(uid_store):
    with pytest.raises(TeamAccessValidationError):
        create_team_member({"username": "invalid", "desiredUid": 6200, "defaultInfraGroups": ["bad"]})
    assert _high_water() == 5999
    assert TeamMemberModel.query.count() == AccessAuditEventModel.query.count() == 0


def test_high_water_survives_downward_edit_deactivation_and_restart(uid_store):
    member = create_team_member({"username": "reserved", "desiredUid": "6200"})["member"]
    update_team_member(member["id"], {"desiredUid": 6100, "status": "deactivated"})
    assert AccessAuditEventModel.query.filter_by(action="team_member_updated").one().metadata_json["desiredUid"] == 6100
    restarted = db.configure(uid_store)
    with db.bind(restarted):
        _ensure_operator_uid_allocation()
        assert create_team_member({"username": "after_restart"})["member"]["desiredUid"] == 6201
    restarted.engine.dispose()


def test_legacy_null_edit_and_import_preserve_null(uid_store):
    db.session.add(TeamMemberModel(id="legacy", username="legacy", desired_uid=None))
    db.session.commit()
    assert update_team_member("legacy", {"desiredUid": " "})["member"]["desiredUid"] is None
    apply_team_import(_import({"username": "legacy", "name": "Updated", "uid": None}))
    assert db.session.get(TeamMemberModel, "legacy").desired_uid is None
    assert _high_water() == 5999


@pytest.mark.parametrize("reverse", [False, True])
def test_preview_is_read_only_and_import_reserves_actionable_explicit_max_first(uid_store, reverse):
    records = [{"username": "automatic"}, {"username": "explicit", "uid": 6100}, {"username": "Bad!", "uid": 64999}]
    body = _import(*(reversed(records) if reverse else records))
    preview_team_import(body)
    assert _high_water() == 5999
    result = apply_team_import(body)
    assert len(result["applied"]["skipped"]) == 1
    assert {m.username: m.desired_uid for m in TeamMemberModel.query.all()} == {"automatic": 6101, "explicit": 6100}
    apply_team_import(_import({"username": "explicit", "uid": 6050}))
    assert TeamMemberModel.query.filter_by(username="explicit").one().desired_uid == 6050
    assert create_team_member({"username": "later"})["member"]["desiredUid"] == 6102


def test_import_exhaustion_rolls_back_members_audits_and_counter(uid_store):
    with pytest.raises(TeamAccessValidationError, match="validation") as error:
        apply_team_import(_import({"username": "explicit", "uid": 64999}, {"username": "automatic"}))
    assert "exhausted" in error.value.errors[0]
    assert TeamMemberModel.query.count() == AccessAuditEventModel.query.count() == 0
    assert _high_water() == 5999
    create_team_member({"username": "last", "desiredUid": 64999})
    with pytest.raises(TeamAccessValidationError):
        create_team_member({"username": "overflow"})
    assert TeamMemberModel.query.count() == AccessAuditEventModel.query.count() == 1


def test_migration_adds_unique_index_and_refuses_duplicates_without_rewriting(uid_store):
    create_team_member({"username": "one", "desiredUid": 6200})
    db.session.remove()
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ux_team_members_desired_uid")
    _ensure_operator_uid_allocation()
    with pytest.raises(IntegrityError):
        with db.engine.begin() as connection:
            connection.exec_driver_sql("INSERT INTO team_members (id,username,display_name,email,status,desired_uid,default_infra_groups,global_roles,created_at,updated_at) SELECT 'two','two',display_name,email,status,desired_uid,default_infra_groups,global_roles,created_at,updated_at FROM team_members LIMIT 1")
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ux_team_members_desired_uid")
        connection.exec_driver_sql("INSERT INTO team_members (id,username,display_name,email,status,desired_uid,default_infra_groups,global_roles,created_at,updated_at) SELECT 'two','two',display_name,email,status,desired_uid,default_infra_groups,global_roles,created_at,updated_at FROM team_members LIMIT 1")
    with pytest.raises(RuntimeError, match="duplicate operator desired UID 6200"):
        _ensure_operator_uid_allocation()
    with db.engine.connect() as connection:
        assert connection.execute(text("SELECT desired_uid FROM team_members ORDER BY username")).scalars().all() == [6200, 6200]


def test_pending_caller_changes_are_not_rolled_back(uid_store):
    pending = TeamMemberModel(id="pending", username="pending")
    db.session.add(pending)
    with pytest.raises(TeamAccessValidationError):
        create_team_member({"username": "other"})
    assert pending in db.session.new
    db.session.rollback()
    db.session.connection().exec_driver_sql("BEGIN")
    with pytest.raises(TeamAccessValidationError):
        create_team_member({"username": "other"})
    assert db.session.connection().connection.driver_connection.in_transaction
    db.session.rollback()


def _process_write(uri, barrier, results, action, username):
    state = db.configure(uri)
    try:
        with db.bind(state):
            # Real auth middleware also reads before entering the write path.
            TeamMemberModel.query.all()
            barrier.wait(timeout=20)
            try:
                if action == "import":
                    result = apply_team_import(_import({"username": username}, {"username": "import_explicit", "uid": 6100}))
                    result = TeamMemberModel.query.filter_by(username=username).one().desired_uid
                elif action == "edit":
                    member = TeamMemberModel.query.filter_by(username="existing").one()
                    result = update_team_member(member.id, {"desiredUid": 6200})["member"]["desiredUid"]
                else:
                    result = create_team_member({"username": username, **({"desiredUid": 6000} if action == "explicit" else {})})["member"]["desiredUid"]
                results.put(("ok", result))
            except TeamAccessValidationError as error:
                results.put(("validation", error.errors))
    finally:
        state.engine.dispose()


def _race(uri, actions):
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(len(actions)), context.Queue()
    processes = [context.Process(target=_process_write, args=(uri, barrier, results, action, f"worker{index}")) for index, action in enumerate(actions)]
    for process in processes:
        process.start()
    try:
        returned = [results.get(timeout=35) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        return returned
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()


def test_independent_process_automatic_creates_are_consecutive(uid_store):
    results = _race(uid_store, ["auto"] * 6)
    assert sorted(value for status, value in results if status == "ok") == list(range(6000, 6006))
    db.session.expire_all()
    assert _high_water() == 6005
    assert AccessAuditEventModel.query.count() == 6


@pytest.mark.parametrize("other", ["explicit", "import", "edit"])
def test_independent_process_auto_races_other_uid_paths(uid_store, other):
    if other == "edit":
        create_team_member({"username": "existing"})
    results = _race(uid_store, ["auto", other])
    assert all(status in {"ok", "validation"} for status, _ in results)
    if other != "explicit":
        assert all(status == "ok" for status, _ in results)
    db.session.expire_all()
    assigned = [member.desired_uid for member in TeamMemberModel.query.all()]
    assert len(assigned) == len(set(assigned))
    assert _high_water() == max(assigned)
    if other == "explicit":
        assert sorted(assigned) in ([6000], [6000, 6001])
    elif other == "import":
        assert sorted(assigned) in ([6000, 6100, 6101], [6100, 6101, 6102])
    else:
        assert sorted(assigned) in ([6001, 6200], [6200, 6201])
    assert len(assigned) == (3 if other == "import" else 2 if other == "edit" else sum(status == "ok" for status, _ in results))


def test_authenticated_create_uses_allocator_after_auth_reads():
    from test_fastapi_auth_runtime import _app_with_account, AuthTestConfig
    from app.services.authentication import AuthenticationService
    app = _app_with_account()
    with app.storage_context():
        AuthenticationService.from_config(AuthTestConfig).reset_password("example_operator_three", "long permanent password", force_password_change=False)
    client = app.test_client()
    login = client.post("/api/auth/login", json={"username": "example_operator_three", "password": "long permanent password"}).json()
    response = client.post("/api/team", headers={"X-Barragan-CSRF": login["csrfToken"]}, json={"username": "new_operator"})
    assert response.status_code == 201, response.json()
    assert response.json()["member"]["desiredUid"] == 6000


def test_explicit_edit_conflict_rolls_back_profile_counter_and_audit(uid_store):
    first = create_team_member({"username": "first"})["member"]
    create_team_member({"username": "second"})
    with pytest.raises(TeamAccessValidationError):
        update_team_member(first["id"], {"displayName": "Should roll back", "desiredUid": 6001})
    assert db.session.get(TeamMemberModel, first["id"]).display_name == "first"
    assert _high_water() == 6001
    assert AccessAuditEventModel.query.count() == 2


def test_oversized_numeric_text_is_validation_without_side_effects(uid_store):
    huge_uid = "6" * 5000
    existing = create_team_member({"username": "existing"})["member"]
    for operation in (
        lambda: create_team_member({"username": "oversized", "desiredUid": huge_uid}),
        lambda: update_team_member(existing["id"], {"displayName": "Should roll back", "desiredUid": huge_uid}),
    ):
        with pytest.raises(TeamAccessValidationError):
            operation()
    imported = apply_team_import(_import({"username": "oversized", "uid": huge_uid}))
    assert imported["applied"]["created"] == []
    assert len(imported["applied"]["skipped"]) == 1
    assert "desired UID" in imported["applied"]["skipped"][0]["errors"][0]
    assert TeamMemberModel.query.count() == 1
    assert db.session.get(TeamMemberModel, existing["id"]).display_name == "existing"
    assert AccessAuditEventModel.query.count() == 1
    assert _high_water() == 6000


def test_oversized_uid_api_returns_validation_instead_of_server_error(client):
    huge_uid = "6" * 5000
    member = client.post("/api/team", json={"username": "existing"}).json()["member"]
    assert client.post("/api/team", json={"username": "oversized", "desiredUid": huge_uid}).status_code == 400
    assert client.patch(f"/api/team/{member['id']}", json={"desiredUid": huge_uid}).status_code == 400
    response = client.post("/api/team/import/apply", json=_import({"username": "oversized", "uid": huge_uid}))
    assert response.status_code == 202
    assert len(response.json()["applied"]["skipped"]) == 1
    with client.application.storage_context():
        assert TeamMemberModel.query.filter_by(username="oversized").first() is None
        assert db.session.get(TeamMemberModel, member["id"]).desired_uid == 6000
        assert _high_water() == 6000
        assert AccessAuditEventModel.query.count() == 1
