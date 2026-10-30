# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Lock

import pytest
from argon2 import Type, extract_parameters
from sqlalchemy import event, inspect, text

from app.core.config import Config, TestConfig
from app.services.authentication import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    AuthenticationError,
    AuthenticationService,
    PasswordPolicyError,
    validate_password,
)
from app.storage.database import db, ensure_database_schema
from app.storage.models import (
    AuthenticationAuditEventModel,
    AuthenticationCredentialModel,
    AuthenticationSessionModel,
    TeamMemberModel,
)


UTC = timezone.utc
START = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
PERMANENT_PASSWORD = "correct horse battery staple"
REPLACEMENT_PASSWORD = "orbiting-magnolia-72"


@pytest.fixture()
def auth_context():
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        yield
    state.engine.dispose()


@pytest.fixture()
def service(auth_context):
    return AuthenticationService()


def _member(
    username: str = "alice",
    *,
    member_id: str | None = None,
    status: str = "active",
) -> TeamMemberModel:
    row = TeamMemberModel(
        id=member_id or f"member-{username}",
        username=username,
        display_name=username.title(),
        email=f"{username}@example.invalid",
        status=status,
        default_infra_groups=[],
        global_roles=[],
    )
    db.session.add(row)
    db.session.commit()
    return row


def _account(
    service: AuthenticationService,
    *,
    username: str = "alice",
    password: str = PERMANENT_PASSWORD,
    initial_password: bool = False,
):
    member = _member(username)
    account = service.create_account(
        member.id,
        username if initial_password else password,
        initial_password=initial_password,
        now=START,
    )
    return member, account


def test_argon2id_parameters_and_password_policy(service):
    _member("alice")
    account = service.create_account(
        "member-alice",
        PERMANENT_PASSWORD,
        now=START,
    )
    stored = db.session.get(AuthenticationCredentialModel, account.credential_id)
    parameters = extract_parameters(stored.password_hash)

    assert parameters.type is Type.ID
    assert parameters.memory_cost == ARGON2_MEMORY_KIB == 19 * 1024
    assert parameters.time_cost == ARGON2_TIME_COST == 2
    assert parameters.parallelism == ARGON2_PARALLELISM == 1

    validate_password("🔐" * 10, username="alice")
    validate_password("0123456789", username="alice")
    with pytest.raises(PasswordPolicyError):
        validate_password("123456789", username="alice")
    with pytest.raises(PasswordPolicyError):
        validate_password("short", username="alice")
    with pytest.raises(PasswordPolicyError):
        validate_password("x" * 129, username="alice")
    with pytest.raises(PasswordPolicyError):
        validate_password("alice", username="alice")


def test_initial_username_password_is_forced_change_exception(service):
    member = _member("bootstrap-user")

    account = service.create_account(
        member.id,
        "bootstrap-user",
        initial_password=True,
        now=START,
    )
    issued = service.authenticate("bootstrap-user", "bootstrap-user", now=START)

    assert account.must_change_password is True
    assert issued.identity.must_change_password is True
    with pytest.raises(PasswordPolicyError):
        service.create_account(
            _member("ordinary").id,
            "ordinary",
            now=START,
        )


def test_authenticate_persists_only_hashes_and_resolves_identity(service):
    _member("alice")
    account = service.create_account(
        "member-alice",
        PERMANENT_PASSWORD,
        roles=("administrator", "service_account"),
        now=START,
    )

    issued = service.authenticate(" ALICE ", PERMANENT_PASSWORD, now=START)
    stored = db.session.get(AuthenticationSessionModel, issued.identity.session_id)

    assert len(issued.session_token) == 64
    assert len(issued.csrf_token) == 64
    assert stored.token_hash == hashlib.sha256(issued.session_token.encode()).hexdigest()
    assert stored.csrf_token_hash == hashlib.sha256(issued.csrf_token.encode()).hexdigest()
    assert issued.session_token not in (stored.token_hash, stored.csrf_token_hash)
    assert issued.csrf_token not in (stored.token_hash, stored.csrf_token_hash)
    assert issued.identity.credential_id == account.credential_id
    assert issued.identity.roles == ("administrator", "service_account")
    assert issued.identity.absolute_expires_at == START + timedelta(hours=12)
    assert issued.identity.idle_expires_at == START + timedelta(hours=2)

    resolved = service.resolve_session(
        issued.session_token,
        now=START + timedelta(hours=1),
    )
    assert resolved.username == "alice"
    assert resolved.idle_expires_at == START + timedelta(hours=3)


def test_csrf_validation_and_rotation_invalidates_previous_token(service):
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)

    identity = service.validate_csrf(
        issued.session_token,
        issued.csrf_token,
        now=START + timedelta(minutes=5),
    )
    replacement = service.rotate_csrf(
        issued.session_token,
        now=START + timedelta(minutes=6),
    )

    assert identity.username == "alice"
    assert replacement != issued.csrf_token
    with pytest.raises(AuthenticationError, match="invalid CSRF") as old_error:
        service.validate_csrf(issued.session_token, issued.csrf_token, now=START)
    assert old_error.value.code == "invalid_csrf"
    assert service.validate_csrf(issued.session_token, replacement, now=START).username == "alice"


def test_session_idle_expiry_and_logout(service):
    _account(service)
    idle_session = service.authenticate("alice", PERMANENT_PASSWORD, now=START)

    with pytest.raises(AuthenticationError) as expired:
        service.resolve_session(
            idle_session.session_token,
            now=START + timedelta(hours=2),
        )
    assert expired.value.code == "invalid_session"
    stored = db.session.get(AuthenticationSessionModel, idle_session.identity.session_id)
    assert stored.revocation_reason == "expired"

    active_session = service.authenticate(
        "alice",
        PERMANENT_PASSWORD,
        now=START + timedelta(hours=3),
    )
    assert service.logout(active_session.session_token, now=START + timedelta(hours=3, minutes=1))
    assert service.logout(active_session.session_token, now=START + timedelta(hours=3, minutes=2)) is False
    with pytest.raises(AuthenticationError):
        service.resolve_session(active_session.session_token, now=START + timedelta(hours=3, minutes=2))


def test_session_absolute_expiry_is_not_extended_by_activity(service):
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)

    for hours in range(1, 12):
        service.resolve_session(
            issued.session_token,
            now=START + timedelta(hours=hours),
        )

    with pytest.raises(AuthenticationError):
        service.resolve_session(
            issued.session_token,
            now=START + timedelta(hours=12),
        )


def test_tenth_consecutive_failure_locks_for_fifteen_minutes(service):
    _account(service)

    for offset in range(9):
        with pytest.raises(AuthenticationError) as denied:
            service.authenticate(
                "alice",
                "wrong password value",
                now=START + timedelta(seconds=offset),
            )
        assert denied.value.code == "invalid_credentials"

    credential = AuthenticationCredentialModel.query.one()
    assert credential.failed_login_count == 9
    assert credential.locked_until is None

    with pytest.raises(AuthenticationError) as locked:
        service.authenticate("alice", "wrong password value", now=START + timedelta(seconds=9))
    assert locked.value.code == "account_locked"
    assert credential.failed_login_count == 10
    assert _utc(credential.locked_until) == START + timedelta(seconds=9, minutes=15)

    with pytest.raises(AuthenticationError) as still_locked:
        service.authenticate("alice", PERMANENT_PASSWORD, now=START + timedelta(minutes=15))
    assert still_locked.value.code == "account_locked"

    issued = service.authenticate(
        "alice",
        PERMANENT_PASSWORD,
        now=START + timedelta(minutes=15, seconds=9),
    )
    assert issued.identity.username == "alice"
    assert credential.failed_login_count == 0
    assert credential.locked_until is None


def test_password_change_revokes_every_session_and_clears_forced_change(service):
    _account(service, username="alice", initial_password=True)
    first = service.authenticate("alice", "alice", now=START)
    second = service.authenticate("alice", "alice", now=START + timedelta(minutes=1))

    service.change_password(
        first.session_token,
        "alice",
        REPLACEMENT_PASSWORD,
        now=START + timedelta(minutes=2),
    )

    sessions = AuthenticationSessionModel.query.order_by(AuthenticationSessionModel.id).all()
    assert len(sessions) == 2
    assert {session.revocation_reason for session in sessions} == {"password_changed"}
    assert all(session.revoked_at is not None for session in sessions)
    with pytest.raises(AuthenticationError):
        service.resolve_session(second.session_token, now=START + timedelta(minutes=3))
    with pytest.raises(AuthenticationError):
        service.authenticate("alice", "alice", now=START + timedelta(minutes=3))

    replacement = service.authenticate(
        "alice",
        REPLACEMENT_PASSWORD,
        now=START + timedelta(minutes=3),
    )
    assert replacement.identity.must_change_password is False


def test_bootstrap_and_administrative_account_operations(service):
    _member("active-b")
    _member("active-a")
    _member("inactive", status="deactivated")

    created = service.bootstrap_active_team(actor="breakglass:tester", now=START)

    assert [account.username for account in created] == ["active-a", "active-b"]
    assert all(account.roles == ("administrator",) for account in created)
    assert all(account.must_change_password for account in created)
    assert [account.username for account in service.list_accounts()] == ["active-a", "active-b"]
    assert service.bootstrap_active_team(now=START) == []

    session = service.authenticate("active-a", "active-a", now=START)
    account = service.get_account("active-a")
    assert service.set_roles(account.credential_id, ("viewer", "administrator")).roles == (
        "administrator",
        "viewer",
    )
    assert TeamMemberModel.query.filter_by(username="active-a").one().global_roles == [
        "administrator",
        "viewer",
    ]
    assert service.disable_account("active-a", now=START).enabled is False
    with pytest.raises(AuthenticationError):
        service.resolve_session(session.session_token, now=START)
    assert service.enable_account("active-a", now=START).enabled is True

    credential = db.session.get(AuthenticationCredentialModel, account.credential_id)
    credential.failed_login_count = 10
    credential.locked_until = START + timedelta(minutes=15)
    db.session.commit()
    unlocked = service.unlock_account("active-a", now=START)
    assert unlocked.failed_login_count == 0
    assert unlocked.locked_until is None


def test_authentication_audit_never_contains_raw_secrets(service):
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)
    service.rotate_csrf(issued.session_token, now=START)

    serialized = "\n".join(
        repr(
            (
                event.action,
                event.outcome,
                event.actor,
                event.username,
                event.session_id,
                event.metadata_json,
            )
        )
        for event in AuthenticationAuditEventModel.query.all()
    )
    assert PERMANENT_PASSWORD not in serialized
    assert issued.session_token not in serialized
    assert issued.csrf_token not in serialized


def test_sqlite_schema_migration_is_idempotent_and_preserves_existing_data(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'existing.sqlite3'}")
    with db.bind(state):
        # Simulate an existing deployment DB with an unrelated table and row.
        db.session.execute(text("CREATE TABLE existing_runtime_data (value TEXT NOT NULL)"))
        db.session.execute(text("INSERT INTO existing_runtime_data (value) VALUES ('keep-me')"))
        db.session.commit()

        ensure_database_schema()
        ensure_database_schema()

        tables = set(inspect(db.engine).get_table_names())
        assert {
            "authentication_credentials",
            "authentication_sessions",
            "authentication_audit_events",
        }.issubset(tables)
        assert db.session.execute(text("SELECT value FROM existing_runtime_data")).scalar_one() == "keep-me"
    state.engine.dispose()


def test_authentication_is_disabled_by_default_with_environment_specific_cookie_names():
    assert Config.AUTH_REQUIRED is False
    assert TestConfig.AUTH_REQUIRED is False
    assert Config.AUTH_SESSION_ABSOLUTE_SECONDS == 12 * 60 * 60
    assert Config.AUTH_SESSION_IDLE_SECONDS == 2 * 60 * 60
    assert Config.AUTH_SESSION_TOUCH_INTERVAL_SECONDS == 5 * 60
    assert Config.AUTH_FAILURE_LIMIT == 10
    assert Config.AUTH_LOCKOUT_SECONDS == 15 * 60
    assert Config.AUTH_ARGON2_MEMORY_KIB == 19 * 1024
    assert Config.AUTH_ARGON2_TIME_COST == 2
    assert Config.AUTH_ARGON2_PARALLELISM == 1
    assert Config.AUTH_SESSION_COOKIE_NAME in {"barragan_session", "barragan_devtest_session"}


@pytest.mark.parametrize(
    ("touch_seconds", "idle_seconds", "absolute_seconds"),
    [
        (0, 120, 240),
        (120, 120, 240),
        (121, 120, 240),
        (60, 241, 240),
    ],
)
def test_session_timing_configuration_rejects_invalid_ordering(
    touch_seconds,
    idle_seconds,
    absolute_seconds,
):
    with pytest.raises(ValueError, match="0 < touch interval < idle lifetime"):
        AuthenticationService(
            touch_interval=timedelta(seconds=touch_seconds),
            idle_lifetime=timedelta(seconds=idle_seconds),
            absolute_lifetime=timedelta(seconds=absolute_seconds),
        )


def test_recent_and_touch_false_resolutions_do_not_update_or_commit(service, monkeypatch):
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)
    statements = []
    commits = 0

    @event.listens_for(db.engine, "before_cursor_execute")
    def capture_statement(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    original_commit = db.session.commit

    def capture_commit():
        nonlocal commits
        commits += 1
        return original_commit()

    monkeypatch.setattr(db.session, "commit", capture_commit)

    recent = service.resolve_session(
        issued.session_token,
        now=START + timedelta(minutes=4, seconds=59),
    )
    untouched = service.resolve_session(
        issued.session_token,
        now=START + timedelta(minutes=30),
        touch=False,
    )

    assert recent.idle_expires_at == issued.identity.idle_expires_at
    assert untouched.idle_expires_at == issued.identity.idle_expires_at
    assert not [statement for statement in statements if statement.lstrip().upper().startswith("UPDATE")]
    assert commits == 0


def test_stale_resolution_performs_one_conditional_update_and_commit(service, monkeypatch):
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)
    statements = []
    commits = 0

    @event.listens_for(db.engine, "before_cursor_execute")
    def capture_statement(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    original_commit = db.session.commit

    def capture_commit():
        nonlocal commits
        commits += 1
        return original_commit()

    monkeypatch.setattr(db.session, "commit", capture_commit)

    resolved = service.resolve_session(
        issued.session_token,
        now=START + timedelta(minutes=5),
    )

    updates = [statement for statement in statements if statement.lstrip().upper().startswith("UPDATE")]
    assert len(updates) == 1
    assert "token_hash" in updates[0]
    assert "last_seen_at" in updates[0]
    assert commits == 1
    assert resolved.idle_expires_at == START + timedelta(hours=2, minutes=5)


def test_invalid_csrf_does_not_extend_stale_session(service, monkeypatch):
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)
    commits = 0
    original_commit = db.session.commit

    def capture_commit():
        nonlocal commits
        commits += 1
        return original_commit()

    monkeypatch.setattr(db.session, "commit", capture_commit)

    with pytest.raises(AuthenticationError) as rejected:
        service.validate_csrf(
            issued.session_token,
            "not-the-csrf-token",
            now=START + timedelta(minutes=10),
        )

    db.session.expire_all()
    stored = db.session.get(AuthenticationSessionModel, issued.identity.session_id)
    assert rejected.value.code == "invalid_csrf"
    assert _utc(stored.last_seen_at) == START
    assert _utc(stored.idle_expires_at) == START + timedelta(hours=2)
    assert commits == 0


def test_concurrent_stale_touches_have_one_winner_across_database_sessions(tmp_path):
    database_uri = f"sqlite:///{tmp_path / 'concurrent-auth.sqlite3'}"
    setup_state = db.configure(database_uri)
    with db.bind(setup_state):
        db.create_all()
        setup_service = AuthenticationService()
        _account(setup_service)
        issued = setup_service.authenticate("alice", PERMANENT_PASSWORD, now=START)
        session_token = issued.session_token
        session_id = issued.identity.session_id
    setup_state.engine.dispose()

    worker_count = 6
    barrier = Barrier(worker_count)
    counter_lock = Lock()
    successful_updates = 0
    commits = 0

    def resolve_concurrently(_worker_number):
        nonlocal successful_updates, commits
        state = db.configure(database_uri)

        @event.listens_for(state.engine, "after_cursor_execute")
        def count_update(_connection, cursor, statement, _parameters, _context, _many):
            nonlocal successful_updates
            if statement.lstrip().upper().startswith("UPDATE AUTHENTICATION_SESSIONS"):
                with counter_lock:
                    successful_updates += int(cursor.rowcount == 1)

        @event.listens_for(state.engine, "commit")
        def count_commit(_connection):
            nonlocal commits
            with counter_lock:
                commits += 1

        try:
            with db.bind(state):
                barrier.wait()
                return AuthenticationService().resolve_session(
                    session_token,
                    now=START + timedelta(minutes=5),
                )
        finally:
            state.engine.dispose()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        identities = list(executor.map(resolve_concurrently, range(worker_count)))

    assert {identity.session_id for identity in identities} == {session_id}
    assert {
        identity.idle_expires_at for identity in identities
    } == {START + timedelta(hours=2, minutes=5)}
    assert successful_updates == 1
    assert commits == 1


@pytest.mark.parametrize("intervening_action", ["logout", "revoke", "disable"])
def test_stale_touch_loses_to_intervening_session_invalidation(
    tmp_path,
    intervening_action,
):
    database_uri = f"sqlite:///{tmp_path / f'{intervening_action}.sqlite3'}"
    setup_state = db.configure(database_uri)
    with db.bind(setup_state):
        db.create_all()
        setup_service = AuthenticationService()
        _account(setup_service)
        issued = setup_service.authenticate("alice", PERMANENT_PASSWORD, now=START)
        session_token = issued.session_token
        session_id = issued.identity.session_id
        original_last_seen = issued.identity.idle_expires_at - timedelta(hours=2)
        original_idle_expiry = issued.identity.idle_expires_at
    setup_state.engine.dispose()

    update_ready = Barrier(2)
    invalidation_complete = Barrier(2)
    resolver_state = db.configure(database_uri)
    winning_activity_updates = 0

    @event.listens_for(resolver_state.engine, "before_cursor_execute")
    def pause_before_activity_update(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _many,
    ):
        if (
            statement.lstrip().upper().startswith("UPDATE AUTHENTICATION_SESSIONS")
            and "last_seen_at" in statement
        ):
            update_ready.wait()
            invalidation_complete.wait()

    @event.listens_for(resolver_state.engine, "after_cursor_execute")
    def count_activity_winner(
        _connection,
        cursor,
        statement,
        _parameters,
        _context,
        _many,
    ):
        nonlocal winning_activity_updates
        if (
            statement.lstrip().upper().startswith("UPDATE AUTHENTICATION_SESSIONS")
            and "last_seen_at" in statement
        ):
            winning_activity_updates += int(cursor.rowcount == 1)

    def resolve_stale_session():
        try:
            with db.bind(resolver_state):
                AuthenticationService().resolve_session(
                    session_token,
                    now=START + timedelta(minutes=5),
                )
        except AuthenticationError as exc:
            return exc.code
        return "resolved"

    with ThreadPoolExecutor(max_workers=1) as executor:
        resolution = executor.submit(resolve_stale_session)
        update_ready.wait()
        invalidator_state = db.configure(database_uri)
        try:
            with db.bind(invalidator_state):
                invalidator = AuthenticationService()
                if intervening_action == "logout":
                    assert invalidator.logout(
                        session_token,
                        now=START + timedelta(minutes=4, seconds=59),
                    )
                elif intervening_action == "revoke":
                    assert invalidator.revoke_sessions(
                        "alice",
                        now=START + timedelta(minutes=4, seconds=59),
                    ) == 1
                else:
                    assert invalidator.disable_account(
                        "alice",
                        now=START + timedelta(minutes=4, seconds=59),
                    ).enabled is False
        finally:
            invalidator_state.engine.dispose()
            invalidation_complete.wait()
        assert resolution.result() == "invalid_session"

    resolver_state.engine.dispose()
    verification_state = db.configure(database_uri)
    with db.bind(verification_state):
        stored = db.session.get(AuthenticationSessionModel, session_id)
        assert _utc(stored.last_seen_at) == original_last_seen
        assert _utc(stored.idle_expires_at) == original_idle_expiry
    verification_state.engine.dispose()
    assert winning_activity_updates == 0


def test_touch_caps_idle_expiry_and_rejects_exact_absolute_boundary(monkeypatch, auth_context):
    service = AuthenticationService(
        absolute_lifetime=timedelta(minutes=10),
        idle_lifetime=timedelta(minutes=8),
        touch_interval=timedelta(minutes=1),
    )
    _account(service)
    issued = service.authenticate("alice", PERMANENT_PASSWORD, now=START)

    near_boundary = service.resolve_session(
        issued.session_token,
        now=START + timedelta(minutes=3),
    )
    assert near_boundary.idle_expires_at == START + timedelta(minutes=10)

    activity_statements = 0

    @event.listens_for(db.engine, "before_cursor_execute")
    def count_activity_statement(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _many,
    ):
        nonlocal activity_statements
        if (
            statement.lstrip().upper().startswith("UPDATE AUTHENTICATION_SESSIONS")
            and "last_seen_at" in statement
        ):
            activity_statements += 1

    with pytest.raises(AuthenticationError) as expired:
        service.resolve_session(
            issued.session_token,
            now=START + timedelta(minutes=10),
        )

    db.session.expire_all()
    stored = db.session.get(AuthenticationSessionModel, issued.identity.session_id)
    assert expired.value.code == "invalid_session"
    assert _utc(stored.last_seen_at) == START + timedelta(minutes=3)
    assert _utc(stored.idle_expires_at) == START + timedelta(minutes=10)
    assert stored.revocation_reason == "expired"
    assert activity_statements == 0


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
