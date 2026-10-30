# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Sequence
from uuid import uuid4

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import update

from app.storage.database import db
from app.storage.models import (
    AuthenticationAuditEventModel,
    AuthenticationCredentialModel,
    AuthenticationSessionModel,
    TeamMemberModel,
)


ARGON2_MEMORY_KIB = 19 * 1024
ARGON2_TIME_COST = 2
ARGON2_PARALLELISM = 1
SESSION_ABSOLUTE_LIFETIME = timedelta(hours=12)
SESSION_IDLE_LIFETIME = timedelta(hours=2)
SESSION_TOUCH_INTERVAL = timedelta(minutes=5)
LOGIN_FAILURE_LIMIT = 10
LOGIN_LOCKOUT_DURATION = timedelta(minutes=15)
MINIMUM_PASSWORD_LENGTH = 10
MAXIMUM_PASSWORD_LENGTH = 128

_ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REJECTED_PASSWORDS = {
    "barragan",
    "barragan123",
    "barragan-password",
    "barragan_password",
    "changeme",
    "password",
}


class AuthenticationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PasswordPolicyError(ValueError):
    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class AccountSummary:
    credential_id: str
    team_member_id: str
    username: str
    display_name: str
    team_member_status: str
    enabled: bool
    roles: tuple[str, ...]
    must_change_password: bool
    failed_login_count: int
    locked_until: datetime | None
    password_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class AuthenticatedIdentity:
    credential_id: str
    team_member_id: str
    username: str
    display_name: str
    roles: tuple[str, ...]
    must_change_password: bool
    session_id: str
    absolute_expires_at: datetime
    idle_expires_at: datetime

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True)
class IssuedSession:
    identity: AuthenticatedIdentity
    session_token: str
    csrf_token: str


class AuthenticationService:
    """Framework-neutral local authentication and account administration.

    The caller is responsible for setting cookies and deciding whether route
    authentication is enforced. Raw session and CSRF tokens only exist in
    ``IssuedSession`` return values (or the return from ``rotate_csrf``).
    """

    def __init__(
        self,
        *,
        password_hasher: PasswordHasher | None = None,
        absolute_lifetime: timedelta = SESSION_ABSOLUTE_LIFETIME,
        idle_lifetime: timedelta = SESSION_IDLE_LIFETIME,
        touch_interval: timedelta = SESSION_TOUCH_INTERVAL,
        failure_limit: int = LOGIN_FAILURE_LIMIT,
        lockout_duration: timedelta = LOGIN_LOCKOUT_DURATION,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not timedelta(0) < touch_interval < idle_lifetime <= absolute_lifetime:
            raise ValueError(
                "session timing must satisfy 0 < touch interval < idle lifetime "
                "<= absolute lifetime"
            )
        if failure_limit < 1 or lockout_duration <= timedelta(0):
            raise ValueError("lockout settings must be positive")
        self.password_hasher = password_hasher or PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self.absolute_lifetime = absolute_lifetime
        self.idle_lifetime = idle_lifetime
        self.touch_interval = touch_interval
        self.failure_limit = failure_limit
        self.lockout_duration = lockout_duration
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        # Verifying a real Argon2 hash for unknown usernames makes the common
        # login path less useful as a username-enumeration timing oracle.
        self._unknown_account_hash = self.password_hasher.hash(
            secrets.token_urlsafe(32)
        )

    @classmethod
    def from_config(cls, config: object) -> "AuthenticationService":
        return cls(
            password_hasher=PasswordHasher(
                time_cost=int(getattr(config, "AUTH_ARGON2_TIME_COST", ARGON2_TIME_COST)),
                memory_cost=int(getattr(config, "AUTH_ARGON2_MEMORY_KIB", ARGON2_MEMORY_KIB)),
                parallelism=int(getattr(config, "AUTH_ARGON2_PARALLELISM", ARGON2_PARALLELISM)),
                hash_len=32,
                salt_len=16,
                type=Type.ID,
            ),
            absolute_lifetime=timedelta(
                seconds=int(
                    getattr(
                        config,
                        "AUTH_SESSION_ABSOLUTE_SECONDS",
                        int(SESSION_ABSOLUTE_LIFETIME.total_seconds()),
                    )
                )
            ),
            idle_lifetime=timedelta(
                seconds=int(
                    getattr(
                        config,
                        "AUTH_SESSION_IDLE_SECONDS",
                        int(SESSION_IDLE_LIFETIME.total_seconds()),
                    )
                )
            ),
            touch_interval=timedelta(
                seconds=int(
                    getattr(
                        config,
                        "AUTH_SESSION_TOUCH_INTERVAL_SECONDS",
                        int(SESSION_TOUCH_INTERVAL.total_seconds()),
                    )
                )
            ),
            failure_limit=int(getattr(config, "AUTH_FAILURE_LIMIT", LOGIN_FAILURE_LIMIT)),
            lockout_duration=timedelta(
                seconds=int(
                    getattr(
                        config,
                        "AUTH_LOCKOUT_SECONDS",
                        int(LOGIN_LOCKOUT_DURATION.total_seconds()),
                    )
                )
            ),
        )

    def authenticate(
        self,
        username: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> IssuedSession:
        current_time = self._now(now)
        normalized_username = _normalize_username(username)
        member = TeamMemberModel.query.filter_by(username=normalized_username).first()
        credential = None
        if member is not None:
            credential = AuthenticationCredentialModel.query.filter_by(
                team_member_id=member.id
            ).first()

        if credential is None or member is None:
            self._verify_unknown(password)
            self._audit(
                action="login",
                outcome="denied",
                actor="anonymous",
                username=normalized_username,
                now=current_time,
            )
            db.session.commit()
            raise AuthenticationError("invalid_credentials", "invalid username or password")

        locked_until = _as_utc(credential.locked_until)
        if locked_until is not None and current_time < locked_until:
            self._audit(
                action="login",
                outcome="locked",
                actor="anonymous",
                credential=credential,
                username=member.username,
                now=current_time,
            )
            db.session.commit()
            raise AuthenticationError("account_locked", "account is temporarily locked")
        if locked_until is not None:
            credential.failed_login_count = 0
            credential.locked_until = None

        if not credential.enabled or member.status != "active":
            self._audit(
                action="login",
                outcome="denied",
                actor="anonymous",
                credential=credential,
                username=member.username,
                now=current_time,
            )
            db.session.commit()
            raise AuthenticationError("invalid_credentials", "invalid username or password")

        if not self._verify_password(credential.password_hash, password):
            credential.failed_login_count = int(credential.failed_login_count or 0) + 1
            outcome = "denied"
            error_code = "invalid_credentials"
            error_message = "invalid username or password"
            if credential.failed_login_count >= self.failure_limit:
                credential.locked_until = current_time + self.lockout_duration
                outcome = "locked"
                error_code = "account_locked"
                error_message = "account is temporarily locked"
            self._audit(
                action="login",
                outcome=outcome,
                actor="anonymous",
                credential=credential,
                username=member.username,
                now=current_time,
            )
            db.session.commit()
            raise AuthenticationError(error_code, error_message)

        credential.failed_login_count = 0
        credential.locked_until = None
        if self.password_hasher.check_needs_rehash(credential.password_hash):
            credential.password_hash = self.password_hasher.hash(password)

        session_token = _new_token()
        csrf_token = _new_token()
        session = AuthenticationSessionModel(
            id=f"session-{uuid4().hex}",
            credential_id=credential.id,
            token_hash=_token_hash(session_token),
            csrf_token_hash=_token_hash(csrf_token),
            created_at=current_time,
            last_seen_at=current_time,
            absolute_expires_at=current_time + self.absolute_lifetime,
            idle_expires_at=current_time + self.idle_lifetime,
            revocation_reason="",
        )
        db.session.add(session)
        self._audit(
            action="login",
            outcome="succeeded",
            actor=f"user:{credential.id}",
            credential=credential,
            username=member.username,
            session=session,
            now=current_time,
        )
        db.session.commit()
        return IssuedSession(
            identity=self._identity(credential, member, session),
            session_token=session_token,
            csrf_token=csrf_token,
        )

    def resolve_session(
        self,
        session_token: str,
        *,
        now: datetime | None = None,
        touch: bool = True,
    ) -> AuthenticatedIdentity:
        current_time = self._now(now)
        session, credential, member = self._active_session(session_token, current_time)
        if touch and current_time - _as_utc(session.last_seen_at) >= self.touch_interval:
            session, credential, member = self._touch_session(
                session_token,
                session,
                current_time,
            )
        return self._identity(credential, member, session)

    def validate_csrf(
        self,
        session_token: str,
        csrf_token: str,
        *,
        now: datetime | None = None,
    ) -> AuthenticatedIdentity:
        current_time = self._now(now)
        session, credential, member = self._active_session(session_token, current_time)
        if not csrf_token or not secrets.compare_digest(
            session.csrf_token_hash,
            _token_hash(csrf_token),
        ):
            raise AuthenticationError("invalid_csrf", "invalid CSRF token")
        if current_time - _as_utc(session.last_seen_at) >= self.touch_interval:
            session, credential, member = self._touch_session(
                session_token,
                session,
                current_time,
            )
        return self._identity(credential, member, session)

    def rotate_csrf(
        self,
        session_token: str,
        *,
        now: datetime | None = None,
    ) -> str:
        current_time = self._now(now)
        session, credential, member = self._active_session(session_token, current_time)
        csrf_token = _new_token()
        session.csrf_token_hash = _token_hash(csrf_token)
        session.last_seen_at = current_time
        session.idle_expires_at = min(
            current_time + self.idle_lifetime,
            _as_utc(session.absolute_expires_at),
        )
        self._audit(
            action="csrf_rotate",
            outcome="succeeded",
            actor=f"user:{credential.id}",
            credential=credential,
            username=member.username,
            session=session,
            now=current_time,
        )
        db.session.commit()
        return csrf_token

    def change_password(
        self,
        session_token: str,
        current_password: str,
        new_password: str,
        *,
        now: datetime | None = None,
    ) -> None:
        current_time = self._now(now)
        session, credential, member = self._active_session(session_token, current_time)
        if not self._verify_password(credential.password_hash, current_password):
            self._audit(
                action="password_change",
                outcome="denied",
                actor=f"user:{credential.id}",
                credential=credential,
                username=member.username,
                session=session,
                now=current_time,
            )
            db.session.commit()
            raise AuthenticationError("invalid_password", "current password is incorrect")
        validate_password(new_password, username=member.username)
        if self._verify_password(credential.password_hash, new_password):
            raise PasswordPolicyError(("new password must differ from the current password",))
        credential.password_hash = self.password_hasher.hash(new_password)
        credential.must_change_password = False
        credential.password_changed_at = current_time
        credential.failed_login_count = 0
        credential.locked_until = None
        self._revoke_credential_sessions(
            credential.id,
            now=current_time,
            reason="password_changed",
        )
        self._audit(
            action="password_change",
            outcome="succeeded",
            actor=f"user:{credential.id}",
            credential=credential,
            username=member.username,
            session=session,
            now=current_time,
        )
        db.session.commit()

    def logout(
        self,
        session_token: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        current_time = self._now(now)
        session = AuthenticationSessionModel.query.filter_by(
            token_hash=_token_hash(session_token)
        ).first()
        if session is None or session.revoked_at is not None:
            return False
        credential, member = self._credential_member(session.credential_id)
        session.revoked_at = current_time
        session.revocation_reason = "logout"
        self._audit(
            action="logout",
            outcome="succeeded",
            actor=f"user:{credential.id}",
            credential=credential,
            username=member.username,
            session=session,
            now=current_time,
        )
        db.session.commit()
        return True

    def revoke_sessions(
        self,
        identifier: str,
        *,
        actor: str = "system",
        reason: str = "administrative_revocation",
        now: datetime | None = None,
    ) -> int:
        current_time = self._now(now)
        credential, member = self._account(identifier)
        count = self._revoke_credential_sessions(
            credential.id,
            now=current_time,
            reason=reason,
        )
        self._audit(
            action="sessions_revoke",
            outcome="succeeded",
            actor=actor,
            credential=credential,
            username=member.username,
            metadata={"revokedCount": count, "reason": reason},
            now=current_time,
        )
        db.session.commit()
        return count

    def create_account(
        self,
        team_member_id: str,
        password: str,
        *,
        roles: Iterable[str] = ("administrator",),
        enabled: bool = True,
        force_password_change: bool = False,
        initial_password: bool = False,
        actor: str = "system",
        now: datetime | None = None,
    ) -> AccountSummary:
        current_time = self._now(now)
        member = TeamMemberModel.query.session.get(TeamMemberModel, team_member_id)
        if member is None:
            raise AuthenticationError("team_member_not_found", "team member does not exist")
        if AuthenticationCredentialModel.query.filter_by(team_member_id=member.id).first():
            raise AuthenticationError("account_exists", "team member already has an account")
        if enabled and member.status != "active":
            raise AuthenticationError("team_member_inactive", "inactive team member cannot be enabled")
        if initial_password:
            if password != member.username:
                raise PasswordPolicyError(("initial password must equal the username",))
            force_password_change = True
        else:
            validate_password(password, username=member.username)
        validated_roles = _validated_roles(roles)
        member.global_roles = list(validated_roles)
        credential = AuthenticationCredentialModel(
            id=f"credential-{uuid4().hex}",
            team_member_id=member.id,
            password_hash=self.password_hasher.hash(password),
            roles_json=validated_roles,
            enabled=enabled,
            must_change_password=force_password_change,
            failed_login_count=0,
            created_at=current_time,
            updated_at=current_time,
        )
        db.session.add(credential)
        self._audit(
            action="account_create",
            outcome="succeeded",
            actor=actor,
            credential=credential,
            username=member.username,
            metadata={"enabled": enabled, "initialPassword": initial_password},
            now=current_time,
        )
        db.session.commit()
        return self._summary(credential, member)

    def reset_password(
        self,
        identifier: str,
        password: str,
        *,
        force_password_change: bool = True,
        initial_password: bool = False,
        actor: str = "system",
        now: datetime | None = None,
    ) -> AccountSummary:
        current_time = self._now(now)
        credential, member = self._account(identifier)
        if initial_password:
            if password != member.username:
                raise PasswordPolicyError(("initial password must equal the username",))
            force_password_change = True
        else:
            validate_password(password, username=member.username)
        credential.password_hash = self.password_hasher.hash(password)
        credential.must_change_password = force_password_change
        credential.password_changed_at = current_time
        credential.failed_login_count = 0
        credential.locked_until = None
        credential.updated_at = current_time
        revoked_count = self._revoke_credential_sessions(
            credential.id,
            now=current_time,
            reason="password_reset",
        )
        self._audit(
            action="password_reset",
            outcome="succeeded",
            actor=actor,
            credential=credential,
            username=member.username,
            metadata={"revokedCount": revoked_count, "initialPassword": initial_password},
            now=current_time,
        )
        db.session.commit()
        return self._summary(credential, member)

    def enable_account(
        self,
        identifier: str,
        *,
        actor: str = "system",
        now: datetime | None = None,
    ) -> AccountSummary:
        return self._set_enabled(identifier, True, actor=actor, now=now)

    def disable_account(
        self,
        identifier: str,
        *,
        actor: str = "system",
        now: datetime | None = None,
    ) -> AccountSummary:
        return self._set_enabled(identifier, False, actor=actor, now=now)

    def unlock_account(
        self,
        identifier: str,
        *,
        actor: str = "system",
        now: datetime | None = None,
    ) -> AccountSummary:
        current_time = self._now(now)
        credential, member = self._account(identifier)
        credential.failed_login_count = 0
        credential.locked_until = None
        credential.updated_at = current_time
        self._audit(
            action="account_unlock",
            outcome="succeeded",
            actor=actor,
            credential=credential,
            username=member.username,
            now=current_time,
        )
        db.session.commit()
        return self._summary(credential, member)

    def set_roles(
        self,
        identifier: str,
        roles: Iterable[str],
        *,
        actor: str = "system",
        now: datetime | None = None,
    ) -> AccountSummary:
        current_time = self._now(now)
        credential, member = self._account(identifier)
        credential.roles_json = _validated_roles(roles)
        member.global_roles = list(credential.roles_json)
        credential.updated_at = current_time
        self._audit(
            action="roles_set",
            outcome="succeeded",
            actor=actor,
            credential=credential,
            username=member.username,
            metadata={"roles": list(credential.roles_json)},
            now=current_time,
        )
        db.session.commit()
        return self._summary(credential, member)

    def bootstrap_active_team(
        self,
        *,
        roles: Iterable[str] = ("administrator",),
        actor: str = "system",
        now: datetime | None = None,
    ) -> list[AccountSummary]:
        current_time = self._now(now)
        role_list = _validated_roles(roles)
        created: list[AccountSummary] = []
        members = TeamMemberModel.query.filter_by(status="active").order_by(
            TeamMemberModel.username.asc()
        )
        for member in members.all():
            if AuthenticationCredentialModel.query.filter_by(
                team_member_id=member.id
            ).first():
                continue
            created.append(
                self.create_account(
                    member.id,
                    member.username,
                    roles=role_list,
                    initial_password=True,
                    actor=actor,
                    now=current_time,
                )
            )
        return created

    def list_accounts(self) -> list[AccountSummary]:
        rows = (
            db.session.query(AuthenticationCredentialModel, TeamMemberModel)
            .join(
                TeamMemberModel,
                TeamMemberModel.id == AuthenticationCredentialModel.team_member_id,
            )
            .order_by(TeamMemberModel.username.asc())
            .all()
        )
        return [self._summary(credential, member) for credential, member in rows]

    def get_account(self, identifier: str) -> AccountSummary:
        credential, member = self._account(identifier)
        return self._summary(credential, member)

    def _set_enabled(
        self,
        identifier: str,
        enabled: bool,
        *,
        actor: str,
        now: datetime | None,
    ) -> AccountSummary:
        current_time = self._now(now)
        credential, member = self._account(identifier)
        if enabled and member.status != "active":
            raise AuthenticationError("team_member_inactive", "inactive team member cannot be enabled")
        credential.enabled = enabled
        credential.updated_at = current_time
        revoked_count = 0
        if not enabled:
            revoked_count = self._revoke_credential_sessions(
                credential.id,
                now=current_time,
                reason="account_disabled",
            )
        self._audit(
            action="account_enable" if enabled else "account_disable",
            outcome="succeeded",
            actor=actor,
            credential=credential,
            username=member.username,
            metadata={"revokedCount": revoked_count},
            now=current_time,
        )
        db.session.commit()
        return self._summary(credential, member)

    def _active_session(
        self,
        session_token: str,
        now: datetime,
    ) -> tuple[AuthenticationSessionModel, AuthenticationCredentialModel, TeamMemberModel]:
        if not session_token:
            raise AuthenticationError("invalid_session", "session is invalid or expired")
        session = AuthenticationSessionModel.query.filter_by(
            token_hash=_token_hash(session_token)
        ).first()
        if session is None or session.revoked_at is not None:
            raise AuthenticationError("invalid_session", "session is invalid or expired")
        if now >= _as_utc(session.absolute_expires_at) or now >= _as_utc(
            session.idle_expires_at
        ):
            session.revoked_at = now
            session.revocation_reason = "expired"
            db.session.commit()
            raise AuthenticationError("invalid_session", "session is invalid or expired")
        credential, member = self._credential_member(session.credential_id)
        if not credential.enabled or member.status != "active":
            session.revoked_at = now
            session.revocation_reason = "account_disabled"
            db.session.commit()
            raise AuthenticationError("invalid_session", "session is invalid or expired")
        return session, credential, member

    def _touch_session(
        self,
        session_token: str,
        session: AuthenticationSessionModel,
        now: datetime,
    ) -> tuple[AuthenticationSessionModel, AuthenticationCredentialModel, TeamMemberModel]:
        """Atomically extend stale activity, then return authoritative state.

        The timestamp predicate is evaluated by the database so concurrent
        workers cannot all extend and commit the same session. A losing worker
        rolls back its no-op statement before reading the winner's state.
        """

        token_hash = _token_hash(session_token)
        threshold = now - self.touch_interval
        idle_expires_at = min(
            now + self.idle_lifetime,
            _as_utc(session.absolute_expires_at),
        )
        # Release the read transaction opened by the initial validity check.
        # In SQLite, retaining that shared lock while several processes try to
        # promote to writers can otherwise produce an avoidable lock-upgrade
        # race. The UPDATE repeats every mutable session validity predicate.
        db.session.rollback()
        result = db.session.execute(
            update(AuthenticationSessionModel)
            .where(
                AuthenticationSessionModel.token_hash == token_hash,
                AuthenticationSessionModel.revoked_at.is_(None),
                AuthenticationSessionModel.absolute_expires_at > now,
                AuthenticationSessionModel.idle_expires_at > now,
                AuthenticationSessionModel.last_seen_at <= threshold,
            )
            .values(last_seen_at=now, idle_expires_at=idle_expires_at)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            db.session.commit()
        else:
            db.session.rollback()
        db.session.expire_all()
        return self._active_session(session_token, now)

    def _account(
        self,
        identifier: str,
    ) -> tuple[AuthenticationCredentialModel, TeamMemberModel]:
        credential = AuthenticationCredentialModel.query.session.get(
            AuthenticationCredentialModel,
            identifier,
        )
        if credential is not None:
            return self._credential_member(credential.id)
        member = TeamMemberModel.query.filter_by(
            username=_normalize_username(identifier)
        ).first()
        if member is None:
            raise AuthenticationError("account_not_found", "account does not exist")
        credential = AuthenticationCredentialModel.query.filter_by(
            team_member_id=member.id
        ).first()
        if credential is None:
            raise AuthenticationError("account_not_found", "account does not exist")
        return credential, member

    def _credential_member(
        self,
        credential_id: str,
    ) -> tuple[AuthenticationCredentialModel, TeamMemberModel]:
        credential = AuthenticationCredentialModel.query.session.get(
            AuthenticationCredentialModel,
            credential_id,
        )
        if credential is None:
            raise AuthenticationError("account_not_found", "account does not exist")
        member = TeamMemberModel.query.session.get(TeamMemberModel, credential.team_member_id)
        if member is None:
            raise AuthenticationError("account_not_found", "account does not exist")
        return credential, member

    def _revoke_credential_sessions(
        self,
        credential_id: str,
        *,
        now: datetime,
        reason: str,
    ) -> int:
        sessions = AuthenticationSessionModel.query.filter_by(
            credential_id=credential_id,
            revoked_at=None,
        ).all()
        for session in sessions:
            session.revoked_at = now
            session.revocation_reason = reason
        return len(sessions)

    def _verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return bool(self.password_hasher.verify(password_hash, password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def _verify_unknown(self, password: str) -> None:
        self._verify_password(self._unknown_account_hash, password)

    def _identity(
        self,
        credential: AuthenticationCredentialModel,
        member: TeamMemberModel,
        session: AuthenticationSessionModel,
    ) -> AuthenticatedIdentity:
        return AuthenticatedIdentity(
            credential_id=credential.id,
            team_member_id=member.id,
            username=member.username,
            display_name=member.display_name,
            roles=tuple(credential.roles_json or ()),
            must_change_password=bool(credential.must_change_password),
            session_id=session.id,
            absolute_expires_at=_as_utc(session.absolute_expires_at),
            idle_expires_at=_as_utc(session.idle_expires_at),
        )

    def _summary(
        self,
        credential: AuthenticationCredentialModel,
        member: TeamMemberModel,
    ) -> AccountSummary:
        return AccountSummary(
            credential_id=credential.id,
            team_member_id=member.id,
            username=member.username,
            display_name=member.display_name,
            team_member_status=member.status,
            enabled=bool(credential.enabled),
            roles=tuple(credential.roles_json or ()),
            must_change_password=bool(credential.must_change_password),
            failed_login_count=int(credential.failed_login_count or 0),
            locked_until=_as_utc(credential.locked_until),
            password_changed_at=_as_utc(credential.password_changed_at),
            created_at=_as_utc(credential.created_at),
            updated_at=_as_utc(credential.updated_at),
        )

    def _audit(
        self,
        *,
        action: str,
        outcome: str,
        actor: str,
        username: str,
        now: datetime,
        credential: AuthenticationCredentialModel | None = None,
        session: AuthenticationSessionModel | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        db.session.add(
            AuthenticationAuditEventModel(
                action=action,
                outcome=outcome,
                actor=actor,
                credential_id=credential.id if credential is not None else None,
                username=username,
                session_id=session.id if session is not None else "",
                metadata_json=metadata or {},
                created_at=now,
            )
        )

    def _now(self, value: datetime | None) -> datetime:
        return _as_utc(value if value is not None else self.clock())


def validate_password(password: str, *, username: str) -> None:
    errors: list[str] = []
    if not isinstance(password, str):
        raise PasswordPolicyError(("password must be text",))
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        errors.append(f"password must be at least {MINIMUM_PASSWORD_LENGTH} characters")
    if len(password) > MAXIMUM_PASSWORD_LENGTH:
        errors.append(f"password must be at most {MAXIMUM_PASSWORD_LENGTH} characters")
    folded = password.casefold()
    if folded == username.casefold():
        errors.append("password must not equal the username")
    if folded in _REJECTED_PASSWORDS:
        errors.append("password is a commonly used Barragan password")
    if errors:
        raise PasswordPolicyError(errors)


def _validated_roles(roles: Iterable[str]) -> list[str]:
    result = sorted({str(role).strip() for role in roles if str(role).strip()})
    if not result:
        raise AuthenticationError("invalid_roles", "at least one role is required")
    invalid = [role for role in result if not _ROLE_RE.fullmatch(role)]
    if invalid:
        raise AuthenticationError("invalid_roles", "roles must be lowercase action-role identifiers")
    return result


def _normalize_username(username: str) -> str:
    return str(username or "").strip().lower()


def _new_token() -> str:
    # token_hex(32) encodes exactly 256 random bits without adding semantics.
    return secrets.token_hex(32)


def _token_hash(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
