# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime
import getpass
import json
import os
import sys

from app.core.bootstrap import initialize_database
from app.services.authentication import AuthenticationError, AuthenticationService, PasswordPolicyError
from app.storage.database import db
from app.storage.models import TeamMemberModel


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    config = _environment_config(args.environment)
    actor = f"breakglass:{os.environ.get('BARRAGAN_BREAKGLASS_ACTOR') or getpass.getuser()}"
    state = initialize_database(config)
    try:
        with db.bind(state):
            service = AuthenticationService.from_config(config)
            result = _execute(service, args, actor)
            _print_result(result)
    except (AuthenticationError, PasswordPolicyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def _execute(service: AuthenticationService, args, actor: str):
    if args.action == "list":
        return service.list_accounts()
    if args.action == "show":
        return service.get_account(args.identifier)
    if args.action == "bootstrap-active-team":
        return service.bootstrap_active_team(actor=actor)
    if args.action == "create":
        member = TeamMemberModel.query.filter_by(username=args.username).first()
        if member is None:
            if not args.service_account:
                raise AuthenticationError(
                    "team_member_not_found",
                    "human accounts must first be created in Global Team; use --service-account only for a non-human identity",
                )
            member = TeamMemberModel(
                id=f"member-{args.username}",
                username=args.username,
                display_name=args.display_name or args.username,
                email="",
                status="active",
                desired_uid=None,
                default_infra_groups=[],
                global_roles=[],
            )
            db.session.add(member)
            db.session.flush()
        return service.create_account(
            member.id,
            _read_password(args),
            roles=_roles(args.roles),
            force_password_change=not args.permanent,
            actor=actor,
        )
    if args.action == "set-password":
        return service.reset_password(
            args.identifier,
            _read_password(args),
            force_password_change=not args.permanent,
            actor=actor,
        )
    if args.action == "enable":
        return service.enable_account(args.identifier, actor=actor)
    if args.action == "disable":
        return service.disable_account(args.identifier, actor=actor)
    if args.action == "unlock":
        return service.unlock_account(args.identifier, actor=actor)
    if args.action == "revoke-sessions":
        count = service.revoke_sessions(args.identifier, actor=actor)
        return {"username": args.identifier, "revokedSessions": count}
    if args.action == "set-roles":
        return service.set_roles(args.identifier, _roles(args.roles), actor=actor)
    raise ValueError(f"unsupported users action: {args.action}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="barragan-admin users")
    parser.add_argument("--environment", required=True, choices=("prod", "devtest"))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list")
    show = sub.add_parser("show"); show.add_argument("identifier")
    sub.add_parser("bootstrap-active-team")
    create = sub.add_parser("create")
    create.add_argument("username")
    create.add_argument("--display-name", default="")
    create.add_argument("--roles", default="administrator")
    create.add_argument("--service-account", action="store_true")
    _password_arguments(create)
    reset = sub.add_parser("set-password"); reset.add_argument("identifier"); _password_arguments(reset)
    for action in ("enable", "disable", "unlock", "revoke-sessions"):
        child = sub.add_parser(action); child.add_argument("identifier")
    roles = sub.add_parser("set-roles")
    roles.add_argument("identifier"); roles.add_argument("--roles", required=True)
    return parser


def _password_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument("--permanent", action="store_true", help="do not require a password change at next login")


def _read_password(args) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            raise ValueError("password stdin was empty")
        return password
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise ValueError("passwords do not match")
    return first


def _roles(value: str) -> tuple[str, ...]:
    return tuple(role.strip() for role in value.split(",") if role.strip())


def _environment_config(environment: str):
    data_dir = "/var/lib/barragan/data" if environment == "prod" else "/var/lib/barragan/devtest-data"
    override = os.environ.get("BARRAGAN_ADMIN_DATABASE_URL", "")
    class AdminConfig:
        SQLALCHEMY_DATABASE_URI = override or f"sqlite:///{data_dir}/barragan.sqlite3"
        AUTH_SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
        AUTH_SESSION_IDLE_SECONDS = 2 * 60 * 60
        AUTH_FAILURE_LIMIT = 10
        AUTH_LOCKOUT_SECONDS = 15 * 60
        AUTH_ARGON2_MEMORY_KIB = 19 * 1024
        AUTH_ARGON2_TIME_COST = 2
        AUTH_ARGON2_PARALLELISM = 1
    return AdminConfig


def _print_result(result) -> None:
    rows = result if isinstance(result, list) else [result]
    for row in rows:
        if hasattr(row, "__dataclass_fields__"):
            payload = asdict(row)
            for key, value in list(payload.items()):
                if isinstance(value, datetime): payload[key] = value.isoformat()
            print(json.dumps(payload, sort_keys=True))
        else:
            print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
