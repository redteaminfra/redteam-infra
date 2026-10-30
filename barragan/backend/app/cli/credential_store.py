# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from app.core.config import Config
from app.core.runtime import initialize_runtime, runtime_context
from app.services.credentials import (
    CredentialStoreLockedError,
    CredentialValidationError,
    SUPPORTED_PROVIDERS,
    create_credential,
    rotate_credential,
    set_default_credential,
)
from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safely register Barragan provider credentials.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register = subparsers.add_parser(
        "register-default",
        description="Create or rotate a provider credential from stdin or a file and mark it as provider default.",
    )
    register.add_argument("--provider", required=True, choices=sorted(SUPPORTED_PROVIDERS))
    register.add_argument("--alias", required=True, help="Credential alias to create or mark as default.")
    register.add_argument("--description", default="", help="Safe human description for the credential.")
    source = register.add_mutually_exclusive_group(required=True)
    source.add_argument("--secret-file", type=Path, help="Read the secret from this local file.")
    source.add_argument("--stdin", action="store_true", help="Read the secret from stdin.")
    register.add_argument(
        "--rotate-existing",
        action="store_true",
        help="Replace an existing alias with the provided secret before marking it default.",
    )
    register.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")

    args = parser.parse_args(argv)
    if args.command == "register-default":
        try:
            secret = _read_secret(secret_file=args.secret_file, read_stdin=args.stdin, stdin=sys.stdin)
            runtime = initialize_runtime(Config, make_default=True)
            with runtime_context(runtime):
                body = register_default_credential(
                    provider=args.provider,
                    alias=args.alias,
                    description=args.description,
                    secret=secret,
                    rotate_existing=args.rotate_existing,
                )
        except (CredentialValidationError, CredentialStoreLockedError, ValueError) as exc:
            errors = exc.errors if isinstance(exc, CredentialValidationError) else [str(exc)]
            print(json.dumps({"ok": False, "errors": errors}, sort_keys=True), file=sys.stderr)
            return 1
        print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    return 1


def register_default_credential(
    *,
    provider: str,
    alias: str,
    description: str,
    secret: str,
    rotate_existing: bool = False,
    repository: CredentialRepository | None = None,
) -> dict[str, Any]:
    repo = repository or SqlAlchemyCredentialRepository()
    existing = repo.get_by_alias(provider.strip().lower(), alias.strip().lower())
    if existing is None:
        credential = create_credential(
            {
                "provider": provider,
                "alias": alias,
                "description": description,
                "secret": secret,
            },
            repository=repo,
        )
        action = "created"
    else:
        if not rotate_existing:
            raise CredentialValidationError(["credential alias already exists; pass --rotate-existing to replace its secret"])
        credential = rotate_credential(
            existing.id,
            {
                "description": description or existing.description,
                "secret": secret,
            },
            repository=repo,
        )
        if credential is None:
            raise CredentialValidationError(["credential alias could not be rotated"])
        action = "rotated"
    default = set_default_credential(credential.id, repository=repo)
    if default is None:
        raise CredentialValidationError(["credential could not be marked default"])
    return {
        "ok": True,
        "action": action,
        "credential": default.to_dict(),
        "secretAccepted": True,
        "secretEchoed": False,
    }


def _read_secret(*, secret_file: Path | None, read_stdin: bool, stdin: TextIO) -> str:
    if secret_file is not None:
        secret = secret_file.read_text(encoding="utf-8")
    elif read_stdin:
        secret = stdin.read()
    else:
        raise ValueError("secret source is required")
    secret = secret.rstrip("\r\n")
    if not secret:
        raise ValueError("secret is empty")
    return secret


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
