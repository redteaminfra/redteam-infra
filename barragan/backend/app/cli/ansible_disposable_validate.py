# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.integrations.ansible_disposable_validation import (
    SSH_PRIVATE_KEY_ENV,
    SSH_PUBLIC_KEY_ENV,
    SSH_SOURCE_CIDR_ENV,
    build_ansible_validation_commands,
    build_ansible_validation_workspace,
    execute_disposable_ansible_validation,
    render_ansible_validation_workspace,
    resolve_ansible,
    resolve_ansible_playbook,
)
from app.integrations.command_resolution import CommandResolution
from app.integrations.oci_disposable_terraform import (
    EXECUTION_CONFIRMATION,
    resolve_terraform,
)
from app.integrations.oci_read_validation import OciDevelopmentTarget, resolve_oci_cli


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Preview, render, print, or run the guarded disposable Ansible validation workspace."
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--include-content",
        action="store_true",
        help="Include rendered artifact content in JSON preview output.",
    )
    parser.add_argument(
        "--render-dir",
        type=Path,
        help="Optional destination directory for the local Terraform and Ansible validation workspace.",
    )
    parser.add_argument(
        "--print-commands",
        action="store_true",
        help="Print the planned Terraform, Ansible, and cleanup commands without running them.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Run the guarded Terraform create, Ansible validation, destroy, and cleanup check. "
            "Requires --render-dir, --confirm-mutation, and --confirm-destroy-cleanup."
        ),
    )
    parser.add_argument(
        "--confirm-mutation",
        help=f"Required exact value for --execute: {EXECUTION_CONFIRMATION}",
    )
    parser.add_argument(
        "--confirm-destroy-cleanup",
        action="store_true",
        help="Required with --execute to confirm the disposable resource will be destroyed.",
    )
    parser.add_argument(
        "--ssh-private-key-path",
        help=f"Optional private key path passed to execute mode; defaults to ${SSH_PRIVATE_KEY_ENV}.",
    )
    parser.add_argument(
        "--ssh-public-key-path",
        help=f"Optional public key path passed to execute mode; defaults to ${SSH_PUBLIC_KEY_ENV}.",
    )
    parser.add_argument(
        "--ssh-source-cidr",
        help=f"Optional trusted SSH source CIDR passed to execute mode; defaults to ${SSH_SOURCE_CIDR_ENV}.",
    )
    args = parser.parse_args(argv)

    if args.execute and args.print_commands:
        parser.error("--execute cannot be combined with --print-commands")

    if args.execute:
        if not args.render_dir:
            parser.error("--execute requires --render-dir")
        if args.confirm_mutation != EXECUTION_CONFIRMATION:
            parser.error(f"--execute requires --confirm-mutation {EXECUTION_CONFIRMATION}")
        if not args.confirm_destroy_cleanup:
            parser.error("--execute requires --confirm-destroy-cleanup")
        body = execute_disposable_ansible_validation(
            args.render_dir,
            ssh_private_key_path=args.ssh_private_key_path,
            ssh_public_key_path=args.ssh_public_key_path,
            ssh_source_cidr=args.ssh_source_cidr,
        ).to_dict()
    elif args.print_commands:
        body = _print_commands_body(
            ssh_private_key_path=args.ssh_private_key_path,
            ssh_public_key_path=args.ssh_public_key_path,
            ssh_source_cidr=args.ssh_source_cidr,
        )
    elif args.render_dir:
        workspace = render_ansible_validation_workspace(args.render_dir)
        body = workspace.to_dict(include_content=args.include_content)
        body["renderResult"] = {
            "root": str(args.render_dir),
            "artifactCount": len(workspace.artifacts),
            "mutation": False,
        }
    else:
        body = build_ansible_validation_workspace().to_dict(include_content=args.include_content)
        body["renderResult"] = None

    print(json.dumps(body, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if body["ok"] else 1


def _print_commands_body(
    *,
    ssh_private_key_path: str | None,
    ssh_public_key_path: str | None,
    ssh_source_cidr: str | None,
) -> dict[str, Any]:
    target = OciDevelopmentTarget()
    terraform_resolution = resolve_terraform()
    oci_resolution = resolve_oci_cli()
    ansible_resolution = resolve_ansible()
    ansible_playbook_resolution = resolve_ansible_playbook()
    workspace = build_ansible_validation_workspace(
        target,
        oci_executable=oci_resolution.command or "oci",
    )
    body = workspace.to_dict(include_content=False)
    body.update(
        {
            "ok": True,
            "mode": "ansible_validation_print_commands",
            "notice": (
                "This output prints planned Terraform, Ansible, and cleanup commands only. "
                "It does not contact OCI, read SSH key material, create compute, run Ansible, "
                "or destroy resources."
            ),
            "renderResult": None,
            "commands": {
                "planned": build_ansible_validation_commands(
                    workspace,
                    terraform_executable=terraform_resolution.command or "terraform",
                    ansible_executable=ansible_resolution.command or "ansible",
                    ansible_playbook_executable=(
                        ansible_playbook_resolution.command or "ansible-playbook"
                    ),
                    ssh_private_key_path=ssh_private_key_path or f"${SSH_PRIVATE_KEY_ENV}",
                    ssh_public_key_path=ssh_public_key_path or f"${SSH_PUBLIC_KEY_ENV}",
                    ssh_source_cidr=ssh_source_cidr or f"${SSH_SOURCE_CIDR_ENV}",
                ),
                "cleanupVerification": workspace.cleanup["verificationCommands"],
            },
            "commandResolution": {
                "oci": _command_resolution_dict(oci_resolution),
                "terraform": _command_resolution_dict(terraform_resolution),
                "ansible": _command_resolution_dict(ansible_resolution),
                "ansiblePlaybook": _command_resolution_dict(ansible_playbook_resolution),
            },
            "sshConfiguration": {
                "privateKeyPath": ssh_private_key_path or f"${SSH_PRIVATE_KEY_ENV}",
                "publicKeyPath": ssh_public_key_path or f"${SSH_PUBLIC_KEY_ENV}",
                "sourceCidr": ssh_source_cidr or f"${SSH_SOURCE_CIDR_ENV}",
                "privateKeyMaterialRead": False,
                "publicKeyMaterialRead": False,
            },
        }
    )
    return body


def _command_resolution_dict(resolution: CommandResolution) -> dict[str, Any]:
    return {
        "binaryName": resolution.binary_name,
        "command": resolution.command,
        "source": resolution.source,
        "overrideVariables": list(resolution.override_variables),
        "ok": resolution.ok,
        "error": resolution.error,
    }


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
