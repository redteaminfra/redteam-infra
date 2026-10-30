# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only binary identity fence before the first paired append Apply.

This module cannot authorize a Terraform Apply.  In particular it cannot be
reused after the first provider state changes: the second GO needs its own
post-first-provider proof and a durable one-shot write journal.
"""

from __future__ import annotations

from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
import stat
from typing import Callable, Mapping

from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    _name, _read, reopen_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release


class MixedAppendPairPreGoAttention(ValueError):
    """The two saved binaries do not prove the reviewed pre-Apply generation."""


def verify_mixed_append_pair_binaries_before_first_go(
    *, expected_review_sha256: str, source, binding_manifest,
    digitalocean_intent, linode_intent, workspaces, provider_states,
    reviewed_inputs, digitalocean_firewall, reviewed_provider_order,
    reviewed_chain_order, lease_lookup: Callable, lease_owner: str,
    credential_repository=None,
    release_check=require_devtest_terraform_release,
    command_environment: Mapping[str, str] | None = None,
    show_runner: Callable = run_gated_command,
    claim_heartbeat: Callable[[], None] | None = None,
):
    """Re-show both exact binaries under one lease and both plan locks.

    The source must already be independently authenticated from the published
    four-host generation.  The returned seal is read-only evidence, not GO
    authority.  The future coordinator must fence its write journal, provider
    prestate and claim immediately before each one-shot Apply.
    """
    kwargs = dict(
        source=source, binding_manifest=binding_manifest,
        digitalocean_intent=digitalocean_intent, linode_intent=linode_intent,
        workspaces=workspaces, provider_states=provider_states,
        reviewed_inputs=reviewed_inputs, digitalocean_firewall=digitalocean_firewall,
        reviewed_provider_order=reviewed_provider_order,
        reviewed_chain_order=reviewed_chain_order, lease_lookup=lease_lookup,
        lease_owner=lease_owner, credential_repository=credential_repository,
        release_check=release_check,
    )
    try:
        if (type(expected_review_sha256) is not str
                or len(expected_review_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_review_sha256)
                or type(reviewed_provider_order) is not tuple
                or len(reviewed_provider_order) != 2
                or set(reviewed_provider_order) != {"digitalocean", "linode"}):
            raise ValueError("mixed append reviewed seal or order differs")
        raw_env = os.environ if command_environment is None else command_environment
        if any(key.upper().startswith("TF_") for key in raw_env):
            raise ValueError("mixed append Terraform environment is unreviewed")
        env = {key: value for key, value in raw_env.items() if key in {
            "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
            "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        }}

        # Fixed acquisition order is independent of the operator's reviewed
        # execution order.  Shared locks exclude producer/apply writers while
        # allowing the existing read-only reopener's nested shared locks.
        with ExitStack() as stack:
            for provider in sorted(reviewed_provider_order):
                root = workspaces[provider].path
                descriptor = os.open(root / _name(provider, "plan.lock"),
                                     os.O_RDONLY | os.O_NOFOLLOW)
                lock = stack.enter_context(os.fdopen(descriptor, "rb"))
                if (not stat.S_ISREG(os.fstat(lock.fileno()).st_mode)
                        or os.fstat(lock.fileno()).st_mode & 0o077):
                    raise ValueError("mixed append plan lock is unsafe")
                fcntl.flock(lock.fileno(), fcntl.LOCK_SH)

            def authority() -> object:
                seal = reopen_mixed_append_pair_plan_review(**kwargs)
                if seal.review_sha256 != expected_review_sha256:
                    raise ValueError("mixed append operator review changed")
                return seal

            seal = authority()
            release = release_check(environment="devtest")
            if (release.version != "1.15.5" or release.platform != "linux_amd64"
                    or hashlib.sha256(_read(release.path, private=False)).hexdigest()
                    != release.sha256):
                raise ValueError("mixed append Terraform release changed")
            for provider in reviewed_provider_order:
                authority()
                workspace = workspaces[provider]
                root = workspace.path
                plan = root / _name(provider, "saved.tfplan")
                reviewed_show = _read(root / _name(provider, "show.json"))
                command = [str(release.path), "show", "-json", str(plan)]
                expected_argv = hashlib.sha256(json.dumps(
                    command, separators=(",", ":")).encode()).hexdigest()
                command_env = dict(env, TF_DATA_DIR=str(workspace.terraform_data_dir),
                                   TF_CLI_CONFIG_FILE="/dev/null")

                def on_intent(intent):
                    authority()
                    if (intent.scratch_path != str(root)
                            or intent.argv_sha256 != expected_argv):
                        raise ValueError("mixed append show invocation differs")

                def on_started(_started):
                    authority()

                def on_heartbeat(_started):
                    if claim_heartbeat is not None:
                        claim_heartbeat()
                    if lease_lookup(source.engagement_id) != (
                            lease_owner, "provider_keyed_mixed_append"):
                        raise ValueError("mixed append lease changed during show")

                def on_result(_result):
                    authority()

                outcome = show_runner(
                    command, scratch_path=root, provider_keyed_v2=True,
                    env=command_env, max_output_bytes=16 * 1024 * 1024,
                    intent_callback=on_intent, started_callback=on_started,
                    heartbeat_callback=on_heartbeat, result_callback=on_result,
                )
                if (outcome.returncode != 0 or outcome.stdout_truncated
                        or outcome.stderr_truncated
                        or outcome.stdout.encode() != reviewed_show):
                    raise ValueError("mixed append binary re-show differs from review")
                authority()
            return seal
    except Exception:
        raise MixedAppendPairPreGoAttention(
            "mixed append saved binaries need exact read-only reconciliation") from None
