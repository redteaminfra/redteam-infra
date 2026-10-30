# Copyright (c) 2026, Oracle and/or its affiliates.
"""Produce one private, reviewable pair of mixed-provider append plans.

This is deliberately not a dispatcher or an Apply authority.  A command
whose outcome is not durably represented by the receipt stops this producer;
in particular a saved Terraform plan is never run a second time on retry.
"""

from __future__ import annotations

from contextlib import ExitStack
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import stat
import tempfile
from typing import Callable, Mapping

from cryptography.hazmat.primitives import serialization

from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_initial_plan_gate import _verify_audited_workspace
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_linode_initial_plan_gate import _workspace as require_audited_linode_workspace
from app.services.provider_keyed_mixed_append_intent import compile_mixed_digitalocean_on_linode_append_intent
from app.services.provider_keyed_mixed_append_linode_intent import compile_mixed_linode_on_digitalocean_append_intent
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    _canonical, _name, _read, _sha, reopen_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_mixed_append_reservation import (
    propose_mixed_external_append_reservations, _retained_ids_match_published,
)
from app.services.provider_keyed_mixed_plan_journal import _Journal, _run_gated
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, read_provider_topology,
    reserve_mixed_external_provider_topologies,
)
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository


_OPERATION = "provider_keyed_mixed_append"
_ENV = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                  "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})


class MixedAppendPairPlanProductionAttention(ValueError):
    """The pair cannot be produced or safely resumed without reconciliation."""


def _complete_retained_resource_ids(provider_states, states):
    """Adapt authenticated cloud receipts to the compiler's complete-state IDs."""
    result = {}
    for provider, raw in provider_states.items():
        saved = states[provider]
        if _sha(raw) != saved.state_sha256:
            raise ValueError("mixed append predecessor state hash differs")
        resources = _state_resources(json.loads(raw))
        complete = {address: str(value["id"]) for address, value in resources.items()}
        if not _retained_ids_match_published(provider, saved.resource_ids, tuple(complete.items())):
            raise ValueError("mixed append published resource identity differs")
        result[provider] = complete
    return result


def _write_new(path: Path, contents: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _same_or_new(path: Path, contents: bytes) -> None:
    if path.exists() or path.is_symlink():
        if _read(path) != contents:
            raise ValueError("mixed append retained plan input differs")
    else:
        _write_new(path, contents)


def _retained_plan_input(path, variables, workspace, workspaces):
    """Upgrade only the known pathless input left before any command started.

    Called with both provider plan locks held, after exact proposal and
    predecessor validation. Every other existing input remains immutable.
    """
    contents = (json.dumps(variables, sort_keys=True) + "\n").encode()
    if not (path.exists() or path.is_symlink()) or _read(path) == contents:
        _same_or_new(path, contents)
        return
    public, private = _admin_material_paths(workspace, variables)
    paths = {"ssh_pub_key_path": str(public), "ssh_priv_key_path": str(private),
             "ssh_config_path": str(public.parent / "ssh-output")}
    if any(variables.get(key) != value for key, value in paths.items()):
        raise ValueError("mixed append input SSH paths differ")
    old = (json.dumps({key: value for key, value in variables.items() if key not in paths},
                      sort_keys=True) + "\n").encode()
    if (_read(path) != old or any(
            (root.path / _name(provider, suffix)).exists()
            or (root.path / _name(provider, suffix)).is_symlink()
            for provider, root in workspaces.items()
            for suffix in ("plan-journal.jsonl", "plan-receipt.json", "saved.tfplan",
                           "show.json", "secret.json"))):
        raise ValueError("mixed append retained plan input differs")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                         prefix=".barragan-input-upgrade-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if _read(path) != old:
            raise ValueError("mixed append retained plan input changed")
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _regular_lock(path: Path, stack: ExitStack, *, existing_only=False):
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | (os.O_NONBLOCK if existing_only else os.O_CREAT), 0o600)
    lock = stack.enter_context(os.fdopen(descriptor, "r+b"))
    if (not stat.S_ISREG(os.fstat(lock.fileno()).st_mode)
            or os.fstat(lock.fileno()).st_mode & 0o077):
        raise ValueError("mixed append plan lock is unsafe")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | (fcntl.LOCK_NB if existing_only else 0))
    return lock


def _exact_journal(journal: _Journal, commands: Mapping[str, list[str]],
                   *, complete: bool, process_quiescence: Callable) -> list[list[dict]]:
    """A retry recognizes only one exact completed command per phase."""
    rows = journal._commands()
    phases = [row[0]["phase"] for row in rows]
    if phases != ["version", "init", "plan", "show"][:len(phases)]:
        raise ValueError("mixed append command chronology differs")
    for row in rows:
        phase = row[0]["phase"]
        expected = hashlib.sha256(json.dumps(commands[phase], separators=(",", ":")).encode()).hexdigest()
        result = row[-1]
        if (row[0]["data"]["argvSha256"] != expected
                or result["kind"] != "result"
                or result["data"]["returnCode"] != 0
                or result["data"]["stdoutTruncated"]
                or result["data"]["stderrTruncated"]):
            raise ValueError("mixed append command outcome needs reconciliation")
        started = row[1]["data"]
        if not process_quiescence(started["bootId"], started["pid"],
                                  started["pgid"], started["startTicks"]):
            raise ValueError("mixed append command process is not quiescent")
    if complete and phases != ["version", "init", "plan", "show"]:
        raise ValueError("mixed append command receipt is incomplete")
    return rows


def _receipt(*, provider: str, source, intent, workspace, state: bytes,
             inputs: Path, plan: Path, shown: Path, journal: _Journal,
             record, release) -> dict:
    root = workspace.path
    return {
        "schema": "mixed-append-saved-plan-receipt-v1", "provider": provider,
        "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
        "chainId": intent.chain_id, "predecessorStateSha256": _sha(state),
        "newEdgeAddress": intent.new_edge_address, "planSha256": _sha(_read(plan)),
        "showJsonSha256": _sha(_read(shown)),
        "sourceRevision": workspace.source_revision, "sourceSha256": workspace.source_sha256,
        "sourceMarkerSha256": _sha(_read(root / ".barragan-provider-keyed-state.json", private=False)),
        "topologySha256": _sha(_read(root / ".barragan-topology.json", private=False)),
        "lockfileSha256": _sha(_read(root / ".terraform.lock.hcl", private=False)),
        "inputSha256": _sha(_read(inputs)), "credentialRecordId": record.id,
        "credentialSecretSha256": _sha(record.encrypted_secret.encode()),
        "credentialUpdatedAt": record.updated_at,
        "terraformBinarySha256": release.sha256,
        "journalSha256": journal.rows[-1]["sha256"],
    }


def _admin_material_paths(workspace: ProviderKeyedWorkspace,
                          variables: Mapping[str, object]) -> tuple[Path, Path]:
    material = workspace.path.parents[1] / ".plan-material" / workspace.provider
    public = material / "admin-public"
    private = material / "admin-private"
    if (variables.get("ssh_pub_key_path") != str(public)
            or variables.get("ssh_priv_key_path") != str(private)
            or material.is_symlink() or not material.is_dir()
            or material.stat().st_mode & 0o077):
        raise ValueError("mixed append retained SSH plan paths differ")
    return public, private


def _matching_admin_key(public: str, private: str) -> bool:
    try:
        derived = serialization.load_ssh_private_key(private.encode(), password=None)
        rendered = derived.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        return tuple(rendered.split()[:2]) == tuple(public.encode().split()[:2])
    except (TypeError, ValueError, AttributeError):
        return False


def _secret_bytes(provider: str, token: str) -> bytes:
    return (json.dumps({
        "do_pat" if provider == "digitalocean" else "linode_api_token": token,
    }) + "\n").encode()


def _cleanup_matching_material(paths: Mapping[Path, bytes]) -> None:
    """Remove only exact staged bytes, including after a partial prior cleanup."""
    present = []
    for path, expected in paths.items():
        if path.exists() or path.is_symlink():
            if _read(path) != expected:
                raise ValueError("mixed append staged private material differs")
            present.append(path)
    directories = set()
    for path in present:
        path.unlink()
        directories.add(path.parent)
    for directory in directories:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _full_gate(provider: str, shown: bytes, *, workspace, intent,
               provider_states, digitalocean_firewall, reviewed_variables) -> None:
    if provider == "digitalocean":
        from app.services.provider_keyed_mixed_append_plan_gate import require_mixed_digitalocean_on_linode_append_full_plan
        require_mixed_digitalocean_on_linode_append_full_plan(
            shown.decode(), workspace=workspace, intent=intent,
            digitalocean_state_json=provider_states["digitalocean"],
            linode_state_json=provider_states["linode"],
            firewall=digitalocean_firewall,
            reviewed_variables=reviewed_variables)
    else:
        from app.services.provider_keyed_mixed_append_linode_full_plan import require_mixed_linode_append_full_plan
        require_mixed_linode_append_full_plan(
            shown.decode(), workspace=workspace, intent=intent,
            digitalocean_state_json=provider_states["digitalocean"],
            linode_state_json=provider_states["linode"],
            reviewed_variables=reviewed_variables)


def produce_mixed_append_pair_plan_review(
    *, source, binding_manifest: Mapping[str, object],
    provider_states: Mapping[str, bytes], workspaces: Mapping[str, ProviderKeyedWorkspace],
    original_topologies: Mapping[str, Mapping[str, object]],
    original_regional_high_water: Mapping[str, int],
    retained_varfiles: Mapping[str, Mapping[str, object]],
    additions: Mapping[str, Mapping[str, object]],
    digitalocean_firewall, reviewed_provider_order: tuple[str, str],
    reviewed_chain_order: tuple[str, str], lease_lookup: Callable,
    lease_owner: str, admin_public_key: str, admin_private_key: str,
    credential_repository=None, release_check=require_devtest_terraform_release,
    command_environment: Mapping[str, str] | None = None,
    gated_command_runner: Callable = run_gated_command,
    process_quiescence: Callable = _process_quiescent,
    completed_plans_only: bool = False,
    completed_first_provider: str | None = None,
):
    """Save both binaries and reopen one joined review, with no Terraform Apply.

    ``source`` and the original topology/ledger must come from an authenticated
    published four-node generation, not mutable operator form data. A fresh
    caller supplies the same originals after restart. Interrupted plan/show
    commands fail closed; a completed receipt is reopened without rerunning a
    command. No live dispatcher calls this private producer yet.
    """
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    providers = {"digitalocean", "linode"}
    try:
        if (type(completed_plans_only) is not bool
                or completed_first_provider is not None and (
                    type(completed_first_provider) is not str or completed_plans_only
                    or completed_first_provider != reviewed_provider_order[0])):
            raise ValueError("mixed append completed-plan mode differs")
        if completed_plans_only:
            for provider in providers:
                journal = _Journal(workspaces[provider].path / _name(provider, "plan-journal.jsonl"),
                                   MixedAppendPairPlanProductionAttention)
                commands = journal._commands()
                if (tuple(command[0]["phase"] for command in commands) != ("version", "init", "plan", "show")
                        or journal.pending() is not None
                        or any(command[-1]["kind"] != "result"
                               or command[-1]["data"].get("returnCode") != 0
                               for command in commands)):
                    raise ValueError("mixed append completed plans require both complete journals")
        if (set(provider_states) != providers or set(workspaces) != providers
                or set(original_topologies) != providers or set(retained_varfiles) != providers
                or set(additions) != providers or set(reviewed_provider_order) != providers
                or len(reviewed_provider_order) != 2
                or type(binding_manifest) is not dict
                or _canonical(binding_manifest) != source.binding_manifest_sha256
                or binding_manifest.get("schema") != "mixed-initial-host-binding-v1"
                or binding_manifest.get("engagementId") != source.engagement_id
                or binding_manifest.get("coreJobId") != source.core_job_id
                or lease_lookup(source.engagement_id) != (lease_owner, _OPERATION)
                or not admin_public_key.strip() or not admin_private_key.strip()
                or not _matching_admin_key(admin_public_key, admin_private_key)):
            raise ValueError("mixed append published source or lease differs")
        states = {row.provider: row for row in source.provider_states}
        if (set(states) != providers or any(
                _sha(provider_states[p]) != states[p].state_sha256 for p in providers)):
            raise ValueError("mixed append predecessor states differ")
        do_resources = _state_resources(json.loads(provider_states["digitalocean"]))
        linode_resources = _state_resources(json.loads(provider_states["linode"]))
        if (do_resources["digitalocean_ssh_key.key"].get("public_key") != admin_public_key
                or any(values.get("authorized_keys") != [admin_public_key]
                       for address, values in linode_resources.items()
                       if address.startswith("linode_instance."))):
            raise ValueError("mixed append durable administration key differs")
        ids = _complete_retained_resource_ids(provider_states, states)
        hashes = {p: states[p].state_sha256 for p in providers}
        base = dict(published_binding=binding_manifest, provider_states=provider_states,
                    provider_state_sha256=hashes, provider_resource_ids=ids)
        do = compile_mixed_digitalocean_on_linode_append_intent(
            **base, retained_digitalocean_varfile=retained_varfiles["digitalocean"],
            **additions["digitalocean"])
        linode = compile_mixed_linode_on_digitalocean_append_intent(
            **base, retained_linode_varfile=retained_varfiles["linode"],
            admin_public_key=admin_public_key, **additions["linode"])
        intents = {"digitalocean": do, "linode": linode}
        inputs = {p: intents[p].nonsecret_varfile for p in providers}
        proposal = propose_mixed_external_append_reservations(
            source=source, binding_manifest=binding_manifest,
            digitalocean_intent=do, linode_intent=linode,
            current_topologies=original_topologies,
            regional_high_water=original_regional_high_water,
            reviewed_provider_order=reviewed_provider_order)
        release = release_check(environment="devtest")
        if (release.version != "1.15.5" or release.platform != "linux_amd64"
                or _sha(_read(release.path, private=False)) != release.sha256):
            raise ValueError("mixed append Terraform release differs")
        raw_env = os.environ if command_environment is None else command_environment
        if any(key.upper().startswith("TF_") for key in raw_env):
            raise ValueError("mixed append Terraform environment is unreviewed")
        if workspaces["digitalocean"].path.parents[1] != workspaces["linode"].path.parents[1]:
            raise ValueError("mixed append workspaces are not joined")
        records = {p: credentials.get(workspaces[p].provider_connection_id) for p in providers}
        for provider in providers:
            workspace = workspaces[provider]
            record = records[provider]
            if (record is None or record.provider != provider or record.status != "active"
                    or record.id != workspace.provider_connection_id
                    or workspace.schema != "provider-keyed-v2"
                    or workspace.provider != provider
                    or workspace.path.parents[2].name != source.engagement_id
                    or workspace.path.parent.name != provider
                    or workspace.path.name != workspace.connection_fingerprint
                    or workspace.state_path != workspace.path / "terraform.tfstate"
                    or json.loads(_read(workspace.path / ".barragan-provider-keyed-state.json",
                                        private=False)).get("engagement_id") != source.engagement_id
                    or _sha(_read(workspace.state_path, private=False)) != hashes[provider]):
                raise ValueError("mixed append credential or state differs")
            (_verify_audited_workspace if provider == "digitalocean"
             else require_audited_linode_workspace)(workspace)

        def authority() -> None:
            if lease_lookup(source.engagement_id) != (lease_owner, _OPERATION):
                raise ValueError("mixed append lease changed")
            for provider in providers:
                workspace, record = workspaces[provider], records[provider]
                current = credentials.get(workspace.provider_connection_id)
                if (current != record
                        or _sha(_read(workspace.state_path, private=False)) != hashes[provider]
                        or read_provider_topology(workspace)
                           != next(row.proposed_topology for row in proposal.reservations
                                   if row.provider == provider)):
                    raise ValueError("mixed append source, credential, or topology changed")
                (_verify_audited_workspace if provider == "digitalocean"
                 else require_audited_linode_workspace)(workspace)

        with ExitStack() as stack:
            # Lock order is fixed even when the reviewed command order is
            # reversed. A concurrent opposite-order plan cannot deadlock.
            for provider in sorted(providers):
                _regular_lock(workspaces[provider].path / _name(provider, "plan.lock"), stack,
                              existing_only=completed_first_provider is not None)
            if completed_first_provider is not None:
                first, second = reviewed_provider_order
                for provider in reviewed_provider_order:
                    root = workspaces[provider].path
                    required = {'plan.lock', 'predecessor.tfstate'}
                    if provider == first:
                        required |= {'inputs.json', 'saved.tfplan', 'show.json', 'plan-journal.jsonl'}
                    allowed = required | ({'plan-receipt.json', 'secret.json'} if provider == first else set())
                    actual = set(root.glob('.barragan-mixed-append-*'))
                    if (not {root / _name(provider, suffix) for suffix in required} <= actual
                            or not actual <= {root / _name(provider, suffix) for suffix in allowed}):
                        raise ValueError("mixed append completed-first retry artifacts changed")
                    for path in actual:
                        _read(path)
                journal = _Journal(workspaces[first].path / _name(first, 'plan-journal.jsonl'),
                                   MixedAppendPairPlanProductionAttention)
                commands = journal._commands()
                if (tuple(command[0]['phase'] for command in commands) != ('version', 'init', 'plan', 'show')
                        or journal.pending() is not None
                        or any(command[-1]['kind'] != 'result'
                               or type(command[-1]['data'].get('returnCode')) is not int
                               or command[-1]['data']['returnCode'] != 0 for command in commands)):
                    raise ValueError("mixed append completed-first retry journal changed")
            reserved = reserve_mixed_external_provider_topologies(workspaces, proposal)
            if reserved != {row.provider: row.proposed_topology for row in proposal.reservations}:
                raise ValueError("mixed append topology reservation differs")
            authority()
            # Terraform replaces terraform.tfstate during Apply. Preserve the
            # exact predecessor under both plan locks before either binary is
            # produced, and never recreate a lost snapshot on retry.
            for provider in sorted(providers):
                root = workspaces[provider].path
                snapshot = root / _name(provider, "predecessor.tfstate")
                if (not snapshot.exists() and not snapshot.is_symlink()
                        and any((root / _name(provider, suffix)).exists()
                                or (root / _name(provider, suffix)).is_symlink()
                                for suffix in ("saved.tfplan", "show.json",
                                               "plan-receipt.json", "plan-journal.jsonl"))):
                    raise ValueError("mixed append predecessor snapshot is missing")
                _same_or_new(snapshot, provider_states[provider])
            for provider in reviewed_provider_order:
                workspace, intent, record = workspaces[provider], intents[provider], records[provider]
                root = workspace.path
                input_path = root / _name(provider, "inputs.json")
                plan_path = root / _name(provider, "saved.tfplan")
                shown_path = root / _name(provider, "show.json")
                receipt_path = root / _name(provider, "plan-receipt.json")
                secret_path = root / _name(provider, "secret.json")
                journal = _Journal(root / _name(provider, "plan-journal.jsonl"),
                                   MixedAppendPairPlanProductionAttention)
                _retained_plan_input(input_path, inputs[provider], workspace, workspaces)
                binary = str(release.path)
                env = {key: value for key, value in raw_env.items() if key in _ENV}
                env.update(TF_DATA_DIR=str(workspace.terraform_data_dir),
                           TF_CLI_CONFIG_FILE="/dev/null")
                commands = {
                    "version": [binary, "version", "-json"],
                    "init": [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"],
                    "plan": [binary, "plan", "-input=false", "-lock=true", "-no-color",
                             f"-out={plan_path}", f"-var-file={input_path}",
                             f"-var-file={secret_path}"],
                    "show": [binary, "show", "-json", str(plan_path)],
                }
                if receipt_path.exists() or receipt_path.is_symlink():
                    _exact_journal(journal, commands, complete=True,
                                   process_quiescence=process_quiescence)
                    if json.loads(_read(receipt_path)) != _receipt(
                            provider=provider, source=source, intent=intent,
                            workspace=workspace, state=provider_states[provider],
                            inputs=input_path, plan=plan_path, shown=shown_path,
                            journal=journal, record=record, release=release):
                        raise ValueError("mixed append completed receipt differs")
                    authority()
                    token = decrypt_secret_value(record.encrypted_secret)
                    if not isinstance(token, str) or not token:
                        raise ValueError("mixed append provider credential unavailable")
                    public_path, private_path = _admin_material_paths(workspace, inputs[provider])
                    _cleanup_matching_material({
                        secret_path: _secret_bytes(provider, token),
                        public_path: admin_public_key.encode(),
                        private_path: admin_private_key.encode(),
                    })
                    continue
                if journal.rows:
                    # A crash after fsyncing show but before fsyncing the
                    # receipt is recoverable by reads. No command is replayed.
                    rows = _exact_journal(journal, commands, complete=True,
                                          process_quiescence=process_quiescence)
                    shown = _read(shown_path)
                    if (not _read(plan_path) or not shown
                            or rows[-1][-1]["data"]["stdoutBytes"] != len(shown)):
                        raise ValueError("mixed append shown binary is incomplete")
                    token = decrypt_secret_value(record.encrypted_secret)
                    if (not isinstance(token, str) or not token
                            or _read(secret_path) != _secret_bytes(provider, token)):
                        raise ValueError("mixed append staged credential differs")
                    public_path, private_path = _admin_material_paths(workspace, inputs[provider])
                    if (_read(public_path) != admin_public_key.encode()
                            or _read(private_path) != admin_private_key.encode()):
                        raise ValueError("mixed append staged administration key differs")
                    _full_gate(provider, shown, workspace=workspace, intent=intent,
                               provider_states=provider_states,
                               digitalocean_firewall=digitalocean_firewall,
                               reviewed_variables=inputs[provider])
                    authority()
                    receipt = _receipt(provider=provider, source=source, intent=intent,
                                       workspace=workspace, state=provider_states[provider],
                                       inputs=input_path, plan=plan_path, shown=shown_path,
                                       journal=journal, record=record, release=release)
                    _write_new(receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode())
                    _cleanup_matching_material({
                        secret_path: _secret_bytes(provider, token),
                        public_path: admin_public_key.encode(),
                        private_path: admin_private_key.encode(),
                    })
                    continue
                if completed_plans_only or completed_first_provider == provider:
                    raise ValueError("mixed append completed plan command replay is forbidden")
                if (plan_path.exists() or plan_path.is_symlink()
                        or shown_path.exists() or shown_path.is_symlink()):
                    raise ValueError("mixed append unsealed artifact needs reconciliation")
                token = decrypt_secret_value(record.encrypted_secret)
                if not isinstance(token, str) or not token:
                    raise ValueError("mixed append provider credential unavailable")
                public_path, private_path = _admin_material_paths(workspace, inputs[provider])
                # A crash before the first journal intent may leave a subset
                # of the private staging files. Verify them before filling in
                # only the missing files; no command has started yet.
                _same_or_new(secret_path, _secret_bytes(provider, token))
                try:
                    _same_or_new(public_path, admin_public_key.encode())
                    _same_or_new(private_path, admin_private_key.encode())
                    for phase in ("version", "init"):
                        authority()
                        outcome = _run_gated(phase, commands[phase], root, env, journal,
                                             authority, gated_command_runner,
                                             MixedAppendPairPlanProductionAttention)
                        if phase == "version" and json.loads(outcome.stdout).get("terraform_version") != "1.15.5":
                            raise ValueError("mixed append Terraform version differs")
                    _write_new(plan_path, b"")
                    _run_gated("plan", commands["plan"], root, env, journal, authority,
                               gated_command_runner, MixedAppendPairPlanProductionAttention)
                    if not _read(plan_path):
                        raise ValueError("mixed append saved binary is empty")
                    plan_sha = _sha(_read(plan_path))
                    shown = _run_gated("show", commands["show"], root, env, journal,
                                       authority, gated_command_runner,
                                       MixedAppendPairPlanProductionAttention).stdout.encode()
                    if not shown or _sha(_read(plan_path)) != plan_sha:
                        raise ValueError("mixed append saved binary changed during show")
                    _write_new(shown_path, shown)
                    _full_gate(provider, shown, workspace=workspace, intent=intent,
                               provider_states=provider_states,
                               digitalocean_firewall=digitalocean_firewall,
                               reviewed_variables=inputs[provider])
                    authority()
                    receipt = _receipt(provider=provider, source=source, intent=intent,
                                       workspace=workspace, state=provider_states[provider],
                                       inputs=input_path, plan=plan_path, shown=shown_path,
                                       journal=journal, record=record, release=release)
                    _write_new(receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode())
                finally:
                    # A complete show without a receipt needs these exact
                    # staged inputs for read-only receipt reconstruction.
                    # An uncertain command also retains them for diagnosis.
                    if receipt_path.exists() and not receipt_path.is_symlink():
                        _cleanup_matching_material({
                            secret_path: _secret_bytes(provider, token),
                            public_path: admin_public_key.encode(),
                            private_path: admin_private_key.encode(),
                        })
            authority()
        return reopen_mixed_append_pair_plan_review(
            source=source, binding_manifest=binding_manifest,
            digitalocean_intent=do, linode_intent=linode,
            workspaces=workspaces, provider_states=provider_states,
            reviewed_inputs=inputs, digitalocean_firewall=digitalocean_firewall,
            reviewed_provider_order=reviewed_provider_order,
            reviewed_chain_order=reviewed_chain_order, lease_lookup=lease_lookup,
            lease_owner=lease_owner, credential_repository=credentials,
            release_check=release_check)
    except Exception:
        logging.getLogger(__name__).exception("Mixed append plan production stopped")
        raise MixedAppendPairPlanProductionAttention(
            "mixed append pair plan needs exact read-only reconciliation") from None
