# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only reopening of a paired mixed append plan review.

The two plan commands and their fsynced receipts must already exist. This
reader never invokes Terraform, compiles an intent after Apply, or grants GO.
A separate producer must journal init/plan/show and write these receipts.
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
from typing import Mapping

from app.services.provider_keyed_mixed_append_intent import MixedDigitalOceanOnLinodeAppendIntent
from app.services.provider_keyed_mixed_append_reservation import _retained_ids_match_published
from app.services.provider_keyed_mixed_append_linode_intent import MixedLinodeOnDigitalOceanAppendIntent
from app.services.provider_keyed_mixed_append_linode_full_plan import require_mixed_linode_append_full_plan
from app.services.provider_keyed_mixed_append_pair_plan import seal_mixed_append_pair_plan
from app.services.provider_keyed_mixed_append_plan_gate import require_mixed_digitalocean_on_linode_append_full_plan
from app.services.provider_keyed_mixed_initial_publication_source import MixedInitialPublicationSource
from app.services.provider_keyed_mixed_plan_journal import _Journal
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository


_OPERATION = "provider_keyed_mixed_append"
_SCHEMA = "mixed-append-saved-plan-receipt-v1"
_RECEIPT_KEYS = frozenset({
    "schema", "provider", "engagementId", "coreJobId", "chainId",
    "predecessorStateSha256", "newEdgeAddress", "planSha256", "showJsonSha256",
    "sourceRevision", "sourceSha256", "sourceMarkerSha256", "topologySha256",
    "lockfileSha256", "inputSha256", "credentialRecordId",
    "credentialSecretSha256", "credentialUpdatedAt", "terraformBinarySha256",
    "journalSha256",
})
_SUMMARY_KEYS = frozenset({
    "provider", "engagementId", "coreJobId", "chainId", "predecessorStateSha256",
    "newEdgeAddress", "planSha256", "showJsonSha256", "sourceRevision",
    "sourceSha256", "credentialRecordId", "credentialSecretSha256",
    "credentialUpdatedAt",
})


class MixedAppendPairPlanReviewAttention(ValueError):
    """Saved paired append review cannot be reopened from exact artifacts."""


def _name(provider: str, suffix: str) -> str:
    return f".barragan-mixed-append-{provider}-{suffix}"


def _read(path: Path, *, private: bool = True) -> bytes:
    if (path.is_symlink() or not path.is_file()
            or not stat.S_ISREG(path.stat().st_mode)
            or private and path.stat().st_mode & 0o077):
        raise ValueError("mixed append artifact is missing or unsafe")
    before = path.stat()
    value = path.read_bytes()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("mixed append artifact changed during read")
    return value


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _journal_complete(path: Path, expected_sha: str) -> None:
    journal = _Journal(path, MixedAppendPairPlanReviewAttention)
    if (not journal.rows or journal.rows[-1]["sha256"] != expected_sha
            or journal.rows[-1]["phase"] != "show"
            or journal.rows[-1]["kind"] != "result"
            or journal.pending() is not None):
        raise ValueError("mixed append command journal is incomplete")
    commands = journal._commands()
    phases = tuple(command[0]["phase"] for command in commands)
    if (len(commands) < 4 or phases[:3] != ("version", "init", "plan")
            or any(phase != "show" for phase in phases[3:])
            or any(command[-1]["kind"] not in {"quiescent", "result"}
                   for command in commands[:-1])
            or any(command[-1]["kind"] == "quiescent"
                   for command in commands[:3])
            or any(command[-1]["kind"] == "result" and (
                       command[-1]["data"]["returnCode"] != 0
                       or command[-1]["data"]["stdoutTruncated"]
                       or command[-1]["data"]["stderrTruncated"])
                   for command in commands)
            or commands[-1][-1]["kind"] != "result"):
        raise ValueError("mixed append command outcome differs")


def reopen_mixed_append_pair_plan_review(
    *, source: MixedInitialPublicationSource,
    binding_manifest: Mapping[str, object],
    digitalocean_intent: MixedDigitalOceanOnLinodeAppendIntent,
    linode_intent: MixedLinodeOnDigitalOceanAppendIntent,
    workspaces: Mapping[str, ProviderKeyedWorkspace],
    provider_states: Mapping[str, bytes],
    reviewed_inputs: Mapping[str, Mapping[str, object]],
    digitalocean_firewall: object,
    reviewed_provider_order: tuple[str, str],
    reviewed_chain_order: tuple[str, str],
    lease_lookup, lease_owner: str,
    credential_repository=None,
    release_check=require_devtest_terraform_release,
):
    """Reopen two already-produced plans under one exact append lease.

    The caller must independently authenticate ``source`` and the binding
    manifest from the published terminal job. This reader additionally checks
    their immutable IDs and exact raw predecessor states. Its return is a
    review fingerprint only; an Apply worker must recheck all authority.
    """
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    try:
        intents = {"digitalocean": digitalocean_intent, "linode": linode_intent}
        if (type(source) is not MixedInitialPublicationSource
                or not isinstance(binding_manifest, Mapping)
                or binding_manifest.get("schema") != "mixed-initial-host-binding-v1"
                or binding_manifest.get("engagementId") != source.engagement_id
                or binding_manifest.get("coreJobId") != source.core_job_id
                or _canonical(binding_manifest) != source.binding_manifest_sha256
                or source.engagement_id != digitalocean_intent.engagement_id
                or source.core_job_id != digitalocean_intent.core_job_id
                or set(source.ordered_providers) != set(intents)
                or set(source.chain_ids) != {digitalocean_intent.chain_id, linode_intent.chain_id}
                # Each new edge belongs to the opposite provider's native
                # middle chain, as authenticated by the intent compilers.
                or tuple(intents["linode" if p == "digitalocean" else "digitalocean"].chain_id
                         for p in source.ordered_providers)
                   != source.chain_ids
                or len(reviewed_provider_order) != 2
                or set(reviewed_provider_order) != set(intents)
                or workspaces["digitalocean"].path == workspaces["linode"].path
                or set(workspaces) != set(intents)
                or set(provider_states) != set(intents)
                or set(reviewed_inputs) != set(intents)
                or not callable(lease_lookup) or type(lease_owner) is not str
                or not lease_owner
                or lease_lookup(source.engagement_id) != (lease_owner, _OPERATION)):
            raise ValueError("mixed append published source or lease differs")
        states = {row.provider: row for row in source.provider_states}
        if (set(states) != set(intents)
                or any(_sha(provider_states[provider]) != states[provider].state_sha256
                       for provider in intents)
                or any(not _retained_ids_match_published(provider, states[provider].resource_ids,
                                     intents[provider].retained_digitalocean_ids
                                     if provider == "digitalocean"
                                     else intents[provider].retained_linode_ids)
                       for provider in intents)):
            raise ValueError("mixed append predecessor state differs")
        release = release_check(environment="devtest")
        if (release.version != "1.15.5" or release.platform != "linux_amd64"
                or _sha(_read(release.path, private=False)) != release.sha256):
            raise ValueError("mixed append Terraform release differs")
        summaries = {}
        with ExitStack() as stack:
            for provider in reviewed_provider_order:
                workspace = workspaces[provider]
                intent = intents[provider]
                root = workspace.path
                if (not isinstance(workspace, ProviderKeyedWorkspace)
                        or workspace.provider != provider
                        or root.is_symlink() or not root.is_dir()
                        or workspace.state_path != root / "terraform.tfstate"
                        or _sha(_read(workspace.state_path, private=False))
                           != states[provider].state_sha256):
                    raise ValueError("mixed append retained workspace differs")
                lock_path = root / _name(provider, "plan.lock")
                descriptor = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
                lock = stack.enter_context(os.fdopen(descriptor, "rb"))
                if (not stat.S_ISREG(os.fstat(lock.fileno()).st_mode)
                        or os.fstat(lock.fileno()).st_mode & 0o077):
                    raise ValueError("mixed append plan lock is unsafe")
                fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
                receipt_path = root / _name(provider, "plan-receipt.json")
                receipt = json.loads(_read(receipt_path))
                if type(receipt) is not dict or set(receipt) != _RECEIPT_KEYS:
                    raise ValueError("mixed append receipt shape differs")
                predecessor = _read(root / _name(provider, "predecessor.tfstate"))
                if (predecessor != provider_states[provider]
                        or predecessor != _read(workspace.state_path, private=False)
                        or _sha(predecessor) != receipt["predecessorStateSha256"]):
                    raise ValueError("mixed append predecessor snapshot differs")
                paths = {
                    "planSha256": root / _name(provider, "saved.tfplan"),
                    "showJsonSha256": root / _name(provider, "show.json"),
                    "sourceMarkerSha256": root / ".barragan-provider-keyed-state.json",
                    "topologySha256": root / ".barragan-topology.json",
                    "lockfileSha256": root / ".terraform.lock.hcl",
                    "inputSha256": root / _name(provider, "inputs.json"),
                }
                for key, path in paths.items():
                    if receipt[key] != _sha(_read(path, private=key in {
                            "planSha256", "showJsonSha256", "inputSha256"})):
                        raise ValueError("mixed append saved artifact changed")
                if json.loads(_read(paths["inputSha256"])) != reviewed_inputs[provider]:
                    raise ValueError("mixed append reviewed variables changed")
                _journal_complete(root / _name(provider, "plan-journal.jsonl"),
                                  receipt["journalSha256"])
                record = credentials.get(workspace.provider_connection_id)
                if (record is None or record.provider != provider
                        or record.status != "active"
                        or record.id != receipt["credentialRecordId"]
                        or record.updated_at != receipt["credentialUpdatedAt"]
                        or _sha(record.encrypted_secret.encode())
                           != receipt["credentialSecretSha256"]):
                    raise ValueError("mixed append credential snapshot differs")
                if (receipt["schema"] != _SCHEMA or receipt["provider"] != provider
                        or receipt["engagementId"] != source.engagement_id
                        or receipt["coreJobId"] != source.core_job_id
                        or receipt["chainId"] != intent.chain_id
                        or receipt["newEdgeAddress"] != intent.new_edge_address
                        or receipt["predecessorStateSha256"] != states[provider].state_sha256
                        or receipt["sourceRevision"] != workspace.source_revision
                        or receipt["sourceSha256"] != workspace.source_sha256
                        or receipt["terraformBinarySha256"] != release.sha256):
                    raise ValueError("mixed append receipt identity differs")
                shown = _read(paths["showJsonSha256"]).decode("utf-8")
                if provider == "digitalocean":
                    require_mixed_digitalocean_on_linode_append_full_plan(
                        shown, workspace=workspace, intent=intent,
                        digitalocean_state_json=provider_states["digitalocean"],
                        linode_state_json=provider_states["linode"],
                        firewall=digitalocean_firewall,
                        reviewed_variables=reviewed_inputs[provider])
                else:
                    require_mixed_linode_append_full_plan(
                        shown, workspace=workspace, intent=intent,
                        digitalocean_state_json=provider_states["digitalocean"],
                        linode_state_json=provider_states["linode"],
                        reviewed_variables=reviewed_inputs[provider])
                summaries[provider] = {key: receipt[key] for key in _SUMMARY_KEYS}
            if lease_lookup(source.engagement_id) != (lease_owner, _OPERATION):
                raise ValueError("mixed append review lease changed")
            return seal_mixed_append_pair_plan(
                digitalocean_intent, linode_intent,
                tuple(summaries[provider] for provider in reviewed_provider_order),
                reviewed_provider_order=reviewed_provider_order,
                reviewed_chain_order=reviewed_chain_order)
    except Exception:
        logging.getLogger(__name__).exception("Mixed append saved-plan review stopped")
        raise MixedAppendPairPlanReviewAttention(
            "mixed append pair plan needs exact read-only reconciliation") from None
