# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot mixed interrupted destroy-plan producer, before any destroy Apply.

Both provider scopes are prepared under the engagement teardown fence. A
state-backed scope receives an exact pinned Terraform destroy plan and show;
an absence-only scope receives no command. An uncertain command is never
replayed, and the parent can seal only after both scopes have been checked.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from uuid import uuid4

from app.domain import JobEvent
from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_initial_teardown import require_exact_digitalocean_destroy_plan
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id as initial_parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as apply_child_id
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _parent_id as cleanup_parent_id,
    recognize_mixed_interrupted_cleanup_checkpoint,
    recognize_mixed_interrupted_sealed_plans,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import (
    _default_quiescent, _quiescent_child, _saved_plans, _saved_review, _workspace,
    seal_mixed_interrupted_cleanup_plans,
)
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
from app.services.provider_keyed_mixed_interrupted_destroy_source import _binary_sha
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_plan_journal import _Journal, _run_gated, _recover_preplan
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.services.provider_keyed_linode_initial_plan_gate import _workspace as require_linode_workspace
from app.services.provider_keyed_initial_plan_gate import _verify_audited_workspace as require_do_workspace
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


_ENV = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                  "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})


class MixedInterruptedPlanWorkerAttention(ValueError):
    """An exact plan or its command outcome requires reconciliation."""


ACTION = "provider_keyed_mixed_interrupted_plan_worker"
_OWNER = f"mixed-interrupted-plan-{uuid4().hex}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


def _job_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-interrupted-plan-{core_job_id.removeprefix('job-')}"


def _pristine_queued_worker(job: StoredJobRun, parent: StoredJobRun,
                            initial: StoredJobRun, review, state_root: Path) -> bool:
    """Only an exact reservation with no command artifact may be started again."""
    base = {"engagementId": parent.target_id, "coreJobId": review.core_job_id,
            "corePlanId": parent.input["corePlanId"],
            "cleanupParentId": parent.id, "reviewSha256": review.review_sha256,
            "mutation": False}
    if (job.id != _job_id(review.core_job_id) or job.action != ACTION
            or job.status != "queued" or job.target != f"engagement:{parent.target_id}"
            or job.target_type != "engagement" or job.target_id != parent.target_id
            or job.requested_by != parent.requested_by or job.input != base
            or job.artifact_refs != [] or not job.created_at
            or job.started_at is not None or job.finished_at is not None
            or job.events != [JobEvent(1, "info", "mixed destroy planning queued", {})]):
        return False
    for provider in review.ordered_providers:
        root = _workspace(initial, provider, state_root).path
        journal = root / f".barragan-mixed-interrupted-destroy-{provider}.journal.jsonl"
        plan = root / f".barragan-mixed-interrupted-destroy-{provider}.tfplan"
        if any(path.exists() or path.is_symlink() for path in (journal, plan)):
            return False
    return True


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("mixed plan input is not a regular file")
    data = path.read_bytes()
    if not data or len(data) > 128 * 1024 * 1024:
        raise ValueError("mixed plan input is empty or unbounded")
    return hashlib.sha256(data).hexdigest()


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _credential(provider: str, policy: dict, credentials) -> str:
    connection_id = policy["provider_connection_id"]
    record = credentials.get(connection_id)
    default = credentials.get_default(provider)
    if (record is None or default is None or record != default
            or record.id != connection_id or record.provider != provider
            or record.status != "active" or record.is_default is not True
            or hashlib.sha256(record.encrypted_secret.encode()).hexdigest()
               != policy["credential_secret_sha256"]
            or record.updated_at != policy["credential_updated_at"]):
        raise ValueError("reviewed provider service credential changed")
    token = decrypt_secret_value(record.encrypted_secret)
    if type(token) is not str or not token:
        raise ValueError("provider credential cannot be decrypted")
    return token


def _produce_state_backed_plan(
    provider: str, scope, initial: StoredJobRun, workspace, *,
    credentials, sketch_keys, release, fence: Callable[[], None],
    source_recheck: Callable[[], None],
    gated_command_runner: Callable, command_environment: Mapping[str, str],
    process_quiescent: Callable[[dict], bool] = _default_quiescent,
    plan_variant: str = "interrupted",
    reviewed_policy: dict | None = None,
) -> tuple[Path, str]:
    """Save one exact destroy plan using reviewed inputs and one-shot commands."""
    if (scope.kind not in {"partial", "full"} or provider not in {"linode", "digitalocean"}
            or plan_variant not in {"interrupted", "published"}):
        raise ValueError("state-backed scope required")
    root = workspace.path
    (require_linode_workspace if provider == "linode" else require_do_workspace)(workspace)
    if (workspace.state_path != root / "terraform.tfstate"
            or workspace.terraform_data_dir != root / ".terraform-data"
            or workspace.terraform_data_dir.is_symlink()
            or not workspace.terraform_data_dir.is_dir()):
        raise ValueError("mixed Terraform workspace paths changed")
    lock_path = root / f".barragan-{provider}-plan.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r+b") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("provider plan lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fence()
        seal = validate_mixed_initial_apply_seal(initial)
        policy = seal["reviewedPolicy"][provider] if reviewed_policy is None else reviewed_policy
        if reviewed_policy is not None and plan_variant != "published":
            raise ValueError("final policy requires published destroy")
        state_path = workspace.state_path
        if (state_path.is_symlink() or not state_path.is_file()
                or hashlib.sha256(state_path.read_bytes()).hexdigest() != scope.state_sha256):
            raise ValueError("reviewed retained state changed")
        state, actual, _cloud = _state(provider, policy, state_path.read_bytes())
        ids = {address: str(attrs["id"]) for address, attrs in actual.items()}
        if (state["lineage"] != scope.lineage or state["serial"] != scope.serial
                or tuple(sorted(_cloud.items())) != scope.resource_ids):
            raise ValueError("reviewed resource IDs changed")
        material = root.parents[1] / ".plan-material" / provider
        if reviewed_policy is not None:
            material_sha = hashlib.sha256(json.dumps({
                "policy": policy, "stateSha256": scope.state_sha256,
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            # The one-shot journal hashes argv, including this immutable input
            # path. Its name binds the final policy and exact pre-destroy state.
            material = root / f".barragan-published-destroy-material-{material_sha}"
            material.mkdir(mode=0o700, exist_ok=True)
            if material.is_symlink() or material.stat().st_mode & 0o077:
                raise ValueError("private destroy material changed")
            destroy_inputs = (json.dumps({
                **policy["nonsecret_varfile"],
                "ssh_pub_key_path": str(material / "admin-public"),
                "ssh_priv_key_path": str(material / "admin-private"),
                "ssh_config_path": str(material / "ssh-output"),
            }, sort_keys=True) + "\n").encode()
            if (material / "inputs.json").is_symlink():
                raise ValueError("private destroy inputs are unsafe")
            if not (material / "inputs.json").exists():
                _write_new(material / "inputs.json", destroy_inputs)

        inputs = material / "inputs.json"
        public = material / "admin-public"
        private = material / "admin-private"
        secret = material / "credential.json"
        plan = root / f".barragan-mixed-{plan_variant}-destroy-{provider}.tfplan"
        journal = _Journal(root / f".barragan-mixed-{plan_variant}-destroy-{provider}.journal.jsonl",
                           MixedInterruptedPlanWorkerAttention)
        if (public.exists() or public.is_symlink()
                or private.exists() or private.is_symlink()
                or secret.exists() or secret.is_symlink()
                or material.is_symlink() or material.resolve(strict=True) != material
                or inputs.read_bytes() != (json.dumps({
                    **policy["nonsecret_varfile"],
                    "ssh_pub_key_path": str(public),
                    "ssh_priv_key_path": str(private),
                    "ssh_config_path": str(material / "ssh-output"),
                }, sort_keys=True) + "\n").encode()):
            raise ValueError("destroy plan attempt already exists or reviewed input changed")
        env = {key: value for key, value in command_environment.items() if key in _ENV}
        env.update(TF_DATA_DIR=str(workspace.terraform_data_dir), TF_CLI_CONFIG_FILE="/dev/null")
        binary = str(release.path)

        def authority():
            fence()
            (require_linode_workspace if provider == "linode" else require_do_workspace)(workspace)
            if (hashlib.sha256(state_path.read_bytes()).hexdigest() != scope.state_sha256
                    or inputs.read_bytes() != (json.dumps({
                        **policy["nonsecret_varfile"],
                        "ssh_pub_key_path": str(public),
                        "ssh_priv_key_path": str(private),
                        "ssh_config_path": str(material / "ssh-output"),
                    }, sort_keys=True) + "\n").encode()
                    or _binary_sha(release.path) != release.sha256):
                raise ValueError("destroy-plan source changed")

        def gated(phase, argv):
            if phase == "plan":
                source_recheck()
            return _run_gated(phase, argv, root, env, journal, authority,
                              gated_command_runner, MixedInterruptedPlanWorkerAttention)

        if journal.rows or plan.exists() or plan.is_symlink():
            commands = journal._commands()
            completed_plan = [command for command in commands
                              if command[0]["phase"] == "plan"
                              and command[-1]["kind"] == "result"
                              and command[-1]["data"]["returnCode"] == 0
                              and not command[-1]["data"]["stdoutTruncated"]
                              and not command[-1]["data"]["stderrTruncated"]]
            if len(completed_plan) != 1 or not plan.exists() or plan.is_symlink():
                raise ValueError("destroy plan command outcome requires reconciliation")
            _recover_preplan(journal, lambda boot, pid, pgid, ticks: process_quiescent({
                "bootId": boot, "pid": pid, "pgid": pgid, "startTicks": ticks}))
            source_recheck()
            authority()
            plan_sha = _sha(plan)
            shown = gated("show", [binary, "show", "-json", str(plan)]).stdout
            require_exact_digitalocean_destroy_plan(shown, expected_resource_ids=ids,
                                                     state=state)
            authority()
            if _sha(plan) != plan_sha:
                raise ValueError("saved destroy plan changed after show")
            return plan, shown

        key = retrieve_sketch_ssh_key(initial.target_id, sketch_keys)
        if (key is None or not key.public_key or not key.private_key
                or key.public_key != policy["admin_public_key"]):
            raise ValueError("reviewed Sketch administration key changed")
        token = _credential(provider, policy, credentials)
        credential_key = "linode_api_token" if provider == "linode" else "do_pat"
        staged = False
        try:
            staged = True
            _write_new(public, key.public_key.encode())
            _write_new(private, key.private_key.encode())
            _write_new(secret, (json.dumps({credential_key: token}) + "\n").encode())
            del token
            version = gated("version", [binary, "version", "-json"])
            if json.loads(version.stdout).get("terraform_version") != "1.15.5":
                raise ValueError("pinned Terraform version changed")
            gated("init", [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"])
            authority()
            gated("plan", [binary, "plan", "-destroy", "-input=false", "-lock=true", "-no-color",
                           f"-out={plan}", f"-var-file={inputs}", f"-var-file={secret}"])
            plan_sha = _sha(plan)
            shown = gated("show", [binary, "show", "-json", str(plan)]).stdout
            require_exact_digitalocean_destroy_plan(shown, expected_resource_ids=ids, state=state)
            authority()
            if _sha(plan) != plan_sha:
                raise ValueError("saved destroy plan changed after show")
            return plan, shown
        finally:
            # Only an uncertain plan command may still read staged inputs.
            # Show is read-only over the binary plan, so its staging can go.
            pending = journal.pending()
            if staged and (pending is None or pending[0]["phase"] != "plan"):
                secret.unlink(missing_ok=True)
                public.unlink(missing_ok=True)
                private.unlink(missing_ok=True)


def prepare_mixed_interrupted_destroy_plans(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path | None = None, job_repository=None,
    credential_repository=None, ssh_key_repository=None, lease_lookup=None,
    gated_command_runner: Callable = run_gated_command,
    command_environment: Mapping[str, str] | None = None,
    plan_producer: Callable = _produce_state_backed_plan,
    snapshot_collector: Callable = collect_provider_inventory_snapshot,
    process_quiescent: Callable = _default_quiescent,
) -> StoredJobRun:
    """Produce both plans/no-plan scopes then seal one teardown checkpoint."""
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedInterruptedPlanWorkerAttention("mixed destroy planning is DevTest-only")
    state_root = state_root or _default_state_root()
    if state_root != _default_state_root():
        raise MixedInterruptedPlanWorkerAttention("configured state root differs")
    jobs = job_repository or SqlAlchemyJobRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        initial = jobs.get(initial_parent_id(core_job_id))
        parent = jobs.get(cleanup_parent_id(core_job_id))
        if initial is None or parent is None or parent.target_id != engagement_id:
            raise ValueError("mixed interrupted source is absent")
        review = _saved_review(parent)
        if parent.input.get("phase") == "plans_sealed":
            recognize_mixed_interrupted_sealed_plans(parent, initial, review, _saved_plans(parent))
            return parent
        recognize_mixed_interrupted_cleanup_checkpoint(parent, initial, review)
        _require_lease(lookup, engagement_id, parent.input["corePlanId"],
                       operation="provider_keyed_teardown_fence")
        raw_environment = os.environ if command_environment is None else command_environment
        if any(key.upper().startswith("TF_") for key in raw_environment):
            raise ValueError("unreviewed Terraform environment input")
        worker_id = _job_id(core_job_id)
        base = {"engagementId": engagement_id, "coreJobId": core_job_id,
                "corePlanId": parent.input["corePlanId"],
                "cleanupParentId": parent.id, "reviewSha256": review.review_sha256,
                "mutation": False}
        previous = jobs.get(worker_id)
        resuming = False
        if previous is not None and previous.status == "succeeded":
            if (previous.action != ACTION or previous.status != "succeeded"
                    or previous.target_id != engagement_id or previous.finished_at is None
                    or previous.input != base
                    or len(previous.events) != 3
                    or previous.events[-1].message != "both mixed destroy plans saved"):
                raise ValueError("existing mixed destroy-plan worker cannot be replayed")
            saved = previous.events[-1].data
            if (type(saved) is not dict or set(saved) != {"reviewSha256", "providers"}
                    or saved["reviewSha256"] != review.review_sha256
                    or type(saved["providers"]) is not list
                    or len(saved["providers"]) != 2):
                raise ValueError("mixed destroy-plan receipt differs")
            plan_paths, shown_json = {}, {}
            for provider, item in zip(review.ordered_providers, saved["providers"], strict=True):
                if type(item) is not dict or item.get("provider") != provider:
                    raise ValueError("mixed destroy-plan receipt order differs")
                if item.get("planPath") is None:
                    if item != {"provider": provider, "planPath": None,
                                "planSha256": None, "showSha256": None}:
                        raise ValueError("absence-only receipt differs")
                    plan_paths[provider] = shown_json[provider] = None
                else:
                    if set(item) != {"provider", "planPath", "planSha256", "showSha256"}:
                        raise ValueError("mixed destroy-plan receipt shape differs")
                    plan = Path(item["planPath"])
                    workspace = _workspace(initial, provider, state_root)
                    release = require_devtest_terraform_release(environment="devtest")
                    expected_plan = workspace.path / f".barragan-mixed-interrupted-destroy-{provider}.tfplan"
                    if plan != expected_plan or _sha(plan) != item["planSha256"]:
                        raise ValueError("mixed destroy-plan artifact changed")
                    if (release.version != "1.15.5" or release.platform != "linux_amd64"
                            or _binary_sha(release.path) != release.sha256):
                        raise ValueError("pinned Terraform release differs")
                    env = {key: value for key, value in raw_environment.items()
                           if key in _ENV}
                    env.update(TF_DATA_DIR=str(workspace.terraform_data_dir),
                               TF_CLI_CONFIG_FILE="/dev/null")
                    read = subprocess.run(
                        [str(release.path), "show", "-json", str(plan)],
                        cwd=workspace.path, env=env, text=True, capture_output=True,
                        timeout=180, check=True)
                    if (len(read.stdout.encode()) > 16 * 1024 * 1024
                            or hashlib.sha256(read.stdout.encode()).hexdigest()
                               != item["showSha256"]):
                        raise ValueError("mixed saved show changed")
                    plan_paths[provider], shown_json[provider] = plan, read.stdout
            return seal_mixed_interrupted_cleanup_plans(
                engagement_id, core_job_id, plan_paths=plan_paths,
                show_json=shown_json, environment=environment, state_root=state_root,
                job_repository=jobs, lease_lookup=lookup)
        if previous is not None and previous.status == "queued":
            if not _pristine_queued_worker(previous, parent, initial, review, state_root):
                raise ValueError("existing mixed destroy-plan worker cannot be resumed")
        elif previous is not None:
            if (previous.action != ACTION or previous.status != "running"
                    or previous.input != {**base, **{
                        key: value for key, value in previous.input.items()
                        if key in {"claimOwner", "claimToken", "claimClaimedAt",
                                   "claimHeartbeatAt", "claimExpiresAt"}}}
                    or previous.target_id != engagement_id
                    or len(previous.events) != 2
                    or previous.events[-1].message != "mixed destroy planning started"):
                raise ValueError("existing mixed destroy-plan worker cannot be resumed")
            resuming = True
        release = require_devtest_terraform_release(environment="devtest")
        if (release.version != "1.15.5" or release.platform != "linux_amd64"
                or _binary_sha(release.path) != release.sha256):
            raise ValueError("pinned Terraform release differs")
        if resuming:
            current = previous
        else:
            queued = previous or StoredJobRun(
                _job_id(core_job_id), ACTION, "queued", f"engagement:{engagement_id}",
                "engagement", engagement_id, parent.requested_by, base, [], _now(), None,
                None, [JobEvent(1, "info", "mixed destroy planning queued", {})])
            stored = jobs.save_if_absent(queued)
            if not _pristine_queued_worker(stored, parent, initial, review, state_root):
                raise ValueError("mixed destroy-plan worker reservation raced")
            current = jobs.start_if_queued(
                stored, started_at=_now(),
                event=JobEvent(2, "info", "mixed destroy planning started", {}))
            if current is None:
                raise ValueError("mixed destroy-plan worker start was not retained")
        token = uuid4().hex
        at = _now()
        current = jobs.claim_lease(worker_id, owner=_OWNER, token=token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if current is None:
            raise ValueError("mixed destroy-plan worker claim was not retained")
        source_children = {provider: jobs.get(apply_child_id(core_job_id, provider))
                           for provider in review.ordered_providers}
        generation = uuid4().hex
        def fence() -> str:
            nonlocal current
            _require_lease(lookup, engagement_id, parent.input["corePlanId"],
                           operation="provider_keyed_teardown_fence")
            if (jobs.get(initial.id) != initial or jobs.get(parent.id) != parent
                    or any(jobs.get(apply_child_id(core_job_id, provider)) != source_children[provider]
                           for provider in review.ordered_providers)
                    or jobs.get(worker_id) != current):
                raise ValueError("mixed destroy planning source changed")
            at = _now()
            renewed = jobs.renew_lease(worker_id, owner=_OWNER, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if renewed is None or renewed.events != current.events:
                raise ValueError("mixed destroy-plan worker claim lost")
            current = renewed
            return generation

        def recheck_source() -> None:
            children = source_children
            snapshots = {}
            for provider in review.ordered_providers:
                fence()
                workspace = _workspace(initial, provider, state_root)
                snapshots[provider] = snapshot_collector(
                    initial, provider, workspace, fence=fence,
                    process_quiescent=lambda provider=provider: _quiescent_child(
                        children[provider], process_quiescent),
                    credential_repository=credentials)
                fence()
            fresh = review_mixed_interrupted_source(
                initial, children, snapshots, fence=fence,
                process_quiescent=process_quiescent)
            for saved, present in zip(review.scopes, fresh.scopes, strict=True):
                stable = lambda scope: (
                    scope.provider, scope.kind, scope.child_journal_sha256,
                    scope.state_sha256, scope.lineage, scope.serial,
                    scope.resource_ids, scope.selector_tag,
                    scope.selector_retirement_pending)
                if stable(saved) != stable(present):
                    raise ValueError("mixed provider state or ownership changed")
            fence()

        paths, shown = {}, {}
        for scope in review.scopes:
            provider = scope.provider
            workspace = _workspace(initial, provider, state_root)
            fence()
            if scope.kind in {"partial", "full"}:
                path, output = plan_producer(
                    provider, scope, initial, workspace,
                    credentials=credentials, sketch_keys=keys, release=release,
                    fence=fence, source_recheck=recheck_source,
                    gated_command_runner=gated_command_runner,
                    command_environment=raw_environment,
                    process_quiescent=process_quiescent)
                paths[provider], shown[provider] = path, output
            elif scope.kind in {"unstarted", "tag_only", "failed_absent"}:
                if workspace.state_path.exists() or workspace.state_path.is_symlink():
                    raise ValueError("absence-only scope gained retained state")
                paths[provider], shown[provider] = None, None
            else:
                raise ValueError("mixed provider scope is unrecognized")
            fence()
        if all(path is None for path in paths.values()):
            recheck_source()
        terminal = {"reviewSha256": review.review_sha256, "providers": []}
        for provider in review.ordered_providers:
            path = paths[provider]
            if path is None:
                terminal["providers"].append({"provider": provider, "planPath": None,
                                              "planSha256": None,
                                              "showSha256": None})
            else:
                terminal["providers"].append({"provider": provider,
                    "planPath": str(path), "planSha256": _sha(path),
                    "showSha256": hashlib.sha256(shown[provider].encode()).hexdigest()})
        fence()
        completed = jobs.finish_if_running_claimed(
            current, owner=_OWNER, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(3, "info", "both mixed destroy plans saved", terminal))
        if completed is None:
            raise ValueError("mixed destroy-plan terminal journal lost")
        return seal_mixed_interrupted_cleanup_plans(
            engagement_id, core_job_id, plan_paths=paths, show_json=shown,
            environment=environment, state_root=state_root,
            job_repository=jobs, lease_lookup=lookup)
    except Exception as exc:
        raise MixedInterruptedPlanWorkerAttention(
            "mixed interrupted destroy planning stopped; no command may be replayed"
        ) from exc
