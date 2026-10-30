# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, locked saved-plan show boundary for mixed interrupted teardown.

There is no Terraform runner default and no provider or Apply call here. The
optional continuation runs under this same lock after the exact show check.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Callable

from app.services.provider_keyed_initial_teardown import require_exact_digitalocean_destroy_plan
from app.services.provider_keyed_mixed_interrupted_cleanup import recognize_mixed_interrupted_sealed_plans
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    MixedInterruptedDestroyPlanSet, _scope_sha,
)
from app.services.provider_keyed_mixed_interrupted_source import MixedInterruptedReview
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_terraform_release import (
    ProviderKeyedTerraformRelease, require_devtest_terraform_release,
)
from app.storage.job_repository import StoredJobRun


class MixedInterruptedDestroySourceAttention(ValueError):
    """The saved binary, plan, state or exact show no longer proves this delete."""


@dataclass(frozen=True)
class MixedInterruptedDestroyShow:
    provider: str
    terraform_path: str
    terraform_sha256: str
    plan_path: str
    plan_sha256: str
    show_sha256: str
    before_state_sha256: str
    argv_sha256: str


def _sha(path: Path) -> str:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1
            or metadata.st_size > 128 * 1024 * 1024):
        raise ValueError("saved file is not bounded and regular")
    value = path.read_bytes()
    if len(value) != metadata.st_size:
        raise ValueError("saved file changed while reading")
    return hashlib.sha256(value).hexdigest()


def _binary_sha(path: Path) -> str:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK)):
        raise ValueError("Terraform binary is not a regular executable")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.lstat()
    if ((metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("Terraform binary changed during read")
    return digest.hexdigest()


def _reviewed_release() -> ProviderKeyedTerraformRelease:
    return require_devtest_terraform_release(environment="devtest")


def bind_mixed_interrupted_destroy_show(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    provider: str, before_state: bytes, terraform_path: Path,
    expected_terraform_sha256: str, *,
    show_runner: Callable[[tuple[str, ...], Path], str],
    fence: Callable[[], str],
    release_validator: Callable[[], ProviderKeyedTerraformRelease] = _reviewed_release,
    on_bound: Callable[[MixedInterruptedDestroyShow], object] | None = None,
) -> object:
    """Re-show the exact sealed binary plan with an injected read-only runner."""
    try:
        recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
        seal = validate_mixed_initial_apply_seal(initial)
        index = plans.ordered_providers.index(provider)
        scope, plan = review.scopes[index], plans.plans[index]
        if (scope.provider != provider or plan.provider != provider
                or scope.kind not in {"partial", "full"}
                or plan.scope_sha256 != _scope_sha(scope)
                or type(before_state) is not bytes
                or hashlib.sha256(before_state).hexdigest() != plan.before_state_sha256
                or not isinstance(terraform_path, Path) or not terraform_path.is_absolute()
                or type(expected_terraform_sha256) is not str
                or not callable(show_runner) or not callable(release_validator)):
            raise ValueError("saved destroy source differs")
        release = release_validator()
        if (not isinstance(release, ProviderKeyedTerraformRelease)
                or release.path != terraform_path
                or release.sha256 != expected_terraform_sha256
                or release.version != "1.15.5" or release.platform != "linux_amd64"):
            raise ValueError("Terraform release differs from reviewed DevTest binary")
        plan_path = Path(plan.plan_path)
        root = plan_path.parent
        if (not plan_path.is_absolute() or root.is_symlink()
                or root.resolve(strict=True) != root
                or plan_path.name != f".barragan-mixed-interrupted-destroy-{provider}.tfplan"
                or root.parent.name != provider or root.parent.parent.name != "provider-keyed-v2"
                or root.parent.parent.parent.name != initial.target_id):
            raise ValueError("saved destroy path differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("teardown fence is unavailable")
        lock_path = root / f".barragan-{provider}-plan.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("saved plan lock differs")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                if lock_path.is_symlink() or lock_path.stat().st_ino != info.st_ino:
                    raise ValueError("saved plan lock was replaced")
                state_path = root / "terraform.tfstate"
                if (state_path.is_symlink() or state_path.read_bytes() != before_state
                        or _sha(plan_path) != plan.plan_sha256
                        or _binary_sha(terraform_path) != expected_terraform_sha256):
                    raise ValueError("saved destroy bytes changed")
                state, actual, _ = _state(provider, seal["reviewedPolicy"][provider], before_state)
                if (state["lineage"] != plan.state_lineage or state["serial"] != plan.state_serial
                        or tuple(sorted((address, str(attrs["id"]))
                                        for address, attrs in actual.items())) != plan.resource_ids):
                    raise ValueError("saved destroy state identity changed")
                command = (str(terraform_path), "show", "-json", str(plan_path))
                shown = show_runner(command, root)
                if (type(shown) is not str or not shown
                        or hashlib.sha256(shown.encode()).hexdigest() != plan.show_json_sha256):
                    raise ValueError("saved destroy show differs")
                require_exact_digitalocean_destroy_plan(
                    shown, expected_resource_ids=dict(plan.resource_ids), state=state)
                if (lock_path.is_symlink() or lock_path.stat().st_ino != info.st_ino
                        or state_path.read_bytes() != before_state
                        or _sha(plan_path) != plan.plan_sha256
                        or _binary_sha(terraform_path) != expected_terraform_sha256
                        or fence() != generation):
                    raise ValueError("saved destroy source changed during show")
                bound = MixedInterruptedDestroyShow(
                    provider, str(terraform_path), expected_terraform_sha256,
                    str(plan_path), plan.plan_sha256, plan.show_json_sha256,
                    plan.before_state_sha256,
                    hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest())
                return on_bound(bound) if on_bound is not None else bound
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise MixedInterruptedDestroySourceAttention(
            "mixed destroy show requires exact saved binary, plan and state") from None
