# Copyright (c) 2026, Oracle and/or its affiliates.
"""Locked pre-GO attestation of one published mixed exact-delete plan.

The selected plan is re-shown with the pinned Terraform executable while the
provider workspace lock is held. Only an explicit continuation can advance
to a one-shot command; this reader alone cannot issue a provider write.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import stat
from typing import Callable

from app.services.provider_keyed_initial_teardown import require_exact_digitalocean_destroy_plan
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_interrupted_destroy_source import _binary_sha, _sha
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_published_destroy_plan import (
    PublishedMixedDestroyPlan, PublishedMixedDestroyPlanSet,
)
from app.services.provider_keyed_mixed_published_teardown_authority import PublishedMixedInitialTeardownReview
from app.services.provider_keyed_mixed_published_teardown_checkpoint import recognize_published_mixed_plans_sealed
from app.services.provider_keyed_terraform_release import (
    ProviderKeyedTerraformRelease, require_devtest_terraform_release,
)
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy, published_review_states

from app.storage.job_repository import StoredJobRun, job_event_digest


class PublishedMixedDestroySourceAttention(ValueError):
    """The retained state, exact plan, binary, or source fence changed."""


def attest_published_mixed_destroy_show(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: PublishedMixedInitialTeardownReview,
    plans: PublishedMixedDestroyPlanSet, provider: str,
    before_state: bytes, core_inspector_scope: dict, engagement_name: str, *,
    fence: Callable[[], str],
    show_runner: Callable[[tuple[str, ...], Path], str],
    release_validator: Callable[[], ProviderKeyedTerraformRelease] | None = None,
    on_attested: Callable[[PublishedMixedDestroyPlan], object] | None = None,
) -> object:
    """Recheck the exact saved plan and return/continue under its file lock."""
    try:
        recognize_published_mixed_plans_sealed(
            cleanup, review, plans, core_inspector_scope, engagement_name)
        seal = validate_mixed_initial_apply_seal(initial)
        order = review.source.ordered_providers
        index = order.index(provider)
        scope, plan = review.provider_scopes[index], plans.plans[index]
        if (initial.id != review.source.parent_job_id
                or initial.status != "succeeded"
                or initial.input.get("phase") != "completed"
                or initial.target_id != review.source.engagement_id
                or job_event_digest(initial.events)
                   != review.published_parent_journal_sha256
                or tuple(seal["orderedProviders"]) != order
                or scope["provider"] != provider or plan.provider != provider
                or type(before_state) is not bytes
                or hashlib.sha256(before_state).hexdigest()
                   != plan.before_state_sha256
                or not callable(fence) or not callable(show_runner)):
            raise ValueError("published mixed selected destroy source differs")
        binary = Path(plan.terraform_path)
        release = ((release_validator or (lambda: require_devtest_terraform_release(
            environment="devtest")))())
        if (not binary.is_absolute()
                or not isinstance(release, ProviderKeyedTerraformRelease)
                or release.path != binary or release.sha256 != plan.terraform_sha256
                or release.version != "1.15.5" or release.platform != "linux_amd64"
                or _binary_sha(binary) != plan.terraform_sha256):
            raise ValueError("published mixed Terraform release differs")
        path = Path(plan.plan_path)
        workspace = Path(scope["workspace"])
        if (path.parent != workspace
                or path.name != f".barragan-mixed-published-destroy-{provider}.tfplan"
                or not workspace.is_absolute() or workspace.is_symlink()
                or workspace.resolve(strict=True) != workspace):
            raise ValueError("published mixed selected workspace differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("published mixed teardown fence absent")
        lock_path = workspace / f".barragan-{provider}-plan.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("published mixed plan lock differs")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                state_path = workspace / "terraform.tfstate"
                def unchanged() -> bool:
                    return (not lock_path.is_symlink()
                            and lock_path.stat().st_ino == info.st_ino
                            and not state_path.is_symlink()
                            and state_path.read_bytes() == before_state
                            and _sha(path) == plan.plan_sha256
                            and _binary_sha(binary) == plan.terraform_sha256
                            and fence() == generation)
                if not unchanged():
                    raise ValueError("published mixed selected plan bytes changed")
                state, actual, cloud = _state(
                    provider, published_review_policy(review, initial, provider), before_state)
                if (state["lineage"] != plan.state_lineage
                        or state["serial"] != plan.state_serial
                        or tuple(sorted(cloud.items()))
                           != published_review_states(review)[index].resource_ids
                        or tuple(sorted((address, str(attrs["id"]))
                                        for address, attrs in actual.items()))
                           != plan.resource_ids):
                    raise ValueError("published mixed selected state identity changed")
                command = (str(binary), "show", "-json", str(path))
                shown = show_runner(command, workspace)
                if (type(shown) is not str or not shown
                        or hashlib.sha256(shown.encode()).hexdigest()
                           != plan.show_json_sha256):
                    raise ValueError("published mixed selected show changed")
                require_exact_digitalocean_destroy_plan(
                    shown, expected_resource_ids=dict(plan.resource_ids), state=state)
                if not unchanged():
                    raise ValueError("published mixed selected source changed during show")
                return on_attested(plan) if on_attested is not None else plan
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise PublishedMixedDestroySourceAttention(
            "published mixed GO requires exact saved binary, plan, state and show") from None
