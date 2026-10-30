# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bind both saved exact-delete plans for a published mixed initial teardown.

This reader executes no Terraform command. The one-action worker must save and
seal both plans before considering either one-shot destroy Apply.
"""

from __future__ import annotations

from app.services.provider_keyed_mixed_published_teardown_authority import published_review_states

from dataclasses import dataclass
import hashlib
import json
import fcntl
import os
from pathlib import Path
import stat
from typing import Callable, Mapping

from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_initial_teardown import (
    _state_resources, require_exact_digitalocean_destroy_plan,
)
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_interrupted_destroy_source import _binary_sha
from app.services.provider_keyed_mixed_interrupted_destroy_go import _real_show
from app.services.provider_keyed_terraform_release import (
    ProviderKeyedTerraformRelease, require_devtest_terraform_release,
)
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedMixedInitialTeardownReview, PublishedSixTeardownSource,
)
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy

from app.storage.job_repository import StoredJobRun, job_event_digest


class PublishedMixedDestroyPlanAttention(ValueError):
    """Both saved plans no longer prove deletion of the exact published state."""


@dataclass(frozen=True)
class PublishedMixedDestroyPlan:
    provider: str
    scope_sha256: str
    before_state_sha256: str
    state_lineage: str
    state_serial: int
    resource_ids: tuple[tuple[str, str], ...]
    plan_path: str
    plan_sha256: str
    show_json_sha256: str
    terraform_path: str
    terraform_sha256: str


@dataclass(frozen=True)
class PublishedMixedDestroyPlanSet:
    published_parent_journal_sha256: str
    ordered_providers: tuple[str, str]
    plans: tuple[PublishedMixedDestroyPlan, PublishedMixedDestroyPlan]
    plan_set_sha256: str


def bind_published_mixed_initial_destroy_plans(
    initial: StoredJobRun, review: PublishedMixedInitialTeardownReview,
    before_states: Mapping[str, bytes], plan_paths: Mapping[str, Path],
    show_json: Mapping[str, str], *, fence: Callable[[], str],
    terraform_path: Path, expected_terraform_sha256: str,
    show_runner: Callable[[tuple[str, ...], Path], str] = _real_show,
    release_validator: Callable[[], ProviderKeyedTerraformRelease] | None = None,
) -> PublishedMixedDestroyPlanSet:
    """Require both complete saved plans under an unchanged review fence."""
    try:
        source = review.source
        seal = validate_mixed_initial_apply_seal(initial)
        order = source.ordered_providers
        chain_ids_match = tuple(seal["chainIds"]) == source.chain_ids
        if type(source) is PublishedSixTeardownSource:
            # Append order follows the target edge provider, hence its foreign
            # middle chains are reversed relative to the initial native roots.
            before = source.six_node_source.before_chains
            native = {chain.middle_provider: chain.chain_id for chain in before}
            chain_ids_match = (
                len(source.chain_ids) == len(set(source.chain_ids)) == 2
                and set(source.chain_ids) == set(seal["chainIds"])
                and len(before) == len(native) == 2
                and native == dict(zip(seal["orderedProviders"], seal["chainIds"], strict=True)))
        if (type(review) is not PublishedMixedInitialTeardownReview
                or initial.id != source.parent_job_id
                or initial.status != "succeeded"
                or initial.input.get("phase") != "completed"
                or initial.target_id != source.engagement_id
                or job_event_digest(initial.events) != review.published_parent_journal_sha256
                or tuple(seal["orderedProviders"]) != order
                or not chain_ids_match
                or tuple(scope.get("provider") for scope in review.provider_scopes) != order
                or set(before_states) != set(order)
                or set(plan_paths) != set(order) or set(show_json) != set(order)):
            raise ValueError("published mixed review differs")
        generation = fence()
        if type(generation) is not str or not generation:
            raise ValueError("published mixed destroy fence is unavailable")
        release = ((release_validator or (lambda: require_devtest_terraform_release(
            environment="devtest")))())
        if (not isinstance(release, ProviderKeyedTerraformRelease)
                or release.path != terraform_path
                or release.sha256 != expected_terraform_sha256
                or release.version != "1.15.5"
                or release.platform != "linux_amd64"
                or _binary_sha(terraform_path) != expected_terraform_sha256):
            raise ValueError("published mixed Terraform release differs")
        plans = []
        for provider, scope, published in zip(
                order, review.provider_scopes, published_review_states(review), strict=True):
            raw = before_states[provider]
            path = plan_paths[provider]
            shown = show_json[provider]
            workspace = Path(scope["workspace"])
            if (type(raw) is not bytes or not isinstance(path, Path)
                    or not workspace.is_absolute() or path.parent != workspace
                    or path.name != f".barragan-mixed-published-destroy-{provider}.tfplan"
                    or path.is_symlink() or type(shown) is not str or not shown
                    or hashlib.sha256(raw).hexdigest() != published.state_sha256
                    or scope["stateSha256"] != published.state_sha256
                    or scope["lineage"] != published.lineage
                    or scope["serial"] != published.serial):
                raise ValueError("published mixed saved plan boundary differs")
            lock_path = workspace / f".barragan-{provider}-plan.lock"
            descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "r+b") as lock:
                info = os.fstat(lock.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) & 0o077):
                    raise ValueError("published mixed saved plan lock differs")
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    if (lock_path.is_symlink() or lock_path.stat().st_ino != info.st_ino
                            or workspace.joinpath("terraform.tfstate").read_bytes() != raw):
                        raise ValueError("published mixed saved plan source changed")
                    metadata = path.lstat()
                    if (not stat.S_ISREG(metadata.st_mode)
                            or not 0 < metadata.st_size <= 128 * 1024 * 1024):
                        raise ValueError("published mixed saved plan file differs")
                    binary = path.read_bytes()
                    if len(binary) != metadata.st_size:
                        raise ValueError("published mixed saved plan changed")
                    command = (str(terraform_path), "show", "-json", str(path))
                    attested = show_runner(command, workspace)
                    if (type(attested) is not str or attested != shown
                            or path.read_bytes() != binary
                            or workspace.joinpath("terraform.tfstate").read_bytes() != raw
                            or _binary_sha(terraform_path) != expected_terraform_sha256
                            or fence() != generation):
                        raise ValueError("published mixed saved plan show changed")
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            state, actual, cloud = _state(provider, published_review_policy(review, initial, provider), raw)
            ids = {address: str(value["id"]) for address, value in actual.items()}
            expected = {row["address"]: row["id"] for row in scope["resources"]}
            if (state["lineage"] != published.lineage
                    or state["serial"] != published.serial
                    or tuple(sorted(cloud.items())) != published.resource_ids
                    or set(ids) != set(_state_resources(state))
                    or ids != expected):
                raise ValueError("published mixed retained resource IDs differ")
            require_exact_digitalocean_destroy_plan(
                shown, expected_resource_ids=ids, state=state)
            plans.append(PublishedMixedDestroyPlan(
                provider, _fingerprint(scope), published.state_sha256,
                published.lineage, published.serial, tuple(sorted(ids.items())),
                str(path), hashlib.sha256(binary).hexdigest(),
                hashlib.sha256(shown.encode()).hexdigest(),
                str(terraform_path), expected_terraform_sha256,
            ))
            if fence() != generation:
                raise ValueError("published mixed destroy fence changed")
        payload = {
            "publishedParentJournalSha256": review.published_parent_journal_sha256,
            "orderedProviders": order,
            "plans": [plan.__dict__ for plan in plans],
        }
        return PublishedMixedDestroyPlanSet(
            review.published_parent_journal_sha256, order, tuple(plans),
            _fingerprint(payload))
    except Exception:
        raise PublishedMixedDestroyPlanAttention(
            "both published mixed destroy plans require exact review") from None
