# Copyright (c) 2026, Oracle and/or its affiliates.
"""The shared tail starts from the original exact no-Apply audit."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_post_sketch_absence import (
    audit_zero_apply_post_sketch_absence,
)
from test_provider_keyed_mixed_zero_apply_teardown_source import case, _fenced


def test_zero_apply_authority_reuses_exact_source_in_both_orders(case):
    source, args = _fenced(case)
    parent = case.jobs.get(
        f"job-provider-keyed-mixed-zero-apply-cleanup-{source.core_job_id.removeprefix('job-')}")
    authority = audit_zero_apply_post_sketch_absence(
        parent, source.engagement_id, source.core_job_id,
        environment=args["environment"], state_root=args["state_root"],
        core_state_root=args["core_state_root"],
        lease_owner=args["lease_owner"], lease_operation=args["lease_operation"],
        **{key: value for key, value in args.items() if key.endswith("_repository")
           or key == "lease_lookup"})
    assert authority.kind == "zero_apply"
    assert authority.source == source
    assert authority.core_state_sha256 == source.core_state_sha256
    assert authority.core_inventory_sha256 == source.core_inventory_sha256


def test_zero_apply_authority_rejects_parent_or_source_drift(case):
    source, args = _fenced(case)
    parent = case.jobs.get(
        f"job-provider-keyed-mixed-zero-apply-cleanup-{source.core_job_id.removeprefix('job-')}")
    options = dict(environment=args["environment"], state_root=args["state_root"],
                   core_state_root=args["core_state_root"], lease_owner=args["lease_owner"],
                   lease_operation=args["lease_operation"],
                   **{key: value for key, value in args.items()
                      if key.endswith("_repository") or key == "lease_lookup"})
    with pytest.raises(ValueError):
        audit_zero_apply_post_sketch_absence(
            replace(parent, input={**parent.input, "sourceSha256": "0" * 64}),
            source.engagement_id, source.core_job_id, **options)
    with pytest.raises(ValueError):
        audit_zero_apply_post_sketch_absence(
            parent, source.engagement_id, source.core_job_id,
            **{**options, "lease_operation": "provider_keyed_initial"})
