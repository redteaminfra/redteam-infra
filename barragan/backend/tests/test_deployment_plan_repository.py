# Copyright (c) 2026, Oracle and/or its affiliates.
"""Atomic core mutation lease operation compare-and-swap."""

import pytest
from sqlalchemy import event

from app.storage.database import db
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository,
)
from app.storage.models import CoreMutationLeaseModel


_ENGAGEMENT = "eng-of02-dev"


def _lease():
    return db.session.get(CoreMutationLeaseModel, _ENGAGEMENT)


def test_expected_operation_retag_changes_same_row_without_ownership_gap(client, monkeypatch):
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.acquire(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial")
    before = _lease()
    assert before is not None
    acquired_at = before.acquired_at

    def unexpected(*_args, **_kwargs):
        pytest.fail("lease was released or reacquired during CAS retag")

    monkeypatch.setattr(repo, "release", unexpected)
    monkeypatch.setattr(repo, "acquire", unexpected)
    statements = []
    def record(_connection, _cursor, statement, _parameters, _context, _executemany):
        if "core_mutation_leases" in statement:
            statements.append(statement.lstrip().split(None, 1)[0].upper())
    event.listen(db.engine, "before_cursor_execute", record)
    try:
        repo.retag_if_operation(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial", "provider_keyed_teardown_fence")
    finally:
        event.remove(db.engine, "before_cursor_execute", record)
    assert statements == ["UPDATE"]

    after = _lease()
    assert after is not None
    assert (after.engagement_id, after.owner_id, after.operation, after.acquired_at) == (
        _ENGAGEMENT, "dpl-owned", "provider_keyed_teardown_fence", acquired_at)
    assert CoreMutationLeaseModel.query.filter_by(engagement_id=_ENGAGEMENT).count() == 1
    # A second worker holding the stale expected operation cannot retag it.
    with pytest.raises(DeploymentPlanConflictError):
        SqlAlchemyDeploymentPlanRepository().retag_if_operation(
            _ENGAGEMENT, "dpl-owned", "provider_keyed_initial", "teardown")
    assert _lease().operation == "provider_keyed_teardown_fence"


@pytest.mark.parametrize("owner, expected", [
    ("wrong-owner", "provider_keyed_initial"),
    ("dpl-owned", "wrong-operation"),
])
def test_expected_operation_retag_rejects_wrong_owner_or_operation(client, owner, expected):
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.acquire(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial")
    with pytest.raises(DeploymentPlanConflictError):
        repo.retag_if_operation(_ENGAGEMENT, owner, expected, "teardown")
    assert (_lease().owner_id, _lease().operation) == ("dpl-owned", "provider_keyed_initial")


def test_expected_operation_retag_rejects_missing_row(client):
    repo = SqlAlchemyDeploymentPlanRepository()
    assert _lease() is None
    with pytest.raises(DeploymentPlanConflictError):
        repo.retag_if_operation(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial", "teardown")
    assert _lease() is None


def test_legacy_retag_still_uses_owner_only_contract(client):
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.acquire(_ENGAGEMENT, "dpl-owned", "prepare")
    repo.retag(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial")
    assert (_lease().owner_id, _lease().operation) == ("dpl-owned", "provider_keyed_initial")


def test_expected_operation_retag_rejects_noop_cas(client):
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.acquire(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial")
    with pytest.raises(ValueError, match="new operation"):
        repo.retag_if_operation(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial", "provider_keyed_initial")
    assert (_lease().owner_id, _lease().operation) == ("dpl-owned", "provider_keyed_initial")


@pytest.mark.parametrize("field", ["", " whitespace "])
def test_expected_operation_retag_rejects_invalid_arguments_without_update(client, field):
    repo = SqlAlchemyDeploymentPlanRepository()
    repo.acquire(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial")
    with pytest.raises(ValueError):
        repo.retag_if_operation(_ENGAGEMENT, "dpl-owned", "provider_keyed_initial", field)
    assert _lease().operation == "provider_keyed_initial"
