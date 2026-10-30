# Copyright (c) 2026, Oracle and/or its affiliates.
"""The retained incident destroy is routed through the strict post-destroy audit."""

import hashlib
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_teardown_quiescence as service


_CORE = "job-db19aa91df17"
_CHILD = "job-provider-keyed-initial-destroy-apply-db19aa91df17"
_PARENT = "job-provider-keyed-initial-db19aa91df17"


class _Jobs:
    def __init__(self, child):
        self.rows = {
            _PARENT: SimpleNamespace(status="failed"),
            child.id: child,
        }

    def get(self, identifier):
        return self.rows.get(identifier)


def _incident_child(state_sha256):
    # The full 18-event journal is independently validated by the existing
    # post-destroy auditor; this fixture exercises only the pending selector.
    events = [JobEvent(index, "info", f"record {index}", {})
              for index in range(1, 18)]
    events.append(JobEvent(18, "info", "provider destroy apply completed; absence proof pending", {
        "stateSha256": state_sha256, "providerAbsenceProofPending": True,
    }))
    return SimpleNamespace(id=_CHILD, status="succeeded", events=events)


def test_pending_incident_selects_existing_post_destroy_auditor(tmp_path, monkeypatch):
    state = tmp_path / "terraform.tfstate"
    state.write_bytes(b'{"resources":[]}')
    digest = hashlib.sha256(state.read_bytes()).hexdigest()
    jobs = _Jobs(_incident_child(digest))
    calls = []

    def audit(core_job_id, **kwargs):
        calls.append((core_job_id, kwargs))
        assert kwargs["post_destroy_state_sha256"] == digest
        assert hashlib.sha256(state.read_bytes()).hexdigest() == digest
        return "post-destroy authority"

    monkeypatch.setattr(service, "audit_failed_prebinding_provider_bootstrap", audit)
    assert service.audit_pending_provider_keyed_bootstrap(
        _CORE, confirmed_scope={"workspace": str(tmp_path)},
        confirmed_scope_sha256="a" * 64, workspace_root=tmp_path,
        job_repository=jobs) == "post-destroy authority"
    assert len(calls) == 1 and calls[0][1]["job_repository"] is jobs


def test_second_incident_pending_selector_uses_empty_state_post_destroy_audit(
    tmp_path, monkeypatch,
):
    state = tmp_path / "terraform.tfstate"
    state.write_bytes(b'{"resources":[]}')
    digest = hashlib.sha256(state.read_bytes()).hexdigest()
    child = _incident_child(digest)
    child = SimpleNamespace(
        id="job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d",
        status=child.status, events=child.events,
    )
    jobs = _Jobs(child)
    jobs.rows["job-provider-keyed-initial-b4f1bceb4a7d"] = SimpleNamespace(status="failed")
    observed = []

    def audit(core_job_id, **kwargs):
        observed.append((core_job_id, kwargs["post_destroy_state_sha256"]))
        assert hashlib.sha256(state.read_bytes()).hexdigest() == kwargs["post_destroy_state_sha256"]
        return "second incident post-destroy authority"

    monkeypatch.setattr(service, "audit_failed_prebinding_provider_bootstrap", audit)
    assert service.audit_pending_provider_keyed_bootstrap(
        "job-b4f1bceb4a7d", confirmed_scope={"workspace": str(tmp_path)},
        confirmed_scope_sha256="a" * 64, workspace_root=tmp_path,
        job_repository=jobs) == "second incident post-destroy authority"
    assert observed == [("job-b4f1bceb4a7d", digest)]


@pytest.mark.parametrize("drift", ["partial", "running", "other_child", "bad_terminal"])
def test_pending_incident_does_not_select_post_destroy_for_other_children(
    tmp_path, monkeypatch, drift,
):
    child = _incident_child("b" * 64)
    if drift == "partial":
        child = SimpleNamespace(id=child.id, status=child.status,
                                events=child.events[:-1])
    elif drift == "running":
        child = SimpleNamespace(id=child.id, status="running", events=child.events)
    elif drift == "other_child":
        child = SimpleNamespace(id="job-provider-keyed-initial-destroy-apply-unreviewed",
                                status=child.status, events=child.events)
    else:
        events = list(child.events)
        events[-1] = JobEvent(18, "info", events[-1].message, {"stateSha256": "wrong"})
        child = SimpleNamespace(id=child.id, status=child.status, events=events)
    jobs = _Jobs(child)
    if drift == "other_child":
        # The lookup returns a row under the expected key, but its persisted
        # identity is outside both reviewed incident IDs.
        jobs.rows[_CHILD] = child
    selected = []

    def audit(_core_job_id, **kwargs):
        selected.append(kwargs["post_destroy_state_sha256"])
        if kwargs["post_destroy_state_sha256"] is None:
            raise service.ProviderKeyedTeardownQuiescenceError("pre-destroy state differs")
        pytest.fail("unproved child reached post-destroy audit")

    monkeypatch.setattr(service, "audit_failed_prebinding_provider_bootstrap", audit)
    with pytest.raises(service.ProviderKeyedTeardownQuiescenceError):
        service.audit_pending_provider_keyed_bootstrap(
            _CORE, confirmed_scope={}, confirmed_scope_sha256="a" * 64,
            workspace_root=tmp_path, job_repository=jobs)
    assert selected == ([] if drift == "bad_terminal" else [None])


def test_pending_incident_empty_state_hash_drift_is_vetoed(tmp_path, monkeypatch):
    state = tmp_path / "terraform.tfstate"
    state.write_bytes(b'{"resources":[]}')
    original = hashlib.sha256(state.read_bytes()).hexdigest()
    jobs = _Jobs(_incident_child(original))
    state.write_bytes(b'{"resources":[],"drift":true}')

    def audit(_core_job_id, **kwargs):
        assert kwargs["post_destroy_state_sha256"] == original
        if hashlib.sha256(state.read_bytes()).hexdigest() != original:
            raise service.ProviderKeyedTeardownQuiescenceError("post-destroy state differs")
        pytest.fail("state drift passed")

    monkeypatch.setattr(service, "audit_failed_prebinding_provider_bootstrap", audit)
    with pytest.raises(service.ProviderKeyedTeardownQuiescenceError):
        service.audit_pending_provider_keyed_bootstrap(
            _CORE, confirmed_scope={}, confirmed_scope_sha256="a" * 64,
            workspace_root=tmp_path, job_repository=jobs)
