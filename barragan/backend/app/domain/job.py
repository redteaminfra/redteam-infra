# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import dataclass
from typing import Any


TERMINAL_JOB_STATUSES = {"succeeded", "failed", "cancelled"}
VALID_JOB_TRANSITIONS = {
    "queued": {"running", "cancelled"},
    "running": {"succeeded", "failed", "cancelled"},
    "succeeded": set(),
    "failed": set(),
    "cancelled": set(),
}


@dataclass(frozen=True)
class JobRunSummary:
    id: str
    action: str
    status: str
    target: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "status": self.status,
            "target": self.target,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True)
class JobEvent:
    sequence: int
    level: str
    message: str
    data: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "level": self.level,
            "message": self.message,
            "data": self.data,
        }


@dataclass(frozen=True)
class JobRunDetail:
    id: str
    action: str
    status: str
    target_type: str
    target_id: str
    requested_by: str
    input: dict[str, Any]
    artifact_refs: list[str]
    events: list[JobEvent]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "status": self.status,
            "targetType": self.target_type,
            "targetId": self.target_id,
            "requestedBy": self.requested_by,
            "input": self.input,
            "artifactRefs": self.artifact_refs,
            "events": [event.to_dict() for event in self.events],
        }


def transition_job_status(current_status: str, next_status: str) -> str:
    allowed = VALID_JOB_TRANSITIONS.get(current_status)
    if allowed is None:
        raise ValueError(f"unknown current job status: {current_status}")
    if next_status not in allowed:
        raise ValueError(f"invalid job status transition: {current_status} -> {next_status}")
    return next_status
