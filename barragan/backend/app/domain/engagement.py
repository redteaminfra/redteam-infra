# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EngagementSummary:
    id: str
    name: str
    status: str
    owner: str
    template_id: str | None
    active_revision: str | None
    sketch_state_schema: str = "split-v1"
    description: str = ""
    documentation_url: str = ""
    jira_url: str = ""
    created_at: str = ""
    updated_at: str = ""
    lifecycle: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        result = {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "owner": self.owner,
            "templateId": self.template_id,
            "activeRevision": self.active_revision,
            "sketchStateSchema": self.sketch_state_schema,
            "description": self.description,
            "documentationUrl": self.documentation_url,
            "jiraUrl": self.jira_url,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }
        if self.lifecycle is not None:
            result["lifecycle"] = self.lifecycle
        return result


@dataclass(frozen=True)
class EngagementDetail:
    id: str
    name: str
    status: str
    owner: str
    template_id: str | None
    active_revision: str | None
    input_parameters: dict[str, Any]
    sketch_state_schema: str = "split-v1"
    description: str = ""
    documentation_url: str = ""
    jira_url: str = ""
    created_at: str = ""
    updated_at: str = ""
    lifecycle: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        result = {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "owner": self.owner,
            "templateId": self.template_id,
            "activeRevision": self.active_revision,
            "inputParameters": self.input_parameters,
            "sketchStateSchema": self.sketch_state_schema,
            "description": self.description,
            "documentationUrl": self.documentation_url,
            "jiraUrl": self.jira_url,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }
        if self.lifecycle is not None:
            result["lifecycle"] = self.lifecycle
        return result
