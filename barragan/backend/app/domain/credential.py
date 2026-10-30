# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialSummary:
    id: str
    provider: str
    alias: str
    status: str
    description: str
    is_default: bool
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "id": self.id,
            "provider": self.provider,
            "alias": self.alias,
            "status": self.status,
            "description": self.description,
            "isDefault": self.is_default,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }
