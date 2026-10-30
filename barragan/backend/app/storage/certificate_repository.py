# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredCertificateProfile:
    engagement_id: str
    acme_email: str = ""
    default_environment: str = "staging"
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagementId": self.engagement_id,
            "acmeEmail": self.acme_email,
            "defaultEnvironment": self.default_environment,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


@dataclass(frozen=True)
class StoredCertificateAsset:
    id: str
    engagement_id: str
    name: str
    source: str
    target_proxy_id: str
    identifiers: tuple[str, ...]
    primary_identifier: str
    status: str = "draft"
    current_version_id: str = ""
    last_job_id: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "name": self.name,
            "source": self.source,
            "targetProxyId": self.target_proxy_id,
            "identifiers": list(self.identifiers),
            "primaryIdentifier": self.primary_identifier,
            "status": self.status,
            "currentVersionId": self.current_version_id,
            "lastJobId": self.last_job_id,
            "notes": self.notes,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


@dataclass(frozen=True)
class StoredCertificateVersion:
    id: str
    certificate_id: str
    sequence: int
    status: str
    acme_environment: str = ""
    key_generation: int = 1
    issuer: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    public_metadata: dict[str, Any] | None = None
    paths: dict[str, Any] | None = None
    issued_at: str = ""
    expires_at: str = ""
    revoked_at: str = ""
    last_job_id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "certificateId": self.certificate_id,
            "sequence": self.sequence,
            "status": self.status,
            "acmeEnvironment": self.acme_environment,
            "keyGeneration": self.key_generation,
            "issuer": self.issuer,
            "serialNumber": self.serial_number,
            "fingerprintSha256": self.fingerprint_sha256,
            "publicMetadata": dict(self.public_metadata or {}),
            "paths": dict(self.paths or {}),
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "revokedAt": self.revoked_at,
            "lastJobId": self.last_job_id,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


@dataclass(frozen=True)
class StoredCertificateBinding:
    id: str
    engagement_id: str
    certificate_id: str
    service_id: str
    channel_id: str
    hostname: str
    status: str = "bound"
    validation: dict[str, Any] | None = None
    last_job_id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "certificateId": self.certificate_id,
            "serviceId": self.service_id,
            "channelId": self.channel_id,
            "hostname": self.hostname,
            "status": self.status,
            "validation": dict(self.validation or {}),
            "lastJobId": self.last_job_id,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


class CertificateRepository(Protocol):
    def get_profile(self, engagement_id: str) -> StoredCertificateProfile | None: ...
    def save_profile(self, value: StoredCertificateProfile) -> StoredCertificateProfile: ...
    def list_assets(self, engagement_id: str) -> list[StoredCertificateAsset]: ...
    def get_asset(self, engagement_id: str, certificate_id: str) -> StoredCertificateAsset | None: ...
    def save_asset(self, value: StoredCertificateAsset) -> StoredCertificateAsset: ...
    def list_versions(self, certificate_id: str) -> list[StoredCertificateVersion]: ...
    def get_version(self, version_id: str) -> StoredCertificateVersion | None: ...
    def save_version(self, value: StoredCertificateVersion) -> StoredCertificateVersion: ...
    def list_bindings(self, engagement_id: str, certificate_id: str = "") -> list[StoredCertificateBinding]: ...
    def get_binding_for_service(self, engagement_id: str, service_id: str) -> StoredCertificateBinding | None: ...
    def save_binding(self, value: StoredCertificateBinding) -> StoredCertificateBinding: ...
    def delete_binding(self, engagement_id: str, binding_id: str) -> bool: ...


class SqlAlchemyCertificateRepository:
    def get_profile(self, engagement_id: str) -> StoredCertificateProfile | None:
        from app.storage.models import EngagementCertificateProfileModel
        row = EngagementCertificateProfileModel.query.get(engagement_id)
        return _profile(row) if row else None

    def save_profile(self, value: StoredCertificateProfile) -> StoredCertificateProfile:
        from app.storage.database import db
        from app.storage.models import EngagementCertificateProfileModel
        row = EngagementCertificateProfileModel.query.get(value.engagement_id)
        if row is None:
            row = EngagementCertificateProfileModel(engagement_id=value.engagement_id)
            db.session.add(row)
        row.acme_email = value.acme_email
        row.default_environment = value.default_environment
        db.session.commit()
        return self.get_profile(value.engagement_id) or value

    def list_assets(self, engagement_id: str) -> list[StoredCertificateAsset]:
        from app.storage.models import CertificateAssetModel
        rows = CertificateAssetModel.query.filter_by(engagement_id=engagement_id).order_by(CertificateAssetModel.created_at.asc()).all()
        return [_asset(row) for row in rows]

    def get_asset(self, engagement_id: str, certificate_id: str) -> StoredCertificateAsset | None:
        from app.storage.models import CertificateAssetModel
        row = CertificateAssetModel.query.filter_by(engagement_id=engagement_id, id=certificate_id).first()
        return _asset(row) if row else None

    def save_asset(self, value: StoredCertificateAsset) -> StoredCertificateAsset:
        from app.storage.database import db
        from app.storage.models import CertificateAssetModel
        row = CertificateAssetModel.query.get(value.id)
        if row is None:
            row = CertificateAssetModel(id=value.id, engagement_id=value.engagement_id)
            db.session.add(row)
        row.name = value.name
        row.source = value.source
        row.target_proxy_id = value.target_proxy_id
        row.identifiers = list(value.identifiers)
        row.primary_identifier = value.primary_identifier
        row.status = value.status
        row.current_version_id = value.current_version_id
        row.last_job_id = value.last_job_id
        row.notes = value.notes
        db.session.commit()
        return self.get_asset(value.engagement_id, value.id) or value

    def list_versions(self, certificate_id: str) -> list[StoredCertificateVersion]:
        from app.storage.models import CertificateVersionModel
        rows = CertificateVersionModel.query.filter_by(certificate_id=certificate_id).order_by(CertificateVersionModel.sequence.asc()).all()
        return [_version(row) for row in rows]

    def get_version(self, version_id: str) -> StoredCertificateVersion | None:
        from app.storage.models import CertificateVersionModel
        row = CertificateVersionModel.query.get(version_id)
        return _version(row) if row else None

    def save_version(self, value: StoredCertificateVersion) -> StoredCertificateVersion:
        from app.storage.database import db
        from app.storage.models import CertificateVersionModel
        row = CertificateVersionModel.query.get(value.id)
        if row is None:
            row = CertificateVersionModel(id=value.id, certificate_id=value.certificate_id, sequence=value.sequence)
            db.session.add(row)
        row.status = value.status
        row.acme_environment = value.acme_environment
        row.key_generation = value.key_generation
        row.issuer = value.issuer
        row.serial_number = value.serial_number
        row.fingerprint_sha256 = value.fingerprint_sha256
        row.public_metadata = dict(value.public_metadata or {})
        row.paths = dict(value.paths or {})
        row.issued_at = value.issued_at
        row.expires_at = value.expires_at
        row.revoked_at = value.revoked_at
        row.last_job_id = value.last_job_id
        db.session.commit()
        return self.get_version(value.id) or value

    def list_bindings(self, engagement_id: str, certificate_id: str = "") -> list[StoredCertificateBinding]:
        from app.storage.models import CertificateBindingModel
        query = CertificateBindingModel.query.filter_by(engagement_id=engagement_id)
        if certificate_id:
            query = query.filter_by(certificate_id=certificate_id)
        return [_binding(row) for row in query.order_by(CertificateBindingModel.created_at.asc()).all()]

    def get_binding_for_service(self, engagement_id: str, service_id: str) -> StoredCertificateBinding | None:
        from app.storage.models import CertificateBindingModel
        row = CertificateBindingModel.query.filter_by(engagement_id=engagement_id, service_id=service_id).first()
        return _binding(row) if row else None

    def save_binding(self, value: StoredCertificateBinding) -> StoredCertificateBinding:
        from app.storage.database import db
        from app.storage.models import CertificateBindingModel
        row = CertificateBindingModel.query.filter_by(engagement_id=value.engagement_id, service_id=value.service_id).first()
        if row is None:
            row = CertificateBindingModel(id=value.id, engagement_id=value.engagement_id, service_id=value.service_id)
            db.session.add(row)
        row.certificate_id = value.certificate_id
        row.channel_id = value.channel_id
        row.hostname = value.hostname
        row.status = value.status
        row.validation = dict(value.validation or {})
        row.last_job_id = value.last_job_id
        db.session.commit()
        return _binding(row)

    def delete_binding(self, engagement_id: str, binding_id: str) -> bool:
        from app.storage.database import db
        from app.storage.models import CertificateBindingModel
        row = CertificateBindingModel.query.filter_by(engagement_id=engagement_id, id=binding_id).first()
        if row is None:
            return False
        db.session.delete(row)
        db.session.commit()
        return True


def asset_with_status(value: StoredCertificateAsset, status: str, *, current_version_id: str | None = None, last_job_id: str | None = None) -> StoredCertificateAsset:
    return replace(value, status=status, current_version_id=value.current_version_id if current_version_id is None else current_version_id, last_job_id=value.last_job_id if last_job_id is None else last_job_id)


def _profile(row) -> StoredCertificateProfile:
    return StoredCertificateProfile(row.engagement_id, row.acme_email or "", row.default_environment or "staging", row.created_at.isoformat(), row.updated_at.isoformat())


def _asset(row) -> StoredCertificateAsset:
    return StoredCertificateAsset(row.id, row.engagement_id, row.name, row.source, row.target_proxy_id, tuple(row.identifiers or []), row.primary_identifier, row.status, row.current_version_id or "", row.last_job_id or "", row.notes or "", row.created_at.isoformat(), row.updated_at.isoformat())


def _version(row) -> StoredCertificateVersion:
    return StoredCertificateVersion(row.id, row.certificate_id, row.sequence, row.status, row.acme_environment or "", row.key_generation or 1, row.issuer or "", row.serial_number or "", row.fingerprint_sha256 or "", dict(row.public_metadata or {}), dict(row.paths or {}), row.issued_at or "", row.expires_at or "", row.revoked_at or "", row.last_job_id or "", row.created_at.isoformat(), row.updated_at.isoformat())


def _binding(row) -> StoredCertificateBinding:
    return StoredCertificateBinding(row.id, row.engagement_id, row.certificate_id, row.service_id, row.channel_id or "", row.hostname, row.status, dict(row.validation or {}), row.last_job_id or "", row.created_at.isoformat(), row.updated_at.isoformat())
