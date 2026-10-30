# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import create_app
from app.core.config import TestConfig
from app.integrations.managed_host_images import MANAGED_HOST_IMAGE_PROFILES
from app.services.managed_host_image_continuity import (
    ManagedHostImageContinuityError,
    pinned_managed_host_image_profile,
    resolve_or_pin_managed_host_image_profile,
    resolve_or_pin_profile_for_new_managed_host,
    retained_managed_compute_image,
    retained_oci_source_image,
)
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceImageProfileConflict,
    SqlAlchemyEngagementWorkspaceRepository,
    StoredEngagementWorkspace,
)
from app.storage.database import db
from app.storage.models import EngagementModel
from app.storage.provider_resource_repository import StoredProviderResourceRecord


class _Repository:
    def __init__(self, workspace: StoredEngagementWorkspace | None):
        self.workspace = workspace

    def get(self, engagement_id: str) -> StoredEngagementWorkspace | None:
        if self.workspace is not None and self.workspace.engagement_id == engagement_id:
            return self.workspace
        return None

    def save(self, workspace: StoredEngagementWorkspace) -> StoredEngagementWorkspace:
        self.workspace = workspace
        return workspace


class _ProviderResourceRepository:
    def __init__(self, records: list[StoredProviderResourceRecord]):
        self.records = records

    def list_for_engagement(self, engagement_id: str) -> list[StoredProviderResourceRecord]:
        return [record for record in self.records if record.engagement_id == engagement_id]


def _workspace(metadata: dict[str, object] | None = None) -> StoredEngagementWorkspace:
    return StoredEngagementWorkspace(
        engagement_id="eng-1",
        slug="eng-1",
        path="/private/eng-1",
        status="prepared",
        profile_id="standard-rti",
        template_source={},
        metadata=dict(metadata or {}),
    )


def _provider_record(*, resource_type: str, status: str = "active") -> StoredProviderResourceRecord:
    provider = "oci" if resource_type == "compute_instance" else "linode"
    return StoredProviderResourceRecord(
        id=f"{provider}:{resource_type}:123",
        engagement_id="eng-1",
        engagement_name="Example",
        provider=provider,
        resource_type=resource_type,
        resource_id="123",
        name="opaque-name",
        region="us-sea",
        lifecycle_state="running",
        status=status,
        source="inspector",
        metadata={"barraganOwned": True},
        adoption_job_id="job-1",
        adopted_at="2026-09-10T00:00:00+00:00",
        updated_at="2026-09-10T00:00:00+00:00",
    )


def _persisted_workspace_repositories():
    app = create_app(TestConfig)
    return app, SqlAlchemyEngagementWorkspaceRepository(), SqlAlchemyEngagementWorkspaceRepository()


def _insert_engagement() -> None:
    db.session.add(
        EngagementModel(
            id="eng-1",
            name="Example",
            status="active",
            owner="operator",
            template_id="standard-rti",
            input_parameters={},
        )
    )
    db.session.commit()


def test_profile_pin_is_immutable_when_the_release_default_changes() -> None:
    repository = _Repository(_workspace())
    pinned_workspace, profile = resolve_or_pin_managed_host_image_profile(
        repository.workspace,
        repository=repository,
        permit_new_pin=True,
        profile=MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"],
    )

    same_workspace, same_profile = resolve_or_pin_managed_host_image_profile(
        pinned_workspace,
        repository=repository,
        permit_new_pin=True,
        profile=MANAGED_HOST_IMAGE_PROFILES["ubuntu-24.04"],
    )

    assert same_workspace.metadata["managedHostImageProfile"] == "ubuntu-22.04"
    assert profile.name == same_profile.name == "ubuntu-22.04"
    assert pinned_managed_host_image_profile("eng-1", repository=repository).linode_image == "linode/ubuntu22.04"


def test_storage_preserves_pin_from_independent_stale_workspace_save() -> None:
    app, first_repository, stale_repository = _persisted_workspace_repositories()
    with app.storage_context():
        _insert_engagement()
        first_repository.save(_workspace({"markerPath": "manifest.json"}))
        pin_writer = first_repository.get("eng-1")
        stale_writer = stale_repository.get("eng-1")
        assert pin_writer is not None and stale_writer is not None

        first_repository.save(
            StoredEngagementWorkspace(
                **{
                    **pin_writer.__dict__,
                    "metadata": {
                        **pin_writer.metadata,
                        "managedHostImageProfile": "ubuntu-22.04",
                    },
                }
            )
        )
        stale_repository.save(
            StoredEngagementWorkspace(
                **{
                    **stale_writer.__dict__,
                    "metadata": {**stale_writer.metadata, "capabilityLock": {"version": 1}},
                }
            )
        )

        stored = first_repository.get("eng-1")
        assert stored is not None
        assert stored.metadata["managedHostImageProfile"] == "ubuntu-22.04"
        assert stored.metadata["capabilityLock"] == {"version": 1}


def test_storage_rejects_conflicting_pin_from_independent_stale_writer() -> None:
    app, first_repository, conflicting_repository = _persisted_workspace_repositories()
    with app.storage_context():
        _insert_engagement()
        first_repository.save(_workspace())
        first = first_repository.get("eng-1")
        conflicting = conflicting_repository.get("eng-1")
        assert first is not None and conflicting is not None

        first_repository.save(
            StoredEngagementWorkspace(
                **{
                    **first.__dict__,
                    "metadata": {"managedHostImageProfile": "ubuntu-22.04"},
                }
            )
        )

        with pytest.raises(EngagementWorkspaceImageProfileConflict, match="immutable"):
            conflicting_repository.save(
                StoredEngagementWorkspace(
                    **{
                        **conflicting.__dict__,
                        "metadata": {"managedHostImageProfile": "ubuntu-24.04"},
                    }
                )
            )

        stored = first_repository.get("eng-1")
        assert stored is not None
        assert stored.metadata["managedHostImageProfile"] == "ubuntu-22.04"


@pytest.mark.parametrize("metadata", [{}, {"managedHostImageProfile": "ubuntu-latest"}])
def test_missing_or_unknown_engagement_pin_fails_closed(metadata: dict[str, object]) -> None:
    with pytest.raises(ManagedHostImageContinuityError):
        pinned_managed_host_image_profile("eng-1", repository=_Repository(_workspace(metadata)))


@pytest.mark.parametrize(
    "resource_type",
    [
        "compute_instance",
        "inspector_instance",
        "inspector_droplet",
        "observer_instance",
        "observer_droplet",
    ],
)
def test_first_provision_refuses_to_pin_when_active_owned_managed_host_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource_type: str,
) -> None:
    monkeypatch.setenv("BARRAGAN_TERRAFORM_STATE_ROOT", str(tmp_path / "core-state"))
    monkeypatch.setenv("BARRAGAN_SKETCH_STATE_ROOT", str(tmp_path / "sketch-state"))
    workspace_repository = _Repository(_workspace())

    with pytest.raises(ManagedHostImageContinuityError, match="retained managed infrastructure"):
        resolve_or_pin_profile_for_new_managed_host(
            "eng-1",
            repository=workspace_repository,
            provider_resource_repository=_ProviderResourceRepository(
                [_provider_record(resource_type=resource_type)]
            ),
        )

    assert "managedHostImageProfile" not in workspace_repository.workspace.metadata


def test_first_provision_fails_closed_when_provider_inventory_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _UnavailableRepository:
        def list_for_engagement(self, _engagement_id: str):
            raise RuntimeError("database unavailable")

    monkeypatch.setenv("BARRAGAN_TERRAFORM_STATE_ROOT", str(tmp_path / "core-state"))
    monkeypatch.setenv("BARRAGAN_SKETCH_STATE_ROOT", str(tmp_path / "sketch-state"))
    workspace_repository = _Repository(_workspace())

    with pytest.raises(ManagedHostImageContinuityError, match="ownership inventory is unavailable"):
        resolve_or_pin_profile_for_new_managed_host(
            "eng-1",
            repository=workspace_repository,
            provider_resource_repository=_UnavailableRepository(),
        )

    assert "managedHostImageProfile" not in workspace_repository.workspace.metadata


@pytest.mark.parametrize(
    ("provider", "resource_type", "image"),
    [
        ("linode", "linode_instance", "linode/ubuntu20.04"),
        ("digitalocean", "digitalocean_droplet", "ubuntu-20-04-x64"),
    ],
)
def test_retained_image_uses_exact_provider_state_identity(
    tmp_path: Path,
    provider: str,
    resource_type: str,
    image: str,
) -> None:
    (tmp_path / "terraform.tfstate").write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "mode": "managed",
                        "type": resource_type,
                        "instances": [{"attributes": {"image": image}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert retained_managed_compute_image(tmp_path, provider) == image


def test_digitalocean_retained_image_accepts_positive_decimal_string_id(tmp_path: Path) -> None:
    (tmp_path / "terraform.tfstate").write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "type": "digitalocean_droplet",
                        "instances": [{"attributes": {"image": "12345678"}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert retained_managed_compute_image(tmp_path, "digitalocean") == "12345678"


def test_digitalocean_retained_image_rejects_numeric_json_identity(tmp_path: Path) -> None:
    (tmp_path / "terraform.tfstate").write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "type": "digitalocean_droplet",
                        "instances": [{"attributes": {"image": 12345678}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ManagedHostImageContinuityError, match="valid image identity"):
        retained_managed_compute_image(tmp_path, "digitalocean")


def test_retained_oci_image_uses_exact_source_ocid(tmp_path: Path) -> None:
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "exact-image",
                "outputs": {},
                "resources": [
                    {
                        "mode": "managed",
                        "type": "oci_core_instance",
                        "instances": [
                            {"attributes": {"source_details": [{"source_id": "ocid1.image.oc1.iad.exact"}]}},
                            {"attributes": {"source_details": [{"source_id": "ocid1.image.oc1.iad.exact"}]}},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert retained_oci_source_image(state_path) == "ocid1.image.oc1.iad.exact"


def test_retained_oci_image_allows_structurally_valid_zero_compute_only_when_requested(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "empty-clean",
                "outputs": {},
                "resources": [],
            }
        ),
        encoding="utf-8",
    )

    assert retained_oci_source_image(state_path, allow_no_compute=True) == ""
    with pytest.raises(ManagedHostImageContinuityError, match="no managed compute image identity"):
        retained_oci_source_image(state_path)


@pytest.mark.parametrize(
    "resources",
    [
        [42],
        [{"mode": "managed", "type": "oci_core_instance", "instances": "not-a-list"}],
        [{"mode": "managed", "instances": []}],
        [{"mode": "other", "type": "oci_core_instance", "instances": []}],
        [{"mode": "data", "type": "oci_core_images", "instances": [{"attributes": "bad"}]}],
        [{"mode": "managed", "type": "oci_core_vcn", "instances": [{}]}],
    ],
)
def test_zero_compute_retry_does_not_relax_structural_state_validation(
    tmp_path: Path,
    resources: object,
) -> None:
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "malformed-empty",
                "outputs": {},
                "resources": resources,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ManagedHostImageContinuityError, match="state is invalid"):
        retained_oci_source_image(state_path, allow_no_compute=True)


@pytest.mark.parametrize(
    "override",
    [
        {"version": 3},
        {"version": True},
        {"serial": -1},
        {"serial": True},
        {"lineage": ""},
        {"lineage": None},
        {"outputs": []},
    ],
)
def test_zero_compute_retry_requires_complete_terraform_v4_metadata(
    tmp_path: Path,
    override: dict[str, object],
) -> None:
    state = {
        "version": 4,
        "serial": 1,
        "lineage": "complete-v4-state",
        "outputs": {},
        "resources": [],
    }
    state.update(override)
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ManagedHostImageContinuityError, match="state is invalid"):
        retained_oci_source_image(state_path, allow_no_compute=True)


@pytest.mark.parametrize("missing_key", ["version", "serial", "lineage", "outputs", "resources"])
def test_zero_compute_retry_rejects_missing_terraform_state_metadata(
    tmp_path: Path,
    missing_key: str,
) -> None:
    state = {
        "version": 4,
        "serial": 1,
        "lineage": "complete-v4-state",
        "outputs": {},
        "resources": [],
    }
    del state[missing_key]
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ManagedHostImageContinuityError, match="state is invalid"):
        retained_oci_source_image(state_path, allow_no_compute=True)


@pytest.mark.parametrize(
    "source_ids",
    [
        [],
        [123],
        ["ubuntu-24.04"],
        ["ocid1.image.x"],
        ["ocid1.image.oc1.iad."],
        ["ocid1.image.oc1.iad.one", "ocid1.image.oc1.iad.two"],
    ],
)
def test_retained_oci_image_rejects_missing_malformed_or_conflicting_identity(
    tmp_path: Path,
    source_ids: list[object],
) -> None:
    state_path = tmp_path / "terraform.tfstate"
    instances = [
        {"attributes": {"source_details": [{"source_id": source_id}]}}
        for source_id in source_ids
    ]
    state_path.write_text(
        json.dumps(
            {
                "version": 4,
                "serial": 1,
                "lineage": "invalid-images",
                "outputs": {},
                "resources": [
                    {"mode": "managed", "type": "oci_core_instance", "instances": instances}
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ManagedHostImageContinuityError):
        retained_oci_source_image(state_path)


@pytest.mark.parametrize(
    "state",
    [
        None,
        "not-json",
        {"resources": "invalid"},
        {"resources": []},
        {
            "resources": [
                {
                    "type": "linode_instance",
                    "instances": [{"attributes": {}}],
                }
            ]
        },
        {
            "resources": [
                {
                    "type": "linode_instance",
                    "instances": [
                        {"attributes": {"image": "linode/ubuntu20.04"}},
                        {"attributes": {"image": "linode/ubuntu24.04"}},
                    ],
                }
            ]
        },
    ],
)
def test_retained_image_rejects_missing_malformed_or_conflicting_state(
    tmp_path: Path,
    state: object,
) -> None:
    if state is not None:
        (tmp_path / "terraform.tfstate").write_text(
            state if isinstance(state, str) else json.dumps(state),
            encoding="utf-8",
        )

    with pytest.raises(ManagedHostImageContinuityError):
        retained_managed_compute_image(tmp_path, "linode")
