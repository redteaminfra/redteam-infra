# Copyright (c) 2026, Oracle and/or its affiliates.
"""Strict implementation for DevTest-only sketch provider contract capture."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import stat
import subprocess
from typing import Any, Callable, Iterator, Mapping

from app.integrations.oci_deployment_targets import BARRAGAN_TESTING_TARGET
from app.integrations.terraform_runner import LocalTerraformCommandRunner, TerraformCommandRunner
from app.services.credentials import resolve_credential_secret
from app.services.engagement_operations import get_operations_overview
from app.services.inbound_mutation_fence import acquire_inbound_mutation, release_inbound_mutation
from app.services.redteam_infra_template import redteam_infra_template_root
from app.services.sketch_component_identity import (
    SketchComponentIdentityError,
    resolve_channel_sketch_components,
)
from app.services.sketch_provider_firewall import (
    PROVIDER_FIREWALL_TARGETS, _credential_alias, _declared_key_paths, _execution_env,
    _expected_ingress_delta, _input_text, _normalize_provider,
    _preserve_retained_firewall_ownership,
    _provider_input_with_materialized_keys, _refresh_provider_firewall_templates,
    _require_live_key_paths, _selected_input_requests_key_materialization,
    _terraform_variables, provider_ingress_plan,
)
from app.services.sketch_state_workspaces import (
    materialized_sketch_key_files, retained_compute_image_for_workspace,
    validate_existing_sketch_state_workspace,
)
from app.services.template_compatibility import (
    ensure_linode_firewall_protocol_compatibility,
    ensure_sketch_firewall_port_list_compatibility,
    ensure_sketch_resource_name_suffix_compatibility,
    ensure_sketch_ssh_variable_contract_compatibility,
    ensure_sketch_udp_ingress_compatibility,
    stabilize_digitalocean_ssh_key_ownership,
)
from app.services.terraform_plan_gate import (
    FirewallIngressDelta, FirewallIngressPort, PlannedResourceChange,
    PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES, TerraformPlanGateError,
    classify_saved_plan_actions,
    require_provider_firewall_ingress_update,
)
from app.storage.credential_repository import CredentialRepository
from app.storage.engagement_repository import EngagementRepository, SqlAlchemyEngagementRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SketchChainRepository, SqlAlchemySketchChainRepository, StoredSketchChain

CANONICAL_DEVTEST_DATA_DIR = Path("/var/lib/barragan/devtest-data")
CAPTURE_SYSTEM_PATH = os.defpath
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_CAPTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
_SCENARIO_STATUSES = {
    "add": {"pending apply"},
    "no-op": {"pending validation", "validated", "validation failed"},
    "remove": {"pending validation", "validated", "validation failed"},
}
_IDENTITY_FIELDS = {"droplet_ids", "fingerprint", "id", "label", "linodes", "name", "nodebalancers", "tags"}
_EXPECTED_PROVIDER_ADDRESSES = {
    "linode": {
        "registry.terraform.io/hashicorp/local",
        "registry.terraform.io/hashicorp/random",
        "registry.terraform.io/linode/linode",
    },
    "digitalocean": {
        "registry.terraform.io/digitalocean/digitalocean",
        "registry.terraform.io/hashicorp/local",
    },
}
REQUIRED_TEMPLATE_PATHS = (
    "templates/inventory.tftpl",
    "templates/ssh-stanza.tftpl",
)
_TEMPLATEFILE_CALL = re.compile(r'\btemplatefile\s*\(\s*"([^"]+)"')
_TEMPLATEFILE_TOKEN = re.compile(r"\btemplatefile\s*\(")
_SOURCE_CLOSURE_DOMAIN = b"barragan-sketch-terraform-source-closure-v1\0"
_TESTING_DEPLOYMENT_TARGET = {
    "provider": "oci",
    "name": BARRAGAN_TESTING_TARGET.name,
    "compartmentId": BARRAGAN_TESTING_TARGET.compartment_id,
    "region": BARRAGAN_TESTING_TARGET.region,
}
_CAPTURE_SCOPE_ERROR = "capture is limited to barragan-testing engagements"
_CAPTURE_OUTPUT_INVENTORY = {
    "digitalocean": frozenset({
        "public-key", "run-ansible", "middle_public_ips", "middle_instance_ids",
        "edge_public_ips", "edge_instance_ids", "good-bye",
    }),
    "linode": frozenset({
        "root-password", "root-password-retrieval", "public-key", "run-ansible",
        "middle_public_ips", "middle_instance_ids", "edge_public_ips",
        "edge_instance_ids", "good-bye",
    }),
}
_CAPTURE_PATH_OUTPUTS = frozenset({"public-key", "run-ansible"})


class SketchProviderContractCaptureError(ValueError):
    pass


@dataclass(frozen=True)
class CaptureOutputPlanDecision:
    provider: str
    classification: str
    output_changes_sha256: str


@dataclass(frozen=True)
class CapturePlanEnvelopeDecision:
    provider: str
    scenario: str
    selected_address: str
    classification: str
    drift_changed_fields: tuple[str, ...]
    document_sha256: str
    mask_classification: str | None = None
    before_ingress_mask_entries: int | None = None
    after_ingress_mask_entries: int | None = None
    before_mask_shape_sha256: str | None = None
    after_mask_shape_sha256: str | None = None

    def semantic_identity(self) -> tuple[Any, ...]:
        return (
            self.provider, self.scenario, self.selected_address,
            self.classification, self.drift_changed_fields,
            self.mask_classification, self.before_ingress_mask_entries,
            self.after_ingress_mask_entries, self.before_mask_shape_sha256,
            self.after_mask_shape_sha256,
        )


@dataclass(frozen=True)
class CaptureSensitivityMaskProof:
    classification: str
    before_ingress_entries: int
    after_ingress_entries: int
    before_shape_sha256: str
    after_shape_sha256: str


def require_testing_deployment_target(input_parameters: Any) -> None:
    """Require exact modern testing scope or an established legacy form."""
    if not isinstance(input_parameters, Mapping):
        raise SketchProviderContractCaptureError(_CAPTURE_SCOPE_ERROR)
    if "deploymentTarget" not in input_parameters or input_parameters["deploymentTarget"] is None:
        return
    value = input_parameters["deploymentTarget"]
    if type(value) is str and value == BARRAGAN_TESTING_TARGET.name:
        return
    if not isinstance(value, Mapping):
        raise SketchProviderContractCaptureError(_CAPTURE_SCOPE_ERROR)
    if set(value) != set(_TESTING_DEPLOYMENT_TARGET):
        raise SketchProviderContractCaptureError(_CAPTURE_SCOPE_ERROR)
    if any(type(value[key]) is not str or value[key] != expected for key, expected in _TESTING_DEPLOYMENT_TARGET.items()):
        raise SketchProviderContractCaptureError(_CAPTURE_SCOPE_ERROR)


@dataclass(frozen=True)
class CaptureRequest:
    engagement_id: str
    chain_id: str
    channel_id: str
    scenario: str
    capture_id: str


@dataclass(frozen=True)
class CaptureResult:
    capture_id: str
    status: str
    manifest_sha256: str
    internal_directory: str
    providers: tuple[str, ...]
    scenario: str

    def to_dict(self) -> dict[str, Any]:
        return {"captureId": self.capture_id, "status": self.status, "hashes": {"manifestSha256": self.manifest_sha256}}


@dataclass(frozen=True)
class RoleCapture:
    role: str
    provider: str
    workspace: Path
    component_id: str | None
    provider_input: dict[str, Any]


@dataclass(frozen=True)
class CaptureSourceProvenance:
    tool_revision: str
    template_revision: str
    template_sources: tuple[tuple[str, str], ...]

    def template_sha256(self, provider: str) -> str:
        matches = [digest for name, digest in self.template_sources if name == provider]
        if len(matches) != 1:
            raise SketchProviderContractCaptureError("capture template provenance was incomplete")
        return matches[0]


@dataclass(frozen=True)
class WorkspaceManifestEntry:
    relative_path: str
    descriptor: int
    identity: tuple[int, ...]
    sha256: str
    parent_descriptor: int


@dataclass(frozen=True)
class WorkspaceDirectoryEntry:
    relative_path: str
    descriptor: int
    identity: tuple[int, ...]


class ApprovedWorkspace:
    """One descriptor-anchored approval used for clone and final verification."""

    def __init__(self, root: Path, root_descriptor: int, root_identity: tuple[int, ...], entries: tuple[WorkspaceManifestEntry, ...], directories: tuple[WorkspaceDirectoryEntry, ...]):
        self.root = root
        self.root_descriptor = root_descriptor
        self.root_identity = root_identity
        self.entries = entries
        self.directories = directories

    @property
    def sha256(self) -> str:
        return _source_closure_sha256(self.entries)

    def clone_to(self, target: Path) -> None:
        mkdir_exclusive(target)
        templates = target / "templates"
        mkdir_exclusive(templates)
        for entry in self.entries:
            _copy_manifest_entry(entry, target / PurePosixPath(entry.relative_path).parent)

    def clone_into(self, target: "AnchoredPrivateDirectory") -> None:
        with target.create_child("templates") as templates:
            for entry in self.entries:
                parent = templates if PurePosixPath(entry.relative_path).parent == PurePosixPath("templates") else target
                _copy_manifest_entry_to_directory(entry, parent)

    def verify(self) -> None:
        _verify_workspace_root(self.root, self.root_descriptor, self.root_identity)
        _audit_workspace_tree(self.root_descriptor)
        for directory in self.directories:
            _verify_manifest_directory(self.root_descriptor, directory)
        expected_names = tuple(entry.relative_path for entry in self.entries)
        templates = next(directory.descriptor for directory in self.directories if directory.relative_path == "templates")
        if _approved_relative_paths(self.root_descriptor, templates) != expected_names:
            raise SketchProviderContractCaptureError("retained workspace file set changed during capture")
        for entry in self.entries:
            _verify_manifest_entry(entry)



class DestinationAnchor:
    def __init__(self, components: tuple[tuple[Path, int, tuple[int, ...]], ...]):
        self.components = components

    @property
    def root_path(self) -> Path:
        return self.components[-1][0]

    @property
    def root_descriptor(self) -> int:
        return self.components[-1][1]

    def verify(self) -> None:
        try:
            for index, (path, descriptor, identity) in enumerate(self.components):
                if _directory_identity(os.fstat(descriptor)) != identity:
                    raise SketchProviderContractCaptureError("canonical DevTest destination descriptor changed")
                if index == 0:
                    current = path.lstat()
                else:
                    parent_descriptor = self.components[index - 1][1]
                    current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
                if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode) or _directory_identity(current) != identity:
                    raise SketchProviderContractCaptureError("canonical DevTest destination path changed")
        except OSError:
            raise SketchProviderContractCaptureError("canonical DevTest destination path changed") from None

    def close(self) -> None:
        for _path, descriptor, _identity in reversed(self.components):
            os.close(descriptor)


class AnchoredPrivateDirectory:
    def __init__(
        self,
        path: Path,
        descriptor: int,
        identity: tuple[int, ...],
        destination_anchor: DestinationAnchor,
        *,
        parent: "AnchoredPrivateDirectory | None" = None,
        owns_descriptor: bool = True,
    ):
        self.path = path
        self.descriptor = descriptor
        self.identity = identity
        self.destination_anchor = destination_anchor
        self.parent = parent
        self.owns_descriptor = owns_descriptor

    def __enter__(self) -> "AnchoredPrivateDirectory":
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.owns_descriptor:
            os.close(self.descriptor)

    def verify(self) -> None:
        try:
            self.destination_anchor.verify()
            if _directory_identity(os.fstat(self.descriptor)) != self.identity:
                raise SketchProviderContractCaptureError("private capture directory descriptor changed")
            if self.parent is not None:
                self.parent.verify()
                current = os.stat(self.path.name, dir_fd=self.parent.descriptor, follow_symlinks=False)
                if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode) or _directory_identity(current) != self.identity:
                    raise SketchProviderContractCaptureError("private capture directory path changed")
        except OSError:
            raise SketchProviderContractCaptureError("private capture directory path changed") from None

    def create_child(self, name: str) -> "AnchoredPrivateDirectory":
        return self._child(name, allow_existing=False)

    def open_or_create_private_child(self, name: str) -> "AnchoredPrivateDirectory":
        return self._child(name, allow_existing=True)

    def _child(self, name: str, *, allow_existing: bool) -> "AnchoredPrivateDirectory":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            raise SketchProviderContractCaptureError("private capture directory name was invalid")
        self.verify()
        try:
            os.mkdir(name, 0o700, dir_fd=self.descriptor)
        except FileExistsError:
            if not allow_existing:
                raise SketchProviderContractCaptureError("private path exists")
        child_descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=self.descriptor,
        )
        metadata = os.fstat(child_descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(child_descriptor)
            raise SketchProviderContractCaptureError("capture root is unsafe")
        child = AnchoredPrivateDirectory(
            self.path / name,
            child_descriptor,
            _directory_identity(metadata),
            self.destination_anchor,
            parent=self,
        )
        child.verify()
        return child

    def write_exclusive(self, name: str, value: str) -> Path:
        return self.write_exclusive_bytes(name, value.encode())

    def write_exclusive_bytes(self, name: str, value: bytes) -> Path:
        written = self.write_exclusive_bytes_held(name, value)
        try:
            written.verify()
        finally:
            written.close()
        return self.path / name

    def write_exclusive_bytes_held(self, name: str, value: bytes) -> "AnchoredWrittenFile":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            raise SketchProviderContractCaptureError("private capture filename was invalid")
        if not isinstance(value, bytes):
            raise SketchProviderContractCaptureError("private capture content was invalid")
        self.verify()
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=self.descriptor,
        )
        try:
            view = memoryview(value)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise SketchProviderContractCaptureError("private file creation failed")
            written = AnchoredWrittenFile(
                name, descriptor, _stat_identity(metadata), hashlib.sha256(value).hexdigest(), self,
            )
            written.verify()
        except BaseException:
            os.close(descriptor)
            raise
        self.verify()
        return written


@dataclass(frozen=True)
class AnchoredWrittenFile:
    name: str
    descriptor: int
    identity: tuple[int, ...]
    sha256: str
    parent: AnchoredPrivateDirectory

    def verify(self) -> None:
        self.parent.verify()
        descriptor_metadata = os.fstat(self.descriptor)
        path_metadata = os.stat(
            self.name, dir_fd=self.parent.descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
            or descriptor_metadata.st_nlink != 1
            or _stat_identity(descriptor_metadata) != self.identity
            or _stat_identity(path_metadata) != self.identity
            or _descriptor_sha256(self.descriptor) != self.sha256
        ):
            raise SketchProviderContractCaptureError("private published file changed")

    def close(self) -> None:
        os.close(self.descriptor)


@dataclass(frozen=True)
class PendingRoleCapture:
    component_name: str
    role: str
    provider: str
    contract_path: Path
    contract_sha256: str
    provenance: dict[str, Any]
    export: AnchoredPrivateDirectory
    runtime_home: AnchoredPrivateDirectory
    directories: tuple[AnchoredPrivateDirectory, ...]

    def verify(self) -> None:
        for directory in self.directories:
            directory.verify()
        require_empty_runtime_home(self.runtime_home)
        if sha256_file(self.contract_path) != self.contract_sha256:
            raise SketchProviderContractCaptureError("sanitized contract changed before publication")

def capture_sketch_provider_contract(
    request: CaptureRequest, *, data_dir: Path, environment: str,
    engagement_repository: EngagementRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
    job_repository: JobRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    credential_resolver: Callable[..., str] = resolve_credential_secret,
    terraform_runner: TerraformCommandRunner | None = None,
    overview_loader: Callable[[str], dict[str, Any] | None] = get_operations_overview,
    lease_repository: Any = None, tool_revision: str = "",
) -> CaptureResult:
    validate_request(request)
    with anchored_devtest_destination(Path(data_dir), environment) as destination:
        engagements = engagement_repository or SqlAlchemyEngagementRepository()
        chains = chain_repository or SqlAlchemySketchChainRepository()
        jobs = job_repository or SqlAlchemyJobRepository()
        engagement = engagements.get(request.engagement_id)
        if engagement is None:
            raise SketchProviderContractCaptureError("engagement was not found")
        require_testing_deployment_target(engagement.input_parameters)
        owner = f"contract-capture:{request.capture_id}"
        lease = acquire_inbound_mutation(request.engagement_id, owner, "provider_contract_capture", lease_repository)
        try:
            chain, deploy_job, overview, channel = load_capture_state(request, chains, jobs, overview_loader)
            roles = runtime_roles(
                request,
                chain,
                deploy_job,
                channel,
                list(overview.get("sketchInfrastructure") or []),
            )
            source_provenance = read_capture_source_provenance(
                {role.provider for role in roles}, expected_tool_revision=tool_revision,
            )
            with ExitStack() as source_stack:
                approvals = {
                    role.role: source_stack.enter_context(approved_workspace(role.workspace))
                    for role in roles
                }
                with private_umask(), ExitStack() as destination_stack:
                    base = destination_stack.enter_context(
                        destination.open_or_create_private_child("provider-contract-captures")
                    )
                    capture_root = destination_stack.enter_context(base.create_child(request.capture_id))
                    pending = [capture_role(
                        request, engagement.name, chain, deploy_job, overview, channel, role,
                        ordinal=index, capture_root=capture_root,
                        directory_stack=destination_stack,
                        source_approval=approvals[role.role],
                        credential_repository=credential_repository,
                        credential_resolver=credential_resolver,
                        terraform_runner=terraform_runner or LocalTerraformCommandRunner(),
                        source_provenance=source_provenance,
                    ) for index, role in enumerate(roles, 1)]
                    manifest_hash = publish_capture_evidence(
                        request,
                        roles,
                        pending,
                        approvals,
                        source_provenance,
                        capture_root,
                        expected_tool_revision=tool_revision,
                    )
                return CaptureResult(
                    request.capture_id, "captured", manifest_hash, str(capture_root.path),
                    tuple(r.provider for r in roles), request.scenario,
                )
        finally:
            release_inbound_mutation(request.engagement_id, owner, lease)


def publish_capture_evidence(
    request: CaptureRequest,
    roles: tuple[RoleCapture, ...],
    pending: list[PendingRoleCapture],
    approvals: Mapping[str, ApprovedWorkspace],
    source_provenance: CaptureSourceProvenance,
    capture_root: AnchoredPrivateDirectory,
    *,
    expected_tool_revision: str,
) -> str:
    """Publish accepted evidence only after every integrity fence passes."""
    require_capture_source_provenance(
        source_provenance,
        {role.provider for role in roles},
        expected_tool_revision=expected_tool_revision,
    )
    for role_capture in pending:
        role_capture.verify()
    capture_root.verify()
    for approval in approvals.values():
        approval.verify()

    provenance_documents = tuple(
        (
            role_capture,
            _deterministic_json_bytes(role_capture.provenance),
        )
        for role_capture in pending
    )
    components = [{
        "role": role_capture.role,
        "provider": role_capture.provider,
        "hashes": {
            "contract": role_capture.contract_sha256,
            "provenance": hashlib.sha256(provenance_bytes).hexdigest(),
        },
    } for role_capture, provenance_bytes in provenance_documents]
    manifest = {
        "captureFormat": 1,
        "captureId": request.capture_id,
        "scenario": request.scenario,
        "components": components,
        "provenance": {
            "engagement": provenance_hash(request.engagement_id),
            "chain": provenance_hash(request.chain_id),
            "channel": provenance_hash(request.channel_id),
        },
    }
    manifest_bytes = _deterministic_json_bytes(manifest)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    _atomically_publish_accepted_evidence(
        capture_root, provenance_documents, manifest_bytes,
    )
    return manifest_hash


def _deterministic_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _atomically_publish_accepted_evidence(
    capture_root: AnchoredPrivateDirectory,
    provenance_documents: tuple[tuple[PendingRoleCapture, bytes], ...],
    manifest_bytes: bytes,
) -> None:
    stage_name = "pending-accepted-evidence"
    final_name = "accepted-evidence"
    with capture_root.create_child(stage_name) as stage:
        with ExitStack() as staged_directories, ExitStack() as published_files:
            held_files: list[AnchoredWrittenFile] = []
            components = staged_directories.enter_context(stage.create_child("components"))
            for role_capture, provenance_bytes in provenance_documents:
                role_directory = staged_directories.enter_context(
                    components.create_child(role_capture.component_name)
                )
                written = role_directory.write_exclusive_bytes_held(
                    "provenance.json", provenance_bytes,
                )
                held_files.append(written)
                published_files.callback(written.close)
                os.fsync(role_directory.descriptor)
            os.fsync(components.descriptor)
            manifest_file = stage.write_exclusive_bytes_held("manifest.json", manifest_bytes)
            held_files.append(manifest_file)
            published_files.callback(manifest_file.close)
            os.fsync(stage.descriptor)
            for written in held_files:
                written.verify()
            stage.verify()
            capture_root.verify()
            os.fsync(capture_root.descriptor)
            try:
                os.stat(final_name, dir_fd=capture_root.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise SketchProviderContractCaptureError("accepted evidence destination was unavailable") from exc
            else:
                raise SketchProviderContractCaptureError("accepted evidence already exists")
            try:
                _rename_directory_noreplace(
                    capture_root.descriptor, stage_name, final_name,
                )
            except OSError as exc:
                raise SketchProviderContractCaptureError("accepted evidence publication failed") from exc


def _rename_directory_noreplace(parent_descriptor: int, source: str, destination: str) -> None:
    """Commit a staged directory with Linux renameat2 no-replace semantics."""
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as exc:
        raise SketchProviderContractCaptureError(
            "atomic no-replace publication is unavailable",
        ) from exc
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        os.fsencode(source),
        parent_descriptor,
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise SketchProviderContractCaptureError("accepted evidence already exists")
    if error in {errno.ENOSYS, errno.EINVAL}:
        raise SketchProviderContractCaptureError(
            "atomic no-replace publication is unavailable",
        )
    raise OSError(error, os.strerror(error))


def load_capture_state(request, chains, jobs, overview_loader):
    chain = chains.get(request.engagement_id, request.chain_id)
    if chain is None or chain.status != "deployed":
        raise SketchProviderContractCaptureError("capture requires a deployed retained sketch chain")
    deploy_job = jobs.get(chain.deploy_job_id) if chain.deploy_job_id else None
    if deploy_job is None:
        raise SketchProviderContractCaptureError("sketch deploy job evidence is unavailable")
    active_jobs = jobs.list_for_engagement(request.engagement_id)
    blockers = [job for job in active_jobs if not active_job_allows_capture(job)]
    if blockers:
        raise SketchProviderContractCaptureError("an engagement infrastructure or channel mutation is already running")
    overview = overview_loader(request.engagement_id) or {}
    channel = next((dict(row) for row in overview.get("inboundChannels", []) if isinstance(row, dict) and str(row.get("channelId") or "") == request.channel_id), None)
    if channel is None:
        raise SketchProviderContractCaptureError("inbound channel was not found")
    if str(channel.get("chainId") or "") != request.chain_id:
        raise SketchProviderContractCaptureError("inbound channel is not bound to the requested chain")
    status = str(channel.get("status") or "").strip().lower()
    if status not in _SCENARIO_STATUSES[request.scenario]:
        raise SketchProviderContractCaptureError(f"scenario {request.scenario} is incompatible with channel status {status or 'unknown'}")
    return chain, deploy_job, overview, channel


def runtime_roles(
    request: CaptureRequest,
    chain: StoredSketchChain,
    deploy_job: StoredJobRun,
    channel: dict[str, Any],
    sketch_rows: list[dict[str, Any]],
) -> tuple[RoleCapture, ...]:
    try:
        resolved = resolve_channel_sketch_components(
            request.engagement_id,
            chain,
            deploy_job,
            channel,
            sketch_rows,
            workspace_validator=validate_existing_sketch_state_workspace,
        )
    except (SketchComponentIdentityError, ValueError) as exc:
        raise SketchProviderContractCaptureError("channel sketch component identity was invalid") from exc
    edge = resolved.edge
    if edge.provider not in PROVIDER_FIREWALL_TARGETS:
        raise SketchProviderContractCaptureError("edge provider does not support contract capture")
    result = [RoleCapture("edge", edge.provider, edge.workspace, edge.component_id, edge.provider_input)]
    if resolved.middle.provider != edge.provider or resolved.middle.workspace != edge.workspace:
        middle = resolved.middle
        if middle.provider not in PROVIDER_FIREWALL_TARGETS:
            raise SketchProviderContractCaptureError("middle provider does not support contract capture")
        result.append(RoleCapture("middle", middle.provider, middle.workspace, middle.component_id, middle.provider_input))
    return tuple(result)


def capture_role(
    request, engagement_name, chain, deploy_job, overview, channel, role, *, ordinal,
    capture_root, directory_stack, source_approval, credential_repository, credential_resolver,
    terraform_runner, source_provenance,
):
    component = directory_stack.enter_context(
        capture_root.create_child(f"{ordinal:02d}-{role.role}-{role.provider}")
    )
    clone_directory = directory_stack.enter_context(component.create_child("workspace"))
    source_approval.clone_into(clone_directory)
    raw = directory_stack.enter_context(component.create_child("raw"))
    export = directory_stack.enter_context(component.create_child("export"))
    tf_data = directory_stack.enter_context(component.create_child("terraform-data"))
    runtime_home = directory_stack.enter_context(component.create_child("runtime-home"))
    clone = clone_directory.path
    retained_source = source_approval.sha256
    operation = "remove" if request.scenario == "remove" else "apply"
    desired = provider_ingress_plan(overview, request.chain_id, operation=operation, channel=channel, port_field="relayPort" if role.role == "middle" else "externalPort")
    return _capture_role_contract(
        request, engagement_name, chain, deploy_job, channel, role,
        clone=clone, raw=raw, export=export, tf_data=tf_data,
        retained_source=retained_source, desired=desired,
        credential_repository=credential_repository,
        credential_resolver=credential_resolver,
        terraform_runner=terraform_runner, source_provenance=source_provenance,
        runtime_home=runtime_home,
        capture_directories=(component, clone_directory, raw, export, tf_data, runtime_home),
    )


def _capture_role_contract(
    request, engagement_name, chain, deploy_job, channel, role, *, clone,
    raw, export, tf_data, retained_source, desired, credential_repository,
    credential_resolver, terraform_runner, source_provenance, runtime_home,
    capture_directories,
):
    with ExitStack() as stack:
        if not _selected_input_requests_key_materialization(deploy_job, role.provider_input):
            raise SketchProviderContractCaptureError("capture requires retained key materialization")
        keys = stack.enter_context(materialized_sketch_key_files(request.engagement_id))
        effective_input = _provider_input_with_materialized_keys(role.provider_input, keys)
        adapt_clone(clone, role.provider)
        retained_image = retained_compute_image_for_workspace(request.engagement_id, request.chain_id, role.provider, role.workspace, component_id=role.component_id)
        variables = _terraform_variables(role.provider, engagement_name, chain, effective_input, desired, clone, retained_image=retained_image, ownership_tags=_preserve_retained_firewall_ownership(clone, role.provider))
        key_paths = _declared_key_paths(variables)
        _require_live_key_paths(key_paths)
        alias = _credential_alias(role.provider, effective_input)
        env = _execution_env(role.provider, alias, credential_repository, credential_resolver)
        env["PATH"] = CAPTURE_SYSTEM_PATH
        env["HOME"] = str(runtime_home.path)
        env["TF_DATA_DIR"] = str(tf_data.path)
        env["TF_IN_AUTOMATION"] = "1"
        env["CHECKPOINT_DISABLE"] = "1"
        runner = PlanOnlyRunner(
            terraform_runner,
            runtime_home_path=runtime_home.path,
            runtime_home_identity=runtime_home.identity,
        )
        version, _ = run_terraform_attempt(
            runner, "version", raw, runtime_home,
            working_directory=str(clone), env=env, inherit_environment=False,
        )
        require_success(version.returncode, "terraform version")
        tf_version = validate_terraform_version(version.stdout, role.provider)
        init, _ = run_terraform_attempt(
            runner, "init", raw, runtime_home,
            working_directory=str(clone), env=env, readonly_lock=True,
            backend=False, inherit_environment=False,
        )
        require_success(init.returncode, "terraform init")
        plan_path = raw.path / "provider-firewall.tfplan"
        plan, _ = run_terraform_attempt(
            runner, "plan", raw, runtime_home,
            working_directory=str(clone), env=env, variables=variables,
            saved_plan_path=plan_path, inherit_environment=False,
        )
        if plan.returncode not in {0, 2}: raise SketchProviderContractCaptureError("terraform plan failed")
        raw.verify()
        require_private_regular_file(plan_path)
        show, raw_show = run_terraform_attempt(
            runner, "show", raw, runtime_home,
            working_directory=str(clone), env=env,
            saved_plan_path=plan_path, inherit_environment=False,
        )
        require_success(show.returncode, "terraform show")
        try:
            document = json.loads(show.stdout)
        except json.JSONDecodeError as exc:
            raise SketchProviderContractCaptureError("Terraform contract output was not JSON") from exc
        delta = _expected_ingress_delta(show.stdout, role.provider, desired)
        raw_changes = require_provider_firewall_ingress_update(show.stdout, provider=role.provider, expected_delta=delta)
        output_decision = classify_capture_output_changes(
            document, role.provider, clone / "output.tf", clone / "terraform.tfstate",
            materialized_public_key_path=keys.administration_public_key_path,
            expected_ssh_config_path=str(
                runtime_home.path / ".ssh" / f"{variables['engagement_name']}-sketch"
            ),
        )
        envelope_decision = classify_capture_plan_envelope(
            document, role.provider, plan.returncode, request.scenario,
            output_decision=output_decision,
        )
        envelope_classification = envelope_decision.classification
        noop_classification = envelope_classification if request.scenario == "no-op" else None
        require_scenario_fidelity(
            request.scenario, role.role, channel, plan.returncode, delta, raw_changes,
            noop_classification=noop_classification,
        )
        sanitized = export_firewall_contract(document, role.provider)
        sanitized_text = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
        clean_changes = require_provider_firewall_ingress_update(sanitized_text, provider=role.provider, expected_delta=delta)
        if raw_changes != clean_changes: raise SketchProviderContractCaptureError("export changed approved Terraform actions")
        sanitized_output_decision = require_sanitized_capture_output_classification(
            document, sanitized, output_decision,
        )
        sanitized_envelope_decision = classify_capture_plan_envelope(
            sanitized, role.provider, plan.returncode, request.scenario,
            output_decision=sanitized_output_decision,
        )
        if sanitized_envelope_decision.semantic_identity() != envelope_decision.semantic_identity():
            raise SketchProviderContractCaptureError("export changed Terraform plan envelope classification")
        if canonical_firewall_semantics(document, role.provider, redact=True) != canonical_firewall_semantics(sanitized, role.provider, redact=False):
            raise SketchProviderContractCaptureError("export changed canonical firewall semantics")
        contract_bytes = (sanitized_text + "\n").encode("utf-8")
        export_path = export.write_exclusive_bytes("terraform-show.sanitized.json", contract_bytes)
        contract_sha256 = hashlib.sha256(contract_bytes).hexdigest()
        state, lock = clone / "terraform.tfstate", clone / ".terraform.lock.hcl"
        schemas = firewall_schema_versions(state, role.provider)
        require_capture_source_provenance(
            source_provenance, {role.provider},
            expected_tool_revision=source_provenance.tool_revision,
        )
        provenance = {
            "role": role.role, "provider": role.provider, "scenario": request.scenario,
            "terraform": tf_version, "lockSha256": sha256_file(lock), "stateSha256": sha256_file(state),
            "retainedSourceSha256": retained_source, "retainedTemplateRevision": None,
            "currentTemplateRevision": source_provenance.template_revision,
            "currentTemplateSha256": source_provenance.template_sha256(role.provider),
            "effectiveAdaptedSourceSha256": terraform_source_digest(clone),
            "savedPlanSha256": sha256_file(plan_path), "rawShowSha256": sha256_file(raw_show),
            "exportSha256": contract_sha256, "planFormatVersion": str(document.get("format_version") or ""),
            "resourceSchemas": schemas, "planResourceSchemas": plan_firewall_schema_versions(document, role.provider),
            "toolRevision": source_provenance.tool_revision,
            "planExitCode": plan.returncode, "gateResult": "accepted",
            "outputPlanClassification": output_decision.classification,
            "planEnvelopeDecision": _plan_envelope_provenance(envelope_decision),
            **({"noOpPlanClassification": noop_classification} if noop_classification else {}),
            **({"refreshDriftClassification": envelope_classification} if request.scenario != "no-op" else {}),
            "approvedChanges": [vars(change) for change in raw_changes],
        }
        raw.verify()
        export.verify()
        tf_data.verify()
        return PendingRoleCapture(
            capture_directories[0].path.name,
            role.role, role.provider, export_path, contract_sha256, provenance,
            export, runtime_home, tuple(capture_directories),
        )


def require_runtime_home_path(
    home: Path, workspace: Path, expected_identity: tuple[int, ...],
) -> None:
    supplied = home.absolute()
    try:
        canonical = supplied.resolve(strict=True)
        metadata = supplied.lstat()
        descriptor = os.open(
            supplied,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise SketchProviderContractCaptureError("plan-only runtime home was invalid") from exc
    try:
        descriptor_metadata = os.fstat(descriptor)
        if (
            home != supplied
            or canonical != supplied
            or home.name != "runtime-home"
            or home.parent != workspace.parent
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _directory_identity(metadata) != expected_identity
            or _directory_identity(descriptor_metadata) != expected_identity
            or os.listdir(descriptor)
        ):
            raise SketchProviderContractCaptureError("plan-only runtime home was invalid")
    finally:
        os.close(descriptor)


def require_empty_runtime_home(runtime_home: AnchoredPrivateDirectory) -> None:
    runtime_home.verify()
    if os.listdir(runtime_home.descriptor):
        raise SketchProviderContractCaptureError("plan-only runtime home was not empty")


def run_terraform_attempt(
    runner: "PlanOnlyRunner", command: str, raw: AnchoredPrivateDirectory,
    runtime_home: AnchoredPrivateDirectory, **kwargs: Any,
) -> tuple[Any, Path]:
    try:
        result = runner.run(command, **kwargs)
    except BaseException:
        require_empty_runtime_home(runtime_home)
        raise
    evidence_path = record_command_attempt(raw, command, result)
    require_empty_runtime_home(runtime_home)
    return result, evidence_path


class PlanOnlyRunner:
    ALLOWED = frozenset({"init", "version", "plan", "show"})
    COMMON_OPTIONS = frozenset({"working_directory", "env", "inherit_environment"})
    COMMAND_OPTIONS = {
        "init": COMMON_OPTIONS | {"readonly_lock", "backend"},
        "version": COMMON_OPTIONS,
        "plan": COMMON_OPTIONS | {"variables", "saved_plan_path", "refresh", "targets"},
        "show": COMMON_OPTIONS | {"saved_plan_path"},
    }
    def __init__(self, runner, *, runtime_home_path=None, runtime_home_identity=None):
        self.runner = runner
        self.runtime_home_path = runtime_home_path
        self.runtime_home_identity = runtime_home_identity
    def run(self, command, **kwargs):
        if command not in self.ALLOWED: raise SketchProviderContractCaptureError("Terraform command is not allowed by plan-only capture")
        if set(kwargs) - self.COMMAND_OPTIONS[command]:
            raise SketchProviderContractCaptureError("Terraform command received unsupported plan-only options")
        if not isinstance(kwargs.get("working_directory"), str) or not isinstance(kwargs.get("env"), dict):
            raise SketchProviderContractCaptureError("Terraform command requires an explicit workspace and environment")
        if kwargs.get("inherit_environment") is not False:
            raise SketchProviderContractCaptureError("plan-only Terraform requires an isolated environment")
        allowed_environment = {
            "TF_VAR_linode_api_token", "TF_VAR_do_pat", "TF_DATA_DIR",
            "TF_IN_AUTOMATION", "CHECKPOINT_DISABLE", "PATH", "HOME",
        }
        if set(kwargs["env"]) - allowed_environment:
            raise SketchProviderContractCaptureError("plan-only Terraform environment was not allowlisted")
        workspace = Path(kwargs["working_directory"])
        tf_data = Path(str(kwargs["env"].get("TF_DATA_DIR") or ""))
        home_value = kwargs["env"].get("HOME")
        if (
            kwargs["env"].get("TF_IN_AUTOMATION") != "1"
            or kwargs["env"].get("CHECKPOINT_DISABLE") != "1"
            or type(kwargs["env"].get("PATH")) is not str
            or kwargs["env"].get("PATH") != CAPTURE_SYSTEM_PATH
            or type(home_value) is not str
            or self.runtime_home_path is None
            or self.runtime_home_identity is None
            or home_value != str(self.runtime_home_path)
            or not tf_data.is_absolute()
            or tf_data.name != "terraform-data"
            or tf_data.parent != workspace.parent
        ):
            raise SketchProviderContractCaptureError("plan-only Terraform environment was invalid")
        require_runtime_home_path(
            Path(home_value), workspace, self.runtime_home_identity,
        )
        variables = kwargs.get("variables")
        targets = tuple(kwargs.get("targets") or ())
        refresh = kwargs.get("refresh", True)
        saved_plan = kwargs.get("saved_plan_path")
        readonly = kwargs.get("readonly_lock", False)
        backend = kwargs.get("backend", True)
        if command == "init" and (variables or targets or refresh is not True or saved_plan is not None or readonly is not True or backend is not False):
            raise SketchProviderContractCaptureError("plan-only init requires backend=false and readonly lock with no planning options")
        if command == "version" and (variables or targets or refresh is not True or saved_plan is not None or readonly or backend is not True):
            raise SketchProviderContractCaptureError("plan-only version does not accept options")
        if command == "plan" and (targets or refresh is not True or saved_plan is None or readonly or backend is not True):
            raise SketchProviderContractCaptureError("plan-only plan requires refresh, a saved path, and no targets")
        if command == "show" and (variables or targets or refresh is not True or saved_plan is None or readonly or backend is not True):
            raise SketchProviderContractCaptureError("plan-only show requires only a saved path")
        return self.runner.run(command, **kwargs)


READ_ONLY_ACTIVE_JOB_ACTIONS = frozenset({
    "inbound_channel_apply_preview",
    "inbound_channel_validation",
    "outbound_channel_apply_preview",
    "outbound_channel_validation",
})


def active_job_allows_capture(job: StoredJobRun) -> bool:
    if job.status in {"succeeded", "failed"}:
        return True
    if job.status not in {"queued", "running"}:
        return False
    return (
        job.action in READ_ONLY_ACTIVE_JOB_ACTIONS
        and isinstance(job.input, dict)
        and job.input.get("mutation") is False
    )


def validate_terraform_version(raw, provider):
    try: document = json.loads(raw)
    except json.JSONDecodeError as exc: raise SketchProviderContractCaptureError("terraform version was not JSON") from exc
    allowed = {"terraform_version", "platform", "provider_selections", "terraform_outdated"}
    if not isinstance(document, dict) or set(document) - allowed:
        raise SketchProviderContractCaptureError("terraform version used an unsupported schema")
    if set(document) < {"terraform_version", "platform", "provider_selections"}:
        raise SketchProviderContractCaptureError("terraform version omitted required fields")
    version = document["terraform_version"]
    platform = document["platform"]
    selections = document["provider_selections"]
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise SketchProviderContractCaptureError("terraform runtime version was invalid")
    if platform != "linux_amd64":
        raise SketchProviderContractCaptureError("terraform runtime platform was unsupported")
    if not isinstance(selections, dict) or set(selections) != _EXPECTED_PROVIDER_ADDRESSES[provider]:
        raise SketchProviderContractCaptureError("terraform provider selections were unsupported")
    if any(not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", value) for value in selections.values()):
        raise SketchProviderContractCaptureError("terraform provider selection version was invalid")
    if "terraform_outdated" in document and not isinstance(document["terraform_outdated"], bool):
        raise SketchProviderContractCaptureError("terraform outdated flag was invalid")
    return {
        "terraform_version": version,
        "platform": platform,
        "provider_selections": {key: selections[key] for key in sorted(selections)},
        **({"terraform_outdated": document["terraform_outdated"]} if "terraform_outdated" in document else {}),
    }



def find_resources(container, address):
    if not isinstance(container, dict): return []
    root = container.get("root_module")
    modules = [root] if isinstance(root, dict) else []
    result = []
    while modules:
        module = modules.pop()
        resources = module.get("resources", [])
        if isinstance(resources, list): result.extend(r for r in resources if isinstance(r, dict) and r.get("address") == address)
        children = module.get("child_modules", [])
        if isinstance(children, list): modules.extend(r for r in children if isinstance(r, dict))
    return result


def classify_capture_output_changes(
    document: Any,
    provider: str,
    output_source: Path,
    retained_state: Path,
    *,
    materialized_public_key_path: str,
    expected_ssh_config_path: str,
) -> CaptureOutputPlanDecision:
    """Prove the two output updates caused by capture key materialization."""
    if provider not in _CAPTURE_OUTPUT_INVENTORY or not isinstance(document, dict):
        raise SketchProviderContractCaptureError("capture output contract was invalid")
    _require_pinned_output_source(output_source, provider)
    try:
        state = json.loads(retained_state.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SketchProviderContractCaptureError("retained output state was unavailable") from exc
    state_outputs = state.get("outputs") if isinstance(state, dict) else None
    expected_names = _CAPTURE_OUTPUT_INVENTORY[provider]
    if not isinstance(state_outputs, dict) or set(state_outputs) != expected_names:
        raise SketchProviderContractCaptureError("retained output inventory did not match the pinned source")
    changes = document.get("output_changes")
    if not isinstance(changes, dict) or set(changes) != expected_names:
        raise SketchProviderContractCaptureError("Terraform output change inventory did not match the pinned source")
    if type(materialized_public_key_path) is not str or not Path(materialized_public_key_path).is_absolute() \
            or type(expected_ssh_config_path) is not str or not Path(expected_ssh_config_path).is_absolute():
        raise SketchProviderContractCaptureError("capture output path evidence was invalid")
    expected_run_ansible = (
        "Run ansible to configure hosts with:\n\tansible-playbook ../ansible/sketch-playbook.yml "
        f'-i inventory.ini -e "ssh_pub_key={materialized_public_key_path}" '
        f'-e "ssh_config_path={expected_ssh_config_path}"'
    )
    for name in sorted(expected_names):
        retained = state_outputs[name]
        change = changes[name]
        if not isinstance(retained, dict) or set(retained) not in (
            {"value", "type"}, {"value", "type", "sensitive"},
        ) \
                or not _valid_retained_output_type(name, retained):
            raise SketchProviderContractCaptureError("retained output state shape was invalid")
        if not isinstance(change, dict) or set(change) != {
            "actions", "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
        }:
            raise SketchProviderContractCaptureError("Terraform output change shape was invalid")
        try:
            action = classify_saved_plan_actions(change["actions"])
        except TerraformPlanGateError as exc:
            raise SketchProviderContractCaptureError("Terraform output action was invalid") from exc
        expected_action = "update" if name in _CAPTURE_PATH_OUTPUTS else "no-op"
        if action != expected_action or not _exact_json_equal(change["before"], retained["value"]):
            raise SketchProviderContractCaptureError("Terraform output change did not match retained state")
        expected_after = (
            materialized_public_key_path if name == "public-key"
            else expected_run_ansible if name == "run-ansible"
            else retained["value"]
        )
        retained_sensitive = retained.get("sensitive", False)
        if not _exact_json_equal(change["after"], expected_after) \
                or change["before_sensitive"] is not retained_sensitive \
                or change["after_sensitive"] is not retained_sensitive \
                or change["after_unknown"] is not False:
            raise SketchProviderContractCaptureError("Terraform output change was not capture-induced")
        if name in _CAPTURE_PATH_OUTPUTS and (
            not isinstance(change["before"], str) or not isinstance(change["after"], str)
        ):
            raise SketchProviderContractCaptureError("Terraform capture path output type was invalid")
    return CaptureOutputPlanDecision(
        provider,
        "materialized-key-path-refresh",
        _output_changes_sha256(changes),
    )


def _output_changes_sha256(output_changes: Any) -> str:
    try:
        encoded = json.dumps(
            output_changes, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SketchProviderContractCaptureError("Terraform output changes were not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _valid_retained_output_type(name: str, retained: dict[str, Any]) -> bool:
    expected_sensitive = name == "root-password"
    if retained.get("sensitive", False) is not expected_sensitive:
        return False
    value, output_type = retained.get("value"), retained.get("type")
    if name in {
        "root-password", "root-password-retrieval", "public-key", "run-ansible", "good-bye",
    }:
        return type(value) is str and output_type == "string"
    return (
        isinstance(value, list)
        and isinstance(output_type, list)
        and len(output_type) == 2
        and output_type[0] == "tuple"
        and isinstance(output_type[1], list)
        and len(output_type[1]) == len(value)
        and all(type(item) is str for item in value)
        and all(item_type == "string" for item_type in output_type[1])
    )


def _require_pinned_output_source(path: Path, provider: str) -> None:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SketchProviderContractCaptureError("pinned Terraform output source was unavailable") from exc
    names = re.findall(r'(?m)^output\s+"([^"]+)"\s*\{', source)
    if len(names) != len(set(names)) or set(names) != _CAPTURE_OUTPUT_INVENTORY[provider]:
        raise SketchProviderContractCaptureError("pinned Terraform output inventory changed")
    public_block = _terraform_output_block(source, "public-key")
    run_block = _terraform_output_block(source, "run-ansible")
    if not re.search(r"(?m)^\s*value\s*=\s*local\.ssh_pub_key_path\s*$", public_block):
        raise SketchProviderContractCaptureError("pinned public-key output derivation changed")
    expected_run_line = (
        'value      = "Run ansible to configure hosts with:\\n\\tansible-playbook '
        '../ansible/sketch-playbook.yml -i inventory.ini -e \\"ssh_pub_key=${local.ssh_pub_key_path}\\" '
        '-e \\"ssh_config_path=${local.abs_ssh_config_path}\\""'
    )
    if expected_run_line not in run_block:
        raise SketchProviderContractCaptureError("pinned run-ansible output derivation changed")


def _terraform_output_block(source: str, name: str) -> str:
    marker = f'output "{name}" {{'
    start = source.find(marker)
    if start < 0:
        raise SketchProviderContractCaptureError("pinned Terraform output was missing")
    end = source.find("\n}", start)
    if end < 0:
        raise SketchProviderContractCaptureError("pinned Terraform output was malformed")
    return source[start:end + 2]


def require_sanitized_capture_output_classification(
    raw: dict[str, Any], sanitized: dict[str, Any], decision: CaptureOutputPlanDecision,
) -> CaptureOutputPlanDecision:
    if not isinstance(decision, CaptureOutputPlanDecision) \
            or decision.classification != "materialized-key-path-refresh" \
            or decision.provider not in _CAPTURE_OUTPUT_INVENTORY:
        raise SketchProviderContractCaptureError("capture output classification was invalid")
    raw_outputs, clean_outputs = raw.get("output_changes"), sanitized.get("output_changes")
    if not isinstance(raw_outputs, dict) or not isinstance(clean_outputs, dict) \
            or len(raw_outputs) != len(clean_outputs):
        raise SketchProviderContractCaptureError("export changed Terraform output structure")
    if decision.output_changes_sha256 != _output_changes_sha256(raw_outputs):
        raise SketchProviderContractCaptureError("capture output classification did not match its document")
    for (raw_name, before), (clean_name, after) in zip(
        raw_outputs.items(), clean_outputs.items(), strict=True,
    ):
        if raw_name == clean_name or not re.fullmatch(r"output_\d{3}", clean_name):
            raise SketchProviderContractCaptureError("export did not pseudonymize Terraform output identity")
        if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after) \
                or before["actions"] != after["actions"] \
                or before["before_sensitive"] is not after["before_sensitive"] \
                or before["after_sensitive"] is not after["after_sensitive"] \
                or before["after_unknown"] is not after["after_unknown"] \
                or _json_type_shape(before["before"]) != _json_type_shape(after["before"]) \
                or _json_type_shape(before["after"]) != _json_type_shape(after["after"]):
            raise SketchProviderContractCaptureError("export changed Terraform output classification")
    return CaptureOutputPlanDecision(
        decision.provider,
        decision.classification,
        _output_changes_sha256(clean_outputs),
    )


def _json_type_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return ("dict", tuple(sorted(_json_type_shape(item) for item in value.values())))
    if isinstance(value, list):
        return ("list", tuple(_json_type_shape(item) for item in value))
    if value is None: return ("null",)
    if isinstance(value, bool): return ("bool", value)
    return (type(value).__name__,)


def classify_capture_noop_plan(
    document: Any, provider: str, exit_code: int,
    *, output_decision: CaptureOutputPlanDecision | None = None,
) -> CapturePlanEnvelopeDecision:
    """Classify a no-op capture without broadening the runtime apply gate.

    Terraform detailed exit code 2 can describe refresh-only drift in provider
    computed firewall fields even when the configuration has no actionable
    changes.  Accept only that exact representation.
    """
    return classify_capture_plan_envelope(
        document, provider, exit_code, "no-op", output_decision=output_decision,
    )


def classify_capture_plan_envelope(
    document: Any,
    provider: str,
    exit_code: int,
    scenario: str,
    *,
    output_decision: CaptureOutputPlanDecision | None = None,
) -> CapturePlanEnvelopeDecision:
    if provider not in PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES or not isinstance(document, dict) \
            or scenario not in {"add", "no-op", "remove"}:
        raise SketchProviderContractCaptureError("no-op Terraform plan was invalid")
    resources = document.get("resource_changes")
    if not isinstance(resources, list):
        raise SketchProviderContractCaptureError("no-op Terraform plan omitted resource changes")
    selected_update: dict[str, Any] | None = None
    mask_proof: CaptureSensitivityMaskProof | None = None
    resource_addresses: set[str] = set()
    try:
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(resource.get("change"), dict):
                raise SketchProviderContractCaptureError("no-op Terraform resource change was invalid")
            if "generated_config" in resource:
                raise SketchProviderContractCaptureError("Terraform plan contained generated configuration")
            address = resource.get("address")
            if not isinstance(address, str) or address in resource_addresses:
                raise SketchProviderContractCaptureError("Terraform plan contained duplicate resource identity")
            resource_addresses.add(address)
            action = classify_saved_plan_actions(resource["change"].get("actions"))
            if action == "no-op":
                _require_exact_noop_resource(resource, provider)
                continue
            if scenario == "no-op" or action != "update" \
                    or resource.get("address") != PROVIDER_FIREWALL_TARGETS[provider][0] \
                    or selected_update is not None:
                raise SketchProviderContractCaptureError("Terraform plan contained an unapproved resource change")
            mask_proof = _require_exact_firewall_update(resource, provider)
            selected_update = resource
    except TerraformPlanGateError as exc:
        raise SketchProviderContractCaptureError("no-op Terraform resource action was invalid") from exc
    if (scenario == "no-op") != (selected_update is None):
        raise SketchProviderContractCaptureError("Terraform plan omitted its exact approved firewall update")
    if scenario != "no-op" and exit_code != 2:
        raise SketchProviderContractCaptureError("Terraform mutation plan did not report changes")
    outputs = document.get("output_changes", {})
    if not isinstance(outputs, dict):
        raise SketchProviderContractCaptureError("no-op Terraform plan contained output changes")
    has_output_refresh = bool(outputs)
    if has_output_refresh:
        if not isinstance(output_decision, CaptureOutputPlanDecision) \
                or output_decision.provider != provider \
                or output_decision.classification != "materialized-key-path-refresh" \
                or output_decision.output_changes_sha256 != _output_changes_sha256(outputs):
            raise SketchProviderContractCaptureError("no-op Terraform output classification was invalid")
    elif output_decision is not None:
        raise SketchProviderContractCaptureError("no-op Terraform output classification was unexpected")
    deferred = document.get("deferred_changes", [])
    if not isinstance(deferred, list) or deferred:
        raise SketchProviderContractCaptureError("no-op Terraform plan contained deferred changes")
    drift = document.get("resource_drift", [])
    if not isinstance(drift, list):
        raise SketchProviderContractCaptureError("no-op Terraform drift evidence was invalid")
    planned = find_resources(document.get("planned_values"), PROVIDER_FIREWALL_TARGETS[provider][0])
    if len(planned) != 1:
        raise SketchProviderContractCaptureError("Terraform plan omitted its selected firewall projection")
    _require_planned_firewall_projection(planned[0], provider)
    baseline = planned[0]
    if selected_update is not None:
        baseline = {
            **planned[0],
            "values": selected_update["change"]["before"],
            "sensitive_values": selected_update["change"]["before_sensitive"],
        }
    if scenario != "no-op":
        if not drift:
            return _capture_plan_envelope_decision(
                document, provider, scenario, "no-refresh-drift", (), mask_proof,
            )
        if len(drift) != 1:
            raise SketchProviderContractCaptureError("Terraform mutation plan contained unrelated or duplicate drift")
        changed_fields = _require_computed_firewall_drift(drift[0], baseline, provider)
        return _capture_plan_envelope_decision(
            document, provider, scenario, "computed-firewall-drift", changed_fields,
            mask_proof,
        )
    if exit_code == 0:
        if drift or has_output_refresh:
            raise SketchProviderContractCaptureError("clean no-op Terraform plan contained classified changes")
        return _capture_plan_envelope_decision(document, provider, scenario, "clean", ())
    if exit_code != 2:
        raise SketchProviderContractCaptureError("no-op Terraform plan was not exact computed firewall drift")
    if not drift and has_output_refresh:
        return _capture_plan_envelope_decision(
            document, provider, scenario, "capture-induced-output-refresh", (),
        )
    if len(drift) != 1:
        raise SketchProviderContractCaptureError("no-op Terraform plan was not exact computed firewall drift")
    changed_fields = _require_computed_firewall_drift(drift[0], baseline, provider)
    classification = (
        "capture-induced-output-and-computed-firewall-drift"
        if has_output_refresh else "computed-firewall-drift"
    )
    return _capture_plan_envelope_decision(
        document, provider, scenario, classification, changed_fields,
    )


def _capture_plan_envelope_decision(
    document: dict[str, Any], provider: str, scenario: str, classification: str,
    changed_fields: tuple[str, ...] | frozenset[str],
    mask_proof: CaptureSensitivityMaskProof | None = None,
) -> CapturePlanEnvelopeDecision:
    try:
        encoded = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SketchProviderContractCaptureError("Terraform plan was not canonical JSON") from exc
    return CapturePlanEnvelopeDecision(
        provider, scenario, PROVIDER_FIREWALL_TARGETS[provider][0], classification,
        tuple(sorted(changed_fields)), hashlib.sha256(encoded).hexdigest(),
        mask_proof.classification if mask_proof else None,
        mask_proof.before_ingress_entries if mask_proof else None,
        mask_proof.after_ingress_entries if mask_proof else None,
        mask_proof.before_shape_sha256 if mask_proof else None,
        mask_proof.after_shape_sha256 if mask_proof else None,
    )


def _plan_envelope_provenance(decision: CapturePlanEnvelopeDecision) -> dict[str, Any]:
    if not isinstance(decision, CapturePlanEnvelopeDecision):
        raise SketchProviderContractCaptureError("Terraform plan envelope decision was invalid")
    return {
        "provider": decision.provider,
        "scenario": decision.scenario,
        "selectedAddress": decision.selected_address,
        "classification": decision.classification,
        "refreshDriftChangedFields": list(decision.drift_changed_fields),
        "sensitivityMaskProof": (
            {
                "classification": decision.mask_classification,
                "beforeIngressEntries": decision.before_ingress_mask_entries,
                "afterIngressEntries": decision.after_ingress_mask_entries,
                "beforeShapeSha256": decision.before_mask_shape_sha256,
                "afterShapeSha256": decision.after_mask_shape_sha256,
            }
            if decision.mask_classification is not None else None
        ),
    }


def _require_exact_firewall_update(
    resource: dict[str, Any], provider: str,
) -> CaptureSensitivityMaskProof:
    address = PROVIDER_FIREWALL_TARGETS[provider][0]
    resource_type, name = address.split(".", 1)
    expected_provider = {
        "linode": "registry.terraform.io/linode/linode",
        "digitalocean": "registry.terraform.io/digitalocean/digitalocean",
    }[provider]
    if set(resource) != {"address", "mode", "type", "name", "provider_name", "change"} \
            or resource.get("address") != address \
            or resource.get("mode") != "managed" \
            or resource.get("type") != resource_type \
            or resource.get("name") != name \
            or resource.get("provider_name") != expected_provider:
        raise SketchProviderContractCaptureError("Terraform firewall update metadata was invalid")
    change = resource["change"]
    if set(change) != {
        "actions", "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
    } or classify_saved_plan_actions(change.get("actions")) != "update" \
            or not isinstance(change.get("before"), dict) \
            or not isinstance(change.get("after"), dict) \
            or not isinstance(change.get("before_sensitive"), dict) \
            or not isinstance(change.get("after_sensitive"), dict) \
            or not isinstance(change.get("after_unknown"), dict):
        raise SketchProviderContractCaptureError("Terraform firewall update change metadata was invalid")
    mask_proof = _require_firewall_update_sensitivity(change, provider)
    unknown_paths = _strict_unknown_value_paths(change["after_unknown"])
    computed = PROVIDER_FIREWALL_COMPUTED_ATTRIBUTES[provider]
    if any(not path or path[0] not in computed for path in unknown_paths):
        raise SketchProviderContractCaptureError("Terraform firewall update left protected values unknown")
    return mask_proof


def _require_firewall_update_sensitivity(
    change: dict[str, Any], provider: str,
) -> CaptureSensitivityMaskProof:
    before, after = change["before"], change["after"]
    before_mask, after_mask = change["before_sensitive"], change["after_sensitive"]
    _require_false_sensitive_mask(before_mask)
    _require_false_sensitive_mask(after_mask)
    if not _sensitive_mask_matches_value(before_mask, before) \
            or not _sensitive_mask_matches_value(after_mask, after):
        raise SketchProviderContractCaptureError(
            "Terraform firewall sensitivity root shape did not match resource values"
        )
    ingress = "inbound" if provider == "linode" else "inbound_rule"
    if not _exact_json_equal(
        _without_mapping_keys(before_mask, frozenset({ingress})),
        _without_mapping_keys(after_mask, frozenset({ingress})),
    ):
        raise SketchProviderContractCaptureError(
            "Terraform firewall update changed protected sensitivity metadata"
        )
    before_rules, after_rules = before.get(ingress), after.get(ingress)
    before_rule_masks, after_rule_masks = before_mask.get(ingress), after_mask.get(ingress)
    if not all(isinstance(value, list) for value in (
        before_rules, after_rules, before_rule_masks, after_rule_masks,
    )) or len(before_rules) != len(before_rule_masks) \
            or len(after_rules) != len(after_rule_masks):
        raise SketchProviderContractCaptureError(
            "Terraform firewall update sensitivity did not align with ingress rules"
        )
    if any(
        not _sensitive_mask_matches_value(mask, rule)
        for rules, masks in ((before_rules, before_rule_masks), (after_rules, after_rule_masks))
        for rule, mask in zip(rules, masks, strict=True)
    ):
        raise SketchProviderContractCaptureError(
            "Terraform firewall update sensitivity rule shape was invalid"
        )
    if len(after_rules) == len(before_rules) + 1:
        alignments = [
            index for index in range(len(after_rules))
            if after_rules[:index] + after_rules[index + 1:] == before_rules
            and after_rule_masks[:index] + after_rule_masks[index + 1:] == before_rule_masks
        ]
    elif len(before_rules) == len(after_rules) + 1:
        alignments = [
            index for index in range(len(before_rules))
            if before_rules[:index] + before_rules[index + 1:] == after_rules
            and before_rule_masks[:index] + before_rule_masks[index + 1:] == after_rule_masks
        ]
    else:
        alignments = []
    if len(alignments) != 1:
        raise SketchProviderContractCaptureError(
            "Terraform firewall update sensitivity did not track the approved ingress rule"
        )
    return CaptureSensitivityMaskProof(
        "false-only-ingress-mask-aligned",
        len(before_rule_masks), len(after_rule_masks),
        _sensitivity_mask_shape_sha256(before_mask),
        _sensitivity_mask_shape_sha256(after_mask),
    )


def _require_false_sensitive_mask(value: Any) -> None:
    if value is False:
        return
    if value is True or value is None or isinstance(value, (str, int, float)):
        raise SketchProviderContractCaptureError(
            "Terraform firewall sensitivity metadata was malformed or sensitive"
        )
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise SketchProviderContractCaptureError(
                "Terraform firewall sensitivity metadata was malformed"
            )
        for item in value.values():
            _require_false_sensitive_mask(item)
        return
    if isinstance(value, list):
        for item in value:
            _require_false_sensitive_mask(item)
        return
    raise SketchProviderContractCaptureError("Terraform firewall sensitivity metadata was malformed")


def _sensitivity_mask_shape_sha256(value: Any) -> str:
    def shape(item: Any) -> Any:
        if item is False:
            return ["bool"]
        if isinstance(item, list):
            return ["list", [shape(child) for child in item]]
        if isinstance(item, dict):
            children = [shape(child) for child in item.values()]
            children.sort(key=lambda child: json.dumps(child, sort_keys=True, separators=(",", ":")))
            return ["dict", children]
        raise SketchProviderContractCaptureError("Terraform firewall sensitivity metadata was malformed")
    encoded = json.dumps(shape(value), separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sensitive_mask_matches_value(mask: Any, value: Any) -> bool:
    if isinstance(mask, dict):
        return isinstance(value, dict) and set(mask) <= set(value) and all(
            _sensitive_mask_matches_value(mask[key], value[key]) for key in mask
        )
    if isinstance(mask, list):
        return isinstance(value, list) and (
            not mask or (
                len(mask) == len(value)
                and all(
                    _sensitive_mask_matches_value(mask_item, value_item)
                    for mask_item, value_item in zip(mask, value, strict=True)
                )
            )
        )
    return mask is False and not isinstance(value, (dict, list))


def _require_exact_noop_resource(resource: dict[str, Any], provider: str) -> None:
    base_keys = {"address", "mode", "type", "name", "provider_name", "change"}
    keys = set(resource)
    if keys not in (base_keys, base_keys | {"index"}):
        raise SketchProviderContractCaptureError("no-op Terraform resource envelope was invalid")
    address = resource.get("address")
    resource_type = resource.get("type")
    name = resource.get("name")
    provider_name = resource.get("provider_name")
    expected_providers = _EXPECTED_PROVIDER_ADDRESSES[provider]
    if resource.get("mode") != "managed" \
            or any(type(value) is not str or not value for value in (address, resource_type, name, provider_name)) \
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", resource_type) \
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name) \
            or provider_name not in expected_providers:
        raise SketchProviderContractCaptureError("no-op Terraform resource identity was invalid")
    if "index" in resource:
        index = resource["index"]
        if type(index) is not int or index < 0 \
                or address != f"{resource_type}.{name}[{index}]":
            raise SketchProviderContractCaptureError("no-op Terraform indexed resource identity was invalid")
    elif address != f"{resource_type}.{name}":
        raise SketchProviderContractCaptureError("no-op Terraform resource address was invalid")
    provider_prefix = {
        "registry.terraform.io/hashicorp/local": "local_",
        "registry.terraform.io/hashicorp/random": "random_",
        "registry.terraform.io/linode/linode": "linode_",
        "registry.terraform.io/digitalocean/digitalocean": "digitalocean_",
    }[provider_name]
    if not resource_type.startswith(provider_prefix):
        raise SketchProviderContractCaptureError("no-op Terraform resource provider identity was invalid")
    _require_exact_noop_resource_change(resource["change"])


def _require_exact_noop_resource_change(change: dict[str, Any]) -> None:
    if "importing" in change:
        raise SketchProviderContractCaptureError("no-op Terraform plan contained an import")
    required = {
        "actions", "before", "after", "before_sensitive", "after_sensitive",
        "after_unknown",
    }
    if set(change) != required:
        raise SketchProviderContractCaptureError("no-op Terraform resource change metadata was invalid")
    if not isinstance(change["before"], dict) or not isinstance(change["after"], dict) \
            or not _exact_json_equal(change["before"], change["after"]):
        raise SketchProviderContractCaptureError("no-op Terraform resource before/after values differed")
    if not isinstance(change["before_sensitive"], dict) \
            or not isinstance(change["after_sensitive"], dict) \
            or not _exact_json_equal(change["before_sensitive"], change["after_sensitive"]):
        raise SketchProviderContractCaptureError("no-op Terraform resource sensitive metadata differed")
    after_unknown = change["after_unknown"]
    if not isinstance(after_unknown, dict) or _strict_unknown_value_paths(after_unknown):
        raise SketchProviderContractCaptureError("no-op Terraform resource left unknown values")


def _require_computed_firewall_drift(
    resource: Any, planned_resource: Any, provider: str,
) -> frozenset[str]:
    if not isinstance(resource, dict) or not isinstance(planned_resource, dict):
        raise SketchProviderContractCaptureError("no-op Terraform firewall drift was invalid")
    _require_planned_firewall_projection(planned_resource, provider)
    address = PROVIDER_FIREWALL_TARGETS[provider][0]
    resource_type, name = address.split(".", 1)
    expected_provider = {
        "linode": "registry.terraform.io/linode/linode",
        "digitalocean": "registry.terraform.io/digitalocean/digitalocean",
    }[provider]
    if (
        set(resource) != {
            "address", "mode", "type", "name", "provider_name", "change",
        }
        or
        resource.get("address") != address
        or resource.get("mode") != "managed"
        or resource.get("type") != resource_type
        or resource.get("name") != name
        or resource.get("provider_name") != expected_provider
        or "index" in resource
        or "module_address" in resource
    ):
        raise SketchProviderContractCaptureError("no-op Terraform firewall drift metadata was invalid")
    change = resource.get("change")
    if not isinstance(change, dict) or set(change) != {
        "actions", "before", "after", "before_sensitive", "after_sensitive",
        "after_unknown",
    }:
        raise SketchProviderContractCaptureError("no-op Terraform firewall drift change was invalid")
    try:
        action = classify_saved_plan_actions(change.get("actions"))
    except TerraformPlanGateError as exc:
        raise SketchProviderContractCaptureError("no-op Terraform firewall drift action was invalid") from exc
    if action != "update":
        raise SketchProviderContractCaptureError("no-op Terraform firewall drift action was not update")
    before, after = change.get("before"), change.get("after")
    planned_values = planned_resource.get("values")
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(planned_values, dict):
        raise SketchProviderContractCaptureError("no-op Terraform firewall drift omitted before/after semantics")
    computed = frozenset({"updated"}) if provider == "linode" else frozenset({
        "pending_changes", "status",
    })
    changed_fields = {
        key for key in set(before) | set(after)
        if key not in before or key not in after or not _exact_json_equal(before.get(key), after.get(key))
    }
    if not changed_fields or not changed_fields <= computed:
        raise SketchProviderContractCaptureError("no-op Terraform drift was not an actual computed-only change")
    if provider == "linode" and (
        changed_fields != {"updated"}
        or type(before.get("updated")) is not str
        or type(after.get("updated")) is not str
    ):
        raise SketchProviderContractCaptureError("no-op Linode drift was not the observed updated timestamp change")
    if provider == "digitalocean" and changed_fields != {"pending_changes", "status"}:
        raise SketchProviderContractCaptureError("no-op DigitalOcean drift was not the observed refresh change")
    if provider == "digitalocean" and (
        not isinstance(before.get("pending_changes"), list)
        or not isinstance(after.get("pending_changes"), list)
        or type(before.get("status")) is not str
        or type(after.get("status")) is not str
    ):
        raise SketchProviderContractCaptureError("no-op DigitalOcean drift value types were invalid")
    protected = _without_mapping_keys(planned_values, computed)
    if not _exact_json_equal(_without_mapping_keys(before, computed), protected) \
            or not _exact_json_equal(_without_mapping_keys(after, computed), protected):
        raise SketchProviderContractCaptureError("no-op Terraform drift changed protected firewall semantics")
    before_sensitive, after_sensitive = change["before_sensitive"], change["after_sensitive"]
    if not isinstance(before_sensitive, dict) or not isinstance(after_sensitive, dict) \
            or not _exact_json_equal(
                _without_mapping_keys(before_sensitive, computed),
                _without_mapping_keys(after_sensitive, computed),
            ):
        raise SketchProviderContractCaptureError("no-op Terraform drift changed protected sensitive metadata")
    planned_sensitive = planned_resource.get("sensitive_values")
    if not isinstance(planned_sensitive, dict) or not _exact_json_equal(
        _without_mapping_keys(before_sensitive, computed),
        _without_mapping_keys(planned_sensitive, computed),
    ):
        raise SketchProviderContractCaptureError("no-op Terraform drift sensitive metadata did not match its projection")
    after_unknown = change["after_unknown"]
    unknown_paths = _strict_unknown_value_paths(after_unknown) if isinstance(after_unknown, dict) else {()}
    if not isinstance(after_unknown, dict) or any(
        path and path[0] not in computed
        for path in unknown_paths
    ) or () in unknown_paths:
        raise SketchProviderContractCaptureError("no-op Terraform drift left protected firewall values unknown")
    return frozenset(changed_fields)


def _require_planned_firewall_projection(planned_resource: Any, provider: str) -> None:
    if not isinstance(planned_resource, dict):
        raise SketchProviderContractCaptureError("Terraform planned firewall projection was invalid")
    address = PROVIDER_FIREWALL_TARGETS[provider][0]
    resource_type, name = address.split(".", 1)
    expected_provider = {
        "linode": "registry.terraform.io/linode/linode",
        "digitalocean": "registry.terraform.io/digitalocean/digitalocean",
    }[provider]
    if (
        set(planned_resource) != {
            "address", "mode", "type", "name", "provider_name", "schema_version",
            "values", "sensitive_values",
        }
        or planned_resource.get("address") != address
        or planned_resource.get("mode") != "managed"
        or planned_resource.get("type") != resource_type
        or planned_resource.get("name") != name
        or planned_resource.get("provider_name") != expected_provider
        or type(planned_resource.get("schema_version")) is not int
        or planned_resource.get("schema_version") != 0
    ):
        raise SketchProviderContractCaptureError("no-op Terraform planned firewall metadata was invalid")


def _without_mapping_keys(value: dict[str, Any], keys: frozenset[str]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in keys}


def _strict_unknown_value_paths(value: Any, path: tuple[str, ...] = ()) -> set[tuple[str, ...]]:
    if value is True:
        return {path}
    if isinstance(value, dict):
        return set().union(*(
            _strict_unknown_value_paths(item, (*path, str(key))) for key, item in value.items()
        ), set())
    if isinstance(value, list):
        return set().union(*(
            _strict_unknown_value_paths(item, (*path, str(index))) for index, item in enumerate(value)
        ), set())
    if value is False or value is None:
        return set()
    raise SketchProviderContractCaptureError("Terraform unknown-value metadata was malformed")


def _exact_json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_exact_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_exact_json_equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def require_scenario_fidelity(
    scenario, role, channel, exit_code, delta, changes, *, noop_classification=None,
):
    field = "relayPort" if role == "middle" else "externalPort"
    try: listener = FirewallIngressPort(str(channel.get("protocol") or "tcp").lower(), int(channel.get(field)))
    except (TypeError, ValueError) as exc: raise SketchProviderContractCaptureError(f"channel omitted its {role} listener port") from exc
    if scenario == "add": valid = exit_code == 2 and delta == FirewallIngressDelta(added=frozenset({listener})) and len(changes) == 1
    elif scenario == "remove": valid = exit_code == 2 and delta == FirewallIngressDelta(removed=frozenset({listener})) and len(changes) == 1
    else:
        valid = (
            delta == FirewallIngressDelta()
            and changes == []
            and (
                (exit_code == 0 and noop_classification == "clean")
                or (
                    exit_code == 2
                    and noop_classification in {
                        "computed-firewall-drift",
                        "capture-induced-output-refresh",
                        "capture-induced-output-and-computed-firewall-drift",
                    }
                )
            )
        )
    if not valid: raise SketchProviderContractCaptureError(f"Terraform plan did not match the requested {scenario} scenario")


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _is_approved_workspace_file(name: str) -> bool:
    return name.endswith(".tf") or name in {".terraform.lock.hcl", "terraform.tfstate"}


def _audit_workspace_tree(directory_descriptor: int) -> None:
    for name in os.listdir(directory_descriptor):
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or (not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode)):
            raise SketchProviderContractCaptureError("retained workspace contains a link or special file")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise SketchProviderContractCaptureError("retained workspace contains a hardlinked file")
        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            try:
                _audit_workspace_tree(child_descriptor)
            finally:
                os.close(child_descriptor)


def _approved_file_names(root_descriptor: int) -> tuple[str, ...]:
    names = []
    for name in os.listdir(root_descriptor):
        metadata = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or (not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode)):
            raise SketchProviderContractCaptureError("retained workspace contains a link or special file")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise SketchProviderContractCaptureError("retained workspace contains a hardlinked file")
        if stat.S_ISREG(metadata.st_mode) and _is_approved_workspace_file(name):
            names.append(name)
    result = tuple(sorted(names))
    if not {".terraform.lock.hcl", "terraform.tfstate"}.issubset(result) or not any(name.endswith(".tf") for name in result):
        raise SketchProviderContractCaptureError("retained workspace omitted required Terraform files")
    return result


def _validated_required_template_paths(paths: tuple[str, ...] = REQUIRED_TEMPLATE_PATHS) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw in paths:
        if type(raw) is not str:
            raise SketchProviderContractCaptureError("approved template path was invalid")
        path = PurePosixPath(raw)
        if (
            not raw
            or path.is_absolute()
            or str(path) != raw
            or path.parts[:1] != ("templates",)
            or len(path.parts) != 2
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise SketchProviderContractCaptureError("approved template path was invalid")
        normalized.append(raw)
    if len(set(normalized)) != len(normalized) or set(normalized) != set(REQUIRED_TEMPLATE_PATHS):
        raise SketchProviderContractCaptureError("approved template closure was invalid")
    return tuple(sorted(normalized))


def _open_workspace_directory(parent_descriptor: int, name: str) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise SketchProviderContractCaptureError("retained workspace omitted required template directory") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise SketchProviderContractCaptureError("retained workspace template directory was invalid")
    return descriptor


def _approved_relative_paths(root_descriptor: int, template_descriptor: int) -> tuple[str, ...]:
    names = list(_approved_file_names(root_descriptor))
    for relative_path in _validated_required_template_paths():
        name = PurePosixPath(relative_path).name
        try:
            metadata = os.stat(name, dir_fd=template_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise SketchProviderContractCaptureError("retained workspace omitted required template file") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SketchProviderContractCaptureError("source template must be one regular non-hardlinked file")
        names.append(relative_path)
    return tuple(sorted(names))


def _descriptor_text(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SketchProviderContractCaptureError("Terraform source was not UTF-8") from exc


def _validate_static_template_dependencies(entries: tuple[WorkspaceManifestEntry, ...]) -> None:
    source = "\n".join(
        _descriptor_text(entry.descriptor)
        for entry in entries
        if PurePosixPath(entry.relative_path).parent == PurePosixPath(".")
        and entry.relative_path.endswith(".tf")
    )
    literals = tuple(_TEMPLATEFILE_CALL.findall(source))
    if len(_TEMPLATEFILE_TOKEN.findall(source)) != len(literals):
        raise SketchProviderContractCaptureError("Terraform template dependency was not a reviewed literal")
    try:
        normalized = _validated_required_template_paths(tuple(literals))
    except SketchProviderContractCaptureError as exc:
        raise SketchProviderContractCaptureError("Terraform template dependencies did not match the approved closure") from exc
    if normalized != tuple(sorted(REQUIRED_TEMPLATE_PATHS)):
        raise SketchProviderContractCaptureError("Terraform template dependencies did not match the approved closure")


def _descriptor_sha256(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _source_closure_sha256(entries: tuple[WorkspaceManifestEntry, ...] | list[WorkspaceManifestEntry]) -> str:
    ordered = sorted(entries, key=lambda entry: entry.relative_path)
    digest = hashlib.sha256()
    digest.update(_SOURCE_CLOSURE_DOMAIN)
    digest.update(len(ordered).to_bytes(8, "big"))
    for entry in ordered:
        path = entry.relative_path.encode("utf-8")
        try:
            raw_digest = bytes.fromhex(entry.sha256)
        except ValueError as exc:
            raise SketchProviderContractCaptureError("source closure digest was invalid") from exc
        if len(raw_digest) != hashlib.sha256().digest_size:
            raise SketchProviderContractCaptureError("source closure digest was invalid")
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(raw_digest)
    return digest.hexdigest()


@contextmanager
def approved_workspace(root: Path) -> Iterator[ApprovedWorkspace]:
    root_descriptor = open_directory_descriptor(root)
    entries: list[WorkspaceManifestEntry] = []
    directories: list[WorkspaceDirectoryEntry] = []
    try:
        root_identity = _stat_identity(os.fstat(root_descriptor))
        _audit_workspace_tree(root_descriptor)
        template_descriptor = _open_workspace_directory(root_descriptor, "templates")
        directories.append(WorkspaceDirectoryEntry("templates", template_descriptor, _stat_identity(os.fstat(template_descriptor))))
        for relative_path in _approved_relative_paths(root_descriptor, template_descriptor):
            path = PurePosixPath(relative_path)
            parent_descriptor = template_descriptor if path.parent == PurePosixPath("templates") else root_descriptor
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise SketchProviderContractCaptureError("source must be one regular non-hardlinked file")
            entries.append(WorkspaceManifestEntry(relative_path, descriptor, _stat_identity(metadata), _descriptor_sha256(descriptor), parent_descriptor))
        _validate_static_template_dependencies(tuple(entries))
        approval = ApprovedWorkspace(root, root_descriptor, root_identity, tuple(entries), tuple(directories))
        approval.verify()
        yield approval
    finally:
        for entry in entries:
            try:
                os.close(entry.descriptor)
            except OSError:
                pass
        for directory in reversed(directories):
            try:
                os.close(directory.descriptor)
            except OSError:
                pass
        os.close(root_descriptor)


def _verify_workspace_root(root: Path, root_descriptor: int, expected_identity: tuple[int, ...]) -> None:
    current = root.lstat()
    if not stat.S_ISDIR(current.st_mode) or _stat_identity(current) != expected_identity:
        raise SketchProviderContractCaptureError("retained workspace root changed during capture")
    if _stat_identity(os.fstat(root_descriptor)) != expected_identity:
        raise SketchProviderContractCaptureError("retained workspace descriptor changed during capture")


def _verify_manifest_directory(root_descriptor: int, entry: WorkspaceDirectoryEntry) -> None:
    if _stat_identity(os.fstat(entry.descriptor)) != entry.identity:
        raise SketchProviderContractCaptureError("retained workspace directory changed during capture")
    current_descriptor = _open_workspace_directory(root_descriptor, entry.relative_path)
    try:
        if _stat_identity(os.fstat(current_descriptor)) != entry.identity:
            raise SketchProviderContractCaptureError("retained workspace directory changed during capture")
    finally:
        os.close(current_descriptor)


def _verify_manifest_entry(entry: WorkspaceManifestEntry) -> None:
    held = os.fstat(entry.descriptor)
    if _stat_identity(held) != entry.identity or _descriptor_sha256(entry.descriptor) != entry.sha256:
        raise SketchProviderContractCaptureError("retained workspace content changed during capture")
    current_descriptor = os.open(
        PurePosixPath(entry.relative_path).name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=entry.parent_descriptor,
    )
    try:
        current = os.fstat(current_descriptor)
        if _stat_identity(current) != entry.identity or _descriptor_sha256(current_descriptor) != entry.sha256:
            raise SketchProviderContractCaptureError("retained workspace content changed during capture")
    finally:
        os.close(current_descriptor)


def _copy_manifest_entry(entry: WorkspaceManifestEntry, target: Path) -> None:
    parent_descriptor = open_directory_descriptor(target)
    destination_descriptor = os.open(
        PurePosixPath(entry.relative_path).name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=parent_descriptor,
    )
    try:
        os.lseek(entry.descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(entry.descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(destination_descriptor, view):]
        os.lseek(entry.descriptor, 0, os.SEEK_SET)
        os.fsync(destination_descriptor)
        copied = os.fstat(destination_descriptor)
        _validate_copied_manifest_entry(entry, copied, digest.hexdigest())
    finally:
        os.close(destination_descriptor)
        os.close(parent_descriptor)


def _copy_manifest_entry_to_directory(entry: WorkspaceManifestEntry, target: AnchoredPrivateDirectory) -> None:
    target.verify()
    destination_descriptor = os.open(
        PurePosixPath(entry.relative_path).name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=target.descriptor,
    )
    try:
        os.lseek(entry.descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(entry.descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(destination_descriptor, view):]
        os.lseek(entry.descriptor, 0, os.SEEK_SET)
        os.fsync(destination_descriptor)
        copied = os.fstat(destination_descriptor)
        _validate_copied_manifest_entry(entry, copied, digest.hexdigest())
    finally:
        os.close(destination_descriptor)
    target.verify()


def _validate_copied_manifest_entry(entry: WorkspaceManifestEntry, copied: os.stat_result, copied_sha256: str) -> None:
    if (
        not stat.S_ISREG(copied.st_mode)
        or stat.S_IMODE(copied.st_mode) != 0o600
        or copied.st_nlink != 1
        or (copied.st_dev, copied.st_ino) == (entry.identity[0], entry.identity[1])
        or copied_sha256 != entry.sha256
    ):
        raise SketchProviderContractCaptureError("approved source content changed while cloning")


def required_files(root):
    with approved_workspace(root) as approval:
        approval.verify()
        return tuple(root / entry.relative_path for entry in approval.entries)


def clone_required_workspace(source, target):
    with approved_workspace(source) as approval:
        approval.clone_to(target)
        approval.verify()


def adapt_clone(workspace, provider):
    _refresh_provider_firewall_templates(provider, workspace)
    ensure_sketch_resource_name_suffix_compatibility(workspace, provider)
    ensure_sketch_udp_ingress_compatibility(workspace, provider)
    ensure_sketch_ssh_variable_contract_compatibility(workspace, provider)
    ensure_linode_firewall_protocol_compatibility(workspace, provider)
    ensure_sketch_firewall_port_list_compatibility(workspace, provider)
    if provider == "digitalocean": stabilize_digitalocean_ssh_key_ownership(workspace)


def validate_request(request):
    for label, value in (("engagement", request.engagement_id), ("chain", request.chain_id), ("channel", request.channel_id)):
        if not _TOKEN.fullmatch(value): raise SketchProviderContractCaptureError(f"invalid {label} ID")
    if not _CAPTURE_ID.fullmatch(request.capture_id): raise SketchProviderContractCaptureError("capture ID must be opaque")
    if request.scenario not in _SCENARIO_STATUSES: raise SketchProviderContractCaptureError("invalid scenario")


def validate_devtest_scope(data_dir, environment):
    if environment != "devtest": raise SketchProviderContractCaptureError("capture requires exact DevTest environment")
    supplied = data_dir.expanduser().absolute()
    expected = CANONICAL_DEVTEST_DATA_DIR.expanduser().absolute()
    if supplied != expected: raise SketchProviderContractCaptureError("capture requires canonical DevTest data directory")
    reject_symlink_components(expected)
    try: root, canonical = data_dir.expanduser().resolve(strict=True), CANONICAL_DEVTEST_DATA_DIR.resolve(strict=True)
    except OSError as exc: raise SketchProviderContractCaptureError("canonical DevTest data directory is unavailable") from exc
    if root != canonical: raise SketchProviderContractCaptureError("capture requires canonical DevTest data directory")
    return root


@contextmanager
def anchored_devtest_destination(data_dir: Path, environment: str) -> Iterator[AnchoredPrivateDirectory]:
    root = validate_devtest_scope(data_dir, environment)
    components: list[tuple[Path, int, tuple[int, ...]]] = []
    current_path = Path(root.anchor)
    descriptor = os.open(
        current_path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    components.append((current_path, descriptor, _directory_identity(os.fstat(descriptor))))
    try:
        for name in root.parts[1:]:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=components[-1][1],
            )
            current_path = current_path / name
            components.append((current_path, descriptor, _directory_identity(os.fstat(descriptor))))
        anchor = DestinationAnchor(tuple(components))
        anchor.verify()
        directory = AnchoredPrivateDirectory(
            root,
            anchor.root_descriptor,
            _directory_identity(os.fstat(anchor.root_descriptor)),
            anchor,
            owns_descriptor=False,
        )
        yield directory
        directory.verify()
    finally:
        for _path, opened, _identity in reversed(components):
            try:
                os.close(opened)
            except OSError:
                pass


def reject_symlink_components(path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try: metadata = current.lstat()
        except OSError as exc: raise SketchProviderContractCaptureError("canonical DevTest path component was unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode): raise SketchProviderContractCaptureError("canonical DevTest path must not contain symlinks")


def ensure_private_base(path):
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077: raise SketchProviderContractCaptureError("capture root is unsafe")
    else: mkdir_exclusive(path)


def mkdir_exclusive(path):
    parent_fd = open_directory_descriptor(path.parent)
    try:
        try: os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc: raise SketchProviderContractCaptureError("private path exists") from exc
        metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700: raise SketchProviderContractCaptureError("private directory creation failed")
    finally: os.close(parent_fd)


def write_exclusive(path, value):
    parent_fd = open_directory_descriptor(path.parent)
    descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(value.encode())
        while view: view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600: raise SketchProviderContractCaptureError("private file creation failed")
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def open_directory_descriptor(path):
    before = path.lstat()
    if not stat.S_ISDIR(before.st_mode): raise SketchProviderContractCaptureError("capture parent was not a directory")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        os.close(descriptor)
        raise SketchProviderContractCaptureError("capture parent changed while opening")
    return descriptor


def require_private_regular_file(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600: raise SketchProviderContractCaptureError("saved plan was not private")
    finally: os.close(descriptor)


@contextmanager
def private_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    try: yield
    finally: os.umask(previous)



def copy_json(value):
    if value is None or isinstance(value, (bool, int, float, str)): return value
    if isinstance(value, list): return [copy_json(item) for item in value]
    if isinstance(value, dict): return {str(key): copy_json(item) for key, item in sorted(value.items())}
    raise SketchProviderContractCaptureError("contract contained non-JSON value")




def workspace_digest(root):
    required_files(root)
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if stat.S_ISREG(candidate.lstat().st_mode)):
        digest.update(str(path.relative_to(root)).encode() + sha256_file(path).encode())
    return digest.hexdigest()


def terraform_source_digest(root):
    root = Path(root)
    root_descriptor = open_directory_descriptor(root)
    template_descriptor = -1
    entries: list[WorkspaceManifestEntry] = []
    try:
        root_identity = _stat_identity(os.fstat(root_descriptor))
        template_descriptor = _open_workspace_directory(root_descriptor, "templates")
        template_identity = _stat_identity(os.fstat(template_descriptor))
        relative_paths = [
            name for name in sorted(os.listdir(root_descriptor))
            if name.endswith(".tf")
        ] + list(_validated_required_template_paths())
        if not any(path.endswith(".tf") for path in relative_paths):
            raise SketchProviderContractCaptureError("Terraform source unavailable")
        for relative_path in relative_paths:
            parsed = PurePosixPath(relative_path)
            parent = template_descriptor if parsed.parent == PurePosixPath("templates") else root_descriptor
            descriptor = os.open(parsed.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise SketchProviderContractCaptureError("Terraform source closure was invalid")
            entries.append(WorkspaceManifestEntry(relative_path, descriptor, _stat_identity(metadata), _descriptor_sha256(descriptor), parent))
        _validate_static_template_dependencies(tuple(entries))
        result = _source_closure_sha256(entries)
        _verify_workspace_root(root, root_descriptor, root_identity)
        _verify_manifest_directory(root_descriptor, WorkspaceDirectoryEntry("templates", template_descriptor, template_identity))
        for entry in entries:
            _verify_manifest_entry(entry)
        return result
    except OSError as exc:
        raise SketchProviderContractCaptureError("Terraform source closure was unavailable") from exc
    finally:
        for entry in entries:
            os.close(entry.descriptor)
        if template_descriptor >= 0:
            os.close(template_descriptor)
        os.close(root_descriptor)


def firewall_schema_versions(state_path, provider):
    try: state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError) as exc: raise SketchProviderContractCaptureError("state was not JSON") from exc
    if not isinstance(state, dict) or not isinstance(state.get("resources"), list):
        raise SketchProviderContractCaptureError("state resource schema was unavailable")
    resource_type = "linode_firewall" if provider == "linode" else "digitalocean_firewall"
    resources = [r for r in state["resources"] if isinstance(r, dict) and r.get("type") == resource_type]
    if len(resources) != 1:
        raise SketchProviderContractCaptureError("state provider firewall schema was missing or duplicated")
    resource = resources[0]
    expected_provider = {
        "linode": 'provider["registry.terraform.io/linode/linode"]',
        "digitalocean": 'provider["registry.terraform.io/digitalocean/digitalocean"]',
    }[provider]
    if (
        resource.get("mode") != "managed"
        or resource.get("name") != "firewall"
        or resource.get("provider") != expected_provider
    ):
        raise SketchProviderContractCaptureError("state provider firewall resource identity was invalid")
    instances = resource.get("instances")
    if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], dict):
        raise SketchProviderContractCaptureError("state provider firewall instance was missing or duplicated")
    schema = instances[0].get("schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != 0:
        raise SketchProviderContractCaptureError("state provider firewall schema was invalid")
    resource_schema = resource.get("schema_version", schema)
    if isinstance(resource_schema, bool) or not isinstance(resource_schema, int) or resource_schema != schema:
        raise SketchProviderContractCaptureError("state provider firewall schema conflicted with its instance")
    return [schema]


def plan_firewall_schema_versions(document, provider):
    resources = find_resources(document.get("planned_values"), PROVIDER_FIREWALL_TARGETS[provider][0])
    if len(resources) != 1:
        raise SketchProviderContractCaptureError("plan provider firewall schema was missing or duplicated")
    schema = resources[0].get("schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != 0:
        raise SketchProviderContractCaptureError("plan provider firewall schema was invalid")
    return [schema]


# The capture artifact retains the complete Terraform show shape. Scalars are
# private by default; only values needed to replay contract and mutation gates
# pass explicit validators below.
def export_firewall_contract(document, provider):
    if provider not in PROVIDER_FIREWALL_TARGETS or not isinstance(document, dict):
        raise SketchProviderContractCaptureError("Terraform show contract was invalid")
    sanitizer = TerraformShowSanitizer(document, provider)
    sanitizer.prepare()
    return sanitizer.sanitize(document, ())


def is_resource_envelope(value):
    return isinstance(value.get("address"), str) and "mode" in value and "type" in value and "name" in value


def is_values_module_path(path: tuple[str, ...]) -> bool:
    prefixes = (("planned_values", "root_module"), ("prior_state", "values", "root_module"))
    prefix = next((candidate for candidate in prefixes if path[:len(candidate)] == candidate), None)
    if prefix is None:
        return False
    tail = path[len(prefix):]
    while tail:
        if len(tail) < 2 or tail[0] != "child_modules" or not tail[1].isdigit():
            return False
        tail = tail[2:]
    return True


def is_configuration_module_path(path: tuple[str, ...]) -> bool:
    prefix = ("configuration", "root_module")
    if path[:len(prefix)] != prefix:
        return False
    tail = path[len(prefix):]
    while tail:
        if len(tail) < 3 or tail[0] != "module_calls" or tail[2] != "module":
            return False
        tail = tail[3:]
    return True


def is_configuration_module_calls_path(path: tuple[str, ...]) -> bool:
    return path[-1:] == ("module_calls",) and is_configuration_module_path(path[:-1])


def is_configuration_module_providers_path(path: tuple[str, ...]) -> bool:
    return (
        path[-1:] == ("providers",)
        and len(path) >= 3
        and path[-3] == "module_calls"
        and is_configuration_module_path(path[:-3])
    )


def is_configuration_expression_map_path(path: tuple[str, ...]) -> bool:
    if path[-1:] != ("expressions",):
        return False
    if len(path) == 4 and path[:2] == ("configuration", "provider_config"):
        return True
    owner = path[:-1]
    if is_resource_envelope_path(owner):
        return owner[:1] == ("configuration",)
    return (
        len(owner) >= 2
        and owner[-2] == "module_calls"
        and is_configuration_module_path(owner[:-2])
    )


def is_child_module_address_path(path: tuple[str, ...]) -> bool:
    return (
        path[-1:] == ("address",)
        and len(path) >= 3
        and path[-3] == "child_modules"
        and path[-2].isdigit()
        and is_values_module_path(path[:-3])
    )


def is_change_actions_path(path: tuple[str, ...]) -> bool:
    return (
        len(path) == 3
        and path[0] == "output_changes"
        and path[2] == "actions"
    ) or (
        len(path) == 4
        and path[0] in {"resource_changes", "resource_drift"}
        and path[1].isdigit()
        and path[2:] == ("change", "actions")
    ) or (
        len(path) == 5
        and path[0] == "deferred_changes"
        and path[1].isdigit()
        and path[2:] == ("resource_change", "change", "actions")
    )


def is_dynamic_identity_map_path(path: tuple[str, ...]) -> bool:
    if path in {("variables",), ("output_changes",)}:
        return True
    if path[-1:] == ("variables",) and is_configuration_module_path(path[:-1]):
        return True
    if path[-1:] == ("outputs",) and (
        is_values_module_path(path[:-1]) or is_configuration_module_path(path[:-1])
    ):
        return True
    return path in {("planned_values", "outputs"), ("prior_state", "values", "outputs")}


def dynamic_identity_kind(path: tuple[str, ...]) -> str:
    if not is_dynamic_identity_map_path(path):
        raise SketchProviderContractCaptureError("Terraform dynamic identity path was invalid")
    return "var" if path[-1] == "variables" else "output"


def is_dynamic_data_path(path: tuple[str, ...]) -> bool:
    if is_configuration_constant_value_path(path):
        return True
    if len(path) == 3 and path[0] == "output_changes" and path[2] in {
        "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
    }:
        return True
    if len(path) == 3 and path[0] == "variables" and path[2] == "value":
        return True
    if len(path) >= 3 and path[-1] in {"value", "default"}:
        collection = path[:-2]
        return is_dynamic_identity_map_path(collection)
    return False


def is_configuration_constant_value_path(path: tuple[str, ...]) -> bool:
    if len(path) < 6 or path[0] != "configuration" or path[-1] != "constant_value":
        return False
    if path[-3] == "expressions":
        owner = path[:-3]
        if is_resource_envelope_path(owner):
            return owner[:1] == ("configuration",)
        return len(owner) >= 2 and owner[-2] == "module_calls" and is_configuration_module_path(owner[:-2])
    if path[-2] == "expression":
        owner = path[:-2]
        return len(owner) >= 2 and owner[-2] == "outputs" and is_configuration_module_path(owner[:-2])
    return False


def configuration_reference_module_path(path: tuple[str, ...]) -> tuple[str, ...] | None:
    """Return the owning configuration module path for an exact expression reference list."""
    if len(path) < 6 or path[0] != "configuration" or path[-1] != "references":
        return None
    expression = path[:-1]
    if len(expression) >= 2 and expression[-2] == "expressions":
        owner = expression[:-2]
        if is_resource_envelope_path(owner) and owner[:1] == ("configuration",):
            return owner[:-2]
        if len(owner) >= 2 and owner[-2] == "module_calls" and is_configuration_module_path(owner[:-2]):
            return owner[:-2]
    if expression[-1:] == ("expression",):
        owner = expression[:-1]
        if len(owner) >= 2 and owner[-2] == "outputs" and is_configuration_module_path(owner[:-2]):
            return owner[:-2]
    return None


def is_configuration_references_path(path: tuple[str, ...]) -> bool:
    return configuration_reference_module_path(path) is not None


def configuration_module_identity(path: tuple[str, ...]) -> tuple[str, ...]:
    if not is_configuration_module_path(path):
        raise SketchProviderContractCaptureError("Terraform configuration reference path was invalid")
    tail = path[2:]
    result: list[str] = []
    while tail:
        result.append(tail[1])
        tail = tail[3:]
    return tuple(result)


def is_resource_envelope_path(path: tuple[str, ...]) -> bool:
    if len(path) == 2 and path[0] in {"resource_changes", "resource_drift"} and path[1].isdigit():
        return True
    if len(path) == 3 and path[0] == "deferred_changes" and path[1].isdigit() and path[2] == "resource_change":
        return True
    if not path or not path[-1].isdigit() or path[-2:-1] != ("resources",):
        return False
    return is_values_module_path(path[:-2]) or is_configuration_module_path(path[:-2])


def is_check_address_path(path: tuple[str, ...]) -> bool:
    return len(path) == 3 and path[0] == "checks" and path[1].isdigit() and path[2] == "address"


@dataclass(frozen=True)
class TerraformAddress:
    modules: tuple[tuple[str, tuple[str, Any] | None], ...]
    mode: str
    resource_type: str
    name: str
    index: tuple[str, Any] | None
    attributes: tuple[tuple[str, tuple[str, Any] | None], ...] = ()

    @property
    def base_key(self) -> tuple[Any, ...]:
        return (self.modules, self.mode, self.resource_type, self.name, self.index)


_ADDRESS_PART = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)(.*)$")
_ADDRESS_INDEX = re.compile(r"^\[(?:(\d+)|(\"(?:[^\"\\]|\\.)*\"))\]")


def _address_part(value: str) -> tuple[str, tuple[str, Any] | None]:
    match = _ADDRESS_PART.fullmatch(value)
    if not match:
        raise SketchProviderContractCaptureError("Terraform resource address was invalid")
    name, suffix = match.groups()
    if not suffix:
        return name, None
    index = _ADDRESS_INDEX.fullmatch(suffix)
    if not index:
        raise SketchProviderContractCaptureError("Terraform resource address index was invalid")
    if index.group(1) is not None:
        return name, ("number", int(index.group(1)))
    try:
        key = json.loads(index.group(2))
    except json.JSONDecodeError as exc:
        raise SketchProviderContractCaptureError("Terraform resource address index was invalid") from exc
    if not isinstance(key, str):
        raise SketchProviderContractCaptureError("Terraform resource address index was invalid")
    return name, ("string", key)


def parse_terraform_address(value: Any, *, reference: bool = False) -> TerraformAddress:
    if not isinstance(value, str) or not value:
        raise SketchProviderContractCaptureError("Terraform resource address was invalid")
    parts = _split_address(value)
    modules: list[tuple[str, tuple[str, Any] | None]] = []
    offset = 0
    while offset + 1 < len(parts) and parts[offset] == "module":
        modules.append(_address_part(parts[offset + 1]))
        offset += 2
    mode = "managed"
    if offset < len(parts) and parts[offset] == "data":
        mode = "data"
        offset += 1
    if len(parts) - offset < 2:
        raise SketchProviderContractCaptureError("Terraform resource address was invalid")
    resource_type, type_index = _address_part(parts[offset])
    if type_index is not None:
        raise SketchProviderContractCaptureError("Terraform resource type address was invalid")
    name, index = _address_part(parts[offset + 1])
    tail = parts[offset + 2:]
    if tail and not reference:
        raise SketchProviderContractCaptureError("Terraform resource address contained attributes")
    attributes = tuple(_address_part(part) for part in tail)
    return TerraformAddress(tuple(modules), mode, resource_type, name, index, attributes)


def parse_module_address(value: Any) -> tuple[tuple[str, tuple[str, Any] | None], ...]:
    if not isinstance(value, str) or not value:
        raise SketchProviderContractCaptureError("Terraform module address was invalid")
    parts = _split_address(value)
    modules = []
    offset = 0
    while offset + 1 < len(parts) and parts[offset] == "module":
        modules.append(_address_part(parts[offset + 1]))
        offset += 2
    if offset != len(parts) or not modules:
        raise SketchProviderContractCaptureError("Terraform module address was invalid")
    return tuple(modules)


def _split_address(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    bracket_depth = 0
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"' and bracket_depth:
            quoted = True
        elif character == "[":
            bracket_depth += 1
        elif character == "]":
            bracket_depth -= 1
            if bracket_depth < 0:
                raise SketchProviderContractCaptureError("Terraform resource address was invalid")
        elif character == "." and bracket_depth == 0:
            parts.append(value[start:index])
            start = index + 1
    if quoted or bracket_depth or escaped:
        raise SketchProviderContractCaptureError("Terraform resource address was invalid")
    parts.append(value[start:])
    if any(not part for part in parts):
        raise SketchProviderContractCaptureError("Terraform resource address was invalid")
    return parts


def _index_text(index: tuple[str, Any] | None, key_names: dict[str, str]) -> str:
    if index is None:
        return ""
    if index[0] == "number":
        return f"[{index[1]}]"
    return f"[{json.dumps(key_names[index[1]], separators=(',', ':'))}]"


def allocate_pseudonyms(values, prefix, *, raw_labels=None):
    identities = sorted(set(values))
    reserved = {str(value) for value in (raw_labels if raw_labels is not None else identities)}
    used: set[str] = set()
    result = {}
    ordinal = 1
    for identity in identities:
        while True:
            candidate = f"{prefix}_{ordinal:03d}"
            ordinal += 1
            if candidate not in reserved and candidate not in used:
                break
        result[identity] = candidate
        used.add(candidate)
    return result


_LINODE_FIREWALL_KEYS = {
    "root": {
        "created", "devices", "fingerprint", "id", "inbound", "inbound_policy", "label",
        "linodes", "nodebalancers", "outbound", "outbound_policy", "status", "tags", "updated",
        "version",
    },
    "rule": {"action", "description", "ipv4", "ipv6", "label", "ports", "protocol"},
    "device": {"entity_id", "id", "label", "type", "url"},
}
_DIGITALOCEAN_FIREWALL_KEYS = {
    "root": {
        "created_at", "droplet_ids", "id", "inbound_rule", "name", "outbound_rule",
        "pending_changes", "status", "tags",
    },
    "rule": {
        "port_range", "protocol", "source_addresses", "source_droplet_ids",
        "source_kubernetes_ids", "source_load_balancer_uids", "source_tags",
        "destination_addresses", "destination_droplet_ids", "destination_kubernetes_ids",
        "destination_load_balancer_uids", "destination_tags",
    },
}


def parse_symbol_address(value: Any, expected_kind: str) -> tuple[tuple[tuple[str, tuple[str, Any] | None], ...], str]:
    if expected_kind not in {"check", "output", "var"} or not isinstance(value, str):
        raise SketchProviderContractCaptureError("Terraform symbolic address was invalid")
    parts = _split_address(value)
    modules = []
    offset = 0
    while offset + 1 < len(parts) and parts[offset] == "module":
        modules.append(_address_part(parts[offset + 1]))
        offset += 2
    if len(parts) - offset != 2 or parts[offset] != expected_kind:
        raise SketchProviderContractCaptureError("Terraform symbolic address was invalid")
    name, index = _address_part(parts[offset + 1])
    if index is not None:
        raise SketchProviderContractCaptureError("Terraform symbolic address index was invalid")
    return tuple(modules), name


class TerraformShowSanitizer:
    """One document-scoped, relational Terraform address pseudonym map."""

    def __init__(self, document: dict[str, Any], provider: str):
        self.document = document
        self.provider = provider
        self.firewall_address = PROVIDER_FIREWALL_TARGETS[provider][0]
        self.resources: dict[tuple[Any, ...], tuple[str | None, int | None]] = {}
        self.module_names: dict[str, str] = {}
        self.resource_names: dict[tuple[str, str], str] = {}
        self.key_names: dict[str, str] = {}
        self.address_keys: set[str] = set()
        self.module_call_names: set[str] = set()
        self.provider_configs: dict[str, str] = {}
        self.provider_alias_names: dict[str, str] = {}
        self.symbol_values: dict[str, set[str]] = {"check": set(), "output": set(), "var": set()}
        self.symbol_names: dict[str, dict[str, str]] = {}
        self.local_values: set[tuple[tuple[str, ...], str]] = set()
        self.local_names: dict[tuple[tuple[str, ...], str], str] = {}
        self.data_keys: set[str] = set()
        self.data_key_names: dict[str, str] = {}
        self.firewall_rule_labels: set[str] = set()
        self.firewall_rule_label_names: dict[str, str] = {}

    def prepare(self) -> None:
        self._collect_schema_names(self.document, ())
        self._collect(self.document, ())
        self._allocate_identity_names()
        firewall = self.resources.get(parse_terraform_address(self.firewall_address).base_key)
        expected_provider = {
            "linode": "registry.terraform.io/linode/linode",
            "digitalocean": "registry.terraform.io/digitalocean/digitalocean",
        }[self.provider]
        if firewall != (expected_provider, 0):
            raise SketchProviderContractCaptureError("provider firewall authoritative metadata was incomplete")

    def _allocate_identity_names(self) -> None:
        module_values = sorted(self.module_call_names | {name for key in self.resources for name, _index in key[0]})
        resource_values = sorted({(key[2], key[3]) for key in self.resources if not self._is_firewall_key(key)})
        key_values = sorted(self.address_keys | {index[1] for key in self.resources for _name, index in key[0] if index and index[0] == "string"} | {
            key[4][1] for key in self.resources if key[4] and key[4][0] == "string"
        })
        raw_identity_labels = set(module_values)
        raw_identity_labels.update(name for _resource_type, name in resource_values)
        raw_identity_labels.update(key_values)
        raw_identity_labels.update(self.provider_configs)
        raw_identity_labels.update(name for values in self.symbol_values.values() for name in values)
        raw_identity_labels.update(name for _module, name in self.local_values)
        raw_identity_labels.update(self.data_keys)
        raw_identity_labels.update(self.firewall_rule_labels)
        self.module_names = allocate_pseudonyms(module_values, "module", raw_labels=raw_identity_labels)
        self.resource_names = allocate_pseudonyms(
            resource_values,
            "resource",
            raw_labels=raw_identity_labels,
        )
        self.key_names = allocate_pseudonyms(key_values, "key", raw_labels=raw_identity_labels)
        self.provider_alias_names = allocate_pseudonyms(
            self.provider_configs, "provider_alias", raw_labels=raw_identity_labels,
        )
        self.symbol_names = {
            kind: allocate_pseudonyms(values, kind, raw_labels=raw_identity_labels)
            for kind, values in self.symbol_values.items()
        }
        self.local_names = allocate_pseudonyms(
            self.local_values,
            "local",
            raw_labels=raw_identity_labels,
        )
        self.data_key_names = allocate_pseudonyms(
            self.data_keys, "data_key", raw_labels=raw_identity_labels,
        )
        self.firewall_rule_label_names = allocate_pseudonyms(
            self.firewall_rule_labels, "rule_label", raw_labels=raw_identity_labels,
        )

    def _collect_schema_names(self, value: Any, path: tuple[str, ...]) -> None:
        if is_dynamic_data_path(path):
            self._collect_generic_keys(value)
            return
        if is_configuration_references_path(path):
            if not isinstance(value, list) or not all(type(item) is str for item in value):
                raise SketchProviderContractCaptureError("Terraform configuration references were invalid")
            for item in value:
                self._collect_reference(item, path)
            return
        if isinstance(value, dict):
            if is_configuration_expression_map_path(path):
                self.data_keys.update(str(key) for key in value)
                for key, item in value.items():
                    self._collect_schema_names(item, (*path, str(key)))
                return
            if is_dynamic_identity_map_path(path):
                self.symbol_values[dynamic_identity_kind(path)].update(str(key) for key in value)
                for key, item in value.items():
                    self._collect_schema_names(item, (*path, str(key)))
                return
            if is_resource_envelope_path(path) and is_resource_envelope(value):
                firewall = value.get("address") == self.firewall_address
                if "sensitive_values" in value:
                    if firewall:
                        self._collect_firewall_keys(value["sensitive_values"], semantic=False)
                    else:
                        self._collect_generic_keys(value["sensitive_values"])
                if "values" in value:
                    if firewall:
                        self._collect_firewall_keys(value["values"])
                    else:
                        self._collect_generic_keys(value["values"])
                change = value.get("change")
                if isinstance(change, dict):
                    for field, item in change.items():
                        if field == "actions":
                            continue
                        if firewall and field in {
                            "before", "after", "before_sensitive", "after_sensitive", "after_unknown",
                        }:
                            self._collect_firewall_keys(
                                item, semantic=field in {"before", "after"},
                            )
                        else:
                            self._collect_generic_keys(item)
            if path == ("configuration", "provider_config"):
                for alias, config in value.items():
                    if not isinstance(alias, str) or not alias or not isinstance(config, dict):
                        raise SketchProviderContractCaptureError("Terraform provider configuration was invalid")
                    full_name = config.get("full_name")
                    if not isinstance(full_name, str) or not re.fullmatch(r"registry\.terraform\.io/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", full_name):
                        raise SketchProviderContractCaptureError("Terraform provider configuration was invalid")
                    self.provider_configs[alias] = full_name
                    module_address = config.get("module_address")
                    if module_address is not None:
                        modules = parse_module_address(module_address)
                        self.module_call_names.update(name for name, _index in modules)
                        self.address_keys.update(
                            index[1] for _name, index in modules if index and index[0] == "string"
                        )
            if is_configuration_module_calls_path(path):
                for name in value:
                    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name):
                        raise SketchProviderContractCaptureError("Terraform module call name was invalid")
                    self.module_call_names.add(name)
            if is_check_address_path(path):
                kind = value.get("kind")
                if kind not in self.symbol_values and kind != "resource":
                    raise SketchProviderContractCaptureError("Terraform check address kind was unsupported")
                if kind in self.symbol_values:
                    modules, name = parse_symbol_address(value.get("to_display"), kind)
                    self.symbol_values[kind].add(name)
                    self.module_call_names.update(module_name for module_name, _index in modules)
                    self.address_keys.update(
                        index[1] for _module_name, index in modules if index and index[0] == "string"
                    )
                else:
                    self._collect_resource_reference(value.get("to_display"))
            for key, item in value.items():
                self._collect_schema_names(item, (*path, str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._collect_schema_names(item, (*path, str(index)))
        elif isinstance(value, str) and is_child_module_address_path(path):
            modules = parse_module_address(value)
            self.module_call_names.update(name for name, _index in modules)
            self.address_keys.update(index[1] for _name, index in modules if index and index[0] == "string")

    def _reference_module_identity(self, path: tuple[str, ...]) -> tuple[str, ...]:
        module_path = configuration_reference_module_path(path)
        if module_path is None:
            raise SketchProviderContractCaptureError("Terraform configuration reference path was invalid")
        return configuration_module_identity(module_path)

    def _parse_local_reference(self, value: Any, path: tuple[str, ...]) -> tuple[tuple[str, ...], str]:
        if not isinstance(value, str):
            raise SketchProviderContractCaptureError("Terraform local reference was invalid")
        try:
            parts = _split_address(value)
            if len(parts) != 2 or parts[0] != "local":
                raise SketchProviderContractCaptureError("Terraform local reference was invalid")
            name, index = _address_part(parts[1])
        except SketchProviderContractCaptureError:
            raise SketchProviderContractCaptureError("Terraform local reference was invalid")
        if index is not None:
            raise SketchProviderContractCaptureError("Terraform local reference was invalid")
        return self._reference_module_identity(path), name

    def _collect_resource_reference(self, value: Any) -> None:
        try:
            address = parse_terraform_address(value, reference=True)
        except SketchProviderContractCaptureError:
            try:
                modules = parse_module_address(value)
            except SketchProviderContractCaptureError:
                raise SketchProviderContractCaptureError("Terraform configuration reference was invalid") from None
            self.module_call_names.update(name for name, _index in modules)
            self.address_keys.update(index[1] for _name, index in modules if index and index[0] == "string")
            return
        self.module_call_names.update(name for name, _index in address.modules)
        for _name, index in (*address.modules, *address.attributes):
            if index and index[0] == "string":
                self.address_keys.add(index[1])
        if address.index and address.index[0] == "string":
            self.address_keys.add(address.index[1])

    def _collect_reference(self, value: str, path: tuple[str, ...]) -> None:
        root = value.split(".", 1)[0]
        if root == "local":
            self.local_values.add(self._parse_local_reference(value, path))
            return
        if root == "count":
            if value != "count.index":
                raise SketchProviderContractCaptureError("Terraform count reference was invalid")
            return
        if root in {"each", "path", "terraform"}:
            raise SketchProviderContractCaptureError("Terraform built-in reference was unsupported")
        if root in self.symbol_values:
            modules, name = parse_symbol_address(value, root)
            self.module_call_names.update(module_name for module_name, _index in modules)
            self.address_keys.update(index[1] for _name, index in modules if index and index[0] == "string")
            return
        for kind in self.symbol_values:
            try:
                modules, _name = parse_symbol_address(value, kind)
            except SketchProviderContractCaptureError:
                continue
            self.module_call_names.update(module_name for module_name, _index in modules)
            self.address_keys.update(index[1] for _name, index in modules if index and index[0] == "string")
            return
        self._collect_resource_reference(value)

    def _collect_generic_keys(self, value: Any) -> None:
        if isinstance(value, dict):
            self.data_keys.update(str(key) for key in value)
            for item in value.values():
                self._collect_generic_keys(item)
        elif isinstance(value, list):
            for item in value:
                self._collect_generic_keys(item)

    def _collect_firewall_keys(
        self, value: Any, context: str = "root", *, semantic: bool = True,
        public_ingress: bool = False,
    ) -> None:
        if isinstance(value, dict):
            if self.provider == "linode" and context == "rule" and semantic:
                label = self._linode_public_listener_label(
                    value, public_ingress=public_ingress,
                )
                if label is None and isinstance(value.get("label"), str):
                    self.firewall_rule_labels.add(value["label"])
            known = (_LINODE_FIREWALL_KEYS if self.provider == "linode" else _DIGITALOCEAN_FIREWALL_KEYS)[context]
            for key, item in value.items():
                key = str(key)
                if key not in known:
                    self.data_keys.add(key)
                    self._collect_generic_keys(item)
                    continue
                child_context = self._firewall_child_context(context, key)
                if child_context is not None:
                    self._collect_firewall_keys(
                        item, child_context, semantic=semantic,
                        public_ingress=self.provider == "linode" and key == "inbound",
                    )
                else:
                    self._collect_generic_keys(item)
        elif isinstance(value, list):
            for item in value:
                self._collect_firewall_keys(
                    item, context, semantic=semantic, public_ingress=public_ingress,
                )

    @staticmethod
    def _linode_public_listener_label(
        rule: dict[str, Any], *, public_ingress: bool,
    ) -> str | None:
        if "label" not in rule:
            return None
        label = rule["label"]
        if label is None:
            return None
        if not isinstance(label, str):
            raise SketchProviderContractCaptureError("firewall rule label was invalid")
        match = re.fullmatch(r"allow-(tcp|udp)-(\d+)", label)
        if match is None:
            return None
        protocol, port_text = match.groups()
        port = int(port_text)
        if not public_ingress or not 1 <= port <= 65535 \
                or str(port) != port_text or set(rule) != _LINODE_FIREWALL_KEYS["rule"] \
                or rule.get("action") != "ACCEPT" or rule.get("protocol") != protocol.upper() \
                or rule.get("ports") != port_text or rule.get("description") != "" \
                or rule.get("ipv4") != ["0.0.0.0/0"] \
                or "ipv6" not in rule or rule["ipv6"] is not None:
            return None
        return label

    def _firewall_child_context(self, context: str, key: str) -> str | None:
        if context != "root":
            return None
        if self.provider == "linode":
            if key in {"inbound", "outbound"}:
                return "rule"
            if key == "devices":
                return "device"
        elif key in {"inbound_rule", "outbound_rule"}:
            return "rule"
        return None

    def _collect(self, value: Any, path: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            if is_resource_envelope_path(path):
                if not is_resource_envelope(value):
                    raise SketchProviderContractCaptureError("Terraform resource envelope was invalid")
                address = self._validate_resource_metadata(value, path)
                schema = value.get("schema_version")
                if schema is not None and (isinstance(schema, bool) or not isinstance(schema, int) or schema < 0):
                    raise SketchProviderContractCaptureError("Terraform resource schema version was invalid")
                provider_identity = (
                    self.provider_configs.get(value.get("provider_config_key"))
                    if path[:1] == ("configuration",)
                    else value.get("provider_name")
                )
                signature = (str(provider_identity) if provider_identity is not None else None, schema)
                prior = self.resources.get(address.base_key)
                if prior is not None:
                    if prior[0] is not None and signature[0] is not None and prior[0] != signature[0]:
                        raise SketchProviderContractCaptureError("Terraform resource provider metadata was inconsistent")
                    if prior[1] is not None and signature[1] is not None and prior[1] != signature[1]:
                        raise SketchProviderContractCaptureError("Terraform resource schema metadata was inconsistent")
                    signature = (prior[0] or signature[0], prior[1] if prior[1] is not None else signature[1])
                self.resources[address.base_key] = signature
            for key, item in value.items():
                self._collect(item, (*path, str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._collect(item, (*path, str(index)))

    def _validate_resource_metadata(self, resource: dict[str, Any], path: tuple[str, ...]) -> TerraformAddress:
        address = parse_terraform_address(resource.get("address"))
        mode, resource_type, name = resource.get("mode"), resource.get("type"), resource.get("name")
        claimed_firewall = resource.get("address") == self.firewall_address
        configuration = path[:1] == ("configuration",)
        if claimed_firewall:
            expected = {
                "linode": ("linode_firewall", "registry.terraform.io/linode/linode"),
                "digitalocean": ("digitalocean_firewall", "registry.terraform.io/digitalocean/digitalocean"),
            }[self.provider]
            provider_matches = (
                resource.get("provider_config_key") in self.provider_configs
                and self.provider_configs[resource["provider_config_key"]] == expected[1]
            ) if configuration else resource.get("provider_name") == expected[1]
            if mode != "managed" or resource_type != expected[0] or name != "firewall" or not provider_matches:
                raise SketchProviderContractCaptureError("provider firewall resource metadata did not match its exact contract")
        if mode not in {"managed", "data"} or address.mode != mode:
            raise SketchProviderContractCaptureError("Terraform resource mode was invalid")
        if resource_type != address.resource_type or name != address.name:
            raise SketchProviderContractCaptureError("Terraform resource address metadata was inconsistent")
        provider_name = resource.get("provider_name")
        provider_config_key = resource.get("provider_config_key")
        if configuration:
            if not isinstance(provider_config_key, str) or provider_config_key not in self.provider_configs:
                raise SketchProviderContractCaptureError("Terraform resource provider configuration was invalid")
            if provider_name is not None:
                raise SketchProviderContractCaptureError("Terraform configuration resource used runtime provider metadata")
        elif provider_config_key is not None or provider_name is None:
            raise SketchProviderContractCaptureError("Terraform runtime resource provider metadata was invalid")
        if provider_name is not None and (
            not isinstance(provider_name, str)
            or not re.fullmatch(r"registry\.terraform\.io/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", provider_name)
        ):
            raise SketchProviderContractCaptureError("Terraform resource provider was invalid")
        if "index" in resource:
            raw_index = resource["index"]
            actual = ("number", raw_index) if type(raw_index) is int else ("string", raw_index) if isinstance(raw_index, str) else None
            if actual != address.index:
                raise SketchProviderContractCaptureError("Terraform resource index metadata was inconsistent")
        module_address = resource.get("module_address")
        if module_address is not None and module_address != self._render_modules(address.modules, identity=True):
            raise SketchProviderContractCaptureError("Terraform module address metadata was inconsistent")
        if self._is_firewall(address):
            expected = {
                "linode": ("linode_firewall", "registry.terraform.io/linode/linode"),
                "digitalocean": ("digitalocean_firewall", "registry.terraform.io/digitalocean/digitalocean"),
            }[self.provider]
            provider_matches = self.provider_configs.get(provider_config_key) == expected[1] if configuration else provider_name == expected[1]
            if mode != "managed" or resource_type != expected[0] or name != "firewall" or not provider_matches:
                raise SketchProviderContractCaptureError("provider firewall resource metadata did not match its exact contract")
            if "schema_version" in resource and (isinstance(resource["schema_version"], bool) or resource["schema_version"] != 0):
                raise SketchProviderContractCaptureError("provider firewall schema version was unsupported")
        return address

    def _is_firewall(self, address: TerraformAddress) -> bool:
        return not address.attributes and self._render(address, identity=True) == self.firewall_address

    def _is_firewall_key(self, key: tuple[Any, ...]) -> bool:
        return key == parse_terraform_address(self.firewall_address).base_key

    def _render_modules(self, modules, *, identity=False) -> str:
        result = []
        for name, index in modules:
            mapped = name if identity else self.module_names[name]
            result.extend(("module", mapped + (_raw_index_text(index) if identity else _index_text(index, self.key_names))))
        return ".".join(result)

    def _render(self, address: TerraformAddress, *, identity=False) -> str:
        parts = []
        modules = self._render_modules(address.modules, identity=identity)
        if modules:
            parts.append(modules)
        if address.mode == "data":
            parts.append("data")
        parts.append(address.resource_type)
        name = address.name if identity or self._is_firewall_key(address.base_key) else self.resource_names[(address.resource_type, address.name)]
        parts.append(name + (_raw_index_text(address.index) if identity else _index_text(address.index, self.key_names)))
        for attribute, index in address.attributes:
            parts.append(attribute + (_raw_index_text(index) if identity else _index_text(index, self.key_names)))
        return ".".join(parts)

    def _map_address(self, value: Any, *, reference=False) -> str:
        address = parse_terraform_address(value, reference=reference)
        if address.base_key not in self.resources:
            raise SketchProviderContractCaptureError("Terraform resource address was unmappable")
        return self._render(address)

    def _map_address_or_module(self, value: Any, *, reference=False) -> str:
        try:
            return self._map_address(value, reference=reference)
        except SketchProviderContractCaptureError as resource_error:
            try:
                modules = parse_module_address(value)
            except SketchProviderContractCaptureError:
                raise resource_error from None
            if not any(key[0][:len(modules)] == modules for key in self.resources):
                raise SketchProviderContractCaptureError("Terraform module address was unmappable")
            return self._render_modules(modules)

    def _map_module(self, value: Any) -> str:
        modules = parse_module_address(value)
        if not any(key[0][:len(modules)] == modules for key in self.resources) and not all(
            name in self.module_names for name, _index in modules
        ):
            raise SketchProviderContractCaptureError("Terraform module address was unmappable")
        return self._render_modules(modules)

    def _map_symbol(self, value: Any, kind: str) -> str:
        modules, name = parse_symbol_address(value, kind)
        if name not in self.symbol_names[kind]:
            raise SketchProviderContractCaptureError("Terraform symbolic address was unmappable")
        prefix = self._render_modules(modules)
        rendered = f"{kind}.{self.symbol_names[kind][name]}"
        return f"{prefix}.{rendered}" if prefix else rendered

    def _map_any_address(self, value: Any, *, reference=False) -> str:
        try:
            return self._map_address_or_module(value, reference=reference)
        except SketchProviderContractCaptureError as resource_error:
            for kind in ("check", "output", "var"):
                try:
                    return self._map_symbol(value, kind)
                except SketchProviderContractCaptureError:
                    continue
            raise resource_error from None

    def _map_reference(self, value: Any, path: tuple[str, ...]) -> str:
        if not isinstance(value, str):
            raise SketchProviderContractCaptureError("Terraform configuration reference was invalid")
        root = value.split(".", 1)[0]
        if root == "local":
            identity = self._parse_local_reference(value, path)
            if identity not in self.local_names:
                raise SketchProviderContractCaptureError("Terraform local reference was unmappable")
            return f"local.{self.local_names[identity]}"
        if root == "count":
            if value != "count.index":
                raise SketchProviderContractCaptureError("Terraform count reference was invalid")
            return value
        if root in {"each", "path", "terraform"}:
            raise SketchProviderContractCaptureError("Terraform built-in reference was unsupported")
        if root in self.symbol_names:
            return self._map_symbol(value, root)
        for kind in self.symbol_names:
            try:
                parse_symbol_address(value, kind)
            except SketchProviderContractCaptureError:
                continue
            return self._map_symbol(value, kind)
        return self._map_address_or_module(value, reference=True)

    def sanitize(self, value: Any, path: tuple[str, ...]) -> Any:
        if is_dynamic_data_path(path):
            return self._sanitize_generic(value)
        if is_configuration_references_path(path):
            if not isinstance(value, list) or not all(type(item) is str for item in value):
                raise SketchProviderContractCaptureError("Terraform configuration references were invalid")
            return [self._map_reference(item, path) for item in value]
        if isinstance(value, dict):
            if is_configuration_expression_map_path(path):
                return {
                    self.data_key_names[str(key)]: self.sanitize(item, (*path, str(key)))
                    for key, item in value.items()
                }
            if is_resource_envelope_path(path):
                if not is_resource_envelope(value):
                    raise SketchProviderContractCaptureError("Terraform resource envelope was invalid")
                return self._sanitize_resource(value, path)
            if is_check_address_path(path):
                if set(value) < {"kind", "to_display"}:
                    raise SketchProviderContractCaptureError("Terraform check address was invalid")
                kind = value.get("kind")
                if kind == "resource":
                    return {
                        str(key): self._map_address_or_module(item, reference=True) if key == "to_display" else (kind if key == "kind" else self.sanitize(item, (*path, str(key))))
                        for key, item in value.items()
                    }
                if kind not in self.symbol_names:
                    raise SketchProviderContractCaptureError("Terraform check address kind was unsupported")
                return {
                    str(key): self._map_symbol(item, kind) if key == "to_display" else (kind if key == "kind" else self.sanitize(item, (*path, str(key))))
                    for key, item in value.items()
                }
            if path == ("configuration", "provider_config"):
                return {
                    self.provider_alias_names[str(key)]: self.sanitize(item, (*path, str(key)))
                    for key, item in value.items()
                }
            if is_dynamic_identity_map_path(path):
                kind = dynamic_identity_kind(path)
                return {
                    self.symbol_names[kind][str(key)]: self.sanitize(item, (*path, str(key)))
                    for key, item in value.items()
                }
            if is_configuration_module_calls_path(path):
                return {
                    self.module_names[str(key)]: self.sanitize(item, (*path, str(key)))
                    for key, item in value.items()
                }
            if is_configuration_module_providers_path(path):
                return {
                    self.provider_alias_names.get(str(key), str(key)): self.sanitize(item, (*path, str(key)))
                    for key, item in value.items()
                }
            return {str(key): self.sanitize(item, (*path, str(key))) for key, item in value.items()}
        if isinstance(value, list):
            if is_change_actions_path(path):
                return validate_actions(value)
            return [self.sanitize(item, (*path, str(index))) for index, item in enumerate(value)]
        if value is None or isinstance(value, bool):
            return value
        if path in {("format_version",), ("terraform_version",)}:
            return validate_show_version(value, path[-1])
        if len(path) == 3 and path[0] == "relevant_attributes" and path[1].isdigit() and path[2] == "resource":
            return self._map_address(value, reference=True)
        if path[:2] == ("configuration", "provider_config") and path[-1:] == ("module_address",):
            return self._map_module(value)
        if len(path) >= 2 and path[-2] == "providers" and is_configuration_module_providers_path(path[:-1]):
            if value not in self.provider_alias_names:
                raise SketchProviderContractCaptureError("Terraform module provider alias was unmappable")
            return self.provider_alias_names[value]
        if is_child_module_address_path(path):
            return self._map_module(value)
        if isinstance(value, str):
            return redact_scalar(value)
        return redact_scalar(value)

    def _sanitize_generic(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                self.data_key_names[str(key)]: self._sanitize_generic(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._sanitize_generic(item) for item in value]
        if value is None or isinstance(value, bool):
            return value
        return redact_scalar(value)

    def _sanitize_resource(self, resource: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
        address = self._validate_resource_metadata(resource, path)
        firewall = self._is_firewall(address)
        result = {}
        for key, item in resource.items():
            child_path = (*path, str(key))
            if key == "address":
                result[key] = self._render(address)
            elif key == "module_address":
                result[key] = self._render_modules(address.modules)
            elif key == "mode":
                result[key] = address.mode
            elif key == "type":
                result[key] = address.resource_type
            elif key == "name":
                result[key] = address.name if firewall else self.resource_names[(address.resource_type, address.name)]
            elif key == "index":
                if item is None:
                    result[key] = None
                elif address.index and address.index[0] == "number":
                    result[key] = address.index[1]
                else:
                    result[key] = self.key_names[address.index[1]]
            elif key == "provider_name":
                result[key] = item
            elif key == "provider_config_key":
                result[key] = self.provider_alias_names[item]
            elif key == "schema_version":
                result[key] = item
            elif key == "change":
                result[key] = self._sanitize_change(item, child_path, firewall)
            elif key == "values" and firewall:
                result[key] = self._sanitize_firewall(item)
            elif key == "sensitive_values" and firewall:
                result[key] = self._sanitize_firewall(item, semantic=False)
            elif key in {"values", "sensitive_values"}:
                result[key] = self._sanitize_generic(item)
            else:
                result[key] = self.sanitize(item, child_path)
        return result

    def _sanitize_change(self, change: Any, path: tuple[str, ...], firewall: bool) -> dict[str, Any]:
        if not isinstance(change, dict):
            raise SketchProviderContractCaptureError("Terraform change envelope was invalid")
        result = {}
        for key, item in change.items():
            child_path = (*path, str(key))
            if key == "actions":
                result[key] = validate_actions(item)
            elif firewall and key in {"before", "after"}:
                result[key] = self._sanitize_firewall(item)
            elif firewall and key in {"before_sensitive", "after_sensitive", "after_unknown"}:
                result[key] = self._sanitize_firewall(item, semantic=False)
            elif not firewall and key != "actions":
                result[key] = self._sanitize_generic(item)
            else:
                result[key] = self.sanitize(item, child_path)
        return result

    def _sanitize_firewall(
        self, value: Any, context: str = "root", *, semantic: bool = True,
        public_ingress: bool = False,
    ) -> Any:
        if isinstance(value, dict):
            public_listener_label = None
            if self.provider == "linode" and context == "rule" and semantic:
                public_listener_label = self._linode_public_listener_label(
                    value, public_ingress=public_ingress,
                )
            known = (_LINODE_FIREWALL_KEYS if self.provider == "linode" else _DIGITALOCEAN_FIREWALL_KEYS)[context]
            result = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                if key not in known:
                    result[self.data_key_names[key]] = self._sanitize_generic(item)
                    continue
                child_context = self._firewall_child_context(context, key)
                if child_context is not None:
                    result[key] = self._sanitize_firewall(
                        item, child_context, semantic=semantic,
                        public_ingress=self.provider == "linode" and key == "inbound",
                    )
                elif not semantic:
                    result[key] = self._sanitize_generic(item)
                elif context == "root" and key not in {
                    "inbound", "inbound_policy", "outbound", "outbound_policy",
                    "inbound_rule", "outbound_rule", "devices",
                }:
                    result[key] = self._sanitize_generic(item)
                elif context == "device" and key in {"entity_id", "id", "label", "type", "url"}:
                    if isinstance(item, (dict, list)):
                        raise SketchProviderContractCaptureError("firewall device identity was invalid")
                    result[key] = redact_identity_shape(item, key)
                elif context == "rule" and key == "label":
                    if item is None:
                        result[key] = None
                    elif not isinstance(item, str):
                        raise SketchProviderContractCaptureError("firewall rule label was invalid")
                    else:
                        result[key] = (
                        item if item == public_listener_label
                        else self.firewall_rule_label_names[item]
                        )
                elif key in {"inbound_policy", "outbound_policy", "action"}:
                    if item not in {"ACCEPT", "DROP"}:
                        raise SketchProviderContractCaptureError("firewall policy or action was invalid")
                    result[key] = item
                elif key == "protocol":
                    if not isinstance(item, str) or item.lower() not in {"tcp", "udp", "icmp", "ipencap"}:
                        raise SketchProviderContractCaptureError("firewall protocol was invalid")
                    result[key] = item
                elif key in {"ports", "port_range"}:
                    if self.provider == "linode" and key == "ports" and item is None:
                        result[key] = None
                    elif not isinstance(item, str) or not re.fullmatch(r"(?:\d+(?:-\d+)?|)", item):
                        raise SketchProviderContractCaptureError("firewall port expression was invalid")
                    else:
                        result[key] = item
                elif key in {"ipv4", "ipv6", "source_addresses", "destination_addresses"}:
                    result[key] = sanitize_address_shape(item)
                elif key in {
                    "source_droplet_ids", "source_kubernetes_ids", "source_load_balancer_uids", "source_tags",
                    "destination_droplet_ids", "destination_kubernetes_ids", "destination_load_balancer_uids", "destination_tags",
                }:
                    if not isinstance(item, list) or any(isinstance(entry, (dict, list)) for entry in item):
                        raise SketchProviderContractCaptureError("firewall identity list was invalid")
                    result[key] = redact_identity_shape(item, key)
                elif key == "description":
                    if not isinstance(item, str):
                        raise SketchProviderContractCaptureError("firewall rule description was invalid")
                    result[key] = "" if item == "" else redact_identity_shape(item, key)
                else:
                    result[key] = redact_scalar(item)
            return result
        if isinstance(value, list):
            return [
                self._sanitize_firewall(
                    item, context, semantic=semantic, public_ingress=public_ingress,
                )
                for item in value
            ]
        if value is None or isinstance(value, bool):
            return value
        return redact_scalar(value)


def _raw_index_text(index: tuple[str, Any] | None) -> str:
    if index is None:
        return ""
    return f"[{index[1]}]" if index[0] == "number" else f"[{json.dumps(index[1], separators=(',', ':'))}]"


def sanitize_address_shape(value):
    if value is None: return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SketchProviderContractCaptureError("firewall address list was invalid")
    return [item if item in {"0.0.0.0/0", "::/0"} else redact_identity_shape(item, "ip") for item in value]


def redact_identity_shape(value, field):
    if isinstance(value, list): return [redact_identity_shape(item, field) for item in value]
    if isinstance(value, dict): return {str(key): redact_identity_shape(item, field) for key, item in value.items()}
    if value is None or isinstance(value, bool): return value
    return typed_placeholder(value, field)


def redact_scalar(value):
    return typed_placeholder(value, "redacted")


def typed_placeholder(value, label):
    digest = hashlib.sha256(f"{type(value).__name__}:{value}".encode()).hexdigest()
    if isinstance(value, str): return f"<{label}-{digest[:16]}>"
    if isinstance(value, int) and not isinstance(value, bool): return int(digest[:12], 16)
    if isinstance(value, float): return int(digest[:12], 16) / float(16 ** 12)
    raise SketchProviderContractCaptureError("Terraform scalar type was unsupported")


def validate_actions(value):
    try:
        classify_saved_plan_actions(value)
    except TerraformPlanGateError:
        raise SketchProviderContractCaptureError("Terraform change actions were invalid") from None
    return list(value)


def validate_show_version(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?", value):
        raise SketchProviderContractCaptureError(f"Terraform show {label} was invalid")
    return value


def validate_resource_address(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.\-\[\]\"']+", value):
        raise SketchProviderContractCaptureError("Terraform resource address was invalid")
    return value


def canonical_firewall_semantics(document, provider, *, redact):
    source = export_firewall_contract(document, provider) if redact else document
    address = PROVIDER_FIREWALL_TARGETS[provider][0]
    planned = find_resources(source.get("planned_values"), address)
    changes = [row for row in source.get("resource_changes", []) if isinstance(row, dict) and row.get("address") == address]
    return {
        "planned": copy_json(planned[0].get("values")) if planned else None,
        "changes": [{
            "actions": copy_json(row.get("change", {}).get("actions")),
            "before": copy_json(row.get("change", {}).get("before")),
            "after": copy_json(row.get("change", {}).get("after")),
            "after_unknown": copy_json(row.get("change", {}).get("after_unknown")),
        } for row in changes],
    }


def read_capture_source_provenance(
    providers: set[str], *, expected_tool_revision: str = "",
) -> CaptureSourceProvenance:
    selected = tuple(sorted(providers))
    if not selected or any(provider not in PROVIDER_FIREWALL_TARGETS for provider in selected):
        raise SketchProviderContractCaptureError("capture template provenance was invalid")
    if expected_tool_revision and not re.fullmatch(r"[0-9a-f]{40}", expected_tool_revision):
        raise SketchProviderContractCaptureError("capture tool revision was invalid")
    tool_root = Path(__file__).resolve().parents[3]
    template_root = redteam_infra_template_root()
    tool_before = strict_git_revision(tool_root)
    template_before = strict_git_revision(template_root)
    if expected_tool_revision and expected_tool_revision != tool_before:
        raise SketchProviderContractCaptureError("capture tool revision did not match the clean checkout")
    template_sources = tuple(
        (
            provider,
            terraform_source_digest(
                template_root / "external" / "sketch" / provider,
            ),
        )
        for provider in selected
    )
    tool_after = strict_git_revision(tool_root)
    template_after = strict_git_revision(template_root)
    if tool_after != tool_before or template_after != template_before:
        raise SketchProviderContractCaptureError("capture source provenance changed while reading")
    return CaptureSourceProvenance(tool_before, template_before, template_sources)


def require_capture_source_provenance(
    expected: CaptureSourceProvenance,
    providers: set[str],
    *, expected_tool_revision: str = "",
) -> None:
    current = read_capture_source_provenance(
        providers, expected_tool_revision=expected_tool_revision,
    )
    expected_sources = tuple(
        item for item in expected.template_sources if item[0] in providers
    )
    if (
        current.tool_revision != expected.tool_revision
        or current.template_revision != expected.template_revision
        or current.template_sources != expected_sources
    ):
        raise SketchProviderContractCaptureError("capture source provenance changed during capture")


def strict_git_revision(root):
    supplied = Path(root).expanduser().absolute()
    try:
        canonical = supplied.resolve(strict=True)
    except OSError as exc:
        raise SketchProviderContractCaptureError("source revision was unavailable") from exc
    if supplied != canonical or not canonical.is_dir():
        raise SketchProviderContractCaptureError("source revision root was invalid")
    git = shutil.which("git", path=CAPTURE_SYSTEM_PATH)
    if not git or not Path(git).is_absolute():
        raise SketchProviderContractCaptureError("source revision was unavailable")
    environment = {
        "PATH": CAPTURE_SYSTEM_PATH,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    prefix = [
        git, "--no-optional-locks", "-c", "core.fsmonitor=false",
        "-c", f"core.hooksPath={os.devnull}", "-C", str(canonical),
    ]
    top_level = subprocess.run(
        [*prefix, "rev-parse", "--show-toplevel"],
        check=False, capture_output=True, text=True, env=environment,
    )
    revision = subprocess.run(
        [*prefix, "rev-parse", "--verify", "HEAD^{commit}"],
        check=False, capture_output=True, text=True, env=environment,
    )
    status = subprocess.run(
        [*prefix, "status", "--porcelain=v1", "--untracked-files=all"],
        check=False, capture_output=True, text=True, env=environment,
    )
    value = revision.stdout.strip()
    if (
        top_level.returncode != 0
        or revision.returncode != 0
        or status.returncode != 0
        or not re.fullmatch(r"[0-9a-f]{40}", value)
    ):
        raise SketchProviderContractCaptureError("source revision was unavailable")
    try:
        reported_root = Path(top_level.stdout.strip()).resolve(strict=True)
    except OSError as exc:
        raise SketchProviderContractCaptureError("source revision root was invalid") from exc
    if reported_root != canonical:
        raise SketchProviderContractCaptureError("source revision root was invalid")
    if status.stdout:
        raise SketchProviderContractCaptureError("source checkout was not clean")
    return value


def sha256_file(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode): raise SketchProviderContractCaptureError("artifact was not regular")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk: break
            digest.update(chunk)
        return digest.hexdigest()
    finally: os.close(descriptor)


def provenance_hash(value): return hashlib.sha256(value.encode()).hexdigest()
def record_command_attempt(raw, command, result):
    stdout_path = raw.write_exclusive(f"terraform-{command}.stdout", result.stdout)
    raw.write_exclusive(f"terraform-{command}.stderr", result.stderr)
    raw.write_exclusive(
        f"terraform-{command}.result.json",
        json.dumps({"command": command, "returnCode": result.returncode}, sort_keys=True, separators=(",", ":")) + "\n",
    )
    raw.verify()
    return stdout_path


def require_success(returncode, command):
    if returncode != 0: raise SketchProviderContractCaptureError(f"{command} failed")
