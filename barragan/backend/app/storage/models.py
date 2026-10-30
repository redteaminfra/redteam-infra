# Copyright (c) 2026, Oracle and/or its affiliates.
from datetime import datetime, timezone

from app.storage.database import db


class EngagementModel(db.Model):
    __tablename__ = "engagements"

    id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    owner = db.Column(db.String(120), nullable=False)
    template_id = db.Column(db.String(80), nullable=False)
    active_revision = db.Column(db.String(120), nullable=True)
    input_parameters = db.Column(db.JSON, nullable=False, default=dict)
    sketch_state_schema = db.Column(db.String(40), nullable=False, default="split-v1")
    description = db.Column(db.Text, nullable=False, default="")
    documentation_url = db.Column(db.String(500), nullable=False, default="")
    jira_url = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class EngagementLifecycleModel(db.Model):
    __tablename__ = "engagement_lifecycles"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    state = db.Column(db.String(40), nullable=False, default="not_deployed")
    evidence_fingerprint = db.Column(db.String(64), nullable=False, default="")
    evidence = db.Column(db.JSON, nullable=False, default=list)
    reconciled_at = db.Column(db.DateTime(timezone=True), nullable=False)


class EngagementLifecycleEventModel(db.Model):
    __tablename__ = "engagement_lifecycle_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    previous_state = db.Column(db.String(40), nullable=False)
    state = db.Column(db.String(40), nullable=False)
    evidence_fingerprint = db.Column(db.String(64), nullable=False)
    evidence = db.Column(db.JSON, nullable=False, default=list)
    reason = db.Column(db.String(160), nullable=False, default="local_evidence_reconciliation")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_engagement_lifecycle_events_engagement_created", "engagement_id", "created_at"),
    )


class EngagementOperationsModel(db.Model):
    __tablename__ = "engagement_operations"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    housekeeping_items = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class EngagementWorkspaceModel(db.Model):
    __tablename__ = "engagement_workspaces"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    slug = db.Column(db.String(160), nullable=False)
    path = db.Column(db.String(1000), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="prepared")
    profile_id = db.Column(db.String(80), nullable=False, default="standard-rti")
    template_source = db.Column(db.JSON, nullable=False, default=dict)
    workspace_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class DeploymentPlanModel(db.Model):
    __tablename__ = "deployment_plans"

    id = db.Column(db.String(80), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    revision_id = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    stage = db.Column(db.String(80), nullable=False)
    review = db.Column(db.JSON, nullable=False, default=dict)
    # Private integrity evidence. This column must never be serialized by an API.
    evidence = db.Column(db.JSON, nullable=False, default=dict)
    is_current = db.Column(db.Boolean, nullable=False, default=True)
    apply_job_id = db.Column(db.String(64), nullable=False, default="")
    error = db.Column(db.Text, nullable=False, default="")
    prepared_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_deployment_plans_engagement_created", "engagement_id", "created_at"),
    )


class CoreMutationLeaseModel(db.Model):
    __tablename__ = "core_mutation_leases"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    owner_id = db.Column(db.String(80), nullable=False)
    operation = db.Column(db.String(40), nullable=False)
    acquired_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class EngagementObserverSettingsModel(db.Model):
    __tablename__ = "engagement_observer_settings"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    provider = db.Column(db.String(40), nullable=False, default="")
    region = db.Column(db.String(80), nullable=False, default="")
    size = db.Column(db.String(80), nullable=False, default="")
    mode = db.Column(db.String(40), nullable=False, default="continuous")
    schedule_weekdays = db.Column(db.JSON, nullable=False, default=list)
    schedule_time_utc = db.Column(db.String(5), nullable=False, default="00:00")
    check_families = db.Column(db.JSON, nullable=False, default=list)
    forbidden_tcp_ports = db.Column(db.JSON, nullable=False, default=list)
    port_scan_profiles = db.Column(db.JSON, nullable=False, default=list)
    current_host = db.Column(db.JSON, nullable=False, default=dict)
    idle_retention_until = db.Column(db.String(80), nullable=False, default="")
    last_scheduled_slot = db.Column(db.String(80), nullable=False, default="")
    last_mutation_job_inspected = db.Column(db.String(80), nullable=False, default="")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class InspectionRunModel(db.Model):
    __tablename__ = "inspection_runs"

    id = db.Column(db.String(80), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    job_id = db.Column(db.String(64), db.ForeignKey("job_runs.id"), nullable=False)
    trigger_type = db.Column(db.String(40), nullable=False, default="manual")
    mode = db.Column(db.String(40), nullable=False, default="once")
    status = db.Column(db.String(40), nullable=False, default="running")
    provider = db.Column(db.String(40), nullable=False, default="")
    region = db.Column(db.String(80), nullable=False, default="")
    host_json = db.Column("host", db.JSON, nullable=False, default=dict)
    targets_json = db.Column("targets", db.JSON, nullable=False, default=dict)
    evidence_json = db.Column("evidence", db.JSON, nullable=False, default=dict)
    findings_json = db.Column("findings", db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_inspection_runs_engagement_created", "engagement_id", "created_at"),
        db.Index("ix_inspection_runs_job", "job_id"),
    )


class JobRunModel(db.Model):
    __tablename__ = "job_runs"

    id = db.Column(db.String(64), primary_key=True)
    action = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    target_type = db.Column(db.String(80), nullable=False, default="system")
    target_id = db.Column(db.String(120), nullable=False, default="seed")
    requested_by = db.Column(db.String(120), nullable=False, default="system")
    input = db.Column(db.JSON, nullable=False, default=dict)
    artifact_refs = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_job_runs_target_id_created_id", "target_id", "created_at", "id"),
        db.Index("ix_job_runs_target_created_id", "target", "created_at", "id"),
    )


class JobEventModel(db.Model):
    __tablename__ = "job_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(db.String(64), db.ForeignKey("job_runs.id"), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(40), nullable=False)
    message = db.Column(db.String(400), nullable=False)
    data = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_job_events_job_sequence", "job_id", "sequence"),
    )


class DeploymentRevisionModel(db.Model):
    __tablename__ = "deployment_revisions"

    id = db.Column(db.String(120), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    revision_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(40), nullable=False)
    template_id = db.Column(db.String(80), nullable=False)
    input_parameters = db.Column(db.JSON, nullable=False, default=dict)
    resolved_topology = db.Column(db.JSON, nullable=False, default=dict)
    run_intent = db.Column(db.JSON, nullable=False, default=list)
    validation_gates = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class CredentialModel(db.Model):
    __tablename__ = "credentials"

    id = db.Column(db.String(80), primary_key=True)
    provider = db.Column(db.String(40), nullable=False)
    alias = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="active")
    description = db.Column(db.Text, nullable=False, default="")
    encrypted_secret = db.Column(db.Text, nullable=False)
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.UniqueConstraint("provider", "alias", name="uq_credentials_provider_alias"),
    )


class SketchSshKeyModel(db.Model):
    __tablename__ = "sketch_ssh_keys"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    private_key_name = db.Column(db.String(200), nullable=False)
    public_key_name = db.Column(db.String(200), nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    encrypted_public_key = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String(120), nullable=False)
    retired_keys = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class SketchTransportSshKeyModel(db.Model):
    """Channel-only identity; deliberately independent from bootstrap access."""

    __tablename__ = "sketch_transport_ssh_keys"

    engagement_id = db.Column(
        db.String(64), db.ForeignKey("engagements.id"), primary_key=True
    )
    private_key_name = db.Column(db.String(200), nullable=False)
    public_key_name = db.Column(db.String(200), nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    encrypted_public_key = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String(120), nullable=False)
    retired_keys = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class SketchChainModel(db.Model):
    __tablename__ = "sketch_chains"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    chain_id = db.Column(db.String(120), nullable=False)
    assigned_proxy = db.Column(db.String(80), nullable=False)
    middle_provider = db.Column(db.String(40), nullable=False)
    middle_region = db.Column(db.String(80), nullable=False)
    middle_size = db.Column(db.String(80), nullable=False)
    edge_provider = db.Column(db.String(40), nullable=False)
    edge_region = db.Column(db.String(80), nullable=False)
    edge_size = db.Column(db.String(80), nullable=False)
    edge_count = db.Column(db.Integer, nullable=False, default=1)
    edge_intents = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(db.String(40), nullable=False, default="pending")
    burned = db.Column(db.Boolean, nullable=False, default=False)
    burned_note = db.Column(db.Text, nullable=False, default="")
    deploy_job_id = db.Column(db.String(64), nullable=False, default="")
    teardown_job_id = db.Column(db.String(64), nullable=False, default="")
    terraform_working_directory = db.Column(db.Text, nullable=False, default="")
    nodes = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.UniqueConstraint("engagement_id", "chain_id", name="uq_sketch_chains_engagement_chain"),
    )


class EngagementServiceModel(db.Model):
    __tablename__ = "engagement_services"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    service_id = db.Column(db.String(120), nullable=False)
    service_type = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    proxy_id = db.Column(db.String(80), nullable=False, default="")
    status = db.Column(db.String(40), nullable=False, default="pending")
    config = db.Column(db.JSON, nullable=False, default=dict)
    apply_job_id = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.UniqueConstraint("engagement_id", "service_id", name="uq_engagement_services_engagement_service"),
    )


class ProviderCatalogCacheModel(db.Model):
    __tablename__ = "provider_catalog_cache"

    provider = db.Column(db.String(40), primary_key=True)
    catalog = db.Column(db.JSON, nullable=False, default=dict)
    source = db.Column(db.String(40), nullable=False, default="live")
    warnings = db.Column(db.JSON, nullable=False, default=list)
    cached_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)


class ProviderRegionPolicyModel(db.Model):
    __tablename__ = "provider_region_policies"

    provider = db.Column(db.String(40), primary_key=True)
    allowed_regions = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class ProviderResourceRecordModel(db.Model):
    __tablename__ = "provider_resource_records"

    id = db.Column(db.String(240), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    engagement_name = db.Column(db.String(200), nullable=False, default="")
    provider = db.Column(db.String(40), nullable=False)
    resource_type = db.Column(db.String(80), nullable=False)
    resource_id = db.Column(db.String(240), nullable=False, default="")
    name = db.Column(db.String(240), nullable=False, default="")
    region = db.Column(db.String(80), nullable=False, default="")
    lifecycle_state = db.Column(db.String(80), nullable=False, default="unknown")
    status = db.Column(db.String(40), nullable=False, default="tracked")
    source = db.Column(db.String(80), nullable=False, default="provider_inventory")
    metadata_json = db.Column("metadata", db.JSON, nullable=False, default=dict)
    adoption_job_id = db.Column(db.String(64), nullable=False, default="")
    destroyed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    adopted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_provider_resource_records_engagement", "engagement_id"),
        db.Index("ix_provider_resource_records_resource", "provider", "resource_type", "resource_id"),
    )


class TeamMemberModel(db.Model):
    __tablename__ = "team_members"

    id = db.Column(db.String(80), primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    display_name = db.Column(db.String(200), nullable=False, default="")
    email = db.Column(db.String(240), nullable=False, default="")
    status = db.Column(db.String(40), nullable=False, default="active")
    desired_uid = db.Column(db.Integer, nullable=True)
    default_infra_groups = db.Column(db.JSON, nullable=False, default=list)
    global_roles = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    deactivated_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (db.Index("ux_team_members_desired_uid", "desired_uid", unique=True),)


class OperatorUidAllocationModel(db.Model):
    __tablename__ = "operator_uid_allocation"

    id = db.Column(db.Integer, primary_key=True)
    high_water_uid = db.Column(db.Integer, nullable=False)


class TeamMemberSshKeyModel(db.Model):
    __tablename__ = "team_member_ssh_keys"

    id = db.Column(db.String(80), primary_key=True)
    member_id = db.Column(db.String(80), db.ForeignKey("team_members.id"), nullable=False)
    label = db.Column(db.String(160), nullable=False, default="")
    public_key = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String(160), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="active")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    retired_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_team_member_ssh_keys_member", "member_id"),
        db.UniqueConstraint("member_id", "fingerprint", name="uq_team_member_ssh_keys_member_fingerprint"),
    )


class EngagementTeamMembershipModel(db.Model):
    __tablename__ = "engagement_team_memberships"

    id = db.Column(db.String(80), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    member_id = db.Column(db.String(80), db.ForeignKey("team_members.id"), nullable=False)
    app_privileges = db.Column(db.JSON, nullable=False, default=list)
    infra_access_enabled = db.Column(db.Boolean, nullable=False, default=True)
    infra_groups_override = db.Column(db.JSON, nullable=True)
    target_scope = db.Column(db.String(80), nullable=False, default="homebase_and_proxies")
    status = db.Column(db.String(40), nullable=False, default="active")
    infrastructure_state = db.Column(db.String(40), nullable=False, default="pending_enable")
    apply_job_id = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    removed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_engagement_team_memberships_engagement", "engagement_id"),
        db.Index("ix_engagement_team_memberships_member", "member_id"),
        db.UniqueConstraint("engagement_id", "member_id", name="uq_engagement_team_memberships_engagement_member"),
    )


class AccessAuditEventModel(db.Model):
    __tablename__ = "access_audit_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    actor_user_id = db.Column(db.String(120), nullable=False, default="operator")
    action = db.Column(db.String(120), nullable=False)
    target_type = db.Column(db.String(80), nullable=False)
    target_id = db.Column(db.String(160), nullable=False)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=True)
    summary = db.Column(db.Text, nullable=False, default="")
    metadata_json = db.Column("metadata", db.JSON, nullable=False, default=dict)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_access_audit_events_engagement", "engagement_id"),
        db.Index("ix_access_audit_events_target", "target_type", "target_id"),
    )


class AuthenticationCredentialModel(db.Model):
    __tablename__ = "authentication_credentials"

    id = db.Column(db.String(80), primary_key=True)
    team_member_id = db.Column(
        db.String(80),
        db.ForeignKey("team_members.id"),
        nullable=False,
        unique=True,
    )
    password_hash = db.Column(db.Text, nullable=False)
    roles_json = db.Column("roles", db.JSON, nullable=False, default=list)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_authentication_credentials_member", "team_member_id"),
    )


class AuthenticationSessionModel(db.Model):
    __tablename__ = "authentication_sessions"

    id = db.Column(db.String(80), primary_key=True)
    credential_id = db.Column(
        db.String(80),
        db.ForeignKey("authentication_credentials.id"),
        nullable=False,
    )
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    csrf_token_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=False)
    absolute_expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    idle_expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revocation_reason = db.Column(db.String(120), nullable=False, default="")

    __table_args__ = (
        db.Index("ix_authentication_sessions_credential", "credential_id"),
        db.Index("ix_authentication_sessions_expiry", "absolute_expires_at", "idle_expires_at"),
    )


class AuthenticationAuditEventModel(db.Model):
    __tablename__ = "authentication_audit_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    action = db.Column(db.String(120), nullable=False)
    outcome = db.Column(db.String(40), nullable=False)
    actor = db.Column(db.String(160), nullable=False, default="system")
    credential_id = db.Column(
        db.String(80),
        db.ForeignKey("authentication_credentials.id"),
        nullable=True,
    )
    username = db.Column(db.String(80), nullable=False, default="")
    session_id = db.Column(db.String(80), nullable=False, default="")
    metadata_json = db.Column("metadata", db.JSON, nullable=False, default=dict)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_authentication_audit_credential", "credential_id"),
        db.Index("ix_authentication_audit_created", "created_at"),
    )


class DomainAssetModel(db.Model):
    __tablename__ = "domain_assets"

    id = db.Column(db.String(80), primary_key=True)
    domain_name = db.Column(db.String(253), nullable=False, unique=True)
    registrar = db.Column(db.String(80), nullable=False, default="namecheap")
    registration_started_at = db.Column(db.String(80), nullable=False, default="")
    expiration_at = db.Column(db.String(80), nullable=False, default="")
    auto_renew = db.Column(db.Boolean, nullable=False, default=False)
    provider_status = db.Column(db.String(80), nullable=False, default="")
    notes = db.Column(db.Text, nullable=False, default="")
    risk_status = db.Column(db.String(40), nullable=False, default="clear")
    risk_flags = db.Column(db.JSON, nullable=False, default=list)
    cooldown_until = db.Column(db.String(80), nullable=False, default="")
    assignable_override = db.Column(db.Boolean, nullable=False, default=False)
    catalog_state = db.Column(db.String(40), nullable=False, default="auto")
    metadata_json = db.Column("metadata", db.JSON, nullable=False, default=dict)
    last_synced_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_domain_assets_registrar", "registrar"),
        db.Index("ix_domain_assets_risk_status", "risk_status"),
        db.Index("ix_domain_assets_catalog_state", "catalog_state"),
    )


class DomainAssignmentModel(db.Model):
    __tablename__ = "domain_assignments"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.String(80), db.ForeignKey("domain_assets.id"), nullable=False)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    engagement_name = db.Column(db.String(200), nullable=False, default="")
    purpose = db.Column(db.String(80), nullable=False, default="other")
    purpose_tags = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(db.String(40), nullable=False, default="active")
    notes = db.Column(db.Text, nullable=False, default="")
    assigned_by = db.Column(db.String(120), nullable=False, default="operator")
    released_by = db.Column(db.String(120), nullable=False, default="")
    assigned_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    released_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_domain_assignments_domain", "domain_id"),
        db.Index("ix_domain_assignments_engagement", "engagement_id"),
        db.Index("ix_domain_assignments_status", "status"),
    )


class DomainDnsSnapshotModel(db.Model):
    __tablename__ = "domain_dns_snapshots"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.String(80), db.ForeignKey("domain_assets.id"), nullable=False)
    provider = db.Column(db.String(80), nullable=False, default="namecheap")
    hosts = db.Column(db.JSON, nullable=False, default=list)
    source = db.Column(db.String(80), nullable=False, default="provider_snapshot")
    sync_job_id = db.Column(db.String(64), nullable=False, default="")
    fetched_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.Index("ix_domain_dns_snapshots_domain", "domain_id"),
        db.Index("ix_domain_dns_snapshots_fetched", "fetched_at"),
    )


class DomainDnsRecordOwnershipModel(db.Model):
    __tablename__ = "domain_dns_record_ownership"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.String(80), db.ForeignKey("domain_assets.id"), nullable=False)
    assignment_id = db.Column(db.Integer, db.ForeignKey("domain_assignments.id"), nullable=False)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    creating_job_id = db.Column(db.String(64), db.ForeignKey("job_runs.id"), nullable=False)
    snapshot_id = db.Column(db.Integer, db.ForeignKey("domain_dns_snapshots.id"), nullable=False)
    record = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    retired_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_domain_dns_record_ownership_domain", "domain_id"),
        db.Index("ix_domain_dns_record_ownership_engagement", "engagement_id"),
        db.UniqueConstraint("creating_job_id", "record", name="uq_domain_dns_record_ownership_job_record"),
    )


class EngagementCertificateProfileModel(db.Model):
    __tablename__ = "engagement_certificate_profiles"

    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), primary_key=True)
    acme_email = db.Column(db.String(320), nullable=False, default="")
    default_environment = db.Column(db.String(20), nullable=False, default="staging")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class CertificateAssetModel(db.Model):
    __tablename__ = "certificate_assets"

    id = db.Column(db.String(80), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    source = db.Column(db.String(40), nullable=False)
    target_proxy_id = db.Column(db.String(120), nullable=False)
    identifiers = db.Column(db.JSON, nullable=False, default=list)
    primary_identifier = db.Column(db.String(253), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="draft")
    current_version_id = db.Column(db.String(80), nullable=False, default="")
    last_job_id = db.Column(db.String(64), nullable=False, default="")
    notes = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_certificate_assets_engagement", "engagement_id"),
        db.UniqueConstraint("engagement_id", "name", name="uq_certificate_assets_engagement_name"),
    )


class CertificateVersionModel(db.Model):
    __tablename__ = "certificate_versions"

    id = db.Column(db.String(80), primary_key=True)
    certificate_id = db.Column(db.String(80), db.ForeignKey("certificate_assets.id"), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(40), nullable=False, default="pending")
    acme_environment = db.Column(db.String(20), nullable=False, default="")
    key_generation = db.Column(db.Integer, nullable=False, default=1)
    issuer = db.Column(db.String(500), nullable=False, default="")
    serial_number = db.Column(db.String(200), nullable=False, default="")
    fingerprint_sha256 = db.Column(db.String(128), nullable=False, default="")
    public_metadata = db.Column(db.JSON, nullable=False, default=dict)
    paths = db.Column(db.JSON, nullable=False, default=dict)
    issued_at = db.Column(db.String(80), nullable=False, default="")
    expires_at = db.Column(db.String(80), nullable=False, default="")
    revoked_at = db.Column(db.String(80), nullable=False, default="")
    last_job_id = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_certificate_versions_asset", "certificate_id"),
        db.UniqueConstraint("certificate_id", "sequence", name="uq_certificate_versions_asset_sequence"),
    )


class CertificateBindingModel(db.Model):
    __tablename__ = "certificate_bindings"

    id = db.Column(db.String(80), primary_key=True)
    engagement_id = db.Column(db.String(64), db.ForeignKey("engagements.id"), nullable=False)
    certificate_id = db.Column(db.String(80), db.ForeignKey("certificate_assets.id"), nullable=False)
    service_id = db.Column(db.String(120), nullable=False)
    channel_id = db.Column(db.String(200), nullable=False, default="")
    hostname = db.Column(db.String(253), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="bound")
    validation = db.Column(db.JSON, nullable=False, default=dict)
    last_job_id = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_certificate_bindings_asset", "certificate_id"),
        db.UniqueConstraint("engagement_id", "service_id", name="uq_certificate_bindings_engagement_service"),
    )
