from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.config_schema import DeploymentConfigV1


class SessionStatus(str, Enum):
    DRAFT = 'draft'
    VALIDATED = 'validated'
    READY = 'ready'
    DEPLOYING = 'deploying'
    DEPLOYED = 'deployed'
    FAILED = 'failed'


class ExecutionMode(str, Enum):
    LIVE = 'live'
    DRY_RUN = 'dry_run'
    MOCK = 'mock'


class SessionMetadata(BaseModel):
    env: str = Field(min_length=1)
    region: str = Field(min_length=1)
    created_by: str = Field(min_length=1)


class DeploymentSessionCreate(BaseModel):
    metadata: SessionMetadata
    config: DeploymentConfigV1
    execution_mode: ExecutionMode = ExecutionMode.LIVE


class DeploymentSessionUpdate(BaseModel):
    metadata: SessionMetadata | None = None
    config: DeploymentConfigV1 | None = None
    status: SessionStatus | None = None
    execution_mode: ExecutionMode | None = None


class DeploymentSession(BaseModel):
    session_id: str
    metadata: SessionMetadata
    config: DeploymentConfigV1
    status: SessionStatus
    execution_mode: ExecutionMode
    created_at: datetime
    updated_at: datetime


class CredentialTestRequest(BaseModel):
    providers: list[str] | None = None


class CredentialProviderResult(BaseModel):
    provider: str
    status: str
    message: str
    attempts: int


class CredentialTestResponse(BaseModel):
    session_id: str
    results: list[CredentialProviderResult]


class GeneratedArtifact(BaseModel):
    name: str
    version: str
    hash: str
    generated_at: datetime
    content: str


class ArtifactDiffEntry(BaseModel):
    path: str
    before: str
    after: str


class GenerateArtifactsResponse(BaseModel):
    session_id: str
    run_id: str
    artifacts: list[GeneratedArtifact]
    diff: list[ArtifactDiffEntry]


class ArtifactRecord(BaseModel):
    run_id: str
    session_id: str
    name: str
    version: str
    hash: str
    generated_at: datetime
    storage_key: str


class ArtifactListItem(BaseModel):
    run_id: str
    name: str
    version: str
    hash: str
    generated_at: datetime
    signed_download_url: str


class ArtifactListResponse(BaseModel):
    session_id: str
    artifacts: list[ArtifactListItem]


class ArtifactDownloadResponse(BaseModel):
    session_id: str
    run_id: str
    artifact_name: str
    version: str
    hash: str
    content: str


class DeployStatus(str, Enum):
    SUCCESS = 'success'
    FAILED = 'failed'


class DeployEvent(BaseModel):
    stage: str
    status: str
    message: str
    details: dict[str, str] | None = None
    created_at: datetime


class DeployResponse(BaseModel):
    session_id: str
    run_id: str
    status: str
    events: list[DeployEvent]
    outputs: dict[str, str]


class DryRunStep(BaseModel):
    category: str
    action: str
    simulated: bool = True


class DryRunResponse(BaseModel):
    session_id: str
    execution_mode: str
    simulated: bool
    validation_summary: dict[str, int | bool]
    artifact_simulation: list[GeneratedArtifact]
    deploy_simulation_status: str
    deploy_simulation_events: list[DeployEvent]
    would_do_steps: list[DryRunStep]
    simulated_outputs: dict[str, str]


class MockDeployResponse(BaseModel):
    session_id: str
    execution_mode: str
    scenario: str
    simulated: bool
    status: str
    events: list[DeployEvent]
    synthetic_outputs: dict[str, str]


class AuditEntry(BaseModel):
    session_id: str
    actor_email: str
    actor_role: str
    action: str
    created_at: datetime
    details: dict[str, str] | None = None


class AuditEntriesResponse(BaseModel):
    session_id: str
    entries: list[AuditEntry]


class ApprovalDecision(str, Enum):
    APPROVE = 'approve'
    REJECT = 'reject'


class ApprovalRecord(BaseModel):
    session_id: str
    actor_email: str
    decision: ApprovalDecision
    comment: str | None = None
    created_at: datetime


class ApprovalRequest(BaseModel):
    decision: ApprovalDecision
    comment: str | None = None


class ApprovalResponse(BaseModel):
    session_id: str
    approvals_required: int
    approved_by: list[str]
    approvals: list[ApprovalRecord]


class SessionEvent(BaseModel):
    event_type: str
    created_at: datetime
    actor_email: str | None = None
    status: str | None = None
    message: str
    details: dict[str, str] | None = None


class SessionEventsResponse(BaseModel):
    session_id: str
    events: list[SessionEvent]


class IdentityProvider(BaseModel):
    provider_id: str
    provider_type: str
    issuer: str
    metadata_url: str | None = None
    client_id: str
    secret_ref: str
    enabled: bool = False
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class IdentityProviderRoleMapping(BaseModel):
    mapping_id: int
    provider_id: str
    external_group_or_claim: str
    internal_role: str
    priority: int
    created_at: datetime


class ExternalIdentity(BaseModel):
    identity_id: int
    user_id: str
    provider_id: str
    external_subject: str
    external_tenant: str
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AdminSSONormalizedIdentity(BaseModel):
    sub: str
    email: str | None = None
    groups: list[str] = Field(default_factory=list)
    tenant_id: str


class AdminSSOCallbackResponse(BaseModel):
    provider_id: str
    auth_method: str = 'ad_sso'
    identity: AdminSSONormalizedIdentity
    session_token: str
    session_role: str
    linked_user_id: str
    linked_external_identity_id: int


class AdminSSORoleMappingSimulationResponse(BaseModel):
    provider_id: str
    groups: list[str]
    resolved_role: str | None = None
    mapping_id: int | None = None
    reason_code: str


class IdentityProviderConfigUpsertRequest(BaseModel):
    provider_id: str
    provider_type: str
    issuer: str
    metadata_url: str | None = None
    client_id: str
    secret_ref: str


class IdentityProviderConfigUpdateRequest(BaseModel):
    provider_type: str | None = None
    issuer: str | None = None
    metadata_url: str | None = None
    client_id: str | None = None
    secret_ref: str | None = None


class IdentityProviderConfigResponse(BaseModel):
    provider: IdentityProvider
    config_status: str


class IdentityProviderConfigListResponse(BaseModel):
    providers: list[IdentityProviderConfigResponse]


class DevDirectoryUser(BaseModel):
    user_id: str
    username: str
    email: str | None = None
    enabled: bool = True
    groups: list[str] = Field(default_factory=list)


class DevDirectoryUsersResponse(BaseModel):
    users: list[DevDirectoryUser]


class DevDirectoryGroupsResponse(BaseModel):
    groups: list[str]


class DevDirectoryUserCreateRequest(BaseModel):
    username: str
    email: str | None = None
    password: str
    groups: list[str] = Field(default_factory=list)


class DevDirectoryUserUpdateRequest(BaseModel):
    email: str | None = None
    enabled: bool | None = None


class DevDirectoryUserGroupRequest(BaseModel):
    group_name: str


class DevDirectoryActivityEvent(BaseModel):
    event_id: int
    event_type: str = 'callback'
    auth_method: str
    outcome: str
    actor_email: str | None = None
    provider_id: str | None = None
    external_subject: str | None = None
    external_tenant: str | None = None
    mapped_role: str | None = None
    failure_reason: str | None = None
    troubleshooting_category: str | None = None
    troubleshooting_hint: str | None = None
    created_at: str


class DevDirectoryActivityResponse(BaseModel):
    events: list[DevDirectoryActivityEvent]
