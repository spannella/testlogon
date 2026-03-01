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
