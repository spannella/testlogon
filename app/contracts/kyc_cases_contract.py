from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

KYC_CONTRACT_VERSION = "2026-03-kyc-v1"
KYC_STATUS = Literal["draft", "submitted", "under_review", "needs_more_info", "approved", "rejected", "expired", "disputed"]

KycErrorCode = Literal[
    "kyc_case_not_found",
    "kyc_access_forbidden",
    "kyc_invalid_transition",
    "kyc_submit_prereq_failed",
    "kyc_case_update_conflict",
    "kyc_invalid_request",
    "kyc_admin_role_required",
    # KYD-005: dispute / reopen-and-resubmit flow
    "kyc_retry_limit_reached",
    "kyc_dispute_window_expired",
    "kyc_feature_disabled",
]


class KycErrorDetail(BaseModel):
    code: KycErrorCode
    message: str
    details: dict[str, Any] | None = None


class KycErrorEnvelope(BaseModel):
    error: KycErrorDetail


class KycCaseQuestionnaireRef(BaseModel):
    questionnaire_id: str | None = None
    version_id: str | None = None
    response_session_id: str | None = None
    response_pdf_ref: str | None = None


class KycCaseSignatureRef(BaseModel):
    packet_id: str | None = None
    status: str | None = None
    final_pdf_ref: str | None = None
    # GAP-0264: list of template packets [{template_type, packet_id, version}].
    template_packets: list[dict[str, Any]] = Field(default_factory=list)


class KycCaseReviewRef(BaseModel):
    ticket_id: str | None = None
    assigned_admin_sub: str | None = None
    decision: str | None = None
    decided_at: int | None = None
    reason_codes: list[str] = Field(default_factory=list)
    # KYD-008: dispute / retry lifecycle metadata (additive, optional).
    attempt_count: int | None = None
    dispute: dict[str, Any] | None = None
    dispute_resolution: dict[str, Any] | None = None


class KycCaseOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    kyc_case_id: str
    user_sub: str
    status: KYC_STATUS
    intake_profile: str | None = None
    questionnaire: KycCaseQuestionnaireRef = Field(default_factory=KycCaseQuestionnaireRef)
    files: list[dict[str, Any]] = Field(default_factory=list)
    signature: KycCaseSignatureRef = Field(default_factory=KycCaseSignatureRef)
    submission: dict[str, Any] = Field(default_factory=dict)
    review: KycCaseReviewRef = Field(default_factory=KycCaseReviewRef)
    # KYC-003: liveness video verification call outcome (mirrored onto the case
    # by app/services/kyc_liveness_call.py when a verifier records the result).
    verification_call: dict[str, Any] | None = None
    created_at: int
    updated_at: int
    version: int
    missing_requirements: list[str] = Field(default_factory=list)


class KycCaseEnvelope(BaseModel):
    case: KycCaseOut


class KycCaseListEnvelope(BaseModel):
    items: list[KycCaseOut]
    next_cursor: str | None = None


class KycCaseCreateRequest(BaseModel):
    intake_profile: str | None = Field(default=None, min_length=1, max_length=80)


class KycCaseDraftPatchRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    intake_profile: str | None = Field(default=None, min_length=1, max_length=80)


class KycStartQuestionnaireRequest(BaseModel):
    published_slug: str = Field(..., min_length=1, max_length=240)


class KycCaseUpdateRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    status: KYC_STATUS
    reason_codes: list[str] = Field(default_factory=list)
    decision_note: str | None = Field(default=None, max_length=2000)


class KycSubmitCaseRequest(BaseModel):
    expected_version: int = Field(..., ge=1)


class KycDisputeRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    reason: str = Field(..., min_length=1, max_length=240)
    note: str = Field(default="", max_length=2000)


class KycReopenRequest(BaseModel):
    expected_version: int = Field(..., ge=1)


class KycReadinessOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    kyc_case_id: str
    status: KYC_STATUS
    ready_to_submit: bool
    missing_requirements: list[str] = Field(default_factory=list)
    missing_hints: list[str] = Field(default_factory=list)
    checks: dict[str, bool] = Field(default_factory=dict)
    requirements: list[dict[str, Any]] = Field(default_factory=list)


class KycReadinessEnvelope(BaseModel):
    readiness: KycReadinessOut


class KycQuestionnaireStatusOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    kyc_case_id: str
    questionnaire_bound: bool
    questionnaire_id: str | None = None
    version_id: str | None = None
    response_session_id: str | None = None
    submitted: bool = False
    response_pdf_ref: str | None = None
    ready_for_submit_gate: bool = False


class KycQuestionnaireStatusEnvelope(BaseModel):
    questionnaire: KycQuestionnaireStatusOut


class KycFileAttachmentRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    path: str = Field(..., min_length=1, max_length=1024)
    file_type: Literal["selfie", "id_front", "id_back", "proof_of_address"]


class KycFileValidationOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    kyc_case_id: str
    required_types: list[str]
    present_types: list[str]
    missing_types: list[str]
    invalid_attachments: list[dict[str, Any]] = Field(default_factory=list)
    ready_for_submit_gate: bool


class KycFileValidationEnvelope(BaseModel):
    files: KycFileValidationOut


class KycLinkSignaturePacketRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    source_path: str = Field(..., min_length=1, max_length=1024)
    origin_channel: Literal["share", "message"] = "share"
    origin_ref: str | None = Field(default=None, max_length=200)


class KycSignatureStatusOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    kyc_case_id: str
    packet_id: str | None = None
    packet_status: str | None = None
    completed: bool = False
    final_pdf_ready: bool = False
    final_pdf_ref: str | None = None
    legal_notice_version: str | None = None
    legal_notice_accepted: bool = False
    ready_for_submit_gate: bool = False
    # GAP-0264: template-based KYC consent workflow stores one packet per
    # required template. Backward-compatible: empty for legacy single-packet cases.
    template_packets: list[dict[str, Any]] = Field(default_factory=list)


class KycSignatureStatusEnvelope(BaseModel):
    signature: KycSignatureStatusOut


# GAP-0262: KYC signature-template / witness router contracts.
class KycAddWitnessRequest(BaseModel):
    packet_id: str = Field(..., min_length=1)
    witness_sub: str | None = Field(
        default=None,
        description="Admin sub to add as witness. If None, uses calling user.",
    )


class KycTemplateStatusItem(BaseModel):
    template_type: str
    display_name: str
    version: str
    packet_id: str | None = None
    packet_status: str | None = None
    signed_by_applicant: bool = False
    needs_version_migration: bool = False


class KycTemplateStatusEnvelope(BaseModel):
    templates: list[KycTemplateStatusItem]
    version_migration_required: bool = False


class KycAdminQueueItem(BaseModel):
    kyc_case_id: str
    user_sub: str
    status: KYC_STATUS
    assigned_admin_sub: str | None = None
    created_at: int
    updated_at: int
    waiting_seconds: int | None = None
    risk_tier: str | None = None


class KycAdminQueueEnvelope(BaseModel):
    items: list[KycAdminQueueItem]
    next_cursor: str | None = None


class KycAdminTimelineEvent(BaseModel):
    event_type: str
    source: Literal["kyc_case", "ticket"]
    created_at: int | None = None
    actor_sub: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class KycAdminCaseDetailOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    kyc_case_id: str
    user_sub: str
    status: KYC_STATUS
    questionnaire_ref: dict[str, Any] = Field(default_factory=dict)
    files_ref: list[dict[str, Any]] = Field(default_factory=list)
    signature_ref: dict[str, Any] = Field(default_factory=dict)
    ticket_ref: dict[str, Any] = Field(default_factory=dict)
    decision_state: dict[str, Any] = Field(default_factory=dict)
    timeline: list[KycAdminTimelineEvent] = Field(default_factory=list)


class KycAdminCaseDetailEnvelope(BaseModel):
    case: KycAdminCaseDetailOut


class KycMetricsSummaryOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    funnel_counts: dict[str, int] = Field(default_factory=dict)
    review_latency_seconds: dict[str, float | None] = Field(default_factory=dict)
    stale_queue_count: int = 0
    submit_guard_failures_by_reason: dict[str, int] = Field(default_factory=dict)
    ticket_sync_counters: dict[str, int] = Field(default_factory=dict)
    ticket_sync_deadletter_count: int = 0
    ticket_sync_deadletter_oldest_age_seconds: int | None = None


class KycMetricsSummaryEnvelope(BaseModel):
    metrics: KycMetricsSummaryOut


class KycEstimatedWaitOut(BaseModel):
    """User-facing estimated review wait time (KYC-013).

    Derived from the existing admin metrics snapshot but exposes no queue
    internals — only a coarse estimate in hours and a human-readable message.
    """

    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    estimated_hours: int = Field(..., ge=1, description="Estimated hours until review")
    queue_position: int | None = Field(default=None, description="Not exposed to users")
    message: str = Field(..., description="Human-readable wait-time message")


class KycEstimatedWaitEnvelope(BaseModel):
    estimated_wait: KycEstimatedWaitOut


class KycPurgeRunOut(BaseModel):
    contract_version: Literal["2026-03-kyc-v1"] = KYC_CONTRACT_VERSION
    scanned_statuses: list[str] = Field(default_factory=list)
    purged_case_ids: list[str] = Field(default_factory=list)
    purged_count: int = 0
    dry_run: bool = False


class KycPurgeRunEnvelope(BaseModel):
    purge: KycPurgeRunOut


class KycAdminRequestInfoRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    requested_items: list[str] = Field(default_factory=list)
    note: str = Field(..., min_length=1, max_length=2000)


class KycAdminDecisionRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    decision: Literal["approve", "reject"]
    reason_codes: list[str] = Field(default_factory=list)
    note: str = Field(..., min_length=1, max_length=2000)


# ── KYC Data Encryption & Privacy (KYC-023) ────────────────────────


class EncryptedFieldOut(BaseModel):
    field_name: str
    encrypted: bool = True
    key_id: str = ""
    algorithm: str = "AES-256-GCM"
    encrypted_at: int = 0


class PiiWriteRequest(BaseModel):
    """Owner-supplied PII to encrypt onto a draft KYC case."""

    expected_version: int = Field(..., ge=1)
    pii: dict[str, str] = Field(
        ..., min_length=1, description="Map of field_name -> plaintext PII value"
    )


class PiiWriteResponse(BaseModel):
    ok: bool = True
    fields_encrypted: list[str] = Field(default_factory=list)


class PiiDecryptRequest(BaseModel):
    fields: list[str] = Field(
        ..., min_length=1, max_length=10, description="PII field names to decrypt"
    )
    reason: str = Field(
        ..., min_length=3, max_length=500,
        description="Reason for accessing PII (required for audit)",
    )


class PiiDecryptResponse(BaseModel):
    pii: dict[str, str] = Field(default_factory=dict)


class PiiMaskedResponse(BaseModel):
    pii: dict[str, str] = Field(default_factory=dict)
    fields: list[EncryptedFieldOut] = Field(default_factory=list)


class PiiAuditEvent(BaseModel):
    event_id: str
    accessor_sub: str
    accessor_display_name: str = ""
    action: str  # "decrypt", "encrypt", "mask", "delete"
    fields: list[str] = Field(default_factory=list)
    reason: str = ""
    ip_address: str = ""
    created_at: int = 0


class PiiAuditLogResponse(BaseModel):
    events: list[PiiAuditEvent] = Field(default_factory=list)
    next_cursor: str | None = None


class KeyRotationResponse(BaseModel):
    ok: bool = True
    new_version: int = 0
    fields_re_encrypted: int = 0


class KeyDestroyResponse(BaseModel):
    ok: bool = True
    keys_destroyed: int = 0
    fields_affected: int = 0


_ERROR_MESSAGES: dict[str, str] = {
    "kyc_case_not_found": "KYC case not found.",
    "kyc_access_forbidden": "You are not allowed to access this KYC case.",
    "kyc_invalid_transition": "Requested KYC state transition is invalid.",
    "kyc_submit_prereq_failed": "KYC submission prerequisites are incomplete.",
    "kyc_case_update_conflict": "KYC case was updated by another request; refresh and retry.",
    "kyc_invalid_request": "Invalid KYC request payload.",
    "kyc_admin_role_required": "Admin role required.",
    "kyc_retry_limit_reached": "You have reached the maximum number of verification attempts.",
    "kyc_dispute_window_expired": "The window to dispute this decision has closed.",
    "kyc_feature_disabled": "This KYC feature is not currently available.",
}


_ERROR_HTTP_STATUS: dict[str, int] = {
    "kyc_case_not_found": 404,
    "kyc_access_forbidden": 403,
    "kyc_invalid_transition": 409,
    "kyc_submit_prereq_failed": 409,
    "kyc_case_update_conflict": 409,
    "kyc_invalid_request": 400,
    "kyc_admin_role_required": 403,
    "kyc_retry_limit_reached": 409,
    "kyc_dispute_window_expired": 409,
    "kyc_feature_disabled": 503,
}


def kyc_error_envelope(code: KycErrorCode, *, details: dict[str, Any] | None = None, message: str | None = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message or _ERROR_MESSAGES[code],
            "details": details,
        }
    }


def kyc_error_http_status(code: KycErrorCode) -> int:
    return _ERROR_HTTP_STATUS[code]


def kyc_validation_error_envelope(exc: ValidationError) -> dict[str, Any]:
    return kyc_error_envelope(
        "kyc_invalid_request",
        details={"errors": exc.errors()},
    )


# ── KYC Tier models (KYC-009) ──────────────────────────────────────


class TierOverrideRequest(BaseModel):
    tier: int = Field(ge=0, le=4)
    reason: str = Field(min_length=5, max_length=500)


class TierDetailsOut(BaseModel):
    user_sub: str
    current_tier: int
    tier_name: str
    updated_at: int | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


class TierRequirementsOut(BaseModel):
    target_tier: int
    current_tier: int
    met: list[str]
    unmet: list[str]
    eligible: bool
