from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
import hashlib
import json
from collections import defaultdict

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.contracts.kyc_cases_contract import (
    KycAdminQueueEnvelope,
    KycAdminCaseDetailEnvelope,
    KycAdminRequestInfoRequest,
    KycAdminDecisionRequest,
    KycMetricsSummaryEnvelope,
    KycEstimatedWaitEnvelope,
    KycPurgeRunEnvelope,
    KycCaseCreateRequest,
    KycCaseDraftPatchRequest,
    KycCaseEnvelope,
    KycFileAttachmentRequest,
    KycLinkSignaturePacketRequest,
    KycFileValidationEnvelope,
    KycCaseListEnvelope,
    KycReadinessEnvelope,
    KycSubmitCaseRequest,
    KycSignatureStatusEnvelope,
    KycQuestionnaireStatusEnvelope,
    KycStartQuestionnaireRequest,
    kyc_error_envelope,
    kyc_error_http_status,
)
from app.models import (
    AdminFaceComparisonOut,
    FaceComparisonListOut,
    FaceComparisonOverrideRequest,
    FaceComparisonOverrideResultOut,
    FaceComparisonResultOut,
)
from app.services.kyc_cases import KycCaseConflictError, KycCaseValidationError, STORE
from app.services.alerts import audit_event
from app.services.filemanager import get_node, norm_path
from app.services.questionnaires_repository import DynamoQuestionnaireRepository
from app.services.signature_packet_store import (
    create_draft_packet,
    get_packet,
    get_packet_artifact,
    list_packet_signers,
)
from app.routers.tickets import get_kyc_sync_snapshot
from app.services.tickets import STORE as TICKET_STORE, TicketStateError
from app.services.sessions import require_ui_session
from uuid import uuid4
from app.core.settings import S

router = APIRouter(prefix="/v1/kyc/cases", tags=["kyc-cases"])
QNR_REPO = DynamoQuestionnaireRepository()
_KYC_REQUIRED_FILE_TYPES = ["selfie", "id_front", "id_back"]
_KYC_ALLOWED_FILE_TYPES = set(_KYC_REQUIRED_FILE_TYPES + ["proof_of_address"])
_SUBMIT_GUARD_FAILURES: defaultdict[str, int] = defaultdict(int)


def _raise_kyc_error(code: str, *, details: dict | None = None) -> None:
    raise HTTPException(status_code=kyc_error_http_status(code), detail=kyc_error_envelope(code, details=details))


def _wrap_case(item: dict) -> KycCaseEnvelope:
    return KycCaseEnvelope.model_validate({"case": item})


def _is_scoped_admin_for_case(user: AuthenticatedUser, case: dict) -> bool:
    role = normalize_role(user.role)
    if role == Role.ROOT:
        return True
    if role != Role.ADMIN:
        return False
    assigned_admin = str((case.get("review") or {}).get("assigned_admin_sub") or "").strip()
    return bool(assigned_admin and assigned_admin == user.sub)


def _is_purged_case(case: dict) -> bool:
    return bool((case.get("review") or {}).get("purged_at"))


def _request_correlation_id(request: Request) -> str:
    return (
        str(request.headers.get("x-request-id") or "").strip()
        or str(request.headers.get("x-correlation-id") or "").strip()
        or f"kyc_req_{uuid4().hex[:12]}"
    )


def _audit_state_transition(
    *,
    event_name: str,
    actor_sub: str,
    request: Request,
    case_id: str,
    from_status: str | None,
    to_status: str | None,
    action: str,
    **extra,
) -> None:
    audit_event(
        event_name,
        actor_sub,
        request,
        outcome="success",
        namespace="kyc",
        kyc_case_id=case_id,
        transition={"from": from_status, "to": to_status, "action": action},
        correlation_id=_request_correlation_id(request),
        **extra,
    )


def _emit_kyc_metric(request: Request, *, metric_name: str, value: float = 1.0, tags: dict[str, str] | None = None) -> None:
    audit_event(
        "kyc_metric",
        "system",
        request,
        outcome="success",
        namespace="kyc_metrics",
        metric_name=metric_name,
        metric_value=value,
        metric_tags=(tags or {}),
        correlation_id=_request_correlation_id(request),
    )


def _questionnaire_status_for_case(case: dict, *, include_submit_gate: bool = True) -> dict:
    qref = case.get("questionnaire") or {}
    questionnaire_id = str(qref.get("questionnaire_id") or "").strip() or None
    version_id = str(qref.get("version_id") or "").strip() or None
    response_session_id = str(qref.get("response_session_id") or "").strip() or None
    response_pdf_ref = str(qref.get("response_pdf_ref") or "").strip() or None
    if not questionnaire_id or not response_session_id:
        return {
            "kyc_case_id": case.get("kyc_case_id"),
            "questionnaire_bound": False,
            "questionnaire_id": questionnaire_id,
            "version_id": version_id,
            "response_session_id": response_session_id,
            "submitted": False,
            "response_pdf_ref": response_pdf_ref,
            "ready_for_submit_gate": False,
        }

    session = QNR_REPO.get_response_session(questionnaire_id=questionnaire_id, response_session_id=response_session_id)
    submitted = bool(session and str(session.get("status") or "") == "submitted")
    return {
        "kyc_case_id": case.get("kyc_case_id"),
        "questionnaire_bound": True,
        "questionnaire_id": questionnaire_id,
        "version_id": version_id,
        "response_session_id": response_session_id,
        "submitted": submitted,
        "response_pdf_ref": response_pdf_ref,
        "ready_for_submit_gate": submitted if include_submit_gate else False,
    }


def _validate_file_requirements(case: dict) -> dict:
    files = list(case.get("files") or [])
    invalid: list[dict] = []
    present: list[str] = []
    present_set: set[str] = set()
    for item in files:
        file_type = str(item.get("type") or "").strip()
        path = str(item.get("path") or "").strip()
        if not file_type or not path:
            invalid.append({"type": file_type or None, "path": path or None, "reason": "missing_type_or_path"})
            continue
        if file_type not in _KYC_ALLOWED_FILE_TYPES:
            invalid.append({"type": file_type, "path": path, "reason": "unsupported_type"})
            continue
        if file_type not in present_set:
            present.append(file_type)
            present_set.add(file_type)

    missing = [f for f in _KYC_REQUIRED_FILE_TYPES if f not in present_set]
    return {
        "kyc_case_id": case.get("kyc_case_id"),
        "required_types": list(_KYC_REQUIRED_FILE_TYPES),
        "present_types": present,
        "missing_types": missing,
        "invalid_attachments": invalid,
        "ready_for_submit_gate": (not missing and not invalid),
    }


def _signature_status_for_case(case: dict) -> dict:
    sref = case.get("signature") or {}
    packet_id = str(sref.get("packet_id") or "").strip() or None
    legal_notice_version = str(sref.get("legal_notice_version") or S.signature_packet_legal_notice_version).strip() or None
    if not packet_id:
        return {
            "kyc_case_id": case.get("kyc_case_id"),
            "packet_id": None,
            "packet_status": None,
            "completed": False,
            "final_pdf_ready": False,
            "final_pdf_ref": None,
            "legal_notice_version": legal_notice_version,
            "legal_notice_accepted": False,
            "ready_for_submit_gate": False,
        }
    packet = get_packet(packet_id) or {}
    packet_status = str(packet.get("status") or "")
    completed = packet_status == "completed"
    artifact = get_packet_artifact(packet_id) or {}
    final_ready = bool(artifact and str(artifact.get("status") or "") == "ready")
    final_ref = f"packet:{packet_id}:final-pdf" if final_ready else None
    signers = list_packet_signers(packet_id)
    accepted = False
    if signers:
        accepted = all(str(s.get("legal_notice_accepted_version") or "") == str(legal_notice_version or "") for s in signers)
    return {
        "kyc_case_id": case.get("kyc_case_id"),
        "packet_id": packet_id,
        "packet_status": packet_status or None,
        "completed": completed,
        "final_pdf_ready": final_ready,
        "final_pdf_ref": final_ref,
        "legal_notice_version": legal_notice_version,
        "legal_notice_accepted": accepted,
        "ready_for_submit_gate": bool(completed and final_ready),
    }


def _readiness_for_case(case: dict) -> dict:
    questionnaire = _questionnaire_status_for_case(case, include_submit_gate=False)
    files = _validate_file_requirements(case)
    signature = _signature_status_for_case(case)

    checks = {
        "questionnaire_submitted": bool(questionnaire.get("submitted")),
        "required_files": bool(files.get("ready_for_submit_gate")),
        "signature_completed": bool(signature.get("ready_for_submit_gate")),
    }
    hint_map = {
        "questionnaire_submitted": "Submit the linked questionnaire to continue.",
        "required_files": "Attach all required identity files: selfie, id_front, id_back.",
        "signature_completed": "Complete the consent signature packet and wait for final PDF generation.",
    }

    requirements: list[dict] = [
        {
            "key": "questionnaire_submitted",
            "ready": checks["questionnaire_submitted"],
            "missing": ([] if checks["questionnaire_submitted"] else ["questionnaire_submission"]),
            "hint": hint_map["questionnaire_submitted"],
            "refs": {
                "questionnaire_id": questionnaire.get("questionnaire_id"),
                "response_session_id": questionnaire.get("response_session_id"),
                "response_pdf_ref": questionnaire.get("response_pdf_ref"),
            },
        },
        {
            "key": "required_files",
            "ready": checks["required_files"],
            "missing": list(files.get("missing_types") or []),
            "hint": hint_map["required_files"],
            "refs": {
                "present_types": ",".join(files.get("present_types") or []),
            },
        },
        {
            "key": "signature_completed",
            "ready": checks["signature_completed"],
            "missing": (
                []
                if checks["signature_completed"]
                else ["signature_completion", "signature_final_pdf"]
            ),
            "hint": hint_map["signature_completed"],
            "refs": {
                "packet_id": signature.get("packet_id"),
                "final_pdf_ref": signature.get("final_pdf_ref"),
            },
        },
    ]
    missing_requirements = [item["key"] for item in requirements if not item["ready"]]
    missing_hints = [hint_map[key] for key in missing_requirements]

    return {
        "kyc_case_id": case.get("kyc_case_id"),
        "status": case.get("status"),
        "ready_to_submit": all(checks.values()),
        "missing_requirements": missing_requirements,
        "missing_hints": missing_hints,
        "checks": checks,
        "requirements": requirements,
    }


def _ensure_review_ticket(case: dict) -> dict:
    review = dict(case.get("review") or {})
    existing_ticket_id = str(review.get("ticket_id") or "").strip()
    if existing_ticket_id:
        return case

    submission = dict(case.get("submission") or {})
    evidence_snapshot = dict(submission.get("evidence_snapshot") or {})
    kyc_case_id = str(case.get("kyc_case_id") or "")
    user_sub = str(case.get("user_sub") or "")
    stable_ticket_id = f"tkt_kyc_{kyc_case_id}"
    subject = f"KYC review required: {kyc_case_id}"
    description = (
        f"KYC submission ready for review.\n"
        f"case_id={kyc_case_id}\n"
        f"questionnaire_session={((evidence_snapshot.get('questionnaire') or {}).get('response_session_id') or '')}\n"
        f"questionnaire_pdf_ref={((evidence_snapshot.get('questionnaire') or {}).get('response_pdf_ref') or '')}\n"
        f"files_present={','.join((evidence_snapshot.get('files') or {}).get('present_types') or [])}\n"
        f"signature_packet_id={((evidence_snapshot.get('signature') or {}).get('packet_id') or '')}\n"
        f"signature_final_pdf_ref={((evidence_snapshot.get('signature') or {}).get('final_pdf_ref') or '')}\n"
        f"evidence_hash={submission.get('evidence_hash') or ''}"
    )
    ticket = TICKET_STORE.create_ticket(
        owner_sub=user_sub,
        subject=subject,
        description=description,
        space_id=S.kyc_review_ticket_space_id or None,
        ticket_id=stable_ticket_id,
        category=S.kyc_review_ticket_category,
        metadata={
            "namespace": "kyc",
            "kyc_case_id": kyc_case_id,
            "evidence_hash": submission.get("evidence_hash"),
            "questionnaire_ref": evidence_snapshot.get("questionnaire"),
            "files_ref": evidence_snapshot.get("files"),
            "signature_ref": evidence_snapshot.get("signature"),
        },
    )
    ticket_id = str(ticket.get("ticket_id") or stable_ticket_id)
    try:
        updated = STORE.update_case_links(
            case_id=kyc_case_id,
            owner_sub=user_sub,
            expected_version=int(case.get("version") or 0),
            review_ticket_id=ticket_id,
        )
        if updated:
            return updated
    except KycCaseConflictError:
        latest = STORE.get_case(kyc_case_id)
        if latest and str((latest.get("review") or {}).get("ticket_id") or "").strip():
            return latest
        raise
    return case


def _build_admin_case_detail(case: dict) -> dict:
    review = dict(case.get("review") or {})
    questionnaire = dict(case.get("questionnaire") or {})
    signature = dict(case.get("signature") or {})
    files = [dict(item) for item in list(case.get("files") or []) if isinstance(item, dict)]
    ticket_id = str(review.get("ticket_id") or "").strip() or None
    ticket = TICKET_STORE.get_ticket(ticket_id) if ticket_id else None

    timeline: list[dict] = [
        {
            "event_type": "kyc_case_created",
            "source": "kyc_case",
            "created_at": case.get("created_at"),
            "actor_sub": case.get("user_sub"),
            "details": {"status": case.get("status")},
        },
        {
            "event_type": "kyc_case_updated",
            "source": "kyc_case",
            "created_at": case.get("updated_at"),
            "actor_sub": (review.get("last_actor_sub") or case.get("user_sub")),
            "details": {"status": case.get("status"), "version": case.get("version")},
        },
    ]
    if ticket:
        timeline.append(
            {
                "event_type": "ticket_opened",
                "source": "ticket",
                "created_at": ticket.get("created_at"),
                "actor_sub": ticket.get("owner_sub"),
                "details": {
                    "ticket_id": ticket.get("ticket_id"),
                    "ticket_status": ticket.get("status"),
                },
            }
        )
        for act in list(ticket.get("activity") or []):
            timeline.append(
                {
                    "event_type": str(act.get("type") or "ticket_activity"),
                    "source": "ticket",
                    "created_at": act.get("created_at"),
                    "actor_sub": act.get("actor_sub"),
                    "details": {
                        "status": act.get("status"),
                        "assignee_sub": act.get("assignee_sub"),
                    },
                }
            )

    timeline.sort(key=lambda e: int(e.get("created_at") or 0))
    return {
        "kyc_case_id": case.get("kyc_case_id"),
        "user_sub": case.get("user_sub"),
        "status": case.get("status"),
        "questionnaire_ref": {
            "questionnaire_id": questionnaire.get("questionnaire_id"),
            "version_id": questionnaire.get("version_id"),
            "response_session_id": questionnaire.get("response_session_id"),
            "response_pdf_ref": questionnaire.get("response_pdf_ref"),
        },
        "files_ref": [
            {
                "type": item.get("type"),
                "path": item.get("path"),
                "verification_state": item.get("verification_state"),
                "uploaded_at": item.get("uploaded_at"),
            }
            for item in files
        ],
        "signature_ref": {
            "packet_id": signature.get("packet_id"),
            "status": signature.get("status"),
            "final_pdf_ref": signature.get("final_pdf_ref"),
            "legal_notice_version": signature.get("legal_notice_version"),
            "legal_notice_accepted": signature.get("legal_notice_accepted"),
        },
        "ticket_ref": {
            "ticket_id": ticket_id,
            "status": (ticket or {}).get("status"),
            "assigned_admin_sub": ((ticket or {}).get("assigned_admin_sub") or review.get("assigned_admin_sub")),
            "last_message_at": (ticket or {}).get("updated_at"),
        },
        "decision_state": {
            "decision": review.get("decision"),
            "decided_at": review.get("decided_at"),
            "reason_codes": list(review.get("reason_codes") or []),
            "assigned_admin_sub": review.get("assigned_admin_sub"),
        },
        "timeline": timeline,
    }


def _request_info_message_body(*, request_hash: str, requested_items: list[str], note: str) -> str:
    items = ", ".join(requested_items) if requested_items else "additional documentation"
    return (
        f"[kyc_request_info:{request_hash}]\n"
        f"KYC reviewer requested follow-up information.\n"
        f"Requested items: {items}\n"
        f"Reviewer note: {note}"
    )


def _ensure_request_info_ticket_message(case: dict, *, admin_sub: str, request_hash: str, requested_items: list[str], note: str) -> None:
    review = dict(case.get("review") or {})
    ticket_id = str(review.get("ticket_id") or "").strip()
    if not ticket_id:
        return
    ticket = TICKET_STORE.get_ticket(ticket_id) or {}
    marker = f"[kyc_request_info:{request_hash}]"
    for msg in list(ticket.get("messages") or []):
        if marker in str(msg.get("body") or ""):
            return

    body = _request_info_message_body(request_hash=request_hash, requested_items=requested_items, note=note)
    email_targets = sorted({str(case.get("user_sub") or ""), str(ticket.get("assigned_admin_sub") or "")} - {""})
    last_exc: Exception | None = None
    for _ in range(3):
        try:
            TICKET_STORE.add_message(
                ticket_id=ticket_id,
                sender_sub=admin_sub,
                sender_role="admin",
                body=body,
                email_targets=email_targets,
            )
            return
        except TicketStateError as exc:
            last_exc = exc
    if last_exc:
        raise last_exc


def _decision_message_body(*, decision_hash: str, decision: str, reason_codes: list[str], note: str) -> str:
    reasons = ", ".join(reason_codes) if reason_codes else "none"
    return (
        f"[kyc_decision:{decision_hash}]\n"
        f"KYC decision recorded: {decision.upper()}.\n"
        f"Reason codes: {reasons}\n"
        f"Reviewer note: {note}"
    )


def _ensure_decision_ticket_updates(case: dict, *, admin_sub: str, decision_hash: str, decision: str, reason_codes: list[str], note: str) -> None:
    review = dict(case.get("review") or {})
    ticket_id = str(review.get("ticket_id") or "").strip()
    if not ticket_id:
        return
    ticket = TICKET_STORE.get_ticket(ticket_id) or {}
    marker = f"[kyc_decision:{decision_hash}]"
    for msg in list(ticket.get("messages") or []):
        if marker in str(msg.get("body") or ""):
            return

    body = _decision_message_body(decision_hash=decision_hash, decision=decision, reason_codes=reason_codes, note=note)
    email_targets = sorted({str(case.get("user_sub") or ""), str(ticket.get("assigned_admin_sub") or "")} - {""})
    try:
        TICKET_STORE.add_message(
            ticket_id=ticket_id,
            sender_sub=admin_sub,
            sender_role="admin",
            body=body,
            email_targets=email_targets,
        )
    except TicketStateError:
        pass
    try:
        TICKET_STORE.update_status(ticket_id=ticket_id, actor_sub=admin_sub, status="done")
    except TicketStateError:
        pass


@router.post("", response_model=KycCaseEnvelope)
def create_kyc_case(
    body: KycCaseCreateRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    created = STORE.create_case(user_sub=user.sub, intake_profile=body.intake_profile)
    _audit_state_transition(
        event_name="kyc_case_created",
        actor_sub=user.sub,
        request=request,
        case_id=str(created.get("kyc_case_id") or ""),
        from_status=None,
        to_status=str(created.get("status") or ""),
        action="create",
    )
    _emit_kyc_metric(request, metric_name="kyc_funnel_transition", tags={"to_status": str(created.get("status") or "")})
    return _wrap_case(created)


@router.get("", response_model=KycCaseListEnvelope)
def list_my_kyc_cases(
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    items = [row for row in STORE.list_cases_by_owner(user_sub=user.sub, limit=100) if not _is_purged_case(row)]
    audit_event("kyc_case_listed", user.sub, request, outcome="success", count=len(items))
    return KycCaseListEnvelope.model_validate({"items": items, "next_cursor": None})


def _wait_message(hours: int) -> str:
    if hours <= 2:
        return "Your application is being processed. Expected review within a few hours."
    if hours <= 24:
        return f"Estimated review time: {hours} hours. We'll notify you when there's an update."
    if hours <= 72:
        return f"Estimated review time: {hours // 24} days. We'll notify you when there's an update."
    return "Review times are currently extended. We'll notify you as soon as possible."


@router.get("/estimated-wait", response_model=KycEstimatedWaitEnvelope)
def get_estimated_wait_time(
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """User-facing estimated KYC review wait time (KYC-013).

    Aggregates the existing admin metrics snapshot into a coarse, queue-detail-free
    estimate. No admin role required — only the derived hours/message are returned.
    """
    snapshot = STORE.get_metrics_snapshot(stale_after_seconds=48 * 3600)
    funnel = snapshot.get("funnel_counts") or {}
    queue_size = int(funnel.get("submitted") or 0) + int(funnel.get("under_review") or 0)
    p50 = (snapshot.get("review_latency_seconds") or {}).get("p50")

    if queue_size == 0:
        est_hours = 1
    elif p50:
        est_hours = max(1, int(float(p50) / 3600))
    else:
        est_hours = 24

    audit_event("kyc_estimated_wait_read", user.sub, request, outcome="success", estimated_hours=est_hours)
    return KycEstimatedWaitEnvelope.model_validate(
        {
            "estimated_wait": {
                "estimated_hours": est_hours,
                "queue_position": None,
                "message": _wait_message(est_hours),
            }
        }
    )


@router.get("/{case_id}", response_model=KycCaseEnvelope)
def get_my_kyc_case(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    item = STORE.get_case(case_id)
    if not item:
        audit_event("kyc_case_read_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if item.get("user_sub") != user.sub:
        audit_event("kyc_case_read_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})
    if _is_purged_case(item):
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id, "reason": "purged"})
    audit_event("kyc_case_read", user.sub, request, outcome="success", kyc_case_id=case_id)
    return _wrap_case(item)


@router.patch("/{case_id}", response_model=KycCaseEnvelope)
def patch_my_kyc_case(
    case_id: str,
    body: KycCaseDraftPatchRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    existing = STORE.get_case(case_id)
    if not existing:
        audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if existing.get("user_sub") != user.sub:
        audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})
    if existing.get("status") != "draft":
        audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason="invalid_transition", kyc_case_id=case_id)
        _raise_kyc_error("kyc_invalid_transition", details={"kyc_case_id": case_id, "status": existing.get("status")})

    try:
        updated = STORE.update_draft(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=body.expected_version,
            intake_profile=body.intake_profile,
        )
    except KycCaseConflictError:
        audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason="conflict", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id, "expected_version": body.expected_version})
    except KycCaseValidationError as exc:
        code = str(exc)
        if code in {"kyc_access_forbidden", "kyc_invalid_transition"}:
            audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason=code, kyc_case_id=case_id)
            _raise_kyc_error(code, details={"kyc_case_id": case_id})
        audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason="invalid_request", kyc_case_id=case_id)
        _raise_kyc_error("kyc_invalid_request", details={"kyc_case_id": case_id})

    if not updated:
        audit_event("kyc_case_update_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    _audit_state_transition(
        event_name="kyc_case_updated",
        actor_sub=user.sub,
        request=request,
        case_id=case_id,
        from_status=str(existing.get("status") or ""),
        to_status=str(updated.get("status") or ""),
        action="draft_update",
        version=updated.get("version"),
    )
    _emit_kyc_metric(request, metric_name="kyc_funnel_transition", tags={"to_status": str(updated.get("status") or "")})
    return _wrap_case(updated)


@router.post("/{case_id}/start-questionnaire", response_model=KycCaseEnvelope)
def start_kyc_questionnaire(
    case_id: str,
    body: KycStartQuestionnaireRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_questionnaire_start_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_questionnaire_start_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})

    qref = case.get("questionnaire") or {}
    existing_qid = str(qref.get("questionnaire_id") or "").strip()
    existing_rid = str(qref.get("response_session_id") or "").strip()
    if existing_qid and existing_rid:
        existing_session = QNR_REPO.get_response_session(questionnaire_id=existing_qid, response_session_id=existing_rid)
        if existing_session and str(existing_session.get("status") or "") != "submitted":
            audit_event("kyc_questionnaire_start", user.sub, request, outcome="success", kyc_case_id=case_id, reused_existing=True)
            return _wrap_case(case)

    version = QNR_REPO.get_published_by_slug(body.published_slug)
    if not version:
        audit_event("kyc_questionnaire_start_denied", user.sub, request, outcome="failure", reason="invalid_request", kyc_case_id=case_id)
        _raise_kyc_error("kyc_invalid_request", details={"published_slug": body.published_slug, "reason": "published_questionnaire_not_found"})

    response_session_id = f"resp_{uuid4().hex}"
    session = QNR_REPO.put_response_session(
        response_session_id=response_session_id,
        questionnaire_id=str(version.get("questionnaire_id")),
        version_id=str(version.get("version_id")),
        respondent_id=user.sub,
    )
    try:
        updated = STORE.update_case_links(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=int(case.get("version") or 0),
            questionnaire={
                "questionnaire_id": str(version.get("questionnaire_id") or ""),
                "version_id": str(version.get("version_id") or ""),
                "response_session_id": str(session.get("response_session_id") or ""),
                "response_pdf_ref": None,
            },
        )
    except KycCaseConflictError:
        current = STORE.get_case(case_id)
        if current:
            updated = current
        else:
            _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id})

    if not updated:
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id})
    audit_event(
        "kyc_questionnaire_started",
        user.sub,
        request,
        outcome="success",
        kyc_case_id=case_id,
        questionnaire_id=version.get("questionnaire_id"),
        response_session_id=response_session_id,
    )
    return _wrap_case(updated)


@router.get("/{case_id}/questionnaire-status", response_model=KycQuestionnaireStatusEnvelope)
def questionnaire_status_for_submit_gate(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_questionnaire_status_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_questionnaire_status_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})

    status_payload = _questionnaire_status_for_case(case)
    qid = status_payload.get("questionnaire_id")
    rid = status_payload.get("response_session_id")
    if qid and rid and not status_payload.get("response_pdf_ref"):
        artifact = QNR_REPO.get_response_pdf_artifact(questionnaire_id=qid, response_session_id=rid)
        if artifact:
            pdf_ref = f"{artifact.get('pk')}#{artifact.get('sk')}"
            status_payload["response_pdf_ref"] = pdf_ref
            try:
                STORE.update_case_links(
                    case_id=case_id,
                    owner_sub=user.sub,
                    expected_version=int(case.get("version") or 0),
                    questionnaire={
                        **(case.get("questionnaire") or {}),
                        "response_pdf_ref": pdf_ref,
                    },
                )
            except KycCaseConflictError:
                pass
    audit_event("kyc_questionnaire_status", user.sub, request, outcome="success", kyc_case_id=case_id, submitted=status_payload.get("submitted"))
    return KycQuestionnaireStatusEnvelope.model_validate({"questionnaire": status_payload})


@router.post("/{case_id}/files", response_model=KycCaseEnvelope)
def attach_kyc_file(
    case_id: str,
    body: KycFileAttachmentRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_file_attach_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_file_attach_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})
    if str(case.get("status") or "") not in {"draft", "needs_more_info"}:
        audit_event("kyc_file_attach_denied", user.sub, request, outcome="failure", reason="invalid_transition", kyc_case_id=case_id)
        _raise_kyc_error("kyc_invalid_transition", details={"kyc_case_id": case_id, "status": case.get("status")})

    canonical_path = norm_path(body.path, is_folder=False)
    try:
        node = get_node(user.sub, canonical_path)
    except HTTPException:
        audit_event("kyc_file_attach_denied", user.sub, request, outcome="failure", reason="invalid_request", kyc_case_id=case_id)
        _raise_kyc_error("kyc_invalid_request", details={"path": body.path, "reason": "file_not_found_or_forbidden"})
    if str(node.get("type") or "") != "file":
        _raise_kyc_error("kyc_invalid_request", details={"path": body.path, "reason": "path_must_reference_file"})

    current_files = [dict(f) for f in list(case.get("files") or []) if isinstance(f, dict)]
    next_files = [f for f in current_files if str(f.get("type") or "") != body.file_type]
    next_files.append(
        {
            "path": canonical_path,
            "type": body.file_type,
            "uploaded_at": node.get("upload_at"),
            "size": node.get("size"),
            "verification_state": "pending",
        }
    )

    try:
        updated = STORE.update_case_links(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=body.expected_version,
            files=next_files,
        )
    except KycCaseConflictError:
        audit_event("kyc_file_attach_denied", user.sub, request, outcome="failure", reason="conflict", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id, "expected_version": body.expected_version})

    if not updated:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    audit_event("kyc_file_attached", user.sub, request, outcome="success", kyc_case_id=case_id, file_type=body.file_type, path=canonical_path)
    return _wrap_case(updated)


@router.get("/{case_id}/files/validation", response_model=KycFileValidationEnvelope)
def validate_kyc_file_requirements(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_file_validation_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_file_validation_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})
    payload = _validate_file_requirements(case)
    audit_event("kyc_file_validation", user.sub, request, outcome="success", kyc_case_id=case_id, missing_count=len(payload["missing_types"]))
    return KycFileValidationEnvelope.model_validate({"files": payload})


@router.get("/{case_id}/readiness", response_model=KycReadinessEnvelope)
def kyc_readiness(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_readiness_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_readiness_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})

    payload = _readiness_for_case(case)
    audit_event("kyc_readiness", user.sub, request, outcome="success", kyc_case_id=case_id, ready=payload.get("ready_to_submit"))
    return KycReadinessEnvelope.model_validate({"readiness": payload})


@router.post("/{case_id}/submit", response_model=KycCaseEnvelope)
def submit_kyc_case(
    case_id: str,
    body: KycSubmitCaseRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_submit_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_submit_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})

    readiness = _readiness_for_case(case)
    if not readiness.get("ready_to_submit"):
        for reason in list(readiness.get("missing_requirements") or []):
            _SUBMIT_GUARD_FAILURES[str(reason)] += 1
            _emit_kyc_metric(request, metric_name="kyc_submit_guard_failure", tags={"reason": str(reason)})
        audit_event("kyc_submit_denied", user.sub, request, outcome="failure", reason="prereq_failed", kyc_case_id=case_id)
        _raise_kyc_error(
            "kyc_submit_prereq_failed",
            details={
                "kyc_case_id": case_id,
                "missing_requirements": readiness.get("missing_requirements") or [],
                "missing_hints": readiness.get("missing_hints") or [],
            },
        )

    evidence_snapshot = {
        "questionnaire": {
            "questionnaire_id": readiness["requirements"][0]["refs"].get("questionnaire_id"),
            "response_session_id": readiness["requirements"][0]["refs"].get("response_session_id"),
            "response_pdf_ref": readiness["requirements"][0]["refs"].get("response_pdf_ref"),
        },
        "files": {
            "required_types": _KYC_REQUIRED_FILE_TYPES,
            "present_types": (readiness["requirements"][1]["refs"].get("present_types") or "").split(","),
        },
        "signature": {
            "packet_id": readiness["requirements"][2]["refs"].get("packet_id"),
            "final_pdf_ref": readiness["requirements"][2]["refs"].get("final_pdf_ref"),
        },
    }
    try:
        updated = STORE.submit_case(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=body.expected_version,
            evidence_snapshot=evidence_snapshot,
        )
    except KycCaseConflictError:
        audit_event("kyc_submit_denied", user.sub, request, outcome="failure", reason="conflict", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id, "expected_version": body.expected_version})
    except KycCaseValidationError as exc:
        code = str(exc)
        if code in {"kyc_access_forbidden", "kyc_invalid_transition"}:
            _raise_kyc_error(code, details={"kyc_case_id": case_id})
        _raise_kyc_error("kyc_invalid_request", details={"kyc_case_id": case_id})

    if not updated:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    updated = _ensure_review_ticket(updated)
    _audit_state_transition(
        event_name="kyc_submitted",
        actor_sub=user.sub,
        request=request,
        case_id=case_id,
        from_status=str(case.get("status") or ""),
        to_status=str(updated.get("status") or ""),
        action="submit",
        ticket_id=((updated.get("review") or {}).get("ticket_id")),
    )
    _emit_kyc_metric(request, metric_name="kyc_funnel_transition", tags={"to_status": str(updated.get("status") or "")})
    return _wrap_case(updated)


@router.get("/admin/queue", response_model=KycAdminQueueEnvelope)
def list_admin_kyc_queue(
    request: Request,
    status: str | None = Query(default=None),
    assignee_admin_sub: str | None = Query(default=None),
    min_waiting_seconds: int | None = Query(default=None, ge=0),
    risk_tier: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event("kyc_admin_queue_denied", user.sub, request, outcome="failure", reason="admin_role_required")
        _raise_kyc_error("kyc_admin_role_required")

    statuses = [status] if status else ["submitted", "under_review", "needs_more_info"]
    payload = STORE.list_admin_queue(
        statuses=statuses,
        assignee_sub=(assignee_admin_sub or "").strip() or None,
        min_waiting_seconds=min_waiting_seconds,
        risk_tier=(risk_tier or "").strip().lower() or None,
        limit=limit,
        cursor=cursor,
    )
    audit_event(
        "kyc_admin_queue_listed",
        user.sub,
        request,
        outcome="success",
        count=len(payload.get("items") or []),
        status_filter=status,
        assignee_filter=assignee_admin_sub,
        risk_tier_filter=risk_tier,
    )
    return KycAdminQueueEnvelope.model_validate(payload)


@router.get("/admin/metrics", response_model=KycMetricsSummaryEnvelope)
def get_admin_kyc_metrics(
    request: Request,
    stale_after_seconds: int = Query(default=48 * 3600, ge=60, le=30 * 24 * 3600),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        _raise_kyc_error("kyc_admin_role_required")
    snapshot = STORE.get_metrics_snapshot(stale_after_seconds=stale_after_seconds)
    snapshot["submit_guard_failures_by_reason"] = dict(_SUBMIT_GUARD_FAILURES)
    ticket_sync_snapshot = get_kyc_sync_snapshot()
    snapshot["ticket_sync_counters"] = ticket_sync_snapshot["counters"]
    snapshot["ticket_sync_deadletter_count"] = ticket_sync_snapshot["deadletter_count"]
    snapshot["ticket_sync_deadletter_oldest_age_seconds"] = ticket_sync_snapshot["deadletter_oldest_age_seconds"]
    audit_event(
        "kyc_metrics_read",
        user.sub,
        request,
        outcome="success",
        namespace="kyc_metrics",
        correlation_id=_request_correlation_id(request),
    )
    return KycMetricsSummaryEnvelope.model_validate({"metrics": snapshot})


@router.post("/admin/purge/run", response_model=KycPurgeRunEnvelope)
def run_admin_kyc_purge(
    request: Request,
    dry_run: bool = Query(default=True),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        _raise_kyc_error("kyc_admin_role_required")
    result = STORE.run_retention_purge(dry_run=dry_run)
    audit_event(
        "kyc_retention_purge_run",
        user.sub,
        request,
        outcome="success",
        namespace="kyc_retention",
        purged_count=result.get("purged_count"),
        dry_run=bool(dry_run),
        purged_case_ids=result.get("purged_case_ids"),
        correlation_id=_request_correlation_id(request),
    )
    return KycPurgeRunEnvelope.model_validate({"purge": result})


@router.get("/admin/cases/{case_id}", response_model=KycAdminCaseDetailEnvelope)
def get_admin_kyc_case_detail(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event("kyc_admin_case_detail_denied", user.sub, request, outcome="failure", reason="admin_role_required", kyc_case_id=case_id)
        _raise_kyc_error("kyc_admin_role_required")

    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_admin_case_detail_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if not _is_scoped_admin_for_case(user, case):
        audit_event("kyc_admin_case_detail_denied", user.sub, request, outcome="failure", reason="scope_forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id, "reason": "reviewer_scope_required"})

    payload = _build_admin_case_detail(case)
    audit_event("kyc_admin_case_detail_read", user.sub, request, outcome="success", kyc_case_id=case_id, status=case.get("status"))
    return KycAdminCaseDetailEnvelope.model_validate({"case": payload})


@router.post("/admin/cases/{case_id}/request-info", response_model=KycCaseEnvelope)
def admin_request_more_info(
    case_id: str,
    body: KycAdminRequestInfoRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event("kyc_admin_request_info_denied", user.sub, request, outcome="failure", reason="admin_role_required", kyc_case_id=case_id)
        _raise_kyc_error("kyc_admin_role_required")

    case = STORE.get_case(case_id)
    if not case:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if not _is_scoped_admin_for_case(user, case):
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id, "reason": "reviewer_scope_required"})

    request_hash = hashlib.sha256(
        json.dumps({"requested_items": list(body.requested_items), "note": body.note.strip()}, sort_keys=True).encode("utf-8")
    ).hexdigest()

    review = dict(case.get("review") or {})
    if str(case.get("status") or "") == "needs_more_info" and str(review.get("last_request_info_hash") or "") == request_hash:
        try:
            _ensure_request_info_ticket_message(
                case,
                admin_sub=user.sub,
                request_hash=request_hash,
                requested_items=list(body.requested_items),
                note=body.note.strip(),
            )
        except TicketStateError:
            audit_event("kyc_admin_request_info_sync_failed", user.sub, request, outcome="failure", reason="ticket_message_conflict", kyc_case_id=case_id)
        return _wrap_case(case)

    try:
        updated = STORE.request_more_info(
            case_id=case_id,
            expected_version=body.expected_version,
            admin_sub=user.sub,
            requested_items=list(body.requested_items),
            note=body.note.strip(),
            request_hash=request_hash,
        )
    except KycCaseConflictError:
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id, "expected_version": body.expected_version})
    except KycCaseValidationError as exc:
        code = str(exc)
        if code in {"kyc_invalid_transition"}:
            _raise_kyc_error(code, details={"kyc_case_id": case_id})
        _raise_kyc_error("kyc_invalid_request", details={"kyc_case_id": case_id})

    if not updated:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    try:
        _ensure_request_info_ticket_message(
            updated,
            admin_sub=user.sub,
            request_hash=request_hash,
            requested_items=list(body.requested_items),
            note=body.note.strip(),
        )
    except TicketStateError:
        audit_event("kyc_admin_request_info_sync_failed", user.sub, request, outcome="failure", reason="ticket_message_conflict", kyc_case_id=case_id)
    _audit_state_transition(
        event_name="kyc_admin_request_info",
        actor_sub=user.sub,
        request=request,
        case_id=case_id,
        from_status=str(case.get("status") or ""),
        to_status=str(updated.get("status") or ""),
        action="request_info",
        requested_items=list(body.requested_items),
    )
    _emit_kyc_metric(request, metric_name="kyc_funnel_transition", tags={"to_status": str(updated.get("status") or "")})
    return _wrap_case(updated)


def _admin_decide_case(
    *,
    case_id: str,
    body: KycAdminDecisionRequest,
    request: Request,
    user: AuthenticatedUser,
    decision: str,
) -> KycCaseEnvelope:
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event("kyc_admin_decision_denied", user.sub, request, outcome="failure", reason="admin_role_required", kyc_case_id=case_id)
        _raise_kyc_error("kyc_admin_role_required")

    if body.decision != decision:
        _raise_kyc_error("kyc_invalid_request", details={"reason": "decision_mismatch", "expected_decision": decision})
    if not list(body.reason_codes):
        _raise_kyc_error("kyc_invalid_request", details={"reason": "reason_codes_required"})
    if len(body.note.strip()) < 5:
        _raise_kyc_error("kyc_invalid_request", details={"reason": "reviewer_note_too_short"})

    case = STORE.get_case(case_id)
    if not case:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if not _is_scoped_admin_for_case(user, case):
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id, "reason": "reviewer_scope_required"})

    decision_hash = hashlib.sha256(
        json.dumps({"decision": decision, "reason_codes": list(body.reason_codes), "note": body.note.strip()}, sort_keys=True).encode("utf-8")
    ).hexdigest()

    review = dict(case.get("review") or {})
    if str(case.get("status") or "") in {"approved", "rejected"} and str(review.get("decision_hash") or "") == decision_hash:
        _ensure_decision_ticket_updates(
            case,
            admin_sub=user.sub,
            decision_hash=decision_hash,
            decision=decision,
            reason_codes=list(body.reason_codes),
            note=body.note.strip(),
        )
        return _wrap_case(case)

    try:
        updated = STORE.apply_admin_decision(
            case_id=case_id,
            expected_version=body.expected_version,
            admin_sub=user.sub,
            decision=decision,
            reason_codes=list(body.reason_codes),
            note=body.note.strip(),
            decision_hash=decision_hash,
        )
    except KycCaseConflictError:
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id, "expected_version": body.expected_version})
    except KycCaseValidationError as exc:
        code = str(exc)
        if code in {"kyc_invalid_transition"}:
            _raise_kyc_error(code, details={"kyc_case_id": case_id})
        _raise_kyc_error("kyc_invalid_request", details={"kyc_case_id": case_id})

    if not updated:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    _ensure_decision_ticket_updates(
        updated,
        admin_sub=user.sub,
        decision_hash=decision_hash,
        decision=decision,
        reason_codes=list(body.reason_codes),
        note=body.note.strip(),
    )
    _audit_state_transition(
        event_name="kyc_admin_decision",
        actor_sub=user.sub,
        request=request,
        case_id=case_id,
        from_status=str(case.get("status") or ""),
        to_status=str(updated.get("status") or ""),
        action=f"decision_{decision}",
        decision=decision,
        reason_codes=list(body.reason_codes),
    )
    _emit_kyc_metric(request, metric_name="kyc_funnel_transition", tags={"to_status": str(updated.get("status") or "")})
    return _wrap_case(updated)


@router.post("/admin/cases/{case_id}/approve", response_model=KycCaseEnvelope)
def admin_approve_case(
    case_id: str,
    body: KycAdminDecisionRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    return _admin_decide_case(case_id=case_id, body=body, request=request, user=user, decision="approve")


@router.post("/admin/cases/{case_id}/reject", response_model=KycCaseEnvelope)
def admin_reject_case(
    case_id: str,
    body: KycAdminDecisionRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    return _admin_decide_case(case_id=case_id, body=body, request=request, user=user, decision="reject")


@router.post("/{case_id}/signature-packet", response_model=KycCaseEnvelope)
def create_or_link_signature_packet(
    case_id: str,
    body: KycLinkSignaturePacketRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_signature_link_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_signature_link_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})

    existing_signature = case.get("signature") or {}
    existing_packet_id = str(existing_signature.get("packet_id") or "").strip()
    if existing_packet_id:
        packet = get_packet(existing_packet_id) or {}
        if str(packet.get("status") or "") != "completed":
            audit_event("kyc_signature_linked", user.sub, request, outcome="success", kyc_case_id=case_id, packet_id=existing_packet_id, reused_existing=True)
            return _wrap_case(case)

    source_path = norm_path(body.source_path, is_folder=False)
    try:
        source = get_node(user.sub, source_path)
    except HTTPException:
        _raise_kyc_error("kyc_invalid_request", details={"source_path": body.source_path, "reason": "source_not_found"})
    if str(source.get("type") or "") != "file" or str(source.get("content_type") or "").lower() != "application/pdf":
        _raise_kyc_error("kyc_invalid_request", details={"source_path": body.source_path, "reason": "source_must_be_pdf_file"})

    packet = create_draft_packet(
        owner_user_id=user.sub,
        source_path=source_path,
        source_content_type="application/pdf",
        source_name=str(source.get("name") or ""),
        origin_channel=body.origin_channel,
        origin_ref=body.origin_ref,
    )
    try:
        updated = STORE.update_case_links(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=body.expected_version,
            signature={
                "packet_id": str(packet.get("packet_id") or ""),
                "status": str(packet.get("status") or ""),
                "final_pdf_ref": None,
                "legal_notice_version": S.signature_packet_legal_notice_version,
                "legal_notice_accepted": False,
            },
        )
    except KycCaseConflictError:
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id, "expected_version": body.expected_version})

    if not updated:
        _raise_kyc_error("kyc_case_update_conflict", details={"kyc_case_id": case_id})
    audit_event("kyc_signature_linked", user.sub, request, outcome="success", kyc_case_id=case_id, packet_id=packet.get("packet_id"))
    return _wrap_case(updated)


@router.get("/{case_id}/signature-status", response_model=KycSignatureStatusEnvelope)
def signature_completion_status(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = STORE.get_case(case_id)
    if not case:
        audit_event("kyc_signature_status_denied", user.sub, request, outcome="failure", reason="not_found", kyc_case_id=case_id)
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        audit_event("kyc_signature_status_denied", user.sub, request, outcome="failure", reason="forbidden", kyc_case_id=case_id)
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})

    payload = _signature_status_for_case(case)
    if payload.get("final_pdf_ref") and not (case.get("signature") or {}).get("final_pdf_ref"):
        try:
            STORE.update_case_links(
                case_id=case_id,
                owner_sub=user.sub,
                expected_version=int(case.get("version") or 0),
                signature={**(case.get("signature") or {}), "final_pdf_ref": payload["final_pdf_ref"]},
            )
        except KycCaseConflictError:
            pass
    audit_event("kyc_signature_status", user.sub, request, outcome="success", kyc_case_id=case_id, ready=payload.get("ready_for_submit_gate"))
    return KycSignatureStatusEnvelope.model_validate({"signature": payload})


# --- KYC-014: Facial Comparison endpoints ----------------------------------

_FACE_COMPARISON_ERROR_STATUS: dict[str, int] = {
    "case_not_found": 404,
    "access_forbidden": 403,
    "selfie_not_uploaded": 400,
    "id_front_not_uploaded": 400,
    "max_attempts_exceeded": 409,
    "comparison_not_found": 404,
    "comparison_service_error": 500,
}


@router.post("/{case_id}/compare-face", response_model=FaceComparisonResultOut)
def run_face_comparison(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not S.kyc_face_comparison_enabled:
        raise HTTPException(status_code=503, detail="kyc_face_comparison_disabled")
    from app.services.kyc_facial_comparison import (
        KycFacialComparisonError,
        compare_faces,
    )

    try:
        result = compare_faces(case_id=case_id, user_sub=user.sub, request=request)
    except KycFacialComparisonError as exc:
        code = str(exc)
        raise HTTPException(
            status_code=_FACE_COMPARISON_ERROR_STATUS.get(code, 400),
            detail=code,
        )
    return FaceComparisonResultOut.model_validate(result)


@router.get("/{case_id}/face-comparisons", response_model=FaceComparisonListOut)
def list_face_comparisons(
    case_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    from app.services.kyc_facial_comparison import _get_comparisons, _public_view

    case = STORE.get_case(case_id)
    if not case:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    if case.get("user_sub") != user.sub:
        _raise_kyc_error("kyc_access_forbidden", details={"kyc_case_id": case_id})
    comparisons = [_public_view(c) for c in _get_comparisons(case_id)]
    return FaceComparisonListOut.model_validate({"comparisons": comparisons})


@router.get(
    "/admin/cases/{case_id}/face-comparison",
    response_model=AdminFaceComparisonOut,
)
def admin_face_comparison(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event("kyc_face_comparison_admin_denied", user.sub, request, outcome="failure", reason="admin_role_required", kyc_case_id=case_id)
        _raise_kyc_error("kyc_admin_role_required")
    from app.services.kyc_facial_comparison import build_admin_view

    payload = build_admin_view(case_id)
    if payload is None:
        _raise_kyc_error("kyc_case_not_found", details={"kyc_case_id": case_id})
    audit_event("kyc_face_comparison_admin_read", user.sub, request, outcome="success", kyc_case_id=case_id, total_attempts=payload.get("total_attempts"))
    return AdminFaceComparisonOut.model_validate(payload)


@router.post(
    "/admin/cases/{case_id}/face-comparison/{comparison_id}/override",
    response_model=FaceComparisonOverrideResultOut,
)
def admin_override_face_comparison(
    case_id: str,
    comparison_id: str,
    body: FaceComparisonOverrideRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event("kyc_face_comparison_override_denied", user.sub, request, outcome="failure", reason="admin_role_required", kyc_case_id=case_id)
        _raise_kyc_error("kyc_admin_role_required")
    if not S.kyc_face_admin_override_enabled:
        raise HTTPException(status_code=503, detail="kyc_face_admin_override_disabled")
    from app.services.kyc_facial_comparison import (
        KycFacialComparisonError,
        admin_override_comparison,
    )

    try:
        result = admin_override_comparison(
            case_id=case_id,
            comparison_id=comparison_id,
            decision=body.decision,
            reason=body.reason,
            admin_sub=user.sub,
            request=request,
        )
    except KycFacialComparisonError as exc:
        code = str(exc)
        raise HTTPException(
            status_code=_FACE_COMPARISON_ERROR_STATUS.get(code, 400),
            detail=code,
        )
    return FaceComparisonOverrideResultOut.model_validate(result)
