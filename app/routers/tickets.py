from __future__ import annotations

import base64
import json
import time
from collections import Counter
from time import time
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.tables import T
from app.services.alerts import audit_event
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session
from app.services.tickets import STORE, TicketStateError
from app.services.payment_incidents_store import DynamoPaymentIncidentRepository
from app.services.payment_incident_ticket_sync import sync_incident_from_ticket
from app.services.kyc_cases import STORE as KYC_STORE, KycCaseConflictError, KycCaseValidationError

router = APIRouter(prefix="/tickets", tags=["tickets"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])
_KYC_TICKET_SYNC_COUNTS: Counter[str] = Counter()
_KYC_TICKET_SYNC_DEADLETTER: list[dict[str, Any]] = []
_KYC_TICKET_SYNC_DEADLETTER_MAX = 200


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


class TicketMessage(BaseModel):
    message_id: str
    sender_sub: str
    sender_role: str
    body: str
    created_at: int
    email_alert_queued_for: list[str]


class TicketActivity(BaseModel):
    type: str
    actor_sub: str
    assignee_sub: str | None = None
    status: str | None = None
    created_at: int


class TicketOut(BaseModel):
    ticket_id: str
    subject: str
    owner_sub: str
    status: str
    space_id: str | None = None
    assigned_admin_sub: str | None = None
    assigned_to_sub: str | None = None
    assigned_by: str | None = None
    assigned_at: int | None = None
    created_at: int
    updated_at: int
    version: int
    messages: list[TicketMessage]
    activity: list[TicketActivity]


class TicketEnvelope(BaseModel):
    ticket: TicketOut


class TicketListEnvelope(BaseModel):
    items: list["TicketListItemOut"]
    next_cursor: str | None = None


class SyncFreshnessOut(BaseModel):
    ingested_at: int | None = None
    updated_at_remote: str | None = None
    staleness_seconds: int | None = None
    sync_state: str | None = None


class TicketListItemOut(BaseModel):
    ticket_id: str | None = None
    external_issue_id: str | None = None
    external_issue_key: str | None = None
    subject: str
    owner_sub: str | None = None
    status: str
    space_id: str | None = None
    assigned_admin_sub: str | None = None
    assigned_to_sub: str | None = None
    assigned_by: str | None = None
    assigned_at: int | None = None
    created_at: int
    updated_at: int
    version: int | None = None
    messages: list[TicketMessage] = []
    activity: list[TicketActivity] = []
    source: Literal["internal", "jira"]
    project_key: str | None = None
    sync_freshness: SyncFreshnessOut


class TicketAdminSummary(BaseModel):
    by_status: dict[str, int]
    unassigned_count: int
    stale_count: int
    stale_after_seconds: int
    total_count: int


class TicketAdminSummaryEnvelope(BaseModel):
    summary: TicketAdminSummary


class TicketKycSyncMetrics(BaseModel):
    counters: dict[str, int]
    deadletter_count: int = 0
    deadletter_oldest_age_seconds: int | None = None


class TicketKycSyncMetricsEnvelope(BaseModel):
    metrics: TicketKycSyncMetrics


class TicketKycSyncDeadletterEntry(BaseModel):
    entry_id: str
    created_at: int
    reason: str
    event_type: str
    actor_sub: str
    ticket_id: str | None = None
    kyc_case_id: str | None = None
    metadata_case_id: str | None = None
    inferred_case_id: str | None = None
    replay_count: int = 0
    last_replay_at: int | None = None
    last_replay_outcome: str | None = None


class TicketKycSyncDeadletterEnvelope(BaseModel):
    items: list[TicketKycSyncDeadletterEntry]
    total_count: int


class TicketKycSyncDeadletterClearEnvelope(BaseModel):
    cleared_count: int
    remaining_count: int


class TicketKycSyncDeadletterReplayEnvelope(BaseModel):
    replayed: bool
    removed: bool
    deadletter_entry_id: str


class TicketKycSyncDeadletterBatchReplayEnvelope(BaseModel):
    attempted_count: int
    replayed_count: int
    failed_count: int
    removed_count: int


class CreateTicketReq(BaseModel):
    subject: str = Field(..., min_length=3, max_length=160)
    description: str = Field(..., min_length=1, max_length=4000)


class AssignTicketReq(BaseModel):
    assignee_admin_sub: str = Field(..., min_length=1)


class TicketMessageReq(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


class TicketStatusReq(BaseModel):
    status: Literal["open", "in_progress", "waiting_on_user", "done", "reopened"]


def _error(code: str, message: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def _raise(status_code: int, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
    raise HTTPException(status_code=status_code, detail=_error(code, message, details=details))


def _error_responses() -> dict[int | str, dict[str, Any]]:
    return {
        400: {"model": ErrorEnvelope, "description": "Bad request"},
        403: {"model": ErrorEnvelope, "description": "Forbidden"},
        404: {"model": ErrorEnvelope, "description": "Not found"},
        409: {"model": ErrorEnvelope, "description": "Conflict"},
    }


def _is_admin(user: AuthenticatedUser) -> bool:
    return normalize_role(user.role) in {Role.ADMIN, Role.ROOT}


def _api_key_principal(request: Request) -> dict[str, Any]:
    principal = getattr(getattr(request, "state", None), "api_key_principal", None)
    return principal if isinstance(principal, dict) else {}


def _has_api_key_scope(request: Request, scope: str) -> bool:
    principal = _api_key_principal(request)
    capabilities = principal.get("capabilities")
    if not isinstance(capabilities, list):
        return False
    return (scope or "").strip().lower() in {str(item).strip().lower() for item in capabilities}


def _is_admin_actor(request: Request, user: AuthenticatedUser) -> bool:
    return _is_admin(user) or _has_api_key_scope(request, "tickets:admin")


def _is_root(user: AuthenticatedUser) -> bool:
    return normalize_role(user.role) == Role.ROOT


def _wrap_ticket(ticket: dict[str, Any]) -> TicketEnvelope:
    return TicketEnvelope(ticket=TicketOut.model_validate(ticket))


def _ticket_list_item_from_internal(ticket: dict[str, Any]) -> TicketListItemOut:
    return TicketListItemOut.model_validate(
        {
            **ticket,
            "source": "internal",
            "sync_freshness": {"sync_state": "not_applicable"},
        }
    )


def _ticket_list_item_from_jira(mirror: dict[str, Any], now: int) -> TicketListItemOut:
    ingested_at = int(mirror.get("ingested_at") or 0) or None
    freshness = {
        "ingested_at": ingested_at,
        "updated_at_remote": mirror.get("updated_at_remote"),
        "staleness_seconds": (max(0, now - ingested_at) if ingested_at else None),
        "sync_state": "mirrored",
    }
    return TicketListItemOut.model_validate(
        {
            "external_issue_id": str(mirror.get("external_issue_id") or ""),
            "external_issue_key": str(mirror.get("external_issue_key") or ""),
            "subject": str(mirror.get("summary") or ""),
            "status": str(mirror.get("status") or ""),
            "created_at": int(mirror.get("ingested_at") or mirror.get("updated_at") or 0),
            "updated_at": int(mirror.get("updated_at") or mirror.get("ingested_at") or 0),
            "source": "jira",
            "project_key": str(mirror.get("project_key") or "") or None,
            "sync_freshness": freshness,
        }
    )


def _wrap_ticket_list(payload: dict[str, Any]) -> TicketListEnvelope:
    now = int(time.time())
    items: list[TicketListItemOut] = []
    for item in payload.get("tickets", []):
        if str(item.get("source") or "internal") == "jira":
            items.append(_ticket_list_item_from_jira(item, now))
        else:
            items.append(_ticket_list_item_from_internal(item))
    return TicketListEnvelope(items=items, next_cursor=payload.get("next_cursor"))


def _encode_unified_cursor(*, updated_at: int, source: str, stable_id: str) -> str:
    raw = json.dumps({"updated_at": int(updated_at), "source": source, "stable_id": stable_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def _decode_unified_cursor(cursor: str | None) -> dict[str, Any] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
        value = json.loads(raw)
        if isinstance(value, dict):
            return value
    except Exception:
        return None
    return None


def _sort_unified_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def _stable_id(item: dict[str, Any]) -> str:
        return str(item.get("ticket_id") or item.get("external_issue_id") or "")

    return sorted(
        items,
        key=lambda item: (
            -int(item.get("updated_at") or 0),
            str(item.get("source") or "internal"),
            _stable_id(item),
        ),
    )


def _apply_unified_cursor(items: list[dict[str, Any]], cursor: str | None) -> list[dict[str, Any]]:
    token = _decode_unified_cursor(cursor)
    if not token:
        return items
    cursor_updated_at = int(token.get("updated_at") or 0)
    cursor_source = str(token.get("source") or "")
    cursor_id = str(token.get("stable_id") or "")
    out: list[dict[str, Any]] = []
    for item in items:
        key = (
            -int(item.get("updated_at") or 0),
            str(item.get("source") or "internal"),
            str(item.get("ticket_id") or item.get("external_issue_id") or ""),
        )
        cursor_key = (-cursor_updated_at, cursor_source, cursor_id)
        if key > cursor_key:
            out.append(item)
    return out


def _ticket_or_404(ticket_id: str) -> dict:
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        _raise(404, "ticket_not_found", "ticket not found", details={"ticket_id": ticket_id})
    return ticket


def _can_access_ticket(request: Request, user: AuthenticatedUser, ticket: dict) -> bool:
    return user.sub == ticket["owner_sub"] or _is_admin_actor(request, user)


def _is_assignable_admin(user_sub: str) -> bool:
    user = T.users.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    return normalize_role(user.get("role")) in {Role.ADMIN, Role.ROOT}


def _ticket_state_http_status(exc: TicketStateError) -> int:
    if exc.detail.get("code") == "ticket_update_conflict":
        return 409
    return 400


def _ticket_state_error(exc: TicketStateError) -> dict[str, Any]:
    code = str(exc.detail.get("code") or "invalid_ticket_state")
    message = "ticket update conflict" if code == "ticket_update_conflict" else "invalid ticket state"
    return _error(code, message, details=exc.detail)




def _emit_ticket_alerts(event: str, *, recipients: list[str], actor_sub: str, request: Request, **fields: Any) -> None:
    principal = _api_key_principal(request)
    api_key_fields: dict[str, Any] = {}
    if principal:
        api_key_fields = {
            "auth_type": "api_key",
            "api_key_id": str(principal.get("api_key_id") or ""),
            "api_key_owner_sub": str(principal.get("user_sub") or ""),
        }
    for recipient in sorted({item for item in recipients if item}):
        audit_event(event, recipient, request, outcome="success", actor_sub=actor_sub, **api_key_fields, **fields)


def get_kyc_sync_counters() -> dict[str, int]:
    return dict(_KYC_TICKET_SYNC_COUNTS)


def get_kyc_sync_snapshot() -> dict[str, Any]:
    deadletter_count = len(_KYC_TICKET_SYNC_DEADLETTER)
    oldest_age = None
    if deadletter_count:
        oldest_created_at = min(int(item.get("created_at") or 0) for item in _KYC_TICKET_SYNC_DEADLETTER)
        oldest_age = max(0, int(time()) - oldest_created_at)
    return {
        "counters": dict(_KYC_TICKET_SYNC_COUNTS),
        "deadletter_count": deadletter_count,
        "deadletter_oldest_age_seconds": oldest_age,
    }


def _push_kyc_sync_deadletter(
    *,
    reason: str,
    event_type: str,
    actor_sub: str,
    ticket_after: dict[str, Any],
    case_id: str | None = None,
    metadata_case_id: str | None = None,
    inferred_case_id: str | None = None,
) -> None:
    _KYC_TICKET_SYNC_DEADLETTER.append(
        {
            "entry_id": str(uuid4()),
            "created_at": int(time()),
            "reason": reason,
            "event_type": event_type,
            "actor_sub": actor_sub,
            "ticket_id": ticket_after.get("ticket_id"),
            "kyc_case_id": case_id,
            "metadata_case_id": metadata_case_id,
            "inferred_case_id": inferred_case_id,
            "replay_count": 0,
            "last_replay_at": None,
            "last_replay_outcome": None,
        }
    )
    if len(_KYC_TICKET_SYNC_DEADLETTER) > _KYC_TICKET_SYNC_DEADLETTER_MAX:
        del _KYC_TICKET_SYNC_DEADLETTER[0 : len(_KYC_TICKET_SYNC_DEADLETTER) - _KYC_TICKET_SYNC_DEADLETTER_MAX]


def _kyc_case_id_for_ticket(ticket: dict[str, Any]) -> str | None:
    metadata = ticket.get("metadata") or {}
    case_id = str(metadata.get("kyc_case_id") or "").strip()
    if case_id:
        return case_id
    ticket_id = str(ticket.get("ticket_id") or "")
    if ticket_id.startswith("tkt_kyc_"):
        return ticket_id.removeprefix("tkt_kyc_")
    return None


def _sync_kyc_for_ticket_event(
    *,
    ticket_before: dict[str, Any],
    ticket_after: dict[str, Any],
    event_type: str,
    actor_sub: str,
    request: Request,
) -> None:
    metadata_case_id = str(((ticket_after.get("metadata") or {}).get("kyc_case_id") or "")).strip() or None
    inferred_case_id = None
    inferred_ticket_id = str(ticket_after.get("ticket_id") or "")
    if inferred_ticket_id.startswith("tkt_kyc_"):
        inferred_case_id = inferred_ticket_id.removeprefix("tkt_kyc_")
    if metadata_case_id and inferred_case_id and metadata_case_id != inferred_case_id:
        _KYC_TICKET_SYNC_COUNTS["failed_ticket_case_id_mismatch"] += 1
        _push_kyc_sync_deadletter(
            reason="ticket_case_id_mismatch",
            event_type=event_type,
            actor_sub=actor_sub,
            ticket_after=ticket_after,
            case_id=metadata_case_id,
            metadata_case_id=metadata_case_id,
            inferred_case_id=inferred_case_id,
        )
        audit_event(
            "kyc_ticket_sync_failed",
            actor_sub,
            request,
            outcome="failure",
            reason="ticket_case_id_mismatch",
            kyc_case_id=metadata_case_id,
            ticket_id=ticket_after.get("ticket_id"),
            metadata_case_id=metadata_case_id,
            inferred_case_id=inferred_case_id,
            correlation_link=f"kyc_case:{metadata_case_id}|ticket:{ticket_after.get('ticket_id')}",
        )
        return
    case_id = _kyc_case_id_for_ticket(ticket_after)
    if not case_id:
        _KYC_TICKET_SYNC_COUNTS["ignored_non_kyc_ticket"] += 1
        return
    if str((ticket_after.get("metadata") or {}).get("namespace") or "") not in {"", "kyc"}:
        _KYC_TICKET_SYNC_COUNTS["ignored_non_kyc_namespace"] += 1
        return

    for _ in range(3):
        case = KYC_STORE.get_case(case_id)
        if not case:
            _KYC_TICKET_SYNC_COUNTS["failed_case_not_found"] += 1
            _push_kyc_sync_deadletter(
                reason="case_not_found",
                event_type=event_type,
                actor_sub=actor_sub,
                ticket_after=ticket_after,
                case_id=case_id,
            )
            audit_event(
                "kyc_ticket_sync_failed",
                actor_sub,
                request,
                outcome="failure",
                reason="case_not_found",
                kyc_case_id=case_id,
                ticket_id=ticket_after.get("ticket_id"),
                correlation_link=f"kyc_case:{case_id}|ticket:{ticket_after.get('ticket_id')}",
            )
            return
        event_id = f"{event_type}:{ticket_after.get('ticket_id')}:{ticket_after.get('version')}:{ticket_after.get('updated_at')}"
        try:
            updated = KYC_STORE.sync_from_ticket_event(
                case_id=case_id,
                expected_version=int(case.get("version") or 0),
                ticket_id=str(ticket_after.get("ticket_id") or ""),
                sync_event_id=event_id,
                ticket_status=str(ticket_after.get("status") or ""),
                ticket_version=(int(ticket_after["version"]) if ticket_after.get("version") is not None else None),
                ticket_updated_at=(int(ticket_after["updated_at"]) if ticket_after.get("updated_at") is not None else None),
                assigned_admin_sub=ticket_after.get("assigned_admin_sub"),
                request_info=(event_type == "message_admin"),
            )
            if updated:
                previous_version = int(case.get("version") or 0)
                updated_version = int(updated.get("version") or 0)
                if updated_version == previous_version:
                    _KYC_TICKET_SYNC_COUNTS["skipped_stale_or_duplicate"] += 1
                    audit_event(
                        "kyc_ticket_sync_skipped",
                        actor_sub,
                        request,
                        outcome="success",
                        reason="stale_or_duplicate_event",
                        kyc_case_id=case_id,
                        ticket_id=ticket_after.get("ticket_id"),
                        event_type=event_type,
                        event_id=event_id,
                        correlation_link=f"kyc_case:{case_id}|ticket:{ticket_after.get('ticket_id')}",
                    )
                else:
                    _KYC_TICKET_SYNC_COUNTS["synced"] += 1
                    audit_event(
                        "kyc_ticket_synced",
                        actor_sub,
                        request,
                        outcome="success",
                        kyc_case_id=case_id,
                        ticket_id=ticket_after.get("ticket_id"),
                        event_type=event_type,
                        event_id=event_id,
                        correlation_link=f"kyc_case:{case_id}|ticket:{ticket_after.get('ticket_id')}",
                    )
            return
        except KycCaseConflictError:
            _KYC_TICKET_SYNC_COUNTS["retry_conflict"] += 1
            continue
        except KycCaseValidationError as exc:
            _KYC_TICKET_SYNC_COUNTS[f"failed_{str(exc)}"] += 1
            _push_kyc_sync_deadletter(
                reason=str(exc),
                event_type=event_type,
                actor_sub=actor_sub,
                ticket_after=ticket_after,
                case_id=case_id,
            )
            audit_event(
                "kyc_ticket_sync_failed",
                actor_sub,
                request,
                outcome="failure",
                reason=str(exc),
                kyc_case_id=case_id,
                ticket_id=ticket_after.get("ticket_id"),
                correlation_link=f"kyc_case:{case_id}|ticket:{ticket_after.get('ticket_id')}",
            )
            return
    audit_event(
        "kyc_ticket_sync_failed",
        actor_sub,
        request,
        outcome="failure",
        reason="conflict_retry_exhausted",
        kyc_case_id=case_id,
        ticket_id=ticket_after.get("ticket_id"),
        correlation_link=f"kyc_case:{case_id}|ticket:{ticket_after.get('ticket_id')}",
    )
    _KYC_TICKET_SYNC_COUNTS["failed_conflict_retry_exhausted"] += 1
    _push_kyc_sync_deadletter(
        reason="conflict_retry_exhausted",
        event_type=event_type,
        actor_sub=actor_sub,
        ticket_after=ticket_after,
        case_id=case_id,
    )


@router.get("/admin/kyc-sync-metrics", response_model=TicketKycSyncMetricsEnvelope, responses=_error_responses())
def admin_kyc_sync_metrics(
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin(user):
        _raise(403, "admin_role_required", "admin role required")
    snapshot = get_kyc_sync_snapshot()
    audit_event(
        "kyc_ticket_sync_metrics_read",
        user.sub,
        request,
        outcome="success",
        deadletter_count=int(snapshot.get("deadletter_count") or 0),
    )
    return TicketKycSyncMetricsEnvelope(
        metrics=TicketKycSyncMetrics(
            counters=snapshot["counters"],
            deadletter_count=int(snapshot["deadletter_count"] or 0),
            deadletter_oldest_age_seconds=snapshot.get("deadletter_oldest_age_seconds"),
        )
    )


@router.get("/admin/kyc-sync-deadletter", response_model=TicketKycSyncDeadletterEnvelope, responses=_error_responses())
def admin_kyc_sync_deadletter(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    reason: str | None = Query(default=None),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin(user):
        _raise(403, "admin_role_required", "admin role required")
    rows = list(_KYC_TICKET_SYNC_DEADLETTER)
    normalized_reason = str(reason or "").strip()
    if normalized_reason:
        rows = [item for item in rows if str(item.get("reason") or "") == normalized_reason]
    items = rows[-limit:]
    audit_event(
        "kyc_ticket_sync_deadletter_listed",
        user.sub,
        request,
        outcome="success",
        count=len(items),
        total_count=len(rows),
        reason_filter=normalized_reason or None,
    )
    return TicketKycSyncDeadletterEnvelope(
        items=[TicketKycSyncDeadletterEntry.model_validate(item) for item in reversed(items)],
        total_count=len(rows),
    )


@router.delete("/admin/kyc-sync-deadletter", response_model=TicketKycSyncDeadletterClearEnvelope, responses=_error_responses())
def clear_admin_kyc_sync_deadletter(
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_root(user):
        _raise(403, "root_role_required", "root role required")
    cleared_count = len(_KYC_TICKET_SYNC_DEADLETTER)
    _KYC_TICKET_SYNC_DEADLETTER.clear()
    audit_event(
        "kyc_ticket_sync_deadletter_cleared",
        user.sub,
        request,
        outcome="success",
        cleared_count=cleared_count,
    )
    return TicketKycSyncDeadletterClearEnvelope(cleared_count=cleared_count, remaining_count=0)


def _replay_deadletter_entry(entry: dict[str, Any], *, actor_sub: str, request: Request) -> tuple[bool, bool]:
    entry_id = str(entry.get("entry_id") or "")
    ticket_id = str(entry.get("ticket_id") or "")
    ticket = STORE.get_ticket(ticket_id) if ticket_id else None
    if not ticket:
        _KYC_TICKET_SYNC_COUNTS["deadletter_replay_failed_ticket_not_found"] += 1
        entry["replay_count"] = int(entry.get("replay_count") or 0) + 1
        entry["last_replay_at"] = int(time())
        entry["last_replay_outcome"] = "ticket_not_found"
        audit_event(
            "kyc_ticket_sync_deadletter_replay_failed",
            actor_sub,
            request,
            outcome="failure",
            reason="ticket_not_found",
            deadletter_entry_id=entry_id,
            ticket_id=ticket_id,
        )
        return False, False

    _sync_kyc_for_ticket_event(
        ticket_before=ticket,
        ticket_after=ticket,
        event_type=f"replay_{str(entry.get('event_type') or 'unknown')}",
        actor_sub=actor_sub,
        request=request,
    )
    _KYC_TICKET_SYNC_COUNTS["deadletter_replay_success"] += 1
    audit_event(
        "kyc_ticket_sync_deadletter_replayed",
        actor_sub,
        request,
        outcome="success",
        deadletter_entry_id=entry_id,
        ticket_id=ticket_id,
        original_event_type=entry.get("event_type"),
    )
    _KYC_TICKET_SYNC_DEADLETTER[:] = [item for item in _KYC_TICKET_SYNC_DEADLETTER if str(item.get("entry_id")) != entry_id]
    return True, True


@router.post("/admin/kyc-sync-deadletter/{entry_id}/replay", response_model=TicketKycSyncDeadletterReplayEnvelope, responses=_error_responses())
def replay_admin_kyc_sync_deadletter(
    entry_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_root(user):
        _raise(403, "root_role_required", "root role required")
    entry = next((item for item in _KYC_TICKET_SYNC_DEADLETTER if str(item.get("entry_id")) == entry_id), None)
    if not entry:
        _KYC_TICKET_SYNC_COUNTS["deadletter_replay_not_found"] += 1
        _raise(404, "ticket_sync_deadletter_not_found", "deadletter entry not found", details={"entry_id": entry_id})
    replayed, removed = _replay_deadletter_entry(entry, actor_sub=user.sub, request=request)
    if not replayed:
        _raise(
            409,
            "ticket_sync_replay_failed",
            "ticket not found for replay",
            details={"entry_id": entry_id, "ticket_id": entry.get("ticket_id")},
        )
    return TicketKycSyncDeadletterReplayEnvelope(replayed=replayed, removed=removed, deadletter_entry_id=entry_id)


@router.post("/admin/kyc-sync-deadletter/replay-batch", response_model=TicketKycSyncDeadletterBatchReplayEnvelope, responses=_error_responses())
def replay_admin_kyc_sync_deadletter_batch(
    request: Request,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_root(user):
        _raise(403, "root_role_required", "root role required")
    entries = list(_KYC_TICKET_SYNC_DEADLETTER)[:limit]
    attempted = len(entries)
    replayed = 0
    failed = 0
    removed = 0
    for entry in entries:
        ok, was_removed = _replay_deadletter_entry(entry, actor_sub=user.sub, request=request)
        if ok:
            replayed += 1
        else:
            failed += 1
        if was_removed:
            removed += 1
    audit_event(
        "kyc_ticket_sync_deadletter_replay_batch",
        user.sub,
        request,
        outcome="success",
        attempted_count=attempted,
        replayed_count=replayed,
        failed_count=failed,
        removed_count=removed,
    )
    return TicketKycSyncDeadletterBatchReplayEnvelope(
        attempted_count=attempted,
        replayed_count=replayed,
        failed_count=failed,
        removed_count=removed,
    )

@router.post("", response_model=TicketEnvelope, responses=_error_responses())
def create_ticket(
    body: CreateTicketReq,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    ticket = STORE.create_ticket(owner_sub=user.sub, subject=body.subject.strip(), description=body.description.strip())
    _emit_ticket_alerts("ticket_created", recipients=[user.sub], actor_sub=user.sub, request=request, ticket_id=ticket["ticket_id"], ticket_subject=ticket.get("subject", ""))
    return _wrap_ticket(ticket)


@router.get("", response_model=TicketListEnvelope, responses=_error_responses())
def list_tickets(
    status: Literal["open", "in_progress", "waiting_on_user", "done"] | None = None,
    source: Literal["internal", "jira", "unified"] = "internal",
    workspace_id: str | None = None,
    jira_project_key: str | None = None,
    jira_status: str | None = None,
    jira_assignee_account_id: str | None = None,
    jira_reporter_account_id: str | None = None,
    jira_issue_key: str | None = None,
    assignee_admin_sub: str | None = None,
    owner_sub: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if source in {"jira", "unified"} and not _is_admin(user):
        _raise(403, "admin_role_required", "admin role required")
    if source in {"jira", "unified"} and not (workspace_id or "").strip():
        _raise(400, "workspace_id_required", "workspace_id is required for jira and unified source filters")

    if source == "jira":
        repo = JiraTicketSyncStore()
        mirrors = repo.list_issue_mirrors_for_workspace(workspace_id=str(workspace_id), limit=200)
        filtered = []
        for row in mirrors:
            if jira_project_key and str(row.get("project_key") or "") != jira_project_key:
                continue
            if jira_status and str(row.get("status") or "") != jira_status:
                continue
            if jira_assignee_account_id and str(row.get("assignee_account_id") or "") != jira_assignee_account_id:
                continue
            if jira_reporter_account_id and str(row.get("reporter_account_id") or "") != jira_reporter_account_id:
                continue
            if jira_issue_key and str(row.get("external_issue_key") or "") != jira_issue_key:
                continue
            filtered.append({**row, "source": "jira"})
        sorted_rows = _sort_unified_items(filtered)
        page_rows = _apply_unified_cursor(sorted_rows, cursor)
        page_items = page_rows[:limit]
        next_cursor = None
        if len(page_rows) > limit and page_items:
            last = page_items[-1]
            next_cursor = _encode_unified_cursor(
                updated_at=int(last.get("updated_at") or 0),
                source="jira",
                stable_id=str(last.get("external_issue_id") or ""),
            )
        return _wrap_ticket_list({"tickets": page_items, "next_cursor": next_cursor})

    if source == "unified":
        repo = JiraTicketSyncStore()
        mirrors = repo.list_issue_mirrors_for_workspace(workspace_id=str(workspace_id), limit=200)
        jira_rows = []
        for row in mirrors:
            if jira_project_key and str(row.get("project_key") or "") != jira_project_key:
                continue
            if jira_status and str(row.get("status") or "") != jira_status:
                continue
            if jira_assignee_account_id and str(row.get("assignee_account_id") or "") != jira_assignee_account_id:
                continue
            if jira_reporter_account_id and str(row.get("reporter_account_id") or "") != jira_reporter_account_id:
                continue
            if jira_issue_key and str(row.get("external_issue_key") or "") != jira_issue_key:
                continue
            jira_rows.append({**row, "source": "jira"})
        internal_rows = STORE.list_tickets(
            limit=100,
            cursor=None,
            status=status,
            assignee_sub=(assignee_admin_sub or "").strip() or None,
            owner_sub=(owner_sub or "").strip() or None,
        ).get("tickets", [])
        combined = [*[{**item, "source": "internal"} for item in internal_rows], *jira_rows]
        sorted_rows = _sort_unified_items(combined)
        page_rows = _apply_unified_cursor(sorted_rows, cursor)
        page_items = page_rows[:limit]
        next_cursor = None
        if len(page_rows) > limit and page_items:
            last = page_items[-1]
            next_cursor = _encode_unified_cursor(
                updated_at=int(last.get("updated_at") or 0),
                source=str(last.get("source") or "internal"),
                stable_id=str(last.get("ticket_id") or last.get("external_issue_id") or ""),
            )
        return _wrap_ticket_list({"tickets": page_items, "next_cursor": next_cursor})

    if _is_admin_actor(request, user):
        payload = STORE.list_tickets(
            limit=limit,
            cursor=cursor,
            status=status,
            assignee_sub=(assignee_admin_sub or "").strip() or None,
            owner_sub=(owner_sub or "").strip() or None,
        )
        return _wrap_ticket_list(payload)

    payload = STORE.list_tickets(
        limit=limit,
        cursor=cursor,
        status=None,
        assignee_sub=None,
        owner_sub=user.sub,
    )
    return _wrap_ticket_list(payload)


@router.get("/admin/summary", response_model=TicketAdminSummaryEnvelope, responses=_error_responses())
def admin_ticket_summary(
    stale_after_seconds: int = Query(default=48 * 3600, ge=60, le=30 * 24 * 3600),
    request: Request = None,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin_actor(request, user):
        _raise(403, "admin_role_required", "admin role required")
    summary = STORE.get_admin_summary(stale_after_seconds=stale_after_seconds)
    return TicketAdminSummaryEnvelope(summary=TicketAdminSummary.model_validate(summary))


@router.get("/{ticket_id}", response_model=TicketEnvelope, responses=_error_responses())
def get_ticket(
    ticket_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    ticket = _ticket_or_404(ticket_id)
    if not _can_access_ticket(request, user, ticket):
        _raise(403, "ticket_access_forbidden", "not authorized to access this ticket", details={"ticket_id": ticket_id})
    return _wrap_ticket(ticket)


@router.post("/{ticket_id}/assign", response_model=TicketEnvelope, responses=_error_responses())
def assign_ticket(
    ticket_id: str,
    body: AssignTicketReq,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin_actor(request, user):
        _raise(403, "admin_role_required", "admin role required")

    assignee = body.assignee_admin_sub.strip()
    if not assignee:
        _raise(400, "assignee_required", "assignee_admin_sub required")
    if not _is_assignable_admin(assignee):
        _raise(400, "invalid_assignee_role", "assignee must be an admin or root user", details={"assignee_admin_sub": assignee})

    ticket = _ticket_or_404(ticket_id)
    try:
        updated = STORE.assign_ticket(ticket_id=ticket["ticket_id"], actor_sub=user.sub, assignee_sub=assignee)
        assert updated is not None
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    _emit_ticket_alerts(
        "ticket_assigned",
        recipients=[ticket["owner_sub"], ticket.get("assigned_admin_sub") or "", assignee],
        actor_sub=user.sub,
        request=request,
        ticket_id=ticket["ticket_id"],
        ticket_subject=ticket.get("subject", ""),
        assignee_admin_sub=assignee,
    )
    _sync_kyc_for_ticket_event(ticket_before=ticket, ticket_after=updated, event_type="assigned", actor_sub=user.sub, request=request)
    return _wrap_ticket(updated)


@router.post("/{ticket_id}/messages", response_model=TicketEnvelope, responses=_error_responses())
def add_ticket_message(
    ticket_id: str,
    body: TicketMessageReq,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    ticket = _ticket_or_404(ticket_id)
    if not _can_access_ticket(request, user, ticket):
        _raise(403, "ticket_reply_forbidden", "not authorized to reply to this ticket", details={"ticket_id": ticket_id})

    sender_role = "admin" if _is_admin_actor(request, user) else "user"
    email_targets = [ticket["owner_sub"]]
    assigned_admin_sub = ticket.get("assigned_admin_sub")
    if assigned_admin_sub:
        email_targets.append(assigned_admin_sub)
    try:
        updated = STORE.add_message(
            ticket_id=ticket_id,
            sender_sub=user.sub,
            sender_role=sender_role,
            body=body.body.strip(),
            email_targets=sorted(set(email_targets)),
        )
        assert updated is not None
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    recipients = [ticket["owner_sub"]] if sender_role == "admin" else [ticket.get("assigned_admin_sub") or ""]
    _emit_ticket_alerts("ticket_replied", recipients=recipients, actor_sub=user.sub, request=request, ticket_id=ticket_id, ticket_subject=ticket.get("subject", ""))
    if ticket.get("status") == "done" and updated.get("status") == "open":
        _emit_ticket_alerts("ticket_reopened", recipients=recipients, actor_sub=user.sub, request=request, ticket_id=ticket_id, ticket_subject=ticket.get("subject", ""))
    _sync_kyc_for_ticket_event(
        ticket_before=ticket,
        ticket_after=updated,
        event_type=("message_admin" if sender_role == "admin" else "message_user"),
        actor_sub=user.sub,
        request=request,
    )
    return _wrap_ticket(updated)


@router.post("/{ticket_id}/status", response_model=TicketEnvelope, responses=_error_responses())
def set_ticket_status(
    ticket_id: str,
    body: TicketStatusReq,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin_actor(request, user):
        _raise(403, "admin_role_required", "admin role required")
    ticket = _ticket_or_404(ticket_id)
    try:
        updated = STORE.update_status(ticket_id=ticket["ticket_id"], actor_sub=user.sub, status=body.status)
        assert updated is not None
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    sync_incident_from_ticket(DynamoPaymentIncidentRepository(), ticket_id=ticket_id, ticket_status=body.status)
    _emit_ticket_alerts("ticket_status_changed", recipients=[ticket["owner_sub"]], actor_sub=user.sub, request=request, ticket_id=ticket_id, ticket_subject=ticket.get("subject", ""), status=body.status)
    _sync_kyc_for_ticket_event(ticket_before=ticket, ticket_after=updated, event_type="status_changed", actor_sub=user.sub, request=request)
    return _wrap_ticket(updated)
