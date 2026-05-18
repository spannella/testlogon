from __future__ import annotations

import base64
import json
import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.tables import T
from app.services.alerts import audit_event
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.sessions import require_ui_session
from app.services.tickets import STORE, TicketStateError
from app.services.payment_incidents_store import DynamoPaymentIncidentRepository
from app.services.payment_incident_ticket_sync import sync_incident_from_ticket

router = APIRouter(prefix="/tickets", tags=["tickets"])


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


def _can_access_ticket(user: AuthenticatedUser, ticket: dict) -> bool:
    return user.sub == ticket["owner_sub"] or _is_admin(user)


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
    for recipient in sorted({item for item in recipients if item}):
        audit_event(event, recipient, request, outcome="success", actor_sub=actor_sub, **fields)

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

    if _is_admin(user):
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
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin(user):
        _raise(403, "admin_role_required", "admin role required")
    summary = STORE.get_admin_summary(stale_after_seconds=stale_after_seconds)
    return TicketAdminSummaryEnvelope(summary=TicketAdminSummary.model_validate(summary))


@router.get("/{ticket_id}", response_model=TicketEnvelope, responses=_error_responses())
def get_ticket(
    ticket_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    ticket = _ticket_or_404(ticket_id)
    if not _can_access_ticket(user, ticket):
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
    if not _is_admin(user):
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
    if not _can_access_ticket(user, ticket):
        _raise(403, "ticket_reply_forbidden", "not authorized to reply to this ticket", details={"ticket_id": ticket_id})

    sender_role = "admin" if _is_admin(user) else "user"
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
    return _wrap_ticket(updated)


@router.post("/{ticket_id}/status", response_model=TicketEnvelope, responses=_error_responses())
def set_ticket_status(
    ticket_id: str,
    body: TicketStatusReq,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if not _is_admin(user):
        _raise(403, "admin_role_required", "admin role required")
    ticket = _ticket_or_404(ticket_id)
    try:
        updated = STORE.update_status(ticket_id=ticket["ticket_id"], actor_sub=user.sub, status=body.status)
        assert updated is not None
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    sync_incident_from_ticket(DynamoPaymentIncidentRepository(), ticket_id=ticket_id, ticket_status=body.status)
    _emit_ticket_alerts("ticket_status_changed", recipients=[ticket["owner_sub"]], actor_sub=user.sub, request=request, ticket_id=ticket_id, ticket_subject=ticket.get("subject", ""), status=body.status)
    return _wrap_ticket(updated)
