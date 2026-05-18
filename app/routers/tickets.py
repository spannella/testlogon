from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.tables import T
from app.services.alerts import audit_event
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
    items: list[TicketOut]
    next_cursor: str | None = None


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


def _wrap_ticket_list(payload: dict[str, Any]) -> TicketListEnvelope:
    return TicketListEnvelope(items=[TicketOut.model_validate(item) for item in payload.get("tickets", [])], next_cursor=payload.get("next_cursor"))


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
    assignee_admin_sub: str | None = None,
    owner_sub: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
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
