from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.tickets import STORE, TicketStateError

router = APIRouter(prefix="/ticket-spaces", tags=["ticket-spaces"])


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


class SpaceMemberOut(BaseModel):
    space_id: str
    member_sub: str
    role: Literal["owner", "editor", "viewer"]
    created_at: int
    updated_at: int


class TicketSpaceOut(BaseModel):
    space_id: str
    owner_sub: str
    name: str
    visibility: Literal["private", "shared"]
    created_at: int
    updated_at: int
    members: list[SpaceMemberOut]


class TicketSpaceEnvelope(BaseModel):
    space: TicketSpaceOut


class TicketSpaceListEnvelope(BaseModel):
    items: list[TicketSpaceOut]
    next_cursor: str | None = None


class CreateSpaceReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    visibility: Literal["private", "shared"] = "private"


class AddSpaceMemberReq(BaseModel):
    member_sub: str = Field(..., min_length=1)
    role: Literal["owner", "editor", "viewer"]


class SpaceTicketMessage(BaseModel):
    message_id: str
    sender_sub: str
    sender_role: str
    body: str
    created_at: int
    email_alert_queued_for: list[str]


class SpaceTicketActivity(BaseModel):
    type: str
    actor_sub: str
    assignee_sub: str | None = None
    status: str | None = None
    created_at: int


class SpaceTicketOut(BaseModel):
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
    messages: list[SpaceTicketMessage]
    activity: list[SpaceTicketActivity]


class SpaceTicketEnvelope(BaseModel):
    ticket: SpaceTicketOut


class SpaceTicketListEnvelope(BaseModel):
    items: list[SpaceTicketOut]
    next_cursor: str | None = None


class CreateSpaceTicketReq(BaseModel):
    subject: str = Field(..., min_length=3, max_length=160)
    description: str = Field(..., min_length=1, max_length=4000)


class AssignSpaceTicketReq(BaseModel):
    assignee_sub: str = Field(..., min_length=1)


class SpaceTicketMessageReq(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


class SpaceTicketStatusReq(BaseModel):
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


def _space_or_404(space_id: str) -> dict[str, Any]:
    space = STORE.get_space(space_id)
    if not space:
        _raise(404, "ticket_space_not_found", "ticket space not found", details={"space_id": space_id})
    return space


def _space_member_role(space: dict[str, Any], user_sub: str) -> str | None:
    for item in space.get("members", []):
        if item.get("member_sub") == user_sub:
            return str(item.get("role") or "")
    return None


def _require_space_read(space: dict[str, Any], user_sub: str) -> str:
    role = _space_member_role(space, user_sub)
    if role not in {"owner", "editor", "viewer"}:
        _raise(403, "space_access_forbidden", "not authorized for this ticket space", details={"space_id": space.get("space_id")})
    return role


def _require_space_write(space: dict[str, Any], user_sub: str) -> str:
    role = _space_member_role(space, user_sub)
    if role not in {"owner", "editor"}:
        _raise(403, "space_write_forbidden", "space write role required", details={"space_id": space.get("space_id")})
    return role or ""


def _require_space_owner(space: dict[str, Any], user_sub: str) -> None:
    role = _space_member_role(space, user_sub)
    if role != "owner":
        _raise(403, "space_owner_required", "space owner required", details={"space_id": space.get("space_id")})


def _ticket_state_http_status(exc: TicketStateError) -> int:
    if exc.detail.get("code") == "ticket_update_conflict":
        return 409
    return 400


def _ticket_state_error(exc: TicketStateError) -> dict[str, Any]:
    code = str(exc.detail.get("code") or "invalid_ticket_state")
    message = "ticket update conflict" if code == "ticket_update_conflict" else "invalid ticket state"
    return _error(code, message, details=exc.detail)


def _emit_space_ticket_alerts(event: str, *, recipients: list[str], actor_sub: str, **fields: Any) -> None:
    for recipient in sorted({item for item in recipients if item}):
        audit_event(event, recipient, None, outcome="success", actor_sub=actor_sub, **fields)


def _space_ticket_participants(ticket: dict[str, Any]) -> list[str]:
    participants = [ticket.get("owner_sub", ""), ticket.get("assigned_to_sub", "")]
    for message in ticket.get("messages", []):
        participants.append(str(message.get("sender_sub") or ""))
    for watcher in ticket.get("watchers", []):
        participants.append(str(watcher or ""))
    return [item for item in participants if item]


@router.post("", response_model=TicketSpaceEnvelope, responses=_error_responses())
def create_ticket_space(
    body: CreateSpaceReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = STORE.create_space(owner_sub=user.sub, name=body.name.strip(), visibility=body.visibility)
    return TicketSpaceEnvelope(space=TicketSpaceOut.model_validate(space))


@router.get("", response_model=TicketSpaceListEnvelope, responses=_error_responses())
def list_ticket_spaces(
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    payload = STORE.list_spaces_for_member(member_sub=user.sub, limit=limit, cursor=cursor)
    return TicketSpaceListEnvelope(
        items=[TicketSpaceOut.model_validate(item) for item in payload.get("spaces", [])],
        next_cursor=payload.get("next_cursor"),
    )


@router.get("/{space_id}", response_model=TicketSpaceEnvelope, responses=_error_responses())
def get_ticket_space(
    space_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_read(space, user.sub)
    return TicketSpaceEnvelope(space=TicketSpaceOut.model_validate(space))


@router.post("/{space_id}/members", response_model=TicketSpaceEnvelope, responses=_error_responses())
def add_ticket_space_member(
    space_id: str,
    body: AddSpaceMemberReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_owner(space, user.sub)
    updated = STORE.add_space_member(space_id=space_id, member_sub=body.member_sub.strip(), role=body.role)
    assert updated is not None
    return TicketSpaceEnvelope(space=TicketSpaceOut.model_validate(updated))


@router.delete("/{space_id}/members/{member_sub}", response_model=TicketSpaceEnvelope, responses=_error_responses())
def remove_ticket_space_member(
    space_id: str,
    member_sub: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_owner(space, user.sub)
    normalized_member = member_sub.strip()
    if not normalized_member:
        _raise(400, "member_sub_required", "member_sub required")
    if normalized_member == space.get("owner_sub"):
        _raise(400, "cannot_remove_space_owner", "cannot remove space owner", details={"space_id": space_id, "member_sub": normalized_member})
    updated = STORE.remove_space_member(space_id=space_id, member_sub=normalized_member)
    if not updated:
        _raise(404, "ticket_space_not_found", "ticket space not found", details={"space_id": space_id})
    return TicketSpaceEnvelope(space=TicketSpaceOut.model_validate(updated))


@router.post("/{space_id}/tickets", response_model=SpaceTicketEnvelope, responses=_error_responses())
def create_space_ticket(
    space_id: str,
    body: CreateSpaceTicketReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_write(space, user.sub)
    ticket = STORE.create_ticket(owner_sub=user.sub, subject=body.subject.strip(), description=body.description.strip(), space_id=space_id)
    return SpaceTicketEnvelope(ticket=SpaceTicketOut.model_validate(ticket))


@router.get("/{space_id}/tickets", response_model=SpaceTicketListEnvelope, responses=_error_responses())
def list_space_tickets(
    space_id: str,
    status: Literal["open", "in_progress", "waiting_on_user", "done"] | None = None,
    assignee_sub: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_read(space, user.sub)
    payload = STORE.list_space_tickets(
        space_id=space_id,
        status=status,
        assigned_to_sub=(assignee_sub or "").strip() or None,
        limit=limit,
        cursor=cursor,
    )
    return SpaceTicketListEnvelope(
        items=[SpaceTicketOut.model_validate(item) for item in payload.get("tickets", [])],
        next_cursor=payload.get("next_cursor"),
    )


def _space_ticket_or_404(space_id: str, ticket_id: str) -> dict[str, Any]:
    ticket = STORE.get_ticket(ticket_id)
    if not ticket or ticket.get("space_id") != space_id:
        _raise(404, "space_ticket_not_found", "space ticket not found", details={"space_id": space_id, "ticket_id": ticket_id})
    return ticket


@router.get("/{space_id}/tickets/{ticket_id}", response_model=SpaceTicketEnvelope, responses=_error_responses())
def get_space_ticket(
    space_id: str,
    ticket_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_read(space, user.sub)
    ticket = _space_ticket_or_404(space_id, ticket_id)
    return SpaceTicketEnvelope(ticket=SpaceTicketOut.model_validate(ticket))


@router.post("/{space_id}/tickets/{ticket_id}/assign", response_model=SpaceTicketEnvelope, responses=_error_responses())
def assign_space_ticket(
    space_id: str,
    ticket_id: str,
    body: AssignSpaceTicketReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_write(space, user.sub)
    _space_ticket_or_404(space_id, ticket_id)
    assignee_sub = body.assignee_sub.strip()
    assignee_role = _space_member_role(space, assignee_sub)
    if assignee_role not in {"owner", "editor", "viewer"}:
        _raise(400, "invalid_space_assignee", "assignee must be a space member", details={"assignee_sub": assignee_sub})
    try:
        updated = STORE.assign_ticket(ticket_id=ticket_id, actor_sub=user.sub, assignee_sub=assignee_sub)
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    assert updated is not None
    _emit_space_ticket_alerts(
        "ticket_assigned",
        recipients=[updated.get("owner_sub", ""), assignee_sub, *updated.get("watchers", [])],
        actor_sub=user.sub,
        ticket_id=updated.get("ticket_id", ""),
        ticket_subject=updated.get("subject", ""),
        assignee_admin_sub=assignee_sub,
    )
    return SpaceTicketEnvelope(ticket=SpaceTicketOut.model_validate(updated))


@router.post("/{space_id}/tickets/{ticket_id}/messages", response_model=SpaceTicketEnvelope, responses=_error_responses())
def reply_space_ticket(
    space_id: str,
    ticket_id: str,
    body: SpaceTicketMessageReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_write(space, user.sub)
    _space_ticket_or_404(space_id, ticket_id)
    try:
        updated = STORE.add_message(ticket_id=ticket_id, sender_sub=user.sub, sender_role="user", body=body.body.strip(), email_targets=[])
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    if not updated:
        _raise(404, "space_ticket_not_found", "space ticket not found", details={"space_id": space_id, "ticket_id": ticket_id})
    event = "ticket_reopened" if updated.get("status") == "open" else "ticket_replied"
    _emit_space_ticket_alerts(
        event,
        recipients=_space_ticket_participants(updated),
        actor_sub=user.sub,
        ticket_id=updated.get("ticket_id", ""),
        ticket_subject=updated.get("subject", ""),
        status=updated.get("status", ""),
    )
    return SpaceTicketEnvelope(ticket=SpaceTicketOut.model_validate(updated))


@router.post("/{space_id}/tickets/{ticket_id}/status", response_model=SpaceTicketEnvelope, responses=_error_responses())
def update_space_ticket_status(
    space_id: str,
    ticket_id: str,
    body: SpaceTicketStatusReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    space = _space_or_404(space_id)
    _require_space_write(space, user.sub)
    _space_ticket_or_404(space_id, ticket_id)
    try:
        updated = STORE.update_status(ticket_id=ticket_id, actor_sub=user.sub, status=body.status)
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    if not updated:
        _raise(404, "space_ticket_not_found", "space ticket not found", details={"space_id": space_id, "ticket_id": ticket_id})
    _emit_space_ticket_alerts(
        "ticket_status_changed",
        recipients=_space_ticket_participants(updated),
        actor_sub=user.sub,
        ticket_id=updated.get("ticket_id", ""),
        ticket_subject=updated.get("subject", ""),
        status=updated.get("status", ""),
    )
    return SpaceTicketEnvelope(ticket=SpaceTicketOut.model_validate(updated))
