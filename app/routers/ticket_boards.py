"""TKB-003 / TKB-008: /boards router — a board-named alias of /ticket-spaces.

This router delegates to the SAME `TicketStore` methods as the legacy
`/ticket-spaces` router, so there is exactly one source of truth. A board
created via /boards is visible via /ticket-spaces and vice-versa
(board_id == space_id; physical PK stays SPACE#{id}, no migration).

Differences from the legacy router:
  * Response models expose `board_id` (alongside the legacy `space_id`).
  * Error codes are board-named (e.g. `board_not_found` instead of
    `ticket_space_not_found`), while /ticket-spaces keeps emitting old codes.
  * Adds board column config CRUD (TKB-006/TKB-008): GET/PUT /boards/{id}/columns.

Registered only when S.ticket_boards_enabled is true (defaults off).
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.tickets import STORE, BoardColumnError, TicketStateError

router = APIRouter(prefix="/boards", tags=["boards"])


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


class BoardMemberOut(BaseModel):
    board_id: str
    space_id: str
    member_sub: str
    role: Literal["owner", "editor", "viewer"]
    created_at: int
    updated_at: int


class BoardColumnOut(BaseModel):
    column_id: str
    title: str
    status_key: str
    order: int
    wip_limit: int | None = None
    color: str | None = None


class BoardOut(BaseModel):
    board_id: str
    space_id: str
    owner_sub: str
    name: str
    visibility: Literal["private", "shared"]
    created_at: int
    updated_at: int
    columns: list[BoardColumnOut] = Field(default_factory=list)
    members: list[BoardMemberOut]


class BoardEnvelope(BaseModel):
    board: BoardOut


class BoardListEnvelope(BaseModel):
    items: list[BoardOut]
    next_cursor: str | None = None


class BoardColumnsEnvelope(BaseModel):
    board_id: str
    columns: list[BoardColumnOut]


class CreateBoardReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    visibility: Literal["private", "shared"] = "private"


class AddBoardMemberReq(BaseModel):
    member_sub: str = Field(..., min_length=1)
    role: Literal["owner", "editor", "viewer"]


class BoardColumnIn(BaseModel):
    column_id: str | None = None
    title: str = Field(..., min_length=1, max_length=120)
    status_key: str = Field(..., min_length=1)
    order: int | None = None
    wip_limit: int | None = None
    color: str | None = None


class UpdateBoardColumnsReq(BaseModel):
    columns: list[BoardColumnIn] = Field(..., min_length=1)


class BoardTicketMessage(BaseModel):
    message_id: str
    sender_sub: str
    sender_role: str
    body: str
    created_at: int
    email_alert_queued_for: list[str]


class BoardTicketActivity(BaseModel):
    type: str
    actor_sub: str
    assignee_sub: str | None = None
    status: str | None = None
    created_at: int


class BoardTicketOut(BaseModel):
    ticket_id: str
    subject: str
    owner_sub: str
    status: str
    board_id: str | None = None
    space_id: str | None = None
    assigned_admin_sub: str | None = None
    assigned_to_sub: str | None = None
    assigned_by: str | None = None
    assigned_at: int | None = None
    created_at: int
    updated_at: int
    version: int
    messages: list[BoardTicketMessage]
    activity: list[BoardTicketActivity]


class BoardTicketEnvelope(BaseModel):
    ticket: BoardTicketOut


class BoardTicketListEnvelope(BaseModel):
    items: list[BoardTicketOut]
    next_cursor: str | None = None


class CreateBoardTicketReq(BaseModel):
    subject: str = Field(..., min_length=3, max_length=160)
    description: str = Field(..., min_length=1, max_length=4000)


class AssignBoardTicketReq(BaseModel):
    assignee_sub: str = Field(..., min_length=1)


class BoardTicketMessageReq(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


class BoardTicketStatusReq(BaseModel):
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


def _board_or_404(board_id: str) -> dict[str, Any]:
    board = STORE.get_board(board_id)
    if not board:
        _raise(404, "board_not_found", "board not found", details={"board_id": board_id})
    return board


def _board_member_role(board: dict[str, Any], user_sub: str) -> str | None:
    for item in board.get("members", []):
        if item.get("member_sub") == user_sub:
            return str(item.get("role") or "")
    return None


def _require_board_read(board: dict[str, Any], user_sub: str) -> str:
    role = _board_member_role(board, user_sub)
    if role not in {"owner", "editor", "viewer"}:
        _raise(403, "board_access_forbidden", "not authorized for this board", details={"board_id": board.get("board_id")})
    return role


def _require_board_write(board: dict[str, Any], user_sub: str) -> str:
    role = _board_member_role(board, user_sub)
    if role not in {"owner", "editor"}:
        _raise(403, "board_write_forbidden", "board write role required", details={"board_id": board.get("board_id")})
    return role or ""


def _require_board_owner(board: dict[str, Any], user_sub: str) -> None:
    role = _board_member_role(board, user_sub)
    if role != "owner":
        _raise(403, "board_owner_required", "board owner required", details={"board_id": board.get("board_id")})


def _ticket_state_http_status(exc: TicketStateError) -> int:
    if exc.detail.get("code") == "ticket_update_conflict":
        return 409
    return 400


def _ticket_state_error(exc: TicketStateError) -> dict[str, Any]:
    code = str(exc.detail.get("code") or "invalid_ticket_state")
    message = "ticket update conflict" if code == "ticket_update_conflict" else "invalid ticket state"
    return _error(code, message, details=exc.detail)


def _emit_board_ticket_alerts(event: str, *, recipients: list[str], actor_sub: str, **fields: Any) -> None:
    for recipient in sorted({item for item in recipients if item}):
        audit_event(event, recipient, None, outcome="success", actor_sub=actor_sub, **fields)


def _board_ticket_participants(ticket: dict[str, Any]) -> list[str]:
    participants = [ticket.get("owner_sub", ""), ticket.get("assigned_to_sub", "")]
    for message in ticket.get("messages", []):
        participants.append(str(message.get("sender_sub") or ""))
    for watcher in ticket.get("watchers", []):
        participants.append(str(watcher or ""))
    return [item for item in participants if item]


@router.post("", response_model=BoardEnvelope, responses=_error_responses())
def create_board(
    body: CreateBoardReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = STORE.create_board(owner_sub=user.sub, name=body.name.strip(), visibility=body.visibility)
    return BoardEnvelope(board=BoardOut.model_validate(board))


@router.get("", response_model=BoardListEnvelope, responses=_error_responses())
def list_boards(
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    payload = STORE.list_boards_for_member(member_sub=user.sub, limit=limit, cursor=cursor)
    return BoardListEnvelope(
        items=[BoardOut.model_validate(item) for item in payload.get("boards", [])],
        next_cursor=payload.get("next_cursor"),
    )


@router.get("/{board_id}", response_model=BoardEnvelope, responses=_error_responses())
def get_board(
    board_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_read(board, user.sub)
    return BoardEnvelope(board=BoardOut.model_validate(board))


@router.get("/{board_id}/columns", response_model=BoardColumnsEnvelope, responses=_error_responses())
def get_board_columns(
    board_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_read(board, user.sub)
    return BoardColumnsEnvelope(
        board_id=board.get("board_id", board_id),
        columns=[BoardColumnOut.model_validate(col) for col in board.get("columns", [])],
    )


@router.put("/{board_id}/columns", response_model=BoardEnvelope, responses=_error_responses())
def update_board_columns(
    board_id: str,
    body: UpdateBoardColumnsReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_write(board, user.sub)
    try:
        updated = STORE.update_board_columns(
            board_id=board_id,
            columns=[col.model_dump(exclude_none=True) for col in body.columns],
        )
    except BoardColumnError as exc:
        raise HTTPException(status_code=400, detail=_error(
            str(exc.detail.get("code") or "invalid_board_columns"),
            str(exc.detail.get("message") or "invalid board columns"),
            details=exc.detail,
        )) from exc
    if not updated:
        _raise(404, "board_not_found", "board not found", details={"board_id": board_id})
    return BoardEnvelope(board=BoardOut.model_validate(updated))


@router.post("/{board_id}/members", response_model=BoardEnvelope, responses=_error_responses())
def add_board_member(
    board_id: str,
    body: AddBoardMemberReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_owner(board, user.sub)
    updated = STORE.add_board_member(board_id=board_id, member_sub=body.member_sub.strip(), role=body.role)
    assert updated is not None
    return BoardEnvelope(board=BoardOut.model_validate(updated))


@router.delete("/{board_id}/members/{member_sub}", response_model=BoardEnvelope, responses=_error_responses())
def remove_board_member(
    board_id: str,
    member_sub: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_owner(board, user.sub)
    normalized_member = member_sub.strip()
    if not normalized_member:
        _raise(400, "member_sub_required", "member_sub required")
    if normalized_member == board.get("owner_sub"):
        _raise(400, "cannot_remove_board_owner", "cannot remove board owner", details={"board_id": board_id, "member_sub": normalized_member})
    updated = STORE.remove_board_member(board_id=board_id, member_sub=normalized_member)
    if not updated:
        _raise(404, "board_not_found", "board not found", details={"board_id": board_id})
    return BoardEnvelope(board=BoardOut.model_validate(updated))


@router.post("/{board_id}/tickets", response_model=BoardTicketEnvelope, responses=_error_responses())
def create_board_ticket(
    board_id: str,
    body: CreateBoardTicketReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_write(board, user.sub)
    ticket = STORE.create_ticket(owner_sub=user.sub, subject=body.subject.strip(), description=body.description.strip(), board_id=board_id)
    return BoardTicketEnvelope(ticket=BoardTicketOut.model_validate(ticket))


@router.get("/{board_id}/tickets", response_model=BoardTicketListEnvelope, responses=_error_responses())
def list_board_tickets(
    board_id: str,
    status: Literal["open", "in_progress", "waiting_on_user", "done"] | None = None,
    assignee_sub: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_read(board, user.sub)
    payload = STORE.list_board_tickets(
        board_id=board_id,
        status=status,
        assigned_to_sub=(assignee_sub or "").strip() or None,
        limit=limit,
        cursor=cursor,
    )
    return BoardTicketListEnvelope(
        items=[BoardTicketOut.model_validate(item) for item in payload.get("tickets", [])],
        next_cursor=payload.get("next_cursor"),
    )


def _board_ticket_or_404(board_id: str, ticket_id: str) -> dict[str, Any]:
    ticket = STORE.get_ticket(ticket_id)
    if not ticket or ticket.get("space_id") != board_id:
        _raise(404, "board_ticket_not_found", "board ticket not found", details={"board_id": board_id, "ticket_id": ticket_id})
    return ticket


@router.get("/{board_id}/tickets/{ticket_id}", response_model=BoardTicketEnvelope, responses=_error_responses())
def get_board_ticket(
    board_id: str,
    ticket_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_read(board, user.sub)
    ticket = _board_ticket_or_404(board_id, ticket_id)
    return BoardTicketEnvelope(ticket=BoardTicketOut.model_validate(ticket))


@router.post("/{board_id}/tickets/{ticket_id}/assign", response_model=BoardTicketEnvelope, responses=_error_responses())
def assign_board_ticket(
    board_id: str,
    ticket_id: str,
    body: AssignBoardTicketReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_write(board, user.sub)
    _board_ticket_or_404(board_id, ticket_id)
    assignee_sub = body.assignee_sub.strip()
    assignee_role = _board_member_role(board, assignee_sub)
    if assignee_role not in {"owner", "editor", "viewer"}:
        _raise(400, "invalid_board_assignee", "assignee must be a board member", details={"assignee_sub": assignee_sub})
    try:
        updated = STORE.assign_ticket(ticket_id=ticket_id, actor_sub=user.sub, assignee_sub=assignee_sub)
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    assert updated is not None
    _emit_board_ticket_alerts(
        "ticket_assigned",
        recipients=[updated.get("owner_sub", ""), assignee_sub, *updated.get("watchers", [])],
        actor_sub=user.sub,
        ticket_id=updated.get("ticket_id", ""),
        ticket_subject=updated.get("subject", ""),
        assignee_admin_sub=assignee_sub,
    )
    return BoardTicketEnvelope(ticket=BoardTicketOut.model_validate(updated))


@router.post("/{board_id}/tickets/{ticket_id}/messages", response_model=BoardTicketEnvelope, responses=_error_responses())
def reply_board_ticket(
    board_id: str,
    ticket_id: str,
    body: BoardTicketMessageReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_write(board, user.sub)
    _board_ticket_or_404(board_id, ticket_id)
    try:
        updated = STORE.add_message(ticket_id=ticket_id, sender_sub=user.sub, sender_role="user", body=body.body.strip(), email_targets=[])
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    if not updated:
        _raise(404, "board_ticket_not_found", "board ticket not found", details={"board_id": board_id, "ticket_id": ticket_id})
    event = "ticket_reopened" if updated.get("status") == "open" else "ticket_replied"
    _emit_board_ticket_alerts(
        event,
        recipients=_board_ticket_participants(updated),
        actor_sub=user.sub,
        ticket_id=updated.get("ticket_id", ""),
        ticket_subject=updated.get("subject", ""),
        status=updated.get("status", ""),
    )
    return BoardTicketEnvelope(ticket=BoardTicketOut.model_validate(updated))


@router.post("/{board_id}/tickets/{ticket_id}/status", response_model=BoardTicketEnvelope, responses=_error_responses())
def update_board_ticket_status(
    board_id: str,
    ticket_id: str,
    body: BoardTicketStatusReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    board = _board_or_404(board_id)
    _require_board_write(board, user.sub)
    _board_ticket_or_404(board_id, ticket_id)
    try:
        updated = STORE.update_status(ticket_id=ticket_id, actor_sub=user.sub, status=body.status)
    except TicketStateError as exc:
        raise HTTPException(status_code=_ticket_state_http_status(exc), detail=_ticket_state_error(exc)) from exc
    if not updated:
        _raise(404, "board_ticket_not_found", "board ticket not found", details={"board_id": board_id, "ticket_id": ticket_id})
    _emit_board_ticket_alerts(
        "ticket_status_changed",
        recipients=_board_ticket_participants(updated),
        actor_sub=user.sub,
        ticket_id=updated.get("ticket_id", ""),
        ticket_subject=updated.get("subject", ""),
        status=updated.get("status", ""),
    )
    return BoardTicketEnvelope(ticket=BoardTicketOut.model_validate(updated))
