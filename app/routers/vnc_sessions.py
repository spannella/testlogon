from __future__ import annotations

from typing import Any

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.vnc_observability import log_vnc_event, resolve_correlation_id, vnc_trace_span
from app.services.vnc_sessions import VncSessionError, create_session, get_transfer_fallback, teardown_session

router = APIRouter(prefix="/api/vnc", tags=["vnc"])
logger = logging.getLogger("app.vnc.api")


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


class VncCapabilities(BaseModel):
    clipboard: bool
    file_transfer: bool
    drag_drop_upload: bool


class CreateVncSessionReq(BaseModel):
    target_id: str = Field(..., min_length=1, max_length=128)


class VncTimeoutPolicy(BaseModel):
    idle_timeout_seconds: int
    max_session_duration_seconds: int
    warning_seconds: int


class CreateVncSessionResp(BaseModel):
    session_id: str
    ws_url: str
    connect_params: dict[str, str]
    created_at: int
    expires_at: int
    capabilities: VncCapabilities
    timeout_policy: VncTimeoutPolicy


class DeleteVncSessionResp(BaseModel):
    session_id: str
    status: str
    closed_at: int | None = None


class VncTransferFallbackResp(BaseModel):
    session_id: str
    method: str
    label: str
    instructions: str
    url: str
    expires_at: int


def _error(code: str, message: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def _raise(status_code: int, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
    raise HTTPException(status_code=status_code, detail=_error(code, message, details=details))


def _error_responses() -> dict[int | str, dict[str, Any]]:
    return {
        400: {"model": ErrorEnvelope, "description": "Bad request"},
        401: {"model": ErrorEnvelope, "description": "Unauthorized"},
        403: {"model": ErrorEnvelope, "description": "Forbidden"},
        404: {"model": ErrorEnvelope, "description": "Not found"},
        409: {"model": ErrorEnvelope, "description": "Conflict"},
        429: {"model": ErrorEnvelope, "description": "Rate limited"},
        500: {"model": ErrorEnvelope, "description": "Internal error"},
        503: {"model": ErrorEnvelope, "description": "Service unavailable"},
    }


def _map_error(exc: VncSessionError) -> None:
    _raise(exc.http_status, exc.code, exc.message, details=exc.details)


@router.post("/session", response_model=CreateVncSessionResp, responses=_error_responses())
def bootstrap_vnc_session(
    body: CreateVncSessionReq,
    req: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    target_id = body.target_id.strip()
    if not target_id:
        _raise(400, "VNC_TARGET_NOT_FOUND", "target_id is required")

    correlation_id = resolve_correlation_id(req.headers.get("x-correlation-id"))
    with vnc_trace_span("vnc.api.bootstrap", target_id=target_id, user_sub=user.sub, correlation_id=correlation_id):
        try:
            session = create_session(user_sub=user.sub, target_id=target_id, user_role=user.role.value)
        except VncSessionError as exc:
            audit_event(
                "vnc_session_bootstrap",
                user.sub,
                req,
                outcome="failure",
                target_id=target_id,
                error_code=exc.code,
                user_role=user.role.value,
                correlation_id=correlation_id,
            )
            log_vnc_event(
                "api_bootstrap_failed",
                target_id=target_id,
                user_sub=user.sub,
                correlation_id=correlation_id,
                error_code=exc.code,
            )
            logger.warning(
                "vnc_api_bootstrap_failed",
                extra={"target_id": target_id, "user_sub": user.sub, "correlation_id": correlation_id, "error_code": exc.code},
            )
            _map_error(exc)

    audit_event(
        "vnc_session_bootstrap",
        user.sub,
        req,
        outcome="success",
        target_id=target_id,
        session_id=session["session_id"],
        user_role=user.role.value,
        correlation_id=correlation_id,
    )
    log_vnc_event(
        "api_bootstrap_success",
        target_id=target_id,
        session_id=session["session_id"],
        user_sub=user.sub,
        correlation_id=correlation_id,
    )

    return CreateVncSessionResp(
        session_id=session["session_id"],
        ws_url=session["ws_url"],
        connect_params=dict(session["connect_params"]),
        created_at=int(session["created_at"]),
        expires_at=int(session["expires_at"]),
        capabilities=VncCapabilities.model_validate(session["capabilities"]),
        timeout_policy=VncTimeoutPolicy.model_validate(session["timeout_policy"]),
    )


@router.delete("/session/{session_id}", response_model=DeleteVncSessionResp, responses=_error_responses())
def delete_vnc_session(
    session_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    sid = session_id.strip()
    if not sid:
        _raise(400, "VNC_SESSION_NOT_FOUND", "session_id is required")
    correlation_id = resolve_correlation_id(None)
    with vnc_trace_span("vnc.api.teardown", session_id=sid, user_sub=user.sub, correlation_id=correlation_id):
        try:
            session = teardown_session(user_sub=user.sub, session_id=sid)
        except VncSessionError as exc:
            logger.warning(
                "vnc_api_teardown_failed",
                extra={"session_id": sid, "user_sub": user.sub, "correlation_id": correlation_id, "error_code": exc.code},
            )
            _map_error(exc)

    status = "closed" if session.get("state") == "closed" else "already_closed"
    log_vnc_event("api_teardown", session_id=sid, status=status, user_sub=user.sub, correlation_id=correlation_id)
    return DeleteVncSessionResp(session_id=sid, status=status, closed_at=session.get("closed_at"))


@router.get("/session/{session_id}/transfer-fallback", response_model=VncTransferFallbackResp, responses=_error_responses())
def get_vnc_transfer_fallback(
    session_id: str,
    req: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    sid = session_id.strip()
    if not sid:
        _raise(400, "VNC_SESSION_NOT_FOUND", "session_id is required")

    try:
        fallback = get_transfer_fallback(user_sub=user.sub, session_id=sid)
    except VncSessionError as exc:
        audit_event(
            "vnc_transfer_fallback_requested",
            user.sub,
            req,
            outcome="failure",
            session_id=sid,
            error_code=exc.code,
        )
        _map_error(exc)

    audit_event(
        "vnc_transfer_fallback_requested",
        user.sub,
        req,
        outcome="success",
        session_id=sid,
        method=fallback["method"],
        expires_at=fallback["expires_at"],
    )

    return VncTransferFallbackResp.model_validate(fallback)
