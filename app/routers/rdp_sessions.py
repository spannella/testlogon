"""RDP browser transport router — Phase 1 (Option C fallback) per ADR-004.

Two endpoints, both cookie-auth (`require_ui_session`) and owner-scoped:

- ``POST /api/rdp/session`` — reserved native-phase bootstrap. With the master
  gate ``RDP_REMOTE_DESKTOP_ENABLED`` off (default) it returns
  ``503 RDP_FEATURE_DISABLED``; with it on (future native build) it currently
  returns ``501 RDP_NATIVE_NOT_IMPLEMENTED`` until Option A (Guacamole) lands.
  The request/response shape mirrors `CreateVncSessionResp` so the FE
  deep-link + renderer are stable across the fallback→native transition.
- ``GET /api/rdp/fallback`` — Phase-1 fallback metadata for a Windows/RDP host
  (`host_id` resolved owner-scoped). Returns copy-ready host:port/username +
  native-client instructions. No session/token minted.

Ownership is enforced server-side via the host_inventory ``Key={user_sub, sk}``
access pattern (CTI-010): a foreign/unknown ``host_id`` fails closed
(RDP_TARGET_NOT_FOUND).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services.alerts import audit_event
from app.services.rdp_sessions import RdpSessionError, create_session, get_fallback_details
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/api/rdp", tags=["rdp"])
logger = logging.getLogger("app.rdp.api")


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


class CreateRdpSessionReq(BaseModel):
    target_id: str = Field(..., min_length=1, max_length=128)


class RdpFallbackResp(BaseModel):
    available: bool
    host_id: str
    label: str
    hostname: str
    port: int
    username: str
    address: str
    instructions: str
    native_clients: list[str]


def _error(code: str, message: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def _raise(status_code: int, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
    raise HTTPException(status_code=status_code, detail=_error(code, message, details=details))


def _map_error(exc: RdpSessionError) -> None:
    _raise(exc.http_status, exc.code, exc.message, details=exc.details)


def _error_responses() -> dict[int | str, dict[str, Any]]:
    return {
        400: {"model": ErrorEnvelope, "description": "Bad request"},
        401: {"model": ErrorEnvelope, "description": "Unauthorized"},
        403: {"model": ErrorEnvelope, "description": "Forbidden"},
        404: {"model": ErrorEnvelope, "description": "Not found"},
        501: {"model": ErrorEnvelope, "description": "Not implemented"},
        503: {"model": ErrorEnvelope, "description": "Service unavailable"},
    }


@router.post("/session", responses=_error_responses())
def bootstrap_rdp_session(
    body: CreateRdpSessionReq,
    req: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    target_id = body.target_id.strip()
    if not target_id:
        _raise(400, "RDP_TARGET_NOT_FOUND", "target_id is required")
    try:
        session = create_session(user_sub=user.sub, target_id=target_id, user_role=user.role.value)
    except RdpSessionError as exc:
        audit_event(
            "rdp_session_bootstrap",
            user.sub,
            req,
            outcome="failure",
            target_id=target_id,
            error_code=exc.code,
            user_role=user.role.value,
        )
        _map_error(exc)
    # Unreachable in Phase 1 (create_session always raises), but keep the success
    # path explicit so the native build slots in without router changes.
    audit_event(
        "rdp_session_bootstrap",
        user.sub,
        req,
        outcome="success",
        target_id=target_id,
        session_id=session.get("session_id"),
        user_role=user.role.value,
    )
    return session


@router.get("/fallback", response_model=RdpFallbackResp, responses=_error_responses())
def rdp_fallback(
    req: Request,
    host_id: str = Query(..., min_length=1, max_length=128),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        details = get_fallback_details(user_sub=user.sub, host_id=host_id.strip())
    except RdpSessionError as exc:
        audit_event(
            "rdp_fallback_requested",
            user.sub,
            req,
            outcome="failure",
            host_id=host_id.strip(),
            error_code=exc.code,
        )
        _map_error(exc)
    audit_event(
        "rdp_fallback_requested",
        user.sub,
        req,
        outcome="success",
        host_id=host_id.strip(),
    )
    return RdpFallbackResp.model_validate(details)
