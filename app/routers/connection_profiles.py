"""Connection Profiles & Quick Connect API router (INFRA-006).

Prefix: /ui/compute/connection-profiles
All endpoints use cookie-based session auth (require_ui_session) and are
owner-scoped — a user can only read/modify their own connection profiles, and
any referenced SSH key / bastion path / instance must also be owned by the user.

A connection profile is a named saved connection (host or instance + port +
username + which SSH key + optional bastion path + terminal prefs). The
``quick-connect`` action resolves the profile into a connection descriptor and
bumps its ``last_used_at`` for recency ordering. This router references — and
does not re-implement — the SSH key / bastion / instance infrastructure.
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.services.sessions import require_ui_session
from app.models import (
    ConnectionProfileListOut,
    ConnectionProfileOut,
    CreateConnectionProfileIn,
    QuickConnectOut,
    UpdateConnectionProfileIn,
)
from app.services.connection_profiles import (
    ProfileLimitExceeded,
    ProfileNotFound,
    ProfileValidationError,
    ReferenceNotFound,
    create_profile,
    delete_profile,
    get_profile,
    list_profiles,
    quick_connect,
    update_profile,
)

logger = logging.getLogger(__name__)

connection_profiles_router = APIRouter(
    prefix="/ui/compute/connection-profiles", tags=["connection-profiles"]
)


# ─── List profiles (favorites + recent first) ─────────────────────

@connection_profiles_router.get("", response_model=ConnectionProfileListOut)
async def list_connection_profiles(session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    profiles = list_profiles(user_sub)
    return ConnectionProfileListOut(profiles=profiles, total=len(profiles))


# ─── Create profile ───────────────────────────────────────────────

@connection_profiles_router.post("", status_code=201, response_model=ConnectionProfileOut)
async def create_connection_profile(
    body: CreateConnectionProfileIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = create_profile(
            user_sub,
            label=body.label,
            protocol=body.protocol,
            hostname=body.hostname or "",
            instance_id=body.instance_id or "",
            port=body.port,
            username=body.username or "",
            auth_method=body.auth_method,
            ssh_key_id=body.ssh_key_id or "",
            bastion_path_id=body.bastion_path_id or "",
            terminal_cols=body.terminal_cols,
            terminal_rows=body.terminal_rows,
            terminal_font_size=body.terminal_font_size,
            terminal_color_scheme=body.terminal_color_scheme,
            is_favorite=body.is_favorite,
            auto_connect=body.auto_connect,
        )
    except ProfileLimitExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ReferenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ProfileValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ConnectionProfileOut(**result)


# ─── Get profile ──────────────────────────────────────────────────

@connection_profiles_router.get("/{profile_id}", response_model=ConnectionProfileOut)
async def get_connection_profile(
    profile_id: str, session: Dict = Depends(require_ui_session)
):
    user_sub = session["user_sub"]
    result = get_profile(user_sub, profile_id)
    if not result:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    return ConnectionProfileOut(**result)


# ─── Quick connect (resolve + bump last_used) ─────────────────────

@connection_profiles_router.post(
    "/{profile_id}/quick-connect", response_model=QuickConnectOut
)
async def quick_connect_profile(
    profile_id: str, session: Dict = Depends(require_ui_session)
):
    user_sub = session["user_sub"]
    try:
        result = quick_connect(user_sub, profile_id)
    except ProfileNotFound:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    except ReferenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ProfileValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return QuickConnectOut(**result)


# ─── Update profile ───────────────────────────────────────────────

@connection_profiles_router.patch("/{profile_id}", response_model=ConnectionProfileOut)
async def update_connection_profile(
    profile_id: str,
    body: UpdateConnectionProfileIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = update_profile(
            user_sub,
            profile_id,
            label=body.label,
            hostname=body.hostname,
            instance_id=body.instance_id,
            port=body.port,
            username=body.username,
            auth_method=body.auth_method,
            ssh_key_id=body.ssh_key_id,
            bastion_path_id=body.bastion_path_id,
            terminal_cols=body.terminal_cols,
            terminal_rows=body.terminal_rows,
            terminal_font_size=body.terminal_font_size,
            terminal_color_scheme=body.terminal_color_scheme,
            is_favorite=body.is_favorite,
            auto_connect=body.auto_connect,
        )
    except ProfileNotFound:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    except ReferenceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ProfileValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ConnectionProfileOut(**result)


# ─── Delete profile ───────────────────────────────────────────────

@connection_profiles_router.delete("/{profile_id}", status_code=204)
async def delete_connection_profile(
    profile_id: str, session: Dict = Depends(require_ui_session)
):
    user_sub = session["user_sub"]
    try:
        delete_profile(user_sub, profile_id)
    except ProfileNotFound:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    return None
