"""Multi-Hop SSH Bastion API router (INFRA-011).

Prefix: /ui/compute/bastion
All endpoints use cookie-based session auth (require_ui_session) and are
owner-scoped — a user can only read/modify their own bastion paths.

Bastion paths model an ordered chain of jump hosts -> target. The router
validates each hop, persists the chain, and exposes the resolved ProxyJump /
ssh_config representation.
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.services.sessions import require_ui_session
from app.models import (
    CreateSshBastionPathIn,
    SshBastionPathListOut,
    SshBastionPathOut,
    SshBastionResolvedOut,
    UpdateSshBastionPathIn,
)
from app.services.ssh_bastion import (
    BastionPathLimitExceeded,
    BastionPathNotFound,
    ChainValidationError,
    InvalidHop,
    create_path,
    delete_path,
    get_path,
    list_paths,
    resolve_path,
    update_path,
)

logger = logging.getLogger(__name__)

ssh_bastion_router = APIRouter(prefix="/ui/compute/bastion", tags=["ssh-bastion"])


def _hop_dicts(hops):
    return [h.model_dump() for h in hops] if hops else []


# ─── List paths ───────────────────────────────────────────────────

@ssh_bastion_router.get("/paths", response_model=SshBastionPathListOut)
async def list_bastion_paths(session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    paths = list_paths(user_sub)
    return SshBastionPathListOut(paths=paths, total=len(paths))


# ─── Create path ──────────────────────────────────────────────────

@ssh_bastion_router.post("/paths", status_code=201, response_model=SshBastionPathOut)
async def create_bastion_path(
    body: CreateSshBastionPathIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = create_path(
            user_sub,
            label=body.label,
            description=body.description,
            jump_hops=_hop_dicts(body.jump_hops),
            target=body.target.model_dump(),
        )
    except BastionPathLimitExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except (InvalidHop, ChainValidationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SshBastionPathOut(**result)


# ─── Get path ─────────────────────────────────────────────────────

@ssh_bastion_router.get("/paths/{path_id}", response_model=SshBastionPathOut)
async def get_bastion_path(path_id: str, session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    result = get_path(user_sub, path_id)
    if not result:
        raise HTTPException(status_code=404, detail="Bastion path not found")
    return SshBastionPathOut(**result)


# ─── Resolve path (ProxyJump / ssh_config) ────────────────────────

@ssh_bastion_router.get("/paths/{path_id}/resolve", response_model=SshBastionResolvedOut)
async def resolve_bastion_path(path_id: str, session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    try:
        result = resolve_path(user_sub, path_id)
    except BastionPathNotFound:
        raise HTTPException(status_code=404, detail="Bastion path not found")
    except ChainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SshBastionResolvedOut(**result)


# ─── Update path ──────────────────────────────────────────────────

@ssh_bastion_router.patch("/paths/{path_id}", response_model=SshBastionPathOut)
async def update_bastion_path(
    path_id: str,
    body: UpdateSshBastionPathIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = update_path(
            user_sub,
            path_id,
            label=body.label,
            description=body.description,
            jump_hops=_hop_dicts(body.jump_hops) if body.jump_hops is not None else None,
            target=body.target.model_dump() if body.target is not None else None,
        )
    except BastionPathNotFound:
        raise HTTPException(status_code=404, detail="Bastion path not found")
    except (InvalidHop, ChainValidationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SshBastionPathOut(**result)


# ─── Delete path ──────────────────────────────────────────────────

@ssh_bastion_router.delete("/paths/{path_id}", status_code=204)
async def delete_bastion_path(path_id: str, session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    try:
        delete_path(user_sub, path_id)
    except BastionPathNotFound:
        raise HTTPException(status_code=404, detail="Bastion path not found")
    return None
