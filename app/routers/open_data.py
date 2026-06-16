"""Open Data router (CSN-005): Branches + ATMs.

Two APIRouter instances in one file (mirrors app/routers/calendar.py pattern):
  router        — admin write (/ui/open-data, require_root_session)
  public_router — public read (/open-data, no auth)

Registered in app/main.py only when S.open_data_enabled is True.
Public routes are also added to API_KEY_ROUTE_EXEMPTIONS in
app/services/api_key_route_scope_registry.py.
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import require_root_session
from app.core.settings import S
from app.models import AtmIn, AtmOut, BranchIn, BranchOut, OpenDataListOut

router = APIRouter(prefix="/ui/open-data", tags=["open_data_admin"])
public_router = APIRouter(prefix="/open-data", tags=["open_data_public"])

_RESOURCE_ID_RE = re.compile(r"^(brn|atm)_[0-9a-f]{32}$")


def _require_enabled() -> None:
    if not S.open_data_enabled:
        raise HTTPException(404, "Not found")


def _validate_resource_id(resource_id: str, prefix: str) -> None:
    if not _RESOURCE_ID_RE.match(resource_id):
        raise HTTPException(400, {"code": "invalid_resource_id", "resource_id": resource_id})
    if not resource_id.startswith(prefix):
        raise HTTPException(400, {"code": "invalid_resource_id", "resource_id": resource_id})


# ---------------------------------------------------------------------------
# Admin Branch endpoints
# ---------------------------------------------------------------------------

@router.post("/branches", status_code=201)
async def create_branch(
    req: Request,
    body: BranchIn,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    from app.services.open_data import upsert_branch
    return upsert_branch(ctx.sub, body, req)


@router.put("/branches/{branch_id}")
async def update_branch(
    req: Request,
    branch_id: str,
    body: BranchIn,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    _validate_resource_id(branch_id, "brn_")
    from app.services.open_data import upsert_branch
    return upsert_branch(ctx.sub, body, req, branch_id=branch_id)


@router.delete("/branches/{branch_id}", status_code=204, response_model=None)
async def admin_delete_branch(
    req: Request,
    branch_id: str,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    _validate_resource_id(branch_id, "brn_")
    from app.services.open_data import delete_resource
    delete_resource("BRANCH", branch_id, ctx.sub, req)


@router.get("/branches")
async def admin_list_branches(
    active_only: bool = Query(False),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx=Depends(require_root_session),
):
    _require_enabled()
    from app.services.open_data import list_branches
    items, next_cursor = list_branches(active_only=active_only, cursor=cursor, limit=limit)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/branches/{branch_id}")
async def admin_get_branch(
    branch_id: str,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    _validate_resource_id(branch_id, "brn_")
    from app.services.open_data import get_branch
    item = get_branch(branch_id)
    if item is None:
        raise HTTPException(404, {"code": "open_data_not_found"})
    return item


# ---------------------------------------------------------------------------
# Admin ATM endpoints
# ---------------------------------------------------------------------------

@router.post("/atms", status_code=201)
async def create_atm(
    req: Request,
    body: AtmIn,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    from app.services.open_data import upsert_atm
    return upsert_atm(ctx.sub, body, req)


@router.put("/atms/{atm_id}")
async def update_atm(
    req: Request,
    atm_id: str,
    body: AtmIn,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    _validate_resource_id(atm_id, "atm_")
    from app.services.open_data import upsert_atm
    return upsert_atm(ctx.sub, body, req, atm_id=atm_id)


@router.delete("/atms/{atm_id}", status_code=204, response_model=None)
async def admin_delete_atm(
    req: Request,
    atm_id: str,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    _validate_resource_id(atm_id, "atm_")
    from app.services.open_data import delete_resource
    delete_resource("ATM", atm_id, ctx.sub, req)


@router.get("/atms")
async def admin_list_atms(
    active_only: bool = Query(False),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx=Depends(require_root_session),
):
    _require_enabled()
    from app.services.open_data import list_atms
    items, next_cursor = list_atms(active_only=active_only, cursor=cursor, limit=limit)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/atms/{atm_id}")
async def admin_get_atm(
    atm_id: str,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    _validate_resource_id(atm_id, "atm_")
    from app.services.open_data import get_atm
    item = get_atm(atm_id)
    if item is None:
        raise HTTPException(404, {"code": "open_data_not_found"})
    return item


# ---------------------------------------------------------------------------
# Public read endpoints (no auth)
# ---------------------------------------------------------------------------

@public_router.get("/branches")
async def public_list_branches(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_enabled()
    lim = min(limit, getattr(S, "open_data_list_max_limit", 200))
    from app.services.open_data import list_branches
    items, next_cursor = list_branches(active_only=True, cursor=cursor, limit=lim)
    return {"items": items, "next_cursor": next_cursor}


@public_router.get("/branches/{branch_id}")
async def public_get_branch(branch_id: str):
    _require_enabled()
    from app.services.open_data import get_branch
    item = get_branch(branch_id)
    if item is None or not item.get("is_active"):
        raise HTTPException(404, {"code": "open_data_not_found"})
    return item


@public_router.get("/atms")
async def public_list_atms(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_enabled()
    lim = min(limit, getattr(S, "open_data_list_max_limit", 200))
    from app.services.open_data import list_atms
    items, next_cursor = list_atms(active_only=True, cursor=cursor, limit=lim)
    return {"items": items, "next_cursor": next_cursor}


@public_router.get("/atms/{atm_id}")
async def public_get_atm(atm_id: str):
    _require_enabled()
    from app.services.open_data import get_atm
    item = get_atm(atm_id)
    if item is None or not item.get("is_active"):
        raise HTTPException(404, {"code": "open_data_not_found"})
    return item
