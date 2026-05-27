"""
Admin rate-limit management endpoints (PLATFORM-001).

All endpoints require root role via ``require_ui_session`` + role check.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_root
from app.core.settings import S
from app.services.rate_limit_config import (
    ENDPOINT_GROUPS,
    get_all_configs,
    get_group_config,
    save_group_override,
)
from app.services.rate_limit_dashboard import get_top_offenders, query_events
from app.services.rate_limit_store import (
    add_to_allowlist,
    add_to_blocklist,
    list_allowlist,
    list_blocklist,
    remove_from_allowlist,
    remove_from_blocklist,
)

router = APIRouter(prefix="/ui/admin/rate-limits", tags=["admin-rate-limits"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class UpdateConfigReq(BaseModel):
    group: str = Field(..., min_length=1)
    window_seconds: Optional[int] = Field(None, ge=1)
    max_requests_per_user: Optional[int] = Field(None, ge=1)
    max_requests_per_ip: Optional[int] = Field(None, ge=1)
    bypass_roles: Optional[List[str]] = None


class BlocklistAddReq(BaseModel):
    ip: str = Field(..., min_length=1)
    reason: str = Field(default="", max_length=500)
    expires_in_hours: Optional[int] = Field(None, ge=1)


class AllowlistAddReq(BaseModel):
    cidr: str = Field(..., min_length=1)
    reason: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_config(user: AuthenticatedUser = Depends(require_root)):
    """Return the full rate limit configuration (defaults + active overrides)."""
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    all_configs = get_all_configs()

    global_ip_cfg = all_configs.pop("global_ip", {})
    return {
        "global_ip": {
            "window_seconds": global_ip_cfg.get("window_seconds", S.rate_limit_global_ip_window_seconds),
            "max_requests": global_ip_cfg.get("max_requests", S.rate_limit_global_ip_max_requests),
            "enabled": S.rate_limit_global_enabled,
        },
        "groups": {
            name: {
                "description": cfg.get("description", ""),
                "paths": cfg.get("paths", []),
                "window_seconds": cfg.get("window_seconds", 60),
                "max_requests_per_user": cfg.get("max_requests_per_user", 120),
                "max_requests_per_ip": cfg.get("max_requests_per_ip", 200),
                "bypass_roles": cfg.get("bypass_roles", []),
                "is_override": cfg.get("is_override", False),
            }
            for name, cfg in all_configs.items()
        },
    }


@router.put("/config")
async def update_config(
    body: UpdateConfigReq,
    user: AuthenticatedUser = Depends(require_root),
):
    """Update rate limit configuration for an endpoint group."""
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    if body.group not in ENDPOINT_GROUPS and body.group != "global_ip":
        raise HTTPException(status_code=400, detail=f"Unknown group: {body.group}")

    previous = get_group_config(body.group)

    save_group_override(
        body.group,
        window_seconds=body.window_seconds,
        max_requests_per_user=body.max_requests_per_user,
        max_requests_per_ip=body.max_requests_per_ip,
        bypass_roles=body.bypass_roles,
        updated_by=user.sub,
    )

    updated = get_group_config(body.group)

    return {
        "ok": True,
        "group": body.group,
        "previous": {
            "max_requests_per_user": previous.get("max_requests_per_user"),
            "max_requests_per_ip": previous.get("max_requests_per_ip"),
        },
        "updated": {
            "max_requests_per_user": updated.get("max_requests_per_user"),
            "max_requests_per_ip": updated.get("max_requests_per_ip"),
        },
    }


@router.get("/events")
async def get_events(
    hours: int = Query(default=1, ge=1, le=168),
    limit: int = Query(default=100, ge=1, le=1000),
    status: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_root),
):
    """Query rate limit events for the dashboard."""
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    events = query_events(hours=hours, limit=limit, status_filter=status)
    return {"events": events, "count": len(events)}


@router.get("/top-offenders")
async def top_offenders(
    hours: int = Query(default=1, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    user: AuthenticatedUser = Depends(require_root),
):
    """Return top offending IPs and users."""
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    return get_top_offenders(hours=hours, limit=limit)


@router.post("/blocklist", status_code=201)
async def add_blocklist(
    body: BlocklistAddReq,
    user: AuthenticatedUser = Depends(require_root),
):
    """Add an IP to the blocklist."""
    item = add_to_blocklist(
        body.ip,
        reason=body.reason,
        added_by=user.sub,
        expires_in_hours=body.expires_in_hours,
    )
    return {
        "ok": True,
        "entry_id": body.ip,
        "expires_at": item.get("ttl_epoch"),
    }


@router.delete("/blocklist/{entry_id}")
async def delete_blocklist(
    entry_id: str,
    user: AuthenticatedUser = Depends(require_root),
):
    """Remove an IP from the blocklist."""
    remove_from_blocklist(entry_id)
    return {"ok": True, "entry_id": entry_id}


@router.post("/allowlist", status_code=201)
async def add_allowlist_entry(
    body: AllowlistAddReq,
    user: AuthenticatedUser = Depends(require_root),
):
    """Add an IP/CIDR to the allowlist."""
    item = add_to_allowlist(
        body.cidr,
        reason=body.reason,
        added_by=user.sub,
    )
    return {
        "ok": True,
        "entry_id": body.cidr,
    }


@router.delete("/allowlist/{entry_id:path}")
async def delete_allowlist_entry(
    entry_id: str,
    user: AuthenticatedUser = Depends(require_root),
):
    """Remove a CIDR from the allowlist."""
    remove_from_allowlist(entry_id)
    return {"ok": True, "entry_id": entry_id}


@router.get("/blocklist")
async def get_blocklist(user: AuthenticatedUser = Depends(require_root)):
    """List all blocklist entries."""
    return {"entries": list_blocklist()}


@router.get("/allowlist")
async def get_allowlist(user: AuthenticatedUser = Depends(require_root)):
    """List all allowlist entries."""
    return {"entries": list_allowlist()}
