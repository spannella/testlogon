"""
Admin rate-limit management endpoints (PLATFORM-001).

All endpoints require root role via ``require_ui_session`` + role check.
"""
from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_root
from app.core.settings import S
from app.core.tables import T
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


# ---------------------------------------------------------------------------
# ADMIN-003: reset override, live summary, CSV export
# ---------------------------------------------------------------------------

def _event_ts(evt: Dict[str, Any]) -> int:
    """Extract the unix timestamp from an event's ``sk`` (``{ts}#{event_id}``)."""
    sk = str(evt.get("sk", ""))
    head = sk.split("#", 1)[0]
    try:
        return int(head)
    except (ValueError, TypeError):
        return 0


def _live_summary(events: List[Dict[str, Any]], hours: int) -> Dict[str, Any]:
    """Aggregate events into by_group / by_source / time_series buckets."""
    by_group: Counter = Counter()
    by_source: Counter = Counter()
    bucket_counts: Counter = Counter()

    for evt in events:
        group = str(evt.get("endpoint_group", "") or "unknown")
        by_group[group] += 1

        source = str(evt.get("identity_value", "") or "unknown")
        by_source[source] += 1

        ts = _event_ts(evt)
        if ts:
            # 5-minute (300s) buckets, keyed by ISO minute
            bucket_start = ts - (ts % 300)
            label = datetime.fromtimestamp(bucket_start, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M")
            bucket_counts[label] += 1

    time_series = [
        {"bucket": label, "count": count}
        for label, count in sorted(bucket_counts.items())
    ]
    top_sources = [
        {"source_ip": source, "count": count}
        for source, count in by_source.most_common(20)
    ]

    return {
        "by_group": dict(by_group),
        "by_source": top_sources,
        "time_series": time_series,
        "total_hits": len(events),
        "window_hours": hours,
    }


@router.delete("/config/{group}")
async def reset_config(
    group: str,
    user: AuthenticatedUser = Depends(require_root),
):
    """Reset an endpoint group's config back to its in-code default.

    Removes any persisted override row; the group then reflects defaults.
    """
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    if group not in ENDPOINT_GROUPS and group != "global_ip":
        raise HTTPException(status_code=400, detail=f"Unknown group: {group}")

    try:
        T.rate_limits.delete_item(Key={"pk": "CONFIG#global", "sk": f"GROUP#{group}"})
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail="Failed to reset config") from exc

    # Bust the in-process override cache so the next read reflects defaults.
    from app.services import rate_limit_config as _rlc

    _rlc._CONFIG_CACHE.pop(group, None)
    _rlc._CONFIG_CACHE_TS.pop(group, None)

    return {"ok": True, "group": group, "is_override": False}


@router.get("/live-summary")
async def live_summary(
    hours: int = Query(default=1, ge=1, le=24),
    user: AuthenticatedUser = Depends(require_root),
):
    """Real-time rate-limit hit summary for the last *hours* hours.

    Returns hits grouped by endpoint group and by source, plus a 5-minute
    bucketed time series.
    """
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    events = query_events(hours=hours, limit=1000)
    return _live_summary(events, hours)


@router.get("/events/export")
async def export_events(
    hours: int = Query(default=24, ge=1, le=168),
    status: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_root),
):
    """Export rate-limit events for the last *hours* hours as CSV (capped 10000)."""
    if not S.rate_limit_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Rate limit dashboard is disabled")

    events = query_events(hours=hours, limit=10000, status_filter=status)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp",
        "endpoint_group",
        "identity_type",
        "identity_value",
        "endpoint",
        "method",
        "status",
        "count",
        "limit",
    ])
    for evt in events:
        writer.writerow([
            _event_ts(evt),
            evt.get("endpoint_group", ""),
            evt.get("identity_type", ""),
            evt.get("identity_value", ""),
            evt.get("endpoint", ""),
            evt.get("method", ""),
            evt.get("status", ""),
            evt.get("count", ""),
            evt.get("limit", ""),
        ])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=rate-limit-events.csv",
            "Cache-Control": "no-store",
        },
    )
