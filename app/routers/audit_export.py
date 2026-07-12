"""Audit log export endpoints (ENTERPRISE-004).

All endpoints require ROOT role. Mounted at /ui/admin/audit-exports.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import base64

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response

from app.services.sessions import require_ui_session
from app.auth.roles import Role
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_adapters import ADAPTERS, VALID_CATEGORIES
from app.services.audit_export_pipeline import (
    create_export_job,
    _merge_sorted_events,
    verify_manifest_signature,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/admin/audit-exports", tags=["audit-export"])


def _require_root(ctx: dict) -> None:
    """Only ROOT can access audit export endpoints."""
    role = ctx.get("role")
    if role != Role.ROOT:
        raise HTTPException(status_code=403, detail="Root access required")


def _validate_categories(categories: list[str]) -> None:
    invalid = set(categories) - VALID_CATEGORIES
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown categories: {', '.join(sorted(invalid))}. "
                   f"Valid: {', '.join(sorted(VALID_CATEGORIES))}",
        )


def _validate_date_range(from_date: int, to_date: int) -> None:
    if from_date > to_date:
        raise HTTPException(status_code=400, detail="from_date must be <= to_date")
    if from_date == 0 and to_date == 0:
        raise HTTPException(status_code=400, detail="Date range is empty")
    max_range = S.audit_export_max_date_range_days * 86400
    if (to_date - from_date) > max_range:
        raise HTTPException(
            status_code=400,
            detail=f"Date range exceeds maximum of {S.audit_export_max_date_range_days} days",
        )


# ---- Export CRUD ----

@router.post("", status_code=201)
async def create_audit_export(
    body: dict,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)

    categories = body.get("categories", [])
    fmt = body.get("format", "ndjson")
    from_date = body.get("from_date", 0)
    to_date = body.get("to_date", 0)
    column_format = body.get("column_format")

    if not categories or not isinstance(categories, list):
        raise HTTPException(status_code=400, detail="categories is required and must be a non-empty list")
    if fmt not in ("csv", "ndjson", "pdf"):
        raise HTTPException(status_code=400, detail="format must be csv, ndjson, or pdf")
    if not isinstance(from_date, int) or not isinstance(to_date, int):
        raise HTTPException(status_code=400, detail="from_date and to_date must be integers")
    # GAP-0211: accounting-software column mapping. Optional; defaults to the
    # generic audit schema. Only applied to CSV billing exports downstream.
    from app.services.audit_export_accounting import VALID_COLUMN_FORMATS
    if column_format not in VALID_COLUMN_FORMATS:
        raise HTTPException(
            status_code=400,
            detail="column_format must be one of: quickbooks, xero (or omitted)",
        )

    _validate_categories(categories)
    _validate_date_range(from_date, to_date)

    user_sub = ctx["user_sub"]

    job = create_export_job(
        categories=categories,
        format=fmt,
        from_ts=from_date,
        to_ts=to_date,
        created_by=user_sub,
        actor_user_id=body.get("actor_user_id"),
        target_user_id=body.get("target_user_id"),
        event_actions=body.get("event_actions"),
        column_format=column_format,
    )

    return _job_to_out(job)


@router.get("")
async def list_audit_exports(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)

    from boto3.dynamodb.conditions import Key

    resp = T.audit_exports.query(
        IndexName="user-created-index",
        KeyConditionExpression=Key("created_by").eq(ctx["user_sub"]),
        ScanIndexForward=False,
        Limit=50,
    )
    items = resp.get("Items", [])

    return {
        "exports": [_job_to_out(item) for item in items],
    }


# ---- Scheduled export CRUD (GAP-0210) ----
#
# NOTE: these /schedules routes MUST be declared before the /{export_id} routes
# below — FastAPI matches routes in declaration order, so a dynamic /{export_id}
# placed first would otherwise capture the literal path segment "schedules".


def _schedule_to_out(item: dict) -> dict:
    return {
        "schedule_id": item.get("schedule_id", ""),
        "created_by": item.get("created_by", ""),
        "categories": list(item.get("categories", [])),
        "format": item.get("format", "ndjson"),
        "cadence": item.get("cadence", ""),
        "lookback_seconds": int(item["lookback_seconds"]) if item.get("lookback_seconds") is not None else None,
        "recipients": list(item.get("recipients", [])),
        "enabled": bool(item.get("enabled", True)),
        "created_at": int(item.get("created_at", 0)),
        "next_run_at": int(item["next_run_at"]) if item.get("next_run_at") is not None else None,
        "last_run_at": int(item["last_run_at"]) if item.get("last_run_at") else None,
        "last_export_id": item.get("last_export_id"),
    }


@router.post("/schedules", status_code=201)
async def create_audit_export_schedule(
    body: dict,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)
    from app.services.audit_export_schedule import (
        CADENCE_OFFSETS,
        create_schedule,
    )

    categories = body.get("categories", [])
    fmt = body.get("format", "ndjson")
    cadence = body.get("cadence")
    recipients = body.get("recipients", [])

    if not categories or not isinstance(categories, list):
        raise HTTPException(status_code=400, detail="categories is required and must be a non-empty list")
    if fmt not in ("csv", "ndjson", "pdf"):
        raise HTTPException(status_code=400, detail="format must be csv, ndjson, or pdf")
    if cadence not in CADENCE_OFFSETS:
        raise HTTPException(
            status_code=400,
            detail=f"cadence must be one of: {', '.join(sorted(CADENCE_OFFSETS))}",
        )
    if not isinstance(recipients, list):
        raise HTTPException(status_code=400, detail="recipients must be a list")
    _validate_categories(categories)

    item = create_schedule(
        created_by=ctx["user_sub"],
        categories=categories,
        format=fmt,
        cadence=cadence,
        recipients=recipients,
        lookback_seconds=body.get("lookback_seconds"),
    )
    return _schedule_to_out(item)


@router.get("/schedules")
async def list_audit_export_schedules(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)
    from app.services.audit_export_schedule import list_schedules

    return {"schedules": [_schedule_to_out(i) for i in list_schedules(ctx["user_sub"])]}


@router.patch("/schedules/{schedule_id}")
async def update_audit_export_schedule(
    schedule_id: str,
    body: dict,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)
    from app.services.audit_export_schedule import (
        get_schedule,
        update_schedule,
    )

    existing = get_schedule(schedule_id)
    if not existing or existing.get("created_by") != ctx["user_sub"]:
        raise HTTPException(status_code=404, detail="Schedule not found")

    categories = body.get("categories")
    if categories is not None:
        if not isinstance(categories, list) or not categories:
            raise HTTPException(status_code=400, detail="categories must be a non-empty list")
        _validate_categories(categories)

    try:
        item = update_schedule(
            schedule_id,
            cadence=body.get("cadence"),
            recipients=body.get("recipients"),
            categories=categories,
            format=body.get("format"),
            enabled=body.get("enabled"),
            lookback_seconds=body.get("lookback_seconds"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except KeyError:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _schedule_to_out(item)


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_audit_export_schedule(
    schedule_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)
    from app.services.audit_export_schedule import delete_schedule, get_schedule

    existing = get_schedule(schedule_id)
    if not existing or existing.get("created_by") != ctx["user_sub"]:
        raise HTTPException(status_code=404, detail="Schedule not found")
    delete_schedule(schedule_id)
    return Response(status_code=204)


# ---- Export read/download (dynamic export_id routes) ----

@router.get("/{export_id}")
async def get_audit_export(
    export_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)

    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")
    return _job_to_out(item)


@router.get("/{export_id}/download")
async def download_audit_export(
    export_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_root(ctx)

    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")
    if item.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Export not yet completed")

    fmt = item.get("format", "ndjson")

    # Dev mode: return inline content. PDF is binary, so it is stored base64
    # encoded under ``export_content_b64`` and served via a binary-safe Response
    # (PlainTextResponse would UTF-8 re-encode and corrupt the bytes).
    if fmt == "pdf":
        content_b64 = item.get("export_content_b64", "")
        if content_b64:
            return Response(
                content=base64.b64decode(content_b64),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="audit-export-{export_id}.pdf"'},
            )
        raise HTTPException(status_code=410, detail="Export content not available")

    content = item.get("export_content", "")
    if content:
        if fmt == "csv":
            # GAP-0211: surface the accounting variant in the filename so the
            # download is self-describing (e.g. ...-quickbooks.csv).
            column_format = item.get("column_format") or ""
            suffix = f"-{column_format}" if column_format in ("quickbooks", "xero") else ""
            return PlainTextResponse(
                content=content,
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="audit-export-{export_id}{suffix}.csv"'},
            )
        else:
            return PlainTextResponse(
                content=content,
                media_type="application/x-ndjson",
                headers={"Content-Disposition": f'attachment; filename="audit-export-{export_id}.ndjson"'},
            )

    raise HTTPException(status_code=410, detail="Export content not available")


# ---- Helper ----

def _job_to_out(item: dict) -> dict:
    return {
        "export_id": item.get("export_id", ""),
        "status": item.get("status", ""),
        "categories": list(item.get("categories", [])),
        "format": item.get("format", "ndjson"),
        "column_format": item.get("column_format") or None,
        "from_date": int(item.get("from_date", 0)),
        "to_date": int(item.get("to_date", 0)),
        "event_count": int(item["event_count"]) if item.get("event_count") is not None else None,
        "file_size_bytes": int(item["file_size_bytes"]) if item.get("file_size_bytes") is not None else None,
        "download_url": item.get("download_url"),
        "download_expires_at": int(item["download_expires_at"]) if item.get("download_expires_at") else None,
        "manifest_sha256": item.get("manifest_sha256"),
        "created_at": int(item.get("created_at", 0)),
        "created_by": item.get("created_by", ""),
        "completed_at": int(item["completed_at"]) if item.get("completed_at") else None,
        "error_message": item.get("error_message"),
        "events_scanned": int(item["events_scanned"]) if item.get("events_scanned") is not None else None,
        "events_written": int(item["events_written"]) if item.get("events_written") is not None else None,
    }


# ── EVT-015: Audit Log Browse (live, paginated, ROOT-only) ─────────────────

from app import models as _models  # noqa: E402 — avoid name collision

browse_router = APIRouter(prefix="/ui/admin", tags=["audit-log-browse"])


def _require_audit_log_browse_enabled() -> None:
    if not S.crm_audit_log_browse_enabled:
        raise HTTPException(status_code=404, detail="not found")


@browse_router.get("/audit-log")
async def browse_audit_log_endpoint(
    category: str = Query(..., description="One of: auth, moderation, broadcast, admin, billing"),
    from_ts: int = Query(..., description="Start Unix timestamp (inclusive)"),
    to_ts: int = Query(..., description="End Unix timestamp (inclusive)"),
    user_sub: Optional[str] = Query(None, description="Filter by actor user_sub"),
    event_type: Optional[str] = Query(None, description="Filter by event_action string"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
    cursor: Optional[str] = Query(None, description="Opaque pagination cursor"),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> dict:
    _require_audit_log_browse_enabled()
    _require_root(ctx)

    # Rate limit: N req/min per ROOT user (configurable)
    from app.services.rate_limit import _bucket_limit  # lazy import
    rate_max = S.crm_audit_log_browse_rate_limit_per_minute
    if not _bucket_limit(ctx["user_sub"], "rl#audit_log_browse", rate_max, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from app.services.audit_log_browse import browse_audit_log  # lazy import (RULE-1)
    try:
        result = browse_audit_log(
            category=category,
            from_ts=from_ts,
            to_ts=to_ts,
            user_sub_filter=user_sub,
            event_type_filter=event_type,
            limit=limit,
            cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return result
