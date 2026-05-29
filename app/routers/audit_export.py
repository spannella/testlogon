"""Audit log export endpoints (ENTERPRISE-004).

All endpoints require ROOT role. Mounted at /ui/admin/audit-exports.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

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

    if not categories or not isinstance(categories, list):
        raise HTTPException(status_code=400, detail="categories is required and must be a non-empty list")
    if fmt not in ("csv", "ndjson"):
        raise HTTPException(status_code=400, detail="format must be csv or ndjson")
    if not isinstance(from_date, int) or not isinstance(to_date, int):
        raise HTTPException(status_code=400, detail="from_date and to_date must be integers")

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

    # Dev mode: return inline content
    content = item.get("export_content", "")
    if content:
        fmt = item.get("format", "ndjson")
        if fmt == "csv":
            return PlainTextResponse(
                content=content,
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="audit-export-{export_id}.csv"'},
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
