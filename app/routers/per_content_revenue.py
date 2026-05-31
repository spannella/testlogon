"""Per-Content Revenue Breakdown router (FIN-006).

Creator-facing endpoints that attribute billing-ledger revenue to the content
item that generated it. All endpoints are scoped to the authenticated
creator: a creator can only ever see their own content revenue.

Prefix: ``/ui/analytics/content-revenue``
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.core.settings import S
from app.models import ContentRevenueDetailOut, ContentRevenueListOut
from app.services.per_content_revenue import (
    VALID_CONTENT_TYPES,
    VALID_SORT_FIELDS,
    export_content_revenue_csv,
    get_content_revenue_detail,
    get_content_revenue_list,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

per_content_revenue_router = APIRouter(
    prefix="/ui/analytics/content-revenue", tags=["analytics", "content-revenue"]
)

_DATE_FMT = "%Y-%m-%d"
_MAX_RANGE_DAYS = 365


def _require_enabled() -> None:
    if not S.per_content_revenue_enabled:
        raise HTTPException(status_code=404, detail="Feature not available")


def _parse_date_to_ts(s: str, *, end: bool = False) -> int:
    """Parse a YYYY-MM-DD date into a UTC Unix timestamp.

    ``end=True`` returns end-of-day (23:59:59) so to_date is inclusive.
    """
    try:
        dt = datetime.strptime(s, _DATE_FMT).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail=f"Date must be YYYY-MM-DD format: {s}")
    if end:
        dt = dt.replace(hour=23, minute=59, second=59)
    return int(dt.timestamp())


def _resolve_range(from_date: Optional[str], to_date: Optional[str]) -> tuple[int, int]:
    from_ts = _parse_date_to_ts(from_date) if from_date else 0
    to_ts = _parse_date_to_ts(to_date, end=True) if to_date else 0
    if from_date and to_date:
        fd = datetime.strptime(from_date, _DATE_FMT)
        td = datetime.strptime(to_date, _DATE_FMT)
        if fd > td:
            raise HTTPException(status_code=422, detail="from_date must be before to_date")
        if (td - fd).days > _MAX_RANGE_DAYS:
            raise HTTPException(status_code=422, detail="Date range cannot exceed 365 days")
    return from_ts, to_ts


def _validate_content_type(content_type: Optional[str]) -> Optional[str]:
    if content_type and content_type not in VALID_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail="content_type must be vod, post, or broadcast",
        )
    return content_type


# ── Endpoints ────────────────────────────────────────────────────


@per_content_revenue_router.get("", response_model=ContentRevenueListOut)
@per_content_revenue_router.get("/", response_model=ContentRevenueListOut)
def list_content_revenue(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    sort_by: str = Query(default="total_cents"),
    sort_order: str = Query(default="desc"),
    content_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
) -> ContentRevenueListOut:
    _require_enabled()
    if sort_by not in VALID_SORT_FIELDS:
        raise HTTPException(
            status_code=422,
            detail="sort_by must be one of: total_cents, tips_cents, unlocks_cents, published_at",
        )
    _validate_content_type(content_type)
    from_ts, to_ts = _resolve_range(from_date, to_date)
    user_id = session["user_sub"]

    result = get_content_revenue_list(
        user_id,
        from_ts=from_ts,
        to_ts=to_ts,
        sort_by=sort_by,
        sort_order=sort_order,
        content_type=content_type,
        limit=limit,
        cursor=cursor,
    )
    return ContentRevenueListOut(**result)


@per_content_revenue_router.get("/export")
def export_content_revenue(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from_ts, to_ts = _resolve_range(from_date, to_date)
    user_id = session["user_sub"]

    csv_text, _rows = export_content_revenue_csv(
        user_id,
        from_ts=from_ts,
        to_ts=to_ts,
        max_rows=S.per_content_revenue_max_export_rows,
    )
    filename = f"content-revenue-{datetime.utcnow().strftime(_DATE_FMT)}.csv"
    return StreamingResponse(
        iter([csv_text]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@per_content_revenue_router.get("/{content_id}", response_model=ContentRevenueDetailOut)
def get_content_revenue(
    content_id: str,
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
) -> ContentRevenueDetailOut:
    _require_enabled()
    from_ts, to_ts = _resolve_range(from_date, to_date)
    user_id = session["user_sub"]

    detail = get_content_revenue_detail(
        user_id, content_id, from_ts=from_ts, to_ts=to_ts
    )
    if detail is None:
        # Same 404 for not-found and not-owned to prevent enumeration.
        raise HTTPException(status_code=404, detail="Content revenue record not found")
    return ContentRevenueDetailOut(**detail)
