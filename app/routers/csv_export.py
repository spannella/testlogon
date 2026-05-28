"""CSV export endpoint (PLATFORM-009).

Provides streaming CSV download for various data sources.
"""

from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.services.csv_export import generate_csv_rows
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["export"])

VALID_SOURCES = {"billing_ledger", "contacts", "questionnaire_responses"}


@router.get("/export/csv")
async def export_csv(
    source: str = Query(
        ...,
        description="Data source to export",
        pattern=r"^(billing_ledger|contacts|questionnaire_responses)$",
    ),
    from_date: Optional[int] = Query(
        None,
        description="Unix timestamp start (inclusive)",
        ge=0,
    ),
    to_date: Optional[int] = Query(
        None,
        description="Unix timestamp end (inclusive)",
        ge=0,
    ),
    questionnaire_id: Optional[str] = Query(
        None,
        description="Required for questionnaire_responses source",
        min_length=1,
        max_length=120,
    ),
    ctx=Depends(require_ui_session),
):
    """Stream CSV data for the requested source.

    Returns a streaming response with Content-Type: text/csv and
    Content-Disposition: attachment to trigger browser download.

    The CSV uses UTF-8 encoding with BOM for Excel compatibility.
    Fields containing commas, quotes, or newlines are properly escaped
    per RFC 4180.
    """
    user_sub = ctx["user_sub"]

    # Validate questionnaire ownership if needed
    if source == "questionnaire_responses":
        if not questionnaire_id:
            raise HTTPException(
                status_code=422,
                detail="questionnaire_id is required for questionnaire_responses source",
            )
        # Verify ownership
        from app.services.questionnaires_repository import DynamoQuestionnaireRepository
        repo = DynamoQuestionnaireRepository()
        q = repo.get_questionnaire(questionnaire_id)
        if not q:
            raise HTTPException(status_code=404, detail="Questionnaire not found")
        if q.get("owner_id") != user_sub:
            raise HTTPException(status_code=403, detail="Not owner of questionnaire")

    # Validate date range
    if from_date is not None and to_date is not None and from_date > to_date:
        raise HTTPException(
            status_code=422,
            detail="from_date must be <= to_date",
        )

    try:
        rows = generate_csv_rows(
            source,
            user_sub,
            from_date=from_date,
            to_date=to_date,
            questionnaire_id=questionnaire_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    filename = f"{source}_{int(time.time())}.csv"
    return StreamingResponse(
        rows,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
