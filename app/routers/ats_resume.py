"""RSK-002 — Résumé text-extraction router.

Provides the re-extract endpoint for triggering/retrying résumé text extraction.
Declared before any /{candidate_id} dynamic segment routes (FastAPI ordering).

All endpoints require require_ui_session. Gated by S.candidates_enabled.
"""
from __future__ import annotations

import asyncio
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import ResumeExtractionOut
from app.services.sessions import require_ui_session

router = APIRouter(tags=["ats-resume"])


def _check_flag() -> None:
    if not S.candidates_enabled:
        raise HTTPException(status_code=404)


@router.post(
    "/ui/ats/candidates/{candidate_id}/resume/{attachment_id}/extract",
    response_model=ResumeExtractionOut,
)
async def re_extract_resume(
    candidate_id: str,
    attachment_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    """Trigger (re-)extraction of text from a résumé attachment.

    Uses asyncio.to_thread to dispatch sync extraction work.
    """
    _check_flag()

    # Fetch the attachment sub-item
    try:
        resp = T.candidates.get_item(  # type: ignore[attr-defined]
            Key={
                "pk": f"CANDIDATE#{candidate_id}",
                "sk": f"ATTACHMENT#{attachment_id}",
            }
        )
    except Exception:
        raise HTTPException(status_code=404, detail="Attachment not found")

    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Attachment not found")

    # Ownership check
    user_sub = ctx["user_sub"]
    is_admin = normalize_role(ctx["role"]) in {Role.ADMIN, Role.ROOT}
    if not is_admin and item.get("uploaded_by") != user_sub:
        raise HTTPException(status_code=403, detail="Access denied")

    s3_key = item.get("s3_key")
    s3_bucket = item.get("s3_bucket")

    from app.services.resume_extraction import extract_resume_text

    result = await asyncio.to_thread(
        extract_resume_text,
        candidate_id,
        attachment_id,
        s3_key=s3_key,
        s3_bucket=s3_bucket,
        actor_sub=user_sub,
    )

    return ResumeExtractionOut(
        candidate_id=candidate_id,
        attachment_id=attachment_id,
        extraction_status=result.get("extraction_status", "error"),
        char_count=result.get("char_count", 0),
        extracted_at=now_ts(),
    )
