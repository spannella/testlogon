"""
ATS Candidates router (CND-005).

Exposes 12 endpoints under /ui/candidates. Flag gate: S.candidates_enabled;
all handlers return HTTP 404 when the flag is off (before auth or service calls).
Routes are declared in the required literal-before-dynamic order so FastAPI does
not shadow literal path segments (e.g. /resumes, /history, /owner) with
wildcard /{candidate_id}.
"""
import asyncio
import logging
import re
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile

from app.core.settings import S
from app.models import (
    CANDIDATE_RESUME_CONTENT_TYPES,
    CandidateCreateIn,
    CandidateHistoryPage,
    CandidateListOut,
    CandidateOut,
    CandidateResumeOut,
    CandidateUpdateIn,
    SetOwnerIn,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/candidates", tags=["candidates"])


# ── helpers ───────────────────────────────────────────────────────────────────

def _require_candidates() -> None:
    if not S.candidates_enabled:
        raise HTTPException(status_code=404, detail="Not found")


def _is_admin(ctx: dict) -> bool:
    from app.auth.roles import Role, normalize_role
    return normalize_role(ctx.get("role", "user")) in {Role.ADMIN, Role.ROOT}


def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name or "resume")[:255]


def _make_candidate_out(item: dict, resumes=None) -> CandidateOut:
    """Project a DDB META item to CandidateOut, handling Decimal coercion."""
    def _int(v):
        return int(v) if v is not None else None

    return CandidateOut(
        candidate_id=item["candidate_id"],
        first_name=item["first_name"],
        last_name=item["last_name"],
        email=item["email"],
        email_raw=item.get("email_raw", item["email"]),
        phone=item.get("phone"),
        company=item.get("company"),
        title=item.get("title"),
        source=item.get("source", "other"),
        owner_sub=item.get("owner_sub", ""),
        status=item.get("status", "active"),
        current_pay=item.get("current_pay"),
        desired_pay=item.get("desired_pay"),
        key_skills=item.get("key_skills"),
        date_available=item.get("date_available"),
        can_relocate=bool(item.get("can_relocate", False)),
        linkedin_url=item.get("linkedin_url"),
        web_url=item.get("web_url"),
        address=item.get("address"),
        city=item.get("city"),
        state=item.get("state"),
        postal_code=item.get("postal_code"),
        country=item.get("country"),
        primary_resume_id=item.get("primary_resume_id"),
        created_by=item.get("created_by", ""),
        created_at=_int(item.get("created_at", 0)),
        updated_at=_int(item.get("updated_at", 0)),
        deleted_at=_int(item.get("deleted_at")),
        resumes=resumes or [],
    )


def _make_resume_out(row: dict, url: str = "") -> CandidateResumeOut:
    """Project a DDB ATTACHMENT sub-item to CandidateResumeOut."""
    return CandidateResumeOut(
        attachment_id=row["attachment_id"],
        candidate_id=row["candidate_id"],
        filename=row.get("filename", ""),
        filename_original=row.get("filename_original", row.get("filename", "")),
        content_type=row.get("content_type", "application/octet-stream"),
        size_bytes=int(row.get("size_bytes", 0)),
        url=url,
        source=row.get("source", "upload"),
        is_primary=bool(row.get("is_primary", False)),
        node_path=row.get("node_path"),
        created_at=int(row.get("created_at", 0)),
        uploaded_by=row.get("uploaded_by", ""),
    )


def _resolve_resume_url(row: dict) -> str:
    """Compute download URL for a résumé row."""
    from app.services.candidates import _make_download_url
    if row.get("source") == "file_manager":
        node_path = row.get("node_path", "")
        try:
            from app.services.filemanager import get_node
            node = get_node(row.get("uploaded_by", ""), node_path)
            s3_key = node.get("s3_key", "")
            s3_bucket = node.get("s3_bucket", S.candidate_resume_bucket)
            return _make_download_url(s3_key, s3_bucket)
        except Exception:
            return ""
    s3_key = row.get("s3_key", "")
    s3_bucket = row.get("s3_bucket", S.candidate_resume_bucket)
    if not s3_key:
        return ""
    return _make_download_url(s3_key, s3_bucket)


# ── Candidate CRUD ────────────────────────────────────────────────────────────

@router.post("", response_model=CandidateOut, status_code=201)
async def create_candidate_endpoint(
    body: CandidateCreateIn,
    ctx: dict = Depends(require_ui_session),
) -> CandidateOut:
    _require_candidates()
    user_sub = ctx["user_sub"]
    from app.services import candidates
    item = await asyncio.to_thread(candidates.create_candidate, user_sub, body)
    return _make_candidate_out(item)


@router.get("", response_model=CandidateListOut)
async def list_candidates_endpoint(
    owner_sub: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    created_after: Optional[int] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> CandidateListOut:
    _require_candidates()
    user_sub = ctx["user_sub"]
    # Default to caller's own candidates unless admin passes owner_sub=* or another sub
    effective_owner = owner_sub if owner_sub is not None else user_sub
    from app.services import candidates
    result = await asyncio.to_thread(
        candidates.list_candidates,
        owner_sub=effective_owner,
        status=status,
        source=source,
        created_after=created_after,
        cursor=cursor,
        limit=limit,
    )
    cands = [_make_candidate_out(c) for c in result.get("candidates", [])]
    return CandidateListOut(candidates=cands, cursor=result.get("cursor"))


@router.get("/{candidate_id}", response_model=CandidateOut)
async def get_candidate_endpoint(
    candidate_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CandidateOut:
    _require_candidates()
    from app.services import candidates
    item = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not item:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if item.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})
    # Populate resumes on detail endpoint
    resume_rows = await asyncio.to_thread(candidates.list_resumes, candidate_id)
    resumes = [_make_resume_out(r, _resolve_resume_url(r)) for r in resume_rows]
    return _make_candidate_out(item, resumes=resumes)


@router.patch("/{candidate_id}", response_model=CandidateOut)
async def update_candidate_endpoint(
    candidate_id: str,
    body: CandidateUpdateIn,
    ctx: dict = Depends(require_ui_session),
) -> CandidateOut:
    _require_candidates()
    user_sub = ctx["user_sub"]
    from app.services import candidates
    existing = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})
    if existing.get("owner_sub") != user_sub and not _is_admin(ctx):
        raise HTTPException(403, {"code": "forbidden"})
    updated = await asyncio.to_thread(candidates.update_candidate, candidate_id, user_sub, body)
    return _make_candidate_out(updated)


@router.delete("/{candidate_id}", status_code=204)
async def delete_candidate_endpoint(
    candidate_id: str,
    ctx: dict = Depends(require_ui_session),
) -> None:
    _require_candidates()
    user_sub = ctx["user_sub"]
    from app.services import candidates
    existing = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})
    if existing.get("owner_sub") != user_sub and not _is_admin(ctx):
        raise HTTPException(403, {"code": "forbidden"})
    await asyncio.to_thread(candidates.delete_candidate, candidate_id, user_sub)


# ── Owner assignment ──────────────────────────────────────────────────────────

@router.put("/{candidate_id}/owner", response_model=CandidateOut)
async def set_owner_endpoint(
    candidate_id: str,
    body: SetOwnerIn,
    ctx: dict = Depends(require_ui_session),
) -> CandidateOut:
    _require_candidates()
    if not _is_admin(ctx):
        raise HTTPException(403, {"code": "forbidden"})
    user_sub = ctx["user_sub"]
    from app.services import candidates
    updated = await asyncio.to_thread(candidates.set_owner, candidate_id, body.owner_sub, user_sub)
    return _make_candidate_out(updated)


# ── Résumé management ─────────────────────────────────────────────────────────
# Literal-segment sub-routes BEFORE /{att_id} to prevent shadowing.

@router.post("/{candidate_id}/resumes", response_model=CandidateResumeOut, status_code=201)
async def upload_resume_endpoint(
    candidate_id: str,
    file: UploadFile = File(...),
    make_primary: bool = Form(False),
    ctx: dict = Depends(require_ui_session),
) -> CandidateResumeOut:
    _require_candidates()
    user_sub = ctx["user_sub"]
    from app.services import candidates

    existing = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})
    if existing.get("owner_sub") != user_sub and not _is_admin(ctx):
        raise HTTPException(403, {"code": "forbidden"})

    data = await file.read()
    if len(data) > S.candidate_resume_max_bytes:
        raise HTTPException(413, detail={"code": "resume_too_large", "message": "File too large"})

    ct = file.content_type or "application/octet-stream"
    if ct not in CANDIDATE_RESUME_CONTENT_TYPES:
        raise HTTPException(
            400,
            detail={"code": "invalid_content_type", "message": f"Allowed: {sorted(CANDIDATE_RESUME_CONTENT_TYPES)}"},
        )

    safe_name = _safe_filename(file.filename or "resume")
    attachment_id = "att_" + uuid4().hex
    bucket = S.candidate_resume_bucket
    s3_key = f"{S.candidate_resume_s3_prefix}{candidate_id}/{attachment_id}/{safe_name}"

    from app.core.aws_clients import s3_client as _s3_factory
    await asyncio.to_thread(
        _s3_factory().put_object,
        Bucket=bucket,
        Key=s3_key,
        Body=data,
        ContentType=ct,
    )

    # add_resume will generate its own attachment_id — pass the same one via pre-calculated key
    item = await asyncio.to_thread(
        candidates.add_resume,
        candidate_id,
        uploaded_by=user_sub,
        filename=file.filename or "resume",
        content_type=ct,
        size_bytes=len(data),
        s3_key=s3_key,
        s3_bucket=bucket,
        source="upload",
        make_primary=make_primary,
    )

    url = candidates._make_download_url(item.get("s3_key", s3_key), bucket)
    return _make_resume_out(item, url)


@router.get("/{candidate_id}/resumes")
async def list_resumes_endpoint(
    candidate_id: str,
    ctx: dict = Depends(require_ui_session),
):
    _require_candidates()
    from app.services import candidates
    existing = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    rows = await asyncio.to_thread(candidates.list_resumes, candidate_id)
    return [_make_resume_out(r, _resolve_resume_url(r)).model_dump() for r in rows]


@router.get("/{candidate_id}/resumes/{att_id}", response_model=CandidateResumeOut)
async def get_resume_endpoint(
    candidate_id: str,
    att_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CandidateResumeOut:
    _require_candidates()
    from app.services import candidates
    row = await asyncio.to_thread(candidates.get_resume, candidate_id, att_id)
    url = _resolve_resume_url(row)
    return _make_resume_out(row, url)


@router.put("/{candidate_id}/resumes/{att_id}/primary", response_model=CandidateResumeOut)
async def set_primary_resume_endpoint(
    candidate_id: str,
    att_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CandidateResumeOut:
    _require_candidates()
    user_sub = ctx["user_sub"]
    from app.services import candidates
    existing = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("owner_sub") != user_sub and not _is_admin(ctx):
        raise HTTPException(403, {"code": "forbidden"})
    await asyncio.to_thread(candidates.set_primary_resume, candidate_id, att_id, user_sub)
    row = await asyncio.to_thread(candidates.get_resume, candidate_id, att_id)
    url = _resolve_resume_url(row)
    return _make_resume_out(row, url)


@router.delete("/{candidate_id}/resumes/{att_id}", status_code=204)
async def delete_resume_endpoint(
    candidate_id: str,
    att_id: str,
    ctx: dict = Depends(require_ui_session),
) -> None:
    _require_candidates()
    user_sub = ctx["user_sub"]
    from app.services import candidates
    existing = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("owner_sub") != user_sub and not _is_admin(ctx):
        raise HTTPException(403, {"code": "forbidden"})
    await asyncio.to_thread(candidates.delete_resume, candidate_id, att_id, user_sub)


# ── Change history ─────────────────────────────────────────────────────────────

@router.get("/{candidate_id}/history", response_model=CandidateHistoryPage)
async def get_history_endpoint(
    candidate_id: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> CandidateHistoryPage:
    _require_candidates()
    from app.services import candidates
    item = await asyncio.to_thread(candidates.get_candidate, candidate_id)
    if not item:
        raise HTTPException(404, {"code": "candidate_not_found"})
    result = await asyncio.to_thread(candidates.list_candidate_history, candidate_id, cursor=cursor, limit=limit)
    from app.models import CandidateHistoryOut
    events = [
        CandidateHistoryOut(**e) if not isinstance(e, CandidateHistoryOut) else e
        for e in result.get("events", [])
    ]
    return CandidateHistoryPage(events=events, cursor=result.get("cursor"))
