"""PLT-003: Glossary router — GET /v1/glossary (public) + admin CRUD."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.settings import S
from app.models import GlossaryCreateIn, GlossaryListOut, GlossaryPatchIn, GlossaryTermOut
from app.routers.admin_usage import _require_admin_user
from app.services.alerts import audit_event
import app.services.glossary as _svc

router = APIRouter(tags=["glossary"])


@router.get("/v1/glossary", response_model=GlossaryListOut)
def list_terms(
    search: Optional[str] = Query(default=None, max_length=200),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> GlossaryListOut:
    result = _svc.list_glossary(search=search, cursor=cursor, limit=limit)
    return GlossaryListOut(**result)


@router.get("/v1/glossary/{term_id}", response_model=GlossaryTermOut)
def get_term(term_id: str) -> GlossaryTermOut:
    item = _svc.get_glossary_term(term_id)
    if item is None:
        raise HTTPException(status_code=404, detail="term not found")
    return GlossaryTermOut(**item)


@router.post("/v1/admin/glossary", response_model=GlossaryTermOut, status_code=201)
def create_term(
    body: GlossaryCreateIn,
    req: Request,
    admin_user: str = Depends(_require_admin_user),
) -> GlossaryTermOut:
    item = _svc.upsert_glossary_term(
        term=body.term,
        definition=body.definition,
        tags=body.tags or [],
        updated_by=admin_user,
    )
    audit_event("glossary_upsert", admin_user, req, term_id=item["term_id"], action="create")
    return GlossaryTermOut(**item)


@router.patch("/v1/admin/glossary/{term_id}", response_model=GlossaryTermOut)
def patch_term(
    term_id: str,
    body: GlossaryPatchIn,
    req: Request,
    admin_user: str = Depends(_require_admin_user),
) -> GlossaryTermOut:
    existing = _svc.get_glossary_term(term_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="term not found")
    merged_term = body.term if body.term is not None else existing["term"]
    merged_def = body.definition if body.definition is not None else existing["definition"]
    merged_tags = body.tags if body.tags is not None else existing.get("tags", [])
    item = _svc.upsert_glossary_term(
        term=merged_term,
        definition=merged_def,
        tags=merged_tags,
        term_id=term_id,
        updated_by=admin_user,
    )
    audit_event("glossary_upsert", admin_user, req, term_id=term_id, action="patch")
    return GlossaryTermOut(**item)


@router.delete("/v1/admin/glossary/{term_id}", status_code=204, response_model=None)
def delete_term(
    term_id: str,
    req: Request,
    admin_user: str = Depends(_require_admin_user),
):
    deleted = _svc.delete_glossary_term(term_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="term not found")
    audit_event("glossary_delete", admin_user, req, term_id=term_id)
