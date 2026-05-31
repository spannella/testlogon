"""Documentation Agent router (AGENT-014).

User-scoped endpoints for documentation coverage tracking, freshness/staleness
monitoring, PR impact assessment, template management, agent config, and inline
documentation ticket creation. All operations are scoped to the authenticated
user's ``user_sub`` (security §9 — cross-tenant access is blocked).
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    AssessPrIn,
    CreateDocTemplateIn,
    CreateInlineDocTicketIn,
    DocAgentConfigOut,
    DocCoverageDetailsOut,
    DocCoverageOut,
    DocCoverageSummaryOut,
    DocTemplateOut,
    DocTemplatesListOut,
    FreshnessCheckOut,
    PrImpactOut,
    RegisterDocIn,
    StaleDocsListOut,
    UpdateDocConfigIn,
    UpdateDocIn,
    UpdateDocTemplateIn,
)
from app.services import agent_docs as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agents/docs", tags=["agent-docs"])


def _uid(session: Dict[str, Any]) -> str:
    return session["user_sub"]


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


@router.get("/coverage", response_model=DocCoverageSummaryOut)
async def get_coverage(session: Dict[str, Any] = Depends(require_ui_session)):
    return DocCoverageSummaryOut(**svc.get_coverage_summary(user_id=_uid(session)))


@router.get("/coverage/details", response_model=DocCoverageDetailsOut)
async def coverage_details(
    doc_type: str | None = Query(default=None),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    if doc_type is not None and doc_type not in svc.DOC_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_DOC_TYPE", "message": f"Invalid doc_type: {doc_type}"},
        )
    docs = svc.list_docs(user_id=_uid(session), doc_type=doc_type)
    return DocCoverageDetailsOut(docs=[DocCoverageOut(**d) for d in docs], count=len(docs))


@router.post("/register", response_model=DocCoverageOut, status_code=201)
async def register_doc(body: RegisterDocIn, session: Dict[str, Any] = Depends(require_ui_session)):
    if not svc.validate_path(body.doc_path):
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_PATH", "message": "Path must be relative, no ../."},
        )
    bad = svc.validate_paths(body.source_refs)
    if bad:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_PATH", "message": f"Invalid source paths: {bad}"},
        )
    try:
        rec = svc.register_doc(
            user_id=_uid(session),
            doc_path=body.doc_path,
            doc_type=body.doc_type,
            source_refs=body.source_refs,
            coverage_score=body.coverage_score,
        )
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={"code": "DOC_ALREADY_EXISTS", "message": f"Documentation already registered: {body.doc_path}"},
        )
    return DocCoverageOut(**rec)


@router.put("/coverage/{doc_path:path}", response_model=DocCoverageOut)
async def update_doc(
    doc_path: str,
    body: UpdateDocIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    if body.source_refs is not None:
        bad = svc.validate_paths(body.source_refs)
        if bad:
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_PATH", "message": f"Invalid source paths: {bad}"},
            )
    try:
        rec = svc.update_doc_record(
            user_id=_uid(session),
            doc_path=doc_path,
            source_refs=body.source_refs,
            coverage_score=body.coverage_score,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "DOC_NOT_FOUND", "message": f"Documentation record not found: {doc_path}"},
        )
    return DocCoverageOut(**rec)


# ---------------------------------------------------------------------------
# Freshness + staleness
# ---------------------------------------------------------------------------


@router.post("/freshness-check", response_model=FreshnessCheckOut)
async def freshness_check(session: Dict[str, Any] = Depends(require_ui_session)):
    return FreshnessCheckOut(**svc.check_freshness(user_id=_uid(session)))


@router.get("/stale", response_model=StaleDocsListOut)
async def list_stale(
    limit: int = Query(default=50, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    docs = svc.list_stale_docs(user_id=_uid(session), limit=limit)
    return StaleDocsListOut(docs=[DocCoverageOut(**d) for d in docs], count=len(docs))


# ---------------------------------------------------------------------------
# PR impact
# ---------------------------------------------------------------------------


@router.post("/assess-pr", response_model=PrImpactOut)
async def assess_pr(body: AssessPrIn, session: Dict[str, Any] = Depends(require_ui_session)):
    bad = svc.validate_paths(body.changed_files)
    if bad:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_PATH", "message": f"Invalid changed file paths: {bad}"},
        )
    result = svc.assess_pr_impact(user_id=_uid(session), changed_files=body.changed_files)
    return PrImpactOut(
        docs_to_update=[DocCoverageOut(**d) for d in result["docs_to_update"]],
        uncovered_files=result["uncovered_files"],
        impact_level=result["impact_level"],
    )


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


@router.get("/templates", response_model=DocTemplatesListOut)
async def list_templates(
    doc_type: str | None = Query(default=None),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    tmpls = svc.list_doc_templates(user_id=_uid(session), doc_type=doc_type)
    return DocTemplatesListOut(templates=[DocTemplateOut(**t) for t in tmpls], count=len(tmpls))


@router.post("/templates", response_model=DocTemplateOut, status_code=201)
async def create_template(
    body: CreateDocTemplateIn, session: Dict[str, Any] = Depends(require_ui_session)
):
    tmpl = svc.create_doc_template(
        user_id=_uid(session),
        name=body.name,
        doc_type=body.doc_type,
        template_body=body.template_body,
        required_sections=body.required_sections,
    )
    return DocTemplateOut(**tmpl)


@router.put("/templates/{template_id}", response_model=DocTemplateOut)
async def update_template(
    template_id: str,
    body: UpdateDocTemplateIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    try:
        tmpl = svc.update_doc_template(
            user_id=_uid(session),
            template_id=template_id,
            name=body.name,
            doc_type=body.doc_type,
            template_body=body.template_body,
            required_sections=body.required_sections,
        )
    except LookupError:
        raise HTTPException(
            status_code=404, detail={"code": "TEMPLATE_NOT_FOUND", "message": "Template not found"}
        )
    return DocTemplateOut(**tmpl)


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str, session: Dict[str, Any] = Depends(require_ui_session)):
    if not svc.delete_doc_template(user_id=_uid(session), template_id=template_id):
        raise HTTPException(
            status_code=404, detail={"code": "TEMPLATE_NOT_FOUND", "message": "Template not found"}
        )
    return {"ok": True, "template_id": template_id}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@router.get("/config", response_model=DocAgentConfigOut)
async def get_config(
    type_id: str = Query(default="documentation"),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return DocAgentConfigOut(**svc.get_doc_config(agent_type_id=type_id))


@router.put("/config", response_model=DocAgentConfigOut)
async def update_config(
    body: UpdateDocConfigIn,
    type_id: str = Query(default="documentation"),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    cfg = svc.update_doc_config(
        agent_type_id=type_id,
        owner_sub=_uid(session),
        config=body.model_dump(exclude_none=True),
    )
    return DocAgentConfigOut(**cfg)


# ---------------------------------------------------------------------------
# Inline doc ticket creation (AGENT-004 bridge)
# ---------------------------------------------------------------------------


@router.post("/inline-ticket", status_code=201)
async def create_inline_ticket(
    body: CreateInlineDocTicketIn, session: Dict[str, Any] = Depends(require_ui_session)
):
    if not svc.validate_path(body.source_file):
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_PATH", "message": "Path must be relative, no ../."},
        )
    from app.core.settings import S

    if not S.doc_inline_tickets_enabled:
        raise HTTPException(
            status_code=403,
            detail={"code": "DOC_INLINE_TICKETS_DISABLED", "message": "Inline doc ticket creation is disabled"},
        )
    ticket = svc.create_inline_doc_ticket(
        user_id=_uid(session), source_file=body.source_file, description=body.description
    )
    return ticket
