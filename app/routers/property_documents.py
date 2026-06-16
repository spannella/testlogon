"""PMD-002 — Property document link router (local link store).

EVT-011 (file-manager CRM record-link) is not yet built; documents are
linked via this self-contained store.

Endpoints:
  POST   /ui/property-documents/link     → link a document to a record
  DELETE /ui/property-documents/link     → remove a document link
  GET    /ui/property-documents/{record_type}/{record_id}  → list linked docs

Both flags must be ON (PROPERTY_DASHBOARD_ENABLED + local feature gate)
— since this is the PMD cluster, PROPERTY_DASHBOARD_ENABLED alone is the
gate (no separate EVT-011 flag needed).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import app.services.property_documents as pd_svc
from app.models import (
    PropertyDocumentLinkIn,
    PropertyDocumentUnlinkIn,
    PropertyDocumentLinkOut,
    PropertyDocumentListOut,
)
from app.services.sessions import require_ui_session

property_documents_router = APIRouter(
    prefix="/ui/property-documents",
    tags=["property-documents"],
)


@property_documents_router.post("/link", response_model=PropertyDocumentLinkOut)
async def link_document(
    body: PropertyDocumentLinkIn,
    session=Depends(require_ui_session),
):
    """Link a document to a property-domain record."""
    return pd_svc.link_document(
        session["user_sub"],
        record_type=body.record_type,
        record_id=body.record_id,
        doc_id=body.doc_id,
        file_path=body.file_path,
        crm_category=body.crm_category,
        crm_description=body.crm_description,
    )


@property_documents_router.delete("/link", status_code=204)
async def unlink_document(
    body: PropertyDocumentUnlinkIn,
    session=Depends(require_ui_session),
):
    """Remove a document link from a property-domain record."""
    found = pd_svc.unlink_document(
        session["user_sub"],
        record_type=body.record_type,
        record_id=body.record_id,
        doc_id=body.doc_id,
    )
    if not found:
        raise HTTPException(status_code=404, detail="document link not found")


@property_documents_router.get(
    "/{record_type}/{record_id}",
    response_model=PropertyDocumentListOut,
)
async def list_documents(
    record_type: str,
    record_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    session=Depends(require_ui_session),
):
    """List documents linked to a specific property-domain record.

    Scoped to the authenticated user's own links (cross-user isolation).
    """
    return pd_svc.list_documents(
        session["user_sub"],
        record_type=record_type,
        record_id=record_id,
        limit=limit,
        cursor=cursor,
    )
