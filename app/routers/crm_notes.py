"""
ACT-010 — CRM Notes router.

Mounted at /ui/crm/notes. Gated by S.crm_activities_enabled AND S.crm_notes_enabled.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from app.core.settings import S
from app.models import CrmNoteCreateIn, CrmNoteUpdateIn, CrmNoteOut, CrmNoteListOut
from app.services.crm_notes import (
    create_note,
    list_notes,
    list_notes_by_entity,
    get_note,
    update_note,
    delete_note,
)
from app.services.sessions import require_ui_session
from app.services.alerts import audit_event

router = APIRouter(prefix="/ui/crm/notes", tags=["crm-notes"])


def _gate():
    if not (S.crm_activities_enabled and S.crm_notes_enabled):
        raise HTTPException(status_code=404, detail="Not found")


@router.post("", response_model=CrmNoteOut, status_code=201)
async def create_crm_note(
    body: CrmNoteCreateIn,
    ctx=Depends(require_ui_session),
) -> CrmNoteOut:
    _gate()
    result = create_note(
        user_sub=ctx["user_sub"],
        body=body.body,
        linked_entity_type=body.linked_entity_type,
        linked_entity_id=body.linked_entity_id,
    )
    return CrmNoteOut(**result)


@router.post("/{note_id}/attachment", response_model=CrmNoteOut)
async def upload_note_attachment(
    note_id: str,
    file: UploadFile = File(...),
    ctx=Depends(require_ui_session),
) -> CrmNoteOut:
    _gate()
    # Verify note exists and belongs to user
    existing = get_note(ctx["user_sub"], note_id)
    if not existing:
        raise HTTPException(404, "Note not found")
    content = await file.read()
    result = create_note(
        user_sub=ctx["user_sub"],
        body=existing.get("body", ""),
        linked_entity_type=existing.get("linked_entity_type"),
        linked_entity_id=existing.get("linked_entity_id"),
        attachment_bytes=content,
        attachment_filename=file.filename or "attachment",
        attachment_content_type=file.content_type,
    )
    audit_event("crm_note_attachment_upload", ctx["user_sub"], None, note_id=note_id)
    return CrmNoteOut(**result)


@router.get("", response_model=CrmNoteListOut)
async def list_crm_notes(
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
) -> CrmNoteListOut:
    _gate()
    result = list_notes(ctx["user_sub"], limit=limit, cursor=cursor)
    return CrmNoteListOut(
        notes=[CrmNoteOut(**n) for n in result["notes"]],
        next_cursor=result.get("next_cursor"),
    )


@router.get("/by-entity", response_model=CrmNoteListOut)
async def list_crm_notes_by_entity(
    entity_type: str = Query(...),
    entity_id: str = Query(...),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
) -> CrmNoteListOut:
    _gate()
    result = list_notes_by_entity(entity_type, entity_id, limit=limit, cursor=cursor)
    return CrmNoteListOut(
        notes=[CrmNoteOut(**n) for n in result["notes"]],
        next_cursor=result.get("next_cursor"),
    )


@router.get("/{note_id}", response_model=CrmNoteOut)
async def get_crm_note(
    note_id: str,
    ctx=Depends(require_ui_session),
) -> CrmNoteOut:
    _gate()
    item = get_note(ctx["user_sub"], note_id)
    if not item:
        raise HTTPException(404, "Note not found")
    return CrmNoteOut(**item)


@router.patch("/{note_id}", response_model=CrmNoteOut)
async def update_crm_note(
    note_id: str,
    body: CrmNoteUpdateIn,
    ctx=Depends(require_ui_session),
) -> CrmNoteOut:
    _gate()
    result = update_note(ctx["user_sub"], note_id, body.body)
    if not result:
        raise HTTPException(404, "Note not found")
    audit_event("crm_note_update", ctx["user_sub"], None, note_id=note_id)
    return CrmNoteOut(**result)


@router.delete("/{note_id}")
async def delete_crm_note(
    note_id: str,
    ctx=Depends(require_ui_session),
):
    _gate()
    deleted = delete_note(ctx["user_sub"], note_id)
    if not deleted:
        raise HTTPException(404, "Note not found")
    audit_event("crm_note_delete", ctx["user_sub"], None, note_id=note_id)
    return {"ok": True}
