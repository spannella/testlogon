"""Email archiving — relate email to CRM record (EML-007).

Prefix: /ui/email/archive
Tag: email-archiving

All endpoints return HTTP 503 when S.email_archiving_enabled is False.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query

from app.auth.deps import get_authenticated_user, AuthenticatedUser
from app.auth.roles import Role
from app.core.settings import S
from app.models import ArchiveEmailIn, ArchivedEmailOut

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/email/archive", tags=["email-archiving"])


# ---------------------------------------------------------------------------
# Feature status (public, no auth)
# ---------------------------------------------------------------------------


@router.get("/status")
async def archive_status():
    return {"enabled": S.email_archiving_enabled}


# ---------------------------------------------------------------------------
# Archive CRUD
# ---------------------------------------------------------------------------


@router.post("/", response_model=ArchivedEmailOut, status_code=201)
async def archive_email_to_entity(
    payload: ArchiveEmailIn = Body(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    from app.services.email_archive import archive_email
    is_admin = user.role in {Role.ADMIN, Role.ROOT}
    result = archive_email(
        user.sub,
        payload.account_id,
        payload.uid,
        payload.entity_type,
        payload.entity_id,
        is_admin=is_admin,
    )
    return result


@router.get("/entity/{entity_type}/{entity_id}")
async def list_entity_archived_emails(
    entity_type: str = Path(...),
    entity_id: str = Path(...),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    from app.services.email_archive import _require_enabled, _require_entity_type_supported, list_archived_emails
    _require_enabled()
    _require_entity_type_supported(entity_type)

    is_admin = user.role in {Role.ADMIN, Role.ROOT}

    # Entity access check
    if entity_type == "ticket" and not is_admin:
        try:
            from app.services.tickets import STORE as ticket_store
            ticket = ticket_store.get_ticket(entity_id)
            if not ticket or ticket.get("owner_sub") != user.sub:
                raise HTTPException(status_code=403, detail={"code": "access_forbidden"})
        except HTTPException:
            raise
        except ImportError:
            pass
        except Exception:
            raise HTTPException(status_code=404, detail={"code": "ticket_not_found"})
    elif entity_type == "contact":
        from app.core.tables import T
        try:
            resp = T.contacts.get_item(Key={"owner_id": user.sub, "contact_id": entity_id})
            if not resp.get("Item"):
                raise HTTPException(status_code=404, detail={"code": "contact_not_found"})
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=404, detail={"code": "contact_not_found"})

    items, next_cursor = list_archived_emails(entity_type, entity_id, limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.delete("/entity/{entity_type}/{entity_id}/{message_id_hash}")
async def unarchive_email_from_entity(
    entity_type: str = Path(...),
    entity_id: str = Path(...),
    message_id_hash: str = Path(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    from app.services.email_archive import unarchive_email
    is_admin = user.role in {Role.ADMIN, Role.ROOT}
    unarchive_email(user.sub, entity_type, entity_id, message_id_hash, is_admin=is_admin)
    return {"ok": True}
