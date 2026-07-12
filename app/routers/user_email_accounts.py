"""Per-user email account management + IMAP inbox sync (EML-003 + EML-004).

Prefix: /ui/email/accounts
Tag: email-client

All endpoints return HTTP 503 when S.email_client_enabled is False.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query

from app.auth.deps import get_authenticated_user, AuthenticatedUser
from app.core.settings import S
from app.models import (
    EmailAccountCreateIn,
    EmailAccountOut,
    EmailAccountUpdateIn,
    EmailMessageListOut,
    EmailMessageOut,
    EmailThreadOut,
    SyncInboxIn,
    SyncInboxOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/email/accounts", tags=["email-client"])


def _require_email_client() -> None:
    if not S.email_client_enabled:
        raise HTTPException(status_code=503, detail="email client is not enabled")


# ---------------------------------------------------------------------------
# EML-003: Account CRUD
# ---------------------------------------------------------------------------


@router.post("/", response_model=EmailAccountOut, status_code=201)
async def create_email_account(
    payload: EmailAccountCreateIn = Body(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.user_email_accounts import AccountNotFound, LimitExceeded, create_account
    result = create_account(user.sub, payload.model_dump())
    return result


@router.get("/")
async def list_email_accounts(
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.user_email_accounts import list_accounts
    items, next_cursor = list_accounts(user.sub, cursor=cursor, limit=limit)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/{account_id}", response_model=EmailAccountOut)
async def get_email_account(
    account_id: str = Path(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.user_email_accounts import get_account, _strip_password
    item = get_account(user.sub, account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    return _strip_password(item)


@router.patch("/{account_id}", response_model=EmailAccountOut)
async def update_email_account(
    account_id: str = Path(...),
    payload: EmailAccountUpdateIn = Body(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.user_email_accounts import AccountNotFound, update_account
    try:
        result = update_account(user.sub, account_id, payload.model_dump(exclude_none=True))
    except AccountNotFound:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


@router.delete("/{account_id}")
async def delete_email_account(
    account_id: str = Path(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.user_email_accounts import AccountNotFound, delete_account
    try:
        delete_account(user.sub, account_id)
    except AccountNotFound:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"ok": True}


@router.post("/{account_id}/verify")
async def verify_email_account(
    account_id: str = Path(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.user_email_accounts import verify_connection
    return verify_connection(user.sub, account_id)


# ---------------------------------------------------------------------------
# EML-004: IMAP inbox sync + message endpoints
# ---------------------------------------------------------------------------


@router.post("/{account_id}/sync", response_model=SyncInboxOut)
async def sync_inbox(
    account_id: str = Path(...),
    payload: SyncInboxIn = Body(default=SyncInboxIn()),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services import email_sync
    result = await asyncio.to_thread(
        email_sync.sync_inbox,
        user.sub,
        account_id,
        folder=payload.folder,
        max_fetch=payload.max_fetch,
    )
    return result


@router.get("/{account_id}/messages")
async def list_inbox_messages(
    account_id: str = Path(...),
    folder: str = Query(default="INBOX"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.email_sync import list_messages
    items, next_cursor = list_messages(user.sub, account_id, folder, limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/{account_id}/messages/{uid}")
async def get_inbox_message(
    account_id: str = Path(...),
    uid: int = Path(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.email_sync import get_message
    msg = get_message(user.sub, account_id, uid)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    return msg


@router.get("/{account_id}/threads/{thread_id}")
async def get_email_thread(
    account_id: str = Path(...),
    thread_id: str = Path(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_email_client()
    from app.services.email_sync import list_thread
    messages = list_thread(user.sub, account_id, thread_id)
    return {"thread_id": thread_id, "messages": messages}
