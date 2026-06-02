"""Custom emoji REST endpoints (MSG-007).

User endpoints (``/ui/emojis/custom``) use cookie+CSRF session auth.
Admin endpoints (``/v1/admin/emojis``) require ADMIN or ROOT.

Custom emojis appear as ``:shortcode:`` tokens in message/comment text and are
resolved client-side to ``<img>`` elements; no new message kind is required.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import CustomEmojiListOut, CustomEmojiOut, ResolveShortcodesOut
from app.services import custom_emojis as svc
from app.services.custom_emojis import CustomEmojiError
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/emojis/custom", tags=["custom-emojis"])
admin_router = APIRouter(prefix="/v1/admin/emojis", tags=["admin-emojis"])


def _require_enabled() -> None:
    if not S.custom_emojis_enabled:
        raise HTTPException(403, "Custom emojis are not enabled")


def _raise_emoji_error(exc: CustomEmojiError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.message)


# ---------------------------------------------------------------------------
# User (personal) endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=CustomEmojiOut, status_code=201)
async def upload_custom_emoji(
    shortcode: str = Form(...),
    name: str = Form(...),
    alt_text: str = Form(default=""),
    category: str = Form(default="Uncategorized"),
    file: UploadFile = File(...),
    ctx=Depends(require_ui_session),
):
    """Upload a personal custom emoji visible only to the caller."""
    _require_enabled()
    user_sub = ctx["user_sub"]
    data = await file.read()
    try:
        result = svc.create_custom_emoji(
            owner_scope=svc.user_scope(user_sub),
            shortcode=shortcode,
            name=name,
            alt_text=alt_text,
            category=category,
            created_by=user_sub,
            data=data,
            declared_content_type=file.content_type or "",
        )
    except CustomEmojiError as exc:
        _raise_emoji_error(exc)
    return CustomEmojiOut(**result)


@router.get("", response_model=CustomEmojiListOut)
def list_my_custom_emojis(ctx=Depends(require_ui_session)):
    """List custom emojis visible to the caller (personal + global)."""
    _require_enabled()
    data = svc.list_visible_emojis(ctx["user_sub"])
    return CustomEmojiListOut(
        emojis=[CustomEmojiOut(**e) for e in data["emojis"]],
        personal_count=data["personal_count"],
        global_count=data["global_count"],
    )


@router.get("/resolve", response_model=ResolveShortcodesOut)
def resolve_shortcodes(
    codes: str = Query(..., description="Comma-separated shortcodes"),
    ctx=Depends(require_ui_session),
):
    """Resolve custom shortcodes to image URLs (personal then global scope)."""
    _require_enabled()
    code_list = [c for c in (codes or "").split(",") if c.strip()]
    resolved = svc.resolve_custom_shortcodes(ctx["user_sub"], code_list)
    return ResolveShortcodesOut(resolved=resolved)


@router.delete("/{emoji_id}")
def delete_my_custom_emoji(emoji_id: str, ctx=Depends(require_ui_session)):
    """Delete one of the caller's personal custom emojis."""
    _require_enabled()
    scope = svc.user_scope(ctx["user_sub"])
    ok = svc.delete_custom_emoji(scope, emoji_id)
    if not ok:
        raise HTTPException(404, "Custom emoji not found")
    return {"ok": True, "emoji_id": emoji_id}


# ---------------------------------------------------------------------------
# Admin (global) endpoints
# ---------------------------------------------------------------------------

@admin_router.post("", response_model=CustomEmojiOut, status_code=201)
async def upload_global_emoji(
    shortcode: str = Form(...),
    name: str = Form(...),
    alt_text: str = Form(default=""),
    category: str = Form(default="Uncategorized"),
    file: UploadFile = File(...),
    ctx=Depends(require_admin_or_root),
):
    """Upload a global custom emoji available to all users (admin only)."""
    _require_enabled()
    data = await file.read()
    try:
        result = svc.create_custom_emoji(
            owner_scope=svc.GLOBAL_SCOPE,
            shortcode=shortcode,
            name=name,
            alt_text=alt_text,
            category=category,
            created_by=ctx.sub,
            data=data,
            declared_content_type=file.content_type or "",
        )
    except CustomEmojiError as exc:
        _raise_emoji_error(exc)
    return CustomEmojiOut(**result)


@admin_router.get("", response_model=CustomEmojiListOut)
def list_global_emojis(ctx=Depends(require_admin_or_root)):
    """List all global custom emojis (admin only)."""
    _require_enabled()
    emojis = svc.list_global_emojis()
    return CustomEmojiListOut(
        emojis=[CustomEmojiOut(**e) for e in emojis],
        personal_count=0,
        global_count=len(emojis),
    )


@admin_router.delete("/{emoji_id}")
def delete_global_emoji(emoji_id: str, ctx=Depends(require_admin_or_root)):
    """Delete a global custom emoji (admin only)."""
    _require_enabled()
    ok = svc.delete_custom_emoji(svc.GLOBAL_SCOPE, emoji_id)
    if not ok:
        raise HTTPException(404, "Custom emoji not found")
    return {"ok": True, "emoji_id": emoji_id}
