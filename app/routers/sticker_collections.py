"""GIF search + sticker collection REST endpoints (MSG-008)."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile

from app.auth.policy import require_admin_scope
from app.auth.roles import AdminScope
from app.core.settings import S
from app.models import (
    CreateStickerCollectionOut,
    GifSearchResult,
    StickerCollectionListOut,
    StickerCollectionOut,
    StickerFavoriteOut,
    StickerListOut,
    StickerOut,
    StickerSearchResponse,
    StickerSearchResult,
)
from app.services import gif_provider, sticker_collections as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/stickers", tags=["stickers"])
admin_router = APIRouter(prefix="/v1/admin/stickers", tags=["admin-stickers"])


# ---------------------------------------------------------------------------
# GIF search (mock provider in dev)
# ---------------------------------------------------------------------------

@router.get("/gifs/search", response_model=List[GifSearchResult])
def search_gifs_endpoint(
    q: str = Query(default=""),
    limit: int = Query(default=20, ge=1, le=50),
    ctx=Depends(require_ui_session),
):
    """Search GIFs via the configured (mock) provider."""
    if not S.gif_messages_enabled:
        raise HTTPException(403, "GIF messages are not enabled")
    return [GifSearchResult(**g) for g in gif_provider.search_gifs(q, limit=limit)]


@router.get("/gifs/trending", response_model=List[GifSearchResult])
def trending_gifs_endpoint(
    limit: int = Query(default=20, ge=1, le=50),
    ctx=Depends(require_ui_session),
):
    """Return trending GIFs."""
    if not S.gif_messages_enabled:
        raise HTTPException(403, "GIF messages are not enabled")
    return [GifSearchResult(**g) for g in gif_provider.trending_gifs(limit=limit)]


# ---------------------------------------------------------------------------
# Sticker collections
# ---------------------------------------------------------------------------

@router.get("/collections", response_model=StickerCollectionListOut)
def list_sticker_collections(ctx=Depends(require_ui_session)):
    """List all active sticker collections."""
    cols = [StickerCollectionOut(**c) for c in svc.list_collections(active_only=True)]
    return StickerCollectionListOut(collections=cols)


@router.get("/collections/{collection_id}/stickers", response_model=StickerListOut)
def get_stickers(collection_id: str, ctx=Depends(require_ui_session)):
    """List stickers in a collection."""
    meta = svc.get_collection_meta(collection_id, active_only=True)
    if not meta:
        raise HTTPException(404, "collection_not_found")
    stickers = [StickerOut(**s) for s in svc.get_collection_stickers(collection_id)]
    return StickerListOut(stickers=stickers)


@router.get("/favorites", response_model=StickerCollectionListOut)
def list_my_favorites(ctx=Depends(require_ui_session)):
    """List the user's favorited sticker collections (with their stickers)."""
    cols = [
        StickerCollectionOut(**c)
        for c in svc.list_favorites_with_stickers(ctx["user_sub"])
    ]
    return StickerCollectionListOut(collections=cols)


@router.post("/favorites/{collection_id}", response_model=StickerFavoriteOut)
def add_to_favorites(collection_id: str, ctx=Depends(require_ui_session)):
    """Add a sticker collection to favorites (idempotent)."""
    meta = svc.get_collection_meta(collection_id, active_only=True)
    if not meta:
        raise HTTPException(404, "collection_not_found")
    svc.add_favorite(ctx["user_sub"], collection_id)
    return StickerFavoriteOut(ok=True, collection_id=collection_id)


@router.delete("/favorites/{collection_id}", response_model=StickerFavoriteOut)
def remove_from_favorites(collection_id: str, ctx=Depends(require_ui_session)):
    """Remove a sticker collection from favorites (idempotent)."""
    svc.remove_favorite(ctx["user_sub"], collection_id)
    return StickerFavoriteOut(ok=True, collection_id=collection_id)


@router.get("/search", response_model=StickerSearchResponse)
def search_stickers_endpoint(q: str = Query(...), ctx=Depends(require_ui_session)):
    """Search stickers by alt_text across the user's favorited collections."""
    results = [
        StickerSearchResult(**r)
        for r in svc.search_stickers(ctx["user_sub"], q)
    ]
    return StickerSearchResponse(results=results)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@admin_router.post("/collections", response_model=CreateStickerCollectionOut, status_code=201)
async def create_sticker_collection(
    name: str = Form(...),
    description: str = Form(default=""),
    alt_texts: str = Form(default=""),
    files: List[UploadFile] = File(...),
    ctx=Depends(require_admin_scope(AdminScope.CONTENT_MODERATION)),
):
    """Create a sticker collection with uploaded images (admin only)."""
    alt_list = [a.strip() for a in alt_texts.split(",")] if alt_texts else []
    payloads = []
    for idx, f in enumerate(files):
        data = await f.read()
        alt = alt_list[idx] if idx < len(alt_list) else ""
        payloads.append((data, f.content_type or "", alt))
    try:
        result = svc.create_collection(
            name=name,
            description=description,
            created_by=ctx.sub,
            files=payloads,
        )
    except ValueError as exc:
        code = str(exc)
        status = 400
        raise HTTPException(status, code)
    return CreateStickerCollectionOut(
        collection_id=result["collection_id"],
        name=result["name"],
        description=result["description"],
        sticker_count=result["sticker_count"],
        thumbnail_url=result.get("thumbnail_url"),
        is_active=result["is_active"],
        created_at=result["created_at"],
        stickers=[StickerOut(**s) for s in result["stickers"]],
    )


@admin_router.delete("/collections/{collection_id}")
def delete_sticker_collection(
    collection_id: str,
    ctx=Depends(require_admin_scope(AdminScope.CONTENT_MODERATION)),
):
    """Soft-delete a sticker collection (admin only)."""
    ok = svc.delete_collection(collection_id)
    if not ok:
        raise HTTPException(404, "collection_not_found")
    return {"ok": True, "collection_id": collection_id}
