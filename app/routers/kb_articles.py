"""Knowledge Base router (KB-001..KB-011).

Route ordering rule: static paths must come before /{article_id} to prevent
path capture. Order within this file:
  1. /kb/search
  2. /kb/categories (and /kb/categories/{id})
  3. /kb/tags (and /kb/tags/{tag}/articles)
  4. /kb/articles (list)
  5. /kb/articles/{article_id}/publish|expire|unpublish|rate|attachments|...
  6. /kb/articles/{article_id}  (CRUD)

Public (unauthenticated) endpoints live under /public/kb/*.
Admin-only write endpoints require require_ui_session + admin role.

Flag gate: _require_kb_enabled() raises HTTP 404 when S.knowledge_base_enabled is False.
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    KbArticleCreateIn,
    KbArticleListOut,
    KbArticleOut,
    KbArticleSummaryOut,
    KbArticleUpdateIn,
    KbAttachmentOut,
    KbCategoryIn,
    KbCategoryListOut,
    KbCategoryOut,
    KbExpireReq,
    KbRateOut,
    KbRateReq,
    KbSearchOut,
    KbTagListOut,
    KbTagStats,
)
from app.services.kb_articles import KbArticleService, KbArticleStateError
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/kb",
    tags=["knowledge-base"],
    dependencies=[Depends(maybe_enforce_api_key_route_policy)],
)

public_router = APIRouter(
    prefix="/public/kb",
    tags=["knowledge-base-public"],
    dependencies=[Depends(maybe_enforce_api_key_route_policy)],
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _require_kb_enabled() -> None:
    if not S.knowledge_base_enabled:
        raise HTTPException(status_code=404, detail="Not found")


def _require_admin(user: AuthenticatedUser) -> None:
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(status_code=403, detail="Admin access required")


def _article_to_out(item: dict) -> KbArticleOut:
    return KbArticleOut.model_validate({
        "article_id": item.get("article_id", ""),
        "title": item.get("title", ""),
        "body_html": item.get("body_html", ""),
        "excerpt": item.get("excerpt", ""),
        "status": item.get("status", "draft"),
        "category_id": item.get("category_id"),
        "category": item.get("category"),
        "author_sub": item.get("author_sub", ""),
        "tags": item.get("tags", []),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "published_at": int(item["published_at"]) if item.get("published_at") is not None else None,
        "expires_at": int(item["expires_at"]) if item.get("expires_at") is not None else None,
        "expired_at": int(item["expired_at"]) if item.get("expired_at") is not None else None,
        "expiry_reason": item.get("expiry_reason"),
        "view_count": int(item.get("view_count", 0)),
        "helpful_count": int(item.get("helpful_count", 0)),
        "not_helpful_count": int(item.get("not_helpful_count", 0)),
        "attachments": [],
    })


def _article_to_summary(item: dict) -> KbArticleSummaryOut:
    return KbArticleSummaryOut.model_validate({
        "article_id": item.get("article_id", ""),
        "title": item.get("title", ""),
        "excerpt": item.get("excerpt", ""),
        "status": item.get("status", "draft"),
        "category_id": item.get("category_id"),
        "category": item.get("category"),
        "author_sub": item.get("author_sub", ""),
        "tags": item.get("tags", []),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "published_at": int(item["published_at"]) if item.get("published_at") is not None else None,
        "view_count": int(item.get("view_count", 0)),
        "helpful_count": int(item.get("helpful_count", 0)),
        "not_helpful_count": int(item.get("not_helpful_count", 0)),
    })


def _category_to_out(item: dict) -> KbCategoryOut:
    return KbCategoryOut.model_validate({
        "category_id": item.get("category_id", ""),
        "name": item.get("name", ""),
        "parent_id": item.get("parent_id"),
        "path": item.get("path", ""),
        "description": item.get("description", ""),
        "sort_order": int(item.get("sort_order", 0)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "children": [],
    })


# ─── Public endpoints (unauthenticated) ───────────────────────────────────────


@public_router.get("/search")
async def public_kb_search(
    q: str = Query(""),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
) -> KbSearchOut:
    _require_kb_enabled()
    svc = KbArticleService()
    items, next_cursor = svc.search_articles(q, limit=limit, cursor=cursor)
    return KbSearchOut(
        items=[_article_to_summary(i) for i in items],
        query=q,
        cursor=next_cursor,
    )


@public_router.get("/categories")
async def public_list_categories() -> KbCategoryListOut:
    _require_kb_enabled()
    svc = KbArticleService()
    cats = svc.list_categories()
    return KbCategoryListOut(categories=[_category_to_out(c) for c in cats])


@public_router.get("/categories/{category_id}")
async def public_get_category(category_id: str) -> KbCategoryOut:
    _require_kb_enabled()
    svc = KbArticleService()
    cat = svc.get_category(category_id)
    return _category_to_out(cat)


@public_router.get("/tags")
async def public_list_tags(limit: int = Query(50, ge=1, le=200)) -> KbTagListOut:
    _require_kb_enabled()
    svc = KbArticleService()
    tags = svc.list_popular_tags(limit=limit)
    return KbTagListOut(
        tags=[KbTagStats(tag=t.get("tag", ""), article_count=int(t.get("article_count", 0))) for t in tags]
    )


@public_router.get("/tags/{tag}/articles")
async def public_articles_by_tag(
    tag: str,
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    request: Request = None,  # type: ignore[assignment]
) -> KbArticleListOut:
    _require_kb_enabled()
    svc = KbArticleService()
    items, next_cursor = svc.list_articles_by_tag(tag, limit=limit, cursor=cursor)
    return KbArticleListOut(
        items=[_article_to_summary(i) for i in items],
        cursor=next_cursor,
        total=len(items),
    )


@public_router.get("/articles")
async def public_list_articles(
    category_id: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
) -> KbArticleListOut:
    _require_kb_enabled()
    svc = KbArticleService()
    if tag:
        items, next_cursor = svc.list_articles_by_tag(tag, limit=limit, cursor=cursor)
    else:
        items, next_cursor = svc.list_articles(
            status="published", category_id=category_id, limit=limit, cursor=cursor
        )
    return KbArticleListOut(
        items=[_article_to_summary(i) for i in items],
        cursor=next_cursor,
        total=len(items),
    )


@public_router.get("/articles/{article_id}")
async def public_get_article(
    article_id: str,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    request: Request = None,  # type: ignore[assignment]
) -> KbArticleOut:
    _require_kb_enabled()
    svc = KbArticleService()
    item = svc.get_article(article_id, published_only=True)
    # Fire-and-forget view counter
    client_ip = ""
    if request is not None:
        try:
            client_ip = request.client.host if request.client else ""
        except Exception:
            pass
    viewer_id = client_ip or "anon"
    background_tasks.add_task(svc.record_view, article_id, viewer_id)
    out = _article_to_out(item)
    attachments = svc.list_attachments(article_id)
    out.attachments = attachments
    return out


# ─── Authenticated article endpoints ──────────────────────────────────────────


# Static paths before /{article_id}
@router.get("/search")
async def search_articles(
    q: str = Query(""),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    _session: dict = Depends(require_ui_session),
) -> KbSearchOut:
    _require_kb_enabled()
    svc = KbArticleService()
    items, next_cursor = svc.search_articles(q, limit=limit, cursor=cursor)
    return KbSearchOut(
        items=[_article_to_summary(i) for i in items],
        query=q,
        cursor=next_cursor,
    )


@router.get("/categories")
async def list_categories(_session: dict = Depends(require_ui_session)) -> KbCategoryListOut:
    _require_kb_enabled()
    return KbCategoryListOut(categories=[_category_to_out(c) for c in KbArticleService().list_categories()])


@router.post("/categories")
async def create_category(
    body: KbCategoryIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbCategoryOut:
    _require_kb_enabled()
    _require_admin(user)
    cat = KbArticleService().create_category(
        user.sub,
        name=body.name,
        parent_id=body.parent_id,
        description=body.description,
        sort_order=body.sort_order,
    )
    return _category_to_out(cat)


@router.get("/categories/{category_id}")
async def get_category(
    category_id: str,
    _session: dict = Depends(require_ui_session),
) -> KbCategoryOut:
    _require_kb_enabled()
    return _category_to_out(KbArticleService().get_category(category_id))


@router.put("/categories/{category_id}")
async def update_category(
    category_id: str,
    body: KbCategoryIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbCategoryOut:
    _require_kb_enabled()
    _require_admin(user)
    cat = KbArticleService().update_category(
        category_id,
        user.sub,
        name=body.name,
        parent_id=body.parent_id,
        description=body.description,
        sort_order=body.sort_order,
    )
    return _category_to_out(cat)


@router.delete("/categories/{category_id}")
async def delete_category(
    category_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> dict:
    _require_kb_enabled()
    _require_admin(user)
    KbArticleService().delete_category(category_id, user.sub)
    return {"ok": True}


# Articles list + create
@router.get("/articles")
async def list_articles(
    status: str = Query("published"),
    category_id: Optional[str] = Query(None),
    author_sub: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleListOut:
    _require_kb_enabled()
    # Non-admins can only see published articles
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        status = "published"
    svc = KbArticleService()
    items, next_cursor = svc.list_articles(
        status=status, category_id=category_id, author_sub=author_sub, limit=limit, cursor=cursor
    )
    return KbArticleListOut(
        items=[_article_to_summary(i) for i in items],
        cursor=next_cursor,
        total=len(items),
    )


@router.get("/my-articles")
async def list_my_articles(
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleListOut:
    _require_kb_enabled()
    svc = KbArticleService()
    items, next_cursor = svc.list_articles(author_sub=user.sub, status="all", limit=limit, cursor=cursor)
    return KbArticleListOut(
        items=[_article_to_summary(i) for i in items],
        cursor=next_cursor,
        total=len(items),
    )


@router.post("/articles", status_code=201)
async def create_article(
    body: KbArticleCreateIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleOut:
    _require_kb_enabled()
    _require_admin(user)
    svc = KbArticleService()
    item = svc.create_article(
        user.sub,
        title=body.title,
        body_html=body.body_html,
        excerpt=body.excerpt,
        category_id=body.category_id,
        tags=body.tags,
        expires_at=body.expires_at,
    )
    return _article_to_out(item)


# Per-article sub-resource endpoints (before /{article_id} generic)
@router.post("/articles/{article_id}/publish")
async def publish_article(
    article_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleOut:
    _require_kb_enabled()
    _require_admin(user)
    try:
        item = KbArticleService().publish_article(article_id, user.sub)
    except KbArticleStateError as exc:
        raise HTTPException(409, detail=str(exc))
    return _article_to_out(item)


@router.post("/articles/{article_id}/expire")
async def expire_article(
    article_id: str,
    body: KbExpireReq,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleOut:
    _require_kb_enabled()
    _require_admin(user)
    try:
        item = KbArticleService().expire_article(article_id, user.sub, reason=body.reason)
    except KbArticleStateError as exc:
        raise HTTPException(409, detail=str(exc))
    return _article_to_out(item)


@router.post("/articles/{article_id}/unpublish")
async def unpublish_article(
    article_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleOut:
    _require_kb_enabled()
    _require_admin(user)
    try:
        item = KbArticleService().unpublish_to_draft(article_id, user.sub)
    except KbArticleStateError as exc:
        raise HTTPException(409, detail=str(exc))
    return _article_to_out(item)


@router.post("/articles/{article_id}/rate")
async def rate_article(
    article_id: str,
    body: KbRateReq,
    _session: dict = Depends(require_ui_session),
) -> KbRateOut:
    _require_kb_enabled()
    user_sub = _session.get("user_sub", "")
    result = KbArticleService().rate_article(article_id, user_sub, helpful=body.helpful)
    return KbRateOut(**result)


@router.get("/articles/{article_id}/attachments")
async def list_attachments(
    article_id: str,
    _session: dict = Depends(require_ui_session),
) -> dict:
    _require_kb_enabled()
    attachments = KbArticleService().list_attachments(article_id)
    return {"attachments": attachments}


@router.post("/articles/{article_id}/attachments", status_code=201)
async def upload_attachment(
    article_id: str,
    file: UploadFile = File(...),
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbAttachmentOut:
    _require_kb_enabled()
    _require_admin(user)
    content = await file.read()
    svc = KbArticleService()
    att = svc.add_attachment(
        article_id,
        user.sub,
        filename=file.filename or "upload",
        content_type=file.content_type or "application/octet-stream",
        content=content,
    )
    return KbAttachmentOut.model_validate({
        "attachment_id": att["attachment_id"],
        "article_id": att["article_id"],
        "filename": att["filename"],
        "content_type": att["content_type"],
        "size_bytes": int(att["size_bytes"]),
        "url": att.get("url", ""),
        "uploaded_by": att["uploaded_by"],
        "created_at": int(att["created_at"]),
    })


@router.delete("/articles/{article_id}/attachments/{attachment_id}")
async def delete_attachment(
    article_id: str,
    attachment_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> dict:
    _require_kb_enabled()
    _require_admin(user)
    KbArticleService().delete_attachment(article_id, attachment_id, user.sub)
    return {"ok": True}


# Generic article CRUD (must come after sub-resource routes)
@router.get("/articles/{article_id}")
async def get_article(
    article_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> KbArticleOut:
    _require_kb_enabled()
    svc = KbArticleService()
    published_only = normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}
    item = svc.get_article(article_id, published_only=published_only)
    if item.get("status") == "published":
        background_tasks.add_task(svc.record_view, article_id, user.sub)
    out = _article_to_out(item)
    out.attachments = svc.list_attachments(article_id)
    return out


@router.put("/articles/{article_id}")
async def update_article(
    article_id: str,
    body: KbArticleUpdateIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> KbArticleOut:
    _require_kb_enabled()
    _require_admin(user)
    item = KbArticleService().update_article(
        article_id,
        user.sub,
        title=body.title,
        body_html=body.body_html,
        excerpt=body.excerpt,
        category_id=body.category_id,
        tags=body.tags,
        expires_at=body.expires_at,
    )
    return _article_to_out(item)


@router.delete("/articles/{article_id}")
async def delete_article(
    article_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
    _session: dict = Depends(require_ui_session),
) -> dict:
    _require_kb_enabled()
    _require_admin(user)
    KbArticleService().delete_article(article_id, user.sub)
    return {"ok": True}
