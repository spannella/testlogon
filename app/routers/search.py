"""Global search aggregator — unified search across users, posts, catalog, and files."""

from __future__ import annotations

import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.aws import ddb
from app.core.tables import T
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/search", tags=["search"])

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

ALLOWED_TYPES = {"users", "posts", "catalog", "files"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_query(q: str) -> str:
    """Remove control characters and excessive whitespace."""
    q = re.sub(r"[\x00-\x1f\x7f]", "", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:200]


def _empty_section() -> Dict[str, Any]:
    return {"items": [], "total_estimate": 0, "has_more": False}


def _make_result_item(
    *,
    type: str,
    id: str,
    title: str,
    snippet: str = "",
    thumbnail_url: Optional[str] = None,
    url: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "type": type,
        "id": id,
        "title": title,
        "snippet": snippet,
        "url": url,
    }
    if thumbnail_url:
        item["thumbnail_url"] = thumbnail_url
    if meta:
        item["meta"] = meta
    return item


# ---------------------------------------------------------------------------
# Per-module search functions
# ---------------------------------------------------------------------------

def _search_users(q: str, viewer_id: str, limit: int) -> Dict[str, Any]:
    """Search users via the discovery index."""
    try:
        from app.services.discovery import search_users
        items, _ = search_users(q, viewer_id=viewer_id, limit=limit)
        results = []
        for it in items:
            uid = it.get("user_id", "")
            display_name = it.get("display_name", uid)
            results.append(_make_result_item(
                type="user",
                id=uid,
                title=display_name,
                snippet=it.get("description", "")[:120] if it.get("description") else "",
                thumbnail_url=it.get("profile_photo_url"),
                url="/discover",
                meta={
                    "follower_count": int(it.get("follower_count", 0)),
                    "is_following": bool(it.get("is_following", False)),
                },
            ))
        return {"items": results, "total_estimate": len(results), "has_more": len(results) >= limit}
    except Exception:
        logger.exception("User search failed")
        return _empty_section()


def _search_posts(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search published posts by body text using DDB scan + FilterExpression."""
    try:
        tokens = q.lower().split()[:5]
        if not tokens:
            return _empty_section()

        # Build FilterExpression: sk=META AND pk begins_with POST# AND each token in body_plain
        filter_parts = ["sk = :meta", "begins_with(pk, :post_prefix)"]
        expr_values: Dict[str, Any] = {":meta": "META", ":post_prefix": "POST#"}
        for i, tok in enumerate(tokens):
            filter_parts.append(f"contains(body_plain_lc, :t{i})")
            expr_values[f":t{i}"] = tok

        filter_expr = " AND ".join(filter_parts)

        matches: List[Dict[str, Any]] = []
        last_key = None
        pages = 0
        now_ts = int(time.time())

        while len(matches) < limit and pages < 4:
            kwargs: Dict[str, Any] = {
                "FilterExpression": filter_expr,
                "ExpressionAttributeValues": expr_values,
                "Limit": 500,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = tbl.scan(**kwargs)
            for item in resp.get("Items", []):
                # Exclude non-public, scheduled (future), locked body
                visibility = item.get("visibility", "")
                if visibility not in ("public", "followers"):
                    continue
                # Skip scheduled/draft posts
                status = item.get("status", "published")
                if status == "scheduled":
                    publish_at = item.get("publish_at")
                    if publish_at and int(publish_at) > now_ts:
                        continue
                if status == "draft":
                    continue

                post_id = item.get("post_id", "")
                body_plain = item.get("body_plain", item.get("body", ""))
                is_locked = bool(item.get("unlock_price_cents"))

                snippet = "[Locked]" if is_locked else (body_plain or "")[:120]

                matches.append(_make_result_item(
                    type="post",
                    id=post_id,
                    title=snippet[:60],
                    snippet=snippet,
                    url=f"/posts/{post_id}",
                    meta={
                        "author_id": item.get("user_id", ""),
                        "is_locked": is_locked,
                    },
                ))
                if len(matches) >= limit:
                    break
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            pages += 1

        has_more = last_key is not None and len(matches) >= limit
        return {"items": matches, "total_estimate": len(matches), "has_more": has_more}
    except Exception:
        logger.exception("Post search failed")
        return _empty_section()


def _search_catalog(q: str, limit: int) -> Dict[str, Any]:
    """Search catalog items by name/description match."""
    try:
        query_tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not query_tokens:
            return _empty_section()

        matches: List[Dict[str, Any]] = []
        last_key = None
        pages = 0

        while len(matches) < limit and pages < 4:
            kwargs: Dict[str, Any] = {"Limit": 200}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.catalog.scan(**kwargs)
            for item in resp.get("Items", []):
                if item.get("entity") != "item":
                    continue
                haystack = " ".join([
                    str(item.get("name", "")).lower(),
                    str(item.get("description", "") or "").lower(),
                ])
                if all(tok in haystack for tok in query_tokens):
                    matches.append(_make_result_item(
                        type="catalog",
                        id=item.get("item_id", ""),
                        title=str(item.get("name", "")),
                        snippet=str(item.get("description", "") or "")[:120],
                        url=f"/shop/{item.get('category_id', '')}/{item.get('item_id', '')}",
                        meta={
                            "price_cents": int(item.get("price_cents", 0)),
                            "category_id": item.get("category_id", ""),
                        },
                    ))
                    if len(matches) >= limit:
                        break
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            pages += 1

        has_more = last_key is not None and len(matches) >= limit
        return {"items": matches, "total_estimate": len(matches), "has_more": has_more}
    except Exception:
        logger.exception("Catalog search failed")
        return _empty_section()


def _search_files(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search user's files by name prefix."""
    try:
        from app.services.filemanager import search_prefix
        items = search_prefix(user_id, q, limit=limit)
        results = []
        for it in items:
            results.append(_make_result_item(
                type="file",
                id=it.get("path", ""),
                title=it.get("name", ""),
                snippet=it.get("path", ""),
                url="/files",
                meta={"size": it.get("size")},
            ))
        return {"items": results, "total_estimate": len(results), "has_more": len(results) >= limit}
    except Exception:
        logger.exception("File search failed")
        return _empty_section()


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def _search_aggregator(
    q: str,
    user_id: str,
    types: List[str],
    limit: int,
) -> Dict[str, Any]:
    """Fan out to per-module searches in parallel using ThreadPoolExecutor."""
    results: Dict[str, Any] = {}
    partial = False

    # Build map of search functions
    search_fns: Dict[str, Any] = {}
    if "users" in types:
        search_fns["users"] = lambda: _search_users(q, user_id, limit)
    if "posts" in types:
        search_fns["posts"] = lambda: _search_posts(q, user_id, limit)
    if "catalog" in types:
        search_fns["catalog"] = lambda: _search_catalog(q, limit)
    if "files" in types:
        search_fns["files"] = lambda: _search_files(q, user_id, limit)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): name for name, fn in search_fns.items()}
        for future in as_completed(futures, timeout=5):
            name = futures[future]
            try:
                results[name] = future.result(timeout=2)
            except Exception:
                logger.exception("Search module %s timed out or failed", name)
                results[name] = _empty_section()
                partial = True

    # Fill in empty sections for types not searched
    for t in ALLOWED_TYPES:
        if t not in results:
            results[t] = _empty_section()

    return {"results": results, "partial": partial}


# ---------------------------------------------------------------------------
# Post-write hook: store body_plain_lc on post creation for search
# ---------------------------------------------------------------------------

def ensure_post_search_field(post_id: str, body_plain: str) -> None:
    """Store a lowercased version of body_plain for search FilterExpression matching."""
    try:
        tbl.update_item(
            Key={"pk": f"POST#{post_id}", "sk": "META"},
            UpdateExpression="SET body_plain_lc = :lc",
            ExpressionAttributeValues={":lc": (body_plain or "").lower()},
        )
    except Exception:
        logger.exception("Failed to store body_plain_lc for post %s", post_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
def global_search(
    q: str = Query(..., min_length=1, max_length=200),
    types: str = Query(default="users,posts,catalog,files"),
    limit: int = Query(default=5, ge=1, le=20),
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    q = _sanitize_query(q)
    if not q:
        raise HTTPException(status_code=400, detail="Query is empty")

    requested_types = [t.strip() for t in types.split(",") if t.strip()]
    invalid = set(requested_types) - ALLOWED_TYPES
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid search types: {', '.join(invalid)}")

    result = _search_aggregator(q, user_id, requested_types, limit)
    return {"query": q, **result}
