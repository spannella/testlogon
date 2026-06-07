"""Global search aggregator — unified search across users, posts, catalog, files,
messages, tickets, contacts, videos, and calendar events.

Search history is stored in ``app_single_table`` under the PK pattern
``SEARCH_HISTORY#{user_sub}``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.aws import ddb
from app.core.tables import T
from app.core.time import now_ts
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/search", tags=["search"])

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

_EXTENDED_SEARCH = os.environ.get("GLOBAL_SEARCH_EXTENDED_DOMAINS", "true").lower() == "true"

ALLOWED_TYPES = {"users", "posts", "catalog", "files"}
if _EXTENDED_SEARCH:
    ALLOWED_TYPES |= {"messages", "tickets", "contacts", "videos", "calendar"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_query(q: str) -> str:
    """Remove control characters, normalize Unicode, and collapse whitespace."""
    q = unicodedata.normalize("NFC", q)
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
        now_ts_val = int(time.time())

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
                    if publish_at and int(publish_at) > now_ts_val:
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
# New search modules (extended domains)
# ---------------------------------------------------------------------------

def _search_messages(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Cross-conversation message search using the MessageSearch token index."""
    try:
        from app.routers.messaging import (
            build_message_query_tokens,
            _message_search_enabled,
            tbl_parts,
            tbl_msgs,
            tbl_msg_search,
        )

        if not _message_search_enabled():
            return _empty_section()

        tokens = build_message_query_tokens(q)
        if not tokens:
            return _empty_section()

        # Step 1: Get the user's conversation IDs for authorization.
        # GAP-0329: paginate until DynamoDB is exhausted so the COMPLETE
        # allowed_conv_ids set is built before filtering. A premature
        # len(parts) >= 500 early-exit previously dropped all conversations
        # beyond the first page, so users in >500 conversations got no search
        # results for conversations 501+. Per the DDB FilterExpression/page
        # caveat, loop on LastEvaluatedKey until it is falsy. A generous
        # page-count safety bound prevents unbounded memory; if it is ever hit
        # we LOG rather than silently truncate.
        _MAX_PARTICIPANT_PAGES = 50  # 50 x 500 = 25,000 conversations
        parts: list[dict] = []
        last_key = None
        page_count = 0
        while True:
            kw: dict = {"KeyConditionExpression": Key("user_id").eq(user_id), "Limit": 500}
            if last_key:
                kw["ExclusiveStartKey"] = last_key
            resp = tbl_parts.query(**kw)
            parts.extend(resp.get("Items", []))
            page_count += 1
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            if page_count >= _MAX_PARTICIPANT_PAGES:
                logger.warning(
                    "search: participant pagination hit safety cap of %d pages "
                    "(%d records) for user_id=%s; allowed_conv_ids may be "
                    "truncated",
                    _MAX_PARTICIPANT_PAGES,
                    len(parts),
                    user_id,
                )
                break

        allowed_conv_ids: set[str] = {p["conversation_id"] for p in parts}
        if not allowed_conv_ids:
            return _empty_section()

        # Step 2: Query MessageSearch table for each token (limit to first 3 tokens)
        candidate_pairs: Dict[str, set] = {}  # conv_id -> set of msg_ids
        for token in tokens[:3]:
            resp = tbl_msg_search.query(
                KeyConditionExpression=Key("token").eq(token),
                Limit=100,
            )
            for item in resp.get("Items", []):
                sk = item.get("conversation_id#message_id", "")
                parts_split = sk.split("#", 1)
                if len(parts_split) != 2:
                    continue
                conv_id, msg_id = parts_split
                if conv_id not in allowed_conv_ids:
                    continue
                if conv_id not in candidate_pairs:
                    candidate_pairs[conv_id] = set()
                candidate_pairs[conv_id].add(msg_id)

        # Step 3: Fetch actual message records for top results
        results: List[Dict[str, Any]] = []
        for conv_id, msg_ids in list(candidate_pairs.items())[:limit]:
            for msg_id in list(msg_ids)[:1]:  # One message per conversation
                try:
                    msg_item = tbl_msgs.get_item(
                        Key={"conversation_id": conv_id, "message_id": msg_id}
                    ).get("Item")
                    if not msg_item:
                        continue

                    text = msg_item.get("text", "")
                    is_encrypted = bool(msg_item.get("encryption"))
                    is_expired = bool(msg_item.get("expired_at"))
                    is_view_once = bool(msg_item.get("view_once"))

                    if is_encrypted:
                        snippet = "[Encrypted message]"
                    elif is_expired:
                        snippet = "[Expired message]"
                    elif is_view_once:
                        snippet = "[View-once message]"
                    else:
                        snippet = text[:120] if text else ""

                    sender_id = msg_item.get("sender_id", "")
                    created_at = int(msg_item.get("created_at", 0))

                    results.append(_make_result_item(
                        type="message",
                        id=msg_id,
                        title="Message in conversation",
                        snippet=snippet,
                        url=f"/messages/{conv_id}",
                        meta={
                            "conversation_id": conv_id,
                            "sender_id": sender_id,
                            "created_at": created_at,
                            "is_encrypted": is_encrypted,
                        },
                    ))
                except Exception:
                    logger.exception("Failed to fetch message %s/%s", conv_id, msg_id)
                    continue

            if len(results) >= limit:
                break

        return {
            "items": results[:limit],
            "total_estimate": sum(len(ids) for ids in candidate_pairs.values()),
            "has_more": len(results) >= limit,
        }
    except Exception:
        logger.exception("Message search failed")
        return _empty_section()


def _search_tickets(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search tickets by subject text. Only META items are searched."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        matches: List[Dict[str, Any]] = []
        last_key = None
        pages = 0

        while len(matches) < limit and pages < 4:
            kwargs: Dict[str, Any] = {"Limit": 200}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = T.tickets.scan(**kwargs)
            for item in resp.get("Items", []):
                # Only META items have the subject
                if item.get("sk") != "META":
                    continue

                # Authorization: user must be creator or assignee
                creator = item.get("owner_sub", "")
                assignee = item.get("assigned_to_sub", "") or ""
                assigned_admin = item.get("assigned_admin_sub", "") or ""
                if creator != user_id and assignee != user_id and assigned_admin != user_id:
                    continue

                # Text matching against subject
                haystack = str(item.get("subject", "")).lower()
                if not all(tok in haystack for tok in tokens):
                    continue

                ticket_id = item.get("ticket_id", "")
                status = item.get("status", "open")
                space_id = item.get("space_id")

                matches.append(_make_result_item(
                    type="ticket",
                    id=ticket_id,
                    title=str(item.get("subject", "")),
                    snippet=str(item.get("subject", ""))[:120],
                    url=f"/tickets/{ticket_id}",
                    meta={
                        "status": status,
                        "priority": item.get("priority", "normal"),
                        "space_id": space_id,
                        "created_by": creator,
                        "assigned_to": assignee,
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
        logger.exception("Ticket search failed")
        return _empty_section()


def _search_contacts(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search user's contacts by name, email, and notes."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        # Query user's contacts partition
        resp = T.contacts.query(
            KeyConditionExpression=Key("owner_id").eq(user_id),
            Limit=500,
        )
        matches: List[Dict[str, Any]] = []
        for item in resp.get("Items", []):
            haystack = " ".join([
                str(item.get("display_name", "")).lower(),
                str(item.get("email", "") or "").lower(),
                str(item.get("notes", "") or "").lower(),
                str(item.get("phone", "") or "").lower(),
                str(item.get("contact_id", "") or "").lower(),
            ])
            if not all(tok in haystack for tok in tokens):
                continue

            contact_id = item.get("contact_id", "")
            matches.append(_make_result_item(
                type="contact",
                id=contact_id,
                title=str(item.get("display_name", "")),
                snippet=str(item.get("email", "") or item.get("contact_id", "")),
                url=f"/contacts/{contact_id}",
                meta={
                    "email": item.get("email"),
                    "phone": item.get("phone"),
                },
            ))
            if len(matches) >= limit:
                break

        return {
            "items": matches[:limit],
            "total_estimate": len(matches),
            "has_more": len(matches) > limit,
        }
    except Exception:
        logger.exception("Contact search failed")
        return _empty_section()


def _search_videos(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search VOD videos by title and description."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        matches: List[Dict[str, Any]] = []
        last_key = None
        pages = 0

        while len(matches) < limit and pages < 4:
            kwargs: Dict[str, Any] = {"Limit": 200}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = T.video_metadata.scan(**kwargs)
            for item in resp.get("Items", []):
                # Authorization: public or owned by user
                visibility = item.get("visibility", "private")
                owner = item.get("owner_user_id", "")
                if visibility != "public" and owner != user_id:
                    continue

                # Skip deleted/processing videos
                status = item.get("status", "")
                if status in ("deleted", "processing"):
                    continue

                haystack = " ".join([
                    str(item.get("title", "")).lower(),
                    str(item.get("description", "") or "").lower(),
                ])
                if not all(tok in haystack for tok in tokens):
                    continue

                video_id = item.get("video_id", "")
                matches.append(_make_result_item(
                    type="video",
                    id=video_id,
                    title=str(item.get("title", "")),
                    snippet=str(item.get("description", "") or "")[:120],
                    thumbnail_url=item.get("thumbnail_url"),
                    url=f"/videos/{video_id}",
                    meta={
                        "duration_seconds": int(item.get("duration_seconds", 0) or 0),
                        "owner_id": owner,
                        "visibility": visibility,
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
        logger.exception("Video search failed")
        return _empty_section()


def _search_calendar(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search calendar events by title and description."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        # Search user's default calendar
        calendar_ids = [f"CAL#{user_id}"]

        matches: List[Dict[str, Any]] = []
        for cal_id in calendar_ids[:10]:  # Cap calendars to prevent fan-out
            resp = T.calendar.query(
                KeyConditionExpression=Key("calendar_id").eq(cal_id),
                Limit=200,
            )
            for item in resp.get("Items", []):
                if not item.get("title"):
                    continue
                haystack = " ".join([
                    str(item.get("title", "")).lower(),
                    str(item.get("description", "") or "").lower(),
                    str(item.get("location", "") or "").lower(),
                ])
                if not all(tok in haystack for tok in tokens):
                    continue

                event_id = item.get("event_id", item.get("sk", ""))
                start_ts = int(item.get("start_ts", 0) or 0)

                matches.append(_make_result_item(
                    type="calendar",
                    id=event_id,
                    title=str(item.get("title", "")),
                    snippet=str(item.get("description", "") or "")[:120],
                    url=f"/calendar?event={event_id}",
                    meta={
                        "start_ts": start_ts,
                        "end_ts": int(item.get("end_ts", 0) or 0),
                        "location": item.get("location"),
                        "calendar_id": cal_id,
                    },
                ))
                if len(matches) >= limit:
                    break

            if len(matches) >= limit:
                break

        return {
            "items": matches[:limit],
            "total_estimate": len(matches),
            "has_more": len(matches) >= limit,
        }
    except Exception:
        logger.exception("Calendar search failed")
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
    if "messages" in types:
        search_fns["messages"] = lambda: _search_messages(q, user_id, limit)
    if "tickets" in types:
        search_fns["tickets"] = lambda: _search_tickets(q, user_id, limit)
    if "contacts" in types:
        search_fns["contacts"] = lambda: _search_contacts(q, user_id, limit)
    if "videos" in types:
        search_fns["videos"] = lambda: _search_videos(q, user_id, limit)
    if "calendar" in types:
        search_fns["calendar"] = lambda: _search_calendar(q, user_id, limit)

    max_workers = min(len(search_fns), 8) if search_fns else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
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
# Search history helpers
# ---------------------------------------------------------------------------

def _query_hash(query: str) -> str:
    """Generate a short hash for deduplication."""
    return hashlib.md5(query.lower().strip().encode()).hexdigest()[:8]


def record_search_history(user_sub: str, query: str, result_count: int = 0) -> str:
    """Record a search query in user's search history. Deduplicates."""
    ts = now_ts()
    q_hash = _query_hash(query)
    history_id = f"TS#{ts:010d}#{q_hash}"
    pk = f"SEARCH_HISTORY#{user_sub}"

    # Check for existing entry with same query hash
    existing = tbl.query(
        KeyConditionExpression=Key("pk").eq(pk),
        ProjectionExpression="pk, sk, #q",
        ExpressionAttributeNames={"#q": "query"},
    ).get("Items", [])

    # Find and delete existing entries with same hash
    for item in existing:
        if item["sk"].endswith(f"#{q_hash}"):
            tbl.delete_item(Key={"pk": pk, "sk": item["sk"]})

    tbl.put_item(Item={
        "pk": pk,
        "sk": history_id,
        "query": query.strip(),
        "ts": ts,
        "result_count": result_count,
        "ttl": ts + (90 * 86400),
    })

    # Enforce cap: delete oldest entries beyond 50
    _trim_search_history(user_sub, max_entries=50)

    return history_id


def list_search_history(user_sub: str, limit: int = 20) -> List[Dict[str, Any]]:
    """List recent search queries, newest first."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        ScanIndexForward=False,
        Limit=min(limit, 50),
    )
    return [
        {
            "id": item["sk"],
            "query": item["query"],
            "ts": int(item["ts"]),
            "result_count": int(item.get("result_count", 0)),
        }
        for item in resp.get("Items", [])
    ]


def delete_search_history_item(user_sub: str, item_id: str) -> bool:
    """Delete a single search history item."""
    try:
        tbl.delete_item(
            Key={"pk": f"SEARCH_HISTORY#{user_sub}", "sk": item_id},
            ConditionExpression="attribute_exists(pk)",
        )
        return True
    except tbl.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def clear_search_history(user_sub: str) -> int:
    """Delete all search history for a user. Returns count of deleted items."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        ProjectionExpression="pk, sk",
    )
    items = resp.get("Items", [])
    for item in items:
        tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
    return len(items)


def _trim_search_history(user_sub: str, max_entries: int = 50) -> None:
    """Evict oldest entries beyond max_entries."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        ScanIndexForward=False,  # newest first
        ProjectionExpression="pk, sk",
    )
    items = resp.get("Items", [])
    if len(items) <= max_entries:
        return
    for item in items[max_entries:]:
        tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})


# ---------------------------------------------------------------------------
# Request/response models for search history
# ---------------------------------------------------------------------------

class RecordSearchHistoryReq(BaseModel):
    query: str
    result_count: int = 0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
def global_search(
    q: str = Query(..., min_length=1, max_length=500),
    types: str = Query(default=",".join(sorted(ALLOWED_TYPES))),
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


# ── Search History Endpoints ──────────────────────────────────────────────

@router.post("/history")
def save_search_history(
    body: RecordSearchHistoryReq,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    query = body.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query is empty")
    history_id = record_search_history(user_id, query, body.result_count)
    return {"ok": True, "id": history_id}


@router.get("/history")
def get_search_history(
    limit: int = Query(default=20, ge=1, le=50),
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    items = list_search_history(user_id, limit)
    return {"items": items}


@router.delete("/history/{item_id:path}")
def delete_single_search_history(
    item_id: str,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    found = delete_search_history_item(user_id, item_id)
    if not found:
        raise HTTPException(status_code=404, detail="History item not found")
    return {"ok": True}


@router.delete("/history")
def clear_all_search_history(
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    count = clear_search_history(user_id)
    return {"ok": True, "deleted_count": count}
