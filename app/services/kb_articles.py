"""Knowledge Base article service — KB-001 through KB-011.

Single-table DynamoDB layout on ``crm_kb_articles`` (T.kb_articles):

  Article META:     pk=ARTICLE#{id}   sk=META
  Attachment:       pk=ARTICLE#{id}   sk=ATTACHMENT#{att_id}
  Rating:           pk=ARTICLE#{id}   sk=RATING#{user_sub}
  View dedup:       pk=ARTICLE#{id}   sk=VIEW#{viewer_id}   (TTL 24 h)
  Category:         pk=CATEGORY#{id}  sk=META
  Tag index row:    pk=TAG#{tag}      sk=ARTICLE#{id}
  Tag stats:        pk=KB_TAG_STATS   sk=TAG#{tag}
  Search token:     pk=SEARCH_TOKEN#{token}  sk=ARTICLE#{id}

Flag gate: every public entry point must check ``S.knowledge_base_enabled``.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Exceptions ───────────────────────────────────────────────────────────────


class KbArticleStateError(Exception):
    """Raised when a lifecycle transition is invalid for the article's current status."""

    def __init__(self, current_status: str, attempted: str) -> None:
        super().__init__(f"Cannot transition from '{current_status}' to '{attempted}'")
        self.current_status = current_status
        self.attempted = attempted


class KbArticleNotFound(Exception):
    pass


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _safe_filename(name: str) -> str:
    """Sanitize a filename: strip path separators, limit to 255 chars."""
    name = re.sub(r"[/\\]", "_", name)
    return name[:255] or "file"


def _article_key(article_id: str) -> Dict[str, str]:
    return {"pk": f"ARTICLE#{article_id}", "sk": "META"}


def _is_conditional_conflict(exc: ClientError) -> bool:
    return (
        exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
    )


# ─── Core Service ─────────────────────────────────────────────────────────────


class KbArticleService:
    """Business logic for KB articles, categories, attachments, ratings, views."""

    # ── Article CRUD ──────────────────────────────────────────────────────────

    def create_article(
        self,
        author_sub: str,
        *,
        title: str,
        body_html: str = "",
        excerpt: str = "",
        category_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        expires_at: Optional[int] = None,
    ) -> dict:
        article_id = "kb_" + uuid.uuid4().hex
        ts = now_ts()
        item: Dict[str, Any] = {
            "pk": f"ARTICLE#{article_id}",
            "sk": "META",
            "article_id": article_id,
            "title": title,
            "body_html": body_html,
            "excerpt": excerpt,
            "status": "draft",
            "author_sub": author_sub,
            "category_id": category_id,
            "tags": tags or [],
            "created_at": ts,
            "updated_at": ts,
            "view_count": 0,
            "helpful_count": 0,
            "not_helpful_count": 0,
        }
        if expires_at is not None:
            item["expires_at"] = expires_at
        T.kb_articles.put_item(Item=item)
        return item

    def get_article(self, article_id: str, *, published_only: bool = False) -> dict:
        resp = T.kb_articles.get_item(Key=_article_key(article_id))
        item = resp.get("Item")
        if not item:
            raise HTTPException(404, detail=f"KB article '{article_id}' not found")
        if published_only and item.get("status") != "published":
            raise HTTPException(404, detail=f"KB article '{article_id}' not found")
        return item

    def update_article(
        self,
        article_id: str,
        admin_sub: str,
        *,
        title: Optional[str] = None,
        body_html: Optional[str] = None,
        excerpt: Optional[str] = None,
        category_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        expires_at: Optional[int] = None,
    ) -> dict:
        self.get_article(article_id)  # 404 guard
        ts = now_ts()
        set_parts = ["updated_at = :ts"]
        names: Dict[str, str] = {}
        values: Dict[str, Any] = {":ts": ts}
        if title is not None:
            set_parts.append("#title = :title")
            names["#title"] = "title"
            values[":title"] = title
        if body_html is not None:
            set_parts.append("body_html = :body_html")
            values[":body_html"] = body_html
        if excerpt is not None:
            set_parts.append("excerpt = :excerpt")
            values[":excerpt"] = excerpt
        if category_id is not None:
            set_parts.append("category_id = :cat")
            values[":cat"] = category_id
        if tags is not None:
            set_parts.append("tags = :tags")
            values[":tags"] = tags
        if expires_at is not None:
            set_parts.append("expires_at = :exp")
            values[":exp"] = expires_at
        expr = "SET " + ", ".join(set_parts)
        kwargs: Dict[str, Any] = {
            "Key": _article_key(article_id),
            "UpdateExpression": expr,
            "ExpressionAttributeValues": values,
        }
        if names:
            kwargs["ExpressionAttributeNames"] = names
        T.kb_articles.update_item(**kwargs)
        _audit("kb.article.updated", admin_sub, article_id=article_id)
        return self.get_article(article_id)

    def delete_article(self, article_id: str, admin_sub: str) -> None:
        self.get_article(article_id)  # 404 guard
        T.kb_articles.delete_item(Key=_article_key(article_id))
        _audit("kb.article.deleted", admin_sub, article_id=article_id)

    def list_articles(
        self,
        *,
        status: str = "published",
        category_id: Optional[str] = None,
        author_sub: Optional[str] = None,
        limit: int = 20,
        cursor: Optional[str] = None,
    ) -> Tuple[List[dict], Optional[str]]:
        """List articles; admin paths may pass status='draft' or 'all'."""
        from app.core.cursor import decode_cursor, encode_cursor

        items: List[dict] = []
        last_key: Optional[dict] = None
        if cursor:
            try:
                last_key = decode_cursor(cursor)
            except Exception:
                last_key = None

        if author_sub:
            # Use ByAuthor GSI
            kwargs: Dict[str, Any] = {
                "IndexName": "ByAuthor",
                "KeyConditionExpression": Key("author_sub").eq(author_sub),
                "Limit": limit,
                "ScanIndexForward": False,
            }
            if status != "all":
                kwargs["FilterExpression"] = Attr("status").eq(status)
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.kb_articles.query(**kwargs)
        elif status != "all":
            kwargs = {
                "IndexName": "ByStatus",
                "KeyConditionExpression": Key("status").eq(status),
                "Limit": limit,
                "ScanIndexForward": False,
            }
            if category_id:
                kwargs["FilterExpression"] = Attr("category_id").eq(category_id)
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.kb_articles.query(**kwargs)
        else:
            # scan all META rows — admin only
            kwargs = {
                "FilterExpression": Attr("sk").eq("META") & Attr("pk").begins_with("ARTICLE#"),
                "Limit": limit * 3,  # scan needs larger limit due to filter
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.kb_articles.scan(**kwargs)

        items = resp.get("Items", [])
        # Filter to only META rows when scanning
        items = [i for i in items if i.get("sk") == "META"][:limit]
        next_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(next_key) if next_key else None
        return items, next_cursor

    # ── Status lifecycle (KB-002) ─────────────────────────────────────────────

    def publish_article(self, article_id: str, admin_sub: str) -> dict:
        item = self.get_article(article_id)
        current_status = item.get("status", "draft")
        if current_status != "draft":
            raise KbArticleStateError(current_status, "published")
        ts = now_ts()
        try:
            T.kb_articles.update_item(
                Key=_article_key(article_id),
                UpdateExpression="SET #status = :published, published_at = :ts REMOVE expired_at, expiry_reason",
                ConditionExpression="#status = :draft",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":published": "published",
                    ":draft": "draft",
                    ":ts": ts,
                },
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KbArticleStateError(current_status, "published")
            raise
        _audit("kb.article.published", admin_sub, article_id=article_id)
        return self.get_article(article_id)

    def expire_article(self, article_id: str, admin_sub: str, *, reason: str = "") -> dict:
        item = self.get_article(article_id)
        current_status = item.get("status", "draft")
        if current_status != "published":
            raise KbArticleStateError(current_status, "expired")
        ts = now_ts()
        upd = "SET #status = :expired, expired_at = :ts"
        values: Dict[str, Any] = {
            ":expired": "expired",
            ":published": "published",
            ":ts": ts,
        }
        if reason:
            upd += ", expiry_reason = :reason"
            values[":reason"] = reason
        try:
            T.kb_articles.update_item(
                Key=_article_key(article_id),
                UpdateExpression=upd,
                ConditionExpression="#status = :published",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues=values,
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KbArticleStateError(current_status, "expired")
            raise
        _audit("kb.article.expired", admin_sub, article_id=article_id, reason=reason)
        return self.get_article(article_id)

    def unpublish_to_draft(self, article_id: str, admin_sub: str) -> dict:
        item = self.get_article(article_id)
        current_status = item.get("status", "draft")
        if current_status != "published":
            raise KbArticleStateError(current_status, "draft")
        try:
            T.kb_articles.update_item(
                Key=_article_key(article_id),
                UpdateExpression="SET #status = :draft REMOVE published_at",
                ConditionExpression="#status = :published",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":draft": "draft",
                    ":published": "published",
                },
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KbArticleStateError(current_status, "draft")
            raise
        _audit("kb.article.unpublished", admin_sub, article_id=article_id)
        return self.get_article(article_id)

    # ── Ratings (KB-005) ──────────────────────────────────────────────────────

    def rate_article(self, article_id: str, user_sub: str, *, helpful: bool) -> dict:
        """
        Rate an article as helpful or not helpful.
        Handles first vote, same-vote (idempotent), and vote change.
        Returns dict with ok, already_rated, helpful_count, not_helpful_count.
        """
        self.get_article(article_id, published_only=True)
        rating_key = {"pk": f"ARTICLE#{article_id}", "sk": f"RATING#{user_sub}"}
        ts = now_ts()

        existing_resp = T.kb_articles.get_item(Key=rating_key)
        existing = existing_resp.get("Item")
        direction = "helpful" if helpful else "not_helpful"

        if existing:
            old_helpful = existing.get("helpful", False)
            if old_helpful == helpful:
                # same vote — idempotent
                article = self.get_article(article_id)
                return {
                    "ok": True,
                    "already_rated": True,
                    "helpful_count": int(article.get("helpful_count", 0)),
                    "not_helpful_count": int(article.get("not_helpful_count", 0)),
                }
            # vote change: decrement old, increment new
            if helpful:
                upd_expr = "ADD helpful_count :pos, not_helpful_count :neg"
            else:
                upd_expr = "ADD not_helpful_count :pos, helpful_count :neg"
            T.kb_articles.update_item(
                Key=_article_key(article_id),
                UpdateExpression=upd_expr,
                ExpressionAttributeValues={":pos": 1, ":neg": -1},
            )
            T.kb_articles.put_item(Item={**rating_key, "helpful": helpful, "updated_at": ts})
        else:
            # first vote
            if helpful:
                upd_expr = "ADD helpful_count :one"
            else:
                upd_expr = "ADD not_helpful_count :one"
            T.kb_articles.update_item(
                Key=_article_key(article_id),
                UpdateExpression=upd_expr,
                ExpressionAttributeValues={":one": 1},
            )
            T.kb_articles.put_item(
                Item={**rating_key, "helpful": helpful, "created_at": ts, "updated_at": ts}
            )
            _audit("kb.article.rated", user_sub, article_id=article_id, direction=direction)

        article = self.get_article(article_id)
        return {
            "ok": True,
            "already_rated": False,
            "helpful_count": int(article.get("helpful_count", 0)),
            "not_helpful_count": int(article.get("not_helpful_count", 0)),
        }

    # ── View counter (KB-006) ──────────────────────────────────────────────────

    def increment_view_count(self, article_id: str) -> None:
        """Atomically increment view_count on the article META row."""
        try:
            T.kb_articles.update_item(
                Key=_article_key(article_id),
                UpdateExpression="ADD view_count :one",
                ExpressionAttributeValues={":one": 1},
            )
        except Exception:
            logger.debug("KB view_count increment failed for %s", article_id)

    def record_view(self, article_id: str, viewer_id: str) -> None:
        """Deduplicate view within 24h using a VIEW# sub-item with TTL.
        Calls increment_view_count only on first view in the window."""
        view_key = {"pk": f"ARTICLE#{article_id}", "sk": f"VIEW#{viewer_id}"}
        ttl = now_ts() + 86400  # 24 hours
        try:
            T.kb_articles.put_item(
                Item={**view_key, "ttl": ttl},
                ConditionExpression="attribute_not_exists(pk)",
            )
            # No existing dedup row — first view
            self.increment_view_count(article_id)
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                pass  # already viewed in last 24h
            else:
                logger.debug("KB record_view error: %s", exc)
        except Exception as exc:
            logger.debug("KB record_view error: %s", exc)

    # ── Attachments (KB-003) ──────────────────────────────────────────────────

    def add_attachment(
        self,
        article_id: str,
        admin_sub: str,
        *,
        filename: str,
        content_type: str,
        content: bytes,
    ) -> dict:
        self.get_article(article_id)  # 404 guard
        att_id = "att_" + uuid.uuid4().hex
        safe_name = _safe_filename(filename)
        s3_key = f"{S.kb_attachments_s3_prefix}{article_id}/{att_id}/{safe_name}"
        size_bytes = len(content)
        if size_bytes > S.kb_attachment_max_bytes:
            raise HTTPException(413, detail="Attachment exceeds maximum size")

        from app.core.aws_clients import s3_client
        s3_client().put_object(
            Bucket=S.kb_attachments_bucket,
            Key=s3_key,
            Body=content,
            ContentType=content_type,
        )
        ts = now_ts()
        item = {
            "pk": f"ARTICLE#{article_id}",
            "sk": f"ATTACHMENT#{att_id}",
            "attachment_id": att_id,
            "article_id": article_id,
            "filename": safe_name,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "s3_key": s3_key,
            "uploaded_by": admin_sub,
            "created_at": ts,
        }
        T.kb_articles.put_item(Item=item)
        _audit("kb.article.attachment_added", admin_sub, article_id=article_id, attachment_id=att_id)
        return {**item, "url": _attachment_url(s3_key)}

    def list_attachments(self, article_id: str) -> List[dict]:
        resp = T.kb_articles.query(
            KeyConditionExpression=Key("pk").eq(f"ARTICLE#{article_id}") & Key("sk").begins_with("ATTACHMENT#"),
        )
        items = [
            {**i, "url": _attachment_url(i.get("s3_key", ""))}
            for i in resp.get("Items", [])
            if not i.get("deleted_at")
        ]
        return items

    def delete_attachment(self, article_id: str, att_id: str, admin_sub: str) -> None:
        att_key = {"pk": f"ARTICLE#{article_id}", "sk": f"ATTACHMENT#{att_id}"}
        resp = T.kb_articles.get_item(Key=att_key)
        if not resp.get("Item"):
            raise HTTPException(404, detail="Attachment not found")
        T.kb_articles.update_item(
            Key=att_key,
            UpdateExpression="SET deleted_at = :ts",
            ExpressionAttributeValues={":ts": now_ts()},
        )
        _audit("kb.article.attachment_deleted", admin_sub, article_id=article_id, attachment_id=att_id)

    # ── Categories (KB-004) ───────────────────────────────────────────────────

    def create_category(
        self,
        admin_sub: str,
        *,
        name: str,
        parent_id: Optional[str] = None,
        description: str = "",
        sort_order: int = 0,
    ) -> dict:
        cat_id = "cat_" + uuid.uuid4().hex
        ts = now_ts()
        path = self._compute_path(name, parent_id)
        item = {
            "pk": f"CATEGORY#{cat_id}",
            "sk": "META",
            "category_id": cat_id,
            "name": name,
            "parent_id": parent_id,
            "path": path,
            "description": description,
            "sort_order": sort_order,
            "created_at": ts,
            "updated_at": ts,
        }
        T.kb_articles.put_item(Item=item)
        _audit("kb.category.created", admin_sub, category_id=cat_id, name=name)
        return item

    def get_category(self, category_id: str) -> dict:
        resp = T.kb_articles.get_item(Key={"pk": f"CATEGORY#{category_id}", "sk": "META"})
        item = resp.get("Item")
        if not item:
            raise HTTPException(404, detail=f"Category '{category_id}' not found")
        return item

    def update_category(
        self,
        category_id: str,
        admin_sub: str,
        *,
        name: Optional[str] = None,
        parent_id: Optional[str] = None,
        description: Optional[str] = None,
        sort_order: Optional[int] = None,
    ) -> dict:
        existing = self.get_category(category_id)
        ts = now_ts()
        set_parts = ["updated_at = :ts"]
        values: Dict[str, Any] = {":ts": ts}
        names: Dict[str, str] = {}
        if name is not None:
            set_parts.append("#name = :name")
            names["#name"] = "name"
            values[":name"] = name
        if parent_id is not None:
            set_parts.append("parent_id = :pid")
            values[":pid"] = parent_id
        if description is not None:
            set_parts.append("description = :desc")
            values[":desc"] = description
        if sort_order is not None:
            set_parts.append("sort_order = :order")
            values[":order"] = sort_order
        # recompute path
        new_name = name or existing.get("name", "")
        new_parent = parent_id if parent_id is not None else existing.get("parent_id")
        new_path = self._compute_path(new_name, new_parent)
        set_parts.append("#path = :path")
        names["#path"] = "path"
        values[":path"] = new_path

        kwargs: Dict[str, Any] = {
            "Key": {"pk": f"CATEGORY#{category_id}", "sk": "META"},
            "UpdateExpression": "SET " + ", ".join(set_parts),
            "ExpressionAttributeValues": values,
        }
        if names:
            kwargs["ExpressionAttributeNames"] = names
        T.kb_articles.update_item(**kwargs)
        _audit("kb.category.updated", admin_sub, category_id=category_id)
        return self.get_category(category_id)

    def delete_category(self, category_id: str, admin_sub: str) -> None:
        self.get_category(category_id)
        T.kb_articles.delete_item(Key={"pk": f"CATEGORY#{category_id}", "sk": "META"})
        _audit("kb.category.deleted", admin_sub, category_id=category_id)

    def list_categories(self) -> List[dict]:
        """Return all CATEGORY# META items. Small dataset — scan is fine."""
        items: List[dict] = []
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "FilterExpression": Attr("pk").begins_with("CATEGORY#") & Attr("sk").eq("META"),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.kb_articles.scan(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return sorted(items, key=lambda c: (c.get("sort_order", 0), c.get("name", "")))

    def _compute_path(self, name: str, parent_id: Optional[str]) -> str:
        if not parent_id:
            return name
        try:
            parent = self.get_category(parent_id)
            parent_path = parent.get("path", parent.get("name", ""))
            return f"{parent_path} > {name}"
        except Exception:
            return name

    # ── Tag index (KB-007 stub — write side) ─────────────────────────────────

    def set_article_tags(self, article_id: str, tags: List[str], admin_sub: str) -> None:
        """Write TAG#{tag}/ARTICLE#{id} index rows and update KB_TAG_STATS."""
        ts = now_ts()
        # Remove old tag rows first
        self._delete_article_tag_index(article_id)
        for tag in tags:
            T.kb_articles.put_item(Item={
                "pk": f"TAG#{tag}",
                "sk": f"ARTICLE#{article_id}",
                "article_id": article_id,
                "tag": tag,
                "created_at": ts,
            })
            # Update tag stats (ADD 1 to count; ignore if already exists)
            try:
                T.kb_articles.update_item(
                    Key={"pk": "KB_TAG_STATS", "sk": f"TAG#{tag}"},
                    UpdateExpression="ADD article_count :one SET #tag = :tag",
                    ExpressionAttributeNames={"#tag": "tag"},
                    ExpressionAttributeValues={":one": 1, ":tag": tag},
                )
            except Exception:
                pass

    def _delete_article_tag_index(self, article_id: str) -> None:
        """Remove all TAG# index rows for this article_id."""
        # Scan TAG# rows that reference this article
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "FilterExpression": Attr("sk").eq(f"ARTICLE#{article_id}") & Attr("pk").begins_with("TAG#"),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.kb_articles.scan(**kwargs)
            for item in resp.get("Items", []):
                T.kb_articles.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                # Decrement stats
                try:
                    T.kb_articles.update_item(
                        Key={"pk": "KB_TAG_STATS", "sk": item["sk"].replace("ARTICLE#", "TAG#")},
                        UpdateExpression="ADD article_count :neg",
                        ExpressionAttributeValues={":neg": -1},
                    )
                except Exception:
                    pass
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    def list_articles_by_tag(self, tag: str, limit: int = 20, cursor: Optional[str] = None) -> Tuple[List[dict], Optional[str]]:
        from app.core.cursor import decode_cursor, encode_cursor
        last_key = None
        if cursor:
            try:
                last_key = decode_cursor(cursor)
            except Exception:
                last_key = None
        kwargs: Dict[str, Any] = {
            "IndexName": "ByTag",
            "KeyConditionExpression": Key("tag").eq(tag),
            "Limit": limit,
            "ScanIndexForward": False,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.kb_articles.query(**kwargs)
        tag_rows = resp.get("Items", [])
        # Resolve full article META for each tag row
        articles: List[dict] = []
        for row in tag_rows:
            article_id = row.get("article_id")
            if not article_id:
                continue
            try:
                art = self.get_article(article_id, published_only=True)
                articles.append(art)
            except Exception:
                pass
        next_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(next_key) if next_key else None
        return articles, next_cursor

    def list_popular_tags(self, limit: int = 50) -> List[dict]:
        """Return tags ordered by article_count descending."""
        last_key = None
        items: List[dict] = []
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq("KB_TAG_STATS"),
                "Limit": 200,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.kb_articles.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        items.sort(key=lambda x: int(x.get("article_count", 0)), reverse=True)
        return items[:limit]

    # ── Full-text search (KB-009 stub) ────────────────────────────────────────

    def search_articles(self, q: str, limit: int = 20, cursor: Optional[str] = None) -> Tuple[List[dict], Optional[str]]:
        """Simple prefix search on title/excerpt. Returns published articles only."""
        from app.core.cursor import decode_cursor, encode_cursor
        q_lower = q.lower().strip()
        if not q_lower:
            return [], None
        last_key = None
        if cursor:
            try:
                last_key = decode_cursor(cursor)
            except Exception:
                pass
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": Key("status").eq("published"),
            "FilterExpression": Attr("title").contains(q_lower) | Attr("excerpt").contains(q_lower) | Attr("body_html").contains(q_lower),
            "Limit": max(limit * 5, 50),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.kb_articles.query(**kwargs)
        items = resp.get("Items", [])[:limit]
        next_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(next_key) if next_key else None
        return items, next_cursor


# ─── Private helpers ──────────────────────────────────────────────────────────


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub, **fields)
    except Exception:
        logger.debug("kb audit_event failed: %s", event)


def _attachment_url(s3_key: str) -> str:
    if not s3_key:
        return ""
    if S.dev_mode:
        return f"/mock/s3/{S.kb_attachments_bucket}/{s3_key}"
    try:
        from app.core.aws_clients import s3_client
        return s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": S.kb_attachments_bucket, "Key": s3_key},
            ExpiresIn=300,
        )
    except Exception:
        return ""


# ─── Background expiry checker (KB-002) ──────────────────────────────────────


def _run_kb_expiry_check_once() -> int:
    """Query published articles with expires_at <= now; expire each. Returns count."""
    ts = now_ts()
    svc = KbArticleService()
    expired_count = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": Key("status").eq("published"),
            "FilterExpression": Attr("expires_at").lte(ts) & Attr("expires_at").exists(),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.kb_articles.query(**kwargs)
        for item in resp.get("Items", []):
            try:
                svc.expire_article(item.get("article_id", ""), "system_kb_expiry", reason="auto_expiry")
                expired_count += 1
            except KbArticleStateError:
                pass
            except Exception:
                logger.exception("KB expiry: failed to expire article %s", item.get("article_id"))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    if expired_count:
        logger.info("KB expiry checker: expired %d article(s)", expired_count)
    return expired_count


async def run_kb_expiry_checker_loop() -> None:
    if not S.knowledge_base_enabled:
        logger.info("KB expiry checker disabled (flag off)")
        return
    interval = max(60, S.kb_expiry_checker_interval_seconds)
    logger.info("KB expiry checker started (interval=%ds)", interval)
    while True:
        try:
            _run_kb_expiry_check_once()
        except Exception:
            logger.exception("KB expiry checker error")
        await asyncio.sleep(interval)


def start_kb_expiry_checker_task() -> None:
    if not S.knowledge_base_enabled:
        return
    try:
        asyncio.get_event_loop().create_task(run_kb_expiry_checker_loop())
    except RuntimeError:
        asyncio.ensure_future(run_kb_expiry_checker_loop())
