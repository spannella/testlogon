from __future__ import annotations

import asyncio
import json
import logging
import re
from html import escape
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional, Set, Tuple

from urllib.parse import quote, urlparse

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field, model_validator
from starlette.responses import StreamingResponse

from app.core.aws import ddb
from app.core.aws_clients import s3_client, sqs_client
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.services.filemanager import download_file, get_node, get_usage_summary, norm_path
from app.services.sessions import require_ui_session
from app.services.subscription_access import can_access_creator
from app.services.usage_metering import (
    build_usage_event,
    build_usage_source_idempotency_key,
    record_usage_event_and_aggregates,
)

# -----------------------------
# Config
# -----------------------------
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
AWS_REGION = S.aws_region or os.environ.get("AWS_REGION", "us-east-1")
UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET")
EVENTS_SQS_URL = os.environ.get("EVENTS_SQS_URL")

tbl = ddb.Table(APP_TABLE)

s3 = s3_client() if UPLOAD_BUCKET else None
sqs = sqs_client() if EVENTS_SQS_URL else None

router = APIRouter(tags=["newsfeed"])
logger = logging.getLogger(__name__)


def _emit_newsfeed_content_metric(event: str, **fields: Any) -> None:
    logger.info("newsfeed content metric", extra={"event": event, **fields})


def _emit_newsfeed_content_reject(reason_code: str, *, source: str, body_format: Optional[str] = None) -> None:
    logger.warning(
        "newsfeed content reject",
        extra={"event": "newsfeed_content_reject", "source": source, "reason_code": reason_code, "body_format": body_format or "unknown"},
    )



# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def decode_cursor_or_400(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    decoded = decode_cursor(cursor)
    if decoded is None:
        raise HTTPException(status_code=400, detail="Invalid cursor")
    return decoded


async def _get_user_id(ctx: Dict[str, str] = Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


UserIdDep = Annotated[str, Depends(_get_user_id)]


def ensure_uploads_enabled() -> None:
    if not UPLOAD_BUCKET or not s3:
        raise HTTPException(status_code=500, detail="UPLOAD_BUCKET not configured")


def _newsfeed_post_quota_error(*, period_id: str, limit_count: int, used_count: int) -> HTTPException:
    remaining_count = max(0, int(limit_count) - int(used_count))
    return HTTPException(
        status_code=403,
        detail={
            "code": "newsfeed_post_quota_exceeded",
            "message": "newsfeed post quota exceeded",
            "quota_type": "newsfeed_post",
            "period_id": period_id,
            "limit_count": int(limit_count),
            "used_count": int(used_count),
            "remaining_count": remaining_count,
        },
    )


def _parse_newsfeed_post_warning_thresholds() -> List[int]:
    raw = str(getattr(S, "newsfeed_post_quota_warning_thresholds", "80,95") or "80,95").strip()
    out: List[int] = []
    for token in raw.split(','):
        t = token.strip()
        if not t:
            continue
        try:
            value = int(t)
        except ValueError:
            continue
        if 1 <= value <= 100 and value not in out:
            out.append(value)
    out.sort()
    return out or [80, 95]


def _emit_newsfeed_post_quota_warning(
    *,
    threshold_percent: int,
    user_id: str,
    period_id: str,
    limit_count: int,
    projected_count: int,
) -> None:
    logger.warning(
        "newsfeed post quota warning threshold crossed",
        extra={
            "user_id": user_id,
            "period_id": period_id,
            "threshold_percent": threshold_percent,
            "limit_count": int(limit_count),
            "projected_count": int(projected_count),
        },
    )


def _enforce_newsfeed_post_quota_precheck(*, user_id: str) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        usage = get_usage_summary(user_id)
    except Exception:
        logger.exception("failed to load usage summary for newsfeed post quota pre-check", extra={"user_id": user_id})
        return

    post_usage = usage.get("post_publish") or {}
    used_count = int(post_usage.get("used_count") or 0)
    limit_count = int(post_usage.get("limit_count") or 0)
    period_id = str(usage.get("period_id") or "")

    if limit_count > 0 and used_count >= limit_count:
        overage_mode = str(getattr(S, "newsfeed_post_quota_overage_mode", "block") or "block").strip().lower()
        if overage_mode != "allow":
            raise _newsfeed_post_quota_error(period_id=period_id, limit_count=limit_count, used_count=used_count)

    if not bool(getattr(S, "newsfeed_post_quota_soft_warnings_enabled", False)):
        return
    if limit_count <= 0:
        return

    projected_count = used_count + 1
    for threshold in _parse_newsfeed_post_warning_thresholds():
        trigger_at = max(1, int((limit_count * threshold + 99) // 100))
        if used_count < trigger_at <= projected_count:
            _emit_newsfeed_post_quota_warning(
                threshold_percent=threshold,
                user_id=user_id,
                period_id=period_id,
                limit_count=limit_count,
                projected_count=projected_count,
            )


def ddb_put_item(item: Dict[str, Any]) -> None:
    try:
        tbl.put_item(Item=item)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_update_item(
    *,
    key: Dict[str, Any],
    update_expr: str,
    expr_vals: Dict[str, Any],
    expr_names: Optional[Dict[str, str]] = None,
    condition_expr: Optional[str] = None,
    return_values: str = "ALL_NEW",
) -> Dict[str, Any]:
    try:
        kwargs = dict(
            Key=key,
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
            ReturnValues=return_values,
        )
        if expr_names:
            kwargs["ExpressionAttributeNames"] = expr_names
        if condition_expr:
            kwargs["ConditionExpression"] = condition_expr
        resp = tbl.update_item(**kwargs)
        return resp.get("Attributes", {})
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict / conditional check failed") from exc
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_get_item(key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        resp = tbl.get_item(Key=key)
        return resp.get("Item")
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_query(**kwargs) -> Dict[str, Any]:
    # Strip None-valued kwargs so DynamoDB doesn't choke on e.g. ExclusiveStartKey=None
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    try:
        return tbl.query(**kwargs)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def _meter_newsfeed_post_publish(*, user_id: str, post_id: str) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        idempotency_key = build_usage_source_idempotency_key(
            "newsfeed_post",
            user_id=user_id,
            post_id=post_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="upload",
            bytes_count=0,
            source="newsfeed_post",
            resource_path=f"/newsfeed/posts/{post_id}",
            idempotency_key=idempotency_key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception("newsfeed post publish usage metering failed", extra={"user_id": user_id, "post_id": post_id})


def _record_newsfeed_attachment_download(
    *,
    user_id: str,
    post_id: str,
    attachment_key: str,
    bytes_count: int,
    idempotency_operation_id: Optional[str] = None,
) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name or bytes_count <= 0:
        return
    try:
        idempotency_key = build_usage_source_idempotency_key(
            "newsfeed_attachment_download",
            user_id=user_id,
            attachment_key=attachment_key,
            operation_id=idempotency_operation_id or post_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="download",
            bytes_count=bytes_count,
            source="newsfeed_attachment_download",
            resource_path=f"/newsfeed/posts/{post_id}/attachments/{attachment_key}",
            idempotency_key=idempotency_key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception(
            "newsfeed attachment download usage metering failed",
            extra={"user_id": user_id, "post_id": post_id, "attachment_key": attachment_key, "bytes_count": bytes_count},
        )


# -----------------------------
# DynamoDB Key builders
# -----------------------------
def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"


def pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


def sk_post() -> str:
    return "META"


def pk_post_comments(post_id: str) -> str:
    return f"POST#{post_id}#COMMENTS"


def pk_notif(user_id: str) -> str:
    return f"NOTIF#{user_id}"


def pk_hide(user_id: str) -> str:
    return f"HIDE#{user_id}"


def pk_unlock(user_id: str) -> str:
    return f"UNLOCK#{user_id}"


def pk_like(user_id: str) -> str:
    return f"LIKE#{user_id}"


# -----------------------------
# Payment Provider (stub)
# -----------------------------
class PaymentProvider:
    """
    Replace with Stripe/CCBill/etc. This stub pretends payments succeed.
    """

    def create_payment_intent(
        self,
        *,
        user_id: str,
        amount_cents: int,
        currency: str,
        metadata: Dict[str, str],
    ) -> Dict[str, Any]:
        intent_id = new_id("pi")
        return {
            "provider": "stub",
            "payment_intent_id": intent_id,
            "client_secret": f"stub_secret_{intent_id}",
            "status": "requires_confirmation",
            "amount_cents": amount_cents,
            "currency": currency,
            "metadata": metadata,
        }

    def confirm_payment_intent(self, *, payment_intent_id: str) -> Dict[str, Any]:
        return {"payment_intent_id": payment_intent_id, "status": "succeeded"}


payments = PaymentProvider()


# -----------------------------
# Models
# -----------------------------
class Attachment(BaseModel):
    attachment_id: str
    filename: str
    content_type: str
    size_bytes: Optional[int] = None
    s3_key: str
    url: Optional[str] = None


BodyFormat = Literal["plain", "markdown", "rich"]

ALLOWED_MARKDOWN_HTML_TAGS: Set[str] = {"p", "br", "strong", "em", "code", "pre", "blockquote", "ul", "ol", "li", "a"}
ALLOWED_MARKDOWN_HTML_ATTRS: Dict[str, Set[str]] = {"a": {"href", "rel", "target"}}
ALLOWED_MARKDOWN_URL_PROTOCOLS: Set[str] = {"https", "mailto"}

ALLOWED_RICH_NODE_TYPES: Set[str] = {
    "doc", "paragraph", "text", "heading", "blockquote", "bulletList", "orderedList", "listItem", "codeBlock", "hardBreak",
}
ALLOWED_RICH_MARK_TYPES: Set[str] = {"bold", "italic", "code", "link"}
ALLOWED_RICH_NODE_ATTRS: Dict[str, Set[str]] = {
    "heading": {"level"},
}
ALLOWED_RICH_MARK_ATTRS: Dict[str, Set[str]] = {
    "link": {"href", "title", "target", "rel"},
}


def _is_safe_rich_link_url(url: str) -> bool:
    return _is_safe_markdown_url(url)


def _raise_rich_schema_error(reason_code: str, message: str) -> None:
    logger.warning("newsfeed rich schema validation failed", extra={"reason_code": reason_code, "detail": message})
    raise ValueError(f"invalid_content_schema:{reason_code}: {message}")


def _validate_rich_node_or_error(node: Any, *, path: str = "doc") -> int:
    if not isinstance(node, dict):
        _raise_rich_schema_error("node_not_object", f"{path} must be a JSON object")

    node_type = node.get("type")
    if not isinstance(node_type, str):
        _raise_rich_schema_error("node_missing_type", f"{path}.type must be a string")
    if node_type not in ALLOWED_RICH_NODE_TYPES:
        _raise_rich_schema_error("unsupported_node_type", f"{path}.type '{node_type}' is not allowed")
    if node_type in {"html", "raw", "rawHtml", "script"}:
        _raise_rich_schema_error("raw_html_not_allowed", f"{path}.type '{node_type}' is not allowed")

    attrs = node.get("attrs")
    if attrs is not None:
        if not isinstance(attrs, dict):
            _raise_rich_schema_error("invalid_node_attrs", f"{path}.attrs must be an object")
        allowed_attrs = ALLOWED_RICH_NODE_ATTRS.get(node_type, set())
        extra_attrs = set(attrs.keys()) - allowed_attrs
        if extra_attrs:
            _raise_rich_schema_error("unsupported_node_attr", f"{path}.attrs contains unsupported keys: {sorted(extra_attrs)}")

    if node_type == "text":
        if not isinstance(node.get("text"), str):
            _raise_rich_schema_error("invalid_text_node", f"{path}.text must be a string")

    marks = node.get("marks")
    if marks is not None:
        if not isinstance(marks, list):
            _raise_rich_schema_error("invalid_marks", f"{path}.marks must be an array")
        for i, mark in enumerate(marks):
            mark_path = f"{path}.marks[{i}]"
            if not isinstance(mark, dict):
                _raise_rich_schema_error("mark_not_object", f"{mark_path} must be an object")
            mark_type = mark.get("type")
            if mark_type not in ALLOWED_RICH_MARK_TYPES:
                _raise_rich_schema_error("unsupported_mark_type", f"{mark_path}.type '{mark_type}' is not allowed")
            mark_attrs = mark.get("attrs")
            if mark_attrs is not None:
                if not isinstance(mark_attrs, dict):
                    _raise_rich_schema_error("invalid_mark_attrs", f"{mark_path}.attrs must be an object")
                allowed_mark_attrs = ALLOWED_RICH_MARK_ATTRS.get(mark_type, set())
                extra_mark_attrs = set(mark_attrs.keys()) - allowed_mark_attrs
                if extra_mark_attrs:
                    _raise_rich_schema_error("unsupported_mark_attr", f"{mark_path}.attrs contains unsupported keys: {sorted(extra_mark_attrs)}")
                if mark_type == "link" and "href" in mark_attrs and not _is_safe_rich_link_url(str(mark_attrs.get("href") or "")):
                    _raise_rich_schema_error("unsafe_link_protocol", f"{mark_path}.attrs.href uses a blocked protocol")

    children = node.get("content")
    count = 1
    if children is not None:
        if not isinstance(children, list):
            _raise_rich_schema_error("invalid_content_children", f"{path}.content must be an array")
        for idx, child in enumerate(children):
            count += _validate_rich_node_or_error(child, path=f"{path}.content[{idx}]")
    return count


def _is_safe_markdown_url(url: str) -> bool:
    candidate = (url or "").strip()
    if not candidate or any(ch in candidate for ch in ['"', "'", " ", "\n", "\r", "\t"]):
        return False
    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if not (scheme and scheme in ALLOWED_MARKDOWN_URL_PROTOCOLS):
        return False
    if scheme == "https" and not parsed.netloc:
        return False
    if scheme == "mailto" and not parsed.path:
        return False
    return True


def _sanitize_markdown_inline(text: str) -> str:
    safe = escape(text or "")
    safe = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", safe)
    safe = re.sub(r"\*\*([^*]+)\*\*", lambda m: f"<strong>{m.group(1)}</strong>", safe)
    safe = re.sub(r"\*([^*]+)\*", lambda m: f"<em>{m.group(1)}</em>", safe)

    def _link_sub(match: re.Match[str]) -> str:
        label = match.group(1)
        href = match.group(2).strip()
        if not _is_safe_markdown_url(href):
            _emit_newsfeed_content_reject("unsafe_link_protocol", source="markdown_sanitizer", body_format="markdown")
            return label
        return f'<a href="{escape(href, quote=True)}" rel="nofollow noopener noreferrer" target="_blank">{label}</a>'

    safe = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link_sub, safe)
    return safe


def render_markdown_sanitized_html(markdown_text: str) -> str:
    text = (markdown_text or "").strip()
    if not text:
        return ""

    lines = text.splitlines()
    html_parts: List[str] = []
    in_ul = False
    in_ol = False

    def _close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            html_parts.append("</ul>")
            in_ul = False
        if in_ol:
            html_parts.append("</ol>")
            in_ol = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            _close_lists()
            continue

        if stripped.startswith("- "):
            if in_ol:
                html_parts.append("</ol>")
                in_ol = False
            if not in_ul:
                html_parts.append("<ul>")
                in_ul = True
            html_parts.append(f"<li>{_sanitize_markdown_inline(stripped[2:].strip())}</li>")
            continue

        if re.match(r"^\d+\.\s+", stripped):
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False
            if not in_ol:
                html_parts.append("<ol>")
                in_ol = True
            item_text = re.sub(r"^\d+\.\s+", "", stripped, count=1)
            html_parts.append(f"<li>{_sanitize_markdown_inline(item_text)}</li>")
            continue

        _close_lists()
        if stripped.startswith(">"):
            html_parts.append(f"<blockquote>{_sanitize_markdown_inline(stripped[1:].strip())}</blockquote>")
            continue
        html_parts.append(f"<p>{_sanitize_markdown_inline(stripped)}</p>")

    _close_lists()
    return "".join(html_parts)


def _content_limit_int(name: str, default: int) -> int:
    raw = getattr(S, name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return value if value > 0 else default


def _content_max_plain_chars() -> int:
    return _content_limit_int("newsfeed_content_max_plain_chars", 10000)


def _content_max_markdown_chars() -> int:
    return _content_limit_int("newsfeed_content_max_markdown_chars", 20000)


def _content_max_rich_nodes() -> int:
    return _content_limit_int("newsfeed_content_max_rich_nodes", 500)


def _content_max_rich_depth() -> int:
    return _content_limit_int("newsfeed_content_max_rich_depth", 20)


def _walk_rich_tree_stats(node: Any, *, depth: int = 1) -> tuple[int, int]:
    if not isinstance(node, (dict, list)):
        return (0, depth)
    if isinstance(node, list):
        count = 0
        max_depth = depth
        for child in node:
            c_count, c_depth = _walk_rich_tree_stats(child, depth=depth)
            count += c_count
            max_depth = max(max_depth, c_depth)
        return count, max_depth

    count = 1
    max_depth = depth
    for child in node.get("content") or []:
        c_count, c_depth = _walk_rich_tree_stats(child, depth=depth + 1)
        count += c_count
        max_depth = max(max_depth, c_depth)
    return count, max_depth


def _validate_rich_schema_or_error(doc: Any) -> None:
    if not isinstance(doc, dict):
        _raise_rich_schema_error("root_not_object", "body_rich must be a JSON object")
    if doc.get("type") != "doc":
        _raise_rich_schema_error("root_not_doc", "body_rich.type must be 'doc'")
    content = doc.get("content")
    if not isinstance(content, list):
        _raise_rich_schema_error("root_content_not_array", "body_rich.content must be a JSON array")

    node_count = _validate_rich_node_or_error(doc, path="doc")
    _legacy_node_count, max_depth = _walk_rich_tree_stats(doc)
    max_nodes = _content_max_rich_nodes()
    max_allowed_depth = _content_max_rich_depth()
    if node_count > max_nodes:
        _raise_rich_schema_error("node_limit_exceeded", f"body_rich node count exceeds max ({max_nodes})")
    if max_depth > max_allowed_depth:
        _raise_rich_schema_error("depth_limit_exceeded", f"body_rich depth exceeds max ({max_allowed_depth})")


class ContentFieldsMixin(BaseModel):
    # Legacy compatibility field kept for older clients.
    body: Optional[str] = None
    # Canonical content envelope fields.
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_markdown_html: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: Optional[BodyFormat] = None
    body_version: Optional[int] = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_content_fields(self):
        has_legacy = bool((self.body or "").strip())
        has_plain = bool((self.body_plain or "").strip())
        has_markdown = bool((self.body_markdown or "").strip())
        has_rich = bool(self.body_rich)

        if not (has_legacy or has_plain or has_markdown or has_rich):
            raise ValueError("invalid_content_payload: one of body/body_plain/body_markdown/body_rich is required")

        chosen_format = self.body_format or (
            "rich" if has_rich else "markdown" if has_markdown else "plain"
        )
        if chosen_format == "rich" and not has_rich:
            raise ValueError("invalid_content_payload: body_rich is required when body_format is rich")
        if chosen_format == "markdown" and not has_markdown:
            raise ValueError("invalid_content_payload: body_markdown is required when body_format is markdown")

        if chosen_format == "markdown" and not bool(getattr(S, "newsfeed_markdown_enabled", False)):
            _emit_newsfeed_content_reject("markdown_feature_disabled", source="validator", body_format="markdown")
            raise ValueError("feature_disabled: markdown format is disabled")
        if chosen_format == "rich" and not bool(getattr(S, "newsfeed_richtext_enabled", False)):
            _emit_newsfeed_content_reject("rich_feature_disabled", source="validator", body_format="rich")
            raise ValueError("feature_disabled: rich format is disabled")

        if chosen_format == "rich" and not (has_plain or has_legacy):
            raise ValueError("invalid_content_payload: body_plain (or legacy body) is required when body_rich is provided")

        plain_text = (self.body_plain or self.body or "").strip()
        markdown_text = (self.body_markdown or "").strip()
        if plain_text and len(plain_text) > _content_max_plain_chars():
            raise ValueError(
                f"invalid_content_payload: body_plain/body exceeds max length ({_content_max_plain_chars()})"
            )
        if markdown_text and len(markdown_text) > _content_max_markdown_chars():
            raise ValueError(
                f"invalid_content_payload: body_markdown exceeds max length ({_content_max_markdown_chars()})"
            )
        if has_rich:
            _validate_rich_schema_or_error(self.body_rich)
        return self


def _content_from_payload(req: ContentFieldsMixin) -> Dict[str, Any]:
    body_plain = (req.body_plain or req.body or "").strip()
    body_markdown = (req.body_markdown or "").strip() or None
    body_rich = req.body_rich or None
    body_format: BodyFormat = req.body_format or (
        "rich" if body_rich else "markdown" if body_markdown else "plain"
    )
    if body_format == "markdown" and not body_plain:
        body_plain = body_markdown or ""
    body_markdown_html = render_markdown_sanitized_html(body_markdown or "") if body_markdown else None
    return {
        "body": body_plain,
        "body_plain": body_plain,
        "body_markdown": body_markdown,
        "body_markdown_html": body_markdown_html,
        "body_rich": body_rich,
        "body_format": body_format,
        "body_version": int(req.body_version or 1),
    }


class CreatePostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    visibility: Literal["followers", "public"] = "followers"
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    file_paths: List[str] = Field(default_factory=list)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"body": "Legacy plain text post", "visibility": "followers"},
                {
                    "body_plain": "Hello world",
                    "body_markdown": "# Hello world",
                    "body_format": "markdown",
                    "body_version": 1,
                },
                {
                    "body_plain": "Hello rich world",
                    "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Hello rich world"}]}]},
                    "body_format": "rich",
                    "body_version": 1,
                },
            ]
        }
    }


class PostResponse(BaseModel):
    post_id: str
    author_id: str
    created_at: str
    body: str
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_markdown_html: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: BodyFormat = "plain"
    body_version: int = 1
    image_urls: List[str] = Field(default_factory=list)
    visibility: str
    locked: bool
    unlock_price_cents: Optional[int] = None
    like_count: int = 0
    comment_count: int = 0


class CreateCommentRequest(ContentFieldsMixin):
    parent_comment_id: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"body": "Legacy plain comment"},
                {"body_plain": "Item one", "body_markdown": "- Item one", "body_format": "markdown"},
                {
                    "body_plain": "Rich comment",
                    "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Rich comment"}]}]},
                    "body_format": "rich",
                },
            ]
        }
    }


class EditCommentRequest(ContentFieldsMixin):
    expected_version: int = Field(default=1, ge=1)


class CommentResponse(BaseModel):
    comment_id: str
    post_id: str
    author_id: str
    created_at: str
    updated_at: Optional[str] = None
    deleted: bool = False
    parent_comment_id: Optional[str] = None
    body: Optional[str] = None
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_markdown_html: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: BodyFormat = "plain"
    body_version: int = 1
    version: int = 1
    tip_total_cents: int = 0


class TipRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"


class UnfollowRequest(BaseModel):
    target_user_id: str


class HidePostRequest(BaseModel):
    post_id: str


class EditPostRequest(ContentFieldsMixin):
    image_urls: Optional[List[str]] = None


class PresignUploadRequest(BaseModel):
    filename: str
    content_type: str
    size_bytes: Optional[int] = None


class PresignUploadResponse(BaseModel):
    attachment: Attachment
    put_url: str
    put_headers: Dict[str, str] = Field(default_factory=dict)


class UnlockPostRequest(BaseModel):
    post_id: str
    payment_method_id: Optional[str] = None


class UnlockPostResponse(BaseModel):
    post_id: str
    payment_intent: Dict[str, Any]


class PostTipRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    payment_method_id: Optional[str] = None


class ReactionRequest(BaseModel):
    emoji: str = Field(..., min_length=1, max_length=10)

class ContentRenderTelemetryRequest(BaseModel):
    reason: Literal["unsupported_format", "render_exception"]
    body_format: Optional[str] = None
    surface: Literal["post", "comment", "unknown"] = "unknown"


# -----------------------------
# Post serialization helper
# -----------------------------
def _rich_doc_to_plain_text(doc: Any) -> str:
    """Best-effort plain text extraction for legacy fallback rendering."""
    parts: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            text = node.get("text")
            if isinstance(text, str) and text:
                parts.append(text)
            for child in node.get("content") or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(doc)
    return " ".join(part.strip() for part in parts if part and part.strip()).strip()


def _coerce_body_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _resolve_read_body_fields(item: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str], Optional[str], Optional[Dict[str, Any]], BodyFormat, int]:
    """Resolve legacy/new content fields for response serialization with rollout-safe fallbacks."""
    legacy_body = _coerce_body_text(item.get("body"))
    body_plain = _coerce_body_text(item.get("body_plain"))
    body_markdown = _coerce_body_text(item.get("body_markdown"))
    body_rich = item.get("body_rich") if isinstance(item.get("body_rich"), dict) else None
    rich_plain = _rich_doc_to_plain_text(body_rich) if body_rich else None

    resolved_plain = body_plain or legacy_body or body_markdown or rich_plain or ""
    resolved_body = resolved_plain

    body_markdown_html = item.get("body_markdown_html")
    if not isinstance(body_markdown_html, str) or not body_markdown_html.strip():
        body_markdown_html = render_markdown_sanitized_html(body_markdown or "") if body_markdown else None

    raw_body_format = item.get("body_format")
    if raw_body_format in {"plain", "markdown", "rich"}:
        body_format: BodyFormat = raw_body_format
    elif body_rich:
        body_format = "rich"
    elif body_markdown:
        body_format = "markdown"
    else:
        body_format = "plain"

    markdown_enabled = bool(getattr(S, "newsfeed_markdown_enabled", False))
    rich_enabled = bool(getattr(S, "newsfeed_richtext_enabled", False))

    if body_format == "rich" and not rich_enabled:
        body_format = "plain"
        body_rich = None
        body_markdown = None
        body_markdown_html = None
    elif body_format == "markdown" and not markdown_enabled:
        body_format = "plain"
        body_markdown = None
        body_markdown_html = None

    body_version = int(item.get("body_version") or 1)
    return resolved_body, resolved_plain or None, body_markdown, body_markdown_html, body_rich, body_format, body_version


def _reaction_summaries(reactions_map: Dict, viewer_id: Optional[str] = None):
    """Compute per-emoji counts and the viewer's own reactions from a DDB reactions map."""
    counts: Dict[str, int] = {}
    mine: List[str] = []
    for emoji, users in (reactions_map or {}).items():
        if isinstance(users, dict) and users:
            counts[emoji] = len(users)
            if viewer_id and users.get(viewer_id):
                mine.append(emoji)
    return counts, mine


def _post_to_dict(post: Dict[str, Any], locked_body: bool = False, liked_by_me: bool = False, unlocked: bool = False, viewer_id: Optional[str] = None) -> Dict[str, Any]:
    """Map a raw DDB post item to the FeedPost shape expected by the frontend."""
    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, body_version = _resolve_read_body_fields(post)

    # Support both old image_url (str) and new image_urls (list)
    image_urls = list(post.get("image_urls") or [])
    if not image_urls and post.get("image_url"):
        image_urls = [post["image_url"]]
    if locked_body:
        body = "[Locked content]"
        image_urls = []
        body_plain = body
        body_markdown = None
        body_markdown_html = None
        body_rich = None
        body_format = "plain"
        body_version = 1
    reactions_map = post.get("reactions") or {}
    reactions_counts, my_reactions = _reaction_summaries(reactions_map, viewer_id)
    post_id = post["post_id"]
    raw_attachments = [] if locked_body else (post.get("file_attachments") or [])
    file_attachments = [
        {
            "name": fa.get("name"),
            "content_type": fa.get("content_type"),
            "size": int(fa["size"]) if fa.get("size") is not None else None,
            "url": f"/api/posts/{post_id}/files/{i}",
        }
        for i, fa in enumerate(raw_attachments)
    ]
    return {
        "post_id": post_id,
        "author_id": post.get("user_id", ""),
        "created_at": post.get("created_at", ""),
        "updated_at": post.get("updated_at"),
        "body": body,
        "body_plain": body_plain,
        "body_markdown": body_markdown,
        "body_markdown_html": body_markdown_html,
        "body_rich": body_rich,
        "body_format": body_format,
        "body_version": body_version,
        "image_urls": image_urls,
        "file_attachments": file_attachments,
        "visibility": post.get("visibility", "followers"),
        "locked": bool(post.get("locked")),
        "unlock_price_cents": post.get("unlock_price_cents"),
        "unlocked": unlocked,
        "like_count": int(post.get("like_count", 0)),
        "comment_count": int(post.get("comment_count", 0)),
        "tip_total_cents": int(post.get("tip_total_cents", 0)),
        "liked_by_me": liked_by_me,
        "reactions_counts": reactions_counts,
        "my_reactions": my_reactions,
    }


def _comment_to_dict(it: Dict[str, Any]) -> Dict[str, Any]:
    """Map a raw DDB comment item to the FeedComment shape expected by the frontend."""
    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, _body_version = _resolve_read_body_fields(it)
    if it.get("deleted"):
        body = None
        body_plain = None
        body_markdown = None
        body_markdown_html = None
        body_rich = None
        body_format = "plain"
    return {
        "comment_id": it["comment_id"],
        "post_id": it["post_id"],
        "author_id": it.get("user_id", ""),
        "created_at": it.get("created_at", ""),
        "updated_at": it.get("updated_at"),
        "deleted": bool(it.get("deleted")),
        "parent_comment_id": it.get("parent_comment_id"),
        "body": body,
        "body_plain": body_plain,
        "body_markdown": body_markdown,
        "body_markdown_html": body_markdown_html,
        "body_rich": body_rich,
        "body_format": body_format,
        "body_version": _body_version,
        "version": int(it.get("version", 1)),
        "tip_total_cents": int(it.get("tip_total_cents", 0)),
    }


# -----------------------------
# SSE Hub (in-memory per instance)
# -----------------------------
class SSEHub:
    """
    Per-instance connection registry. Distributed delivery is achieved via SNS->SQS,
    where each instance receives events from SQS and then dispatches locally.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._conns: Dict[str, Set[asyncio.Queue]] = {}

    async def add(self, user_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        async with self._lock:
            self._conns.setdefault(user_id, set()).add(q)
        return q

    async def remove(self, user_id: str, q: asyncio.Queue) -> None:
        async with self._lock:
            conns = self._conns.get(user_id)
            if not conns:
                return
            conns.discard(q)
            if not conns:
                self._conns.pop(user_id, None)

    async def publish(self, user_id: str, event: Dict[str, Any]) -> int:
        async with self._lock:
            qs = list(self._conns.get(user_id, set()))
        delivered = 0
        for q in qs:
            try:
                q.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                pass
        return delivered


sse_hub = SSEHub()


def sse_format(event: Dict[str, Any]) -> str:
    data = json.dumps(event, separators=(",", ":"))
    return f"data: {data}\n\n"


async def sse_event_stream(request: Request, user_id: str, q: asyncio.Queue):
    yield sse_format({"type": "hello", "user_id": user_id, "ts": now_iso()})

    keepalive_seconds = 15
    while True:
        if await request.is_disconnected():
            break
        try:
            event = await asyncio.wait_for(q.get(), timeout=keepalive_seconds)
            yield sse_format(event)
        except asyncio.TimeoutError:
            yield ":\n\n"


async def sqs_poller_task() -> None:
    if not EVENTS_SQS_URL or not sqs:
        return

    loop = asyncio.get_running_loop()

    while True:
        try:
            resp = await loop.run_in_executor(
                None,
                lambda: sqs.receive_message(
                    QueueUrl=EVENTS_SQS_URL,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=20,
                    VisibilityTimeout=30,
                ),
            )
            msgs = resp.get("Messages", [])
            if not msgs:
                continue

            for msg in msgs:
                receipt = msg["ReceiptHandle"]
                body = msg.get("Body", "")

                try:
                    envelope = json.loads(body)
                    payload_str = envelope.get("Message", body)
                    payload = json.loads(payload_str) if isinstance(payload_str, str) else payload_str

                    user_id = payload.get("user_id") if isinstance(payload, dict) else None
                    if user_id:
                        await sse_hub.publish(user_id, payload)
                except Exception:
                    pass
                finally:
                    await loop.run_in_executor(
                        None,
                        lambda r=receipt: sqs.delete_message(QueueUrl=EVENTS_SQS_URL, ReceiptHandle=r),
                    )
        except Exception:
            await asyncio.sleep(1.0)


async def startup() -> None:
    if EVENTS_SQS_URL:
        asyncio.create_task(sqs_poller_task())


@router.get("/sse")
async def sse(request: Request, user_id: UserIdDep):
    q = await sse_hub.add(user_id)

    async def _gen():
        try:
            async for chunk in sse_event_stream(request, user_id, q):
                yield chunk
        finally:
            await sse_hub.remove(user_id, q)

    return StreamingResponse(_gen(), media_type="text/event-stream")


# -----------------------------
# Notification writer
# -----------------------------
def put_notification(*, recipient_user_id: str, notif_type: str, payload: Dict[str, Any]) -> str:
    notif_id = new_id("ntf")
    created_at = now_iso()
    item = {
        "pk": pk_notif(recipient_user_id),
        "sk": f"{created_at}#NOTIF#{notif_id}",
        "Entity": "Notification",
        "notif_id": notif_id,
        "recipient_user_id": recipient_user_id,
        "type": notif_type,
        "payload": payload,
        "created_at": created_at,
        "GSI3PK": pk_notif(recipient_user_id),
        "GSI3SK": f"{created_at}#{notif_id}",
        "read": False,
    }
    ddb_put_item(item)

    event = {
        "type": "notification",
        "user_id": recipient_user_id,
        "created_at": created_at,
        "data": {"notif_type": notif_type, "payload": payload, "notif_id": notif_id},
    }
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(sse_hub.publish(recipient_user_id, event))
    except RuntimeError:
        # Called from a sync threadpool context — SSE push not possible; notification is in DDB
        pass

    return notif_id


# -----------------------------
# Following / hiding / unlock helpers
# -----------------------------
def is_following(viewer_id: str, target_id: str) -> bool:
    it = ddb_get_item({"pk": pk_user(viewer_id), "sk": f"FOLLOWING#{target_id}"})
    return bool(it and it.get("state") == "following")


def is_hidden(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"pk": pk_hide(user_id), "sk": f"POST#{post_id}"})
    return bool(it and it.get("hidden") is True)


def has_unlocked(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"})
    return bool(it and it.get("unlocked") is True)


# -----------------------------
# Uploads (multipart POST + GET proxy)
# -----------------------------
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


@router.post("/uploads/image")
async def upload_image(
    file: UploadFile = File(...),
    user_id: UserIdDep = None,
):
    ensure_uploads_enabled()
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are accepted")
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Image must be under 10 MB")
    attachment_id = new_id("att")
    safe_name = (file.filename or "upload.bin").replace("/", "_").replace("\\", "_")
    s3_key = f"uploads/{user_id}/{attachment_id}/{safe_name}"
    try:
        s3.put_object(Bucket=UPLOAD_BUCKET, Key=s3_key, Body=content, ContentType=file.content_type or "application/octet-stream")
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"S3 error: {exc.response['Error'].get('Message','unknown')}") from exc
    encoded_key = quote(s3_key, safe="")
    url = f"/uploads/object?s3_key={encoded_key}"
    return {"url": url, "s3_key": s3_key}


@router.get("/uploads/object")
def get_upload_object(s3_key: str = Query(...)):
    ensure_uploads_enabled()
    try:
        obj = s3.get_object(Bucket=UPLOAD_BUCKET, Key=s3_key)
    except ClientError as exc:
        raise HTTPException(status_code=404, detail="Not found") from exc
    content_type = obj.get("ContentType", "application/octet-stream")

    def _iter():
        for chunk in obj["Body"].iter_chunks(64 * 1024):
            if chunk:
                yield chunk

    return StreamingResponse(_iter(), media_type=content_type, headers={"Cache-Control": "private, max-age=300"})


# -----------------------------
# Follow / Unfollow
# -----------------------------
@router.post("/social/unfollow")
def unfollow(req: UnfollowRequest, user_id: UserIdDep):
    target = req.target_user_id
    item = {
        "pk": pk_user(user_id),
        "sk": f"FOLLOWING#{target}",
        "Entity": "Following",
        "user_id": user_id,
        "target_user_id": target,
        "state": "unfollowed",
        "updated_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}


@router.post("/social/refollow")
def refollow(req: UnfollowRequest, user_id: UserIdDep):
    target = req.target_user_id
    item = {
        "pk": pk_user(user_id),
        "sk": f"FOLLOWING#{target}",
        "Entity": "Following",
        "user_id": user_id,
        "target_user_id": target,
        "state": "following",
        "updated_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}


# -----------------------------
# Posts
# -----------------------------
@router.post("/posts", response_model=PostResponse)
def create_post(req: CreatePostRequest, user_id: UserIdDep):
    _enforce_newsfeed_post_quota_precheck(user_id=user_id)
    post_id = new_id("post")
    created_at = now_iso()

    unlock_price_cents = req.unlock_price_cents if req.unlock_price_cents and req.unlock_price_cents > 0 else None
    locked = unlock_price_cents is not None
    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("create_post", surface="post", body_format=content.get("body_format", "plain"))

    # Validate and collect file attachment metadata (max 5)
    file_attachments = []
    for fp in req.file_paths[:5]:
        node_path = norm_path(fp, is_folder=False)
        node = get_node(user_id, node_path)  # raises 404 if not found or not owned
        file_attachments.append({
            "path": node_path,
            "name": node.get("name") or node_path.rsplit("/", 1)[-1],
            "content_type": node.get("content_type"),
            "size": int(node["size"]) if node.get("size") is not None else None,
            "owner": user_id,
        })

    post_item = {
        "pk": pk_post(post_id),
        "sk": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        **content,
        "image_urls": req.image_urls,
        "visibility": req.visibility,
        "locked": locked,
        "unlock_price_cents": unlock_price_cents,
        "like_count": 0,
        "comment_count": 0,
        "file_attachments": file_attachments,
    }
    ddb_put_item(post_item)

    feed_item = {
        "pk": pk_post(post_id),
        "sk": f"FEEDREF#{user_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{user_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    ddb_put_item(feed_item)
    _meter_newsfeed_post_publish(user_id=user_id, post_id=post_id)

    return PostResponse(
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        body=content["body"],
        body_plain=content["body_plain"],
        body_markdown=content["body_markdown"],
        body_markdown_html=content["body_markdown_html"],
        body_rich=content["body_rich"],
        body_format=content["body_format"],
        body_version=content["body_version"],
        image_urls=req.image_urls,
        visibility=req.visibility,
        locked=locked,
        unlock_price_cents=unlock_price_cents,
        like_count=0,
        comment_count=0,
    )


@router.patch("/posts/{post_id}")
def edit_post(post_id: str, req: EditPostRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("edit_post", surface="post", body_format=content.get("body_format", "plain"))
    image_urls_in_payload = "image_urls" in req.model_fields_set
    if image_urls_in_payload and req.image_urls:
        update_expr = "SET #body = :b, body_plain = :bp, body_markdown = :bm, body_markdown_html = :bmh, body_rich = :br, body_format = :bf, body_version = :bv, image_urls = :imgs, updated_at = :u"
        expr_vals = {":b": content["body"], ":bp": content["body_plain"], ":bm": content["body_markdown"], ":bmh": content["body_markdown_html"], ":br": content["body_rich"], ":bf": content["body_format"], ":bv": content["body_version"], ":imgs": req.image_urls, ":u": now_iso()}
    elif image_urls_in_payload:
        update_expr = "SET #body = :b, body_plain = :bp, body_markdown = :bm, body_markdown_html = :bmh, body_rich = :br, body_format = :bf, body_version = :bv, updated_at = :u REMOVE image_urls"
        expr_vals = {":b": content["body"], ":bp": content["body_plain"], ":bm": content["body_markdown"], ":bmh": content["body_markdown_html"], ":br": content["body_rich"], ":bf": content["body_format"], ":bv": content["body_version"], ":u": now_iso()}
    else:
        update_expr = "SET #body = :b, body_plain = :bp, body_markdown = :bm, body_markdown_html = :bmh, body_rich = :br, body_format = :bf, body_version = :bv, updated_at = :u"
        expr_vals = {":b": content["body"], ":bp": content["body_plain"], ":bm": content["body_markdown"], ":bmh": content["body_markdown_html"], ":br": content["body_rich"], ":bf": content["body_format"], ":bv": content["body_version"], ":u": now_iso()}
    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr=update_expr,
        expr_names={"#body": "body"},
        expr_vals=expr_vals,
    )
    return _post_to_dict(updated, viewer_id=user_id)


@router.get("/posts/{post_id}")
def get_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    author = post.get("user_id")
    if author and author != user_id:
        if not can_access_creator(user_id, author):
            raise HTTPException(status_code=403, detail="Subscription required")
    locked = bool(post.get("locked"))
    is_locked_for_viewer = locked and author != user_id and not has_unlocked(user_id, post_id)
    viewer_unlocked = locked and not is_locked_for_viewer
    liked = bool(ddb_get_item({"pk": pk_like(user_id), "sk": f"POST#{post_id}"}))
    return _post_to_dict(post, locked_body=is_locked_for_viewer, liked_by_me=liked, unlocked=viewer_unlocked, viewer_id=user_id)


@router.get("/posts/{post_id}/files/{file_index}")
def get_post_file(post_id: str, file_index: int, user_id: UserIdDep):
    """Proxy a file attachment from a post to an authorized viewer."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    author = post.get("user_id")
    if author and author != user_id:
        if not can_access_creator(user_id, author):
            raise HTTPException(status_code=403, detail="Subscription required")
    locked = bool(post.get("locked"))
    if locked and author != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required")
    attachments = post.get("file_attachments") or []
    if file_index < 0 or file_index >= len(attachments):
        raise HTTPException(status_code=404, detail="File attachment not found")
    fa = attachments[file_index]
    owner = fa.get("owner")
    path = fa.get("path")
    if not owner or not path:
        raise HTTPException(status_code=404, detail="File attachment metadata missing")
    result = download_file(owner, path)
    node = result["node"]
    obj = result["object"]
    content_type = node.get("content_type") or "application/octet-stream"

    def _iter():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    headers: dict = {"Cache-Control": "private, max-age=300"}
    if node.get("size") is not None:
        headers["Content-Length"] = str(node["size"])
    return StreamingResponse(_iter(), media_type=content_type, headers=headers)


@router.delete("/posts/{post_id}")
def delete_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    try:
        tbl.delete_item(Key={"pk": pk_post(post_id), "sk": sk_post()})
        tbl.delete_item(Key={"pk": pk_post(post_id), "sk": f"FEEDREF#{user_id}"})
    except ClientError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
        ) from exc
    return {"ok": True}


@router.post("/posts/{post_id}/like")
def like_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    try:
        tbl.put_item(
            Item={
                "pk": pk_like(user_id),
                "sk": f"POST#{post_id}",
                "Entity": "Like",
                "user_id": user_id,
                "post_id": post_id,
                "created_at": now_iso(),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr="SET like_count = if_not_exists(like_count, :z) + :one",
            expr_vals={":one": 1, ":z": 0},
            return_values="NONE",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=500,
                detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
            ) from exc
        # Already liked — idempotent
    return {"ok": True}


@router.post("/posts/{post_id}/unlike")
def unlike_post(post_id: str, user_id: UserIdDep):
    try:
        tbl.delete_item(
            Key={"pk": pk_like(user_id), "sk": f"POST#{post_id}"},
            ConditionExpression="attribute_exists(pk)",
        )
        try:
            ddb_update_item(
                key={"pk": pk_post(post_id), "sk": sk_post()},
                update_expr="SET like_count = like_count - :one",
                expr_vals={":one": 1, ":z": 0},
                condition_expr="like_count > :z",
                return_values="NONE",
            )
        except HTTPException as ex:
            if ex.status_code != 409:
                raise
            # ConditionalCheckFailed — like_count already at 0, that's fine
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=500,
                detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
            ) from exc
        # Already unliked — idempotent
    return {"ok": True}


@router.post("/posts/{post_id}/tip")
def tip_post(post_id: str, req: PostTipRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") == user_id:
        raise HTTPException(status_code=400, detail="Cannot tip your own post")

    # Validate payment method belongs to this user (if provided and billing enabled)
    if req.payment_method_id and S.billing_table_name:
        billing_tbl = ddb.Table(S.billing_table_name)
        billing_items = billing_tbl.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"USER#{user_id}"},
        ).get("Items", [])
        pm_ids = {
            it["payment_method_id"]
            for it in billing_items
            if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
        }
        if req.payment_method_id not in pm_ids:
            raise HTTPException(status_code=400, detail="Payment method not found")

    pi = payments.create_payment_intent(
        user_id=user_id,
        amount_cents=req.amount_cents,
        currency=req.currency,
        metadata={"type": "tip_post", "post_id": post_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":z": 0, ":amt": req.amount_cents},
    )

    # Write billing ledger debit entry (best-effort)
    if S.billing_table_name:
        try:
            billing_tbl_led = ddb.Table(S.billing_table_name)
            led_entry_id = uuid.uuid4().hex
            ts_now = int(time.time())
            billing_tbl_led.put_item(Item={
                "pk": f"USER#{user_id}",
                "sk": f"LEDGER#{ts_now}#{led_entry_id}",
                "entry_id": led_entry_id,
                "ts": ts_now,
                "type": "debit",
                "amount_cents": req.amount_cents,
                "currency": "USD",
                "state": "settled",
                "reason": "Post tip",
                "meta": {"post_id": post_id, "payment_method_id": req.payment_method_id},
            })
        except Exception:
            pass

    author = post.get("user_id")
    if author:
        put_notification(
            recipient_user_id=author,
            notif_type="tip_on_post",
            payload={
                "post_id": post_id,
                "from_user_id": user_id,
                "amount_cents": req.amount_cents,
                "currency": req.currency,
                "created_at": now_iso(),
            },
        )

    return {"ok": True, "tip_total_cents": int(updated.get("tip_total_cents", 0))}


@router.post("/posts/{post_id}/reactions")
def add_reaction(post_id: str, req: ReactionRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    reactions = dict(post.get("reactions") or {})
    emoji_map = dict(reactions.get(req.emoji, {}))
    emoji_map[user_id] = True
    reactions[req.emoji] = emoji_map

    ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET reactions = :r",
        expr_vals={":r": reactions},
        return_values="NONE",
    )
    return {"ok": True}


@router.post("/posts/{post_id}/unreact")
def remove_reaction(post_id: str, req: ReactionRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    reactions = dict(post.get("reactions") or {})
    if req.emoji in reactions:
        emoji_map = dict(reactions[req.emoji])
        emoji_map.pop(user_id, None)
        if emoji_map:
            reactions[req.emoji] = emoji_map
        else:
            del reactions[req.emoji]
        ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr="SET reactions = :r",
            expr_vals={":r": reactions},
            return_values="NONE",
        )
    return {"ok": True}


@router.post("/feed/hide")
def hide_post(req: HidePostRequest, user_id: UserIdDep):
    item = {
        "pk": pk_hide(user_id),
        "sk": f"POST#{req.post_id}",
        "Entity": "Hide",
        "user_id": user_id,
        "post_id": req.post_id,
        "hidden": True,
        "created_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}


@router.get("/feed")
def view_feed(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    eks = decode_cursor_or_400(cursor)

    resp = ddb_query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk",
        ExpressionAttributeValues={":pk": f"FEED#{user_id}"},
        ScanIndexForward=False,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )

    refs = resp.get("Items", [])
    post_ids = [ref.get("post_id") for ref in refs if ref.get("post_id")]

    posts: List[Dict[str, Any]] = []
    if post_ids:
        keys = [{"pk": pk_post(pid), "sk": sk_post()} for pid in post_ids]
        try:
            raw = ddb.batch_get_item(
                RequestItems={APP_TABLE: {"Keys": keys}}
            )
            posts = raw.get("Responses", {}).get(APP_TABLE, [])
        except ClientError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"DDB batch_get_item error: {exc.response['Error'].get('Message','unknown')}",
            ) from exc

    post_by_id = {post["post_id"]: post for post in posts if "post_id" in post}

    # Batch-fetch like records so we can set liked_by_me per post
    liked_post_ids: set = set()
    if post_ids:
        like_keys = [{"pk": pk_like(user_id), "sk": f"POST#{pid}"} for pid in post_ids]
        try:
            like_raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": like_keys}})
            liked_post_ids = {item.get("post_id", "") for item in like_raw.get("Responses", {}).get(APP_TABLE, [])}
        except ClientError:
            pass  # Best effort — liked_by_me will default to False

    ordered: List[Dict[str, Any]] = []

    for post_id in post_ids:
        post = post_by_id.get(post_id)
        if not post:
            continue

        if is_hidden(user_id, post_id):
            continue

        author = post.get("user_id")
        if author and author != user_id:
            if not can_access_creator(user_id, author):
                continue
            if not is_following(user_id, author):
                continue

        locked = bool(post.get("locked"))
        is_locked_for_viewer = locked and author != user_id and not has_unlocked(user_id, post_id)
        viewer_unlocked = locked and not is_locked_for_viewer
        ordered.append(_post_to_dict(post, locked_body=is_locked_for_viewer, liked_by_me=post_id in liked_post_ids, unlocked=viewer_unlocked, viewer_id=user_id))

    return {"items": ordered, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


@router.get("/posts/{post_id}/attachments/{attachment_id}")
def download_post_attachment(
    post_id: str,
    attachment_id: str,
    user_id: UserIdDep = None,
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    ensure_uploads_enabled()

    post = ddb_get_item({"PK": pk_post(post_id), "SK": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    author = post.get("user_id")
    if author and author != user_id:
        if not can_access_creator(user_id, author):
            raise HTTPException(status_code=403, detail="Subscription required")
        if not is_following(user_id, author):
            raise HTTPException(status_code=403, detail="Following required")

    if bool(post.get("locked")) and author != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required")

    attachment = None
    for it in post.get("attachments") or []:
        if str((it or {}).get("attachment_id") or "") == attachment_id:
            attachment = it or {}
            break
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")

    s3_key = str(attachment.get("s3_key") or "").strip()
    if not s3_key:
        raise HTTPException(status_code=404, detail="Attachment object not found")

    try:
        obj = s3.get_object(Bucket=UPLOAD_BUCKET, Key=s3_key)
    except ClientError as exc:
        raise HTTPException(status_code=404, detail="Attachment object not found") from exc

    body = obj.get("Body")
    if body is None:
        raise HTTPException(status_code=404, detail="Attachment stream missing")

    content_len = int(obj.get("ContentLength") or 0)
    content_type = str(attachment.get("content_type") or obj.get("ContentType") or "application/octet-stream")
    filename = str(attachment.get("filename") or os.path.basename(s3_key) or "attachment")
    attachment_key = f"{UPLOAD_BUCKET}/{s3_key}"

    def _iter_stream():
        sent = 0
        try:
            for chunk in body.iter_chunks(chunk_size=64 * 1024):
                if not chunk:
                    continue
                sent += len(chunk)
                yield chunk
        finally:
            _record_newsfeed_attachment_download(
                user_id=user_id,
                post_id=post_id,
                attachment_key=attachment_key,
                bytes_count=sent,
                idempotency_operation_id=x_request_id or attachment_id,
            )

    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Cache-Control": "private, max-age=60",
    }
    if content_len > 0:
        headers["Content-Length"] = str(content_len)

    return StreamingResponse(_iter_stream(), media_type=content_type, headers=headers)


# -----------------------------
# Comments
# -----------------------------
@router.post("/posts/{post_id}/comments", response_model=CommentResponse)
def create_comment(post_id: str, req: CreateCommentRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    post_author = post.get("user_id")
    if post_author and post_author != user_id and not can_access_creator(user_id, post_author):
        raise HTTPException(status_code=403, detail="Subscription required to comment")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to comment")

    comment_id = new_id("cmt")
    created_at = now_iso()
    parent = req.parent_comment_id
    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("create_comment", surface="comment", body_format=content.get("body_format", "plain"))

    item = {
        "pk": pk_post_comments(post_id),
        "sk": f"{created_at}#CMT#{comment_id}",
        "Entity": "Comment",
        "comment_id": comment_id,
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "updated_at": None,
        "deleted": False,
        "parent_comment_id": parent,
        **content,
        "version": 1,
        "tip_total_cents": 0,
        "GSI2PK": pk_post_comments(post_id),
        "GSI2SK": f"{created_at}#CMT#{comment_id}",
    }
    ddb_put_item(item)

    ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET comment_count = if_not_exists(comment_count, :z) + :one",
        expr_vals={":z": 0, ":one": 1},
    )

    if post_author and post_author != user_id and parent is None:
        put_notification(
            recipient_user_id=post_author,
            notif_type="comment_on_post",
            payload={"post_id": post_id, "comment_id": comment_id, "from_user_id": user_id, "created_at": created_at},
        )

    if parent:
        q = ddb_query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
            ScanIndexForward=False,
            Limit=200,
        )
        parent_user = None
        for it in q.get("Items", []):
            if it.get("comment_id") == parent:
                parent_user = it.get("user_id")
                break
        if parent_user and parent_user != user_id:
            put_notification(
                recipient_user_id=parent_user,
                notif_type="reply_to_comment",
                payload={
                    "post_id": post_id,
                    "parent_comment_id": parent,
                    "comment_id": comment_id,
                    "from_user_id": user_id,
                    "created_at": created_at,
                },
            )

    return CommentResponse(
        comment_id=comment_id,
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        updated_at=None,
        deleted=False,
        parent_comment_id=parent,
        body=content["body"],
        body_plain=content["body_plain"],
        body_markdown=content["body_markdown"],
        body_markdown_html=content["body_markdown_html"],
        body_rich=content["body_rich"],
        body_format=content["body_format"],
        body_version=content["body_version"],
        version=1,
        tip_total_cents=0,
    )


@router.get("/posts/{post_id}/comments")
def list_comments(
    post_id: str,
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to view comments")

    eks = decode_cursor_or_400(cursor)
    resp = ddb_query(
        IndexName="GSI2",
        KeyConditionExpression="GSI2PK = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=True,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    items = [_comment_to_dict(it) for it in resp.get("Items", [])]
    return {"items": items, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


@router.patch("/posts/{post_id}/comments/{comment_id}", response_model=CommentResponse)
def edit_comment(post_id: str, comment_id: str, req: EditCommentRequest, user_id: UserIdDep):
    q = ddb_query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for it in q.get("Items", []):
        if it.get("comment_id") == comment_id:
            target = it
            break
    if not target:
        raise HTTPException(status_code=404, detail="Comment not found")
    if target.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your comment")
    if target.get("deleted"):
        raise HTTPException(status_code=409, detail="Comment deleted")

    key = {"pk": target["pk"], "sk": target["sk"]}
    new_version = int(req.expected_version) + 1

    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("edit_comment", surface="comment", body_format=content.get("body_format", "plain"))
    updated = ddb_update_item(
        key=key,
        update_expr="SET #body = :b, body_plain = :bp, body_markdown = :bm, body_markdown_html = :bmh, body_rich = :br, body_format = :bf, body_version = :bv, updated_at = :u, version = :nv",
        expr_names={"#body": "body"},
        expr_vals={":b": content["body"], ":bp": content["body_plain"], ":bm": content["body_markdown"], ":bmh": content["body_markdown_html"], ":br": content["body_rich"], ":bf": content["body_format"], ":bv": content["body_version"], ":u": now_iso(), ":nv": new_version, ":ev": int(req.expected_version)},
        condition_expr="version = :ev",
    )

    return CommentResponse(
        comment_id=updated["comment_id"],
        post_id=updated["post_id"],
        author_id=updated.get("user_id", ""),
        created_at=updated["created_at"],
        updated_at=updated.get("updated_at"),
        deleted=bool(updated.get("deleted")),
        parent_comment_id=updated.get("parent_comment_id"),
        body=(updated.get("body_plain") or updated.get("body")) if not updated.get("deleted") else None,
        body_plain=updated.get("body_plain") if not updated.get("deleted") else None,
        body_markdown=updated.get("body_markdown") if not updated.get("deleted") else None,
        body_markdown_html=updated.get("body_markdown_html") if not updated.get("deleted") else None,
        body_rich=updated.get("body_rich") if not updated.get("deleted") else None,
        body_format=updated.get("body_format") if updated.get("body_format") in {"plain", "markdown", "rich"} else "plain",
        body_version=int(updated.get("body_version") or 1),
        version=int(updated.get("version", 1)),
        tip_total_cents=int(updated.get("tip_total_cents", 0)),
    )


@router.delete("/posts/{post_id}/comments/{comment_id}")
def delete_comment(post_id: str, comment_id: str, user_id: UserIdDep):
    q = ddb_query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for it in q.get("Items", []):
        if it.get("comment_id") == comment_id:
            target = it
            break
    if not target:
        raise HTTPException(status_code=404, detail="Comment not found")
    if target.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your comment")

    key = {"pk": target["pk"], "sk": target["sk"]}
    ddb_update_item(
        key=key,
        update_expr="SET deleted = :t, #body = :null, updated_at = :u",
        expr_names={"#body": "body"},
        expr_vals={":t": True, ":null": None, ":u": now_iso()},
    )
    return {"ok": True}


# -----------------------------
# Tips on comments
# -----------------------------
@router.post("/posts/{post_id}/comments/{comment_id}/tip")
def tip_comment(post_id: str, comment_id: str, req: TipRequest, user_id: UserIdDep):
    tipper_id = user_id

    q = ddb_query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for it in q.get("Items", []):
        if it.get("comment_id") == comment_id:
            target = it
            break
    if not target:
        raise HTTPException(status_code=404, detail="Comment not found")
    if target.get("deleted"):
        raise HTTPException(status_code=409, detail="Comment deleted")

    pi = payments.create_payment_intent(
        user_id=tipper_id,
        amount_cents=req.amount_cents,
        currency=req.currency,
        metadata={"type": "tip", "post_id": post_id, "comment_id": comment_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    key = {"pk": target["pk"], "sk": target["sk"]}
    updated = ddb_update_item(
        key=key,
        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":z": 0, ":amt": req.amount_cents},
    )

    comment_author = updated.get("user_id")
    if comment_author and comment_author != tipper_id:
        put_notification(
            recipient_user_id=comment_author,
            notif_type="tip_on_comment",
            payload={
                "post_id": post_id,
                "comment_id": comment_id,
                "from_user_id": tipper_id,
                "amount_cents": req.amount_cents,
                "currency": req.currency,
                "created_at": now_iso(),
            },
        )

    return {"ok": True, "tip_total_cents": int(updated.get("tip_total_cents", 0)), "payment_intent": pi}


# -----------------------------
# Unlock post via payment
# -----------------------------
@router.post("/posts/unlock", response_model=UnlockPostResponse)
def unlock_post(req: UnlockPostRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(req.post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if not post.get("locked"):
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "not_required"})
    if post.get("user_id") == user_id:
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "not_required"})
    if has_unlocked(user_id, req.post_id):
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "already_unlocked"})

    price = int(post.get("unlock_price_cents") or 0)
    if price <= 0:
        raise HTTPException(status_code=500, detail="Locked post has invalid price")

    # Validate payment method belongs to this user
    if req.payment_method_id and S.billing_table_name:
        billing_tbl_pm = ddb.Table(S.billing_table_name)
        billing_items = billing_tbl_pm.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"USER#{user_id}"},
        ).get("Items", [])
        pm_ids = {
            it["payment_method_id"]
            for it in billing_items
            if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
        }
        if req.payment_method_id not in pm_ids:
            raise HTTPException(status_code=400, detail="Payment method not found")

    pi = payments.create_payment_intent(
        user_id=user_id,
        amount_cents=price,
        currency="usd",
        metadata={"type": "unlock_post", "post_id": req.post_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    item = {
        "pk": pk_unlock(user_id),
        "sk": f"POST#{req.post_id}",
        "Entity": "Unlock",
        "user_id": user_id,
        "post_id": req.post_id,
        "unlocked": True,
        "created_at": now_iso(),
        "payment_intent_id": pi["payment_intent_id"],
    }
    ddb_put_item(item)

    # Write billing ledger debit entry (best-effort)
    if S.billing_table_name:
        try:
            billing_tbl_led = ddb.Table(S.billing_table_name)
            led_entry_id = uuid.uuid4().hex
            ts_now = int(time.time())
            billing_tbl_led.put_item(Item={
                "pk": f"USER#{user_id}",
                "sk": f"LEDGER#{ts_now}#{led_entry_id}",
                "entry_id": led_entry_id,
                "ts": ts_now,
                "type": "debit",
                "amount_cents": price,
                "currency": "USD",
                "state": "settled",
                "reason": "Post unlock",
                "meta": {
                    "post_id": req.post_id,
                    "payment_method_id": req.payment_method_id,
                },
            })
        except Exception:
            pass  # Best-effort; do not fail the unlock if billing write fails

    author = post.get("user_id")
    if author and author != user_id:
        put_notification(
            recipient_user_id=author,
            notif_type="post_unlocked",
            payload={
                "post_id": req.post_id,
                "from_user_id": user_id,
                "amount_cents": price,
                "currency": "usd",
                "created_at": now_iso(),
            },
        )

    return UnlockPostResponse(post_id=req.post_id, payment_intent=pi)


# -----------------------------
# Notifications inbox (view)
# -----------------------------
@router.get("/notifications")
def list_notifications(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    eks = decode_cursor_or_400(cursor)

    resp = ddb_query(
        IndexName="GSI3",
        KeyConditionExpression="GSI3PK = :pk",
        ExpressionAttributeValues={":pk": pk_notif(user_id)},
        ScanIndexForward=False,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    return {"items": resp.get("Items", []), "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}



@router.post("/telemetry/content-render")
def content_render_telemetry(req: ContentRenderTelemetryRequest, user_id: UserIdDep):
    _emit_newsfeed_content_reject(req.reason, source="renderer", body_format=req.body_format)
    return {"ok": True}


# -----------------------------
# Health
# -----------------------------
@router.get("/health")
def health():
    return {
        "ok": True,
        "ts": int(time.time()),
        "uploads_enabled": bool(UPLOAD_BUCKET),
        "sse_fanout_enabled": bool(EVENTS_SQS_URL),
        "table": APP_TABLE,
        "region": AWS_REGION,
    }
