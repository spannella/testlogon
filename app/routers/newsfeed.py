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
from zoneinfo import ZoneInfo
from typing import Annotated, Any, Dict, List, Literal, Optional, Set, Tuple

from urllib.parse import parse_qs, quote, urlparse

from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeSerializer
from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field, ValidationError, model_validator
from starlette.responses import StreamingResponse

from app.core.aws import ddb
from app.core.aws_clients import s3_client, sqs_client
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.metrics import record_newsfeed_schedule_operation
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
_SCHEDULED_LOCAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
_ddb_serializer = TypeSerializer()


def _emit_newsfeed_content_metric(event: str, **fields: Any) -> None:
    logger.info("newsfeed content metric", extra={"event": event, **fields})


def _emit_newsfeed_draft_metric(
    event: str,
    *,
    outcome: Literal["success", "fail"],
    source: Literal["backend", "frontend"] = "backend",
    reason_code: Optional[str] = None,
    **fields: Any,
) -> None:
    payload = {"event": event, "outcome": outcome, "source": source, **fields}
    if reason_code:
        payload["reason_code"] = reason_code
    if outcome == "success":
        logger.info("newsfeed draft lifecycle metric", extra=payload)
    else:
        logger.warning("newsfeed draft lifecycle metric", extra=payload)


def _emit_newsfeed_content_reject(reason_code: str, *, source: str, body_format: Optional[str] = None) -> None:
    logger.warning(
        "newsfeed content reject",
        extra={"event": "newsfeed_content_reject", "source": source, "reason_code": reason_code, "body_format": body_format or "unknown"},
    )


def _schedule_payload_error(
    *,
    code: str,
    message: str,
    field: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    operation: Optional[str] = None,
) -> HTTPException:
    if operation:
        record_newsfeed_schedule_operation(operation=operation, outcome="validation_error")
        logger.warning(
            "newsfeed schedule validation failed",
            extra={"event": "newsfeed_schedule_validation_failed", "operation": operation, "code": code, "field": field or "unknown"},
        )
    detail: Dict[str, Any] = {"code": code, "message": message}
    if field:
        detail["field"] = field
    if extra:
        detail.update(extra)
    return HTTPException(status_code=400, detail=detail)


def _require_newsfeed_scheduling_api_enabled() -> None:
    if bool(getattr(S, "newsfeed_scheduling_api_enabled", True)):
        return
    raise HTTPException(
        status_code=404,
        detail={
            "code": "schedule_feature_disabled",
            "message": "scheduled posting is currently disabled",
        },
    )


def _schedule_min_lead_seconds() -> int:
    try:
        return max(1, int(getattr(S, "newsfeed_scheduling_min_lead_seconds", 5)))
    except Exception:
        return 5


def _schedule_max_horizon_seconds() -> int:
    min_lead = _schedule_min_lead_seconds()
    try:
        return max(min_lead + 1, int(getattr(S, "newsfeed_scheduling_max_horizon_seconds", 31536000)))
    except Exception:
        return 31536000


def _ddb_serialize_map(values: Dict[str, Any]) -> Dict[str, Any]:
    return {key: _ddb_serializer.serialize(value) for key, value in values.items()}



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


def _draft_retention_days() -> int:
    raw = int(getattr(S, "newsfeed_draft_retention_days", 0) or 0)
    return max(0, min(raw, 3650))


def _draft_max_per_user() -> int:
    raw = int(getattr(S, "newsfeed_draft_max_per_user", 50) or 50)
    return max(1, min(raw, 1000))


def _draft_max_payload_bytes() -> int:
    raw = int(getattr(S, "newsfeed_draft_max_payload_bytes", 65536) or 65536)
    return max(1024, min(raw, 1_048_576))


def _draft_quota_bypass_user_ids() -> Set[str]:
    raw = str(getattr(S, "newsfeed_draft_quota_bypass_user_ids", "") or "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def _drafts_enabled_user_ids() -> Set[str]:
    raw = str(getattr(S, "newsfeed_drafts_enabled_user_ids", "") or "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def _drafts_disabled_user_ids() -> Set[str]:
    raw = str(getattr(S, "newsfeed_drafts_disabled_user_ids", "") or "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def _is_drafts_feature_enabled_for_user(user_id: str) -> bool:
    if user_id in _drafts_enabled_user_ids():
        return True
    if user_id in _drafts_disabled_user_ids():
        return False
    return bool(getattr(S, "newsfeed_drafts_enabled", True))


def _ensure_drafts_feature_enabled(user_id: str) -> None:
    if _is_drafts_feature_enabled_for_user(user_id):
        return
    raise HTTPException(status_code=404, detail="Drafts feature is disabled")


def _draft_quota_error(*, limit_count: int, used_count: int) -> HTTPException:
    remaining_count = max(0, int(limit_count) - int(used_count))
    return HTTPException(
        status_code=403,
        detail={
            "code": "newsfeed_draft_quota_exceeded",
            "message": "newsfeed draft quota exceeded",
            "quota_type": "newsfeed_draft",
            "limit_count": int(limit_count),
            "used_count": int(used_count),
            "remaining_count": remaining_count,
        },
    )


def _draft_payload_too_large_error(*, max_payload_bytes: int, payload_bytes: int) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail={
            "code": "newsfeed_draft_payload_too_large",
            "message": "newsfeed draft payload exceeds max size",
            "max_payload_bytes": int(max_payload_bytes),
            "payload_bytes": int(payload_bytes),
        },
    )


def _draft_conflict_error(*, expected_updated_at: str, actual_updated_at: Optional[str]) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "newsfeed_draft_version_conflict",
            "message": "draft has changed since last read",
            "expected_updated_at": expected_updated_at,
            "actual_updated_at": actual_updated_at,
        },
    )


def _enforce_draft_expected_updated_at(
    *,
    expected_updated_at: Optional[str],
    existing_item: Dict[str, Any],
) -> None:
    if not expected_updated_at:
        return
    actual_updated_at = str(existing_item.get("updated_at") or "")
    if actual_updated_at != expected_updated_at:
        raise _draft_conflict_error(
            expected_updated_at=expected_updated_at,
            actual_updated_at=actual_updated_at or None,
        )


def _draft_payload_bytes(payload: Dict[str, Any]) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _maybe_draft_ttl_epoch(updated_at_iso: str) -> Optional[int]:
    retention_days = _draft_retention_days()
    if retention_days <= 0:
        return None
    dt = datetime.fromisoformat(updated_at_iso)
    return int(dt.timestamp()) + (retention_days * 86400)


def _enforce_draft_payload_size(payload: Dict[str, Any]) -> None:
    payload_bytes = _draft_payload_bytes(payload)
    max_payload_bytes = _draft_max_payload_bytes()
    if payload_bytes > max_payload_bytes:
        raise _draft_payload_too_large_error(max_payload_bytes=max_payload_bytes, payload_bytes=payload_bytes)


def _enforce_draft_count_quota(user_id: str) -> None:
    if user_id in _draft_quota_bypass_user_ids():
        return
    limit_count = _draft_max_per_user()
    q = ddb_query(
        **build_draft_list_query(user_id=user_id, cursor=None, limit=limit_count + 1),
        ProjectionExpression="draft_id",
    )
    used_count = len(q.get("Items") or [])
    if used_count >= limit_count:
        raise _draft_quota_error(limit_count=limit_count, used_count=used_count)


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


SCHEDULED_POST_REF_PREFIX = "SCHEDULEDPOST"
SCHEDULE_DUE_INDEX_PK_ATTR = "GSI_SCHEDULE_PK"
SCHEDULE_DUE_INDEX_SK_ATTR = "GSI_SCHEDULE_SK"
SCHEDULE_DUE_INDEX_PK_VALUE = "SCHEDULED"


def _scheduled_publish_sort_key(publish_at: int) -> str:
    # Zero-pad to keep lexicographic sort aligned with numeric timestamp order.
    return f"{int(publish_at):012d}"


def schedule_due_index_values(publish_at: int, post_id: str) -> Dict[str, str]:
    return {
        SCHEDULE_DUE_INDEX_PK_ATTR: SCHEDULE_DUE_INDEX_PK_VALUE,
        SCHEDULE_DUE_INDEX_SK_ATTR: f"{_scheduled_publish_sort_key(publish_at)}#POST#{post_id}",
    }


def sk_scheduled_post_ref(publish_at: int, post_id: str) -> str:
    return f"{SCHEDULED_POST_REF_PREFIX}#{_scheduled_publish_sort_key(publish_at)}#{post_id}"


def parse_scheduled_post_ref_sk(sk: str) -> Optional[Tuple[int, str]]:
    raw = str(sk or "").strip()
    parts = raw.split("#", 2)
    if len(parts) != 3:
        return None
    prefix, publish_at_token, post_id = parts
    if prefix != SCHEDULED_POST_REF_PREFIX or not publish_at_token.isdigit() or not post_id:
        return None
    try:
        return int(publish_at_token), post_id
    except ValueError:
        return None


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


def sk_draft(draft_id: str) -> str:
    return f"DRAFT#{draft_id}"


def gsi_drafts_pk(user_id: str) -> str:
    return f"DRAFTS#{user_id}"


def gsi_drafts_sk(updated_at: str, draft_id: str) -> str:
    return f"{updated_at}#DRAFT#{draft_id}"


def drafts_index_name() -> str:
    return str(getattr(S, "newsfeed_drafts_index_name", "GSI4"))


def build_draft_item(
    *,
    user_id: str,
    draft_id: str,
    payload: Dict[str, Any],
    created_at: Optional[str] = None,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    created = created_at or now_iso()
    updated = updated_at or created
    item = {
        "pk": pk_user(user_id),
        "sk": sk_draft(draft_id),
        "entity_type": "draft_post",
        "status": "draft",
        "draft_id": draft_id,
        "author_id": user_id,
        "created_at": created,
        "updated_at": updated,
        "payload": payload,
        # Draft list index (descending by setting ScanIndexForward=False)
        "GSI4PK": gsi_drafts_pk(user_id),
        "GSI4SK": gsi_drafts_sk(updated, draft_id),
    }
    ttl_epoch = _maybe_draft_ttl_epoch(updated)
    if ttl_epoch is not None:
        item["ttl_epoch"] = ttl_epoch
    return item


def build_draft_list_query(
    *,
    user_id: str,
    cursor: Optional[str],
    limit: int = 20,
) -> Dict[str, Any]:
    query: Dict[str, Any] = {
        "IndexName": drafts_index_name(),
        "KeyConditionExpression": "GSI4PK = :pk",
        "ExpressionAttributeValues": {":pk": gsi_drafts_pk(user_id)},
        "Limit": max(1, min(int(limit), 100)),
        "ScanIndexForward": False,
    }
    eks = decode_cursor_or_400(cursor)
    if eks:
        query["ExclusiveStartKey"] = eks
    return query


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
    publish_at: Optional[int] = Field(
        default=None,
        ge=0,
        description="Unix timestamp (seconds) for scheduled publish time.",
    )
    schedule_timezone: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="IANA timezone name used when scheduling (e.g. America/New_York).",
    )
    scheduled_at_local: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=32,
        description="User-entered local datetime string (for display/audit), e.g. 2026-12-31T19:00.",
    )

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
                {
                    "body_plain": "Scheduled post",
                    "publish_at": 1767225600,
                    "schedule_timezone": "America/New_York",
                    "scheduled_at_local": "2026-12-31T19:00",
                },
            ]
        }
    }


class PostResponse(BaseModel):
    post_id: str
    author_id: str
    created_at: str
    published_at: Optional[str] = None
    status: Literal["scheduled", "published", "cancelled"] = "published"
    publish_at: Optional[int] = None
    schedule_timezone: Optional[str] = None
    scheduled_at_local: Optional[str] = None
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


class ScheduledPostsResponse(BaseModel):
    items: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "items": [
                        {
                            "post_id": "post_123",
                            "author_id": "user_abc",
                            "status": "scheduled",
                            "publish_at": 1767225600,
                            "schedule_timezone": "America/New_York",
                            "scheduled_at_local": "2026-12-31T19:00",
                            "created_at": "2026-01-01T00:00:00+00:00",
                            "published_at": None,
                            "body": "Scheduled post body",
                            "body_plain": "Scheduled post body",
                            "body_format": "plain",
                            "body_version": 1,
                            "image_urls": [],
                            "visibility": "followers",
                            "locked": False,
                            "like_count": 0,
                            "comment_count": 0,
                        }
                    ],
                    "next_cursor": "eyJwayI6ICJVU0VSI3UxIiwgInNrIjogIlNDSEVEVUxFRFBPU1QjMDAwMDAxNzY3MjI1NjAwI3Bvc3RfMTIzIn0",
                }
            ]
        }
    }


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
    publish_at: Optional[int] = Field(default=None, ge=0)
    schedule_timezone: Optional[str] = Field(default=None, min_length=1, max_length=64)
    scheduled_at_local: Optional[str] = Field(default=None, min_length=1, max_length=32)


class DraftPostResponse(BaseModel):
    draft_id: str
    author_id: str
    created_at: str
    updated_at: str
    body: Optional[str] = None
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: Optional[BodyFormat] = None
    body_version: int = 1
    image_urls: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)


class CreateDraftPostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "body": "Legacy plain draft",
                    "image_urls": ["https://cdn.example.com/image-1.jpg"],
                    "file_paths": ["/docs/contracts.pdf"],
                },
                {
                    "body_plain": "Hello draft",
                    "body_markdown": "# Hello draft",
                    "body_format": "markdown",
                    "body_version": 1,
                    "unlock_price_cents": 299,
                },
                {
                    "body_plain": "Hello rich draft",
                    "body_rich": {
                        "type": "doc",
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Hello rich draft"}]}],
                    },
                    "body_format": "rich",
                    "body_version": 1,
                },
            ]
        }
    }


class UpdateDraftPostRequest(BaseModel):
    body: Optional[str] = None
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: Optional[BodyFormat] = None
    body_version: Optional[int] = Field(default=1, ge=1)
    image_urls: Optional[List[str]] = None
    file_paths: Optional[List[str]] = None
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    expected_updated_at: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "body_plain": "Updated plain draft body",
                    "image_urls": ["https://cdn.example.com/updated-image.jpg"],
                },
                {
                    "body_plain": "Updated markdown draft",
                    "body_markdown": "## Updated markdown draft",
                    "body_format": "markdown",
                    "unlock_price_cents": 499,
                },
                {
                    "body_plain": "Updated rich draft",
                    "body_rich": {
                        "type": "doc",
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Updated rich draft"}]}],
                    },
                    "body_format": "rich",
                },
            ]
        }
    }


class ListDraftPostsResponse(BaseModel):
    items: List[DraftPostResponse] = Field(default_factory=list)
    next_cursor: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "items": [
                        {
                            "draft_id": "dft_123",
                            "author_id": "user_123",
                            "created_at": "2026-04-04T00:00:00Z",
                            "updated_at": "2026-04-04T00:10:00Z",
                            "body_plain": "Saved draft body",
                            "body_format": "plain",
                            "image_urls": ["https://cdn.example.com/image-1.jpg"],
                            "file_paths": ["/docs/contract.pdf"],
                        }
                    ],
                    "next_cursor": "eyJwayI6ICJ..."
                }
            ]
        }
    }


class PublishDraftPostRequest(BaseModel):
    keep_copy: bool = False
    expected_updated_at: Optional[str] = None


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


class DraftLifecycleTelemetryRequest(BaseModel):
    event: Literal["save_success", "save_fail", "load_success", "load_fail", "delete_success", "delete_fail", "publish_from_draft"]
    outcome: Literal["success", "fail"]
    reason_code: Optional[str] = Field(default=None, max_length=120)
    surface: Literal["composer", "unknown"] = "composer"


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


def _resolve_post_lifecycle_fields(post: Dict[str, Any]) -> Tuple[Literal["scheduled", "published", "cancelled"], Optional[int], Optional[str], Optional[str], Optional[str]]:
    raw_status = str(post.get("status") or "").strip().lower()
    status: Literal["scheduled", "published", "cancelled"]
    if raw_status in {"scheduled", "published", "cancelled"}:
        status = raw_status
    else:
        status = "published"

    publish_at_raw = post.get("publish_at")
    try:
        publish_at = int(publish_at_raw) if publish_at_raw is not None else None
    except (TypeError, ValueError):
        publish_at = None

    published_at_raw = post.get("published_at")
    published_at = published_at_raw.strip() if isinstance(published_at_raw, str) and published_at_raw.strip() else None
    if not published_at and status == "published":
        created_at_raw = post.get("created_at")
        if isinstance(created_at_raw, str) and created_at_raw.strip():
            published_at = created_at_raw.strip()

    schedule_timezone_raw = post.get("schedule_timezone")
    schedule_timezone = schedule_timezone_raw.strip() if isinstance(schedule_timezone_raw, str) and schedule_timezone_raw.strip() else None

    scheduled_at_local_raw = post.get("scheduled_at_local")
    scheduled_at_local = scheduled_at_local_raw.strip() if isinstance(scheduled_at_local_raw, str) and scheduled_at_local_raw.strip() else None

    if status != "scheduled":
        publish_at = None
        schedule_timezone = None
        scheduled_at_local = None

    return status, publish_at, published_at, schedule_timezone, scheduled_at_local


def _write_feed_ref_for_published_post(*, user_id: str, post_id: str, created_at: str) -> None:
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


def _write_scheduled_post_ref(
    *,
    user_id: str,
    post_id: str,
    created_at: str,
    publish_at: int,
    schedule_timezone: Optional[str] = None,
    scheduled_at_local: Optional[str] = None,
) -> None:
    scheduled_ref = {
        "pk": pk_user(user_id),
        "sk": sk_scheduled_post_ref(publish_at, post_id),
        "Entity": "ScheduledPostRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "status": "scheduled",
        "publish_at": publish_at,
        "schedule_timezone": schedule_timezone,
        "scheduled_at_local": scheduled_at_local,
        "created_at": created_at,
    }
    ddb_put_item(scheduled_ref)


def _post_to_dict(post: Dict[str, Any], locked_body: bool = False, liked_by_me: bool = False, unlocked: bool = False, viewer_id: Optional[str] = None) -> Dict[str, Any]:
    """Map a raw DDB post item to the FeedPost shape expected by the frontend."""
    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, body_version = _resolve_read_body_fields(post)
    status, publish_at, published_at, schedule_timezone, scheduled_at_local = _resolve_post_lifecycle_fields(post)

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
        "published_at": published_at,
        "status": status,
        "publish_at": publish_at,
        "schedule_timezone": schedule_timezone,
        "scheduled_at_local": scheduled_at_local,
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


def _dedupe_strs(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _validate_and_normalize_draft_image_urls(*, user_id: str, image_urls: List[str]) -> List[str]:
    normalized: List[str] = []
    for idx, raw in enumerate(image_urls):
        if not isinstance(raw, str):
            raise ValueError(f"invalid_draft_payload: image_urls[{idx}] must be a string")
        url = raw.strip()
        if not url:
            raise ValueError(f"invalid_draft_payload: image_urls[{idx}] cannot be empty")
        if len(url) > 2048:
            raise ValueError(f"invalid_draft_payload: image_urls[{idx}] exceeds max length (2048)")
        if url.startswith("/uploads/object"):
            parsed = urlparse(url)
            query = parse_qs(parsed.query or "")
            s3_key = ((query.get("s3_key") or [""])[0] or "").strip()
            if not s3_key:
                raise ValueError(f"invalid_draft_payload: image_urls[{idx}] missing s3_key")
            owner_prefix = f"uploads/{user_id}/"
            if not s3_key.startswith(owner_prefix):
                raise ValueError(
                    f"invalid_draft_payload: image_urls[{idx}] must reference an upload owned by the current user"
                )
            normalized.append(url)
            continue
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(
                f"invalid_draft_payload: image_urls[{idx}] must be an https URL or an /uploads/object URL"
            )
        normalized.append(url)
    return _dedupe_strs(normalized)[:10]


def _validate_and_normalize_draft_file_paths(*, user_id: str, file_paths: List[str]) -> List[str]:
    normalized: List[str] = []
    for idx, raw in enumerate(file_paths):
        if not isinstance(raw, str):
            raise ValueError(f"invalid_draft_payload: file_paths[{idx}] must be a string")
        if not raw.strip():
            raise ValueError(f"invalid_draft_payload: file_paths[{idx}] cannot be empty")
        try:
            clean = norm_path(raw, is_folder=False)
            get_node(user_id, clean)
        except HTTPException as exc:
            if exc.status_code in {400, 403, 404}:
                raise ValueError(
                    f"invalid_draft_payload: file_paths[{idx}] must reference an existing file owned by the current user"
                ) from exc
            raise
        normalized.append(clean)
    return _dedupe_strs(normalized)[:5]


def _validate_and_normalize_unlock_price(unlock_price_cents: Optional[int]) -> Optional[int]:
    if unlock_price_cents is None:
        return None
    cents = int(unlock_price_cents)
    if cents <= 0:
        raise ValueError("invalid_draft_payload: unlock_price_cents must be greater than zero when provided")
    if cents > 10_000_000:
        raise ValueError("invalid_draft_payload: unlock_price_cents exceeds max allowed value")
    return cents


def _validate_and_normalize_draft_payload(*, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(payload)
    normalized["image_urls"] = _validate_and_normalize_draft_image_urls(
        user_id=user_id,
        image_urls=list(normalized.get("image_urls") or []),
    )
    normalized["file_paths"] = _validate_and_normalize_draft_file_paths(
        user_id=user_id,
        file_paths=list(normalized.get("file_paths") or []),
    )
    normalized["unlock_price_cents"] = _validate_and_normalize_unlock_price(
        normalized.get("unlock_price_cents")
    )
    return normalized


def _build_file_attachments_for_post(*, user_id: str, file_paths: List[str]) -> List[Dict[str, Any]]:
    attachments: List[Dict[str, Any]] = []
    for idx, fp in enumerate(file_paths[:5]):
        try:
            node_path = norm_path(fp, is_folder=False)
            node = get_node(user_id, node_path)
        except HTTPException as exc:
            if exc.status_code in {400, 403, 404}:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid attachment reference at file_paths[{idx}]: file is missing or not accessible",
                ) from exc
            raise
        attachments.append({
            "path": node_path,
            "name": node.get("name") or node_path.rsplit("/", 1)[-1],
            "content_type": node.get("content_type"),
            "size": int(node["size"]) if node.get("size") is not None else None,
            "owner": user_id,
        })
    return attachments


def _draft_payload_from_create(*, user_id: str, req: CreateDraftPostRequest) -> Dict[str, Any]:
    content = _content_from_payload(req)
    payload = {
        **content,
        "image_urls": list(req.image_urls or []),
        "file_paths": list(req.file_paths or []),
        "unlock_price_cents": req.unlock_price_cents,
    }
    return _validate_and_normalize_draft_payload(user_id=user_id, payload=payload)


def _draft_item_to_response(item: Dict[str, Any]) -> DraftPostResponse:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    return DraftPostResponse(
        draft_id=str(item.get("draft_id") or ""),
        author_id=str(item.get("author_id") or ""),
        created_at=str(item.get("created_at") or ""),
        updated_at=str(item.get("updated_at") or item.get("created_at") or ""),
        body=payload.get("body"),
        body_plain=payload.get("body_plain"),
        body_markdown=payload.get("body_markdown"),
        body_rich=payload.get("body_rich"),
        body_format=payload.get("body_format"),
        body_version=int(payload.get("body_version") or 1),
        image_urls=list(payload.get("image_urls") or []),
        file_paths=list(payload.get("file_paths") or []),
        unlock_price_cents=payload.get("unlock_price_cents"),
    )


def _get_draft_or_404(*, user_id: str, draft_id: str) -> Dict[str, Any]:
    item = ddb_get_item({"pk": pk_user(user_id), "sk": sk_draft(draft_id)})
    if not item or item.get("entity_type") != "draft_post":
        raise HTTPException(status_code=404, detail="Draft not found")
    if item.get("author_id") != user_id:
        # defensive: if key schema ever changes, keep ownership checks explicit
        raise HTTPException(status_code=404, detail="Draft not found")
    return item


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
@router.post("/posts/drafts", response_model=DraftPostResponse)
def create_draft_post(req: CreateDraftPostRequest, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    try:
        _enforce_draft_count_quota(user_id)
        draft_id = new_id("draft")
        payload = _draft_payload_from_create(user_id=user_id, req=req)
        _enforce_draft_payload_size(payload)
        item = build_draft_item(user_id=user_id, draft_id=draft_id, payload=payload)
        ddb_put_item(item)
        _emit_newsfeed_draft_metric("save_success", outcome="success", operation="create")
        return _draft_item_to_response(item)
    except ValueError as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="create", reason_code="validation_error")
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="create", reason_code=f"http_{exc.status_code}")
        raise


@router.get("/posts/drafts", response_model=ListDraftPostsResponse)
def list_draft_posts(
    user_id: UserIdDep,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    _ensure_drafts_feature_enabled(user_id)
    query = build_draft_list_query(user_id=user_id, cursor=cursor, limit=limit)
    resp = ddb_query(**query)
    items = [_draft_item_to_response(it) for it in (resp.get("Items") or []) if it.get("entity_type") == "draft_post"]
    return ListDraftPostsResponse(items=items, next_cursor=encode_cursor(resp.get("LastEvaluatedKey")))


@router.get("/posts/drafts/{draft_id}", response_model=DraftPostResponse)
def get_draft_post(draft_id: str, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    try:
        item = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _emit_newsfeed_draft_metric("load_success", outcome="success")
        return _draft_item_to_response(item)
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("load_fail", outcome="fail", reason_code=f"http_{exc.status_code}")
        raise


@router.patch("/posts/drafts/{draft_id}", response_model=DraftPostResponse)
def update_draft_post(draft_id: str, req: UpdateDraftPostRequest, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    try:
        existing = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _enforce_draft_expected_updated_at(
            expected_updated_at=req.expected_updated_at,
            existing_item=existing,
        )
        current_payload = existing.get("payload") if isinstance(existing.get("payload"), dict) else {}

        patch = req.model_dump(exclude_unset=True, exclude={"expected_updated_at"})
        merged: Dict[str, Any] = {**current_payload, **patch}

        # Validate merged content with create validator for parity with publish content rules.
        CreateDraftPostRequest(**merged)

        merged = _validate_and_normalize_draft_payload(user_id=user_id, payload=merged)
        _enforce_draft_payload_size(merged)

        updated_at = now_iso()
        item = build_draft_item(
            user_id=user_id,
            draft_id=draft_id,
            payload=merged,
            created_at=str(existing.get("created_at") or updated_at),
            updated_at=updated_at,
        )
        ddb_put_item(item)
        _emit_newsfeed_draft_metric("save_success", outcome="success", operation="update")
        return _draft_item_to_response(item)
    except ValueError as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="update", reason_code="validation_error")
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="update", reason_code=f"http_{exc.status_code}")
        raise


@router.delete("/posts/drafts/{draft_id}")
def delete_draft_post(
    draft_id: str,
    user_id: UserIdDep,
    expected_updated_at: Optional[str] = Query(default=None),
):
    _ensure_drafts_feature_enabled(user_id)
    try:
        existing = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _enforce_draft_expected_updated_at(
            expected_updated_at=expected_updated_at,
            existing_item=existing,
        )
        ddb_delete_item({"pk": pk_user(user_id), "sk": sk_draft(draft_id)})
        _emit_newsfeed_draft_metric("delete_success", outcome="success")
        return {"ok": True}
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("delete_fail", outcome="fail", reason_code=f"http_{exc.status_code}")
        raise


@router.post("/posts/drafts/{draft_id}/publish", response_model=PostResponse)
def publish_draft_post(
    draft_id: str,
    req: PublishDraftPostRequest,
    user_id: UserIdDep,
):
    _ensure_drafts_feature_enabled(user_id)
    try:
        draft_item = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _enforce_draft_expected_updated_at(
            expected_updated_at=req.expected_updated_at,
            existing_item=draft_item,
        )
        payload = draft_item.get("payload") if isinstance(draft_item.get("payload"), dict) else {}
        if not payload:
            raise HTTPException(status_code=422, detail="Draft payload is empty")

        payload = _validate_and_normalize_draft_payload(user_id=user_id, payload=payload)
    except ValueError as exc:
        _emit_newsfeed_draft_metric("publish_from_draft", outcome="fail", reason_code="attachment_validation_error")
        raise HTTPException(status_code=422, detail=f"Invalid draft attachment reference: {exc}") from exc
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("publish_from_draft", outcome="fail", reason_code=f"http_{exc.status_code}")
        raise

    try:
        post_req = CreatePostRequest(**payload)
    except ValidationError as exc:
        _emit_newsfeed_draft_metric("publish_from_draft", outcome="fail", reason_code="payload_validation_error")
        raise HTTPException(status_code=422, detail=f"Invalid draft payload: {exc.errors()}") from exc

    published = create_post(post_req, user_id)
    _emit_newsfeed_draft_metric("publish_from_draft", outcome="success")

    if not req.keep_copy:
        try:
            ddb_delete_item({"pk": pk_user(user_id), "sk": sk_draft(draft_id)})
        except Exception:
            logger.exception("draft cleanup failed after publish", extra={"user_id": user_id, "draft_id": draft_id})

    return published


@router.post(
    "/posts",
    response_model=PostResponse,
    responses={
        400: {
            "description": "Invalid schedule payload",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_timezone": {
                            "summary": "Invalid IANA timezone",
                            "value": {
                                "detail": {
                                    "code": "schedule_timezone_invalid",
                                    "message": "schedule_timezone must be a valid IANA timezone",
                                    "field": "schedule_timezone",
                                }
                            },
                        },
                        "publish_at_too_soon": {
                            "summary": "Publish time must be in the future",
                            "value": {
                                "detail": {
                                    "code": "schedule_publish_at_too_soon",
                                    "message": "publish_at must be at least 5 seconds in the future",
                                    "field": "publish_at",
                                    "minimum_publish_at": 1767000006,
                                }
                            },
                        },
                    }
                }
            },
        }
    },
)
def create_post(req: CreatePostRequest, user_id: UserIdDep):
    """
    Create a newsfeed post immediately or schedule it for later publication.

    Immediate create (no `publish_at`) publishes now and appears in the feed.
    Scheduled create (with `publish_at`) persists with `status=scheduled` and is excluded from feed until publish time.
    """
    _enforce_newsfeed_post_quota_precheck(user_id=user_id)
    post_id = new_id("post")
    created_at = now_iso()
    now_ts = int(time.time())

    has_schedule_metadata = bool(req.schedule_timezone or req.scheduled_at_local)
    if req.publish_at is not None or has_schedule_metadata:
        _require_newsfeed_scheduling_api_enabled()
    if req.publish_at is None and has_schedule_metadata:
        raise _schedule_payload_error(
            code="schedule_publish_at_required",
            field="publish_at",
            message="publish_at is required when schedule_timezone or scheduled_at_local is provided",
            operation="create",
        )

    is_scheduled = req.publish_at is not None
    if is_scheduled:
        min_lead = _schedule_min_lead_seconds()
        max_horizon = _schedule_max_horizon_seconds()
        max_publish_at = now_ts + max_horizon
        if req.publish_at is None or req.publish_at <= now_ts + min_lead:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_soon",
                field="publish_at",
                message=f"publish_at must be at least {min_lead} seconds in the future",
                extra={"minimum_publish_at": now_ts + min_lead + 1},
                operation="create",
            )
        if int(req.publish_at) > max_publish_at:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_far",
                field="publish_at",
                message=f"publish_at must be within {max_horizon} seconds from now",
                extra={"maximum_publish_at": max_publish_at},
                operation="create",
            )
        if not req.schedule_timezone:
            raise _schedule_payload_error(
                code="schedule_timezone_required",
                field="schedule_timezone",
                message="schedule_timezone is required when publish_at is set",
                operation="create",
            )
        try:
            ZoneInfo(req.schedule_timezone)
        except Exception as exc:
            raise _schedule_payload_error(
                code="schedule_timezone_invalid",
                field="schedule_timezone",
                message="schedule_timezone must be a valid IANA timezone",
                operation="create",
            ) from exc
        if req.scheduled_at_local and not _SCHEDULED_LOCAL_RE.fullmatch(req.scheduled_at_local):
            raise _schedule_payload_error(
                code="schedule_local_datetime_invalid",
                field="scheduled_at_local",
                message="scheduled_at_local must use format YYYY-MM-DDTHH:mm",
                operation="create",
            )

    unlock_price_cents = req.unlock_price_cents if req.unlock_price_cents and req.unlock_price_cents > 0 else None
    locked = unlock_price_cents is not None
    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("create_post", surface="post", body_format=content.get("body_format", "plain"))

    # Validate and collect file attachment metadata (max 5)
    file_attachments = _build_file_attachments_for_post(user_id=user_id, file_paths=req.file_paths)

    post_item = {
        "pk": pk_post(post_id),
        "sk": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "published_at": None if is_scheduled else created_at,
        "status": "scheduled" if is_scheduled else "published",
        "publish_at": req.publish_at if is_scheduled else None,
        "schedule_timezone": req.schedule_timezone if is_scheduled else None,
        "scheduled_at_local": req.scheduled_at_local if is_scheduled else None,
        **content,
        "image_urls": req.image_urls,
        "visibility": req.visibility,
        "locked": locked,
        "unlock_price_cents": unlock_price_cents,
        "like_count": 0,
        "comment_count": 0,
        "file_attachments": file_attachments,
    }
    if is_scheduled:
        post_item.update(schedule_due_index_values(req.publish_at or 0, post_id))
    ddb_put_item(post_item)

    if not is_scheduled:
        _write_feed_ref_for_published_post(user_id=user_id, post_id=post_id, created_at=created_at)
        _meter_newsfeed_post_publish(user_id=user_id, post_id=post_id)
    else:
        record_newsfeed_schedule_operation(operation="create", outcome="success")
        _write_scheduled_post_ref(
            user_id=user_id,
            post_id=post_id,
            created_at=created_at,
            publish_at=req.publish_at or 0,
            schedule_timezone=req.schedule_timezone,
            scheduled_at_local=req.scheduled_at_local,
        )

    return PostResponse(
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        published_at=None if is_scheduled else created_at,
        status="scheduled" if is_scheduled else "published",
        publish_at=req.publish_at if is_scheduled else None,
        schedule_timezone=req.schedule_timezone if is_scheduled else None,
        scheduled_at_local=req.scheduled_at_local if is_scheduled else None,
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


@router.get(
    "/posts/scheduled",
    response_model=ScheduledPostsResponse,
)
def list_scheduled_posts(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    """List caller-owned scheduled posts in stable publish-time order (oldest scheduled publish first)."""
    _require_newsfeed_scheduling_api_enabled()
    eks = decode_cursor_or_400(cursor)
    resp = ddb_query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={
            ":pk": pk_user(user_id),
            ":prefix": f"{SCHEDULED_POST_REF_PREFIX}#",
        },
        ScanIndexForward=True,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    refs = resp.get("Items", [])
    parsed_refs: List[Tuple[int, str]] = []
    for ref in refs:
        post_id = str(ref.get("post_id") or "").strip()
        parsed = parse_scheduled_post_ref_sk(str(ref.get("sk") or ""))
        if not post_id or parsed is None:
            continue
        publish_at, parsed_post_id = parsed
        if parsed_post_id != post_id:
            continue
        parsed_refs.append((publish_at, post_id))

    parsed_refs.sort(key=lambda row: (row[0], row[1]))
    post_ids = [post_id for _publish_at, post_id in parsed_refs]
    posts: List[Dict[str, Any]] = []
    if post_ids:
        keys = [{"pk": pk_post(pid), "sk": sk_post()} for pid in post_ids]
        try:
            raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": keys}})
            posts = raw.get("Responses", {}).get(APP_TABLE, [])
        except ClientError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"DDB batch_get_item error: {exc.response['Error'].get('Message','unknown')}",
            ) from exc

    post_by_id = {post.get("post_id"): post for post in posts if post.get("post_id")}
    ordered: List[Dict[str, Any]] = []
    for _publish_at, post_id in parsed_refs:
        post = post_by_id.get(post_id)
        if not post:
            continue
        if post.get("user_id") != user_id:
            continue
        if str(post.get("status") or "").strip().lower() != "scheduled":
            continue
        ordered.append(_post_to_dict(post, viewer_id=user_id))

    return {"items": ordered, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


@router.patch("/posts/{post_id}")
def edit_post(post_id: str, req: EditPostRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("edit_post", surface="post", body_format=content.get("body_format", "plain"))
    schedule_fields_in_payload = bool({"publish_at", "schedule_timezone", "scheduled_at_local"} & req.model_fields_set)
    if schedule_fields_in_payload:
        _require_newsfeed_scheduling_api_enabled()
    schedule_updates: Dict[str, Any] = {}
    if schedule_fields_in_payload:
        if str(post.get("status") or "").strip().lower() != "scheduled":
            record_newsfeed_schedule_operation(operation="edit", outcome="rejected")
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "schedule_update_not_allowed",
                    "message": "schedule metadata can only be updated for scheduled posts",
                },
            )
        now_ts = int(time.time())
        min_lead = _schedule_min_lead_seconds()
        max_horizon = _schedule_max_horizon_seconds()
        max_publish_at = now_ts + max_horizon
        publish_at = req.publish_at if "publish_at" in req.model_fields_set else post.get("publish_at")
        schedule_timezone = req.schedule_timezone if "schedule_timezone" in req.model_fields_set else post.get("schedule_timezone")
        scheduled_at_local = req.scheduled_at_local if "scheduled_at_local" in req.model_fields_set else post.get("scheduled_at_local")

        if publish_at is None or int(publish_at) <= now_ts + min_lead:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_soon",
                field="publish_at",
                message=f"publish_at must be at least {min_lead} seconds in the future",
                extra={"minimum_publish_at": now_ts + min_lead + 1},
                operation="edit",
            )
        if int(publish_at) > max_publish_at:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_far",
                field="publish_at",
                message=f"publish_at must be within {max_horizon} seconds from now",
                extra={"maximum_publish_at": max_publish_at},
                operation="edit",
            )
        if not schedule_timezone:
            raise _schedule_payload_error(
                code="schedule_timezone_required",
                field="schedule_timezone",
                message="schedule_timezone is required when updating schedule metadata",
                operation="edit",
            )
        try:
            ZoneInfo(str(schedule_timezone))
        except Exception as exc:
            raise _schedule_payload_error(
                code="schedule_timezone_invalid",
                field="schedule_timezone",
                message="schedule_timezone must be a valid IANA timezone",
                operation="edit",
            ) from exc
        if scheduled_at_local is not None and (not isinstance(scheduled_at_local, str) or not _SCHEDULED_LOCAL_RE.fullmatch(scheduled_at_local)):
            raise _schedule_payload_error(
                code="schedule_local_datetime_invalid",
                field="scheduled_at_local",
                message="scheduled_at_local must use format YYYY-MM-DDTHH:mm",
                operation="edit",
            )
        schedule_updates = {
            "publish_at": int(publish_at),
            "schedule_timezone": str(schedule_timezone),
            "scheduled_at_local": scheduled_at_local,
        }

    image_urls_in_payload = "image_urls" in req.model_fields_set
    set_parts = [
        "#body = :b",
        "body_plain = :bp",
        "body_markdown = :bm",
        "body_markdown_html = :bmh",
        "body_rich = :br",
        "body_format = :bf",
        "body_version = :bv",
        "updated_at = :u",
    ]
    expr_vals: Dict[str, Any] = {
        ":b": content["body"],
        ":bp": content["body_plain"],
        ":bm": content["body_markdown"],
        ":bmh": content["body_markdown_html"],
        ":br": content["body_rich"],
        ":bf": content["body_format"],
        ":bv": content["body_version"],
        ":u": now_iso(),
    }
    if schedule_updates:
        set_parts.extend(
            [
                "publish_at = :pa",
                "schedule_timezone = :stz",
                "scheduled_at_local = :sal",
                f"{SCHEDULE_DUE_INDEX_PK_ATTR} = :sdpk",
                f"{SCHEDULE_DUE_INDEX_SK_ATTR} = :sdsk",
            ]
        )
        expr_vals[":pa"] = schedule_updates["publish_at"]
        expr_vals[":stz"] = schedule_updates["schedule_timezone"]
        expr_vals[":sal"] = schedule_updates["scheduled_at_local"]
        due_values = schedule_due_index_values(schedule_updates["publish_at"], post_id)
        expr_vals[":sdpk"] = due_values[SCHEDULE_DUE_INDEX_PK_ATTR]
        expr_vals[":sdsk"] = due_values[SCHEDULE_DUE_INDEX_SK_ATTR]

    if image_urls_in_payload and req.image_urls:
        update_expr = f"SET {', '.join(set_parts)}, image_urls = :imgs"
        expr_vals[":imgs"] = req.image_urls
    elif image_urls_in_payload:
        update_expr = f"SET {', '.join(set_parts)} REMOVE image_urls"
    else:
        update_expr = f"SET {', '.join(set_parts)}"
    if schedule_updates:
        condition_expr = "#user = :uid AND #status = :scheduled"
        expr_vals_tx = dict(expr_vals)
        expr_vals_tx[":uid"] = user_id
        expr_vals_tx[":scheduled"] = "scheduled"

        old_publish_at = int(post.get("publish_at") or 0)
        old_ref_sk = sk_scheduled_post_ref(old_publish_at, post_id)
        new_ref_sk = sk_scheduled_post_ref(int(schedule_updates["publish_at"]), post_id)
        transact_items: List[Dict[str, Any]] = [
            {
                "Update": {
                    "TableName": APP_TABLE,
                    "Key": _ddb_serialize_map({"pk": pk_post(post_id), "sk": sk_post()}),
                    "UpdateExpression": update_expr,
                    "ExpressionAttributeNames": {"#body": "body", "#status": "status", "#user": "user_id"},
                    "ExpressionAttributeValues": _ddb_serialize_map(expr_vals_tx),
                    "ConditionExpression": condition_expr,
                }
            }
        ]
        if old_ref_sk != new_ref_sk:
            transact_items.append(
                {
                    "Delete": {
                        "TableName": APP_TABLE,
                        "Key": _ddb_serialize_map({"pk": pk_user(user_id), "sk": old_ref_sk}),
                    }
                }
            )
            transact_items.append(
                {
                    "Put": {
                        "TableName": APP_TABLE,
                        "Item": _ddb_serialize_map(
                            {
                                "pk": pk_user(user_id),
                                "sk": new_ref_sk,
                                "Entity": "ScheduledPostRef",
                                "post_id": post_id,
                                "owner_user_id": user_id,
                                "status": "scheduled",
                                "publish_at": int(schedule_updates["publish_at"]),
                                "schedule_timezone": schedule_updates["schedule_timezone"],
                                "scheduled_at_local": schedule_updates.get("scheduled_at_local"),
                                "created_at": post.get("created_at") or now_iso(),
                            }
                        ),
                    }
                }
            )
        try:
            ddb.meta.client.transact_write_items(TransactItems=transact_items)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                record_newsfeed_schedule_operation(operation="edit", outcome="conflict")
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "schedule_edit_conflict",
                        "message": "schedule update conflicted with concurrent modification",
                    },
                ) from exc
            record_newsfeed_schedule_operation(operation="edit", outcome="error")
            raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc
        updated = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()}) or {}
        record_newsfeed_schedule_operation(operation="edit", outcome="success")
    else:
        updated = ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr=update_expr,
            expr_names={"#body": "body"},
            expr_vals=expr_vals,
        )
    return _post_to_dict(updated, viewer_id=user_id)


@router.post("/posts/{post_id}/cancel")
def cancel_scheduled_post(post_id: str, user_id: UserIdDep):
    _require_newsfeed_scheduling_api_enabled()
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")

    status = str(post.get("status") or "").strip().lower()
    if status == "cancelled":
        record_newsfeed_schedule_operation(operation="cancel", outcome="noop")
        return _post_to_dict(post, viewer_id=user_id)
    if status != "scheduled":
        record_newsfeed_schedule_operation(operation="cancel", outcome="rejected")
        raise HTTPException(
            status_code=409,
            detail={
                "code": "schedule_cancel_not_allowed",
                "message": "only scheduled posts can be cancelled",
            },
        )

    publish_at = post.get("publish_at")
    try:
        publish_at_int = int(publish_at)
    except Exception as exc:
        record_newsfeed_schedule_operation(operation="cancel", outcome="invalid_state")
        raise HTTPException(
            status_code=409,
            detail={
                "code": "schedule_cancel_not_allowed",
                "message": "scheduled post has invalid publish_at",
            },
        ) from exc

    now = now_iso()
    ref_sk = sk_scheduled_post_ref(publish_at_int, post_id)
    transact_items: List[Dict[str, Any]] = [
        {
            "Update": {
                "TableName": APP_TABLE,
                "Key": _ddb_serialize_map({"pk": pk_post(post_id), "sk": sk_post()}),
                "UpdateExpression": f"SET #status = :cancelled, updated_at = :u, published_at = :null, publish_at = :null, schedule_timezone = :null, scheduled_at_local = :null, {SCHEDULE_DUE_INDEX_PK_ATTR} = :null, {SCHEDULE_DUE_INDEX_SK_ATTR} = :null",
                "ConditionExpression": "#user = :uid AND #status = :scheduled",
                "ExpressionAttributeNames": {"#status": "status", "#user": "user_id"},
                "ExpressionAttributeValues": _ddb_serialize_map(
                    {
                        ":cancelled": "cancelled",
                        ":u": now,
                        ":null": None,
                        ":uid": user_id,
                        ":scheduled": "scheduled",
                    }
                ),
            }
        },
        {
            "Delete": {
                "TableName": APP_TABLE,
                "Key": _ddb_serialize_map({"pk": pk_user(user_id), "sk": ref_sk}),
            }
        },
    ]
    try:
        ddb.meta.client.transact_write_items(TransactItems=transact_items)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            latest = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
            latest_status = str((latest or {}).get("status") or "").strip().lower()
            if latest and latest.get("user_id") == user_id and latest_status == "cancelled":
                record_newsfeed_schedule_operation(operation="cancel", outcome="noop")
                return _post_to_dict(latest, viewer_id=user_id)
            record_newsfeed_schedule_operation(operation="cancel", outcome="conflict")
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "schedule_cancel_conflict",
                    "message": "schedule cancel conflicted with concurrent modification",
                },
            ) from exc
        record_newsfeed_schedule_operation(operation="cancel", outcome="error")
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc

    updated = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()}) or {
        **post,
        "status": "cancelled",
        "publish_at": None,
        "schedule_timezone": None,
        "scheduled_at_local": None,
        "published_at": None,
        "updated_at": now,
    }
    record_newsfeed_schedule_operation(operation="cancel", outcome="success")
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
        status, _publish_at, _published_at, _schedule_timezone, _scheduled_at_local = _resolve_post_lifecycle_fields(post)
        if status != "published":
            continue
        if post.get("moderation_removed") or post.get("moderation_removed_at"):
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
    items = [
        _comment_to_dict(it)
        for it in resp.get("Items", [])
        if not it.get("moderation_removed")
    ]
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
        update_expr="SET deleted = :t, #body = :null, body_plain = :null, body_markdown = :null, body_rich = :null, updated_at = :u",
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


@router.post("/telemetry/draft-lifecycle")
def draft_lifecycle_telemetry(req: DraftLifecycleTelemetryRequest, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    _emit_newsfeed_draft_metric(
        req.event,
        outcome=req.outcome,
        source="frontend",
        reason_code=req.reason_code,
        surface=req.surface,
    )
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
