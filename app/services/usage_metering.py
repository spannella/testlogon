from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Literal, Optional, TypedDict

from botocore.exceptions import ClientError

from app.core.settings import S
from app.metrics import (
    record_usage_metering_bytes,
    record_usage_metering_event,
    record_usage_metering_pipeline_error,
    record_usage_metering_pipeline_latency,
    record_usage_surface_transfer_bytes,
    record_usage_surface_units,
)
import time

UsageEventType = Literal["upload", "download", "storage_delta"]

# Canonical usage sources. Keep this list additive/backward compatible so
# existing metering sources used by file manager continue to work.
USAGE_EVENT_SOURCES: frozenset[str] = frozenset(
    {
        # File manager/upload flows
        "api_upload",
        "presign_complete",
        "upload_archive_entry",
        "upload_archive_total",
        "upload_zip_total",
        # File manager/download flows
        "download",
        "download_file",
        "download_zip",
        "shared_download",
        "shared_download_zip",
        # File manager/storage delta flows
        "upload_create",
        "complete_upload_create",
        "delete_soft",
        "move_folder",
        "move_file",
        "purge_finalize",
        # Messaging/newsfeed taxonomy (MTR-001)
        "messaging_send",
        "newsfeed_post",
        "messaging_attachment_upload",
        "messaging_attachment_download",
        "newsfeed_attachment_upload",
        "newsfeed_attachment_download",
    }
)


def build_usage_source_idempotency_key(source: str, **parts: str) -> str:
    """Build a deterministic idempotency key for a known usage source.

    This helper is intentionally narrow for taxonomy-defined sources and leaves
    `build_usage_event(..., idempotency_key=...)` as the compatibility escape hatch
    for legacy/custom sources.
    """

    source_name = source.strip()
    if source_name not in USAGE_EVENT_SOURCES:
        raise ValueError(f"Unknown usage source '{source_name}'")

    if source_name == "messaging_send":
        return "|".join(
            [
                parts["user_id"],
                source_name,
                parts["conversation_id"],
                parts["message_id"],
            ]
        )

    if source_name == "newsfeed_post":
        return "|".join([parts["user_id"], source_name, parts["post_id"]])

    if source_name in {
        "messaging_attachment_upload",
        "messaging_attachment_download",
        "newsfeed_attachment_upload",
        "newsfeed_attachment_download",
    }:
        return "|".join(
            [
                parts["user_id"],
                source_name,
                parts["attachment_key"],
                parts.get("operation_id", ""),
            ]
        )

    raise ValueError(
        f"Source '{source_name}' does not have a dedicated idempotency-key pattern; "
        "pass idempotency_key directly to build_usage_event for compatibility flows"
    )


class UsageEvent(TypedDict):
    event_id: str
    user_id: str
    event_type: UsageEventType
    bytes: int
    resource_path: Optional[str]
    timestamp: str
    request_id: Optional[str]
    source: str
    idempotency_key: str


class UsagePeriodTotals(TypedDict):
    PK: str
    SK: str
    entity_type: str
    user_id: str
    period_id: str
    upload_bytes_total: int
    download_bytes_total: int
    storage_bytes_current: int
    storage_bytes_peak: int
    storage_byte_seconds: int
    message_send_count_total: int
    post_publish_count_total: int
    updated_at: str


class UsageDaily(TypedDict):
    PK: str
    SK: str
    entity_type: str
    user_id: str
    day_utc: str
    period_id: str
    upload_bytes_total: int
    download_bytes_total: int
    storage_bytes_end_of_day: int
    message_send_count_total: int
    post_publish_count_total: int
    updated_at: str


class BillingUsageSnapshot(TypedDict):
    PK: str
    SK: str
    entity_type: str
    user_id: str
    period_id: str
    version: int
    status: Literal["draft", "finalized", "invoiced"]
    schema_version: int
    upload_bytes_total: int
    download_bytes_total: int
    storage_bytes_peak: int
    storage_byte_seconds: int
    message_send_count_total: int
    post_publish_count_total: int
    messaging_upload_bytes_total: int
    messaging_download_bytes_total: int
    newsfeed_upload_bytes_total: int
    newsfeed_download_bytes_total: int
    finalized_at: Optional[str]
    created_at: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: Optional[datetime] = None) -> str:
    dt = value or utc_now()
    return dt.astimezone(timezone.utc).isoformat()


def _ttl_epoch_for_days(days: int, *, base: Optional[datetime] = None) -> int:
    safe_days = max(1, int(days))
    dt = (base or utc_now()) + timedelta(days=safe_days)
    return int(dt.timestamp())


def period_id_for_datetime(value: Optional[datetime] = None) -> str:
    dt = value or utc_now()
    dt_utc = dt.astimezone(timezone.utc)
    return f"{dt_utc.year:04d}-{dt_utc.month:02d}"


def period_id_for_timestamp(epoch_seconds: int) -> str:
    dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return period_id_for_datetime(dt)


def _parse_period_id(period_id: str) -> tuple[int, int]:
    parts = period_id.split("-")
    if len(parts) != 2:
        raise ValueError("period_id must be YYYY-MM")
    year = int(parts[0])
    month = int(parts[1])
    if month < 1 or month > 12:
        raise ValueError("period_id month must be 01..12")
    return year, month


def period_bounds_utc(period_id: str) -> tuple[datetime, datetime]:
    year, month = _parse_period_id(period_id)
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    if month == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return start, end


def usage_event_id_from_idempotency_key(idempotency_key: str) -> str:
    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]
    return f"uev_{digest}"


def build_usage_event(
    *,
    user_id: str,
    event_type: UsageEventType,
    bytes_count: int,
    source: str,
    resource_path: Optional[str] = None,
    request_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> UsageEvent:
    if event_type in {"upload", "download"} and bytes_count < 0:
        raise ValueError("bytes_count must be >= 0 for upload/download events")
    ts = timestamp or iso_utc()
    key = idempotency_key or "|".join(
        [
            user_id,
            event_type,
            source,
            request_id or "",
            resource_path or "",
            str(bytes_count),
        ]
    )
    return {
        "event_id": usage_event_id_from_idempotency_key(key),
        "user_id": user_id,
        "event_type": event_type,
        "bytes": int(bytes_count),
        "resource_path": resource_path,
        "timestamp": ts,
        "request_id": request_id,
        "source": source,
        "idempotency_key": key,
    }


def build_usage_period_totals_item(*, user_id: str, period_id: str, now: Optional[str] = None) -> UsagePeriodTotals:
    _parse_period_id(period_id)
    return {
        "PK": f"USER#{user_id}",
        "SK": f"USAGE#PERIOD#{period_id}",
        "entity_type": "usage_period_totals",
        "user_id": user_id,
        "period_id": period_id,
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_current": 0,
        "storage_bytes_peak": 0,
        "storage_byte_seconds": 0,
        "message_send_count_total": 0,
        "post_publish_count_total": 0,
        "updated_at": now or iso_utc(),
    }


def build_usage_daily_item(*, user_id: str, day_utc: str, now: Optional[str] = None) -> UsageDaily:
    day_dt = datetime.fromisoformat(f"{day_utc}T00:00:00+00:00")
    return {
        "PK": f"USER#{user_id}",
        "SK": f"USAGE#DAY#{day_utc}",
        "entity_type": "usage_daily",
        "user_id": user_id,
        "day_utc": day_utc,
        "period_id": period_id_for_datetime(day_dt),
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_end_of_day": 0,
        "message_send_count_total": 0,
        "post_publish_count_total": 0,
        "updated_at": now or iso_utc(),
    }


def build_billing_usage_snapshot_item(
    *,
    user_id: str,
    period_id: str,
    version: int = 1,
    schema_version: int = 2,
    status: Literal["draft", "finalized", "invoiced"] = "draft",
    now: Optional[str] = None,
) -> BillingUsageSnapshot:
    if version < 1:
        raise ValueError("version must be >= 1")
    if schema_version < 1:
        raise ValueError("schema_version must be >= 1")
    _parse_period_id(period_id)
    created = now or iso_utc()
    return {
        "PK": f"USER#{user_id}",
        "SK": f"USAGE#SNAPSHOT#{period_id}#V{version:04d}",
        "entity_type": "billing_usage_snapshot",
        "user_id": user_id,
        "period_id": period_id,
        "version": version,
        "status": status,
        "schema_version": schema_version,
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_peak": 0,
        "storage_byte_seconds": 0,
        "message_send_count_total": 0,
        "post_publish_count_total": 0,
        "messaging_upload_bytes_total": 0,
        "messaging_download_bytes_total": 0,
        "newsfeed_upload_bytes_total": 0,
        "newsfeed_download_bytes_total": 0,
        "finalized_at": None,
        "created_at": created,
    }


def random_idempotency_key() -> str:
    return secrets.token_hex(16)


def _is_conditional_check_failed(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    return exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def record_usage_event_and_aggregates(table: Any, event: UsageEvent, *, apply_aggregates: bool = True) -> bool:
    """
    Persist usage event and increment period/daily aggregates.

    Returns True when this is a new event (aggregates updated) and False when
    the event already exists (idempotent retry; no aggregate mutation).
    """
    started = time.perf_counter()
    event_period = period_id_for_datetime(datetime.fromisoformat(event["timestamp"]))
    day_utc = event["timestamp"][:10]
    user_id = event["user_id"]

    source = str(event.get("source") or "")
    if source.startswith("messaging_") or source == "messaging_send":
        source_family = "messaging"
    elif source.startswith("newsfeed_") or source == "newsfeed_post":
        source_family = "newsfeed"
    else:
        source_family = "filemanager"

    try:
        table.put_item(
            Item={
                "PK": f"USER#{user_id}",
                "SK": f"USAGE#EVENT#{event['event_id']}",
                "entity_type": "usage_event",
                **event,
                "period_id": event_period,
                "day_utc": day_utc,
                "apply_aggregates": apply_aggregates,
                "ttl_epoch": _ttl_epoch_for_days(getattr(S, "filemgr_usage_event_retention_days", 365)),
            },
            ConditionExpression="attribute_not_exists(SK)",
        )
    except Exception as exc:
        if _is_conditional_check_failed(exc):
            record_usage_metering_event(event["event_type"], event["source"], "duplicate", period_id=event_period)
            return False
        record_usage_metering_pipeline_error("event_put")
        record_usage_metering_event(event["event_type"], event["source"], "error", period_id=event_period)
        raise

    if not apply_aggregates:
        record_usage_metering_event(event["event_type"], event["source"], "event_only", period_id=event_period)
        record_usage_metering_bytes(event["event_type"], event["source"], int(event["bytes"]), period_id=event_period)
        record_usage_metering_pipeline_latency("record_usage_event_and_aggregates", time.perf_counter() - started)
        return True

    bytes_delta = int(event["bytes"])
    upload_inc = bytes_delta if event["event_type"] == "upload" else 0
    download_inc = bytes_delta if event["event_type"] == "download" else 0
    storage_delta = bytes_delta if event["event_type"] == "storage_delta" else 0
    message_send_inc = 1 if event.get("source") == "messaging_send" else 0
    post_publish_inc = 1 if event.get("source") == "newsfeed_post" else 0
    now = iso_utc()

    try:
        table.update_item(
            Key={"PK": f"USER#{user_id}", "SK": f"USAGE#PERIOD#{event_period}"},
            UpdateExpression=(
                "SET entity_type = if_not_exists(entity_type, :entity_type), "
                "user_id = if_not_exists(user_id, :user_id), "
                "period_id = if_not_exists(period_id, :period_id), "
                "upload_bytes_total = if_not_exists(upload_bytes_total, :z) + :upload_inc, "
                "download_bytes_total = if_not_exists(download_bytes_total, :z) + :download_inc, "
                "storage_bytes_current = if_not_exists(storage_bytes_current, :z) + :storage_delta, "
                "storage_bytes_peak = if_not_exists(storage_bytes_peak, :z), "
                "storage_byte_seconds = if_not_exists(storage_byte_seconds, :z), "
                "message_send_count_total = if_not_exists(message_send_count_total, :z) + :message_send_inc, "
                "post_publish_count_total = if_not_exists(post_publish_count_total, :z) + :post_publish_inc, "
                "updated_at = :updated_at, "
                "ttl_epoch = :ttl_epoch"
            ),
            ExpressionAttributeValues={
                ":entity_type": "usage_period_totals",
                ":user_id": user_id,
                ":period_id": event_period,
                ":z": 0,
                ":upload_inc": upload_inc,
                ":download_inc": download_inc,
                ":storage_delta": storage_delta,
                ":message_send_inc": message_send_inc,
                ":post_publish_inc": post_publish_inc,
                ":updated_at": now,
                ":ttl_epoch": _ttl_epoch_for_days(getattr(S, "filemgr_usage_aggregate_retention_days", 1095)),
            },
        )
    except Exception:
        record_usage_metering_pipeline_error("period_aggregate_update")
        record_usage_metering_event(event["event_type"], event["source"], "error", period_id=event_period)
        raise

    try:
        table.update_item(
            Key={"PK": f"USER#{user_id}", "SK": f"USAGE#DAY#{day_utc}"},
            UpdateExpression=(
                "SET entity_type = if_not_exists(entity_type, :entity_type), "
                "user_id = if_not_exists(user_id, :user_id), "
                "day_utc = if_not_exists(day_utc, :day_utc), "
                "period_id = if_not_exists(period_id, :period_id), "
                "upload_bytes_total = if_not_exists(upload_bytes_total, :z) + :upload_inc, "
                "download_bytes_total = if_not_exists(download_bytes_total, :z) + :download_inc, "
                "storage_bytes_end_of_day = if_not_exists(storage_bytes_end_of_day, :z) + :storage_delta, "
                "message_send_count_total = if_not_exists(message_send_count_total, :z) + :message_send_inc, "
                "post_publish_count_total = if_not_exists(post_publish_count_total, :z) + :post_publish_inc, "
                "updated_at = :updated_at, "
                "ttl_epoch = :ttl_epoch"
            ),
            ExpressionAttributeValues={
                ":entity_type": "usage_daily",
                ":user_id": user_id,
                ":day_utc": day_utc,
                ":period_id": event_period,
                ":z": 0,
                ":upload_inc": upload_inc,
                ":download_inc": download_inc,
                ":storage_delta": storage_delta,
                ":message_send_inc": message_send_inc,
                ":post_publish_inc": post_publish_inc,
                ":updated_at": now,
                ":ttl_epoch": _ttl_epoch_for_days(getattr(S, "filemgr_usage_aggregate_retention_days", 1095)),
            },
        )
    except Exception:
        record_usage_metering_pipeline_error("daily_aggregate_update")
        record_usage_metering_event(event["event_type"], event["source"], "error", period_id=event_period)
        raise

    record_usage_metering_event(event["event_type"], event["source"], "applied", period_id=event_period)
    record_usage_metering_bytes(event["event_type"], event["source"], int(event["bytes"]), period_id=event_period)
    if message_send_inc:
        record_usage_surface_units(source_family, "message_send", message_send_inc, period_id=event_period)
    if post_publish_inc:
        record_usage_surface_units(source_family, "post_publish", post_publish_inc, period_id=event_period)
    if event["event_type"] == "upload" and int(event["bytes"]) > 0:
        record_usage_surface_transfer_bytes(source_family, "upload", int(event["bytes"]), period_id=event_period)
    if event["event_type"] == "download" and int(event["bytes"]) > 0:
        record_usage_surface_transfer_bytes(source_family, "download", int(event["bytes"]), period_id=event_period)
    record_usage_metering_pipeline_latency("record_usage_event_and_aggregates", time.perf_counter() - started)
    return True


__all__ = [
    "UsageEvent",
    "UsagePeriodTotals",
    "UsageDaily",
    "BillingUsageSnapshot",
    "period_id_for_datetime",
    "period_id_for_timestamp",
    "period_bounds_utc",
    "usage_event_id_from_idempotency_key",
    "build_usage_event",
    "build_usage_period_totals_item",
    "build_usage_daily_item",
    "build_billing_usage_snapshot_item",
    "random_idempotency_key",
    "record_usage_event_and_aggregates",
]
