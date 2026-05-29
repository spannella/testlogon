"""Delivery statistics for webhook endpoints (ENTERPRISE-005)."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _hour_bucket(ts: int | None = None) -> str:
    """Get the hourly bucket key for a given timestamp."""
    if ts is None:
        ts = int(time.time())
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y%m%d%H")


def record_delivery_stat(
    endpoint_id: str,
    result: Dict[str, Any],
) -> None:
    """Record a single delivery result into hourly stats.

    Uses DynamoDB atomic counters for thread-safe aggregation.
    """
    bucket = _hour_bucket()
    duration_ms = result.get("duration_ms", 0)
    success = result.get("success", False)

    update_expr = (
        "SET total_deliveries = if_not_exists(total_deliveries, :zero) + :one"
    )
    expr_vals: Dict[str, Any] = {":zero": 0, ":one": 1}

    if success:
        update_expr += ", successful = if_not_exists(successful, :zero2) + :one2"
        expr_vals[":zero2"] = 0
        expr_vals[":one2"] = 1
    else:
        update_expr += ", failed = if_not_exists(failed, :zero3) + :one3"
        expr_vals[":zero3"] = 0
        expr_vals[":one3"] = 1

    update_expr += ", latency_sum_ms = if_not_exists(latency_sum_ms, :zero4) + :lat"
    expr_vals[":zero4"] = 0
    expr_vals[":lat"] = duration_ms

    try:
        T.webhook_stats.update_item(
            Key={"pk": f"STATS#{endpoint_id}", "sk": f"HOUR#{bucket}"},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
        )
    except Exception:
        logger.debug("Failed to record webhook stat for %s", endpoint_id)

    # Also update global stats
    try:
        T.webhook_stats.update_item(
            Key={"pk": "GLOBAL", "sk": f"HOUR#{bucket}"},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
        )
    except Exception:
        pass


def get_endpoint_stats(
    endpoint_id: str,
    hours: int = 24,
) -> Dict[str, Any]:
    """Get delivery statistics for an endpoint over the last N hours."""
    now = int(time.time())
    buckets = []
    total = 0
    success_total = 0
    fail_total = 0
    latency_sum = 0

    for h in range(hours):
        bucket = _hour_bucket(now - h * 3600)
        try:
            resp = T.webhook_stats.get_item(
                Key={"pk": f"STATS#{endpoint_id}", "sk": f"HOUR#{bucket}"}
            )
            item = resp.get("Item", {})
            t = int(item.get("total_deliveries", 0))
            s = int(item.get("successful", 0))
            f = int(item.get("failed", 0))
            lat = int(item.get("latency_sum_ms", 0))

            if t > 0:
                buckets.append({
                    "bucket": bucket,
                    "total": t,
                    "success": s,
                    "failed": f,
                    "avg_latency_ms": round(lat / t) if t else 0,
                })
                total += t
                success_total += s
                fail_total += f
                latency_sum += lat
        except Exception:
            pass

    return {
        "endpoint_id": endpoint_id,
        "period": "hour",
        "buckets": list(reversed(buckets)),
        "total_deliveries": total,
        "success_rate": round(success_total / total, 4) if total > 0 else 1.0,
        "avg_latency_ms": round(latency_sum / total) if total > 0 else 0,
    }


def get_global_stats(hours: int = 24) -> Dict[str, Any]:
    """Get platform-wide delivery statistics."""
    now = int(time.time())
    total = 0
    success = 0
    failed = 0
    latency_sum = 0

    for h in range(hours):
        bucket = _hour_bucket(now - h * 3600)
        try:
            resp = T.webhook_stats.get_item(
                Key={"pk": "GLOBAL", "sk": f"HOUR#{bucket}"}
            )
            item = resp.get("Item", {})
            t = int(item.get("total_deliveries", 0))
            s = int(item.get("successful", 0))
            f = int(item.get("failed", 0))
            lat = int(item.get("latency_sum_ms", 0))
            total += t
            success += s
            failed += f
            latency_sum += lat
        except Exception:
            pass

    return {
        "total_deliveries_24h": total,
        "success_count_24h": success,
        "failed_count_24h": failed,
        "success_rate_24h": round(success / total, 4) if total > 0 else 1.0,
        "avg_latency_ms_24h": round(latency_sum / total) if total > 0 else 0,
    }
