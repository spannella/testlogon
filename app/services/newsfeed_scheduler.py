from __future__ import annotations

import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.metrics import (
    record_newsfeed_schedule_alert,
    record_newsfeed_schedule_operation,
    record_newsfeed_schedule_run,
    record_newsfeed_schedule_run_duration,
    record_newsfeed_schedule_publish_lag,
    set_newsfeed_schedule_last_run,
    set_newsfeed_schedule_backlog,
    set_newsfeed_schedule_oldest_due_age,
)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
DUE_INDEX_NAME = os.environ.get("NEWSFEED_SCHEDULE_DUE_INDEX_NAME", "GSI_SCHEDULE_DUE")
DUE_INDEX_PK_ATTR = "GSI_SCHEDULE_PK"
DUE_INDEX_SK_ATTR = "GSI_SCHEDULE_SK"
DUE_INDEX_PK_VALUE = "SCHEDULED"

RETRYABLE_CODES = {
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "InternalServerError",
    "TransactionConflictException",
}
logger = logging.getLogger(__name__)
ALERT_PUBLISH_LAG_SECONDS = int(os.environ.get("NEWSFEED_SCHEDULER_ALERT_PUBLISH_LAG_SECONDS", "300"))
ALERT_ERROR_THRESHOLD = int(os.environ.get("NEWSFEED_SCHEDULER_ALERT_ERROR_THRESHOLD", "1"))
ALERT_OLDEST_DUE_AGE_SECONDS = int(os.environ.get("NEWSFEED_SCHEDULER_ALERT_OLDEST_DUE_AGE_SECONDS", "900"))
MAX_QUERY_PAGE_LIMIT = int(os.environ.get("NEWSFEED_SCHEDULER_MAX_PAGE_LIMIT_CAP", "200"))
MAX_RUN_BATCHES = int(os.environ.get("NEWSFEED_SCHEDULER_MAX_BATCHES_CAP", "20"))
QUERY_RETRY_MAX = int(os.environ.get("NEWSFEED_SCHEDULER_QUERY_RETRY_MAX", "2"))
QUERY_RETRY_BACKOFF_SECONDS = float(os.environ.get("NEWSFEED_SCHEDULER_QUERY_RETRY_BACKOFF_SECONDS", "0.1"))


def _tbl():
    return ddb.Table(APP_TABLE)


def pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


def sk_post() -> str:
    return "META"


def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"


def sk_scheduled_post_ref(publish_at: int, post_id: str) -> str:
    return f"SCHEDULEDPOST#{int(publish_at):012d}#{post_id}"


def _due_sk_upper_bound(now_ts: int) -> str:
    return f"{int(now_ts):012d}#POST#~"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _query_due_posts(*, now_ts: int, limit: int, eks: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "IndexName": DUE_INDEX_NAME,
        "KeyConditionExpression": Key(DUE_INDEX_PK_ATTR).eq(DUE_INDEX_PK_VALUE)
        & Key(DUE_INDEX_SK_ATTR).lte(_due_sk_upper_bound(now_ts)),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks
    return _query_ddb_with_retry(operation="due_posts", **kwargs)


def _query_due_backlog(*, now_ts: int) -> int:
    resp = _query_ddb_with_retry(
        operation="due_backlog",
        IndexName=DUE_INDEX_NAME,
        KeyConditionExpression=Key(DUE_INDEX_PK_ATTR).eq(DUE_INDEX_PK_VALUE)
        & Key(DUE_INDEX_SK_ATTR).lte(_due_sk_upper_bound(now_ts)),
        Select="COUNT",
    )
    return int(resp.get("Count") or 0)


def _query_oldest_due_publish_at(*, now_ts: int) -> Optional[int]:
    resp = _query_ddb_with_retry(
        operation="oldest_due",
        IndexName=DUE_INDEX_NAME,
        KeyConditionExpression=Key(DUE_INDEX_PK_ATTR).eq(DUE_INDEX_PK_VALUE)
        & Key(DUE_INDEX_SK_ATTR).lte(_due_sk_upper_bound(now_ts)),
        ProjectionExpression="publish_at",
        ScanIndexForward=True,
        Limit=1,
    )
    items = resp.get("Items") or []
    if not items:
        return None
    try:
        return int(items[0].get("publish_at"))
    except Exception:
        return None


def _query_ddb_with_retry(*, operation: str, **kwargs) -> Dict[str, Any]:
    retries = max(0, int(QUERY_RETRY_MAX))
    backoff = max(0.01, float(QUERY_RETRY_BACKOFF_SECONDS))
    for attempt in range(retries + 1):
        try:
            resp = _tbl().query(**kwargs)
            if attempt > 0:
                record_newsfeed_schedule_operation(operation=f"query_{operation}", outcome="recovered")
            return resp
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code") or "")
            if code not in RETRYABLE_CODES or attempt >= retries:
                record_newsfeed_schedule_operation(operation=f"query_{operation}", outcome="error")
                raise
            record_newsfeed_schedule_operation(operation=f"query_{operation}", outcome="retry")
            time.sleep(backoff * (2**attempt))
    record_newsfeed_schedule_operation(operation=f"query_{operation}", outcome="error")
    return _tbl().query(**kwargs)


def _publish_due_post(item: Dict[str, Any], *, now_ts: int, now_iso: str) -> str:
    post_id = str(item.get("post_id") or "").strip()
    user_id = str(item.get("user_id") or "").strip()
    try:
        publish_at = int(item.get("publish_at"))
    except Exception:
        return "invalid"
    if not post_id or not user_id:
        return "invalid"
    current = _tbl().get_item(Key={"pk": pk_post(post_id), "sk": sk_post()}).get("Item") or {}
    current_status = str(current.get("status") or "").strip().lower()
    if current_status == "published":
        return "already_published"
    if current_status == "cancelled":
        return "already_cancelled"
    if current_status and current_status != "scheduled":
        return "invalid_state"

    tbl = _tbl()
    try:
        tbl.update_item(
            Key={"pk": pk_post(post_id), "sk": sk_post()},
            UpdateExpression="SET #status = :published, published_at = :now, updated_at = :now REMOVE publish_at, schedule_timezone, scheduled_at_local, GSI_SCHEDULE_PK, GSI_SCHEDULE_SK",
            ConditionExpression="#status = :scheduled AND publish_at <= :now_ts",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":published": "published",
                ":scheduled": "scheduled",
                ":now": now_iso,
                ":now_ts": now_ts,
            },
        )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code") or "")
        if code == "ConditionalCheckFailedException":
            latest = tbl.get_item(Key={"pk": pk_post(post_id), "sk": sk_post()}).get("Item") or {}
            latest_status = str(latest.get("status") or "").strip().lower()
            if latest_status == "published":
                return "already_published"
            if latest_status == "cancelled":
                return "already_cancelled"
            return "conflict"
        if code in RETRYABLE_CODES:
            raise
        return "error"

    try:
        tbl.delete_item(Key={"pk": pk_user(user_id), "sk": sk_scheduled_post_ref(publish_at, post_id)})
    except ClientError:
        pass

    try:
        tbl.put_item(
            Item={
                "pk": pk_post(post_id),
                "sk": f"FEEDREF#{user_id}",
                "Entity": "FeedRef",
                "post_id": post_id,
                "user_id": user_id,
                "created_at": now_iso,
                "GSI1PK": f"FEED#{user_id}",
                "GSI1SK": now_iso,
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError:
        pass

    # SOC-002: Fan out published scheduled post to followers
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers
        fan_out_post_to_followers(author_id=user_id, post_id=post_id, created_at=now_iso)
    except Exception:
        logger.exception("Fan-out failed for scheduled post %s by %s", post_id, user_id)

    return "published"


def _publish_with_retry(item: Dict[str, Any], *, now_ts: int, now_iso: str, max_retries: int, backoff_seconds: float) -> str:
    for attempt in range(max_retries + 1):
        try:
            result = _publish_due_post(item, now_ts=now_ts, now_iso=now_iso)
            return result
        except ClientError:
            if attempt >= max_retries:
                return "retry_exhausted"
            time.sleep(backoff_seconds * (2**attempt))
    return "retry_exhausted"


def _meter_publish_once(*, user_id: str, post_id: str) -> bool:
    try:
        # Imported lazily to avoid tight coupling at module import time.
        from app.routers.newsfeed import _meter_newsfeed_post_publish

        _meter_newsfeed_post_publish(user_id=user_id, post_id=post_id)
        return True
    except Exception:
        logger.exception("newsfeed scheduled publish metering failed", extra={"user_id": user_id, "post_id": post_id})
        return False


def process_due_scheduled_posts(
    *,
    now_ts: Optional[int] = None,
    page_limit: int = 50,
    max_batches: int = 1,
    publish_retry_max: int = 3,
    retry_backoff_seconds: float = 0.25,
) -> Dict[str, Any]:
    started = time.perf_counter()
    now_ts = int(now_ts or time.time())
    now_iso = _now_iso()
    effective_page_limit = min(max(1, int(page_limit)), max(1, int(MAX_QUERY_PAGE_LIMIT)))
    effective_max_batches = min(max(1, int(max_batches)), max(1, int(MAX_RUN_BATCHES)))
    summary = {
        "now_ts": now_ts,
        "index": DUE_INDEX_NAME,
        "page_limit_effective": effective_page_limit,
        "max_batches_effective": effective_max_batches,
        "batches": 0,
        "scanned": 0,
        "published": 0,
        "already_published": 0,
        "already_cancelled": 0,
        "invalid": 0,
        "invalid_state": 0,
        "conflict": 0,
        "error": 0,
        "retry_exhausted": 0,
        "metered": 0,
        "meter_errors": 0,
        "max_publish_lag_seconds": 0,
        "backlog_due": 0,
        "backlog_oldest_due_age_seconds": 0,
        "worker_enabled": True,
        "run_exception": 0,
    }
    run_outcome = "completed"
    try:
        if not bool(getattr(S, "newsfeed_scheduling_worker_enabled", True)):
            logger.info("newsfeed scheduler disabled by feature flag")
            run_outcome = "disabled"
            summary["worker_enabled"] = False
            return summary
        try:
            summary["backlog_due"] = _query_due_backlog(now_ts=now_ts)
            set_newsfeed_schedule_backlog(due_count=int(summary["backlog_due"]))
            oldest_due_publish_at = _query_oldest_due_publish_at(now_ts=now_ts)
            if oldest_due_publish_at is None:
                summary["backlog_oldest_due_age_seconds"] = 0
            else:
                summary["backlog_oldest_due_age_seconds"] = max(0, int(now_ts) - int(oldest_due_publish_at))
            set_newsfeed_schedule_oldest_due_age(elapsed_seconds=float(summary["backlog_oldest_due_age_seconds"]))
        except Exception:
            logger.exception("newsfeed scheduler backlog query failed")

        eks: Optional[Dict[str, Any]] = None
        for _ in range(effective_max_batches):
            resp = _query_due_posts(now_ts=now_ts, limit=effective_page_limit, eks=eks)
            items = resp.get("Items", [])
            summary["batches"] += 1
            summary["scanned"] += len(items)

            for item in items:
                status = _publish_with_retry(
                    item,
                    now_ts=now_ts,
                    now_iso=now_iso,
                    max_retries=max(0, int(publish_retry_max)),
                    backoff_seconds=max(0.01, float(retry_backoff_seconds)),
                )
                summary[status] = int(summary.get(status, 0)) + 1
                record_newsfeed_schedule_operation(operation="publish", outcome=status)
                if status == "published":
                    post_id = str(item.get("post_id") or "").strip()
                    user_id = str(item.get("user_id") or "").strip()
                    try:
                        publish_at = int(item.get("publish_at"))
                    except Exception:
                        publish_at = now_ts
                    lag_seconds = max(0, int(now_ts) - int(publish_at))
                    summary["max_publish_lag_seconds"] = max(int(summary["max_publish_lag_seconds"]), int(lag_seconds))
                    record_newsfeed_schedule_publish_lag(elapsed_seconds=float(lag_seconds))
                    if post_id and user_id and _meter_publish_once(user_id=user_id, post_id=post_id):
                        summary["metered"] += 1
                    else:
                        summary["meter_errors"] += 1
                elif status in {"error", "retry_exhausted", "conflict"}:
                    logger.error("newsfeed scheduled publish failed", extra={"event": "newsfeed_schedule_publish_failed", "status": status, "post_id": item.get("post_id"), "user_id": item.get("user_id")})

            eks = resp.get("LastEvaluatedKey")
            if not eks:
                break

        total_errors = int(summary.get("error", 0)) + int(summary.get("retry_exhausted", 0))
        if total_errors >= max(1, ALERT_ERROR_THRESHOLD):
            record_newsfeed_schedule_alert(alert_type="error_threshold_breach")
            logger.error(
                "newsfeed scheduler error threshold breached",
                extra={"event": "newsfeed_schedule_alert", "alert_type": "error_threshold_breach", "errors": total_errors, "threshold": max(1, ALERT_ERROR_THRESHOLD)},
            )
        if int(summary.get("max_publish_lag_seconds", 0)) >= max(1, ALERT_PUBLISH_LAG_SECONDS):
            record_newsfeed_schedule_alert(alert_type="lag_threshold_breach")
            logger.error(
                "newsfeed scheduler lag threshold breached",
                extra={
                    "event": "newsfeed_schedule_alert",
                    "alert_type": "lag_threshold_breach",
                    "max_publish_lag_seconds": int(summary.get("max_publish_lag_seconds", 0)),
                    "threshold_seconds": max(1, ALERT_PUBLISH_LAG_SECONDS),
                },
            )
        if int(summary.get("backlog_oldest_due_age_seconds", 0)) >= max(1, ALERT_OLDEST_DUE_AGE_SECONDS):
            record_newsfeed_schedule_alert(alert_type="oldest_due_age_threshold_breach")
            logger.error(
                "newsfeed scheduler oldest-due age threshold breached",
                extra={
                    "event": "newsfeed_schedule_alert",
                    "alert_type": "oldest_due_age_threshold_breach",
                    "oldest_due_age_seconds": int(summary.get("backlog_oldest_due_age_seconds", 0)),
                    "threshold_seconds": max(1, ALERT_OLDEST_DUE_AGE_SECONDS),
                },
            )
        return summary
    except Exception:
        run_outcome = "failed"
        summary["error"] = int(summary.get("error", 0)) + 1
        summary["run_exception"] = 1
        logger.exception("newsfeed scheduler run failed", extra={"event": "newsfeed_schedule_run_failed"})
        return summary
    finally:
        set_newsfeed_schedule_last_run(unix_seconds=time.time())
        record_newsfeed_schedule_run(outcome=run_outcome)
        record_newsfeed_schedule_run_duration(elapsed_seconds=time.perf_counter() - started)


def run_scheduler_loop(
    *,
    interval_seconds: float,
    iterations: Optional[int] = None,
    page_limit: int = 50,
    max_batches: int = 1,
    publish_retry_max: int = 3,
    retry_backoff_seconds: float = 0.25,
) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    run_count = 0
    while iterations is None or run_count < iterations:
        runs.append(
            process_due_scheduled_posts(
                page_limit=page_limit,
                max_batches=max_batches,
                publish_retry_max=publish_retry_max,
                retry_backoff_seconds=retry_backoff_seconds,
            )
        )
        run_count += 1
        if iterations is not None and run_count >= iterations:
            break
        time.sleep(max(0.1, float(interval_seconds)))
    return runs


def scheduler_summary_has_failures(summary: Dict[str, Any]) -> bool:
    return bool(
        int(summary.get("run_exception", 0))
        or int(summary.get("error", 0))
        or int(summary.get("retry_exhausted", 0))
        or int(summary.get("conflict", 0))
        or int(summary.get("meter_errors", 0))
    )
