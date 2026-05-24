"""Transcode job DynamoDB store (VOD-003).

Provides CRUD operations for transcode jobs with conditional state transitions
to prevent race conditions between concurrent workers.
"""

from __future__ import annotations

import logging
import random
from typing import Any, Dict, List, Optional
from uuid import uuid4

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Constants ───────────────��──────────────���──────────────────────────────────

MAX_RETRY_DELAY = 600  # 10 minutes cap
BASE_RETRY_DELAY = 30  # seconds


# ─── Public API ────────────────────────────────────────────────────────────���───


def create_job(
    video_id: str,
    tenant_id: str,
    rendition_profiles: List[Dict[str, Any]],
    source_uri: str = "",
    watermark_policy: Optional[Dict[str, Any]] = None,
    drm_policy: Optional[Dict[str, Any]] = None,
    priority: int = 0,
) -> Dict[str, Any]:
    """Create a new transcode job in queued status. Returns the full job dict."""
    job_id = f"tj_{uuid4().hex}"
    ts = now_ts()
    max_attempts = S.transcode_max_attempts

    item: Dict[str, Any] = {
        "job_id": job_id,
        "video_id": video_id,
        "tenant_id": tenant_id,
        "status": "queued",
        "status_created_at": f"queued#{ts}",
        "created_at": ts,
        "updated_at": ts,
        "attempt": 0,
        "max_attempts": max_attempts,
        "priority": priority,
        "source_uri": source_uri,
        "renditions": rendition_profiles,
        "watermark": watermark_policy or {},
        "drm": drm_policy or {},
        "progress_pct": 0,
        "renditions_completed": [],
    }

    T.transcode_jobs.put_item(Item=item)
    return item


def get_job(job_id: str) -> Dict[str, Any]:
    """Get a job by ID. Raises 404 if not found."""
    from fastapi import HTTPException

    resp = T.transcode_jobs.get_item(Key={"job_id": job_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Transcode job not found")
    return item


def claim_job(job_id: str, worker_id: str) -> bool:
    """Atomically claim a queued job. Returns False if already claimed or not eligible."""
    ts = now_ts()
    try:
        T.transcode_jobs.update_item(
            Key={"job_id": job_id},
            UpdateExpression=(
                "SET #s = :running, worker_id = :wid, started_at = :now, "
                "updated_at = :now, status_created_at = :sc"
            ),
            ConditionExpression=(
                "#s = :queued AND "
                "(attribute_not_exists(next_retry_at) OR next_retry_at <= :now)"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":running": "running",
                ":queued": "queued",
                ":wid": worker_id,
                ":now": ts,
                ":sc": f"running#{ts}",
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def update_job_progress(
    job_id: str,
    progress_pct: int,
    current_rendition: Optional[str] = None,
    renditions_completed: Optional[List[str]] = None,
    eta_seconds: Optional[int] = None,
) -> None:
    """Update progress fields on a running job."""
    ts = now_ts()
    update_expr = "SET progress_pct = :p, updated_at = :now"
    values: Dict[str, Any] = {":p": progress_pct, ":now": ts}

    if current_rendition is not None:
        update_expr += ", current_rendition = :cr"
        values[":cr"] = current_rendition

    if renditions_completed is not None:
        update_expr += ", renditions_completed = :rc"
        values[":rc"] = renditions_completed

    if eta_seconds is not None:
        update_expr += ", eta_seconds = :eta"
        values[":eta"] = eta_seconds

    T.transcode_jobs.update_item(
        Key={"job_id": job_id},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=values,
    )


def complete_job(
    job_id: str,
    output_manifest_uri: str,
    renditions_completed: Optional[List[str]] = None,
) -> None:
    """Transition a running job to completed."""
    ts = now_ts()
    update_expr = (
        "SET #s = :completed, updated_at = :now, completed_at = :now, "
        "output_hls_manifest_uri = :uri, progress_pct = :hundred, "
        "status_created_at = :sc"
    )
    values: Dict[str, Any] = {
        ":completed": "completed",
        ":running": "running",
        ":now": ts,
        ":uri": output_manifest_uri,
        ":hundred": 100,
        ":sc": f"completed#{ts}",
    }

    if renditions_completed is not None:
        update_expr += ", renditions_completed = :rc"
        values[":rc"] = renditions_completed

    T.transcode_jobs.update_item(
        Key={"job_id": job_id},
        UpdateExpression=update_expr,
        ConditionExpression="#s = :running",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues=values,
    )


def fail_job(job_id: str, error_message: str, attempt: int) -> Dict[str, Any]:
    """Handle a job failure. If retries remain, transition back to queued; otherwise mark failed.

    Returns the updated job dict.
    """
    ts = now_ts()
    max_attempts = S.transcode_max_attempts

    new_attempt = attempt + 1

    if new_attempt < max_attempts:
        # Retry: back to queued with next_retry_at
        next_retry_at = _compute_next_retry_at(new_attempt)
        T.transcode_jobs.update_item(
            Key={"job_id": job_id},
            UpdateExpression=(
                "SET #s = :queued, updated_at = :now, attempt = :att, "
                "error_message = :err, next_retry_at = :nra, "
                "status_created_at = :sc, worker_id = :null_wid"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":queued": "queued",
                ":now": ts,
                ":att": new_attempt,
                ":err": error_message,
                ":nra": next_retry_at,
                ":sc": f"queued#{ts}",
                ":null_wid": None,
            },
        )
        return get_job(job_id)
    else:
        # Terminal failure
        T.transcode_jobs.update_item(
            Key={"job_id": job_id},
            UpdateExpression=(
                "SET #s = :failed, updated_at = :now, completed_at = :now, "
                "attempt = :att, error_message = :err, "
                "status_created_at = :sc"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":failed": "failed",
                ":now": ts,
                ":att": new_attempt,
                ":err": error_message,
                ":sc": f"failed#{ts}",
            },
        )
        return get_job(job_id)


def list_jobs_by_status(
    status: str,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List jobs by status, ordered by created_at ascending (oldest first).

    Returns {"items": [...], "cursor": str | None}.
    """
    from boto3.dynamodb.conditions import Key

    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq(status),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if cursor:
        import json
        kwargs["ExclusiveStartKey"] = json.loads(cursor)

    resp = T.transcode_jobs.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = None
    if last_key:
        import json
        next_cursor = json.dumps(last_key, default=str)

    return {"items": items, "cursor": next_cursor}


def list_jobs_by_video(video_id: str) -> List[Dict[str, Any]]:
    """List all jobs for a given video, ordered by created_at descending (newest first)."""
    from boto3.dynamodb.conditions import Key

    resp = T.transcode_jobs.query(
        IndexName="ByVideoId",
        KeyConditionExpression=Key("video_id").eq(video_id),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


# ─── Internal helpers ─────────────────────────���────────────────────────────────


def _compute_next_retry_at(attempt: int) -> int:
    """Exponential backoff with jitter."""
    delay = min(MAX_RETRY_DELAY, BASE_RETRY_DELAY * (2 ** attempt))
    jitter = random.randint(0, delay // 4)
    return now_ts() + delay + jitter
