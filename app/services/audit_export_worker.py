"""Background worker that processes pending audit export jobs (ENTERPRISE-004 / GAP-0178).

Mirrors the existing background-worker pattern (e.g. ``webhook_dispatcher``): a
polling loop scans the ``AuditExports`` table for ``pending`` jobs, claims each
one via a compare-and-swap on ``status``, and hands it to
``process_export_job`` (which forks dev/prod inside the pipeline — GAP-0179).

Gated behind ``S.audit_export_worker_enabled``; runs in both dev (moto S3
in-process) and prod (real S3) for dev/prod parity (SECOPS-007).
"""
from __future__ import annotations

import asyncio
import logging
import time as _time
from typing import Any

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_export_pipeline import process_export_job
from app.services.job_registry import register_task, report_error, report_poll

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 10
MAX_BATCH_SIZE = 3  # matches S.audit_export_worker_max_concurrent default


def _query_pending_jobs(limit: int) -> list[dict[str, Any]]:
    """Return up to ``limit`` export jobs with ``status == "pending"``.

    DynamoDB applies ``FilterExpression`` after reading a page, so over-fetch to
    reduce the chance of a busy table returning zero post-filter items on the
    first page.
    """
    resp = T.audit_exports.scan(
        FilterExpression=Attr("status").eq("pending"),
        Limit=max(limit, 1) * 10,
    )
    items = resp.get("Items", [])
    pending = [i for i in items if i.get("status") == "pending"]
    return pending[:limit]


def _claim_job(export_id: str) -> bool:
    """Atomically transition a job from ``pending`` to ``processing``.

    Returns ``True`` if this worker won the claim, ``False`` if another worker
    already claimed it (ConditionalCheckFailedException).
    """
    try:
        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression="SET #st = :st, started_at = :now",
            ConditionExpression=Attr("status").eq("pending"),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "processing", ":now": now_ts()},
        )
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _mark_failed(export_id: str, reason: str) -> None:
    T.audit_exports.update_item(
        Key={"export_id": export_id, "sk": "META"},
        UpdateExpression="SET #st = :st, error_message = :em",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "failed", ":em": reason[:500]},
    )


async def run_audit_export_worker_loop() -> None:
    """Poll for pending export jobs and process them until cancelled."""
    poll_interval = S.audit_export_worker_poll_interval_seconds or POLL_INTERVAL_SECONDS
    register_task(
        "audit_export_worker",
        poll_interval,
        enabled=True,
        description="Processes pending audit log export jobs and uploads results to S3",
    )

    while True:
        _poll_start = _time.perf_counter()
        _processed = 0
        _failed = 0
        try:
            due = _query_pending_jobs(limit=S.audit_export_worker_max_concurrent or MAX_BATCH_SIZE)
            for job in due:
                export_id = job["export_id"]
                try:
                    if not _claim_job(export_id):
                        # Another worker already picked this up; skip silently.
                        continue
                    process_export_job(export_id, job)
                    _processed += 1
                except Exception:
                    _failed += 1
                    logger.exception(
                        "audit_export_worker: failed to process job %s", export_id
                    )
                    try:
                        _mark_failed(export_id, "worker exception")
                    except Exception:
                        logger.exception(
                            "audit_export_worker: failed to mark job %s failed", export_id
                        )

            _duration_ms = (_time.perf_counter() - _poll_start) * 1000
            report_poll(
                "audit_export_worker",
                items_processed=_processed,
                items_failed=_failed,
                duration_ms=_duration_ms,
            )
        except Exception as exc:
            report_error("audit_export_worker", str(exc))
            logger.exception("audit_export_worker: poll loop error")

        await asyncio.sleep(poll_interval)


async def start_audit_export_worker_task() -> None:
    """Start the audit export worker if enabled (FastAPI startup hook)."""
    if S.audit_export_worker_enabled:
        asyncio.create_task(run_audit_export_worker_loop())
    else:
        register_task(
            "audit_export_worker",
            S.audit_export_worker_poll_interval_seconds or POLL_INTERVAL_SECONDS,
            enabled=False,
            description="Processes pending audit log export jobs and uploads results to S3",
        )
