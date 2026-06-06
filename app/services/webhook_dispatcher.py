"""Webhook dispatcher background task (PLATFORM-002)."""
from __future__ import annotations

import asyncio
import logging
import time as _time

from app.core.settings import S
from app.core.time import now_ts
from app.services.job_registry import register_task, report_error, report_poll
from app.services.webhook_circuit_breaker import (
    record_delivery_result,
    should_attempt_delivery,
)
from app.services.webhook_service import (
    _decrypt_secret,
    _get_endpoint_raw,
    deliver_webhook,
    handle_delivery_failure,
    mark_delivery_dead_letter,
    mark_delivery_success,
    query_due_deliveries,
    reset_endpoint_failure_count,
)

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 10
MAX_BATCH_SIZE = 50


async def run_webhook_dispatcher_loop() -> None:
    """Background coroutine that processes pending webhook deliveries."""
    poll_interval = S.webhooks_dispatcher_poll_interval or POLL_INTERVAL_SECONDS
    register_task("webhook_dispatcher", poll_interval, enabled=True,
                   description="Delivers pending webhook notifications to user endpoints")

    while True:
        _poll_start = _time.perf_counter()
        _processed = 0
        _failed = 0
        try:
            now = now_ts()
            due_pending = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
            due_retry = query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
            due = due_pending + due_retry

            for delivery in due:
                try:
                    endpoint_id = delivery.get("endpoint_id", "")
                    user_sub = delivery.get("user_sub", "")
                    endpoint = _get_endpoint_raw(user_sub, endpoint_id)
                    if not endpoint or not endpoint.get("enabled", True):
                        mark_delivery_dead_letter(delivery, reason="endpoint_disabled")
                        continue

                    # Circuit breaker guard: skip delivery when the endpoint's
                    # circuit is open and its cooldown has not yet expired
                    # (GAP-0180 / ENTERPRISE-005).
                    if not should_attempt_delivery(endpoint, now):
                        logger.debug(
                            "Circuit open for endpoint %s — skipping delivery %s",
                            endpoint_id,
                            delivery.get("delivery_id", ""),
                        )
                        continue

                    secret = _decrypt_secret(endpoint["secret"])
                    result = await deliver_webhook(
                        url=endpoint["url"],
                        payload=delivery.get("payload", "{}"),
                        secret=secret,
                        delivery_id=delivery.get("delivery_id", ""),
                        event_type=delivery.get("event_type", ""),
                    )

                    if result["success"]:
                        mark_delivery_success(delivery, result)
                        reset_endpoint_failure_count(endpoint_id, user_sub)
                        record_delivery_result(endpoint, success=True)
                        _processed += 1
                    else:
                        handle_delivery_failure(delivery, endpoint, result)
                        record_delivery_result(endpoint, success=False)
                        _failed += 1
                except Exception:
                    _failed += 1
                    logger.exception("Webhook delivery error for %s", delivery.get("delivery_id", ""))

            _duration_ms = (_time.perf_counter() - _poll_start) * 1000
            report_poll("webhook_dispatcher", items_processed=_processed,
                        items_failed=_failed, duration_ms=_duration_ms)
            _record_run("success" if _failed == 0 else "partial",
                        _duration_ms, _processed, _failed)

        except Exception as exc:
            report_error("webhook_dispatcher", str(exc))
            _record_run("failed", (_time.perf_counter() - _poll_start) * 1000,
                        _processed, _failed, error=str(exc))
            logger.exception("Webhook dispatcher loop error")

        await asyncio.sleep(poll_interval)


def _record_run(status: str, duration_ms: float, processed: int, failed: int,
                error: str | None = None) -> None:
    """Persist this poll cycle to the job_runs history (PLATFORM-008)."""
    try:
        from app.services.job_dashboard import record_job_run

        record_job_run(
            "webhook_dispatcher", status,
            duration_ms=duration_ms, items_processed=processed,
            items_failed=failed, error=error,
        )
    except Exception:
        logger.debug("webhook_dispatcher: record_job_run failed", exc_info=True)


async def run_webhook_dispatcher_once() -> dict:
    """Process one batch of due webhook deliveries (manual "run now")."""
    now = now_ts()
    processed = 0
    failed = 0
    due = (
        query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
        + query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
    )
    for delivery in due:
        try:
            endpoint_id = delivery.get("endpoint_id", "")
            user_sub = delivery.get("user_sub", "")
            endpoint = _get_endpoint_raw(user_sub, endpoint_id)
            if not endpoint or not endpoint.get("enabled", True):
                mark_delivery_dead_letter(delivery, reason="endpoint_disabled")
                continue
            # Circuit breaker guard (GAP-0180 / ENTERPRISE-005).
            if not should_attempt_delivery(endpoint, now):
                logger.debug(
                    "Circuit open for endpoint %s — skipping delivery %s",
                    endpoint_id,
                    delivery.get("delivery_id", ""),
                )
                continue
            secret = _decrypt_secret(endpoint["secret"])
            result = await deliver_webhook(
                url=endpoint["url"],
                payload=delivery.get("payload", "{}"),
                secret=secret,
                delivery_id=delivery.get("delivery_id", ""),
                event_type=delivery.get("event_type", ""),
            )
            if result["success"]:
                mark_delivery_success(delivery, result)
                reset_endpoint_failure_count(endpoint_id, user_sub)
                record_delivery_result(endpoint, success=True)
                processed += 1
            else:
                handle_delivery_failure(delivery, endpoint, result)
                record_delivery_result(endpoint, success=False)
                failed += 1
        except Exception:
            failed += 1
            logger.exception("run-now webhook delivery error for %s", delivery.get("delivery_id", ""))
    return {"items_processed": processed, "items_failed": failed, "due": len(due)}


async def start_webhook_dispatcher_task() -> None:
    """Start the webhook dispatcher if enabled."""
    if S.webhooks_enabled:
        asyncio.create_task(run_webhook_dispatcher_loop())
    else:
        register_task("webhook_dispatcher", POLL_INTERVAL_SECONDS, enabled=False,
                       description="Delivers pending webhook notifications to user endpoints")
