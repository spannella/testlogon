from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.settings import S
from app.services.calendar_integrations.base import CalendarIntegrationError
from app.services.calendar_integrations.credentials import (
    finalize_apple_push_outbox_attempt,
    list_due_apple_push_outbox,
)
from app.services.calendar_integrations.registry import get_provider_services


def _record_calendar_metric(metric_name: str, **kwargs: Any) -> None:
    try:
        from app import metrics as _metrics

        metric_fn = getattr(_metrics, metric_name, None)
        if callable(metric_fn):
            metric_fn(**kwargs)
    except Exception:
        return


def process_apple_push_outbox(*, now: datetime | None = None, limit: int | None = None) -> dict[str, Any]:
    provider_services = get_provider_services("apple_caldav")
    if provider_services is None:
        return {"processed": 0, "delivered": 0, "retried": 0, "dead_lettered": 0}

    current = now or datetime.now(timezone.utc)
    effective_limit = max(int(limit if limit is not None else S.apple_caldav_outbox_process_limit), 1)
    due = list_due_apple_push_outbox(now=current, limit=effective_limit)
    _record_calendar_metric(
        "record_calendar_sync_queue_backlog",
        provider="apple_caldav",
        queue="push_outbox_due",
        depth=len(due),
    )

    processed = 0
    delivered = 0
    retried = 0
    dead_lettered = 0

    for item in due:
        processed += 1
        outbox_id = str(item.get("outbox_id") or "")
        try:
            result = provider_services.sync.push_event(
                connection_id=str(item.get("connection_id") or ""),
                calendar_id=str(item.get("external_calendar_id") or ""),
                event={
                    **dict(item.get("payload") or {}),
                    "operation": item.get("operation"),
                },
            )
            status = str(result.get("status") or "").strip().lower()
            if status in {"ok", "noop"}:
                finalize_apple_push_outbox_attempt(
                    outbox_id=outbox_id,
                    success=True,
                    transient=False,
                    error=None,
                    now=current,
                )
                delivered += 1
            elif status == "conflict":
                finalize_apple_push_outbox_attempt(
                    outbox_id=outbox_id,
                    success=False,
                    transient=False,
                    error=str(result.get("conflict_reason") or "push_conflict"),
                    now=current,
                )
                dead_lettered += 1
            else:
                finalized = finalize_apple_push_outbox_attempt(
                    outbox_id=outbox_id,
                    success=False,
                    transient=True,
                    error="push_unknown_status",
                    now=current,
                )
                if str(finalized.get("status") or "") == "retry":
                    retried += 1
                else:
                    dead_lettered += 1
        except CalendarIntegrationError as exc:
            finalized = finalize_apple_push_outbox_attempt(
                outbox_id=outbox_id,
                success=False,
                transient=bool(exc.retriable),
                error=str(exc.detail),
                now=current,
            )
            if str(finalized.get("status") or "") == "retry":
                retried += 1
            else:
                dead_lettered += 1

    return {
        "processed": processed,
        "delivered": delivered,
        "retried": retried,
        "dead_lettered": dead_lettered,
    }
