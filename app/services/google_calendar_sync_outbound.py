from __future__ import annotations

import random
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.metrics import (
    record_google_calendar_sync_conflict,
    record_google_calendar_sync_job,
    record_google_calendar_sync_latency,
    set_google_calendar_outbox_backlog,
)
from app.services.google_calendar_client import (
    create_google_calendar_event,
    delete_google_calendar_event,
    patch_google_calendar_event,
)
from app.services.google_calendar_conflicts import detect_sync_conflict
from app.services.google_calendar_audit import emit_google_calendar_audit_event
from app.services.google_calendar_event_mappings import get_event_mapping, mark_event_sync_conflict, upsert_event_mapping
from app.services.google_calendar_transform import (
    build_google_event_sync_fingerprint,
    map_internal_event_to_google,
)

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _outbox_pk(user_sub: str) -> str:
    return f"gcal_outbox#{user_sub}"


def _event_key(event_id: str) -> str:
    return f"event#{event_id}"


def _default_connection_id() -> str:
    return str(getattr(S, "google_calendar_connection_default_id", "google-primary") or "google-primary")


def _load_internal_event(calendar_id: str, event_id: str) -> Dict[str, Any]:
    item = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": _event_key(event_id)}).get("Item")
    if not item or item.get("type") != "event":
        raise HTTPException(status_code=404, detail="internal event not found")
    return item


def _classify_outbound_error(exc: HTTPException) -> str:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    provider_status = int(detail.get("provider_status_code") or 0) if isinstance(detail, dict) else 0
    retryable = bool(detail.get("retryable")) if isinstance(detail, dict) else False
    if provider_status in {409, 412}:
        return "conflict"
    if retryable or exc.status_code >= 500:
        return "retryable_error"
    return "failed"


def _update_job_status(owner_user_sub: str, sk: str, *, status: str, attempts: int, last_error: str = "") -> None:
    item = T.calendar.get_item(Key={"calendar_id": _outbox_pk(owner_user_sub), "sk": sk}).get("Item") or {}
    item.update(
        {
            "calendar_id": _outbox_pk(owner_user_sub),
            "sk": sk,
            "status": status,
            "attempts": attempts,
            "last_error": last_error,
            "updated_at_utc": _utc_now_iso(),
        }
    )
    T.calendar.put_item(Item=item)


def _compute_retry_delay_seconds(attempts: int) -> int:
    base = max(1.0, float(getattr(S, "google_calendar_outbound_retry_base_seconds", 5.0) or 5.0))
    max_delay = max(base, float(getattr(S, "google_calendar_outbound_retry_max_seconds", 300.0) or 300.0))
    jitter_ratio = float(getattr(S, "google_calendar_outbound_retry_jitter_ratio", 0.2) or 0.2)
    bounded_jitter_ratio = min(1.0, max(0.0, jitter_ratio))
    exp_delay = min(max_delay, base * (2 ** max(0, attempts - 1)))
    jitter_multiplier = 1.0 + (random.random() * 2.0 - 1.0) * bounded_jitter_ratio
    return max(1, int(round(exp_delay * jitter_multiplier)))


def _schedule_retry(owner_user_sub: str, sk: str, attempts: int, *, last_error: str = "") -> int:
    delay_seconds = _compute_retry_delay_seconds(attempts)
    next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
    item = T.calendar.get_item(Key={"calendar_id": _outbox_pk(owner_user_sub), "sk": sk}).get("Item") or {}
    item.update(
        {
            "calendar_id": _outbox_pk(owner_user_sub),
            "sk": sk,
            "status": "retry_pending",
            "attempts": attempts,
            "last_error": last_error,
            "next_attempt_at_utc": next_attempt.isoformat().replace("+00:00", "Z"),
            "updated_at_utc": _utc_now_iso(),
        }
    )
    T.calendar.put_item(Item=item)
    return delay_seconds


def _dead_letter_job(owner_user_sub: str, sk: str, attempts: int, *, last_error: str = "", reason: str = "") -> None:
    item = T.calendar.get_item(Key={"calendar_id": _outbox_pk(owner_user_sub), "sk": sk}).get("Item") or {}
    item.update(
        {
            "calendar_id": _outbox_pk(owner_user_sub),
            "sk": sk,
            "status": "dead_letter",
            "attempts": attempts,
            "last_error": last_error,
            "dead_letter_reason": reason or "retry_budget_exhausted",
            "dead_lettered_at_utc": _utc_now_iso(),
            "replay_hint": "python scripts/google_calendar_replay_dead_letters.py --owner-user-sub <user_sub>",
            "updated_at_utc": _utc_now_iso(),
        }
    )
    T.calendar.put_item(Item=item)


def replay_google_calendar_dead_letters(*, owner_user_sub: str, limit: int = 100) -> Dict[str, Any]:
    resp = T.calendar.query(KeyConditionExpression=Key("calendar_id").eq(_outbox_pk(owner_user_sub)))
    dead_letters = [
        it
        for it in (resp.get("Items") or [])
        if it.get("type") == "google_calendar_outbound_sync_job" and str(it.get("status") or "") == "dead_letter"
    ]
    dead_letters = sorted(dead_letters, key=lambda j: str(j.get("dead_lettered_at_utc") or j.get("updated_at_utc") or ""))[
        : max(1, int(limit))
    ]
    replayed = 0
    for job in dead_letters:
        item = dict(job)
        item["status"] = "pending"
        item["last_error"] = ""
        item["next_attempt_at_utc"] = _utc_now_iso()
        item["dead_letter_replayed_at_utc"] = _utc_now_iso()
        item["replay_count"] = int(item.get("replay_count") or 0) + 1
        item["updated_at_utc"] = _utc_now_iso()
        T.calendar.put_item(Item=item)
        replayed += 1
    return {"owner_user_sub": owner_user_sub, "replayed": replayed, "limit": max(1, int(limit))}


def _handle_create(owner_user_sub: str, job: Dict[str, Any], connection_id: str) -> None:
    internal_calendar_id = str(job.get("internal_calendar_id") or "")
    internal_event_id = str(job.get("internal_event_id") or "")
    google_calendar_id = str((job.get("google_calendar_ids") or [""])[0] or "")
    if not google_calendar_id:
        raise HTTPException(status_code=400, detail="no google mapping for internal calendar")
    internal_event = _load_internal_event(internal_calendar_id, internal_event_id)
    mapped = map_internal_event_to_google(internal_event=internal_event)
    created = create_google_calendar_event(
        user_sub=owner_user_sub,
        connection_id=connection_id,
        google_calendar_id=google_calendar_id,
        event_body=mapped["google_event"],
    )
    upsert_event_mapping(
        user_sub=owner_user_sub,
        internal_calendar_id=internal_calendar_id,
        internal_event_id=internal_event_id,
        google_calendar_id=google_calendar_id,
        google_event_id=str(created.get("id") or ""),
        provider_etag=str(created.get("etag") or ""),
        sync_fingerprint=build_google_event_sync_fingerprint(google_event=created),
        last_synced_at_utc=str(created.get("updated") or _utc_now_iso()),
    )


def _handle_update(owner_user_sub: str, job: Dict[str, Any], connection_id: str) -> None:
    internal_calendar_id = str(job.get("internal_calendar_id") or "")
    internal_event_id = str(job.get("internal_event_id") or "")
    existing = get_event_mapping(
        user_sub=owner_user_sub,
        internal_calendar_id=internal_calendar_id,
        internal_event_id=internal_event_id,
        include_inactive=True,
    )
    internal_event = _load_internal_event(internal_calendar_id, internal_event_id)
    mapped = map_internal_event_to_google(internal_event=internal_event)
    updated = patch_google_calendar_event(
        user_sub=owner_user_sub,
        connection_id=connection_id,
        google_calendar_id=str(existing.get("google_calendar_id") or ""),
        google_event_id=str(existing.get("google_event_id") or ""),
        event_body=mapped["google_event"],
        if_match_etag=str(existing.get("provider_etag") or "") or None,
    )
    upsert_event_mapping(
        user_sub=owner_user_sub,
        internal_calendar_id=internal_calendar_id,
        internal_event_id=internal_event_id,
        google_calendar_id=str(existing.get("google_calendar_id") or ""),
        google_event_id=str(existing.get("google_event_id") or ""),
        provider_etag=str(updated.get("etag") or existing.get("provider_etag") or ""),
        sync_fingerprint=build_google_event_sync_fingerprint(google_event=updated),
        last_synced_at_utc=str(updated.get("updated") or _utc_now_iso()),
    )


def _handle_delete(owner_user_sub: str, job: Dict[str, Any], connection_id: str) -> None:
    internal_calendar_id = str(job.get("internal_calendar_id") or "")
    internal_event_id = str(job.get("internal_event_id") or "")
    existing = get_event_mapping(
        user_sub=owner_user_sub,
        internal_calendar_id=internal_calendar_id,
        internal_event_id=internal_event_id,
        include_inactive=True,
    )
    _ = delete_google_calendar_event(
        user_sub=owner_user_sub,
        connection_id=connection_id,
        google_calendar_id=str(existing.get("google_calendar_id") or ""),
        google_event_id=str(existing.get("google_event_id") or ""),
        if_match_etag=str(existing.get("provider_etag") or "") or None,
    )


def process_google_calendar_outbound_jobs(*, owner_user_sub: str, connection_id: str | None = None, limit: int = 50) -> Dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    resolved_connection_id = connection_id or _default_connection_id()
    resp = T.calendar.query(KeyConditionExpression=Key("calendar_id").eq(_outbox_pk(owner_user_sub)))
    now = datetime.now(timezone.utc)
    jobs = []
    for it in resp.get("Items") or []:
        if it.get("type") != "google_calendar_outbound_sync_job":
            continue
        status = str(it.get("status") or "pending")
        if status == "pending":
            jobs.append(it)
            continue
        if status == "retry_pending":
            due_at = _parse_utc_iso(str(it.get("next_attempt_at_utc") or "")) or now
            if due_at <= now:
                jobs.append(it)
    jobs = sorted(jobs, key=lambda j: str(j.get("enqueued_at_utc") or ""))[: max(1, int(limit))]
    set_google_calendar_outbox_backlog(status="pending", count=sum(1 for it in resp.get("Items") or [] if str(it.get("status") or "pending") == "pending"))
    set_google_calendar_outbox_backlog(status="retry_pending", count=sum(1 for it in resp.get("Items") or [] if str(it.get("status") or "") == "retry_pending"))
    set_google_calendar_outbox_backlog(status="dead_letter", count=sum(1 for it in resp.get("Items") or [] if str(it.get("status") or "") == "dead_letter"))

    processed = 0
    success = 0
    retryable_errors = 0
    conflicts = 0
    failed = 0
    dead_lettered = 0
    retries_scheduled = 0
    retry_budget = max(1, int(getattr(S, "google_calendar_outbound_retry_max_attempts", 5) or 5))

    for job in jobs:
        processed += 1
        sk = str(job.get("sk") or "")
        attempts = int(job.get("attempts") or 0) + 1
        action = str(job.get("action") or "").lower()
        correlation_id = str(job.get("correlation_id") or f"gcal:{owner_user_sub}:{job.get('dedup_key') or sk}")
        try:
            if action == "create":
                _handle_create(owner_user_sub, job, resolved_connection_id)
            elif action == "update":
                _handle_update(owner_user_sub, job, resolved_connection_id)
            elif action == "delete":
                _handle_delete(owner_user_sub, job, resolved_connection_id)
            else:
                raise HTTPException(status_code=400, detail=f"unsupported outbound action '{action}'")
            _update_job_status(owner_user_sub, sk, status="done", attempts=attempts)
            record_google_calendar_sync_job(flow="outbound", state="done")
            logger.info(
                "google_calendar_outbound_job_processed",
                extra={
                    "correlation_id": correlation_id,
                    "owner_user_sub": owner_user_sub,
                    "action": action,
                    "status": "done",
                    "attempts": attempts,
                    "job_sk": sk,
                    "mapping_internal_calendar_id": str(job.get("internal_calendar_id") or ""),
                    "mapping_internal_event_id": str(job.get("internal_event_id") or ""),
                },
            )
            success += 1
        except HTTPException as exc:
            klass = _classify_outbound_error(exc)
            if klass == "conflict":
                internal_calendar_id = str(job.get("internal_calendar_id") or "")
                internal_event_id = str(job.get("internal_event_id") or "")
                try:
                    mapping = get_event_mapping(
                        user_sub=owner_user_sub,
                        internal_calendar_id=internal_calendar_id,
                        internal_event_id=internal_event_id,
                        include_inactive=True,
                    )
                    internal_snapshot = _load_internal_event(internal_calendar_id, internal_event_id)
                    provider_error = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
                    detected = detect_sync_conflict(
                        internal_event_snapshot=internal_snapshot,
                        mapping_snapshot=mapping,
                        provider_error=provider_error if isinstance(provider_error, dict) else None,
                    )
                    mark_event_sync_conflict(
                        user_sub=owner_user_sub,
                        internal_calendar_id=internal_calendar_id,
                        internal_event_id=internal_event_id,
                        reason=str(detected.get("reason") or "conflict"),
                        internal_snapshot=internal_snapshot,
                        provider_snapshot={"error": provider_error},
                    )
                except Exception:
                    pass
                _update_job_status(owner_user_sub, sk, status="conflict", attempts=attempts, last_error=str(exc.detail))
                record_google_calendar_sync_job(flow="outbound", state="conflict")
                record_google_calendar_sync_conflict(reason="provider_conflict")
                emit_google_calendar_audit_event(
                    event="google_calendar_sync_conflict",
                    actor_user_sub=owner_user_sub,
                    outcome="failure",
                    target_type="event_mapping",
                    target_id=f"{internal_calendar_id}:{internal_event_id}",
                    connection_id=resolved_connection_id,
                    job_sk=sk,
                    correlation_id=correlation_id,
                )
                conflicts += 1
            elif klass == "retryable_error":
                if attempts >= retry_budget:
                    _dead_letter_job(
                        owner_user_sub,
                        sk,
                        attempts,
                        last_error=str(exc.detail),
                        reason="retry_budget_exhausted",
                    )
                    record_google_calendar_sync_job(flow="outbound", state="dead_letter")
                    emit_google_calendar_audit_event(
                        event="google_calendar_sync_dead_lettered",
                        actor_user_sub=owner_user_sub,
                        outcome="failure",
                        target_type="outbox_job",
                        target_id=sk,
                        connection_id=resolved_connection_id,
                        correlation_id=correlation_id,
                        reason="retry_budget_exhausted",
                    )
                    dead_lettered += 1
                else:
                    _schedule_retry(owner_user_sub, sk, attempts, last_error=str(exc.detail))
                    record_google_calendar_sync_job(flow="outbound", state="retry_pending")
                    retries_scheduled += 1
                    retryable_errors += 1
            else:
                _update_job_status(owner_user_sub, sk, status="failed", attempts=attempts, last_error=str(exc.detail))
                record_google_calendar_sync_job(flow="outbound", state="failed")
                emit_google_calendar_audit_event(
                    event="google_calendar_sync_error",
                    actor_user_sub=owner_user_sub,
                    outcome="failure",
                    target_type="outbox_job",
                    target_id=sk,
                    connection_id=resolved_connection_id,
                    correlation_id=correlation_id,
                    reason=str(exc.detail),
                )
                failed += 1
            logger.warning(
                "google_calendar_outbound_job_error",
                extra={
                    "correlation_id": correlation_id,
                    "owner_user_sub": owner_user_sub,
                    "action": action,
                    "attempts": attempts,
                    "job_sk": sk,
                    "error_class": klass,
                    "error_detail": str(exc.detail),
                    "mapping_internal_calendar_id": str(job.get("internal_calendar_id") or ""),
                    "mapping_internal_event_id": str(job.get("internal_event_id") or ""),
                },
            )

    elapsed = max(0.0, (datetime.now(timezone.utc) - started_at).total_seconds())
    record_google_calendar_sync_latency(flow="outbound", elapsed_seconds=elapsed)

    return {
        "owner_user_sub": owner_user_sub,
        "connection_id": resolved_connection_id,
        "processed": processed,
        "success": success,
        "retryable_errors": retryable_errors,
        "retries_scheduled": retries_scheduled,
        "conflicts": conflicts,
        "failed": failed,
        "dead_lettered": dead_lettered,
        "retry_budget": retry_budget,
    }
