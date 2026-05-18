from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.core.tables import T
from app.services.google_calendar_mappings import list_calendar_provider_mappings


OUTBOUND_SYNC_JOB_TYPE = "google_calendar_outbound_sync_job"
logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _pk(user_sub: str) -> str:
    return f"gcal_outbox#{user_sub}"


def _sk(dedup_key: str) -> str:
    return f"job#{dedup_key}"


def _stable_dedup_key(
    *,
    action: str,
    internal_calendar_id: str,
    internal_event_id: str,
    event_snapshot: Dict[str, Any],
) -> str:
    basis = {
        "action": action,
        "internal_calendar_id": internal_calendar_id,
        "internal_event_id": internal_event_id,
        "updated_at_utc": str(event_snapshot.get("updated_at_utc") or ""),
        "created_at_utc": str(event_snapshot.get("created_at_utc") or ""),
        "status": str(event_snapshot.get("status") or ""),
        "start_utc": str(event_snapshot.get("start_utc") or ""),
        "end_utc": str(event_snapshot.get("end_utc") or ""),
        "all_day": bool(event_snapshot.get("all_day", False)),
        "all_day_date": str(event_snapshot.get("all_day_date") or ""),
    }
    canonical = json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def enqueue_google_calendar_outbound_sync_job(
    *,
    owner_user_sub: str,
    actor_user_sub: str,
    action: str,
    internal_calendar_id: str,
    internal_event_id: str,
    event_snapshot: Dict[str, Any] | None = None,
    source: str = "calendar_api",
) -> Dict[str, Any]:
    snapshot = dict(event_snapshot or {})
    dedup_key = _stable_dedup_key(
        action=action,
        internal_calendar_id=internal_calendar_id,
        internal_event_id=internal_event_id,
        event_snapshot=snapshot,
    )
    mappings = list_calendar_provider_mappings(user_sub=owner_user_sub, include_inactive=False)
    google_calendar_ids: List[str] = sorted(
        {
            str(m.get("google_calendar_id") or "")
            for m in mappings
            if bool(m.get("active", True)) and str(m.get("internal_calendar_id") or "") == internal_calendar_id
        }
        - {""}
    )
    now = _utc_now_iso()
    correlation_id = f"gcal:{owner_user_sub}:{internal_calendar_id}:{internal_event_id}:{dedup_key[:12]}"
    item = {
        "calendar_id": _pk(owner_user_sub),
        "sk": _sk(dedup_key),
        "type": OUTBOUND_SYNC_JOB_TYPE,
        "provider": "google",
        "owner_user_sub": owner_user_sub,
        "actor_user_sub": actor_user_sub,
        "action": action,
        "dedup_key": dedup_key,
        "correlation_id": correlation_id,
        "source": source,
        "internal_calendar_id": internal_calendar_id,
        "internal_event_id": internal_event_id,
        "google_calendar_ids": google_calendar_ids,
        "event_snapshot": snapshot,
        "enqueued_at_utc": now,
        "status": "pending",
    }
    try:
        T.calendar.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(calendar_id) AND attribute_not_exists(sk)",
        )
        logger.info(
            "google_calendar_outbound_job_enqueued",
            extra={
                "correlation_id": correlation_id,
                "owner_user_sub": owner_user_sub,
                "actor_user_sub": actor_user_sub,
                "action": action,
                "mapping_internal_calendar_id": internal_calendar_id,
                "mapping_internal_event_id": internal_event_id,
                "dedup_key": dedup_key,
                "status": "pending",
            },
        )
        return {"accepted": True, "duplicate": False, "dedup_key": dedup_key, "job": item}
    except Exception as exc:
        code = str(getattr(exc, "response", {}).get("Error", {}).get("Code") or "")
        if code == "ConditionalCheckFailedException":
            existing = T.calendar.get_item(Key={"calendar_id": _pk(owner_user_sub), "sk": _sk(dedup_key)}).get("Item")
            logger.info(
                "google_calendar_outbound_job_duplicate",
                extra={
                    "correlation_id": correlation_id,
                    "owner_user_sub": owner_user_sub,
                    "action": action,
                    "mapping_internal_calendar_id": internal_calendar_id,
                    "mapping_internal_event_id": internal_event_id,
                    "dedup_key": dedup_key,
                },
            )
            return {"accepted": True, "duplicate": True, "dedup_key": dedup_key, "job": existing or item}
        raise
