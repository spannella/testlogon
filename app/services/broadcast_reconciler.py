from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Iterable

from app.core.settings import S
from app.metrics import (
    record_broadcast_drift_incident,
    record_broadcast_input_loss,
    record_broadcast_output_error,
)
from app.services.broadcast_provider import get_broadcast_provider
from app.services.broadcast_store import (
    get_output,
    list_sessions_by_status,
    put_output,
    transition_session_status,
)

logger = logging.getLogger("broadcast.reconciler")

ACTIVE_STATES = ("provisioning", "ready", "live", "stopping")


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _parse_iso_ts(value: str | None) -> int:
    if not value:
        return 0
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except Exception:
        return 0


def _iter_active_sessions() -> Iterable:
    for status in ACTIVE_STATES:
        result = list_sessions_by_status(status, limit=200)
        for item in result.get("items", []):
            yield item


def reconcile_once(*, now_ts: int | None = None) -> dict:
    provider = get_broadcast_provider()
    now = int(now_ts or _now_ts())
    drift_incidents = 0
    stale_incidents = 0
    checked = 0

    for session in _iter_active_sessions():
        checked += 1
        output = get_output(session.id)
        snapshot = dict(output.provider_state_snapshot if output else {})
        desired = session.status
        actual = provider.status(session).state
        snapshot["last_reconciled_at"] = now
        snapshot["desired_state"] = desired
        snapshot["actual_state"] = actual

        if actual != desired:
            first = int(snapshot.get("drift_first_detected_at") or now)
            snapshot["drift_first_detected_at"] = first
            snapshot["drift_detected"] = True
            logger.warning(
                "drift detected",
                extra={
                    "session_id": session.id,
                    "desired": desired,
                    "actual": actual,
                    "drift_age_seconds": now - first,
                },
            )
            if now - first >= int(S.broadcast_drift_sla_seconds or 120):
                transition_session_status(
                    session_id=session.id,
                    to_status="error",
                    reason=f"drift_detected:{desired}->{actual}",
                    actor="broadcast-reconciler",
                )
                drift_incidents += 1
                record_broadcast_drift_incident(provider=provider.name, incident_type="state_drift")
        else:
            snapshot.pop("drift_first_detected_at", None)
            snapshot["drift_detected"] = False

        updated_at_ts = _parse_iso_ts(getattr(session, "updated_at", None))
        is_stale = desired in {"provisioning", "stopping"} and updated_at_ts > 0 and (now - updated_at_ts) >= int(S.broadcast_stale_session_seconds or 300)
        if is_stale:
            transition_session_status(
                session_id=session.id,
                to_status="error",
                reason=f"stale_session_timeout:{desired}",
                actor="broadcast-reconciler",
            )
            snapshot["stale_detected"] = True
            stale_incidents += 1
            record_broadcast_drift_incident(provider=provider.name, incident_type="stale_session")
        else:
            snapshot["stale_detected"] = False

        actual_lower = str(actual or "").lower()
        if "input" in actual_lower and ("loss" in actual_lower or "lost" in actual_lower):
            record_broadcast_input_loss(provider=provider.name, reason=actual_lower)
        if actual_lower in {"error", "failed", "stopped"} and desired == "live":
            record_broadcast_output_error(provider=provider.name, reason=actual_lower)

        put_output(
            session_id=session.id,
            mediapackage_endpoint=output.mediapackage_endpoint if output else None,
            cloudfront_playback_url=output.cloudfront_playback_url if output else None,
            s3_archive_prefix=output.s3_archive_prefix if output else None,
            aws_input_arn=output.aws_input_arn if output else None,
            aws_channel_arn=output.aws_channel_arn if output else None,
            provider_state_snapshot=snapshot,
        )

    return {
        "checked": checked,
        "drift_incidents": drift_incidents,
        "stale_incidents": stale_incidents,
    }


def start_broadcast_reconciler_task() -> None:
    if not S.broadcast_reconciler_enabled:
        return

    async def _runner() -> None:
        while True:
            try:
                reconcile_once()
            except Exception:
                pass
            await asyncio.sleep(max(5, int(S.broadcast_reconciler_interval_seconds or 30)))

    asyncio.create_task(_runner())
