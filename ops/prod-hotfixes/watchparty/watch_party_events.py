"""Watch-party playback fan-out over the shared per-user event queue (ENGAGE-004 realtime).

Host-authoritative playback state (play / pause / seek + position) is delivered to
participants by REUSING the existing per-user event channel that backs
``GET /messaging/events/poll`` (the ``UserEvents`` DynamoDB queue the Android
``SseMessagingEventStream`` already polls ~every 600ms, and that call-signaling and
message events already ride). We do NOT invent new realtime infra: a
``watch_party:playback`` event is written to each ACTIVE participant's queue, exactly
like ``messaging_call_signaling`` fans call events out per-recipient.

Kept as a thin, separately-testable module so the reuse of the events channel is explicit.
"""

from __future__ import annotations

import logging
import os
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.core.time import now_ts

logger = logging.getLogger(__name__)

# 7-day TTL mirrors the messaging event-queue convention (call/message events).
_EVENT_TTL_SECONDS = 7 * 24 * 3600
_WP_PLAYBACK_EVENT_TYPE = "watch_party:playback"


def _events_table():
    """The SAME per-user UserEvents table that /messaging/events/poll reads from.

    Resolved lazily (and by env name) so dev (DDB-Local) and prod share one code path
    and no import-time table handle is created.
    """
    from app.core.aws import ddb

    return ddb.Table(os.getenv("DDB_USER_EVENTS", "UserEvents"))


def _active_participant_subs(party_id: str) -> List[str]:
    from app.services.watch_party import list_participants

    subs: List[str] = []
    for p in list_participants(party_id):
        if str(p.get("status") or "") != "active":
            continue
        sub = str(p.get("user_sub") or "").strip()
        if sub:
            subs.append(sub)
    return subs


def publish_playback_state(
    party_id: str,
    *,
    action: str,
    status: str,
    position: float,
    position_updated_at: int,
    controlled_by: str,
    duration_seconds: Optional[int] = None,
    put_item=None,
) -> int:
    """Fan the host-authoritative playback state out to every active participant's queue.

    Writes one ``watch_party:playback`` UserEvents item per active participant (incl. the
    controller, harmless — the client dedups by event_id and ignores its own drift). The
    core fields are placed at the TOP LEVEL of the frame (not nested under ``payload``) so
    the Android envelope parser reads them flat, the same way ``message:new`` frames are
    flattened by ``events_poll``. Returns the number of participants delivered to.

    Best-effort: a per-recipient write failure is logged and skipped — playback realtime
    must never break the authoritative REST control call.
    """
    ts = int(now_ts())
    subs = _active_participant_subs(party_id)
    writer = put_item or _events_table().put_item
    delivered = 0
    for sub in subs:
        item: Dict[str, Any] = {
            "user_id": sub,
            # Unique per (recipient, publish) so distinct fan-out rows never collide and
            # the client can dedup on event_id like every other queue event.
            "event_id": f"wp_pb_{party_id}_{ts}_{uuid.uuid4().hex}",
            "type": _WP_PLAYBACK_EVENT_TYPE,
            "party_id": party_id,
            "action": action,
            "status": status,
            "position": Decimal(str(position)),
            "position_updated_at": int(position_updated_at),
            "controlled_by": controlled_by,
            "server_time": ts,
            "created_at": ts,
            "read": False,
            "ttl": ts + _EVENT_TTL_SECONDS,
        }
        if duration_seconds is not None:
            item["video_duration_seconds"] = int(duration_seconds)
        try:
            writer(Item=item, ConditionExpression="attribute_not_exists(event_id)")
            delivered += 1
        except Exception:
            logger.exception(
                "watch_party playback fan-out failed",
                extra={"party_id": party_id, "recipient": sub},
            )
    return delivered
