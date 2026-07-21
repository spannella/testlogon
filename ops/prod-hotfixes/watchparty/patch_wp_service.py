#!/usr/bin/env python3
"""Idempotent anchor patcher: fan watch-party playback out over the shared events
queue in app/services/watch_party.py (control_playback).

Injects the identical fan-out block used on the dev clone, immediately after the
in-process SSE broadcast in control_playback. Byte-identical anchor confirmed on
prod before running. Idempotent: if the block is already present, does nothing.
"""
import sys

P = "app/services/watch_party.py"
s = open(P).read()

if "watch_party_events" in s:
    print("PATCH: already applied, skipping")
    sys.exit(0)

anchor = """    broadcast_sse_publish(party_id, {
        "_type": "playback_control",
        "action": action,
        "status": new_status,
        "position": new_pos,
        "position_updated_at": ts,
        "controlled_by": user_sub,
    })

    party["status"] = new_status"""

insert = """    broadcast_sse_publish(party_id, {
        "_type": "playback_control",
        "action": action,
        "status": new_status,
        "position": new_pos,
        "position_updated_at": ts,
        "controlled_by": user_sub,
    })

    # Also fan the host-authoritative state out to each participant over the SHARED
    # per-user event queue backing /messaging/events/poll (the channel the Android
    # SseMessagingEventStream already polls). The in-process SSE above serves the web
    # /stream endpoint; this durable, cross-worker queue serves the mobile clients.
    try:
        from app.services.watch_party_events import publish_playback_state
        publish_playback_state(
            party_id,
            action=action,
            status=new_status,
            position=new_pos,
            position_updated_at=ts,
            controlled_by=user_sub,
            duration_seconds=duration,
        )
    except Exception:  # pragma: no cover - realtime fan-out must never break control
        import logging
        logging.getLogger(__name__).exception(
            "watch_party playback event fan-out failed", extra={"party_id": party_id}
        )

    party["status"] = new_status"""

if s.count(anchor) != 1:
    print("PATCH: anchor not unique (count=%d) - ABORT" % s.count(anchor))
    sys.exit(2)
s = s.replace(anchor, insert, 1)
open(P, "w").write(s)
print("PATCH: fan-out wired into control_playback")
