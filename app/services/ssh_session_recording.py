"""SSH session recording & playback (INFRA-010).

Records an SSH browser-terminal session as a timed stream of terminal output
chunks (asciinema-style events: ``[timestamp_offset, "o"|"i", data]``) and stores
them in DynamoDB so they can be listed and played back later.

Storage layout (single-table, PK=user_sub):
  - Metadata item:  sk = ``REC#{recording_id}``      (one per recording)
  - Event chunks:   sk = ``EVT#{recording_id}#{seq}`` (one per appended batch)

This builds on the existing SSH terminal infra (``app/routers/browser_ssh_terminal.py``,
``app/services/ssh_key_manager.py``) — it does NOT recreate the SSH key/PTY bridge.
In the local mock there is no real PTY capture, so output is streamed in via the
append API (``append_events``); a live SSH bridge would call the same function.

Recordings are owner-scoped: every read/write is keyed on ``user_sub``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("ssh_session_recording")

ASCIICAST_CONTENT_TYPE = "application/x-asciicast"

VALID_EVENT_TYPES = ("o", "i")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class RecordingNotFound(Exception):
    pass


class RecordingClosed(Exception):
    """Raised when appending events to a stopped recording."""


class RecordingLimitExceeded(Exception):
    """Raised when a recording exceeds the configured event/byte cap."""


class InvalidEvent(Exception):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _num(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, Decimal):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _fnum(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _meta_sk(recording_id: str) -> str:
    return f"REC#{recording_id}"


def _event_sk(recording_id: str, seq: int) -> str:
    return f"EVT#{recording_id}#{seq:08d}"


def _meta_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Map a DDB metadata item to the API recording shape."""
    return {
        "recording_id": item.get("recording_id", ""),
        "session_id": item.get("session_id", ""),
        "host_id": item.get("host_id", ""),
        "hostname": item.get("hostname", ""),
        "port": _num(item.get("port"), 22),
        "username": item.get("username", ""),
        "host_key": item.get("host_key", ""),
        "status": item.get("status", "recording"),
        "start_time": _num(item.get("start_time")),
        "end_time": _num(item.get("end_time")),
        "duration_seconds": _num(item.get("duration_seconds")),
        "file_size_bytes": _num(item.get("file_size_bytes")),
        "terminal_cols": _num(item.get("terminal_cols"), 80),
        "terminal_rows": _num(item.get("terminal_rows"), 24),
        "event_count": _num(item.get("event_count")),
        "created_at": _num(item.get("created_at")),
        "retention_days": _num(item.get("retention_days")),
        "expires_at": _num(item.get("expires_at")),
    }


# ---------------------------------------------------------------------------
# Start / append / stop
# ---------------------------------------------------------------------------

def start_recording(
    user_sub: str,
    *,
    hostname: str,
    port: int = 22,
    username: str = "",
    terminal_cols: int = 80,
    terminal_rows: int = 24,
    host_id: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """Create a new recording in ``recording`` state and return its metadata."""
    now = now_ts()
    recording_id = "rec_" + uuid.uuid4().hex[:16]
    retention_days = S.ssh_session_recording_retention_days
    item = {
        "user_sub": user_sub,
        "sk": _meta_sk(recording_id),
        "recording_id": recording_id,
        "session_id": session_id or ("sess_" + uuid.uuid4().hex[:12]),
        "host_id": host_id or "",
        "hostname": hostname,
        "port": int(port),
        "username": username or "",
        "host_key": f"{hostname}:{int(port)}",
        "status": "recording",
        "start_time": now,
        "end_time": 0,
        "duration_seconds": 0,
        "file_size_bytes": 0,
        "terminal_cols": int(terminal_cols),
        "terminal_rows": int(terminal_rows),
        "event_count": 0,
        "next_seq": 0,
        "created_at": now,
        "retention_days": retention_days,
        "expires_at": now + (retention_days * 86400),
    }
    T.ssh_session_recordings.put_item(Item=item)
    logger.info(
        "recording_started user_sub=%s recording_id=%s host=%s",
        user_sub, recording_id, item["host_key"],
    )
    return _meta_to_dict(item)


def _get_meta_item(user_sub: str, recording_id: str) -> Optional[Dict[str, Any]]:
    resp = T.ssh_session_recordings.get_item(
        Key={"user_sub": user_sub, "sk": _meta_sk(recording_id)}
    )
    return resp.get("Item")


def get_recording(user_sub: str, recording_id: str) -> Optional[Dict[str, Any]]:
    item = _get_meta_item(user_sub, recording_id)
    if not item:
        return None
    return _meta_to_dict(item)


def _normalize_events(events: List[Any]) -> Tuple[List[List[Any]], int]:
    """Validate + normalize a list of asciicast events.

    Accepts ``[offset, type, data]`` lists/tuples or ``{"time","type","data"}``
    dicts. Returns ``(normalized, byte_size)``.
    """
    normalized: List[List[Any]] = []
    byte_size = 0
    for ev in events:
        if isinstance(ev, dict):
            offset = ev.get("time", ev.get("offset", 0.0))
            etype = ev.get("type", "o")
            data = ev.get("data", "")
        elif isinstance(ev, (list, tuple)) and len(ev) == 3:
            offset, etype, data = ev
        else:
            raise InvalidEvent("Event must be [offset, type, data] or an object")
        if etype not in VALID_EVENT_TYPES:
            raise InvalidEvent(f"Invalid event type: {etype!r}")
        if not isinstance(data, str):
            raise InvalidEvent("Event data must be a string")
        offset_f = round(_fnum(offset), 6)
        normalized.append([offset_f, etype, data])
        byte_size += len(data.encode("utf-8"))
    return normalized, byte_size


def append_events(
    user_sub: str,
    recording_id: str,
    events: List[Any],
) -> Dict[str, Any]:
    """Append a batch of output/input events to a recording.

    Stored as a single chunk item; metadata counters updated.
    """
    item = _get_meta_item(user_sub, recording_id)
    if not item:
        raise RecordingNotFound(recording_id)
    if item.get("status") != "recording":
        raise RecordingClosed(recording_id)

    normalized, byte_size = _normalize_events(events)
    if not normalized:
        return _meta_to_dict(item)

    new_count = _num(item.get("event_count")) + len(normalized)
    new_bytes = _num(item.get("file_size_bytes")) + byte_size
    if (
        new_count > S.ssh_session_recording_max_events
        or new_bytes > S.ssh_session_recording_max_bytes
    ):
        raise RecordingLimitExceeded(
            f"Recording exceeds limit (events={new_count}, bytes={new_bytes})"
        )

    seq = _num(item.get("next_seq"))
    T.ssh_session_recordings.put_item(
        Item={
            "user_sub": user_sub,
            "sk": _event_sk(recording_id, seq),
            "recording_id": recording_id,
            "seq": seq,
            "events_json": json.dumps(normalized, separators=(",", ":")),
            "event_count": len(normalized),
        }
    )
    T.ssh_session_recordings.update_item(
        Key={"user_sub": user_sub, "sk": _meta_sk(recording_id)},
        UpdateExpression=(
            "SET next_seq = :ns, event_count = :ec, file_size_bytes = :fb"
        ),
        ExpressionAttributeValues={
            ":ns": seq + 1,
            ":ec": new_count,
            ":fb": new_bytes,
        },
    )
    item["next_seq"] = seq + 1
    item["event_count"] = new_count
    item["file_size_bytes"] = new_bytes
    return _meta_to_dict(item)


def stop_recording(user_sub: str, recording_id: str) -> Dict[str, Any]:
    """Finalize a recording: mark stopped, compute duration."""
    item = _get_meta_item(user_sub, recording_id)
    if not item:
        raise RecordingNotFound(recording_id)
    now = now_ts()
    duration = max(0, now - _num(item.get("start_time"), now))
    T.ssh_session_recordings.update_item(
        Key={"user_sub": user_sub, "sk": _meta_sk(recording_id)},
        UpdateExpression=(
            "SET #s = :st, end_time = :et, duration_seconds = :du"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":st": "stopped",
            ":et": now,
            ":du": duration,
        },
    )
    item["status"] = "stopped"
    item["end_time"] = now
    item["duration_seconds"] = duration
    logger.info(
        "recording_stopped user_sub=%s recording_id=%s events=%s bytes=%s",
        user_sub, recording_id,
        _num(item.get("event_count")), _num(item.get("file_size_bytes")),
    )
    return _meta_to_dict(item)


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

def list_recordings(
    user_sub: str,
    *,
    hostname: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List a user's recordings, newest first. Optional hostname filter."""
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub)
            & Key("sk").begins_with("REC#"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.ssh_session_recordings.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    recordings = [_meta_to_dict(it) for it in items]
    if hostname:
        recordings = [r for r in recordings if r["hostname"] == hostname]
    recordings.sort(key=lambda r: r["created_at"], reverse=True)
    return recordings[:limit]


# ---------------------------------------------------------------------------
# Playback
# ---------------------------------------------------------------------------

def get_playback(user_sub: str, recording_id: str) -> Dict[str, Any]:
    """Reassemble the full event stream + asciicast header for playback."""
    meta = _get_meta_item(user_sub, recording_id)
    if not meta:
        raise RecordingNotFound(recording_id)

    events: List[List[Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub)
            & Key("sk").begins_with(f"EVT#{recording_id}#"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.ssh_session_recordings.query(**kwargs)
        for it in sorted(resp.get("Items", []), key=lambda x: _num(x.get("seq"))):
            try:
                events.extend(json.loads(it.get("events_json", "[]")))
            except (TypeError, ValueError):
                continue
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    md = _meta_to_dict(meta)
    header = {
        "version": 2,
        "width": md["terminal_cols"],
        "height": md["terminal_rows"],
        "timestamp": md["start_time"],
        "title": f"SSH session to {md['host_key']} as {md['username']}",
        "env": {"TERM": "xterm-256color"},
    }
    return {
        "recording_id": recording_id,
        "content_type": ASCIICAST_CONTENT_TYPE,
        "header": header,
        "events": events,
        "event_count": len(events),
    }


def get_asciicast(user_sub: str, recording_id: str) -> str:
    """Return the recording as a newline-delimited asciicast v2 (.cast) string."""
    playback = get_playback(user_sub, recording_id)
    lines = [json.dumps(playback["header"], separators=(",", ":"))]
    for ev in playback["events"]:
        lines.append(json.dumps(ev, separators=(",", ":")))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def delete_recording(user_sub: str, recording_id: str) -> bool:
    """Delete a recording's metadata + all event chunks. Returns False if absent."""
    meta = _get_meta_item(user_sub, recording_id)
    if not meta:
        return False

    # Delete all event chunks
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub)
            & Key("sk").begins_with(f"EVT#{recording_id}#"),
            "ProjectionExpression": "sk",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.ssh_session_recordings.query(**kwargs)
        with T.ssh_session_recordings.batch_writer() as bw:
            for it in resp.get("Items", []):
                bw.delete_item(Key={"user_sub": user_sub, "sk": it["sk"]})
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    T.ssh_session_recordings.delete_item(
        Key={"user_sub": user_sub, "sk": _meta_sk(recording_id)}
    )
    return True


# ---------------------------------------------------------------------------
# Retention cleanup
# ---------------------------------------------------------------------------

def cleanup_expired_recordings() -> int:
    """Scan for recordings past their ``expires_at`` and delete them.

    Returns the number of recordings purged. Used by a daily background task.
    """
    now = now_ts()
    purged = 0
    last_key: Optional[Dict[str, Any]] = None
    expired: List[Tuple[str, str]] = []
    while True:
        kwargs: Dict[str, Any] = {
            "FilterExpression": Key("sk").begins_with("REC#"),
            "ProjectionExpression": "user_sub, recording_id, expires_at",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.ssh_session_recordings.scan(**kwargs)
        for it in resp.get("Items", []):
            exp = _num(it.get("expires_at"))
            if exp and exp <= now:
                expired.append((it.get("user_sub", ""), it.get("recording_id", "")))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    for user_sub, recording_id in expired:
        if user_sub and recording_id and delete_recording(user_sub, recording_id):
            purged += 1
    if purged:
        logger.info("recording_cleanup purged=%d", purged)
    return purged


async def run_recording_cleanup(*, poll_interval: int = 86400) -> None:
    """Background task: daily, delete recordings past their retention window."""
    while True:
        try:
            cleanup_expired_recordings()
        except Exception:
            logger.exception("recording_cleanup error")
        await asyncio.sleep(poll_interval)


def start_recording_cleanup_task() -> None:
    """Register the retention-cleanup background task at app startup."""
    if S.ssh_session_recording_enabled:
        asyncio.ensure_future(run_recording_cleanup())
        logger.info("SSH session recording cleanup task started")
