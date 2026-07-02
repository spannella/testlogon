"""Per-room audio-room STAGE store (broadcast audio rooms).

Transport-neutral roster + role model for a broadcast session running in
`mode="audio_room"`. Mirrors the group_call_service keyspace pattern and
REUSES the existing `group_call_sessions` DynamoDB table (pk/sk), so no new
table/infra is provisioned.

Keyspace:
    pk = ROOM#{session_id}
    sk = SPK#{user_id}          — one item per on-stage participant OR raised hand

An item exists ONLY for: the host, active speakers, and listeners who have a
raised hand. Plain listeners have NO item (listeners are unbounded; counted via
the existing broadcast_viewers registry). Role transitions:
    raise_hand  -> role="listener", hand_raised=True   (item created)
    promote     -> role="speaker",  hand_raised=False
    demote/leave-> item deleted (back to a plain listener)

Fields: role (host|speaker|listener), mic_muted(bool), hand_raised(bool),
joined_at(int epoch seconds).
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

STAGE_ROLES_ON_STAGE = {"host", "speaker"}


def _table():
    from app.core.tables import T
    return T.group_call_sessions


def _pk(session_id: str) -> str:
    return f"ROOM#{session_id}"


def _sk(user_id: str) -> str:
    return f"SPK#{user_id}"


def _now() -> int:
    return int(time.time())


def _rec_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_id": item.get("user_id", ""),
        "role": item.get("role", "listener"),
        "mic_muted": bool(item.get("mic_muted", False)),
        "hand_raised": bool(item.get("hand_raised", False)),
        "joined_at": int(item.get("joined_at", 0) or 0),
    }


def get_record(session_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    resp = _table().get_item(Key={"pk": _pk(session_id), "sk": _sk(user_id)})
    item = resp.get("Item")
    return _rec_out(item) if item else None


def list_stage(session_id: str) -> List[Dict[str, Any]]:
    """All stage items for a room (host + speakers + raised hands)."""
    resp = _table().query(
        KeyConditionExpression=Key("pk").eq(_pk(session_id)) & Key("sk").begins_with("SPK#"),
    )
    return [_rec_out(i) for i in resp.get("Items", [])]


def roster(session_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """Split the stage into speakers (host+speaker) and raised hands."""
    recs = list_stage(session_id)
    speakers = [r for r in recs if r["role"] in STAGE_ROLES_ON_STAGE]
    hands = [r for r in recs if r["role"] not in STAGE_ROLES_ON_STAGE and r["hand_raised"]]
    # host first, then earliest joiners first
    speakers.sort(key=lambda r: (0 if r["role"] == "host" else 1, r["joined_at"]))
    hands.sort(key=lambda r: r["joined_at"])
    return {"speakers": speakers, "hands": hands}


def speaker_count(session_id: str) -> int:
    return sum(1 for r in list_stage(session_id) if r["role"] in STAGE_ROLES_ON_STAGE)


def _put(session_id: str, user_id: str, *, role: str, hand_raised: bool, mic_muted: bool,
         joined_at: Optional[int] = None) -> Dict[str, Any]:
    item = {
        "pk": _pk(session_id),
        "sk": _sk(user_id),
        "session_id": session_id,
        "user_id": user_id,
        "role": role,
        "hand_raised": bool(hand_raised),
        "mic_muted": bool(mic_muted),
        "joined_at": int(joined_at if joined_at is not None else _now()),
    }
    _table().put_item(Item=item)
    return _rec_out(item)


def ensure_host(session_id: str, user_id: str) -> Dict[str, Any]:
    existing = get_record(session_id, user_id)
    if existing and existing["role"] == "host":
        return existing
    joined = existing["joined_at"] if existing else None
    return _put(session_id, user_id, role="host", hand_raised=False, mic_muted=False, joined_at=joined)


def raise_hand(session_id: str, user_id: str) -> Dict[str, Any]:
    existing = get_record(session_id, user_id)
    if existing and existing["role"] in STAGE_ROLES_ON_STAGE:
        return existing  # already on stage; no-op
    joined = existing["joined_at"] if existing else None
    return _put(session_id, user_id, role="listener", hand_raised=True, mic_muted=False, joined_at=joined)


def promote(session_id: str, user_id: str) -> Dict[str, Any]:
    existing = get_record(session_id, user_id)
    joined = existing["joined_at"] if existing else None
    return _put(session_id, user_id, role="speaker", hand_raised=False, mic_muted=False, joined_at=joined)


def set_mic_muted(session_id: str, user_id: str, muted: bool) -> Optional[Dict[str, Any]]:
    existing = get_record(session_id, user_id)
    if not existing:
        return None
    return _put(session_id, user_id, role=existing["role"], hand_raised=existing["hand_raised"],
                mic_muted=bool(muted), joined_at=existing["joined_at"])


def remove(session_id: str, user_id: str) -> None:
    _table().delete_item(Key={"pk": _pk(session_id), "sk": _sk(user_id)})
