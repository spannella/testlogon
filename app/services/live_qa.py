"""Live Q&A Mode service — audience question queue, voting, host moderation (ENGAGE-003).

Distinct, self-contained implementation that stores questions in the
``live_qa_questions`` DynamoDB table and reuses the broadcast session record
(``created_by`` / ``moderators``) for host/moderator authorization plus the
broadcast SSE channel for real-time fan-out. It does NOT depend on the parallel
``broadcast_qa`` module.

Table layout (``live_qa_questions``):
  PK  session_id
  SK  question_id  (``laq_{uuid4}`` for questions, ``__qa_config__`` for the
      per-session mode toggle row)
  GSI ByStatusVotes:
      gsi_status_pk = ``LQ#{session_id}#{status}``
      gsi_votes_sk  = ``{99999999 - vote_count:08d}#{created_at}``  (descending
                      votes, then ascending submission time)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_chat_store import get_mute_status
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger(__name__)

_CONFIG_SK = "__qa_config__"
_VOTE_SORT_BASE = 99_999_999

_VALID_STATUSES = ("pending", "featured", "answered", "dismissed", "removed")

# ─── Rate limiting (separate buckets from chat / broadcast_qa) ──────────────
_LIVE_QA_RATE_LOCK = threading.Lock()
_LIVE_QA_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_ms


def _enforce_rate_limit(session_id: str, user_id: str) -> None:
    key = f"liveqa#{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = S.live_qa_rate_limit_ms
    with _LIVE_QA_RATE_LOCK:
        last = _LIVE_QA_RATE_BUCKETS.get(key, 0)
        if now_ms - last < limit_ms:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "LIVE_QA_RATE_LIMITED",
                    "message": "You can submit one question every 30 seconds.",
                    "retry_after_ms": limit_ms - (now_ms - last),
                },
            )
        _LIVE_QA_RATE_BUCKETS[key] = now_ms


def _enforce_mute(session_id: str, user_id: str) -> None:
    """Reuse the broadcast chat mute system — muted users cannot submit/vote."""
    muted_until = get_mute_status(session_id, user_id)
    if muted_until is not None:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "BROADCAST_CHAT_MUTED",
                "message": "You are temporarily muted and cannot submit questions.",
                "muted_until": muted_until,
            },
        )


def _votes_sk(vote_count: int, created_at: int) -> str:
    return f"{(_VOTE_SORT_BASE - int(vote_count)):08d}#{int(created_at)}"


# ─── Session lookup + authorization ─────────────────────────────────────────

def _load_session(session_id: str):
    """Return the broadcast session model, or raise 404."""
    from app.services.broadcast_store import get_session

    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Broadcast session not found")
    return session


def is_host_or_moderator(session_id: str, user_sub: str) -> bool:
    """True when the user owns the broadcast session or is a moderator."""
    session = _load_session(session_id)
    if getattr(session, "created_by", None) == user_sub:
        return True
    moderators = getattr(session, "moderators", None) or []
    return user_sub in moderators


def require_host(session_id: str, user_sub: str):
    """Raise 403 unless the caller owns the broadcast session."""
    session = _load_session(session_id)
    if getattr(session, "created_by", None) != user_sub:
        raise HTTPException(status_code=403, detail="Only the session owner can perform this action")
    return session


def require_host_or_moderator(session_id: str, user_sub: str):
    """Raise 403 unless the caller owns the session or is a moderator."""
    session = _load_session(session_id)
    moderators = getattr(session, "moderators", None) or []
    if getattr(session, "created_by", None) == user_sub or user_sub in moderators:
        return session
    raise HTTPException(status_code=403, detail="Only the host or a moderator can perform this action")


# ─── Q&A mode toggle (stored as a config row in the questions table) ────────

def set_qa_mode(session_id: str, enabled: bool) -> bool:
    ts = now_ts()
    T.live_qa_questions.put_item(
        Item={
            "session_id": session_id,
            "question_id": _CONFIG_SK,
            "qa_mode_enabled": bool(enabled),
            "updated_at": ts,
        }
    )
    broadcast_sse_publish(session_id, {"_type": "live_qa:mode_toggle", "enabled": bool(enabled)})
    return bool(enabled)


def get_qa_mode(session_id: str) -> bool:
    item = T.live_qa_questions.get_item(
        Key={"session_id": session_id, "question_id": _CONFIG_SK},
    ).get("Item")
    if not item:
        return False
    return bool(item.get("qa_mode_enabled", False))


# ─── Question CRUD ──────────────────────────────────────────────────────────

def submit_question(session_id: str, user_id: str, display_name: str, text: str) -> Dict[str, Any]:
    """Submit a question to the Live Q&A queue."""
    session = _load_session(session_id)

    if not get_qa_mode(session_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "LIVE_QA_DISABLED", "message": "Live Q&A mode is not active."},
        )
    if getattr(session, "status", None) not in ("live", "idle", "draft", "ready"):
        raise HTTPException(
            status_code=400,
            detail={"code": "SESSION_NOT_LIVE", "message": "Broadcast is not active."},
        )

    _enforce_mute(session_id, user_id)
    _enforce_rate_limit(session_id, user_id)

    text = (text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Question text cannot be empty.")
    max_len = S.live_qa_max_question_length
    if len(text) > max_len:
        text = text[:max_len]

    question_id = f"laq_{uuid4().hex}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "session_id": session_id,
        "question_id": question_id,
        "submitter_id": user_id,
        "submitter_display_name": display_name,
        "text": text,
        "status": "pending",
        "vote_count": 0,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 86400,
        "gsi_status_pk": f"LQ#{session_id}#pending",
        "gsi_votes_sk": _votes_sk(0, ts),
    }
    # DynamoDB rejects empty sets, so ``voters`` is only created on first vote.
    T.live_qa_questions.put_item(Item=item)

    out = _question_out(item)
    broadcast_sse_publish(session_id, {"_type": "live_qa:submitted", **out})
    return out


def get_question(session_id: str, question_id: str) -> Dict[str, Any]:
    item = T.live_qa_questions.get_item(
        Key={"session_id": session_id, "question_id": question_id},
    ).get("Item")
    if not item or question_id == _CONFIG_SK:
        raise HTTPException(status_code=404, detail="Question not found")
    return item


def _transition_status(session_id: str, question_id: str, new_status: str, *, actor: str, set_ts_field: Optional[str] = None) -> Dict[str, Any]:
    existing = get_question(session_id, question_id)
    ts = now_ts()
    vote_count = int(existing.get("vote_count", 0))
    created_at = int(existing.get("created_at", 0))

    names = {"#s": "status"}
    expr_parts = ["#s = :status", "gsi_status_pk = :pk", "gsi_votes_sk = :sk"]
    values: Dict[str, Any] = {
        ":status": new_status,
        ":pk": f"LQ#{session_id}#{new_status}",
        ":sk": _votes_sk(vote_count, created_at),
    }
    if set_ts_field:
        expr_parts.append(f"{set_ts_field} = :ts")
        values[":ts"] = ts
        expr_parts.append("last_actor = :actor")
        values[":actor"] = actor

    T.live_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    return get_question(session_id, question_id)


def feature_question(session_id: str, question_id: str, actor: str) -> Dict[str, Any]:
    """Feature a question. Only one may be featured at a time; the previously
    featured question is moved to ``answered``."""
    current = get_featured_question(session_id)
    if current and current["question_id"] != question_id:
        answer_question(session_id, current["question_id"], actor)

    updated = _transition_status(
        session_id, question_id, "featured", actor=actor, set_ts_field="featured_at"
    )
    # also record explicit featured_by for parity with output serializer
    T.live_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET featured_by = :a",
        ExpressionAttributeValues={":a": actor},
    )
    updated["featured_by"] = actor
    out = _question_out(updated)
    broadcast_sse_publish(session_id, {"_type": "live_qa:featured", **out})
    return out


def answer_question(session_id: str, question_id: str, actor: str) -> Dict[str, Any]:
    updated = _transition_status(
        session_id, question_id, "answered", actor=actor, set_ts_field="answered_at"
    )
    out = _question_out(updated)
    broadcast_sse_publish(session_id, {"_type": "live_qa:answered", **out})
    return out


def dismiss_question(session_id: str, question_id: str, actor: str) -> Dict[str, Any]:
    updated = _transition_status(
        session_id, question_id, "dismissed", actor=actor, set_ts_field="dismissed_at"
    )
    out = _question_out(updated)
    broadcast_sse_publish(session_id, {"_type": "live_qa:dismissed", **out})
    return out


def pin_question(session_id: str, question_id: str, actor: str, pinned: bool = True) -> Dict[str, Any]:
    """Pin (or unpin) a question so it sorts to the top of the queue."""
    get_question(session_id, question_id)
    T.live_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET pinned = :p, last_actor = :a",
        ExpressionAttributeValues={":p": bool(pinned), ":a": actor},
    )
    out = _question_out(get_question(session_id, question_id))
    broadcast_sse_publish(session_id, {"_type": "live_qa:pinned", **out})
    return out


def remove_question(session_id: str, question_id: str, actor: str) -> Dict[str, Any]:
    """Moderator soft-delete: hide the question from every view."""
    get_question(session_id, question_id)
    T.live_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET deleted = :t, removed_by = :a, #s = :removed, gsi_status_pk = :pk",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":t": True,
            ":a": actor,
            ":removed": "removed",
            ":pk": f"LQ#{session_id}#removed",
        },
    )
    broadcast_sse_publish(session_id, {"_type": "live_qa:removed", "session_id": session_id, "question_id": question_id})
    return {"ok": True, "question_id": question_id}


# ─── Voting ─────────────────────────────────────────────────────────────────

def upvote_question(session_id: str, question_id: str, user_id: str) -> Dict[str, Any]:
    """Add an upvote. Idempotent per user — double votes do not inflate count."""
    _enforce_mute(session_id, user_id)
    get_question(session_id, question_id)
    try:
        T.live_qa_questions.update_item(
            Key={"session_id": session_id, "question_id": question_id},
            UpdateExpression=(
                "ADD voters :uid SET vote_count = if_not_exists(vote_count, :zero) + :one"
            ),
            ConditionExpression="attribute_not_exists(voters) OR NOT contains(voters, :uid_str)",
            ExpressionAttributeValues={
                ":uid": {user_id},
                ":uid_str": user_id,
                ":one": 1,
                ":zero": 0,
            },
        )
    except T.live_qa_questions.meta.client.exceptions.ConditionalCheckFailedException:
        pass  # already voted — no-op

    return _resync_vote_sort_and_publish(session_id, question_id)


def remove_vote(session_id: str, question_id: str, user_id: str) -> Dict[str, Any]:
    """Remove an upvote. No-op if the user had not voted."""
    get_question(session_id, question_id)
    try:
        T.live_qa_questions.update_item(
            Key={"session_id": session_id, "question_id": question_id},
            UpdateExpression="DELETE voters :uid SET vote_count = vote_count - :one",
            ConditionExpression="contains(voters, :uid_str)",
            ExpressionAttributeValues={
                ":uid": {user_id},
                ":uid_str": user_id,
                ":one": 1,
            },
        )
    except T.live_qa_questions.meta.client.exceptions.ConditionalCheckFailedException:
        pass  # was not voted

    return _resync_vote_sort_and_publish(session_id, question_id)


def _resync_vote_sort_and_publish(session_id: str, question_id: str) -> Dict[str, Any]:
    question = get_question(session_id, question_id)
    vote_count = int(question.get("vote_count", 0))
    if vote_count < 0:
        vote_count = 0
    created_at = int(question.get("created_at", 0))
    T.live_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET gsi_votes_sk = :sk, vote_count = :vc",
        ExpressionAttributeValues={":sk": _votes_sk(vote_count, created_at), ":vc": vote_count},
    )
    question["vote_count"] = vote_count
    question["gsi_votes_sk"] = _votes_sk(vote_count, created_at)
    out = _question_out(question)
    broadcast_sse_publish(session_id, {"_type": "live_qa:vote", **out})
    return out


# ─── Queries ────────────────────────────────────────────────────────────────

def list_questions(session_id: str, status: str = "pending", limit: int = 50) -> List[Dict[str, Any]]:
    """List questions for a session filtered by status, sorted by votes desc."""
    if status not in _VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    resp = T.live_qa_questions.query(
        IndexName="ByStatusVotes",
        KeyConditionExpression=Key("gsi_status_pk").eq(f"LQ#{session_id}#{status}"),
        ScanIndexForward=True,  # ascending on inverted SK == descending votes
        FilterExpression=Attr("deleted").ne(True),
        Limit=limit,
    )
    items = resp.get("Items", [])
    # pinned questions float to the top regardless of votes
    items.sort(key=lambda i: (0 if i.get("pinned") else 1, i.get("gsi_votes_sk", "")))
    return [_question_out(i) for i in items]


def get_featured_question(session_id: str) -> Optional[Dict[str, Any]]:
    resp = T.live_qa_questions.query(
        IndexName="ByStatusVotes",
        KeyConditionExpression=Key("gsi_status_pk").eq(f"LQ#{session_id}#featured"),
        FilterExpression=Attr("deleted").ne(True),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _question_out(items[0])


def get_stats(session_id: str) -> Dict[str, Any]:
    items = T.live_qa_questions.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        FilterExpression=Attr("deleted").ne(True),
    ).get("Items", [])
    questions = [i for i in items if i.get("question_id") != _CONFIG_SK]

    total = len(questions)
    answered = sum(1 for q in questions if q.get("status") == "answered")
    dismissed = sum(1 for q in questions if q.get("status") == "dismissed")
    featured = sum(1 for q in questions if q.get("status") == "featured")
    total_votes = sum(int(q.get("vote_count", 0)) for q in questions)
    pending = total - answered - dismissed - featured
    return {
        "total_questions": total,
        "answered": answered,
        "dismissed": dismissed,
        "featured": featured,
        "pending": pending,
        "total_upvotes": total_votes,
        "avg_upvotes": round(total_votes / total, 1) if total > 0 else 0.0,
        "answer_rate": round((answered / total) * 100, 1) if total > 0 else 0.0,
    }


# ─── Output serializer ──────────────────────────────────────────────────────

def _question_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "question_id": item.get("question_id", ""),
        "session_id": item.get("session_id", ""),
        "submitter_id": item.get("submitter_id", ""),
        "submitter_display_name": item.get("submitter_display_name", ""),
        "text": item.get("text", ""),
        "status": item.get("status", "pending"),
        "vote_count": int(item.get("vote_count", 0)),
        "pinned": bool(item.get("pinned", False)),
        "featured_at": int(item["featured_at"]) if item.get("featured_at") else None,
        "answered_at": int(item["answered_at"]) if item.get("answered_at") else None,
        "created_at": int(item.get("created_at", 0)),
        "featured_by": item.get("featured_by"),
    }
