"""Broadcast Q&A service -- question queue, featuring, upvoting (ENGAGE-003)."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key, Attr
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.broadcast_chat_store import get_mute_status

logger = logging.getLogger(__name__)

# ─── Rate Limiting (separate from chat) ─────────────────────
_QA_RATE_LOCK = threading.Lock()
_QA_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_submit_ts_ms
_QA_RATE_LIMIT_MS = 30_000  # 1 question per 30 seconds


def _enforce_qa_rate_limit(session_id: str, user_id: str) -> None:
    key = f"qa#{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _QA_RATE_LOCK:
        last = _QA_RATE_BUCKETS.get(key, 0)
        if now_ms - last < _QA_RATE_LIMIT_MS:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "QA_RATE_LIMITED",
                    "message": "You can submit one question every 30 seconds.",
                    "retry_after_ms": _QA_RATE_LIMIT_MS - (now_ms - last),
                },
            )
        _QA_RATE_BUCKETS[key] = now_ms


def _enforce_qa_mute(session_id: str, user_id: str) -> None:
    """Reuse broadcast chat mute enforcement."""
    muted_until = get_mute_status(session_id, user_id)
    if muted_until is not None:
        raise HTTPException(status_code=403, detail={
            "code": "BROADCAST_CHAT_MUTED",
            "message": "You are temporarily muted and cannot submit questions.",
            "muted_until": muted_until,
        })


# ─── Question CRUD ──────────────────────────────────────────

def submit_question(
    session_id: str,
    user_id: str,
    display_name: str,
    text: str,
) -> Dict[str, Any]:
    """Submit a question to the Q&A queue."""
    from app.services.broadcast_store import get_session
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Broadcast session not found")
    if not session.qa_mode_enabled:
        raise HTTPException(400, {"code": "QA_MODE_DISABLED", "message": "Q&A mode is not active."})
    if session.status not in ("live", "idle", "draft", "ready"):
        raise HTTPException(400, {"code": "SESSION_NOT_LIVE", "message": "Broadcast is not active."})

    _enforce_qa_mute(session_id, user_id)
    _enforce_qa_rate_limit(session_id, user_id)

    # Validate text
    text = text.strip()
    if not text:
        raise HTTPException(400, "Question text cannot be empty.")
    if len(text) > 500:
        text = text[:500]

    question_id = f"qa_{uuid4().hex}"
    ts = now_ts()
    upvote_padded = "99999999"  # 99999999 - 0 for descending sort

    item: Dict[str, Any] = {
        "session_id": session_id,
        "question_id": question_id,
        "submitter_id": user_id,
        "submitter_display_name": display_name,
        "text": text,
        "status": "pending",
        "upvote_count": 0,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 86400,
        "GSI1PK": f"QA#{session_id}#pending",
        "GSI1SK": f"{upvote_padded}#{ts}",
    }
    # Note: DDB doesn't accept empty sets, so we don't include upvoters initially
    T.broadcast_qa_questions.put_item(Item=item)

    out = _question_out(item)
    broadcast_sse_publish(session_id, {"_type": "qa:submitted", **out})
    return out


def feature_question(
    session_id: str,
    question_id: str,
    actor: str,
) -> Dict[str, Any]:
    """Feature a question (broadcaster/moderator only).

    1. Unfeatures any currently-featured question (moves to 'answered' status).
    2. Sets the target question to 'featured' status.
    3. Publishes qa:featured event to ALL viewers.
    """
    _unfeature_current(session_id, actor)

    ts = now_ts()
    T.broadcast_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression=(
            "SET #s = :featured, featured_at = :ts, featured_by = :actor, "
            "GSI1PK = :gsi1pk, GSI1SK = :gsi1sk"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":featured": "featured",
            ":ts": ts,
            ":actor": actor,
            ":gsi1pk": f"QA#{session_id}#featured",
            ":gsi1sk": f"99999999#{ts}",
        },
    )

    question = get_question(session_id, question_id)
    out = _question_out(question)
    broadcast_sse_publish(session_id, {"_type": "qa:featured", **out})
    return out


def answer_question(
    session_id: str,
    question_id: str,
    actor: str,
) -> Dict[str, Any]:
    """Mark a featured question as answered."""
    ts = now_ts()
    T.broadcast_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression=(
            "SET #s = :answered, answered_at = :ts, "
            "GSI1PK = :gsi1pk, GSI1SK = :gsi1sk"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":answered": "answered",
            ":ts": ts,
            ":gsi1pk": f"QA#{session_id}#answered",
            ":gsi1sk": f"99999999#{ts}",
        },
    )

    out = _question_out(get_question(session_id, question_id))
    broadcast_sse_publish(session_id, {"_type": "qa:answered", **out})
    return out


def dismiss_question(
    session_id: str,
    question_id: str,
    actor: str,
) -> Dict[str, Any]:
    """Dismiss a question (pending or featured)."""
    ts = now_ts()
    T.broadcast_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression=(
            "SET #s = :dismissed, "
            "GSI1PK = :gsi1pk, GSI1SK = :gsi1sk"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":dismissed": "dismissed",
            ":gsi1pk": f"QA#{session_id}#dismissed",
            ":gsi1sk": f"99999999#{ts}",
        },
    )

    out = _question_out(get_question(session_id, question_id))
    broadcast_sse_publish(session_id, {"_type": "qa:dismissed", **out})
    return out


def remove_question(
    session_id: str,
    question_id: str,
    actor: str,
) -> Dict[str, Any]:
    """Moderator-remove a question (soft delete)."""
    T.broadcast_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET deleted = :t, removed_by = :actor, #s = :removed",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":t": True, ":actor": actor, ":removed": "removed"},
    )
    return {"ok": True, "question_id": question_id}


def upvote_question(
    session_id: str,
    question_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Toggle upvote on a question. Returns updated question."""
    try:
        T.broadcast_qa_questions.update_item(
            Key={"session_id": session_id, "question_id": question_id},
            UpdateExpression=(
                "ADD upvoters :uid "
                "SET upvote_count = if_not_exists(upvote_count, :zero) + :one"
            ),
            ConditionExpression="attribute_not_exists(upvoters) OR NOT contains(upvoters, :uid_str)",
            ExpressionAttributeValues={
                ":uid": {user_id},
                ":uid_str": user_id,
                ":one": 1,
                ":zero": 0,
            },
        )
    except T.broadcast_qa_questions.meta.client.exceptions.ConditionalCheckFailedException:
        # Already upvoted -- return current state
        pass

    # Update GSI sort key with new upvote count
    question = get_question(session_id, question_id)
    upvote_count = int(question.get("upvote_count", 0))
    upvote_padded = str(99999999 - upvote_count).zfill(8)
    created_at = int(question.get("created_at", 0))

    T.broadcast_qa_questions.update_item(
        Key={"session_id": session_id, "question_id": question_id},
        UpdateExpression="SET GSI1SK = :sk",
        ExpressionAttributeValues={":sk": f"{upvote_padded}#{created_at}"},
    )

    out = _question_out(question)
    broadcast_sse_publish(session_id, {"_type": "qa:upvote", **out})
    return out


def remove_upvote(
    session_id: str,
    question_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Remove an upvote from a question."""
    try:
        T.broadcast_qa_questions.update_item(
            Key={"session_id": session_id, "question_id": question_id},
            UpdateExpression=(
                "DELETE upvoters :uid "
                "SET upvote_count = upvote_count - :one"
            ),
            ConditionExpression="contains(upvoters, :uid_str)",
            ExpressionAttributeValues={
                ":uid": {user_id},
                ":uid_str": user_id,
                ":one": 1,
            },
        )
    except T.broadcast_qa_questions.meta.client.exceptions.ConditionalCheckFailedException:
        pass  # Was not upvoted

    question = get_question(session_id, question_id)
    out = _question_out(question)
    broadcast_sse_publish(session_id, {"_type": "qa:upvote", **out})
    return out


# ─── Query helpers ───────────────────────────────────────────

def list_questions(
    session_id: str,
    status: str = "pending",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List questions for a session, filtered by status."""
    gsi1pk = f"QA#{session_id}#{status}"
    resp = T.broadcast_qa_questions.query(
        IndexName="BySessionStatus",
        KeyConditionExpression=Key("GSI1PK").eq(gsi1pk),
        ScanIndexForward=True,  # ascending on inverted SK = descending upvotes
        FilterExpression=Attr("deleted").ne(True),
        Limit=limit,
    )
    return [_question_out(item) for item in resp.get("Items", [])]


def get_question(session_id: str, question_id: str) -> Dict[str, Any]:
    """Get a single question by PK/SK."""
    resp = T.broadcast_qa_questions.get_item(
        Key={"session_id": session_id, "question_id": question_id},
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "Question not found")
    return item


def get_featured_question(session_id: str) -> Optional[Dict[str, Any]]:
    """Get the currently featured question for a session, or None."""
    gsi1pk = f"QA#{session_id}#featured"
    resp = T.broadcast_qa_questions.query(
        IndexName="BySessionStatus",
        KeyConditionExpression=Key("GSI1PK").eq(gsi1pk),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _question_out(items[0])


def get_qa_stats(session_id: str) -> Dict[str, Any]:
    """Get Q&A engagement statistics for a session."""
    all_questions = T.broadcast_qa_questions.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        FilterExpression=Attr("deleted").ne(True),
    ).get("Items", [])

    total = len(all_questions)
    answered = sum(1 for q in all_questions if q.get("status") == "answered")
    dismissed = sum(1 for q in all_questions if q.get("status") == "dismissed")
    total_upvotes = sum(int(q.get("upvote_count", 0)) for q in all_questions)
    avg_upvotes = total_upvotes / total if total > 0 else 0

    return {
        "total_questions": total,
        "answered": answered,
        "dismissed": dismissed,
        "pending": total - answered - dismissed,
        "total_upvotes": total_upvotes,
        "avg_upvotes": round(avg_upvotes, 1),
        "answer_rate": round((answered / total) * 100, 1) if total > 0 else 0,
    }


def _unfeature_current(session_id: str, actor: str) -> None:
    """Unfeature any currently-featured question (move to answered)."""
    current = get_featured_question(session_id)
    if current:
        answer_question(session_id, current["question_id"], actor)


# ─── Output serializers ─────────────────────────────────────

def _question_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB question item to output dict."""
    return {
        "question_id": item.get("question_id", ""),
        "session_id": item.get("session_id", ""),
        "submitter_id": item.get("submitter_id", ""),
        "submitter_display_name": item.get("submitter_display_name", ""),
        "text": item.get("text", ""),
        "status": item.get("status", "pending"),
        "upvote_count": int(item.get("upvote_count", 0)),
        "featured_at": int(item["featured_at"]) if item.get("featured_at") else None,
        "answered_at": int(item["answered_at"]) if item.get("answered_at") else None,
        "created_at": int(item.get("created_at", 0)),
        "featured_by": item.get("featured_by"),
    }
