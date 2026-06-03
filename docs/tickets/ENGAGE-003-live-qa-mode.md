# ENGAGE-003: Live Q&A Mode for Broadcasts

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 10-14 days

---

## 1. Overview & Motivation

### 1.1 Problem Statement

During live broadcasts, viewers frequently want to ask questions, but their messages get buried in the fast-scrolling chat. The existing broadcast chat (`app/services/broadcast_chat_store.py`, 423 lines) handles real-time messaging with rate limiting, muting, reactions, replies, and expiring/locked messages -- but all messages share a single undifferentiated stream. <!-- CORRECTED: was "424 lines", actually 423 lines --> There is **no mechanism to**:

1. **Submit a question** that is visually distinct from chat messages.
2. **Queue questions** for the broadcaster to review and select.
3. **Feature a selected question** as a persistent overlay on the broadcast.
4. **Upvote questions** so the most popular ones rise to the top.
5. **Track question state** (pending, featured, answered, dismissed).

Without a dedicated Q&A mode, broadcasters must manually scan the chat for questions, often missing good ones in high-volume streams. This reduces audience engagement and wastes the broadcaster's cognitive bandwidth.

### 1.2 How It Works

1. Broadcaster enables "Q&A Mode" on their active broadcast session (toggle in the dashboard).
2. Viewers see a new "Ask a Question" button that opens a dedicated input field.
3. Submitted questions enter a **moderation queue** visible only to the broadcaster (and moderators).
4. The broadcaster reviews the queue and can **feature** a question, which:
   - Displays it as a persistent overlay on the viewer player.
   - Sends an SSE event to all viewers so the question appears highlighted in their chat.
5. Viewers can **upvote** questions in the queue to signal community interest.
6. After answering, the broadcaster marks the question as "answered" or "dismissed", removing the overlay.
7. Q&A mode can be toggled on/off during the broadcast without losing the question history.

### 1.3 Design Principles

- **Separate from chat**: Questions are a distinct entity from chat messages. They have their own DynamoDB partition, their own SSE event types, and their own UI treatment.
- **Moderated by default**: All questions enter the queue as `pending`. No question appears publicly until the broadcaster features it.
- **Non-disruptive toggle**: Enabling/disabling Q&A mode does not interrupt the broadcast or the chat stream.
- **Upvote-driven priority**: The queue is sorted by upvote count (descending), then submission time (ascending).

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Broadcaster | As a broadcaster, I want to enable Q&A mode so viewers can submit questions. | Toggle appears in broadcast dashboard; viewers see "Ask a Question" button after toggle. |
| Broadcaster | As a broadcaster, I want to see a queue of submitted questions sorted by popularity. | Queue panel shows questions with upvote counts; most-upvoted at top. |
| Broadcaster | As a broadcaster, I want to feature a question so my audience sees it prominently. | SSE event sent; viewer player shows question overlay; chat highlights the question. |
| Broadcaster | As a broadcaster, I want to dismiss or skip questions I don't want to answer. | "Dismiss" action hides from queue; question marked as dismissed. |
| Viewer | As a viewer, I want to submit a question during Q&A mode. | "Ask a Question" input appears; submission acknowledged with "Submitted" toast. |
| Viewer | As a viewer, I want to upvote other viewers' questions. | Upvote button on each queue item; count increments; sort order updates. |
| Viewer | As a viewer, I want to see which question the broadcaster is answering. | Featured question appears as an overlay above the chat. |
| Moderator | As a moderator, I want to remove inappropriate questions from the queue. | "Remove" action soft-deletes the question; removed questions not shown. |
| Viewer | As a viewer, I want to see a history of answered questions during this broadcast. | "Answered" tab in Q&A panel shows previously answered questions. |
| Broadcaster | As a broadcaster, I want to see analytics on Q&A engagement after the broadcast. | Post-broadcast dashboard shows question count, answer rate, avg upvotes. |

---

## 2. Current State Analysis

### 2.1 Broadcast Chat Store (`app/services/broadcast_chat_store.py`) <!-- VERIFIED: app/services/broadcast_chat_store.py exists, 423 lines -->

Chat messages are stored in `T.broadcast_chat_messages` with PK=`session_id` and SK=`{timestamp_ms}#{message_id}` (line 165): <!-- VERIFIED: app/services/broadcast_chat_store.py:165 approximate (item construction) -->

```python
item: Dict[str, Any] = {
    "session_id": session_id,
    "sort_key": sort_key,
    "message_id": msg_id,
    "sender_id": user_id,
    "sender_display_name": display_name,
    "text": text.strip(),
    "created_at": ts,
    "deleted": False,
    "ttl": ts + 7 * 24 * 3600,
}
```

The Q&A system will use a **separate table** (`broadcast_qa_questions`) rather than embedding questions in the chat table. This avoids polluting the chat history with non-conversational items and allows independent GSI structures optimized for queue sorting.

### 2.2 Broadcast SSE (`app/services/broadcast_sse.py`) <!-- VERIFIED: app/services/broadcast_sse.py exists, 50 lines -->

The real-time event system is simple and well-suited for Q&A events. The publish function (line 29): <!-- VERIFIED: app/services/broadcast_sse.py:29 broadcast_sse_publish -->

```python
def broadcast_sse_publish(session_id: str, event: Dict[str, Any]) -> None:
    """Publish an event to all subscribers of a broadcast session."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    dead = []
    for q in list(subs):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        subs.discard(q)
        if not subs:
            _BROADCAST_SUBSCRIBERS.pop(session_id, None)
```

And the subscribe function (line 11): <!-- CORRECTED: was "line 12", actually line 11 -->

```python
def broadcast_sse_subscribe(session_id: str) -> asyncio.Queue:
    """Subscribe to real-time events for a broadcast session."""
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subs = _BROADCAST_SUBSCRIBERS.setdefault(session_id, set())
    subs.add(q)
    return q
```

Q&A events (`qa:submitted`, `qa:featured`, `qa:answered`, `qa:dismissed`, `qa:upvote`) will be published through this same SSE channel.

### 2.3 Broadcast Router (`app/routers/broadcast.py`) <!-- CORRECTED: router at line 76, not 64 -->

The broadcast router (see `app/routers/broadcast.py:76`) is registered with prefix `/broadcast` and has endpoints for session management, chat, muting, and tip goals. The Q&A endpoints will be added to this same router:

```python
router = APIRouter(prefix="/broadcast", tags=["broadcast"])
```

Session creation and status tracking use the broadcast store (line 13): <!-- VERIFIED: app/routers/broadcast.py:13 -->

```python
from app.services.broadcast_store import (
    create_profile, create_session, get_session, get_output,
    list_profiles_by_creator, list_sessions_by_creator,
    list_sessions_by_status, transition_session_status,
    list_scheduled_sessions_by_creator, update_session_fields,
)
```

The Q&A mode toggle will be implemented as an `update_session_fields` call setting `qa_mode_enabled=True` on the session record.

### 2.4 Chat Rate Limiting (`app/services/broadcast_chat_store.py`) <!-- VERIFIED: app/services/broadcast_chat_store.py:20 _CHAT_RATE_LOCK -->

Chat messages are rate-limited per user per session (line 20): <!-- CORRECTED: was "line 25", actually line 20 -->

```python
_CHAT_RATE_LOCK = threading.Lock()
_CHAT_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_send_ts_ms

def _enforce_chat_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = S.broadcast_chat_rate_limit_ms
    with _CHAT_RATE_LOCK:
        last = _CHAT_RATE_BUCKETS.get(key, 0)
        if now_ms - last < limit_ms:
            raise HTTPException(status_code=429, ...)
        _CHAT_RATE_BUCKETS[key] = now_ms
```

Question submissions will use a separate, more permissive rate limit (e.g., 1 question per 30 seconds) since questions require more thought than chat messages.

### 2.5 Mute Enforcement (`app/services/broadcast_chat_store.py`) <!-- VERIFIED: app/services/broadcast_chat_store.py:117 _enforce_chat_mute -->

Muted users are prevented from chatting (line 117):

```python
def _enforce_chat_mute(session_id: str, user_id: str) -> None:
    muted_until = get_mute_status(session_id, user_id)
    if muted_until is not None:
        raise HTTPException(status_code=403, detail={
            "code": "BROADCAST_CHAT_MUTED",
            "message": "You are temporarily muted in this chat.",
            "muted_until": muted_until,
        })
```

Muted users will also be prevented from submitting questions. The same `_enforce_chat_mute` check will be called before question submission.

### 2.6 Tip Goal Progress Pattern (`app/services/broadcast_tip_goals.py`) <!-- VERIFIED: app/services/broadcast_tip_goals.py:189 _goal_out -->

The tip goal `_goal_out` serializer (line 189) provides a clean pattern for question output serialization:

```python
def _goal_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "goal_id": item.get("goal_id", ""),
        "session_id": item.get("session_id", ""),
        "label": item.get("label", ""),
        "target_cents": int(item.get("target_cents", 0)),
        "current_cents": int(item.get("current_cents", 0)),
        "reached": bool(item.get("reached", False)),
        "reached_at": int(item["reached_at"]) if item.get("reached_at") else None,
        "sort_order": int(item.get("sort_order", 0)),
        "created_at": int(item.get("created_at", 0)),
    }
```

### 2.7 Broadcast Session Fields (`app/services/broadcast_store.py`) <!-- CORRECTED: update_session_fields is at line 469, not 459 -->

The session record stores configuration flags that the frontend reads to enable/disable features. The `update_session_fields` function (see `app/services/broadcast_store.py:469`) uses a get-modify-put cycle: <!-- CORRECTED: was "**fields" kwargs pattern, actually takes a single dict argument: update_session_fields(session_id: str, fields: Dict[str, Any]) -->

```python
def update_session_fields(session_id: str, fields: Dict[str, Any]) -> BroadcastSessionModel:
    """Update arbitrary fields on a session by doing a get-modify-put cycle."""
    current = get_session(session_id)
    data = current.model_dump()
    data.update(fields)
    data["updated_at"] = now_iso()
    updated = BroadcastSessionModel(**data)
    T.broadcast_sessions.put_item(Item=session_to_item(updated))
    return updated
```

The `qa_mode_enabled` field will be added alongside existing flags like `tip_enabled`, `chat_enabled`, and `clips_enabled`.

### 2.8 Moderator System

The broadcast session stores a `moderators` list of user_sub values who can perform moderation actions (muting, message deletion). The same list will grant Q&A moderation permissions (feature, dismiss, remove questions).

---

## 3. Technical Design

### 3.1 DynamoDB Schema

**Table: `broadcast_qa_questions`**

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `session_id` | S | PK | Broadcast session this question belongs to |
| `question_id` | S | SK | Unique question ID: `qa_{uuid4().hex}` |
| `submitter_id` | S | | User who submitted the question |
| `submitter_display_name` | S | | Display name at time of submission |
| `text` | S | | Question text (max 500 chars) |
| `status` | S | | `pending`, `featured`, `answered`, `dismissed`, `removed` |
| `upvote_count` | N | | Number of upvotes |
| `upvoters` | SS | | Set of user_sub values who upvoted |
| `featured_at` | N | | Timestamp when broadcaster featured this question |
| `answered_at` | N | | Timestamp when marked as answered |
| `created_at` | N | | Submission timestamp |
| `deleted` | BOOL | | Soft-delete flag for moderator removal |
| `removed_by` | S | | Who removed it (for audit) |
| `featured_by` | S | | Who featured it |
| `ttl` | N | | DynamoDB TTL (7 days after broadcast ends) |
| `GSI1PK` | S | GSI | `QA#{session_id}#{status}` for filtered queue queries |
| `GSI1SK` | S | GSI | `{upvote_count_padded}#{created_at}` for popularity sort |

DynamoDB table definition for `scripts/local-ddb-init.py`:

```python
TableDef(
    "broadcast_qa_questions",
    "session_id",
    "question_id",
    gsi=[
        {"index_name": "BySessionStatus", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
),
```

**GSI: `BySessionStatus`**

- PK: `QA#{session_id}#{status}` -- allows querying for `pending` questions only, or `answered` questions only
- SK: `{upvote_count_padded}#{created_at}` -- composite for sorting pending questions by popularity then time

The `upvote_count_padded` is a zero-padded 8-digit number (e.g., `00000042`) to ensure correct string sort ordering. Since we want highest upvotes first, the SK is constructed as `{99999999 - upvote_count}#{created_at}` for descending sort within `ScanIndexForward=True`.

### 3.2 Question Lifecycle

```
  submit         feature           answer
  ──────>  pending  ──────>  featured  ──────>  answered
              |                  |
              |  dismiss         |  dismiss
              +──────> dismissed <──────+
              |
              |  remove (mod)
              +──────> removed
```

State transitions:
- `pending -> featured`: Broadcaster/moderator selects a question. Only one question can be `featured` at a time.
- `featured -> answered`: Broadcaster marks the question as answered. Overlay is removed.
- `featured -> dismissed`: Broadcaster dismisses without answering. Overlay is removed.
- `pending -> dismissed`: Broadcaster dismisses from queue without featuring.
- `pending -> removed`: Moderator removes (soft-delete). Question is hidden from all views.

### 3.3 Service Layer (`app/services/broadcast_qa.py`)

```python
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
    """Submit a question to the Q&A queue.

    Validates:
    - Q&A mode is enabled on the session
    - User is not muted
    - Rate limit not exceeded
    - Question text is non-empty and within length limit

    Returns the question output dict.
    """
    # Check Q&A mode is enabled
    from app.services.broadcast_store import get_session
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Broadcast session not found")
    if not session.get("qa_mode_enabled"):
        raise HTTPException(400, {"code": "QA_MODE_DISABLED", "message": "Q&A mode is not active."})
    if session.get("status") not in ("live", "idle"):
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

    item = {
        "session_id": session_id,
        "question_id": question_id,
        "submitter_id": user_id,
        "submitter_display_name": display_name,
        "text": text,
        "status": "pending",
        "upvote_count": 0,
        "upvoters": set(),  # Empty SS -- DDB handles empty sets
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 86400,
        "GSI1PK": f"QA#{session_id}#pending",
        "GSI1SK": f"{upvote_padded}#{ts}",
    }
    T.broadcast_qa_questions.put_item(Item=item)

    out = _question_out(item)
    # Only publish to broadcaster/moderators (not all viewers)
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
    # Publish to ALL viewers (featured question is public)
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
    """Toggle upvote on a question. Returns updated question.

    Uses DynamoDB ADD for the set (idempotent for the user_id),
    and atomic increment for the count. The ConditionExpression prevents
    double-counting.
    """
    try:
        T.broadcast_qa_questions.update_item(
            Key={"session_id": session_id, "question_id": question_id},
            UpdateExpression=(
                "ADD upvoters :uid "
                "SET upvote_count = if_not_exists(upvote_count, :zero) + :one"
            ),
            ConditionExpression="NOT contains(upvoters, :uid_str)",
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
    """List questions for a session, filtered by status.

    Returns sorted by upvote_count descending (via GSI1SK inverted encoding).
    """
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
```

### 3.4 Pydantic Request/Response Models

```python
# Additions for broadcast.py

class QAModeToggleIn(BaseModel):
    enabled: bool

class QAModeToggleOut(BaseModel):
    ok: bool = True
    qa_mode_enabled: bool

class QAQuestionSubmitIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)

class QAQuestionOut(BaseModel):
    question_id: str
    session_id: str
    submitter_id: str
    submitter_display_name: str
    text: str
    status: Literal["pending", "featured", "answered", "dismissed", "removed"]
    upvote_count: int
    featured_at: Optional[int] = None
    answered_at: Optional[int] = None
    created_at: int
    featured_by: Optional[str] = None

class QAQueueOut(BaseModel):
    questions: List[QAQuestionOut]
    has_more: bool = False

class QAStatsOut(BaseModel):
    total_questions: int
    answered: int
    dismissed: int
    pending: int
    total_upvotes: int
    avg_upvotes: float
    answer_rate: float
```

### 3.5 Router Endpoints Implementation

```python
# Additions to app/routers/broadcast.py

from app.services.broadcast_qa import (
    submit_question,
    feature_question,
    answer_question,
    dismiss_question,
    remove_question,
    upvote_question,
    remove_upvote,
    list_questions,
    get_featured_question,
    get_qa_stats,
)


@router.post("/sessions/{session_id}/qa-mode")
def toggle_qa_mode(
    session_id: str,
    body: QAModeToggleIn,
    ctx: dict = Depends(require_ui_session),
):
    """Toggle Q&A mode on a broadcast session. Owner only."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    if session.get("created_by") != ctx["user_sub"]:
        raise HTTPException(403, "Only the session owner can toggle Q&A mode")

    update_session_fields(session_id, {"qa_mode_enabled": body.enabled})  # CORRECTED: dict arg, not kwargs
    broadcast_sse_publish(session_id, {
        "_type": "qa:mode_toggle",
        "enabled": body.enabled,
    })
    return {"ok": True, "qa_mode_enabled": body.enabled}


@router.post("/sessions/{session_id}/qa/questions")
def submit_qa_question(
    session_id: str,
    body: QAQuestionSubmitIn,
    ctx: dict = Depends(require_ui_session),
):
    """Submit a question to the Q&A queue."""
    display_name = ctx.get("display_name", ctx["user_sub"])
    return submit_question(
        session_id=session_id,
        user_id=ctx["user_sub"],
        display_name=display_name,
        text=body.text,
    )


@router.get("/sessions/{session_id}/qa/questions")
def list_qa_questions(
    session_id: str,
    status: str = Query(default="pending"),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
):
    """List questions in the Q&A queue.

    Pending/featured/answered questions visible to broadcaster/moderators.
    Only featured and answered questions visible to regular viewers.
    """
    session = get_session(session_id)
    is_owner_or_mod = _is_session_owner_or_moderator(session, ctx["user_sub"])

    # Regular viewers can only see featured and answered
    if not is_owner_or_mod and status == "pending":
        raise HTTPException(403, "Only the broadcaster can view pending questions")

    questions = list_questions(session_id, status=status, limit=limit)
    return {"questions": questions, "has_more": len(questions) >= limit}


@router.post("/sessions/{session_id}/qa/questions/{question_id}/feature")
def feature_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Feature a question (broadcaster/moderator only)."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can feature questions")
    return feature_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/answer")
def answer_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Mark a featured question as answered."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can answer questions")
    return answer_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/dismiss")
def dismiss_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Dismiss a question."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can dismiss questions")
    return dismiss_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/remove")
def remove_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Remove a question (moderator action)."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can remove questions")
    return remove_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/upvote")
def upvote_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Upvote a question."""
    return upvote_question(session_id, question_id, ctx["user_sub"])


@router.delete("/sessions/{session_id}/qa/questions/{question_id}/upvote")
def remove_upvote_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Remove upvote from a question."""
    return remove_upvote(session_id, question_id, ctx["user_sub"])


@router.get("/sessions/{session_id}/qa/featured")
def get_featured_qa_question(
    session_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Get the currently featured question, or 204 if none."""
    from fastapi.responses import Response
    featured = get_featured_question(session_id)
    if not featured:
        return Response(status_code=204)
    return featured


@router.get("/sessions/{session_id}/qa/stats")
def get_qa_stats_endpoint(
    session_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """Get Q&A engagement statistics for a session."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can view stats")
    return get_qa_stats(session_id)


def _is_session_owner_or_moderator(session: Dict[str, Any], user_sub: str) -> bool:
    """Check if user is the session owner or a moderator."""
    if session.get("created_by") == user_sub:
        return True
    moderators = session.get("moderators", [])
    return user_sub in moderators
```

### 3.6 SSE Event Types

| Event Type | Audience | Payload | Description |
|-----------|----------|---------|-------------|
| `qa:submitted` | Broadcaster + moderators | Full question object | New question in queue |
| `qa:featured` | All viewers | Featured question (displayed as overlay) | Question being answered |
| `qa:answered` | All viewers | Question ID + answer timestamp | Overlay removed |
| `qa:dismissed` | Broadcaster + moderators | Question ID | Question dismissed from queue |
| `qa:upvote` | All viewers (if queue is public) or broadcaster only | Question ID + new upvote count | Vote count changed |
| `qa:mode_toggle` | All viewers | `{ enabled: bool }` | Q&A mode toggled on/off |
| `qa:removed` | Broadcaster + moderators | Question ID | Moderator removed question |

### 3.7 Featured Question Overlay

The featured question overlay is a persistent UI element on the viewer player. It displays:
- Submitter's display name
- Question text
- Upvote count at time of featuring
- Time since featured

The overlay is rendered client-side based on the `qa:featured` SSE event and removed when `qa:answered` or `qa:dismissed` is received.

### 3.8 Auto-Disable on Broadcast End

When a broadcast session transitions to `stopped` status, the Q&A mode is automatically disabled:

```python
# In broadcast_store.py transition_session_status, after status change:
if new_status == "stopped":
    update_session_fields(session_id, {"qa_mode_enabled": False})  # CORRECTED: dict arg, not kwargs
    broadcast_sse_publish(session_id, {"_type": "qa:mode_toggle", "enabled": False})
```

---

## 4. API Endpoints

### 4.1 Q&A Mode Toggle

```
POST /broadcast/sessions/{session_id}/qa-mode
```

Auth: `Depends(require_ui_session)` (see `app/services/sessions.py:283`) -- session owner only. <!-- NOTE: require_ui_session is defined in app/services/sessions.py, NOT app/auth/deps.py -->

Request: `{ "enabled": true }`
Response: `{ "ok": true, "qa_mode_enabled": true }`

Error responses:
- 403: Not the session owner
- 404: Session not found

### 4.2 Question Submission

```
POST /broadcast/sessions/{session_id}/qa/questions
```

Auth: `Depends(require_ui_session)` -- any authenticated, non-muted user.

Request: `{ "text": "What camera do you use?" }`
Response: `{ "question_id": "qa_abc123", "text": "...", "status": "pending", "upvote_count": 0, "created_at": 1748400000 }`

Error responses:
- 400: `QA_MODE_DISABLED` -- Q&A not active
- 400: `SESSION_NOT_LIVE` -- broadcast not active
- 403: `BROADCAST_CHAT_MUTED` -- user is muted
- 429: `QA_RATE_LIMITED` -- too frequent

### 4.3 Queue Retrieval (Broadcaster/Moderator)

```
GET /broadcast/sessions/{session_id}/qa/questions?status=pending&limit=50
```

Auth: `Depends(require_ui_session)` -- broadcaster/moderator for pending; any for featured/answered.

Query params:
- `status`: `pending` | `featured` | `answered` | `dismissed` (default `pending`)
- `limit`: int (default 50, max 200)

Response: `{ "questions": [...], "has_more": false }`

### 4.4 Question Actions

```
POST /broadcast/sessions/{session_id}/qa/questions/{question_id}/feature
POST /broadcast/sessions/{session_id}/qa/questions/{question_id}/answer
POST /broadcast/sessions/{session_id}/qa/questions/{question_id}/dismiss
POST /broadcast/sessions/{session_id}/qa/questions/{question_id}/remove
```

Auth: `Depends(require_ui_session)` -- broadcaster/moderator only.

Response: Updated question object.

### 4.5 Upvoting

```
POST   /broadcast/sessions/{session_id}/qa/questions/{question_id}/upvote
DELETE /broadcast/sessions/{session_id}/qa/questions/{question_id}/upvote
```

Auth: `Depends(require_ui_session)` -- any authenticated user.

Response: Updated question object with new `upvote_count`.

### 4.6 Featured Question (Public)

```
GET /broadcast/sessions/{session_id}/qa/featured
```

Auth: `Depends(require_ui_session)` -- any authenticated user.

Response: The currently featured question, or 204 if none.

### 4.7 Q&A Statistics

```
GET /broadcast/sessions/{session_id}/qa/stats
```

Auth: `Depends(require_ui_session)` -- broadcaster/moderator only.

Response:
```json
{
  "total_questions": 42,
  "answered": 15,
  "dismissed": 8,
  "pending": 19,
  "total_upvotes": 230,
  "avg_upvotes": 5.5,
  "answer_rate": 35.7
}
```

---

## 5. Frontend Components

### 5.1 New Components

| Component | Path | Description |
|-----------|------|-------------|
| `QAModeToggle` | `pages/broadcast/QAModeToggle.tsx` | Toggle switch for broadcaster dashboard |
| `QAQuestionInput` | `pages/broadcast/QAQuestionInput.tsx` | Viewer input for submitting questions |
| `QAQueuePanel` | `pages/broadcast/QAQueuePanel.tsx` | Broadcaster queue: sortable list with feature/dismiss/remove actions |
| `QAQuestionCard` | `pages/broadcast/QAQuestionCard.tsx` | Single question in queue with upvote button, submitter name, text |
| `QAFeaturedOverlay` | `pages/broadcast/QAFeaturedOverlay.tsx` | Persistent overlay on viewer player showing featured question |
| `QAAnsweredList` | `pages/broadcast/QAAnsweredList.tsx` | List of previously answered questions |
| `QAStatsPanel` | `pages/broadcast/QAStatsPanel.tsx` | Post-broadcast Q&A engagement statistics |

### 5.2 TypeScript Types

```typescript
// frontend/src/api/types.ts additions

export interface QAQuestion {
  question_id: string;
  session_id: string;
  submitter_id: string;
  submitter_display_name: string;
  text: string;
  status: "pending" | "featured" | "answered" | "dismissed" | "removed";
  upvote_count: number;
  featured_at?: number;
  answered_at?: number;
  created_at: number;
  featured_by?: string;
}

export interface QAQueueResponse {
  questions: QAQuestion[];
  has_more: boolean;
}

export interface QAStats {
  total_questions: number;
  answered: number;
  dismissed: number;
  pending: number;
  total_upvotes: number;
  avg_upvotes: number;
  answer_rate: number;
}
```

### 5.3 API Endpoints

```typescript
// frontend/src/api/endpoints/broadcastQA.ts

import client from "../client";  // BUG: should be `import { api } from "@/api/client"` — client.ts has no default export
import type { QAQuestion, QAQueueResponse, QAStats } from "../types";  // NOTE: should be `from "@/api/types"`

export const toggleQAMode = async (sessionId: string, enabled: boolean) =>
  client.post(`/broadcast/sessions/${sessionId}/qa-mode`, { enabled }).then(r => r.data);

export const submitQuestion = async (sessionId: string, text: string) =>
  client.post<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions`, { text }).then(r => r.data);

export const listQuestions = async (sessionId: string, status = "pending", limit = 50) =>
  client.get<QAQueueResponse>(`/broadcast/sessions/${sessionId}/qa/questions`, {
    params: { status, limit },
  }).then(r => r.data);

export const featureQuestion = async (sessionId: string, questionId: string) =>
  client.post<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions/${questionId}/feature`).then(r => r.data);

export const answerQuestion = async (sessionId: string, questionId: string) =>
  client.post<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions/${questionId}/answer`).then(r => r.data);

export const dismissQuestion = async (sessionId: string, questionId: string) =>
  client.post<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions/${questionId}/dismiss`).then(r => r.data);

export const removeQuestion = async (sessionId: string, questionId: string) =>
  client.post(`/broadcast/sessions/${sessionId}/qa/questions/${questionId}/remove`).then(r => r.data);

export const upvoteQuestion = async (sessionId: string, questionId: string) =>
  client.post<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions/${questionId}/upvote`).then(r => r.data);

export const removeUpvote = async (sessionId: string, questionId: string) =>
  client.delete<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions/${questionId}/upvote`).then(r => r.data);

export const getFeaturedQuestion = async (sessionId: string) =>
  client.get<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/featured`).then(r => r.data);

export const getQAStats = async (sessionId: string) =>
  client.get<QAStats>(`/broadcast/sessions/${sessionId}/qa/stats`).then(r => r.data);
```

### 5.4 Viewer Chat Integration

When Q&A mode is enabled, the chat panel shows an "Ask a Question" button above the message input:

```tsx
{qaEnabled && (
    <div className="border-b px-3 py-2">
        <Button variant="outline" size="sm" onClick={() => setQAOpen(true)}>
            <MessageCircleQuestion className="h-4 w-4 mr-1" /> Ask a Question
        </Button>
    </div>
)}
```

### 5.5 QAQuestionInput Component

```tsx
// frontend/src/pages/broadcast/QAQuestionInput.tsx
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { submitQuestion } from "@/api/endpoints/broadcastQA";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { toast } from "sonner";
import { Send } from "lucide-react";

interface QAQuestionInputProps {
  sessionId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function QAQuestionInput({ sessionId, open, onOpenChange }: QAQuestionInputProps) {
  const [text, setText] = useState("");

  const submitMut = useMutation({
    mutationFn: (questionText: string) => submitQuestion(sessionId, questionText),
    onSuccess: () => {
      toast.success("Question submitted! The broadcaster will review it.");
      setText("");
      onOpenChange(false);
    },
    onError: (err: any) => {
      const code = err?.response?.data?.detail?.code;
      if (code === "QA_RATE_LIMITED") {
        toast.error("Please wait before submitting another question.");
      } else if (code === "BROADCAST_CHAT_MUTED") {
        toast.error("You are currently muted.");
      } else {
        toast.error("Failed to submit question.");
      }
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Ask a Question</DialogTitle>
        </DialogHeader>
        <Textarea
          placeholder="Type your question..."
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={500}
          rows={3}
        />
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{text.length}/500</span>
          <Button
            onClick={() => submitMut.mutate(text)}
            disabled={!text.trim() || submitMut.isPending}
          >
            <Send className="h-4 w-4 mr-1" />
            {submitMut.isPending ? "Submitting..." : "Submit"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
```

### 5.6 Broadcaster Queue Panel

The queue panel replaces the chat panel when the broadcaster clicks "Q&A Queue":

```tsx
// frontend/src/pages/broadcast/QAQueuePanel.tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listQuestions, featureQuestion, dismissQuestion, removeQuestion } from "@/api/endpoints/broadcastQA";
import { QAQuestionCard } from "./QAQuestionCard";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";

interface QAQueuePanelProps {
  sessionId: string;
}

export function QAQueuePanel({ sessionId }: QAQueuePanelProps) {
  const queryClient = useQueryClient();

  const pendingQuery = useQuery({
    queryKey: ["qa-questions", sessionId, "pending"],
    queryFn: () => listQuestions(sessionId, "pending"),
    refetchInterval: 10_000,
  });

  const answeredQuery = useQuery({
    queryKey: ["qa-questions", sessionId, "answered"],
    queryFn: () => listQuestions(sessionId, "answered"),
  });

  const featureMut = useMutation({
    mutationFn: (questionId: string) => featureQuestion(sessionId, questionId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] }),
  });

  const dismissMut = useMutation({
    mutationFn: (questionId: string) => dismissQuestion(sessionId, questionId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] }),
  });

  const removeMut = useMutation({
    mutationFn: (questionId: string) => removeQuestion(sessionId, questionId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] }),
  });

  const pending = pendingQuery.data?.questions ?? [];
  const answered = answeredQuery.data?.questions ?? [];

  return (
    <Tabs defaultValue="pending">
      <TabsList className="w-full">
        <TabsTrigger value="pending" className="flex-1">
          Pending ({pending.length})
        </TabsTrigger>
        <TabsTrigger value="answered" className="flex-1">
          Answered ({answered.length})
        </TabsTrigger>
      </TabsList>
      <TabsContent value="pending">
        <ScrollArea className="h-[400px]">
          {pending.length === 0 ? (
            <p className="text-sm text-muted-foreground p-4 text-center">No questions yet</p>
          ) : (
            pending.map((q) => (
              <QAQuestionCard
                key={q.question_id}
                question={q}
                onFeature={() => featureMut.mutate(q.question_id)}
                onDismiss={() => dismissMut.mutate(q.question_id)}
                onRemove={() => removeMut.mutate(q.question_id)}
                isModerator
              />
            ))
          )}
        </ScrollArea>
      </TabsContent>
      <TabsContent value="answered">
        <ScrollArea className="h-[400px]">
          {answered.map((q) => (
            <QAQuestionCard key={q.question_id} question={q} isModerator={false} />
          ))}
        </ScrollArea>
      </TabsContent>
    </Tabs>
  );
}
```

### 5.7 QAFeaturedOverlay Component

```tsx
// frontend/src/pages/broadcast/QAFeaturedOverlay.tsx
import { Card, CardContent } from "@/components/ui/card";
import { MessageCircleQuestion, ThumbsUp } from "lucide-react";
import type { QAQuestion } from "@/api/types";

interface QAFeaturedOverlayProps {
  question: QAQuestion;
}

export function QAFeaturedOverlay({ question }: QAFeaturedOverlayProps) {
  return (
    <Card className="absolute top-4 left-4 right-4 z-10 bg-background/90 backdrop-blur-sm border-primary/50">
      <CardContent className="p-3">
        <div className="flex items-start gap-2">
          <MessageCircleQuestion className="h-5 w-5 text-primary mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-primary">
              {question.submitter_display_name} asks:
            </p>
            <p className="text-sm mt-1">{question.text}</p>
            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
              <ThumbsUp className="h-3 w-3" />
              <span>{question.upvote_count}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
```

### 5.8 SSE Event Handling

```tsx
// In useBroadcastStream hook
case "qa:mode_toggle":
    setQAEnabled(event.enabled);
    if (event.enabled) {
        toast.info("Q&A mode is now active! You can ask questions.");
    }
    break;
case "qa:featured":
    setFeaturedQuestion(event);
    break;
case "qa:answered":
case "qa:dismissed":
    setFeaturedQuestion(null);
    queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] });
    break;
case "qa:submitted":
    // Only shown to broadcaster/moderators
    queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId, "pending"] });
    break;
case "qa:upvote":
    queryClient.setQueryData(
        ["qa-questions", sessionId, "pending"],
        (old: QAQueueResponse | undefined) => {
            if (!old) return old;
            return {
                ...old,
                questions: old.questions
                    .map(q => q.question_id === event.question_id
                        ? { ...q, upvote_count: event.upvote_count }
                        : q
                    )
                    .sort((a, b) => b.upvote_count - a.upvote_count),
            };
        }
    );
    break;
```

### 5.9 Dashboard Tab Integration

```tsx
// In BroadcastDashboard.tsx
<Tabs defaultValue="chat">
    <TabsList>
        <TabsTrigger value="chat">Chat</TabsTrigger>
        {qaEnabled && (
            <TabsTrigger value="qa">
                Q&A Queue ({pendingCount})
            </TabsTrigger>
        )}
        <TabsTrigger value="goals">Goals</TabsTrigger>
    </TabsList>
    <TabsContent value="chat"><ChatPanel /></TabsContent>
    {qaEnabled && (
        <TabsContent value="qa">
            <QAQueuePanel sessionId={sessionId} />
        </TabsContent>
    )}
    <TabsContent value="goals"><TipGoalsPanel /></TabsContent>
</Tabs>
```

---

## 6. E2E Test Plan

### Section 89: Q&A Mode Toggle API

| # | Test | Assertion |
|---|------|-----------|
| 89.1 | Enable Q&A mode on active session | 200, qa_mode_enabled=true |
| 89.2 | Disable Q&A mode | 200, qa_mode_enabled=false |
| 89.3 | Non-owner cannot toggle Q&A mode | 403 |
| 89.4 | Toggle on non-existent session returns 404 | 404 |
| 89.5 | Q&A mode persists across re-fetches | GET session shows qa_mode_enabled |

### Section 90: Question Submission API

| # | Test | Assertion |
|---|------|-----------|
| 90.1 | Viewer submits a question | 200, question_id returned, status=pending |
| 90.2 | Muted viewer cannot submit | 403, BROADCAST_CHAT_MUTED |
| 90.3 | Rate-limited viewer gets 429 | 429 after rapid submissions |
| 90.4 | Question text truncated at 500 chars | Text capped at 500 |
| 90.5 | Q&A mode disabled rejects submission | 400, QA_MODE_DISABLED |
| 90.6 | Empty question text rejected | 400 |
| 90.7 | Question created_at is a valid timestamp | created_at > 0 |
| 90.8 | Submitted question appears in pending queue | GET questions includes submitted question |

### Section 91: Queue & Actions API

| # | Test | Assertion |
|---|------|-----------|
| 91.1 | List pending questions sorted by upvotes | Array sorted descending by upvote_count |
| 91.2 | Feature a question | status=featured, featured_at set |
| 91.3 | Featuring a new question unfeatures the previous | Only one featured at a time; previous becomes answered |
| 91.4 | Answer a featured question | status=answered, answered_at set |
| 91.5 | Dismiss a pending question | status=dismissed |
| 91.6 | Moderator removes a question | deleted=true, question hidden from queue |
| 91.7 | Non-owner/non-moderator cannot feature | 403 |
| 91.8 | Get featured question returns current | 200 with featured question |
| 91.9 | Get featured question when none returns 204 | 204 No Content |
| 91.10 | Regular viewer cannot view pending queue | 403 |
| 91.11 | Regular viewer can view answered queue | 200 |

### Section 92: Upvote API

| # | Test | Assertion |
|---|------|-----------|
| 92.1 | Upvote a question | upvote_count incremented to 1 |
| 92.2 | Remove upvote | upvote_count decremented to 0 |
| 92.3 | Cannot upvote same question twice | Count stays at 1 (idempotent) |
| 92.4 | Multiple users upvote same question | Count reflects total unique upvoters |
| 92.5 | Upvote changes sort order in queue | Higher-upvoted question appears first |

### Section 93: Q&A UI

| # | Test | Assertion |
|---|------|-----------|
| 93.1 | "Ask a Question" button appears when Q&A enabled | Button visible in chat panel |
| 93.2 | Featured question overlay appears on viewer | Overlay element visible with question text |
| 93.3 | Broadcaster queue panel shows pending questions | Queue panel renders with correct count |
| 93.4 | Q&A mode toggle switch works | Toggle flips qa_mode_enabled |
| 93.5 | Dismissed question removed from pending list | Question disappears from pending tab |
| 93.6 | Answered questions appear in answered tab | Answered tab shows previously answered questions |

### Section 93b: Q&A Statistics API

| # | Test | Assertion |
|---|------|-----------|
| 93b.1 | Stats endpoint returns correct counts | total_questions, answered, pending match actual |
| 93b.2 | Answer rate calculated correctly | (answered/total)*100 |
| 93b.3 | Non-owner cannot access stats | 403 |

---

## 7. Edge Cases

1. **Broadcast ends while Q&A active**: When a broadcast transitions to `stopped`, Q&A mode is automatically disabled. Pending questions remain in DDB for review but no new submissions are accepted. The frontend removes the "Ask a Question" button when `session:stopped` is received.

2. **Featured question while broadcast stops**: The overlay disappears when the viewer detects the `session:stopped` SSE event. The featured question transitions to `answered` status automatically.

3. **Upvote count race condition**: Two users upvoting simultaneously could both pass the `NOT contains(upvoters, :uid)` check. The `ADD upvoters :uid` is idempotent for sets, and the count uses atomic increment. Worst case: count is 1 too high. Acceptable for a non-financial counter. A periodic repair job could recount from the `upvoters` set if needed.

4. **Queue sorting stability**: When two questions have the same upvote count, secondary sort is by `created_at` ascending (first-come-first-served). The GSI sort key encodes both values: `{99999999 - upvote_count}#{created_at}`.

5. **Question length and content**: Questions are plain text, max 500 characters. No markdown, no links. Rendered with `escape()` to prevent XSS. The Pydantic model enforces `max_length=500`.

6. **Moderator vs. broadcaster permissions**: Both the session owner and users in the `moderators` list can feature, dismiss, and remove questions. Only the session owner can toggle Q&A mode.

7. **SSE event routing**: `qa:submitted` events are published to ALL SSE subscribers for the session, but the frontend only shows them in the broadcaster/moderator UI. Regular viewers ignore `qa:submitted` events. Alternatively, a future enhancement could use per-user SSE channels, but the current broadcast SSE is per-session.

8. **Upvote on featured question**: Users can still upvote a question after it has been featured. The upvote count updates in real-time on the overlay. This is intentional -- it lets the audience signal agreement while the broadcaster is answering.

9. **Submitter upvoting own question**: The system does not prevent a submitter from upvoting their own question. This is acceptable -- the upvote count is a soft signal, not a financial metric. Self-upvote prevention could be added as a future enhancement.

10. **High-volume broadcasts**: In a broadcast with 10,000+ viewers, the Q&A rate limit (1 per 30s per user) means at most ~333 questions per second. DDB write throughput at this rate requires provisioned capacity. The `broadcast_qa_questions` table should use on-demand capacity mode.

11. **Question deduplication**: Two viewers asking the same question is allowed. The broadcaster can dismiss duplicates manually. Automated dedup (e.g., fuzzy text matching) is a future enhancement.

---

## 8. Security Considerations

1. **Authorization**: Q&A toggle requires session ownership. Feature/dismiss/remove require session ownership or moderator status. Question submission requires authenticated session + non-muted status.

2. **Rate limiting**: Separate rate limit for question submission (1 per 30 seconds) prevents spam. Uses the same in-memory bucket pattern as chat rate limiting. The bucket key is `qa#{session_id}#{user_id}`, separate from chat buckets.

3. **Content moderation**: Questions enter a moderated queue by default. No question is publicly visible until explicitly featured by the broadcaster. This prevents abusive content from reaching the audience.

4. **Mute enforcement**: Muted users cannot submit questions or upvote. The `_enforce_qa_mute` function reuses the chat mute system, ensuring consistency.

5. **XSS prevention**: Question text is HTML-escaped before rendering. The featured question overlay uses React's automatic JSX escaping (textContent, not dangerouslySetInnerHTML).

6. **DynamoDB TTL**: Questions are automatically deleted 7 days after the broadcast ends, preventing indefinite storage growth.

7. **Upvote manipulation**: Upvotes use DDB set operations (`ADD upvoters :uid`), which are idempotent per user_sub. A user cannot inflate the count by sending multiple upvote requests.

8. **Queue visibility**: Regular viewers can only see `featured` and `answered` questions. The `pending` queue is restricted to broadcaster/moderators. This prevents viewers from seeing questions the broadcaster chose not to feature.

---

## 9. Rollout Plan

1. **Phase 1** (days 1-4): Backend -- DDB table definition, broadcast_qa.py service (submit, feature, answer, dismiss, remove, upvote), router endpoints in broadcast.py, Q&A mode toggle via update_session_fields.

2. **Phase 2** (days 5-7): SSE integration -- Q&A event types published through broadcast_sse_publish, auto-disable on broadcast stop, featured question management.

3. **Phase 3** (days 8-10): Frontend -- QAModeToggle, QAQuestionInput, QAQueuePanel, QAQuestionCard, QAFeaturedOverlay. SSE event handlers in useBroadcastStream. Dashboard tab integration.

4. **Phase 4** (days 11-14): E2E tests (sections 89-93b), Q&A statistics endpoint, performance testing with simulated high-volume Q&A, QA.

Feature flag: `QA_MODE_ENABLED` (default `false`). When disabled, the Q&A toggle is hidden in the dashboard, and the `qa-mode` endpoint returns 400. The feature flag is checked in both the backend (endpoint handler) and frontend (QAModeToggle visibility).

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| Broadcast chat store | `app/services/broadcast_chat_store.py` | 423 lines | VERIFIED |
| Broadcast SSE | `app/services/broadcast_sse.py` | 49 lines | VERIFIED |
| `broadcast_sse_publish` | `app/services/broadcast_sse.py` | 29 | VERIFIED |
| `broadcast_sse_subscribe` | `app/services/broadcast_sse.py` | 11 | VERIFIED |
| Broadcast router | `app/routers/broadcast.py` | 76 (router def), 3969 lines | VERIFIED (ticket said line 64) |
| `_CHAT_RATE_LOCK` | `app/services/broadcast_chat_store.py` | 20 | VERIFIED |
| `_enforce_chat_mute` | `app/services/broadcast_chat_store.py` | 117 | VERIFIED |
| `_goal_out` | `app/services/broadcast_tip_goals.py` | 189 | VERIFIED |
| `update_session_fields` | `app/services/broadcast_store.py` | 469 | VERIFIED (ticket said 459) |
| `send_chat_message` | `app/services/broadcast_chat_store.py` | 136 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py) |
| Broadcast Q&A service | `app/services/broadcast_qa.py` | exists (13276 bytes) | VERIFIED |
| Q&A toggle endpoint | `app/routers/broadcast.py` | 3822 | VERIFIED |
| Frontend QA API | `frontend/src/api/endpoints/broadcastQA.ts` | exists | VERIFIED (BUG: uses `import client from "../client"` — no default export in client.ts) |
| QAModeToggle | `frontend/src/pages/broadcast/QAModeToggle.tsx` | exists (1133 bytes) | VERIFIED |
| QAQuestionInput | `frontend/src/pages/broadcast/QAQuestionInput.tsx` | exists (2230 bytes) | VERIFIED |
| QAQueuePanel | `frontend/src/pages/broadcast/QAQueuePanel.tsx` | exists (3230 bytes) | VERIFIED |
| QAQuestionCard | `frontend/src/pages/broadcast/QAQuestionCard.tsx` | exists (2345 bytes) | VERIFIED |
| QAFeaturedOverlay | `frontend/src/pages/broadcast/QAFeaturedOverlay.tsx` | exists (1110 bytes) | VERIFIED |
| QAStatsPanel | `frontend/src/pages/broadcast/QAStatsPanel.tsx` | exists (1801 bytes) | VERIFIED |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_broadcast_qa.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_engage_003_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_engage_003_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_engage_003_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_engage_003_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_engage_003_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_engage_003_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_engage_003_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_engage_003_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/broadcast-qa.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 14

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `QA_MODE_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `QA_MODE_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `QA_MODE_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
