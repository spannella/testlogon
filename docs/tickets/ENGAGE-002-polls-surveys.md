# ENGAGE-002: Standalone Polls & Surveys in the Newsfeed

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 10-14 days

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform's newsfeed (`app/routers/newsfeed.py`, 5954 lines) supports rich text posts, images, videos, locked content, and tip-lottery mechanics -- but has **no native poll or survey capability**. <!-- CORRECTED: was "5776 lines", then corrected to 5775, actually 5954 lines --> Creators who want to gauge audience preferences or collect structured feedback must resort to external polling services (Google Forms, Strawpoll) and paste links into posts, which:

1. Breaks the engagement loop -- users leave the platform to vote.
2. Provides no real-time feedback -- results are not visible inline.
3. Cannot leverage the existing SSE infrastructure for live vote count updates.
4. Misses monetization opportunities -- polls cannot be gated behind subscriptions or unlock mechanics.

The platform already has a **meeting poll** implementation in broadcast chat (`app/services/broadcast_chat_store.py`) but it is tightly coupled to broadcast sessions and DM conversations (calendar integration), not the newsfeed. A newsfeed-native poll system would provide a first-class content type alongside text posts.

### 1.2 How It Works

1. Creator opens the post composer and selects "Create Poll" (or "Create Survey" for multi-question mode).
2. For a poll: they enter a question, 2-6 answer options, select single-choice or multi-choice, and optionally set a closing time.
3. For a survey: they add multiple questions, each with its own option set and choice mode.
4. After publishing, the poll/survey appears inline in the newsfeed as a special post type.
5. Viewers vote by clicking an option. Votes are recorded immediately and the updated tallies are pushed to all connected clients via SSE.
6. Results are shown as horizontal bar charts with counts and percentages.
7. After the poll closes (either by timer or manually), no further votes are accepted and final results are displayed.

### 1.3 Design Principles

- **Post-native**: Polls and surveys are stored as newsfeed posts with `post_type: "poll"` or `post_type: "survey"`. They appear in the feed alongside standard posts and participate in the same visibility, locking, and pagination systems.
- **Real-time**: Vote counts update in real-time via the existing newsfeed SSE hub.
- **Privacy**: By default, votes are anonymous (only counts are shown). An optional "public votes" mode reveals who voted for what.
- **Time-bounded**: Optional `closes_at` timestamp after which votes are frozen.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to create a poll with 4 options so my audience can vote on my next content topic. | Poll appears in feed; viewers can click to vote; counts update live. |
| Creator | As a creator, I want to set a poll to close after 24 hours. | After 24h, votes are frozen; "Closed" badge appears; final results shown. |
| Creator | As a creator, I want to create a multi-question survey. | Survey with 3 questions renders inline; each question has its own bar chart. |
| Viewer | As a viewer, I want to see real-time vote percentages as others vote. | SSE event updates bar chart without page reload. |
| Viewer | As a viewer, I want to change my vote before the poll closes. | Click a different option; previous vote is removed; counts update. |
| Creator | As a creator, I want to close my poll early. | "Close Poll" button sets `closes_at` to now; no further votes accepted. |
| Creator | As a creator, I want to gate my poll behind a subscription. | Poll post uses existing `visibility: "followers"` or lock mechanics. |
| Creator | As a creator, I want to see voter breakdown per option for non-anonymous polls. | Results dialog shows voter list per option. |
| Viewer | As a viewer, I want to see whether I already voted and which option I chose. | My selected option is highlighted in the poll UI. |

---

## 2. Current State Analysis

### 2.1 Newsfeed Post Creation (`app/routers/newsfeed.py`) <!-- VERIFIED: app/routers/newsfeed.py exists -->

The `CreatePostRequest` model (line 1276) defines the post creation schema: <!-- CORRECTED: was line 1257, actually line 1276 -->

```python
class CreatePostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    image_variants: Optional[List[Dict[str, Any]]] = Field(default=None)
    tags: List[str] = Field(default_factory=list)
    video_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^v_[a-f0-9]{32}$")
    visibility: Literal["followers", "public"] = "followers"
    lock_type: Optional[Literal["fixed_price", "tip_lottery"]] = None
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    ...
```

Posts are stored using the single-table pattern with `pk=POST#{post_id}`, `sk=META`, and a feed reference item `GSI1PK=FEED#{user_id}` (see `app/routers/newsfeed.py:1818`): <!-- CORRECTED: was "line 1799", then corrected to 1791, actually line 1818 (_write_feed_ref_for_published_post) -->

```python
def _write_feed_ref_for_published_post(*, user_id: str, post_id: str, created_at: str) -> None:
    feed_item = {
        "pk": pk_post(post_id),
        "sk": f"FEEDREF#{user_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{user_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    ddb_put_item(feed_item)
```

Poll posts will extend `CreatePostRequest` with poll-specific fields and use the same feed reference pattern.

### 2.2 Post Serialization (`_post_to_dict`) <!-- CORRECTED: _post_to_dict is at line 1900, not 1864 -->

The `_post_to_dict` function (see `app/routers/newsfeed.py:1900`) maps DDB items to the frontend shape. It already handles `post_type` (line 2006): <!-- CORRECTED: was "line 1969", then corrected to 1970, actually line 2006 -->

```python
return {
    ...
    # BCAST-010: broadcast post type and metadata
    "post_type": post.get("post_type", "standard"),
    "broadcast_meta": post.get("broadcast_meta"),
    # SOCIAL-002: repost count
    "repost_count": int(post.get("repost_count", 0)),
    "reposted_by_me": _check_reposted_by_me(viewer_id, post_id) if viewer_id else False,
    # SOCIAL-006: hashtags/topics
    "tags": list(post.get("tags") or []),
}
```

Poll posts will set `post_type: "poll"` or `post_type: "survey"` and include `poll_data` / `survey_data` in the serialized output.

### 2.3 Meeting Poll Pattern (`app/services/broadcast_chat_store.py`) <!-- VERIFIED: app/services/broadcast_chat_store.py exists -->

The broadcast chat system includes meeting polls with a similar structure. The `send_chat_message` function (line 136) handles various message kinds: <!-- VERIFIED: app/services/broadcast_chat_store.py:136 -->

```python
def send_chat_message(
    session_id: str, user_id: str, display_name: str, text: str,
    *, skip_rate_limit: bool = False,
    reply_to_message_id: Optional[str] = None,
    expires_in_seconds: Optional[int] = None,
    lock_price_cents: Optional[int] = None,
    lock_description: Optional[str] = None,
) -> Dict[str, Any]:
```

And the SSE dispatch pattern (line 214): <!-- VERIFIED: app/services/broadcast_chat_store.py:214 -->

```python
out = _chat_msg_out(item)
broadcast_sse_publish(session_id, {"_type": "chat:message", **out})
```

The newsfeed poll will use the same SSE publish pattern but through the newsfeed `sse_hub` (see `app/routers/newsfeed.py:2089`): <!-- CORRECTED: SSEHub class at line 2051, sse_hub instance at line 2089 (ticket said 2051) -->

```python
sse_hub = SSEHub()

async def publish(self, user_id: str, event: Dict[str, Any]) -> int:
    async with self._lock:
        qs = list(self._conns.get(user_id, set()))
    delivered = 0
    for q in qs:
        try:
            q.put_nowait(event)
            delivered += 1
        except asyncio.QueueFull:
            pass
    return delivered
```

### 2.4 Newsfeed SSE Stream (`app/routers/newsfeed.py`) <!-- CORRECTED: SSE endpoint is at line 2160, not 2122 -->

The SSE endpoint at `/sse` (see `app/routers/newsfeed.py:2160`) already delivers real-time events: <!-- CORRECTED: was line 2122, actually line 2160 -->

```python
@router.get("/sse")
async def sse(request: Request, user_id: UserIdDep):
    q = await sse_hub.add(user_id)
    async def _gen():
        try:
            async for chunk in sse_event_stream(request, user_id, q):
                yield chunk
        finally:
            await sse_hub.remove(user_id, q)
    return StreamingResponse(_gen(), media_type="text/event-stream")
```

Poll vote events will be published through this SSE stream with `type: "poll:vote_update"`.

### 2.5 Reaction System (Existing Pattern) <!-- CORRECTED: _reaction_summaries is at line 1771, not 1744 -->

The post reaction system in `_post_to_dict` computes per-emoji counts (line 1744):

```python
def _reaction_summaries(reactions_map: Dict, viewer_id: Optional[str] = None):
    counts: Dict[str, int] = {}
    mine: List[str] = []
    for emoji, users in (reactions_map or {}).items():
        if isinstance(users, dict) and users:
            counts[emoji] = len(users)
            if viewer_id and users.get(viewer_id):
                mine.append(emoji)
    return counts, mine
```

Poll votes use a conceptually similar structure: a map of `{option_id: {user_id: True}}` for per-option voter tracking. However, unlike reactions (which allow multiple emojis), single-choice polls must enforce mutual exclusivity.

### 2.6 Post Quota and Rate Limiting (`app/routers/newsfeed.py`) <!-- VERIFIED: app/routers/newsfeed.py:606 _enforce_newsfeed_post_quota_precheck -->

The existing post creation rate limiter at line 606 enforces a maximum number of posts per user per time window:

```python
def _enforce_newsfeed_post_quota_precheck(user_id: str) -> None:
    """Raise 429 if user has exceeded the post creation quota."""
    ...
```

Poll posts go through this same rate limiter, preventing poll spam without additional configuration. This means poll creation is automatically bounded by the same quotas as regular posts.

### 2.7 Post Locking and Visibility

Polls inherit the existing lock/visibility system from regular posts. A poll can be:
- **Locked** (fixed_price or tip_lottery): Viewers must unlock to see the poll options and vote. The locked body shows "[Locked content]".
- **Visibility-gated**: `followers` or `public`. Only visible users can vote.

This is handled by `_post_to_dict` which already checks `locked_body` flag and redacts content accordingly.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

Poll data is embedded directly in the post item (single-table pattern) rather than in a separate table, keeping read latency low for feed rendering.

**Post item extensions for polls:**

| Field | Type | Description |
|-------|------|-------------|
| `post_type` | S | `"poll"` or `"survey"` |
| `poll_data` | M | Poll metadata (see below) |
| `poll_votes` | M | Vote tallies: `{question_id: {option_id: {user_sub: True}}}` |
| `poll_vote_counts` | M | Denormalized counts: `{question_id: {option_id: N}}` (for read performance) |
| `poll_total_votes` | N | Total vote count across all questions (for simple polls) |

**`poll_data` map structure:**

```json
{
  "questions": [
    {
      "question_id": "q_abc123",
      "text": "What should I stream next?",
      "choice_mode": "single",
      "options": [
        {"option_id": "opt_1", "text": "Horror game"},
        {"option_id": "opt_2", "text": "Cooking stream"},
        {"option_id": "opt_3", "text": "Music session"},
        {"option_id": "opt_4", "text": "AMA"}
      ],
      "max_selections": 1
    }
  ],
  "closes_at": 1748486400,
  "closed": false,
  "anonymous": true,
  "allow_vote_change": true,
  "total_votes": 0
}
```

For surveys (multi-question), `questions` contains multiple entries. Each question gets its own `poll_votes_q_{question_id}` attribute on the post item.

**Overflow table for high-volume polls: `poll_votes_overflow`**

When a poll option exceeds 1000 voters, the system switches to a separate table to avoid the 400KB DynamoDB item size limit:

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `vote_key` | S | PK | `{post_id}#{question_id}#{option_id}` |
| `user_sub` | S | SK | Voter user ID |
| `voted_at` | N | | Vote timestamp |
| `GSI1PK` | S | GSI | `USERVOTE#{user_sub}` (for user's vote lookup) |
| `GSI1SK` | S | GSI | `{post_id}#{question_id}` |

```python
TableDef(
    "poll_votes_overflow",
    "vote_key",
    "user_sub",
    gsi=[
        {"index_name": "ByUser", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
),
```

### 3.2 Vote Storage

**Single-choice vote (inline mode, <1000 voters per option):**

When a user votes for `opt_2` on question `q_abc123`:

```python
# app/services/poll_votes.py

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from fastapi import HTTPException
from app.core.tables import T
from app.core.time import now_ts

def cast_vote(
    post_id: str,
    question_id: str,
    option_id: str,
    user_sub: str,
    poll_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Record a vote for a poll option.

    Handles:
    - Closed poll rejection
    - Single-choice mutual exclusivity
    - Vote change (remove old, add new)
    - Atomic count update
    - Overflow detection

    Returns updated vote_counts for the question.
    """
    # Check if poll is closed
    if poll_data.get("closed"):
        raise HTTPException(409, {"code": "POLL_CLOSED", "message": "This poll is closed."})
    closes_at = poll_data.get("closes_at")
    if closes_at and int(closes_at) <= now_ts():
        raise HTTPException(409, {"code": "POLL_CLOSED", "message": "This poll has closed."})

    # Find the question
    question = _find_question(poll_data, question_id)
    if not question:
        raise HTTPException(404, "Question not found")

    # Validate option exists
    valid_options = {o["option_id"] for o in question["options"]}
    if option_id not in valid_options:
        raise HTTPException(400, "Invalid option_id")

    choice_mode = question.get("choice_mode", "single")

    # Get current user vote for this question
    current_vote = _get_user_vote(post_id, question_id, user_sub)

    if choice_mode == "single":
        if current_vote and current_vote == option_id:
            # Already voted for this option -- no-op
            return _get_vote_counts(post_id, question_id)

        if current_vote:
            # Vote change -- check if allowed
            if not poll_data.get("allow_vote_change", True):
                raise HTTPException(409, {"code": "VOTE_CHANGE_DISABLED", "message": "Vote changes are not allowed."})
            # Remove old vote atomically
            _remove_vote(post_id, question_id, current_vote, user_sub)

        # Add new vote
        _add_vote(post_id, question_id, option_id, user_sub)

    elif choice_mode == "multi":
        max_sel = question.get("max_selections", len(valid_options))
        user_votes = _get_user_multi_votes(post_id, question_id, user_sub)
        if option_id in user_votes:
            # Toggle off
            _remove_vote(post_id, question_id, option_id, user_sub)
        else:
            if len(user_votes) >= max_sel:
                raise HTTPException(400, f"Maximum {max_sel} selections allowed")
            _add_vote(post_id, question_id, option_id, user_sub)

    return _get_vote_counts(post_id, question_id)


def _add_vote(post_id: str, question_id: str, option_id: str, user_sub: str) -> None:
    """Add a vote -- uses inline storage for small polls, overflow table for large."""
    pk = f"POST#{post_id}"

    # Try inline DDB map update first
    try:
        T.app_single_table.update_item(
            Key={"pk": pk, "sk": "META"},
            UpdateExpression=(
                "SET poll_votes.#qid.#oid.#uid = :t, "
                "poll_vote_counts.#qid.#oid = if_not_exists(poll_vote_counts.#qid.#oid, :zero) + :one, "
                "poll_total_votes = if_not_exists(poll_total_votes, :zero) + :one"
            ),
            ExpressionAttributeNames={
                "#qid": question_id,
                "#oid": option_id,
                "#uid": user_sub,
            },
            ExpressionAttributeValues={":t": True, ":one": 1, ":zero": 0},
        )
    except Exception as exc:
        # If item size limit approached, use overflow table
        if "ValidationException" in str(exc) and "size" in str(exc).lower():
            _add_vote_overflow(post_id, question_id, option_id, user_sub)
        else:
            raise


def _remove_vote(post_id: str, question_id: str, option_id: str, user_sub: str) -> None:
    """Remove a vote from the inline map and decrement count."""
    pk = f"POST#{post_id}"
    try:
        T.app_single_table.update_item(
            Key={"pk": pk, "sk": "META"},
            UpdateExpression=(
                "REMOVE poll_votes.#qid.#oid.#uid "
                "SET poll_vote_counts.#qid.#oid = poll_vote_counts.#qid.#oid - :one, "
                "poll_total_votes = poll_total_votes - :one"
            ),
            ExpressionAttributeNames={
                "#qid": question_id,
                "#oid": option_id,
                "#uid": user_sub,
            },
            ExpressionAttributeValues={":one": 1},
        )
    except Exception:
        _remove_vote_overflow(post_id, question_id, option_id, user_sub)


def _add_vote_overflow(post_id: str, question_id: str, option_id: str, user_sub: str) -> None:
    """Store vote in overflow table for high-volume polls."""
    vote_key = f"{post_id}#{question_id}#{option_id}"
    T.poll_votes_overflow.put_item(Item={
        "vote_key": vote_key,
        "user_sub": user_sub,
        "voted_at": now_ts(),
        "GSI1PK": f"USERVOTE#{user_sub}",
        "GSI1SK": f"{post_id}#{question_id}",
    })
    # Still increment the denormalized count on the post item
    T.app_single_table.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=(
            "SET poll_vote_counts.#qid.#oid = if_not_exists(poll_vote_counts.#qid.#oid, :zero) + :one, "
            "poll_total_votes = if_not_exists(poll_total_votes, :zero) + :one"
        ),
        ExpressionAttributeNames={"#qid": question_id, "#oid": option_id},
        ExpressionAttributeValues={":one": 1, ":zero": 0},
    )


def _remove_vote_overflow(post_id: str, question_id: str, option_id: str, user_sub: str) -> None:
    """Remove vote from overflow table."""
    vote_key = f"{post_id}#{question_id}#{option_id}"
    T.poll_votes_overflow.delete_item(Key={"vote_key": vote_key, "user_sub": user_sub})
    T.app_single_table.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=(
            "SET poll_vote_counts.#qid.#oid = poll_vote_counts.#qid.#oid - :one, "
            "poll_total_votes = poll_total_votes - :one"
        ),
        ExpressionAttributeNames={"#qid": question_id, "#oid": option_id},
        ExpressionAttributeValues={":one": 1},
    )


def _get_user_vote(post_id: str, question_id: str, user_sub: str) -> Optional[str]:
    """Get the user's current single-choice vote for a question.

    Returns option_id or None.
    """
    pk = f"POST#{post_id}"
    resp = T.app_single_table.get_item(
        Key={"pk": pk, "sk": "META"},
        ProjectionExpression="poll_votes.#qid",
        ExpressionAttributeNames={"#qid": question_id},
    )
    item = resp.get("Item", {})
    q_votes = (item.get("poll_votes") or {}).get(question_id, {})
    for oid, voters in q_votes.items():
        if isinstance(voters, dict) and voters.get(user_sub):
            return oid
    return None


def _get_user_multi_votes(post_id: str, question_id: str, user_sub: str) -> set:
    """Get all options the user voted for in a multi-choice question."""
    pk = f"POST#{post_id}"
    resp = T.app_single_table.get_item(
        Key={"pk": pk, "sk": "META"},
        ProjectionExpression="poll_votes.#qid",
        ExpressionAttributeNames={"#qid": question_id},
    )
    item = resp.get("Item", {})
    q_votes = (item.get("poll_votes") or {}).get(question_id, {})
    result = set()
    for oid, voters in q_votes.items():
        if isinstance(voters, dict) and voters.get(user_sub):
            result.add(oid)
    return result


def _get_vote_counts(post_id: str, question_id: str) -> Dict[str, int]:
    """Get denormalized vote counts for a question."""
    pk = f"POST#{post_id}"
    resp = T.app_single_table.get_item(
        Key={"pk": pk, "sk": "META"},
        ProjectionExpression="poll_vote_counts.#qid",
        ExpressionAttributeNames={"#qid": question_id},
    )
    item = resp.get("Item", {})
    counts = (item.get("poll_vote_counts") or {}).get(question_id, {})
    return {k: int(v) for k, v in counts.items()}


def _find_question(poll_data: Dict[str, Any], question_id: str) -> Optional[Dict[str, Any]]:
    """Find a question by ID in poll_data."""
    for q in poll_data.get("questions", []):
        if q.get("question_id") == question_id:
            return q
    return None
```

**Vote change:** For single-choice polls with `allow_vote_change=True`, the backend must:
1. Find the user's current vote via a point read on `poll_votes.{question_id}`.
2. Remove the user from the old option and decrement its count.
3. Add the user to the new option and increment its count.

This requires a conditional transaction to prevent race conditions:

```python
# TransactWriteItems to atomically swap vote
ddb.meta.client.transact_write_items(TransactItems=[
    {"Update": {
        "TableName": APP_TABLE,
        "Key": _serialize_key(pk_post(post_id), "META"),
        "UpdateExpression": "REMOVE poll_votes.#qid.#old_oid.#uid SET poll_vote_counts.#qid.#old_oid = poll_vote_counts.#qid.#old_oid - :one",
        ...
    }},
    {"Update": {
        "TableName": APP_TABLE,
        "Key": _serialize_key(pk_post(post_id), "META"),
        "UpdateExpression": "SET poll_votes.#qid.#new_oid.#uid = :t, poll_vote_counts.#qid.#new_oid = if_not_exists(poll_vote_counts.#qid.#new_oid, :zero) + :one",
        ...
    }},
])
```

### 3.3 Post Serialization Extension

The `_post_to_dict` function must be extended to include poll data in the output:

```python
# Addition to _post_to_dict in app/routers/newsfeed.py

def _post_to_dict(post, locked_body=False, liked_by_me=False, unlocked=False, viewer_id=None):
    # ... existing code ...

    # Poll data (ENGAGE-002)
    poll_data_out = None
    poll_vote_counts_out = None
    poll_my_votes = None
    post_type = post.get("post_type", "standard")

    if post_type in ("poll", "survey") and not locked_body:
        raw_poll_data = post.get("poll_data", {})
        poll_data_out = {
            "questions": raw_poll_data.get("questions", []),
            "closes_at": raw_poll_data.get("closes_at"),
            "closed": _is_poll_closed(raw_poll_data),
            "anonymous": raw_poll_data.get("anonymous", True),
            "allow_vote_change": raw_poll_data.get("allow_vote_change", True),
            "total_votes": int(post.get("poll_total_votes", 0)),
        }

        # Denormalized counts per question per option
        poll_vote_counts_out = {}
        raw_counts = post.get("poll_vote_counts", {})
        for qid, opts in raw_counts.items():
            poll_vote_counts_out[qid] = {oid: int(c) for oid, c in opts.items()}

        # Viewer's own votes (for highlighting selected option)
        if viewer_id:
            poll_my_votes = {}
            raw_votes = post.get("poll_votes", {})
            for qid, opts in raw_votes.items():
                for oid, voters in opts.items():
                    if isinstance(voters, dict) and voters.get(viewer_id):
                        poll_my_votes.setdefault(qid, []).append(oid)

    return {
        # ... existing fields ...
        "post_type": post_type,
        "poll_data": poll_data_out,
        "poll_vote_counts": poll_vote_counts_out,
        "poll_my_votes": poll_my_votes,
    }


def _is_poll_closed(poll_data: Dict[str, Any]) -> bool:
    """Check if a poll is closed by flag or by expiry."""
    if poll_data.get("closed"):
        return True
    closes_at = poll_data.get("closes_at")
    if closes_at and int(closes_at) <= now_ts():
        return True
    return False
```

### 3.4 Real-Time Vote Updates

After a vote is recorded, the backend publishes an SSE event to all connected feed viewers:

```python
# In the vote endpoint handler
async def _publish_vote_update(post_author_id: str, post_id: str, question_id: str, updated_counts: Dict, new_total: int):
    """Publish vote update to post author's SSE stream and all followers."""
    event = {
        "type": "poll:vote_update",
        "post_id": post_id,
        "question_id": question_id,
        "vote_counts": updated_counts,
        "total_votes": new_total,
    }
    await sse_hub.publish(post_author_id, event)

    # Also publish to followers who might be viewing the feed
    # The frontend SSE handler will update the React Query cache for the specific post
```

The frontend receives this event and updates the React Query cache for the specific post.

### 3.5 Poll Closing

Polls close in two ways:
1. **Timer expiry**: A background loop (every 30s, same pattern as the scheduled post publisher) scans for polls with `closes_at <= now()` and sets `closed=true`.
2. **Manual close**: Creator calls `POST /posts/{post_id}/close-poll`, which sets `closes_at = now_ts()` and `closed = true`.

Closed polls reject vote attempts with `409 POLL_CLOSED`.

```python
# Background poll closer (runs in the scheduled-post publisher loop)
async def _close_expired_polls():
    """Scan for polls past their closes_at and mark them closed.

    Runs every 30 seconds as part of the scheduled post background loop.
    Uses a GSI on post_type + closes_at to efficiently find expired polls.
    """
    now = now_ts()
    # Query for poll/survey posts with closes_at <= now and not yet closed
    # This is a targeted scan since polls are a small fraction of all posts
    resp = T.app_single_table.scan(
        FilterExpression=(
            Attr("post_type").is_in(["poll", "survey"]) &
            Attr("poll_data.closes_at").lte(now) &
            Attr("poll_data.closed").ne(True)
        ),
        ProjectionExpression="pk, sk, post_id, poll_data, #uid",
        ExpressionAttributeNames={"#uid": "user_id"},
        Limit=100,
    )
    for item in resp.get("Items", []):
        T.app_single_table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET poll_data.closed = :t",
            ExpressionAttributeValues={":t": True},
        )
        # Publish close event
        await sse_hub.publish(item.get("user_id", ""), {
            "type": "poll:closed",
            "post_id": item["post_id"],
        })
```

### 3.6 Pydantic Models

```python
# Additions to app/models.py (or inline in newsfeed.py)

class PollOption(BaseModel):
    text: str = Field(..., min_length=1, max_length=200)

class PollQuestion(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)
    choice_mode: Literal["single", "multi"] = "single"
    options: List[PollOption] = Field(..., min_length=2, max_length=6)
    max_selections: Optional[int] = Field(default=None, ge=1, le=6)

class PollDataIn(BaseModel):
    questions: List[PollQuestion] = Field(..., min_length=1, max_length=10)
    closes_at: Optional[int] = Field(default=None, ge=0)
    anonymous: bool = True
    allow_vote_change: bool = True

    @field_validator("closes_at")
    @classmethod
    def closes_at_must_be_future(cls, v):
        if v is not None and v <= now_ts():
            raise ValueError("closes_at must be in the future")
        return v

class VoteIn(BaseModel):
    question_id: str = Field(..., min_length=1, max_length=64)
    option_id: str = Field(..., min_length=1, max_length=64)

class VoteOut(BaseModel):
    ok: bool = True
    question_id: str
    option_id: str
    vote_counts: Dict[str, int]
    total_votes: int
    my_vote: Optional[str] = None
    my_votes: Optional[List[str]] = None

class PollResultsOut(BaseModel):
    question_id: str
    options: List[Dict[str, Any]]  # {option_id, text, count, percentage, voters?}
    total_votes: int
    closed: bool
    closes_at: Optional[int] = None
    my_vote: Optional[str] = None
    my_votes: Optional[List[str]] = None
```

---

## 4. API Endpoints

### 4.1 Poll Post Creation

```
POST /ui/posts
```

Extended `CreatePostRequest` with poll fields:

Request body:
```json
{
  "body_plain": "What should I stream next?",
  "post_type": "poll",
  "poll_data": {
    "questions": [
      {
        "text": "What should I stream next?",
        "choice_mode": "single",
        "options": [
          {"text": "Horror game"},
          {"text": "Cooking stream"},
          {"text": "Music session"}
        ]
      }
    ],
    "closes_at": 1748486400,
    "anonymous": true,
    "allow_vote_change": true
  }
}
```

Response (200):
```json
{
  "post_id": "p_abc123def456",
  "author_id": "e2e_alice@test.local",
  "post_type": "poll",
  "poll_data": {
    "questions": [
      {
        "question_id": "q_abc123",
        "text": "What should I stream next?",
        "choice_mode": "single",
        "options": [
          {"option_id": "opt_1", "text": "Horror game"},
          {"option_id": "opt_2", "text": "Cooking stream"},
          {"option_id": "opt_3", "text": "Music session"}
        ],
        "max_selections": 1
      }
    ],
    "closes_at": 1748486400,
    "closed": false,
    "anonymous": true,
    "allow_vote_change": true,
    "total_votes": 0
  },
  "poll_vote_counts": {"q_abc123": {"opt_1": 0, "opt_2": 0, "opt_3": 0}},
  "poll_my_votes": null,
  "created_at": "1748400000",
  "visibility": "followers",
  "locked": false
}
```

Server-side processing for poll post creation:
```python
# In create_post endpoint handler
if req.post_type in ("poll", "survey"):
    if not req.poll_data:
        raise HTTPException(400, "poll_data is required for poll/survey posts")

    # Assign IDs to questions and options
    poll_data = req.poll_data.model_dump()
    for q in poll_data["questions"]:
        q["question_id"] = f"q_{uuid4().hex[:8]}"
        for opt in q["options"]:
            opt["option_id"] = f"opt_{uuid4().hex[:6]}"
        if q["choice_mode"] == "single":
            q["max_selections"] = 1
        elif q.get("max_selections") is None:
            q["max_selections"] = len(q["options"])

    post_item["post_type"] = req.post_type
    post_item["poll_data"] = poll_data
    post_item["poll_votes"] = {}
    post_item["poll_vote_counts"] = {
        q["question_id"]: {opt["option_id"]: 0 for opt in q["options"]}
        for q in poll_data["questions"]
    }
    post_item["poll_total_votes"] = 0
```

### 4.2 Voting

```
POST /ui/posts/{post_id}/vote
```

Auth: `Depends(require_ui_session)`

Request body:
```json
{
  "question_id": "q_abc123",
  "option_id": "opt_2"
}
```

Response (200):
```json
{
  "ok": true,
  "question_id": "q_abc123",
  "option_id": "opt_2",
  "vote_counts": {"opt_1": 12, "opt_2": 25, "opt_3": 8},
  "total_votes": 45,
  "my_vote": "opt_2"
}
```

Error responses:
- 409 `POLL_CLOSED`: Poll has closed (timer or manual)
- 409 `VOTE_CHANGE_DISABLED`: `allow_vote_change=false` and user already voted
- 400: Invalid question_id or option_id
- 400: Multi-choice max_selections exceeded
- 404: Post not found

### 4.3 Vote Removal (for vote change)

```
DELETE /ui/posts/{post_id}/vote?question_id=q_abc123
```

Auth: `Depends(require_ui_session)`

Response (200):
```json
{
  "ok": true,
  "question_id": "q_abc123",
  "vote_counts": {"opt_1": 12, "opt_2": 24, "opt_3": 8},
  "total_votes": 44,
  "my_vote": null
}
```

### 4.4 Poll Close

```
POST /ui/posts/{post_id}/close-poll
```

Auth: `Depends(require_ui_session)` -- must be post author or admin.

Response (200):
```json
{
  "ok": true,
  "post_id": "p_abc123def456",
  "closed": true,
  "closes_at": 1748400000
}
```

Error responses:
- 403: Not the post author and not admin
- 409: Poll already closed

### 4.5 Poll Results (Detailed)

```
GET /ui/posts/{post_id}/poll-results?question_id=q_abc123
```

Auth: `Depends(require_ui_session)`

Response (when `anonymous=false`):
```json
{
  "question_id": "q_abc123",
  "options": [
    {"option_id": "opt_1", "text": "Horror game", "count": 12, "percentage": 26.7, "voters": ["user_1", "user_2"]},
    {"option_id": "opt_2", "text": "Cooking stream", "count": 25, "percentage": 55.6, "voters": ["user_3", "user_4"]},
    {"option_id": "opt_3", "text": "Music session", "count": 8, "percentage": 17.8, "voters": []}
  ],
  "total_votes": 45,
  "closed": false,
  "closes_at": 1748486400,
  "my_vote": "opt_2"
}
```

Response (when `anonymous=true`): Same shape but `voters` arrays are always empty.

---

## 5. Frontend Components

### 5.1 New Components

| Component | Path | Description |
|-----------|------|-------------|
| `PollComposer` | `pages/feed/PollComposer.tsx` | UI for creating polls: question input, option list (add/remove), choice mode toggle, close timer picker |
| `SurveyComposer` | `pages/feed/SurveyComposer.tsx` | Multi-question survey builder (wraps multiple `PollComposer` instances) |
| `PollCard` | `pages/feed/PollCard.tsx` | Renders a poll inside a `PostCard`: question text, option bars, vote button, results |
| `PollOptionBar` | `pages/feed/PollOptionBar.tsx` | Single option with animated progress bar, count, percentage, and "selected" state |
| `PollResultsDialog` | `pages/feed/PollResultsDialog.tsx` | Full results view with voter list (non-anonymous polls) |

### 5.2 TypeScript Types

```typescript
// frontend/src/api/types.ts additions

export interface PollOption {
  option_id: string;
  text: string;
}

export interface PollQuestion {
  question_id: string;
  text: string;
  choice_mode: "single" | "multi";
  options: PollOption[];
  max_selections?: number;
}

export interface PollData {
  questions: PollQuestion[];
  closes_at?: number;
  closed: boolean;
  anonymous: boolean;
  allow_vote_change: boolean;
  total_votes: number;
}

export interface PollVoteCounts {
  [questionId: string]: { [optionId: string]: number };
}

export interface PollMyVotes {
  [questionId: string]: string[];
}

export interface PollPost extends FeedPost {
  post_type: "poll" | "survey";
  poll_data: PollData;
  poll_vote_counts: PollVoteCounts;
  poll_my_votes?: PollMyVotes;
}

export interface VoteResponse {
  ok: boolean;
  question_id: string;
  option_id: string;
  vote_counts: { [optionId: string]: number };
  total_votes: number;
  my_vote?: string;
  my_votes?: string[];
}

export interface PollResultsResponse {
  question_id: string;
  options: Array<{
    option_id: string;
    text: string;
    count: number;
    percentage: number;
    voters: string[];
  }>;
  total_votes: number;
  closed: boolean;
  closes_at?: number;
  my_vote?: string;
}
```

### 5.3 API Endpoints

```typescript
// frontend/src/api/endpoints/polls.ts

import { api } from "@/api/client";  // NOTE: codebase uses named `api` export, not default `client` import
import type { VoteResponse, PollResultsResponse } from "@/api/types";  // NOTE: actual file uses `@/api/types` not `../types`

export const castVote = async (postId: string, questionId: string, optionId: string) =>
  api.post<VoteResponse>(`/ui/posts/${postId}/vote`, { question_id: questionId, option_id: optionId })
    .then(r => r.data);

export const removeVote = async (postId: string, questionId: string) =>
  api.delete<VoteResponse>(`/ui/posts/${postId}/vote`, { params: { question_id: questionId } })
    .then(r => r.data);

export const closePoll = async (postId: string) =>
  api.post(`/ui/posts/${postId}/close-poll`).then(r => r.data);

export const getPollResults = async (postId: string, questionId: string) =>
  api.get<PollResultsResponse>(`/ui/posts/${postId}/poll-results`, { params: { question_id: questionId } })
    .then(r => r.data);
```

### 5.4 Integration with CreatePost

The `CreatePost.tsx` component will gain a poll toggle button. When active, `PollComposer` replaces the rich text editor:

```tsx
<div className="flex gap-2">
    <Button variant="ghost" size="sm" onClick={() => setMode("text")}>
        <AlignLeft className="h-4 w-4" /> Text
    </Button>
    <Button variant="ghost" size="sm" onClick={() => setMode("poll")}>
        <BarChart3 className="h-4 w-4" /> Poll
    </Button>
    <Button variant="ghost" size="sm" onClick={() => setMode("survey")}>
        <ClipboardList className="h-4 w-4" /> Survey
    </Button>
</div>
```

### 5.5 PollComposer Component

```tsx
// frontend/src/pages/feed/PollComposer.tsx
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, X, Clock } from "lucide-react";

interface PollComposerProps {
  onPollDataChange: (data: PollDataInput) => void;
}

interface PollDataInput {
  questions: Array<{
    text: string;
    choice_mode: "single" | "multi";
    options: Array<{ text: string }>;
    max_selections?: number;
  }>;
  closes_at?: number;
  anonymous: boolean;
  allow_vote_change: boolean;
}

export function PollComposer({ onPollDataChange }: PollComposerProps) {
  const [question, setQuestion] = useState("");
  const [options, setOptions] = useState(["", ""]);
  const [choiceMode, setChoiceMode] = useState<"single" | "multi">("single");
  const [anonymous, setAnonymous] = useState(true);
  const [allowChange, setAllowChange] = useState(true);
  const [closesInHours, setClosesInHours] = useState<number | null>(null);

  const addOption = () => {
    if (options.length < 6) setOptions([...options, ""]);
  };

  const removeOption = (index: number) => {
    if (options.length > 2) setOptions(options.filter((_, i) => i !== index));
  };

  const updateOption = (index: number, text: string) => {
    const updated = [...options];
    updated[index] = text;
    setOptions(updated);
    emitChange(question, updated);
  };

  const emitChange = (q: string, opts: string[]) => {
    onPollDataChange({
      questions: [{
        text: q,
        choice_mode: choiceMode,
        options: opts.filter(o => o.trim()).map(o => ({ text: o.trim() })),
        max_selections: choiceMode === "multi" ? undefined : 1,
      }],
      closes_at: closesInHours ? Math.floor(Date.now() / 1000) + closesInHours * 3600 : undefined,
      anonymous,
      allow_vote_change: allowChange,
    });
  };

  return (
    <div className="space-y-4 p-4 border rounded-lg">
      <div>
        <Label>Question</Label>
        <Input
          placeholder="Ask your audience something..."
          value={question}
          onChange={(e) => { setQuestion(e.target.value); emitChange(e.target.value, options); }}
          maxLength={500}
        />
      </div>

      <div className="space-y-2">
        <Label>Options</Label>
        {options.map((opt, i) => (
          <div key={i} className="flex gap-2">
            <Input
              placeholder={`Option ${i + 1}`}
              value={opt}
              onChange={(e) => updateOption(i, e.target.value)}
              maxLength={200}
            />
            {options.length > 2 && (
              <Button variant="ghost" size="icon" onClick={() => removeOption(i)}>
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        ))}
        {options.length < 6 && (
          <Button variant="outline" size="sm" onClick={addOption}>
            <Plus className="h-4 w-4 mr-1" /> Add Option
          </Button>
        )}
      </div>

      <div className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <Label>Mode:</Label>
          <Select value={choiceMode} onValueChange={(v) => setChoiceMode(v as "single" | "multi")}>
            <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="single">Single choice</SelectItem>
              <SelectItem value="multi">Multi choice</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={anonymous} onCheckedChange={setAnonymous} />
          <Label>Anonymous voting</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={allowChange} onCheckedChange={setAllowChange} />
          <Label>Allow vote change</Label>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Clock className="h-4 w-4 text-muted-foreground" />
        <Select value={String(closesInHours ?? "")} onValueChange={(v) => setClosesInHours(v ? Number(v) : null)}>
          <SelectTrigger className="w-40"><SelectValue placeholder="No time limit" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="">No time limit</SelectItem>
            <SelectItem value="1">1 hour</SelectItem>
            <SelectItem value="6">6 hours</SelectItem>
            <SelectItem value="24">24 hours</SelectItem>
            <SelectItem value="72">3 days</SelectItem>
            <SelectItem value="168">1 week</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
```

### 5.6 PollCard Component

```tsx
// frontend/src/pages/feed/PollCard.tsx
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { castVote } from "@/api/endpoints/polls";
import { PollOptionBar } from "./PollOptionBar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Lock, Clock, BarChart3 } from "lucide-react";
import type { PollData, PollVoteCounts, PollMyVotes, PollQuestion } from "@/api/types";

interface PollCardProps {
  postId: string;
  pollData: PollData;
  voteCounts: PollVoteCounts;
  myVotes?: PollMyVotes;
  isAuthor: boolean;
}

export function PollCard({ postId, pollData, voteCounts, myVotes, isAuthor }: PollCardProps) {
  const queryClient = useQueryClient();

  return (
    <div className="space-y-4">
      {pollData.questions.map((question) => (
        <PollQuestionView
          key={question.question_id}
          postId={postId}
          question={question}
          counts={voteCounts[question.question_id] ?? {}}
          myVote={myVotes?.[question.question_id]?.[0]}
          closed={pollData.closed}
          totalVotes={pollData.total_votes}
          isAuthor={isAuthor}
        />
      ))}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <BarChart3 className="h-3 w-3" />
        <span>{pollData.total_votes} total votes</span>
        {pollData.closed && <Badge variant="secondary">Closed</Badge>}
        {pollData.closes_at && !pollData.closed && (
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            Closes {new Date(pollData.closes_at * 1000).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}

function PollQuestionView({
  postId, question, counts, myVote, closed, totalVotes, isAuthor,
}: {
  postId: string;
  question: PollQuestion;
  counts: Record<string, number>;
  myVote?: string;
  closed: boolean;
  totalVotes: number;
  isAuthor: boolean;
}) {
  const queryClient = useQueryClient();
  const voteMut = useMutation({
    mutationFn: (optionId: string) => castVote(postId, question.question_id, optionId),
    onSuccess: (data) => {
      queryClient.setQueryData(["feed"], (old: any) => {
        // Update the specific post in the feed cache
        // ... deep merge logic ...
      });
    },
  });

  const questionTotal = Object.values(counts).reduce((sum, c) => sum + c, 0);

  return (
    <div className="space-y-2">
      <p className="font-medium text-sm">{question.text}</p>
      {question.options.map((opt) => {
        const count = counts[opt.option_id] ?? 0;
        const pct = questionTotal > 0 ? (count / questionTotal) * 100 : 0;
        const selected = myVote === opt.option_id;

        return (
          <PollOptionBar
            key={opt.option_id}
            text={opt.text}
            count={count}
            percentage={pct}
            selected={selected}
            disabled={closed}
            onClick={() => !closed && voteMut.mutate(opt.option_id)}
          />
        );
      })}
    </div>
  );
}
```

### 5.7 PollOptionBar Component

Each option bar animates width transitions when vote counts update:

```tsx
// frontend/src/pages/feed/PollOptionBar.tsx
import { cn } from "@/lib/utils";
import { Check } from "lucide-react";

interface PollOptionBarProps {
  text: string;
  count: number;
  percentage: number;
  selected: boolean;
  disabled: boolean;
  onClick: () => void;
}

export function PollOptionBar({ text, count, percentage, selected, disabled, onClick }: PollOptionBarProps) {
  return (
    <button
      className={cn(
        "relative w-full h-10 rounded-md overflow-hidden text-left",
        "border transition-all",
        selected ? "border-primary bg-primary/5" : "border-border bg-muted/30",
        disabled ? "cursor-default opacity-75" : "cursor-pointer hover:border-primary/50"
      )}
      onClick={onClick}
      disabled={disabled}
      type="button"
    >
      <div
        className={cn(
          "absolute inset-y-0 left-0 transition-[width] duration-500 ease-out",
          selected ? "bg-primary/20" : "bg-muted"
        )}
        style={{ width: `${percentage}%` }}
      />
      <div className="relative flex items-center justify-between px-3 h-full">
        <span className="text-sm font-medium flex items-center gap-1.5">
          {selected && <Check className="h-3.5 w-3.5 text-primary" />}
          {text}
        </span>
        <span className="text-sm text-muted-foreground tabular-nums">
          {count} ({percentage.toFixed(1)}%)
        </span>
      </div>
    </button>
  );
}
```

### 5.8 Real-Time Updates via SSE

The existing newsfeed SSE hook will handle `poll:vote_update` events:

```tsx
// In useNewsfeedStream.ts
case "poll:vote_update":
    queryClient.setQueryData(["feed"], (old: any) => {
        if (!old?.pages) return old;
        return {
            ...old,
            pages: old.pages.map((page: any) => ({
                ...page,
                posts: page.posts.map((post: any) =>
                    post.post_id === event.post_id
                        ? {
                            ...post,
                            poll_vote_counts: {
                                ...post.poll_vote_counts,
                                [event.question_id]: event.vote_counts,
                            },
                            poll_data: {
                                ...post.poll_data,
                                total_votes: event.total_votes,
                            },
                        }
                        : post
                ),
            })),
        };
    });
    break;

case "poll:closed":
    queryClient.setQueryData(["feed"], (old: any) => {
        if (!old?.pages) return old;
        return {
            ...old,
            pages: old.pages.map((page: any) => ({
                ...page,
                posts: page.posts.map((post: any) =>
                    post.post_id === event.post_id
                        ? {
                            ...post,
                            poll_data: { ...post.poll_data, closed: true },
                        }
                        : post
                ),
            })),
        };
    });
    break;
```

---

## 6. E2E Test Plan

### Section 85: Poll API

| # | Test | Assertion |
|---|------|-----------|
| 85.1 | Create a single-choice poll with 3 options | 200, post_type="poll", poll_data.questions[0].options.length=3, all option_ids assigned |
| 85.2 | Vote for an option | 200, vote_counts updated, my_vote set |
| 85.3 | Vote for a different option (change vote) | 200, old option decremented, new option incremented, my_vote updated |
| 85.4 | Vote after poll closed returns 409 | Set closes_at in past; vote attempt returns POLL_CLOSED |
| 85.5 | Creator manually closes poll | POST close-poll returns 200; subsequent vote returns 409 |
| 85.6 | Create multi-choice poll | Vote for 2 options on same question; both recorded |
| 85.7 | Delete vote | DELETE removes user's vote; count decremented |
| 85.8 | Poll with closes_at in past rejected | 400, "closes_at must be in the future" |
| 85.9 | Poll with fewer than 2 options rejected | 400 validation error |
| 85.10 | Poll with more than 6 options rejected | 400 validation error |
| 85.11 | Vote change when allow_vote_change=false returns 409 | 409, VOTE_CHANGE_DISABLED |
| 85.12 | Multi-choice max_selections enforced | 400 after exceeding max |
| 85.13 | Duplicate vote is idempotent (same option) | 200, counts unchanged |
| 85.14 | Poll results show correct percentages | Math: count/total*100 within 0.1 tolerance |
| 85.15 | Anonymous poll results omit voter list | voters arrays are empty |
| 85.16 | Non-anonymous poll results include voter IDs | voters arrays populated |

### Section 86: Survey API

| # | Test | Assertion |
|---|------|-----------|
| 86.1 | Create survey with 3 questions | 200, post_type="survey", 3 questions in poll_data |
| 86.2 | Vote on each question independently | Each question's vote_counts updated separately |
| 86.3 | Closing survey closes all questions | All questions become unvoteable |
| 86.4 | Survey with 10 questions (max) | 200, all 10 questions stored |
| 86.5 | Survey with 11 questions rejected | 400, validation error |
| 86.6 | Mixed single/multi choice modes per question | Each question respects its own mode |

### Section 87: Poll Feed Rendering

| # | Test | Assertion |
|---|------|-----------|
| 87.1 | Poll appears in feed with option bars | PostCard renders PollCard with correct options |
| 87.2 | Clicking an option records vote and updates bar | Bar width increases; percentage updates |
| 87.3 | Closed poll shows "Closed" badge and disables voting | Button disabled; "Closed" text visible |
| 87.4 | Poll results show correct percentages | Math: count / total * 100 matches displayed |
| 87.5 | Selected option shows check icon | Check icon visible next to user's choice |
| 87.6 | Poll time remaining shown for time-bounded polls | "Closes [datetime]" text visible |
| 87.7 | Locked poll shows "[Locked content]" | Poll options hidden when locked |
| 87.8 | Survey renders multiple questions vertically | Each question section visible with its own bars |

### Section 88: Poll SSE Real-Time

| # | Test | Assertion |
|---|------|-----------|
| 88.1 | Bob votes; Alice sees count update via SSE | Alice's page shows updated vote count without reload |
| 88.2 | Multiple rapid votes produce correct final tally | Atomic operations prevent count drift |
| 88.3 | Poll close event disables voting on all viewers | After close event, option bars become disabled |
| 88.4 | Vote change updates bar widths in real-time | Old option shrinks, new option grows |

---

## 7. Edge Cases

1. **Concurrent vote + close**: A user submits a vote at the exact moment the poll closes. The backend must check `closed` or `closes_at <= now()` inside the update transaction. If the poll is closed, the vote is rejected with 409.

2. **DynamoDB item size limit**: A poll with 6 options and 100,000 voters in `poll_votes` would exceed the 400KB DynamoDB item limit. Mitigation: for polls with >1000 voters per option, switch to a separate `poll_votes_overflow` table keyed by `{post_id}#{question_id}#{option_id}` with individual voter rows. The denormalized `poll_vote_counts` map (integer counts only) stays on the post item. The transition is automatic -- the `_add_vote` function catches the DDB size exception and falls back to overflow.

3. **Multi-choice maximum selections**: Multi-choice polls should allow configurable `max_selections` (e.g., "pick up to 2"). Enforce server-side by counting user's existing votes for the question before adding a new one.

4. **Empty options**: Reject polls with fewer than 2 options or options with empty text. The Pydantic model validates `min_length=2` on options list and `min_length=1` on option text.

5. **Anonymous vote + vote change**: When anonymous=true and allow_vote_change=true, the voter list is still stored server-side (needed to enforce single-vote and enable change), but never exposed in API responses. The `PollResultsOut` response omits `voters` when anonymous=true.

6. **Survey with 0 responses**: Render "No votes yet" with 0% bars, not NaN percentages. The frontend guards against division by zero: `questionTotal > 0 ? (count / questionTotal) * 100 : 0`.

7. **Vote count desync**: If an inline vote write fails but the count update succeeds (or vice versa), the count may be off by 1. Mitigation: the count is denormalized and can be recomputed from the voter map via a repair script. In practice, the single-item update is atomic per expression, so this only happens in the overflow transition case.

8. **Locked poll unlock then vote**: A user unlocks a poll post, sees the options, then votes. The vote endpoint must verify the user has unlocked the post if it is locked. The same `_check_post_unlocked(post_id, user_sub)` check used for viewing locked content applies to voting.

9. **Scheduled poll post**: A poll with `publish_at` set will not appear in the feed until the scheduled time. Votes before publication are impossible since the post is not visible.

10. **Poll in repost**: When a poll post is reposted, the repost shows the poll UI but votes still go to the original post. The frontend passes the original `post_id` for voting, not the repost post_id.

---

## 8. Security Considerations

1. **Vote manipulation**: Votes are tied to `user_sub` from the authenticated session. No anonymous/unauthenticated voting is possible. The `require_ui_session` dependency (see `app/services/sessions.py:283`) ensures the user is authenticated. <!-- NOTE: require_ui_session is defined in app/services/sessions.py, NOT app/auth/deps.py -->

2. **Poll creation rate limiting**: Poll posts go through the same `_enforce_newsfeed_post_quota_precheck` (line 606 of `newsfeed.py`) as regular posts. No additional rate limiting needed for poll creation. <!-- VERIFIED: app/routers/newsfeed.py:606 -->

3. **Voter privacy**: When `anonymous=true`, the `voters` array is omitted from all API responses. The `poll_votes` map is never exposed to non-admin users in anonymous mode. The server-side voter map is only accessible via admin endpoints for moderation purposes.

4. **Option injection**: Option text is sanitized using the same `escape()` function used for post body text. The Pydantic model enforces `max_length=200` on option text.

5. **CSRF**: All vote endpoints require `x-csrf-token` header (enforced by `require_ui_session` dependency). This prevents cross-site vote manipulation.

6. **Close authority**: Only the post author or an admin can close a poll. Checked via `post.author_id == ctx["user_sub"]` or `ctx["role"] >= ADMIN`. Non-owners receive 403.

7. **Vote timing attacks**: The server validates `closes_at` on every vote, not just on the first vote after expiry. This prevents attackers from racing the close time by submitting votes in a tight loop.

8. **Overflow table access control**: The overflow table is not directly accessible via any API endpoint. It is only written to and read from by the backend vote service.

9. **Question/option ID enumeration**: Question IDs and option IDs are generated server-side as UUIDs. Clients cannot predict or enumerate them, preventing vote submission to non-existent options.

---

## 9. Rollout Plan

1. **Phase 1** (days 1-4): Backend -- Pydantic models, poll creation in `create_post`, vote casting/removal/change logic, poll closing (manual + background), poll results endpoint. Overflow table definition in `local-ddb-init.py`.

2. **Phase 2** (days 5-7): Backend SSE -- Vote update events published through `sse_hub`, `_post_to_dict` extension with poll data, poll_vote_counts, poll_my_votes.

3. **Phase 3** (days 8-10): Frontend -- PollComposer, SurveyComposer, PollCard, PollOptionBar, PollResultsDialog. Integration with CreatePost and PostCard. SSE handler in useNewsfeedStream.

4. **Phase 4** (days 11-14): E2E tests (sections 85-88), edge case testing, performance testing with high-volume vote simulation, QA.

Feature flag: `POLLS_ENABLED` (default `false`). The poll/survey post type is rejected in `create_post` when disabled. The PollComposer buttons are hidden in the frontend when the flag is off.

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| Newsfeed router | `app/routers/newsfeed.py` | 5954 lines total | VERIFIED |
| `CreatePostRequest` | `app/routers/newsfeed.py` | 1276 | VERIFIED (ticket said 1257) |
| `_write_feed_ref_for_published_post` | `app/routers/newsfeed.py` | 1818 | VERIFIED (ticket said 1791) |
| `_post_to_dict` | `app/routers/newsfeed.py` | 1900 | VERIFIED (ticket said 1864) |
| `post_type` in `_post_to_dict` | `app/routers/newsfeed.py` | 2006 | VERIFIED (ticket said 1970) |
| `_reaction_summaries` | `app/routers/newsfeed.py` | 1771 | VERIFIED (ticket said 1744) |
| `_enforce_newsfeed_post_quota_precheck` | `app/routers/newsfeed.py` | 606 | VERIFIED |
| `SSEHub` class | `app/routers/newsfeed.py` | 2051 | VERIFIED |
| `sse_hub` instance | `app/routers/newsfeed.py` | 2089 | VERIFIED |
| SSE endpoint | `app/routers/newsfeed.py` | 2160 | VERIFIED (ticket said 2122) |
| `send_chat_message` | `app/services/broadcast_chat_store.py` | 136 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py) |
| Poll vote endpoint | `app/routers/newsfeed.py` | 5843 | VERIFIED (`@router.post("/posts/{post_id}/vote")`) |
| `newsfeed_polls` service | `app/services/newsfeed_polls.py` | exists (16300 bytes) | VERIFIED |
| Frontend polls API | `frontend/src/api/endpoints/polls.ts` | 1 (`import { api } from "@/api/client"`) | VERIFIED |
| PollComposer | `frontend/src/pages/feed/PollComposer.tsx` | exists (5527 bytes) | VERIFIED |
| PollDisplay | `frontend/src/pages/feed/PollDisplay.tsx` | N/A | NOT YET CREATED |
| PollResultsView | `frontend/src/pages/feed/PollResultsView.tsx` | N/A | NOT YET CREATED |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_newsfeed_polls.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_engage_002_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_engage_002_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_engage_002_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_engage_002_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_engage_002_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_engage_002_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_engage_002_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_engage_002_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/polls.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 14

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `POLLS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `POLLS_ENABLED` must be enabled for tests to run
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
- [ ] Feature flag `POLLS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
