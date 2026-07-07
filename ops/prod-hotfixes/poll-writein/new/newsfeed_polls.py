"""
ENGAGE-002: Newsfeed Polls & Surveys service layer.

Polls are stored inline on the post item in the app_single_table.
Vote tracking uses a nested map: poll_votes.{question_id}.{option_id}.{user_sub} = True
Denormalized counts: poll_vote_counts.{question_id}.{option_id} = N

Write-in options (sender-enabled, per question ``allow_write_in``): a voter may
submit free text; it is normalised (trim + collapse whitespace + casefold) and
either consolidated into an existing option or appended as a new option
(``is_write_in=True`` + ``author``) and then voted for.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _get_table():
    import os
    from app.core.aws import ddb
    _table_name = os.environ.get("APP_TABLE", "app_single_table")
    return ddb.Table(_table_name)


def _clean_write_in_text(text: str) -> str:
    """Display form of a write-in: trim + collapse internal whitespace, keep case."""
    return " ".join((text or "").split()).strip()


def _normalize_write_in(text: str) -> str:
    """Match key for a write-in: collapse whitespace + casefold (case-insensitive)."""
    return " ".join((text or "").split()).strip().casefold()


def create_poll_data(
    questions: List[Dict[str, Any]],
    closes_at: Optional[int],
    anonymous: bool = True,
    allow_vote_change: bool = True,
    allow_write_in: bool = False,
) -> Dict[str, Any]:
    """Validate and build poll_data dict with generated IDs for questions and options."""
    max_options = getattr(S, "newsfeed_poll_max_options", 10)

    processed_questions = []
    for q in questions:
        text = q.get("text", "").strip()
        if not text:
            raise HTTPException(400, "Question text is required")
        choice_mode = q.get("choice_mode", "single")
        options = q.get("options", [])
        if len(options) < 2:
            raise HTTPException(400, "Each question must have at least 2 options")
        if len(options) > max_options:
            raise HTTPException(400, f"Maximum {max_options} options per question")

        processed_options = []
        for opt in options:
            opt_text = opt.get("text", "").strip() if isinstance(opt, dict) else str(opt).strip()
            if not opt_text:
                raise HTTPException(400, "Option text is required")
            processed_options.append({
                "option_id": f"opt_{uuid4().hex[:6]}",
                "text": opt_text,
            })

        max_sel = q.get("max_selections")
        if choice_mode == "single":
            max_sel = 1
        elif max_sel is None:
            max_sel = len(processed_options)

        # Sender-controlled write-in: enable when EITHER the per-question flag
        # or the poll-level default is set. (Surfaces like newsfeed send an
        # explicit per-question default of False via model_dump, so the
        # poll-level flag must act as a floor rather than a fallback.)
        q_write_in = bool(q.get("allow_write_in", False)) or bool(allow_write_in)

        processed_questions.append({
            "question_id": f"q_{uuid4().hex[:8]}",
            "text": text,
            "choice_mode": choice_mode,
            "options": processed_options,
            "max_selections": max_sel,
            "allow_write_in": q_write_in,
        })

    poll_data: Dict[str, Any] = {
        "questions": processed_questions,
        "closed": False,
        "anonymous": anonymous,
        "allow_vote_change": allow_vote_change,
        "allow_write_in": bool(allow_write_in) or any(
            q.get("allow_write_in") for q in processed_questions
        ),
    }
    if closes_at is not None:
        if closes_at <= now_ts():
            raise HTTPException(400, "closes_at must be in the future")
        poll_data["closes_at"] = closes_at

    return poll_data


def build_initial_vote_counts(poll_data: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    """Build the initial poll_vote_counts map with zero counts."""
    counts: Dict[str, Dict[str, int]] = {}
    for q in poll_data.get("questions", []):
        qid = q["question_id"]
        counts[qid] = {}
        for opt in q.get("options", []):
            counts[qid][opt["option_id"]] = 0
    return counts


def is_poll_closed(poll_data: Dict[str, Any]) -> bool:
    """Check if a poll is closed by flag or by expiry."""
    if poll_data.get("closed"):
        return True
    closes_at = poll_data.get("closes_at")
    if closes_at is not None and int(closes_at) <= now_ts():
        return True
    return False


def _find_question(poll_data: Dict[str, Any], question_id: str) -> Optional[Dict[str, Any]]:
    for q in poll_data.get("questions", []):
        if q.get("question_id") == question_id:
            return q
    return None


def _find_question_index(poll_data: Dict[str, Any], question_id: str) -> int:
    for i, q in enumerate(poll_data.get("questions", [])):
        if q.get("question_id") == question_id:
            return i
    return -1


def get_user_vote_for_question(post: Dict[str, Any], question_id: str, user_sub: str) -> Optional[str]:
    """Get the user's current single-choice vote option_id for a question, or None."""
    q_votes = (post.get("poll_votes") or {}).get(question_id, {})
    for oid, voters in q_votes.items():
        if isinstance(voters, dict) and voters.get(user_sub):
            return oid
    return None


def get_user_multi_votes(post: Dict[str, Any], question_id: str, user_sub: str) -> Set[str]:
    """Get all option_ids the user voted for in a multi-choice question."""
    q_votes = (post.get("poll_votes") or {}).get(question_id, {})
    result: Set[str] = set()
    for oid, voters in q_votes.items():
        if isinstance(voters, dict) and voters.get(user_sub):
            result.add(oid)
    return result


def cast_vote(
    post: Dict[str, Any],
    post_id: str,
    question_id: str,
    option_id: str,
    user_sub: str,
) -> Dict[str, Any]:
    """Record a vote. Returns updated vote_counts for the question."""
    poll_data = post.get("poll_data", {})

    if is_poll_closed(poll_data):
        raise HTTPException(409, {"code": "POLL_CLOSED", "message": "This poll is closed."})

    question = _find_question(poll_data, question_id)
    if not question:
        raise HTTPException(404, "Question not found")

    valid_options = {o["option_id"] for o in question["options"]}
    if option_id not in valid_options:
        raise HTTPException(400, "Invalid option_id")

    choice_mode = question.get("choice_mode", "single")
    tbl = _get_table()
    pk = f"POST#{post_id}"

    if choice_mode == "single":
        current_vote = get_user_vote_for_question(post, question_id, user_sub)

        if current_vote == option_id:
            # Idempotent - already voted for this option
            counts = (post.get("poll_vote_counts") or {}).get(question_id, {})
            return {k: int(v) for k, v in counts.items()}

        if current_vote:
            if not poll_data.get("allow_vote_change", True):
                raise HTTPException(409, {"code": "VOTE_CHANGE_DISABLED", "message": "Vote changes are not allowed."})
            # Remove old vote
            try:
                tbl.update_item(
                    Key={"pk": pk, "sk": "META"},
                    UpdateExpression=(
                        "REMOVE poll_votes.#qid.#old_oid.#uid "
                        "SET poll_vote_counts.#qid.#old_oid = poll_vote_counts.#qid.#old_oid - :one"
                    ),
                    ExpressionAttributeNames={
                        "#qid": question_id,
                        "#old_oid": current_vote,
                        "#uid": user_sub,
                    },
                    ExpressionAttributeValues={":one": 1},
                )
            except Exception:
                logger.warning("Failed to remove old vote for %s on %s", user_sub, post_id)

        # Add new vote
        tbl.update_item(
            Key={"pk": pk, "sk": "META"},
            UpdateExpression=(
                "SET poll_votes.#qid.#oid.#uid = :t, "
                "poll_vote_counts.#qid.#oid = if_not_exists(poll_vote_counts.#qid.#oid, :zero) + :one"
            ),
            ExpressionAttributeNames={
                "#qid": question_id,
                "#oid": option_id,
                "#uid": user_sub,
            },
            ExpressionAttributeValues={":t": True, ":one": 1, ":zero": 0},
        )

        # Update total votes (only increment if it was a new vote, not a change)
        if not current_vote:
            tbl.update_item(
                Key={"pk": pk, "sk": "META"},
                UpdateExpression="SET poll_total_votes = if_not_exists(poll_total_votes, :zero) + :one",
                ExpressionAttributeValues={":one": 1, ":zero": 0},
            )

    elif choice_mode == "multi":
        max_sel = question.get("max_selections", len(valid_options))
        user_votes = get_user_multi_votes(post, question_id, user_sub)

        if option_id in user_votes:
            # Toggle off
            tbl.update_item(
                Key={"pk": pk, "sk": "META"},
                UpdateExpression=(
                    "REMOVE poll_votes.#qid.#oid.#uid "
                    "SET poll_vote_counts.#qid.#oid = poll_vote_counts.#qid.#oid - :one, "
                    "poll_total_votes = if_not_exists(poll_total_votes, :zero) - :one"
                ),
                ExpressionAttributeNames={
                    "#qid": question_id,
                    "#oid": option_id,
                    "#uid": user_sub,
                },
                ExpressionAttributeValues={":one": 1, ":zero": 0},
            )
        else:
            if len(user_votes) >= max_sel:
                raise HTTPException(400, f"Maximum {max_sel} selections allowed")
            tbl.update_item(
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

    # Re-fetch updated counts
    resp = tbl.get_item(
        Key={"pk": pk, "sk": "META"},
        ProjectionExpression="poll_vote_counts.#qid, poll_total_votes",
        ExpressionAttributeNames={"#qid": question_id},
    )
    item = resp.get("Item", {})
    counts = (item.get("poll_vote_counts") or {}).get(question_id, {})
    return {k: int(v) for k, v in counts.items()}


def add_write_in(
    post: Dict[str, Any],
    post_id: str,
    question_id: str,
    text: str,
    user_sub: str,
) -> Dict[str, Any]:
    """Submit a write-in answer.

    Rejected with 403 when the question does not allow write-ins. The text is
    normalised (trim + collapse whitespace + casefold); if it matches an
    existing option the vote is consolidated onto that option, otherwise a new
    option (``is_write_in=True``, ``author`` = voter) is appended and voted for.
    Honours single/multi + closed rules via ``cast_vote``.
    """
    poll_data = post.get("poll_data", {})

    if is_poll_closed(poll_data):
        raise HTTPException(409, {"code": "POLL_CLOSED", "message": "This poll is closed."})

    question = _find_question(poll_data, question_id)
    if question is None:
        raise HTTPException(404, "Question not found")

    if not question.get("allow_write_in"):
        raise HTTPException(403, {"code": "WRITE_IN_DISABLED",
                                  "message": "Write-in answers are not allowed for this poll."})

    norm = _normalize_write_in(text)
    if not norm:
        raise HTTPException(400, "Write-in text is required")
    display = _clean_write_in_text(text)
    if len(display) > 200:
        raise HTTPException(400, "Write-in text is too long")

    # Consolidate against existing options (seed + prior write-ins).
    target_oid: Optional[str] = None
    for o in question.get("options", []):
        if _normalize_write_in(o.get("text", "")) == norm:
            target_oid = o["option_id"]
            break

    created = False
    if target_oid is None:
        created = True
        new_oid = f"opt_{uuid4().hex[:6]}"
        new_opt = {
            "option_id": new_oid,
            "text": display,
            "is_write_in": True,
            "author": user_sub,
        }
        qidx = _find_question_index(poll_data, question_id)
        if qidx < 0:
            raise HTTPException(404, "Question not found")
        tbl = _get_table()
        pk = f"POST#{post_id}"
        # Append the option to the nested question list and pre-materialise the
        # count + votes-map parent paths so cast_vote's nested SET succeeds.
        tbl.update_item(
            Key={"pk": pk, "sk": "META"},
            UpdateExpression=(
                f"SET poll_data.questions[{qidx}].options = "
                f"list_append(poll_data.questions[{qidx}].options, :newopt), "
                "poll_vote_counts.#qid.#oid = :zero, "
                "poll_votes.#qid.#oid = :emptymap"
            ),
            ExpressionAttributeNames={"#qid": question_id, "#oid": new_oid},
            ExpressionAttributeValues={":newopt": [new_opt], ":zero": 0, ":emptymap": {}},
        )
        # Mirror into the in-memory post so cast_vote validates + writes correctly.
        question.setdefault("options", []).append(new_opt)
        post.setdefault("poll_vote_counts", {}).setdefault(question_id, {})[new_oid] = 0
        post.setdefault("poll_votes", {}).setdefault(question_id, {})[new_oid] = {}
        target_oid = new_oid

    # Cast the vote. For multi, avoid cast_vote's toggle-off when the voter has
    # already selected this option (a repeat write-in must not un-vote).
    choice_mode = question.get("choice_mode", "single")
    counts: Dict[str, Any]
    if choice_mode == "multi" and target_oid in get_user_multi_votes(post, question_id, user_sub):
        counts = (post.get("poll_vote_counts") or {}).get(question_id, {})
        counts = {k: int(v) for k, v in counts.items()}
    else:
        counts = cast_vote(post, post_id, question_id, target_oid, user_sub)

    return {
        "ok": True,
        "question_id": question_id,
        "option_id": target_oid,
        "created": created,
        "text": display,
        "vote_counts": counts,
    }


def remove_vote(
    post: Dict[str, Any],
    post_id: str,
    question_id: str,
    user_sub: str,
) -> Dict[str, Any]:
    """Remove user's vote for a question. Returns updated vote_counts."""
    poll_data = post.get("poll_data", {})

    if is_poll_closed(poll_data):
        raise HTTPException(409, {"code": "POLL_CLOSED", "message": "This poll is closed."})

    question = _find_question(poll_data, question_id)
    if not question:
        raise HTTPException(404, "Question not found")

    choice_mode = question.get("choice_mode", "single")
    tbl = _get_table()
    pk = f"POST#{post_id}"

    if choice_mode == "single":
        current_vote = get_user_vote_for_question(post, question_id, user_sub)
        if not current_vote:
            # No vote to remove
            counts = (post.get("poll_vote_counts") or {}).get(question_id, {})
            return {k: int(v) for k, v in counts.items()}

        tbl.update_item(
            Key={"pk": pk, "sk": "META"},
            UpdateExpression=(
                "REMOVE poll_votes.#qid.#oid.#uid "
                "SET poll_vote_counts.#qid.#oid = poll_vote_counts.#qid.#oid - :one, "
                "poll_total_votes = if_not_exists(poll_total_votes, :zero) - :one"
            ),
            ExpressionAttributeNames={
                "#qid": question_id,
                "#oid": current_vote,
                "#uid": user_sub,
            },
            ExpressionAttributeValues={":one": 1, ":zero": 0},
        )
    else:
        # Multi: remove all votes for this question
        user_votes = get_user_multi_votes(post, question_id, user_sub)
        for oid in user_votes:
            tbl.update_item(
                Key={"pk": pk, "sk": "META"},
                UpdateExpression=(
                    "REMOVE poll_votes.#qid.#oid.#uid "
                    "SET poll_vote_counts.#qid.#oid = poll_vote_counts.#qid.#oid - :one, "
                    "poll_total_votes = if_not_exists(poll_total_votes, :zero) - :one"
                ),
                ExpressionAttributeNames={
                    "#qid": question_id,
                    "#oid": oid,
                    "#uid": user_sub,
                },
                ExpressionAttributeValues={":one": 1, ":zero": 0},
            )

    # Re-fetch updated counts
    resp = tbl.get_item(
        Key={"pk": pk, "sk": "META"},
        ProjectionExpression="poll_vote_counts.#qid, poll_total_votes",
        ExpressionAttributeNames={"#qid": question_id},
    )
    item = resp.get("Item", {})
    counts = (item.get("poll_vote_counts") or {}).get(question_id, {})
    return {k: int(v) for k, v in counts.items()}


def close_poll(post: Dict[str, Any], post_id: str, user_sub: str) -> Dict[str, Any]:
    """Close a poll early. Only the post author can do this."""
    poll_data = post.get("poll_data", {})

    if is_poll_closed(poll_data):
        raise HTTPException(409, {"code": "POLL_ALREADY_CLOSED", "message": "This poll is already closed."})

    if post.get("user_id") != user_sub:
        raise HTTPException(403, "Only the post author can close a poll")

    tbl = _get_table()
    pk = f"POST#{post_id}"
    now = now_ts()

    tbl.update_item(
        Key={"pk": pk, "sk": "META"},
        UpdateExpression="SET poll_data.closed = :t, poll_data.closes_at = :now",
        ExpressionAttributeValues={":t": True, ":now": now},
    )

    return {"ok": True, "post_id": post_id, "closed": True, "closes_at": now}


def get_poll_results(
    post: Dict[str, Any],
    question_id: str,
    viewer_id: Optional[str] = None,
    top_n: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Get detailed poll results for a question.

    Options are returned SORTED by count descending (write-in options included,
    flagged ``is_write_in`` + ``author``). When ``top_n`` is provided the option
    list is paginated (slice ``[offset:offset+top_n]``) with ``has_more`` +
    ``next_offset`` so a client can show the top N and page the rest.
    """
    poll_data = post.get("poll_data", {})
    question = _find_question(poll_data, question_id)
    if not question:
        raise HTTPException(404, "Question not found")

    vote_counts = (post.get("poll_vote_counts") or {}).get(question_id, {})
    total = sum(int(v) for v in vote_counts.values())
    is_anon = poll_data.get("anonymous", True)

    options_out = []
    for opt in question["options"]:
        oid = opt["option_id"]
        count = int(vote_counts.get(oid, 0))
        pct = round((count / total) * 100, 1) if total > 0 else 0.0
        voters: List[str] = []
        if not is_anon:
            q_votes = (post.get("poll_votes") or {}).get(question_id, {})
            opt_voters = q_votes.get(oid, {})
            if isinstance(opt_voters, dict):
                voters = list(opt_voters.keys())
        options_out.append({
            "option_id": oid,
            "text": opt["text"],
            "count": count,
            "percentage": pct,
            "voters": voters,
            "is_write_in": bool(opt.get("is_write_in", False)),
            "author": opt.get("author"),
        })

    # Sort by count desc; Python's stable sort preserves creation order on ties.
    options_out.sort(key=lambda o: -o["count"])

    total_options = len(options_out)
    if top_n is not None:
        start = max(0, int(offset))
        end = start + max(0, int(top_n))
        page = options_out[start:end]
        has_more = end < total_options
        next_offset = end if has_more else None
    else:
        page = options_out
        has_more = False
        next_offset = None

    # Viewer's own votes
    my_vote = None
    my_votes = None
    if viewer_id:
        choice_mode = question.get("choice_mode", "single")
        if choice_mode == "single":
            my_vote = get_user_vote_for_question(post, question_id, viewer_id)
        else:
            my_votes = list(get_user_multi_votes(post, question_id, viewer_id))

    return {
        "question_id": question_id,
        "options": page,
        "total_options": total_options,
        "has_more": has_more,
        "offset": max(0, int(offset)) if top_n is not None else 0,
        "top_n": top_n,
        "next_offset": next_offset,
        "total_votes": total,
        "allow_write_in": bool(question.get("allow_write_in", False)),
        "closed": is_poll_closed(poll_data),
        "closes_at": poll_data.get("closes_at"),
        "my_vote": my_vote,
        "my_votes": my_votes,
    }


def serialize_poll_for_post(post: Dict[str, Any], viewer_id: Optional[str] = None) -> Dict[str, Any]:
    """Extract poll data for _post_to_dict output."""
    poll_data = post.get("poll_data", {})
    if not poll_data:
        return {"poll_data": None, "poll_vote_counts": None, "poll_my_votes": None}

    questions = poll_data.get("questions", [])
    poll_data_out = {
        "questions": questions,
        "closes_at": poll_data.get("closes_at"),
        "closed": is_poll_closed(poll_data),
        "anonymous": poll_data.get("anonymous", True),
        "allow_vote_change": poll_data.get("allow_vote_change", True),
        "allow_write_in": bool(poll_data.get("allow_write_in")) or any(
            q.get("allow_write_in") for q in questions
        ),
        "total_votes": int(post.get("poll_total_votes", 0)),
    }

    # Denormalized counts per question per option
    poll_vote_counts_out: Dict[str, Dict[str, int]] = {}
    raw_counts = post.get("poll_vote_counts", {})
    for qid, opts in raw_counts.items():
        poll_vote_counts_out[qid] = {oid: int(c) for oid, c in opts.items()}

    # Viewer's own votes
    poll_my_votes = None
    if viewer_id:
        poll_my_votes = {}
        raw_votes = post.get("poll_votes") or {}
        for qid, opts in raw_votes.items():
            for oid, voters in opts.items():
                if isinstance(voters, dict) and voters.get(viewer_id):
                    poll_my_votes.setdefault(qid, []).append(oid)

    return {
        "poll_data": poll_data_out,
        "poll_vote_counts": poll_vote_counts_out,
        "poll_my_votes": poll_my_votes,
    }
