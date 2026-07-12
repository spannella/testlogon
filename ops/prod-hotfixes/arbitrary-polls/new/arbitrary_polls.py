"""Arbitrary (custom text-option) polls — shared across messaging, group feed
and syndicate feed.

Reuses the newsfeed poll engine (``app.services.newsfeed_polls``) verbatim by
storing each poll as its own detached item in ``app_single_table`` keyed
``POST#{poll_id} / META`` (the exact shape the newsfeed engine operates on).
Each surface stores only the ``poll_id`` reference on its post/message and
embeds a live snapshot at read time. Voting / results / close are exposed
surface-agnostically via ``app/routers/polls.py`` (``/ui/polls/{poll_id}/...``).

This is DISTINCT from messaging's meeting_poll / find_datetime pickers
(time-based availability), which are left intact.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException
from pydantic import BaseModel, Field

from app.core.time import now_ts
from app.services import newsfeed_polls


class PollCreateIn(BaseModel):
    """Arbitrary text-option poll input, shared by every surface composer."""
    question: str = Field(min_length=1, max_length=300)
    options: List[str] = Field(min_length=2, max_length=10)
    choice_mode: str = Field(default="single", pattern="^(single|multi)$")
    max_selections: Optional[int] = Field(default=None, ge=1, le=10)
    closes_at: Optional[int] = Field(default=None)
    allow_vote_change: bool = True
    anonymous: bool = True


def _table():
    from app.core.aws import ddb
    return ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))


def _load(poll_id: str) -> Optional[Dict[str, Any]]:
    if not poll_id:
        return None
    resp = _table().get_item(Key={"pk": f"POST#{poll_id}", "sk": "META"})
    return resp.get("Item")


def _build_initial_votes(poll_data: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Pre-materialise the nested poll_votes map so the newsfeed engine's
    ``SET poll_votes.#qid.#oid.#uid`` update has an existing parent path."""
    votes: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for q in poll_data.get("questions", []):
        qid = q["question_id"]
        votes[qid] = {opt["option_id"]: {} for opt in q.get("options", [])}
    return votes


def _first_qid(item: Dict[str, Any]) -> str:
    qs = (item.get("poll_data") or {}).get("questions") or []
    if not qs:
        raise HTTPException(404, "Poll has no questions")
    return qs[0]["question_id"]


def _snapshot(item: Dict[str, Any], viewer: Optional[str]) -> Dict[str, Any]:
    ser = newsfeed_polls.serialize_poll_for_post(item, viewer)
    pd = ser.get("poll_data") or {}
    questions = pd.get("questions", [])
    first_q = questions[0] if questions else {}
    return {
        "poll_id": item.get("poll_id") or item.get("post_id"),
        "owner": item.get("user_id"),
        "surface": item.get("poll_surface"),
        "ref_id": item.get("poll_ref_id"),
        "question": first_q.get("text"),
        "choice_mode": first_q.get("choice_mode", "single"),
        "questions": questions,
        "closed": bool(pd.get("closed")),
        "closes_at": pd.get("closes_at"),
        "allow_vote_change": pd.get("allow_vote_change", True),
        "anonymous": pd.get("anonymous", True),
        "total_votes": int(pd.get("total_votes", 0) or 0),
        "vote_counts": ser.get("poll_vote_counts") or {},
        "my_votes": ser.get("poll_my_votes"),
    }


def create_poll(
    *,
    owner: str,
    question: str,
    options: List[Any],
    choice_mode: str = "single",
    max_selections: Optional[int] = None,
    closes_at: Optional[int] = None,
    allow_vote_change: bool = True,
    anonymous: bool = True,
    surface: Optional[str] = None,
    ref_id: Optional[str] = None,
) -> Dict[str, Any]:
    poll_id = "poll_" + uuid4().hex
    q: Dict[str, Any] = {
        "text": question,
        "choice_mode": choice_mode,
        "options": [{"text": (o.get("text") if isinstance(o, dict) else o)} for o in options],
    }
    if max_selections is not None:
        q["max_selections"] = max_selections
    poll_data = newsfeed_polls.create_poll_data(
        [q], closes_at, anonymous=anonymous, allow_vote_change=allow_vote_change
    )
    counts = newsfeed_polls.build_initial_vote_counts(poll_data)
    now = now_ts()
    item: Dict[str, Any] = {
        "pk": f"POST#{poll_id}",
        "sk": "META",
        "post_id": poll_id,
        "poll_id": poll_id,
        "item_type": "arbitrary_poll",
        "user_id": owner,
        "poll_data": poll_data,
        "poll_vote_counts": counts,
        "poll_votes": _build_initial_votes(poll_data),
        "poll_total_votes": 0,
        "created_at": now,
        "updated_at": now,
    }
    if surface:
        item["poll_surface"] = surface
    if ref_id:
        item["poll_ref_id"] = ref_id
    _table().put_item(Item=item)
    return _snapshot(item, owner)


def get_snapshot(poll_id: str, viewer: Optional[str] = None) -> Optional[Dict[str, Any]]:
    item = _load(poll_id)
    if not item or not item.get("poll_data"):
        return None
    return _snapshot(item, viewer)


def vote(poll_id: str, user: str, option_id: str, question_id: Optional[str] = None) -> Dict[str, Any]:
    item = _load(poll_id)
    if not item or not item.get("poll_data"):
        raise HTTPException(404, "Poll not found")
    qid = question_id or _first_qid(item)
    newsfeed_polls.cast_vote(item, poll_id, qid, option_id, user)
    return get_snapshot(poll_id, user)


def unvote(poll_id: str, user: str, question_id: Optional[str] = None) -> Dict[str, Any]:
    item = _load(poll_id)
    if not item or not item.get("poll_data"):
        raise HTTPException(404, "Poll not found")
    qid = question_id or _first_qid(item)
    newsfeed_polls.remove_vote(item, poll_id, qid, user)
    return get_snapshot(poll_id, user)


def close(poll_id: str, user: str) -> Dict[str, Any]:
    item = _load(poll_id)
    if not item or not item.get("poll_data"):
        raise HTTPException(404, "Poll not found")
    newsfeed_polls.close_poll(item, poll_id, user)
    return get_snapshot(poll_id, user)


def results(poll_id: str, viewer: Optional[str] = None, question_id: Optional[str] = None) -> Dict[str, Any]:
    item = _load(poll_id)
    if not item or not item.get("poll_data"):
        raise HTTPException(404, "Poll not found")
    qid = question_id or _first_qid(item)
    return newsfeed_polls.get_poll_results(item, qid, viewer)
