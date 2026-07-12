"""Arbitrary text-option polls — surface-agnostic vote/results/close API.

These endpoints operate on any poll created via ``app.services.arbitrary_polls``
(messaging poll messages, group-feed poll posts, syndicate-feed poll posts and
standalone polls). Newsfeed posts keep their own inline poll endpoints
(``/posts/{id}/vote`` etc.).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services import arbitrary_polls
from app.services.arbitrary_polls import PollCreateIn
from app.services.sessions import require_ui_session

polls_router = APIRouter(prefix="/ui/polls", tags=["polls"])


class PollVoteIn(BaseModel):
    option_id: str = Field(min_length=1, max_length=64)
    question_id: Optional[str] = Field(default=None, max_length=64)


@polls_router.post("", status_code=201)
def create_standalone_poll(body: PollCreateIn, session=Depends(require_ui_session)):
    return arbitrary_polls.create_poll(
        owner=session["user_sub"],
        question=body.question,
        options=list(body.options),
        choice_mode=body.choice_mode,
        max_selections=body.max_selections,
        closes_at=body.closes_at,
        allow_vote_change=body.allow_vote_change,
        anonymous=body.anonymous,
        surface="standalone",
    )


@polls_router.get("/{poll_id}")
def get_poll(poll_id: str, session=Depends(require_ui_session)):
    snap = arbitrary_polls.get_snapshot(poll_id, session["user_sub"])
    if snap is None:
        raise HTTPException(404, "Poll not found")
    return snap


@polls_router.post("/{poll_id}/vote")
def vote_poll(poll_id: str, body: PollVoteIn, session=Depends(require_ui_session)):
    return arbitrary_polls.vote(poll_id, session["user_sub"], body.option_id, body.question_id)


@polls_router.delete("/{poll_id}/vote")
def unvote_poll(
    poll_id: str,
    question_id: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    return arbitrary_polls.unvote(poll_id, session["user_sub"], question_id)


@polls_router.post("/{poll_id}/close")
def close_poll_endpoint(poll_id: str, session=Depends(require_ui_session)):
    return arbitrary_polls.close(poll_id, session["user_sub"])


@polls_router.get("/{poll_id}/results")
def poll_results(
    poll_id: str,
    question_id: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    return arbitrary_polls.results(poll_id, session["user_sub"], question_id)
