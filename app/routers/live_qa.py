"""Live Q&A Mode router — audience question queue, voting, host moderation (ENGAGE-003).

Distinct implementation mounted under ``/ui/live-qa``; questions live in the
``live_qa_questions`` table and authorization is scoped to the broadcast
session owner (host) / moderators.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app.core.settings import S
from app.models import (
    LiveQaModeToggleIn,
    LiveQaPinIn,
    LiveQaQuestionSubmitIn,
)
from app.services import live_qa
from app.services.sessions import require_ui_session

live_qa_router = APIRouter(prefix="/ui/live-qa", tags=["live-qa"])


def _check_enabled() -> None:
    if not S.live_qa_enabled:
        raise HTTPException(status_code=404, detail="Live Q&A mode is not available")


# ─── Mode toggle (host only) ────────────────────────────────────────────────


@live_qa_router.post("/sessions/{session_id}/mode")
def toggle_qa_mode(
    session_id: str,
    body: LiveQaModeToggleIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Enable or disable Live Q&A on a broadcast session. Session owner only."""
    _check_enabled()
    live_qa.require_host(session_id, ctx["user_sub"])
    enabled = live_qa.set_qa_mode(session_id, body.enabled)
    return {"ok": True, "session_id": session_id, "qa_mode_enabled": enabled}


@live_qa_router.get("/sessions/{session_id}/mode")
def get_qa_mode(
    session_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Read the current Live Q&A mode state for a session."""
    _check_enabled()
    return {
        "ok": True,
        "session_id": session_id,
        "qa_mode_enabled": live_qa.get_qa_mode(session_id),
    }


# ─── Question submission + queue ────────────────────────────────────────────


@live_qa_router.post("/sessions/{session_id}/questions")
def submit_question(
    session_id: str,
    body: LiveQaQuestionSubmitIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Submit a question to the queue (any authenticated, non-muted user)."""
    _check_enabled()
    display_name = ctx.get("display_name") or ctx["user_sub"]
    return live_qa.submit_question(
        session_id=session_id,
        user_id=ctx["user_sub"],
        display_name=display_name,
        text=body.text,
    )


@live_qa_router.get("/sessions/{session_id}/questions")
def list_questions(
    session_id: str,
    status: str = Query(default="pending"),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """List questions filtered by status, sorted by votes (descending).

    Pending questions are restricted to the host/moderators; featured and
    answered questions are visible to any authenticated viewer.
    """
    _check_enabled()
    is_host_mod = live_qa.is_host_or_moderator(session_id, ctx["user_sub"])
    if status in ("pending", "dismissed", "removed") and not is_host_mod:
        raise HTTPException(
            status_code=403,
            detail="Only the host or a moderator can view this queue",
        )
    questions = live_qa.list_questions(session_id, status=status, limit=limit)
    return {"questions": questions, "has_more": len(questions) >= limit}


@live_qa_router.get("/sessions/{session_id}/featured")
def get_featured(
    session_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Return the currently featured question, or 204 if none."""
    _check_enabled()
    featured = live_qa.get_featured_question(session_id)
    if not featured:
        return Response(status_code=204)
    return featured


@live_qa_router.get("/sessions/{session_id}/stats")
def get_stats(
    session_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Q&A engagement statistics (host/moderator only)."""
    _check_enabled()
    live_qa.require_host_or_moderator(session_id, ctx["user_sub"])
    return live_qa.get_stats(session_id)


# ─── Voting (any authenticated user) ────────────────────────────────────────


@live_qa_router.post("/sessions/{session_id}/questions/{question_id}/vote")
def upvote_question(
    session_id: str,
    question_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Upvote a question (idempotent — no double voting)."""
    _check_enabled()
    return live_qa.upvote_question(session_id, question_id, ctx["user_sub"])


@live_qa_router.delete("/sessions/{session_id}/questions/{question_id}/vote")
def remove_vote(
    session_id: str,
    question_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Remove the caller's upvote from a question."""
    _check_enabled()
    return live_qa.remove_vote(session_id, question_id, ctx["user_sub"])


# ─── Host moderation actions (host/moderator only) ──────────────────────────


@live_qa_router.post("/sessions/{session_id}/questions/{question_id}/feature")
def feature_question(
    session_id: str,
    question_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Feature a question as the one being answered (host/moderator)."""
    _check_enabled()
    live_qa.require_host_or_moderator(session_id, ctx["user_sub"])
    return live_qa.feature_question(session_id, question_id, ctx["user_sub"])


@live_qa_router.post("/sessions/{session_id}/questions/{question_id}/answer")
def answer_question(
    session_id: str,
    question_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Mark a question as answered (host/moderator)."""
    _check_enabled()
    live_qa.require_host_or_moderator(session_id, ctx["user_sub"])
    return live_qa.answer_question(session_id, question_id, ctx["user_sub"])


@live_qa_router.post("/sessions/{session_id}/questions/{question_id}/dismiss")
def dismiss_question(
    session_id: str,
    question_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Dismiss a question without answering (host/moderator)."""
    _check_enabled()
    live_qa.require_host_or_moderator(session_id, ctx["user_sub"])
    return live_qa.dismiss_question(session_id, question_id, ctx["user_sub"])


@live_qa_router.post("/sessions/{session_id}/questions/{question_id}/pin")
def pin_question(
    session_id: str,
    question_id: str,
    body: LiveQaPinIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Pin or unpin a question to the top of the queue (host/moderator)."""
    _check_enabled()
    live_qa.require_host_or_moderator(session_id, ctx["user_sub"])
    return live_qa.pin_question(session_id, question_id, ctx["user_sub"], pinned=body.pinned)


@live_qa_router.post("/sessions/{session_id}/questions/{question_id}/remove")
def remove_question(
    session_id: str,
    question_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Soft-delete a question (host/moderator moderation action)."""
    _check_enabled()
    live_qa.require_host_or_moderator(session_id, ctx["user_sub"])
    return live_qa.remove_question(session_id, question_id, ctx["user_sub"])
