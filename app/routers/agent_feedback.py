"""Agent Feedback router (AGENT-006).

Endpoints for managing agent feedback requests, terminal output,
and pattern configuration.

IMPORTANT: Route order matters in FastAPI. Fixed-path segments like
``/test-patterns``, ``/{worker_id}/patterns``, ``/{worker_id}/terminal-log``
must be declared BEFORE parameterised catch-alls like ``/{worker_id}/{request_id}``
to avoid the fixed segment being consumed as a path parameter.
"""

from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    CreateFeedbackRequestIn,
    FeedbackListOut,
    FeedbackRequestOut,
    FeedbackRespondIn,
    PatternConfigOut,
    PatternTestIn,
    PatternTestOut,
    PatternUpdateIn,
    TerminalOutputOut,
    TerminalSearchOut,
)
from app.services import terminal_monitor as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agent/feedback", tags=["agent-feedback"])


def _item_to_out(item: Dict) -> FeedbackRequestOut:
    """Convert a DDB item to a FeedbackRequestOut model."""
    return FeedbackRequestOut(
        request_id=item.get("request_id", ""),
        worker_id=item.get("worker_id", ""),
        ticket_id=item.get("ticket_id", ""),
        feedback_status=item.get("feedback_status", ""),
        question=item.get("question", ""),
        terminal_context=item.get("terminal_context", ""),
        detected_pattern=item.get("detected_pattern", ""),
        response_text=item.get("response_text", ""),
        responded_at=int(item.get("responded_at", 0)),
        timeout_at=int(item.get("timeout_at", 0)),
        timeout_action=item.get("timeout_action", "skip"),
        created_at=int(item.get("created_at", 0)),
        user_id=item.get("user_id", ""),
    )


# ---------------------------------------------------------------------------
# Fixed-path endpoints (MUST come before parameterised /{worker_id} routes)
# ---------------------------------------------------------------------------


@router.get("", response_model=FeedbackListOut)
async def list_all_feedback(
    status: Optional[str] = Query(None),
    session: Dict = Depends(require_ui_session),
):
    """List all feedback requests across all workers for the current user."""
    user_id = session["user_sub"]
    items = svc.list_pending_feedback_for_user(user_id)
    requests = [_item_to_out(item) for item in items]
    pending_count = sum(1 for r in requests if r.feedback_status == "pending")
    return FeedbackListOut(
        requests=requests,
        count=len(requests),
        pending_count=pending_count,
    )


@router.post("/test-patterns", response_model=PatternTestOut)
async def test_patterns(
    body: PatternTestIn,
    session: Dict = Depends(require_ui_session),
):
    """Test patterns against sample text."""
    matches = svc.test_patterns(body.patterns, body.sample_text)
    return PatternTestOut(
        matches=matches,
        match_count=len(matches),
    )


# ---------------------------------------------------------------------------
# Worker-scoped fixed-path endpoints (MUST come before /{worker_id}/{request_id})
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/patterns", response_model=PatternConfigOut)
async def get_patterns(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Get pattern configuration for a worker. Falls back to defaults."""
    custom = svc.get_worker_pattern_config(worker_id)
    if custom:
        return PatternConfigOut(
            agent_type="custom",
            completion=custom.get("completion", []),
            feedback_needed=custom.get("feedback_needed", []),
            error=custom.get("error", []),
        )
    patterns = svc.DEFAULT_FEEDBACK_PATTERNS
    return PatternConfigOut(
        agent_type="default",
        completion=patterns.get("completion", []),
        feedback_needed=patterns.get("feedback_needed", []),
        error=patterns.get("error", []),
    )


@router.put("/{worker_id}/patterns", response_model=PatternConfigOut)
async def update_patterns(
    worker_id: str,
    body: PatternUpdateIn,
    session: Dict = Depends(require_ui_session),
):
    """Update custom pattern configuration for a worker."""
    user_id = session["user_sub"]
    current = svc.get_worker_pattern_config(worker_id) or dict(svc.DEFAULT_FEEDBACK_PATTERNS)
    if body.completion is not None:
        current["completion"] = body.completion
    if body.feedback_needed is not None:
        current["feedback_needed"] = body.feedback_needed
    if body.error is not None:
        current["error"] = body.error

    try:
        result = svc.update_pattern_config(user_id, worker_id, current)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_pattern", "message": str(exc)},
        )

    return PatternConfigOut(
        agent_type="custom",
        completion=result.get("completion", []),
        feedback_needed=result.get("feedback_needed", []),
        error=result.get("error", []),
    )


@router.get("/{worker_id}/terminal-log", response_model=TerminalOutputOut)
async def get_terminal_log(
    worker_id: str,
    chars: int = Query(5000, ge=100, le=50000),
    session: Dict = Depends(require_ui_session),
):
    """Get recent terminal output for a worker."""
    output = svc.get_terminal_output(worker_id, chars=chars)
    return TerminalOutputOut(
        worker_id=worker_id,
        output=output,
        char_count=len(output),
    )


@router.get("/{worker_id}/terminal-search", response_model=TerminalSearchOut)
async def search_terminal(
    worker_id: str,
    keyword: str = Query(..., min_length=1, max_length=200),
    session: Dict = Depends(require_ui_session),
):
    """Search terminal output for a keyword."""
    matches = svc.search_terminal_output(worker_id, keyword)
    return TerminalSearchOut(
        worker_id=worker_id,
        keyword=keyword,
        matches=matches[:100],
        match_count=len(matches),
    )


# ---------------------------------------------------------------------------
# Worker-scoped list + create
# ---------------------------------------------------------------------------


@router.get("/{worker_id}", response_model=FeedbackListOut)
async def list_worker_feedback(
    worker_id: str,
    status: Optional[str] = Query(None),
    session: Dict = Depends(require_ui_session),
):
    """List feedback requests for a specific worker."""
    items = svc.list_feedback_requests(worker_id, status=status)
    requests = [_item_to_out(item) for item in items]
    pending_count = sum(1 for r in requests if r.feedback_status == "pending")
    return FeedbackListOut(
        requests=requests,
        count=len(requests),
        pending_count=pending_count,
    )


@router.post("/{worker_id}", response_model=FeedbackRequestOut, status_code=201)
async def create_feedback(
    worker_id: str,
    body: CreateFeedbackRequestIn,
    session: Dict = Depends(require_ui_session),
):
    """Create a feedback request (used internally or for testing)."""
    user_id = session["user_sub"]
    item = svc.create_feedback_request(
        user_id=user_id,
        worker_id=worker_id,
        ticket_id=body.ticket_id,
        question=body.question,
        terminal_context=body.terminal_context,
        detected_pattern=body.detected_pattern,
        timeout_seconds=body.timeout_seconds,
        timeout_action=body.timeout_action,
    )
    return _item_to_out(item)


# ---------------------------------------------------------------------------
# Single feedback request: get / respond / skip
# (MUST be last — /{worker_id}/{request_id} catches everything)
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/{request_id}", response_model=FeedbackRequestOut)
async def get_feedback(
    worker_id: str,
    request_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Get a single feedback request."""
    item = svc.get_feedback_request(worker_id, request_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"code": "feedback_not_found", "message": "Feedback request not found."},
        )
    return _item_to_out(item)


@router.post(
    "/{worker_id}/{request_id}/respond",
    response_model=FeedbackRequestOut,
)
async def respond_to_feedback(
    worker_id: str,
    request_id: str,
    body: FeedbackRespondIn,
    session: Dict = Depends(require_ui_session),
):
    """Submit a response to a feedback request."""
    user_id = session["user_sub"]
    try:
        item = svc.respond_to_feedback(
            user_id=user_id,
            worker_id=worker_id,
            request_id=request_id,
            response_text=body.response_text,
        )
        return _item_to_out(item)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "feedback_not_found", "message": "Feedback request not found."},
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": str(exc)},
        )


@router.post(
    "/{worker_id}/{request_id}/skip",
    response_model=FeedbackRequestOut,
)
async def skip_feedback(
    worker_id: str,
    request_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Skip a feedback request. Agent resumes with best judgment."""
    user_id = session["user_sub"]
    try:
        item = svc.skip_feedback(user_id, worker_id, request_id)
        return _item_to_out(item)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "feedback_not_found", "message": "Feedback request not found."},
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": str(exc)},
        )
