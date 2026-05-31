"""Agent PR & Ticket Integration router (AGENT-007).

Endpoints for creating PRs from agent work, listing PRs, managing the
ticket status lifecycle, cross-agent handoffs, GitHub webhook receipt,
and the admin audit listing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.policy import require_admin_or_root
from app.models import (
    AgentPrCreateIn,
    AgentPrListOut,
    AgentWorkCompleteIn,
    StatusFlowUpdateIn,
)
from app.services import agent_pr_integration as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/agent/pr", tags=["agent-pr-integration"])
webhook_router = APIRouter(prefix="/ui/agent/webhooks", tags=["agent-pr-integration"])
admin_router = APIRouter(prefix="/ui/admin/agent", tags=["agent-pr-integration"])


def _require_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    worker = svc._get_worker(user_id, worker_id)
    if not worker:
        raise HTTPException(
            status_code=404,
            detail={"code": "worker_not_found", "message": "Worker not found."},
        )
    return worker


# ---------------------------------------------------------------------------
# PR creation & listing
# ---------------------------------------------------------------------------


@router.post("/{worker_id}/create", status_code=201)
async def create_pr(
    worker_id: str,
    body: AgentPrCreateIn,
    session: Dict = Depends(require_ui_session),
):
    """Create a PR for the worker's ticket (CLI injection or GitHub API)."""
    user_id = session["user_sub"]
    _require_worker(user_id, worker_id)
    pr = svc.create_pr_from_agent(
        user_id,
        worker_id,
        body.ticket_id,
        repo_url=body.repo_url,
        branch=body.branch,
        title=body.title,
        description=body.description,
        files_changed=body.files_changed,
        method=body.method,
    )
    return pr


@router.get("", response_model=AgentPrListOut)
async def list_prs(
    worker_id: str | None = None,
    ticket_id: str | None = None,
    limit: int = 50,
    session: Dict = Depends(require_ui_session),
):
    """List agent-created PRs for the current user."""
    user_id = session["user_sub"]
    prs = svc.list_agent_prs(
        user_id, worker_id=worker_id, ticket_id=ticket_id, limit=limit
    )
    return {"prs": prs, "count": len(prs)}


@router.get("/ticket/{ticket_id}", response_model=AgentPrListOut)
async def get_prs_for_ticket(
    ticket_id: str,
    session: Dict = Depends(require_ui_session),
):
    """List PRs linked to a specific ticket."""
    user_id = session["user_sub"]
    prs = svc.list_agent_prs(user_id, ticket_id=ticket_id)
    return {"prs": prs, "count": len(prs)}


@router.get("/{pr_id}")
async def get_pr(
    pr_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Get a single PR by id."""
    user_id = session["user_sub"]
    pr = svc.get_agent_pr(user_id, pr_id)
    if not pr:
        raise HTTPException(
            status_code=404,
            detail={"code": "pr_not_found", "message": "PR not found."},
        )
    return pr


# ---------------------------------------------------------------------------
# Work completion
# ---------------------------------------------------------------------------


@router.post("/{worker_id}/complete")
async def complete_work(
    worker_id: str,
    body: AgentWorkCompleteIn,
    session: Dict = Depends(require_ui_session),
):
    """Complete agent work: generate summary, create PR, transition status."""
    user_id = session["user_sub"]
    _require_worker(user_id, worker_id)
    try:
        result = svc.complete_agent_work(user_id, worker_id, body.ticket_id)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail={"code": "complete_failed", "message": str(e)},
        )
    return result


# ---------------------------------------------------------------------------
# Status flow config
# ---------------------------------------------------------------------------


@router.get("/status-flow/{agent_type}")
async def get_status_flow(
    agent_type: str,
    session: Dict = Depends(require_ui_session),
):
    """Get the status flow config for an agent type."""
    user_id = session["user_sub"]
    return svc.get_status_flow_config(user_id, agent_type)


@router.put("/status-flow/{agent_type}")
async def set_status_flow(
    agent_type: str,
    body: StatusFlowUpdateIn,
    session: Dict = Depends(require_ui_session),
):
    """Set a custom status flow config for an agent type."""
    user_id = session["user_sub"]
    flow = {k: v for k, v in body.model_dump().items() if v is not None}
    return svc.set_status_flow_config(user_id, agent_type, flow)


# ---------------------------------------------------------------------------
# GitHub webhook receiver
# ---------------------------------------------------------------------------


@webhook_router.post("/github")
async def github_webhook(request: Request):
    """Receive a GitHub webhook event (HMAC-SHA256 verified)."""
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    event_type = request.headers.get("x-github-event", "")

    if not svc.verify_webhook_signature(body, signature):
        raise HTTPException(
            status_code=403,
            detail={"code": "invalid_signature", "message": "Webhook signature verification failed."},
        )

    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_payload", "message": "Webhook payload is not valid JSON."},
        )

    result = svc.handle_github_webhook(payload, event_type)
    return result


# ---------------------------------------------------------------------------
# Admin audit listing
# ---------------------------------------------------------------------------


@admin_router.get("/prs", response_model=AgentPrListOut)
async def admin_list_all_prs(
    limit: int = 200,
    user=Depends(require_admin_or_root),
):
    """Admin: list all agent-created PRs across users."""
    prs = svc.list_all_agent_prs(limit=limit)
    return {"prs": prs, "count": len(prs)}
