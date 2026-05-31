"""Agent Orchestrator router (AGENT-003).

Endpoints for controlling the agent loop, managing state transitions,
claiming/releasing tickets, heartbeat monitoring, and checkpoint management.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    AgentStatusOut,
    CheckpointOut,
    EligibleTicketsOut,
    TicketFilterConfig,
)
from app.services import agent_orchestrator as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agent/orchestrator", tags=["agent-orchestrator"])


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/status", response_model=AgentStatusOut)
async def get_agent_status(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Get agent state and status."""
    user_id = session["user_sub"]
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})
    return status


# ---------------------------------------------------------------------------
# Loop Control
# ---------------------------------------------------------------------------


@router.post("/{worker_id}/start")
async def start_agent(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Start the agent loop for a worker."""
    user_id = session["user_sub"]
    try:
        result = svc.start_agent_loop(user_id, worker_id)
        return result
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": msg})
        if "already running" in msg.lower():
            raise HTTPException(status_code=409, detail={"code": "loop_already_running", "message": msg})
        raise HTTPException(status_code=400, detail={"code": "start_failed", "message": msg})


@router.post("/{worker_id}/pause")
async def pause_agent(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Pause the agent (finish current work, don't pick new)."""
    user_id = session["user_sub"]
    try:
        worker = svc.transition_agent_state(user_id, worker_id, "paused")
        current_ticket = worker.get("current_ticket_id", "")
        return {
            "ok": True,
            "worker_id": worker_id,
            "agent_state": "paused",
            "current_ticket_id": current_ticket,
            "message": "Agent paused. Current ticket retained. Resume to continue.",
        }
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": msg})
        if "concurrently" in msg.lower():
            raise HTTPException(status_code=409, detail={"code": "state_conflict", "message": msg})
        raise HTTPException(status_code=400, detail={"code": "invalid_state_transition", "message": msg})


@router.post("/{worker_id}/resume")
async def resume_agent(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Resume a paused agent."""
    user_id = session["user_sub"]
    try:
        worker = svc.transition_agent_state(user_id, worker_id, "idle")
        return {
            "ok": True,
            "worker_id": worker_id,
            "agent_state": "idle",
            "message": "Agent resumed.",
        }
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": msg})
        if "concurrently" in msg.lower():
            raise HTTPException(status_code=409, detail={"code": "state_conflict", "message": msg})
        raise HTTPException(status_code=400, detail={"code": "invalid_state_transition", "message": msg})


@router.post("/{worker_id}/stop")
async def stop_agent(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Stop the agent loop (graceful)."""
    user_id = session["user_sub"]
    try:
        result = svc.stop_agent_loop(user_id, worker_id)
        return result
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": msg})
        raise HTTPException(status_code=400, detail={"code": "stop_failed", "message": msg})


# ---------------------------------------------------------------------------
# Ticket Operations
# ---------------------------------------------------------------------------


@router.post("/{worker_id}/release-ticket")
async def release_ticket(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Manually release the current ticket."""
    user_id = session["user_sub"]
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})

    ticket_id = status.get("current_ticket_id", "")
    if not ticket_id:
        raise HTTPException(status_code=400, detail={"code": "no_active_ticket", "message": "Worker has no active ticket to release."})

    svc.release_ticket(user_id, worker_id, ticket_id)
    return {
        "ok": True,
        "worker_id": worker_id,
        "released_ticket_id": ticket_id,
        "agent_state": "idle",
    }


@router.post("/{worker_id}/claim-ticket")
async def claim_ticket_endpoint(
    worker_id: str,
    body: Dict[str, Any] = {},
    session: Dict = Depends(require_ui_session),
):
    """Manually claim a specific ticket."""
    user_id = session["user_sub"]
    ticket_id = body.get("ticket_id", "")
    if not ticket_id:
        raise HTTPException(status_code=400, detail={"code": "missing_ticket_id", "message": "ticket_id is required."})

    # Check worker exists
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})

    # Check worker doesn't already have a ticket
    if status.get("current_ticket_id"):
        raise HTTPException(status_code=409, detail={"code": "worker_busy", "message": "Worker is already processing a ticket."})

    try:
        claim = svc.claim_ticket(user_id, worker_id, ticket_id)
        return claim
    except ValueError as e:
        msg = str(e)
        if "already claimed" in msg.lower():
            raise HTTPException(status_code=409, detail={"code": "ticket_already_claimed", "message": msg})
        raise HTTPException(status_code=400, detail={"code": "claim_failed", "message": msg})


@router.post("/{worker_id}/complete-ticket")
async def complete_ticket_endpoint(
    worker_id: str,
    body: Dict[str, Any] = {},
    session: Dict = Depends(require_ui_session),
):
    """Manually complete the current ticket."""
    user_id = session["user_sub"]
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})

    ticket_id = status.get("current_ticket_id", "")
    if not ticket_id:
        raise HTTPException(status_code=400, detail={"code": "no_active_ticket", "message": "Worker has no active ticket to complete."})

    svc.complete_ticket(
        user_id, worker_id, ticket_id,
        summary=body.get("summary", ""),
        pr_url=body.get("pr_url", ""),
    )
    return {
        "ok": True,
        "worker_id": worker_id,
        "completed_ticket_id": ticket_id,
        "agent_state": "idle",
    }


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/checkpoint", response_model=CheckpointOut)
async def get_checkpoint(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Get current checkpoint data."""
    user_id = session["user_sub"]
    cp = svc.get_checkpoint(user_id, worker_id)
    if not cp:
        raise HTTPException(status_code=404, detail={"code": "no_checkpoint", "message": "No checkpoint data found for this worker."})
    return cp


@router.post("/{worker_id}/checkpoint")
async def save_checkpoint(
    worker_id: str,
    body: Dict[str, Any] = {},
    session: Dict = Depends(require_ui_session),
):
    """Save checkpoint data for the current ticket."""
    user_id = session["user_sub"]
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})

    ticket_id = status.get("current_ticket_id", "")
    if not ticket_id:
        raise HTTPException(status_code=400, detail={"code": "no_active_ticket", "message": "Worker has no active ticket."})

    checkpoint_data = body.get("checkpoint", body)
    try:
        svc.save_checkpoint(user_id, worker_id, ticket_id, checkpoint_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"code": "checkpoint_too_large", "message": str(e)})

    return {"ok": True, "ticket_id": ticket_id}


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


@router.post("/{worker_id}/heartbeat")
async def heartbeat(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Manual heartbeat (for debugging)."""
    user_id = session["user_sub"]
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})

    ts = svc.record_heartbeat(user_id, worker_id)
    return {"ok": True, "heartbeat_at": ts}


# ---------------------------------------------------------------------------
# Eligible Tickets
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/eligible-tickets", response_model=EligibleTicketsOut)
async def get_eligible_tickets(
    worker_id: str,
    session: Dict = Depends(require_ui_session),
):
    """Preview tickets the agent would pick up."""
    user_id = session["user_sub"]
    status = svc.get_agent_status(user_id, worker_id)
    if not status:
        raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": "Worker not found."})

    result = svc.get_eligible_tickets(user_id, worker_id)
    return result


# ---------------------------------------------------------------------------
# Ticket Filter
# ---------------------------------------------------------------------------


@router.put("/{worker_id}/ticket-filter")
async def update_ticket_filter(
    worker_id: str,
    body: TicketFilterConfig,
    session: Dict = Depends(require_ui_session),
):
    """Update the ticket filter config."""
    user_id = session["user_sub"]
    try:
        result = svc.update_ticket_filter(user_id, worker_id, body.model_dump())
        return result
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail={"code": "worker_not_found", "message": msg})
        raise HTTPException(status_code=400, detail={"code": "update_failed", "message": msg})


# ---------------------------------------------------------------------------
# Worker creation helper (for bootstrapping when AGENT-002 is not deployed)
# ---------------------------------------------------------------------------


@router.post("/create-worker")
async def create_worker_stub(
    body: Dict[str, Any] = {},
    session: Dict = Depends(require_ui_session),
):
    """Create a minimal worker record for agent orchestration.

    This is a convenience endpoint used when AGENT-002 is not deployed.
    """
    user_id = session["user_sub"]
    worker_id = body.get("worker_id", "")
    label = body.get("label", "Agent Worker")
    agent_type = body.get("agent_type", "coder")

    if not worker_id:
        from uuid import uuid4
        worker_id = f"w_{uuid4().hex}"

    worker = svc.ensure_worker_exists(
        user_id, worker_id,
        label=label,
        agent_type=agent_type,
    )
    return worker
