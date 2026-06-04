"""Agent Fleet Management router (AGENT-004).

Endpoints for fleet-level operations: aggregate status, bulk start/stop,
worker template CRUD, and create-from-template.
"""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    BulkActionOut,
    FleetStatusOut,
    WorkerOut,
    WorkerTemplateIn,
    WorkerTemplateListOut,
    WorkerTemplateOut,
)
from app.services import agent_fleet as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agent/fleet", tags=["agent-fleet"])


# ---------------------------------------------------------------------------
# Fleet status & capacity
# ---------------------------------------------------------------------------


@router.get("/status", response_model=FleetStatusOut)
async def fleet_status(ctx: Dict = Depends(require_ui_session)):
    """Get aggregate fleet metrics for the current user."""
    return svc.fleet_status(ctx["user_sub"])


@router.get("/capacity")
async def fleet_capacity(ctx: Dict = Depends(require_ui_session)):
    """Get queue depth vs. worker availability.

    Note: no ``response_model`` is declared because the intended
    ``CapacityOut`` model (queue_by_type / workers_by_type / workers_by_state /
    recommended_action) is shadowed later in ``app/models.py`` by an unrelated
    ``CapacityOut`` definition. Returning the service dict directly preserves
    the full fleet-capacity shape.
    """
    return svc.fleet_capacity(ctx["user_sub"])


# ---------------------------------------------------------------------------
# Bulk actions
# ---------------------------------------------------------------------------


@router.post("/start-all", response_model=BulkActionOut)
async def bulk_start(ctx: Dict = Depends(require_ui_session)):
    """Start all stopped workers."""
    return svc.bulk_start(ctx["user_sub"])


@router.post("/stop-all", response_model=BulkActionOut)
async def bulk_stop(ctx: Dict = Depends(require_ui_session)):
    """Stop all running/ready workers."""
    return svc.bulk_stop(ctx["user_sub"])


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


@router.post("/templates", response_model=WorkerTemplateOut, status_code=201)
async def create_template(
    body: WorkerTemplateIn,
    ctx: Dict = Depends(require_ui_session),
):
    """Save a new worker template."""
    return svc.save_template(
        ctx["user_sub"],
        label=body.label,
        agent_type=body.agent_type,
        tool=body.tool,
        compute_type=body.compute_type,
        instance_type=body.instance_type,
        llm_key_id=body.llm_key_id,
        repo_url=body.repo_url,
        branch_convention=body.branch_convention,
        idle_timeout_seconds=body.idle_timeout_seconds,
        ticket_filter=body.ticket_filter.model_dump() if body.ticket_filter else None,
    )


@router.get("/templates", response_model=WorkerTemplateListOut)
async def list_templates(ctx: Dict = Depends(require_ui_session)):
    """List all saved worker templates."""
    templates = svc.list_templates(ctx["user_sub"])
    return WorkerTemplateListOut(templates=templates, count=len(templates))


@router.delete("/templates/{template_id}")
async def delete_template(
    template_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    """Delete a worker template."""
    svc.delete_template(ctx["user_sub"], template_id)
    return {"ok": True}


@router.post("/templates/{template_id}/create", response_model=WorkerOut, status_code=201)
async def create_from_template(
    template_id: str,
    body: dict | None = None,
    ctx: Dict = Depends(require_ui_session),
):
    """Create a new worker from a saved template."""
    label = ""
    if body and isinstance(body, dict):
        label = body.get("label", "")
    try:
        return svc.create_worker_from_template(ctx["user_sub"], template_id, label)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)
    except LookupError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
