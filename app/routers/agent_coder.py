"""Coder Agent router (AGENT-008).

Admin-only endpoints for coder agent type configuration, ticket label filtering
and claiming, deterministic workflow preview/execution, structured output
retrieval, and throughput metrics.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root
from app.models import (
    CoderConfigIn,
    CoderConfigOut,
    CoderConfigValidationOut,
    CoderMetricsOut,
    CoderOutputOut,
    EligibleTicketsOutCoder,
    TestWorkflowIn,
    TicketClaimIn,
    TicketCreateCoderIn,
    WorkflowPreviewOut,
)
from app.services import agent_coder as svc
from app.services import tickets as tickets_svc

router = APIRouter(prefix="/ui/agents", tags=["agent-coder"])


def _require_coder_config(type_id: str) -> Dict[str, Any]:
    agent_type = svc.get_agent_type(agent_type_id=type_id)
    config = svc.get_coder_config(agent_type_id=type_id)
    if config is None:
        if agent_type is None:
            raise HTTPException(status_code=404, detail={"code": "agent_type_not_found", "message": "Agent type not found"})
        raise HTTPException(
            status_code=409,
            detail={"code": "not_a_coder", "message": "Agent type is not configured as a coder"},
        )
    return config


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


@router.get("/types/coder/config-schema")
async def get_config_schema(user=Depends(require_admin_or_root)):
    return svc.config_schema()


# ---------------------------------------------------------------------------
# Config CRUD
# ---------------------------------------------------------------------------


@router.put("/types/{type_id}/coder-config", response_model=CoderConfigOut)
async def put_coder_config(
    type_id: str,
    body: CoderConfigIn,
    user=Depends(require_admin_or_root),
):
    result = svc.update_coder_config(
        agent_type_id=type_id, owner_sub=user.sub, config=body.model_dump()
    )
    return CoderConfigOut(**result)


@router.get("/types/{type_id}/coder-config", response_model=CoderConfigOut)
async def get_coder_config(type_id: str, user=Depends(require_admin_or_root)):
    config = _require_coder_config(type_id)
    return CoderConfigOut(**config)


@router.post("/types/{type_id}/coder-config/validate", response_model=CoderConfigValidationOut)
async def validate_coder_config(
    type_id: str,
    body: Dict[str, Any],
    user=Depends(require_admin_or_root),
):
    errors = svc.validate_coder_config(body or {})
    return CoderConfigValidationOut(valid=len(errors) == 0, errors=errors)


# ---------------------------------------------------------------------------
# Ticket creation helper (labels) + eligibility + claiming
# ---------------------------------------------------------------------------


@router.post("/coder/tickets")
async def create_labeled_ticket(
    body: TicketCreateCoderIn,
    user=Depends(require_admin_or_root),
):
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=user.sub,
        subject=body.subject,
        description=body.description,
        space_id=body.space_id,
        labels=body.labels,
        estimated_effort_hours=body.estimated_effort_hours,
    )
    return ticket


@router.get("/types/{type_id}/eligible-tickets", response_model=EligibleTicketsOutCoder)
async def eligible_tickets(
    type_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    space_id: str | None = Query(default=None),
    user=Depends(require_admin_or_root),
):
    config = _require_coder_config(type_id)
    tickets = svc.find_eligible_tickets(
        skill_level=config.get("skill_level", "mid"),
        complexity_labels=config.get("complexity_labels"),
        space_id=space_id,
        limit=limit,
    )
    return EligibleTicketsOutCoder(tickets=tickets, count=len(tickets))


@router.post("/runs/{run_id}/claim-ticket")
async def claim_ticket(
    run_id: str,
    body: TicketClaimIn,
    user=Depends(require_admin_or_root),
):
    agent_sub = f"agent_{run_id}"
    try:
        return svc.claim_ticket(ticket_id=body.ticket_id, agent_sub=agent_sub)
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"})
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={"code": "ticket_already_claimed", "message": "Ticket is already assigned to another agent"},
        )


# ---------------------------------------------------------------------------
# Workflow preview + mock execution
# ---------------------------------------------------------------------------


@router.post("/types/{type_id}/test-workflow", response_model=WorkflowPreviewOut)
async def test_workflow(
    type_id: str,
    body: TestWorkflowIn,
    user=Depends(require_admin_or_root),
):
    config = _require_coder_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"})
    workflow = svc.build_coder_workflow(
        agent_run_id=f"preview_{type_id}", config=config, ticket=ticket
    )
    return WorkflowPreviewOut(**workflow)


@router.post("/types/{type_id}/runs/{run_id}/execute", response_model=CoderOutputOut)
async def execute_workflow(
    type_id: str,
    run_id: str,
    body: TestWorkflowIn,
    user=Depends(require_admin_or_root),
):
    """Drive the deterministic mock lifecycle for a ticket and persist output."""
    config = _require_coder_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"})
    output = svc.run_mock_workflow(
        run_id=run_id,
        agent_type_id=type_id,
        ticket=ticket,
        config=config,
        agent_sub=f"agent_{run_id}",
    )
    return CoderOutputOut(**output)


# ---------------------------------------------------------------------------
# Output + metrics
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/coder-output", response_model=CoderOutputOut)
async def get_coder_output(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_coder_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "no_coder_output", "message": "No coder output available for this run"},
        )
    return CoderOutputOut(**output)


@router.get("/coder/metrics", response_model=CoderMetricsOut)
async def coder_metrics(
    type_id: str = Query(..., alias="type_id"),
    period_days: int = Query(default=30, ge=1, le=365),
    user=Depends(require_admin_or_root),
):
    metrics = svc.coder_metrics(agent_type_id=type_id, period_days=period_days)
    return CoderMetricsOut(**metrics)
