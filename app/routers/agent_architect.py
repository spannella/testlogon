"""Solution Architect Agent router (AGENT-011).

Admin-only endpoints for architect agent type configuration, feature-request
ticket eligibility, deterministic decomposition workflow preview/execution,
decomposition + dependency-graph retrieval, structured output, and metrics.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root
from app.models import (
    ArchitectConfigIn,
    ArchitectConfigOut,
    ArchitectConfigValidationOut,
    ArchitectEligibleTicketsOut,
    ArchitectMetricsOut,
    ArchitectOutputOut,
    ArchitectWorkflowPreviewOut,
    DecompositionOut,
    DependencyGraphOut,
    DevTicketListOut,
    TestArchitectWorkflowIn,
    TicketCreateFeatureIn,
)
from app.services import agent_architect as svc
from app.services import agent_coder as coder_svc
from app.services import tickets as tickets_svc

router = APIRouter(prefix="/ui/agents", tags=["agent-architect"])


def _require_architect_config(type_id: str) -> Dict[str, Any]:
    agent_type = coder_svc.get_agent_type(agent_type_id=type_id)
    config = svc.get_architect_config(agent_type_id=type_id)
    if config is None:
        if agent_type is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "AGENT_TYPE_NOT_FOUND", "message": "Agent type not found"},
            )
        raise HTTPException(
            status_code=409,
            detail={"code": "AGENT_TYPE_MISMATCH", "message": "Agent type is not configured as architect"},
        )
    return config


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


@router.get("/types/architect/config-schema")
async def get_config_schema(user=Depends(require_admin_or_root)):
    return svc.config_schema()


# ---------------------------------------------------------------------------
# Config CRUD
# ---------------------------------------------------------------------------


@router.put("/types/{type_id}/architect-config", response_model=ArchitectConfigOut)
async def put_architect_config(
    type_id: str,
    body: ArchitectConfigIn,
    user=Depends(require_admin_or_root),
):
    result = svc.update_architect_config(
        agent_type_id=type_id, owner_sub=user.sub, config=body.model_dump()
    )
    return ArchitectConfigOut(**result)


@router.get("/types/{type_id}/architect-config", response_model=ArchitectConfigOut)
async def get_architect_config(type_id: str, user=Depends(require_admin_or_root)):
    config = _require_architect_config(type_id)
    return ArchitectConfigOut(**config)


@router.post("/types/{type_id}/architect-config/validate", response_model=ArchitectConfigValidationOut)
async def validate_architect_config(
    type_id: str,
    body: Dict[str, Any],
    user=Depends(require_admin_or_root),
):
    errors = svc.validate_architect_config(body or {})
    return ArchitectConfigValidationOut(valid=len(errors) == 0, errors=errors)


# ---------------------------------------------------------------------------
# Feature ticket creation helper + eligibility
# ---------------------------------------------------------------------------


@router.post("/architect/tickets")
async def create_feature_ticket(
    body: TicketCreateFeatureIn,
    user=Depends(require_admin_or_root),
):
    labels = body.labels or [svc.FEATURE_REQUEST_LABEL]
    if svc.FEATURE_REQUEST_LABEL not in labels:
        labels = [*labels, svc.FEATURE_REQUEST_LABEL]
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=user.sub,
        subject=body.subject,
        description=body.description,
        space_id=body.space_id,
        labels=labels,
    )
    return ticket


@router.get("/types/{type_id}/architect-eligible-tickets", response_model=ArchitectEligibleTicketsOut)
async def architect_eligible_tickets(
    type_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    user=Depends(require_admin_or_root),
):
    _require_architect_config(type_id)
    tickets = svc.find_architect_eligible_tickets(agent_type_id=type_id, limit=limit)
    return ArchitectEligibleTicketsOut(tickets=tickets, count=len(tickets))


# ---------------------------------------------------------------------------
# Workflow preview + mock execution
# ---------------------------------------------------------------------------


@router.post("/types/{type_id}/test-architect-workflow", response_model=ArchitectWorkflowPreviewOut)
async def test_architect_workflow(
    type_id: str,
    body: TestArchitectWorkflowIn,
    user=Depends(require_admin_or_root),
):
    config = _require_architect_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(
            status_code=404,
            detail={"code": "FEATURE_NOT_FOUND", "message": "Feature request ticket not found"},
        )
    workflow = svc.build_architect_workflow(
        agent_run_id=f"preview_{type_id}", config=config, ticket=ticket
    )
    return ArchitectWorkflowPreviewOut(**workflow)


@router.post("/types/{type_id}/runs/{run_id}/decompose", response_model=ArchitectOutputOut)
async def decompose_feature(
    type_id: str,
    run_id: str,
    body: TestArchitectWorkflowIn,
    user=Depends(require_admin_or_root),
):
    """Drive the deterministic mock decomposition lifecycle for a feature request."""
    config = _require_architect_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(
            status_code=404,
            detail={"code": "FEATURE_NOT_FOUND", "message": "Feature request ticket not found"},
        )
    if svc.is_feature_decomposed(feature_ticket_id=body.ticket_id):
        raise HTTPException(
            status_code=409,
            detail={"code": "ALREADY_DECOMPOSED", "message": "This feature request has already been decomposed"},
        )
    try:
        output = svc.run_mock_workflow(
            run_id=run_id,
            agent_type_id=type_id,
            ticket=ticket,
            config=config,
            agent_sub=f"agent_{run_id}",
        )
    except ValueError as exc:
        if str(exc) == "circular_dependency":
            raise HTTPException(
                status_code=422,
                detail={"code": "CIRCULAR_DEPENDENCY", "message": "Circular dependency detected in ticket graph"},
            )
        raise
    return ArchitectOutputOut(**output)


# ---------------------------------------------------------------------------
# Decomposition + dependency graph + dev tickets
# ---------------------------------------------------------------------------


@router.get("/features/{feature_ticket_id}/decomposition", response_model=DecompositionOut)
async def get_decomposition(feature_ticket_id: str, user=Depends(require_admin_or_root)):
    decomp = svc.get_decomposition(feature_ticket_id=feature_ticket_id)
    if decomp is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "FEATURE_NOT_FOUND", "message": "No decomposition found for this feature request"},
        )
    return DecompositionOut(**decomp)


@router.get("/features/{feature_ticket_id}/dependency-graph", response_model=DependencyGraphOut)
async def get_dependency_graph(feature_ticket_id: str, user=Depends(require_admin_or_root)):
    view = svc.get_dependency_graph_view(feature_ticket_id=feature_ticket_id)
    if view is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "FEATURE_NOT_FOUND", "message": "No decomposition found for this feature request"},
        )
    return DependencyGraphOut(**view)


@router.get("/features/{feature_ticket_id}/dev-tickets", response_model=DevTicketListOut)
async def get_dev_tickets(feature_ticket_id: str, user=Depends(require_admin_or_root)):
    tickets = svc.get_dev_tickets_for_feature(feature_ticket_id=feature_ticket_id)
    return DevTicketListOut(tickets=tickets, count=len(tickets))


# ---------------------------------------------------------------------------
# Output + metrics
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/architect-output", response_model=ArchitectOutputOut)
async def get_architect_output(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_architect_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "RUN_NOT_FOUND", "message": "No architect output available for this run"},
        )
    return ArchitectOutputOut(**output)


@router.get("/architect/metrics", response_model=ArchitectMetricsOut)
async def architect_metrics(
    type_id: str = Query(..., alias="type_id"),
    period_days: int = Query(default=30, ge=1, le=365),
    user=Depends(require_admin_or_root),
):
    metrics = svc.get_architect_metrics(agent_type_id=type_id, period_days=period_days)
    return ArchitectMetricsOut(**metrics)
