"""DevOps/SRE Agent router (AGENT-010).

Admin-only endpoints for DevOps agent type configuration, deployment-eligible
ticket previewing, deterministic workflow preview/execution, deployment audit
log retrieval, production approval/rejection, and deployment metrics.

All endpoints require admin or root (``require_admin_or_root``); there is no
agent-specific AdminScope (per ticket NOTE — ``require_admin_session`` does not
exist).
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.models import (
    DeploymentApprovalIn,
    DeploymentApprovalOut,
    DeploymentLogOut,
    DevOpsConfigIn,
    DevOpsConfigOut,
    DevOpsConfigValidationOut,
    DevOpsDeploymentsOut,
    DevOpsEligibleTicketsOut,
    DevOpsExecuteWorkflowIn,
    DevOpsMetricsOut,
    DevOpsOutputOut,
    DevOpsTestWorkflowIn,
    DevOpsWorkflowPreviewOut,
    TicketCreateDevOpsIn,
)
from app.services import agent_devops as svc
from app.services import tickets as tickets_svc

router = APIRouter(prefix="/ui/agents", tags=["agent-devops"])


def _require_devops_config(type_id: str) -> Dict[str, Any]:
    agent_type = svc.get_agent_type(agent_type_id=type_id)
    config = svc.get_devops_config(agent_type_id=type_id)
    if config is None:
        if agent_type is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "agent_type_not_found", "message": "Agent type not found"},
            )
        raise HTTPException(
            status_code=409,
            detail={"code": "not_a_devops", "message": "Agent type is not configured as devops"},
        )
    return config


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


@router.get("/types/devops/config-schema")
async def get_config_schema(user=Depends(require_admin_or_root)):
    return svc.config_schema()


# ---------------------------------------------------------------------------
# Config CRUD
# ---------------------------------------------------------------------------


@router.put("/types/{type_id}/devops-config", response_model=DevOpsConfigOut)
async def put_devops_config(
    type_id: str,
    body: DevOpsConfigIn,
    user=Depends(require_admin_or_root_csrf),
):
    config = body.model_dump()
    errors = svc.validate_devops_config(config)
    if errors:
        raise HTTPException(status_code=422, detail={"code": "invalid_devops_config", "errors": errors})
    result = svc.update_devops_config(agent_type_id=type_id, owner_sub=user.sub, config=config)
    return DevOpsConfigOut(**result)


@router.get("/types/{type_id}/devops-config", response_model=DevOpsConfigOut)
async def get_devops_config(type_id: str, user=Depends(require_admin_or_root)):
    config = _require_devops_config(type_id)
    item = svc.get_agent_type(agent_type_id=type_id) or {}
    return DevOpsConfigOut(type_id=type_id, devops_config=config, updated_at=int(item.get("updated_at", 0) or 0))


@router.post("/types/{type_id}/devops-config/validate", response_model=DevOpsConfigValidationOut)
async def validate_devops_config(
    type_id: str,
    body: Dict[str, Any],
    user=Depends(require_admin_or_root),
):
    errors = svc.validate_devops_config(body or {})
    return DevOpsConfigValidationOut(valid=len(errors) == 0, errors=errors)


# ---------------------------------------------------------------------------
# Ticket creation helper (labels) + eligibility
# ---------------------------------------------------------------------------


@router.post("/devops/tickets")
async def create_labeled_ticket(
    body: TicketCreateDevOpsIn,
    user=Depends(require_admin_or_root),
):
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=user.sub,
        subject=body.subject,
        description=body.description,
        space_id=body.space_id,
        labels=body.labels,
    )
    return ticket


@router.get("/types/{type_id}/devops-eligible-tickets", response_model=DevOpsEligibleTicketsOut)
async def devops_eligible_tickets(
    type_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    user=Depends(require_admin_or_root),
):
    config = _require_devops_config(type_id)
    label_sets = {
        "deployment": config.get("deploy_ticket_labels") or ["type:deployment"],
        "infrastructure": config.get("infra_ticket_labels") or ["type:infrastructure"],
        "incident_response": config.get("incident_ticket_labels") or ["type:incident"],
    }
    tickets = svc.find_devops_eligible_tickets(
        label_sets=label_sets,
        auto_deploy_on_qa=bool(config.get("auto_deploy_on_qa_approved", False)),
        limit=limit,
    )
    return DevOpsEligibleTicketsOut(tickets=tickets, count=len(tickets))


# ---------------------------------------------------------------------------
# Workflow preview + mock execution
# ---------------------------------------------------------------------------


@router.post("/types/{type_id}/test-devops-workflow", response_model=DevOpsWorkflowPreviewOut)
async def test_devops_workflow(
    type_id: str,
    body: DevOpsTestWorkflowIn,
    user=Depends(require_admin_or_root),
):
    config = _require_devops_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"})
    operation_type = svc.classify_operation(ticket=ticket, config=config)
    workflow = svc.build_devops_workflow(
        agent_run_id=f"preview_{type_id}",
        config=config,
        ticket=ticket,
        operation_type=operation_type,
    )
    return DevOpsWorkflowPreviewOut(**workflow)


@router.post("/types/{type_id}/runs/{run_id}/execute-devops", response_model=DevOpsOutputOut)
async def execute_devops_workflow(
    type_id: str,
    run_id: str,
    body: DevOpsExecuteWorkflowIn,
    user=Depends(require_admin_or_root),
):
    """Drive the deterministic mock deployment lifecycle and persist output."""
    config = _require_devops_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"})
    # Mutex check for concurrent deployment to the same environment (§6.7).
    environments = config.get("environments") or []
    env = None
    if body.environment_name:
        env = next((e for e in environments if e.get("name") == body.environment_name), None)
    else:
        env = environments[0] if environments else None
    if env is not None and not env.get("requires_approval", False):
        held = svc.acquire_env_mutex(
            environment=env.get("name", ""), deployment_id=f"chk_{run_id}", agent_run_id=run_id
        )
        if not held:
            raise HTTPException(
                status_code=409,
                detail={"code": "deploy_in_progress", "message": "A deployment is already in progress for this environment"},
            )
        # Release the probe; run_mock_workflow re-acquires for the real run.
        svc.release_env_mutex(environment=env.get("name", ""))
    output = svc.run_mock_workflow(
        run_id=run_id,
        agent_type_id=type_id,
        ticket=ticket,
        config=config,
        agent_sub=f"agent_{run_id}",
        environment_name=body.environment_name,
        version=body.version,
        force_health_failure=body.force_health_failure,
    )
    return DevOpsOutputOut(**output)


# ---------------------------------------------------------------------------
# Output + deployment log
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/devops-output", response_model=DevOpsOutputOut)
async def get_devops_output(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_devops_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "no_devops_output", "message": "No devops output available for this run"},
        )
    return DevOpsOutputOut(**output)


@router.get("/runs/{run_id}/deployment-log", response_model=DeploymentLogOut)
async def get_deployment_log(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_devops_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "run_not_found", "message": "Agent run not found"},
        )
    deployment_id = output.get("deployment_id", "")
    steps = svc.get_deployment_log(deployment_id=deployment_id)
    return DeploymentLogOut(
        deployment_id=deployment_id, environment=output.get("environment", ""), steps=steps
    )


# ---------------------------------------------------------------------------
# Approval / rejection
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/approve-deployment", response_model=DeploymentApprovalOut)
async def approve_deployment(
    run_id: str,
    body: DeploymentApprovalIn,
    user=Depends(require_admin_or_root),
):
    try:
        result = svc.approve_deployment(run_id=run_id, approver_sub=user.sub, notes=body.approver_notes)
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "run_not_found", "message": "Agent run not found"})
    return DeploymentApprovalOut(**result)


@router.post("/runs/{run_id}/reject-deployment", response_model=DeploymentApprovalOut)
async def reject_deployment(
    run_id: str,
    body: DeploymentApprovalIn,
    user=Depends(require_admin_or_root),
):
    try:
        result = svc.reject_deployment(run_id=run_id, approver_sub=user.sub, notes=body.approver_notes)
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "run_not_found", "message": "Agent run not found"})
    return DeploymentApprovalOut(**result)


# ---------------------------------------------------------------------------
# Metrics + deployment listing
# ---------------------------------------------------------------------------


@router.get("/devops/metrics", response_model=DevOpsMetricsOut)
async def devops_metrics(
    type_id: str | None = Query(default=None),
    period_days: int = Query(default=30, ge=1, le=365),
    user=Depends(require_admin_or_root),
):
    metrics = svc.get_devops_metrics(agent_type_id=type_id, period_days=period_days)
    return DevOpsMetricsOut(**metrics)


@router.get("/devops/deployments", response_model=DevOpsDeploymentsOut)
async def devops_deployments(
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(require_admin_or_root),
):
    deployments = svc.list_recent_deployments(limit=limit)
    return DevOpsDeploymentsOut(deployments=deployments, count=len(deployments))
