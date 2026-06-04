"""QA Agent router (AGENT-009).

Admin-only endpoints for QA agent type configuration, QA-eligible ticket
discovery and atomic claiming, deterministic workflow preview/execution,
structured QA output / report / screenshot retrieval, and throughput metrics.

Auth: admin/root gating via ``require_admin_or_root`` (there is no QA-specific
AdminScope). Cookie auth + CSRF is enforced by the session dependency stack.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.time import now_ts
from app.models import (
    QaClaimIn,
    QaConfigIn,
    QaConfigOut,
    QaConfigValidationOut,
    QaEligibleTicketsOut,
    QaExecuteIn,
    QaMetricsOut,
    QaOutputOut,
    QaReportOut,
    QaScreenshotsOut,
    QaWorkflowPreviewOut,
)
from app.services import agent_qa as svc
from app.services import tickets as tickets_svc

router = APIRouter(prefix="/ui/agents", tags=["agent-qa"])


def _require_qa_config(type_id: str) -> Dict[str, Any]:
    agent_type = svc.get_agent_type(agent_type_id=type_id)
    config = svc.get_qa_config(agent_type_id=type_id)
    if config is None:
        if agent_type is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "agent_type_not_found", "message": "Agent type not found"},
            )
        raise HTTPException(
            status_code=409,
            detail={"code": "not_a_qa", "message": "Agent type is not configured as qa"},
        )
    return config


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


@router.get("/types/qa/config-schema")
async def get_qa_config_schema(user=Depends(require_admin_or_root)):
    return svc.config_schema()


# ---------------------------------------------------------------------------
# Config CRUD + validation
# ---------------------------------------------------------------------------


@router.put("/types/{type_id}/qa-config", response_model=QaConfigOut)
async def put_qa_config(
    type_id: str,
    body: QaConfigIn,
    user=Depends(require_admin_or_root_csrf),
):
    result = svc.update_qa_config(
        agent_type_id=type_id, owner_sub=user.sub, config=body.model_dump()
    )
    return QaConfigOut(**result)


@router.get("/types/{type_id}/qa-config", response_model=QaConfigOut)
async def get_qa_config(type_id: str, user=Depends(require_admin_or_root)):
    config = _require_qa_config(type_id)
    return QaConfigOut(**config)


@router.post("/types/{type_id}/qa-config/validate", response_model=QaConfigValidationOut)
async def validate_qa_config(
    type_id: str,
    body: Dict[str, Any],
    user=Depends(require_admin_or_root),
):
    errors = svc.validate_qa_config(body or {})
    return QaConfigValidationOut(valid=len(errors) == 0, errors=errors)


# ---------------------------------------------------------------------------
# Eligible tickets + claiming
# ---------------------------------------------------------------------------


@router.get("/types/{type_id}/qa-eligible-tickets", response_model=QaEligibleTicketsOut)
async def qa_eligible_tickets(
    type_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    space_id: str | None = Query(default=None),
    user=Depends(require_admin_or_root),
):
    _require_qa_config(type_id)
    tickets = svc.find_qa_eligible_tickets(space_id=space_id, limit=limit)
    return QaEligibleTicketsOut(tickets=tickets, count=len(tickets))


@router.post("/runs/{run_id}/claim-qa-ticket")
async def claim_qa_ticket(
    run_id: str,
    body: QaClaimIn,
    user=Depends(require_admin_or_root),
):
    agent_sub = f"qa_agent_{run_id}"
    try:
        return svc.claim_qa_ticket(
            agent_run_id=run_id, ticket_id=body.ticket_id, agent_sub=agent_sub
        )
    except LookupError:
        raise HTTPException(
            status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"}
        )
    except ValueError as exc:
        if str(exc) == "invalid_status":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "invalid_ticket_status",
                    "message": "Ticket must be in code_complete status for QA",
                },
            )
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ticket_already_claimed",
                "message": "This ticket is already being tested by another QA agent",
            },
        )


# ---------------------------------------------------------------------------
# Workflow preview + mock execution
# ---------------------------------------------------------------------------


@router.post("/types/{type_id}/test-qa-workflow", response_model=QaWorkflowPreviewOut)
async def test_qa_workflow(
    type_id: str,
    body: QaClaimIn,
    user=Depends(require_admin_or_root),
):
    config = _require_qa_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(
            status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"}
        )
    pr_info = svc.resolve_pr_from_ticket(ticket=ticket) or {
        "pr_url": "",
        "pr_branch": "main",
        "pr_number": 0,
    }
    workflow = svc.build_qa_workflow(
        agent_run_id=f"preview_{type_id}", config=config, ticket=ticket, pr_info=pr_info
    )
    return QaWorkflowPreviewOut(**workflow)


@router.post("/types/{type_id}/runs/{run_id}/execute-qa", response_model=QaOutputOut)
async def execute_qa_workflow(
    type_id: str,
    run_id: str,
    body: QaExecuteIn,
    user=Depends(require_admin_or_root),
):
    """Drive the deterministic mock QA lifecycle for a ticket and persist output."""
    config = _require_qa_config(type_id)
    ticket = tickets_svc.STORE.get_ticket(body.ticket_id)
    if not ticket:
        raise HTTPException(
            status_code=404, detail={"code": "ticket_not_found", "message": "Ticket not found"}
        )
    output = svc.run_mock_workflow(
        run_id=run_id,
        agent_type_id=type_id,
        ticket=ticket,
        config=config,
        agent_sub=f"qa_agent_{run_id}",
        scenario=body.scenario,
    )
    return QaOutputOut(**output)


# ---------------------------------------------------------------------------
# Output + report + screenshots
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/qa-output", response_model=QaOutputOut)
async def get_qa_output(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_qa_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "run_not_found", "message": "No QA output available for this run"},
        )
    return QaOutputOut(**output)


@router.get("/runs/{run_id}/qa-report", response_model=QaReportOut)
async def get_qa_report(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_qa_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "run_not_found", "message": "No QA output available for this run"},
        )
    verdict = output.get("verdict", "error")
    report = svc.build_qa_report(verdict=verdict, output=output)
    return QaReportOut(
        run_id=run_id, verdict=verdict, report_markdown=report, generated_at=now_ts()
    )


@router.get("/runs/{run_id}/qa-screenshots", response_model=QaScreenshotsOut)
async def get_qa_screenshots(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_qa_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "run_not_found", "message": "No QA output available for this run"},
        )
    screenshots = svc.screenshot_presigned_urls(run_id=run_id)
    return QaScreenshotsOut(screenshots=screenshots)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@router.get("/qa/metrics", response_model=QaMetricsOut)
async def qa_metrics(
    type_id: str = Query(..., alias="type_id"),
    period_days: int = Query(default=30, ge=1, le=365),
    user=Depends(require_admin_or_root),
):
    metrics = svc.qa_metrics(agent_type_id=type_id, period_days=period_days)
    return QaMetricsOut(**metrics)
