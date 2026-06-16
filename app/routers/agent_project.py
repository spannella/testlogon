"""Project Manager Agent router (AGENT-012).

The PM Agent orchestrates the downstream agent pipeline (architect -> coder ->
qa -> devops). Most endpoints are admin-only (config, backlog, sprints, reports,
dashboard) via ``require_admin_or_root``; idea submission/listing is open to any
authenticated user via ``require_ui_session`` (users see only their own ideas).

See AGENT-012 §3.3. The ticket originally referenced ``require_admin_session`` /
``require_admin_scope`` — per the correction NOTEs and the codebase convention the
admin dependency is ``require_admin_or_root`` from ``app/auth/policy.py``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.models import (
    AgentCapacityOut,
    BacklogItemOut,
    BacklogOut,
    BlockerListOut,
    BlockerOut,
    AgentProjectCapacityOut,
    CreateSprintIn,
    IdeaListOut,
    IdeaOut,
    PmConfigIn,
    PmConfigOut,
    PmConfigValidationOut,
    PmMetricsOut,
    PmOutputOut,
    ProjectDashboardOut,
    ReportListOut,
    PmReportOut,
    ReprioritizeOut,
    SprintDetailOut,
    SprintListOut,
    SprintOut,
    SubmitIdeaIn,
    TriggerPmOperationIn,
    UpdateIdeaIn,
    UpdateSprintIn,
)
from app.services import agent_coder as coder_svc
from app.services import agent_project as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agents", tags=["agent-pm"])


def _require_pm_config(type_id: str) -> Dict[str, Any]:
    agent_type = coder_svc.get_agent_type(agent_type_id=type_id)
    config = svc.get_pm_config(agent_type_id=type_id)
    if config is None:
        if agent_type is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "AGENT_TYPE_NOT_FOUND", "message": "Agent type not found"},
            )
        raise HTTPException(
            status_code=409,
            detail={"code": "AGENT_TYPE_MISMATCH", "message": "Agent type is not configured as pm"},
        )
    return config


def _is_admin(session: Dict[str, Any]) -> bool:
    return normalize_role(session.get("role")) in (Role.ADMIN, Role.ROOT)


def _resolve_space_id(space_id: Optional[str], type_id: Optional[str]) -> Optional[str]:
    if space_id:
        return space_id
    if type_id:
        config = svc.get_pm_config(agent_type_id=type_id)
        if config:
            return config.get("project_space_id")
    return None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@router.put("/types/{type_id}/pm-config", response_model=PmConfigOut)
async def put_pm_config(type_id: str, body: PmConfigIn, user=Depends(require_admin_or_root)):
    result = svc.update_pm_config(
        agent_type_id=type_id, owner_sub=user.sub, config=body.model_dump()
    )
    return PmConfigOut(**result)


@router.get("/types/{type_id}/pm-config", response_model=PmConfigOut)
async def get_pm_config(type_id: str, user=Depends(require_admin_or_root)):
    config = _require_pm_config(type_id)
    return PmConfigOut(**config)


@router.post("/types/{type_id}/pm-config/validate", response_model=PmConfigValidationOut)
async def validate_pm_config(type_id: str, body: Dict[str, Any], user=Depends(require_admin_or_root)):
    errors = svc.validate_pm_config(body or {})
    return PmConfigValidationOut(valid=len(errors) == 0, errors=errors)


# ---------------------------------------------------------------------------
# Idea intake (user-accessible)
# ---------------------------------------------------------------------------


@router.post("/ideas", response_model=IdeaOut, status_code=201)
async def submit_idea(body: SubmitIdeaIn, response: Response, session=Depends(require_ui_session)):
    idea = svc.submit_idea(
        user_sub=session["user_sub"], title=body.title, description=body.description
    )
    return IdeaOut(**idea)


@router.get("/ideas", response_model=IdeaListOut)
async def list_ideas(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    # Users only see their own ideas; admins see all (optionally filtered by status).
    if _is_admin(session):
        result = svc.list_ideas(status=status, limit=limit, cursor=cursor)
    else:
        result = svc.list_ideas(user_sub=session["user_sub"], limit=limit, cursor=cursor)
    return IdeaListOut(**result)


@router.get("/ideas/{idea_id}", response_model=IdeaOut)
async def get_idea(idea_id: str, session=Depends(require_ui_session)):
    idea = svc.get_idea(idea_id=idea_id)
    if not idea:
        raise HTTPException(
            status_code=404,
            detail={"code": "IDEA_NOT_FOUND", "message": "Product idea not found"},
        )
    if not _is_admin(session) and idea.get("submitted_by") != session["user_sub"]:
        raise HTTPException(
            status_code=404,
            detail={"code": "IDEA_NOT_FOUND", "message": "Product idea not found"},
        )
    return IdeaOut(**idea)


@router.patch("/ideas/{idea_id}", response_model=IdeaOut)
async def update_idea(idea_id: str, body: UpdateIdeaIn, user=Depends(require_admin_or_root)):
    idea = svc.get_idea(idea_id=idea_id)
    if not idea:
        raise HTTPException(
            status_code=404,
            detail={"code": "IDEA_NOT_FOUND", "message": "Product idea not found"},
        )
    if idea.get("status") == "converted":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "IDEA_ALREADY_CONVERTED",
                "message": "This idea has already been converted to a feature request",
            },
        )
    updated = svc.update_idea_status(
        idea_id=idea_id, status=body.status, rejection_reason=body.rejection_reason
    )
    return IdeaOut(**updated)


# ---------------------------------------------------------------------------
# Backlog & prioritization
# ---------------------------------------------------------------------------


@router.get("/backlog", response_model=BacklogOut)
async def get_backlog(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=100),
    user=Depends(require_admin_or_root),
):
    config = svc.get_pm_config(agent_type_id=type_id) if type_id else None
    resolved_space = _resolve_space_id(space_id, type_id)
    weights = (config or {}).get("priority_weights") if config else None
    capacity = (config or {}).get("capacity_per_agent_type") if config else None
    backlog = svc.get_backlog(space_id=resolved_space, limit=limit)
    prioritized = svc.prioritize_backlog(
        backlog=backlog, weights=weights or {}, capacity=capacity or {}
    )
    items = svc.backlog_view(prioritized=prioritized)
    return BacklogOut(items=[BacklogItemOut(**i) for i in items], count=len(items))


@router.post("/backlog/reprioritize", response_model=ReprioritizeOut)
async def reprioritize_backlog(
    type_id: str = Query(...),
    run_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    config = _require_pm_config(type_id)
    output = svc.run_backlog_prioritize(
        run_id=run_id or f"reprio_{type_id}",
        agent_type_id=type_id,
        config=config,
        agent_sub=user.sub,
    )
    return ReprioritizeOut(
        tickets_reprioritized=output.get("tickets_reprioritized", 0),
        escalations_created=output.get("escalations_created", 0),
    )


# ---------------------------------------------------------------------------
# Blockers & capacity
# ---------------------------------------------------------------------------


@router.get("/blockers", response_model=BlockerListOut)
async def get_blockers(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    stale_hours: int = Query(default=48, ge=1, le=720),
    user=Depends(require_admin_or_root),
):
    config = svc.get_pm_config(agent_type_id=type_id) if type_id else None
    if config and "blocker_stale_hours" in config:
        stale_hours = int(config["blocker_stale_hours"])
    resolved_space = _resolve_space_id(space_id, type_id)
    blockers = svc.detect_blockers(space_id=resolved_space, stale_hours=stale_hours)
    return BlockerListOut(blockers=[BlockerOut(**b) for b in blockers], count=len(blockers))


@router.get("/capacity", response_model=AgentProjectCapacityOut)
async def get_capacity(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    config = svc.get_pm_config(agent_type_id=type_id) if type_id else None
    capacity = (config or {}).get("capacity_per_agent_type") or {}
    resolved_space = _resolve_space_id(space_id, type_id)
    backlog = svc.get_backlog(space_id=resolved_space)
    utilization = svc.get_agent_utilization(capacity=capacity, backlog=backlog)
    fit = svc.check_capacity_fit(backlog=backlog, capacity=capacity)
    return AgentProjectCapacityOut(
        capacity=[AgentCapacityOut(**u) for u in utilization],
        fits=fit["fits"],
        overflow_hours=fit["overflow_hours"],
        recommendation=fit["recommendation"],
    )


# ---------------------------------------------------------------------------
# Sprints
# ---------------------------------------------------------------------------


@router.get("/sprints", response_model=SprintListOut)
async def list_sprints(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    sprints = svc.list_sprints(space_id=resolved_space)
    return SprintListOut(sprints=[SprintOut(**s) for s in sprints], count=len(sprints))


@router.post("/sprints", response_model=SprintOut, status_code=201)
async def create_sprint(
    body: CreateSprintIn,
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    try:
        sprint = svc.create_sprint(
            space_id=resolved_space,
            start_date=body.start_date,
            end_date=body.end_date,
            planned_tickets=body.planned_ticket_ids,
        )
    except ValueError as exc:
        if str(exc) == "invalid_dates":
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_DATES", "message": "End date must be after start date"},
            )
        if str(exc) == "overlap":
            raise HTTPException(
                status_code=409,
                detail={"code": "SPRINT_OVERLAP", "message": "Sprint dates overlap with an existing sprint"},
            )
        raise
    return SprintOut(**sprint)


@router.get("/sprints/{sprint_id}", response_model=SprintDetailOut)
async def get_sprint(
    sprint_id: str,
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    sprint = svc.get_sprint(space_id=resolved_space, sprint_id=sprint_id)
    if not sprint:
        raise HTTPException(
            status_code=404,
            detail={"code": "SPRINT_NOT_FOUND", "message": "Sprint not found"},
        )
    burndown = svc.get_sprint_burndown(space_id=resolved_space, sprint_id=sprint_id)
    return SprintDetailOut(sprint=SprintOut(**sprint), burndown=burndown)


@router.patch("/sprints/{sprint_id}", response_model=SprintOut)
async def update_sprint(
    sprint_id: str,
    body: UpdateSprintIn,
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    if not svc.get_sprint(space_id=resolved_space, sprint_id=sprint_id):
        raise HTTPException(
            status_code=404,
            detail={"code": "SPRINT_NOT_FOUND", "message": "Sprint not found"},
        )
    if body.action == "activate":
        sprint = svc.activate_sprint(space_id=resolved_space, sprint_id=sprint_id)
    else:
        sprint = svc.close_sprint(space_id=resolved_space, sprint_id=sprint_id)
    return SprintOut(**sprint)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@router.get("/reports", response_model=ReportListOut)
async def list_reports(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    reports = svc.list_reports(space_id=resolved_space, limit=limit)
    return ReportListOut(reports=[PmReportOut(**r) for r in reports], count=len(reports))


@router.get("/reports/{report_id}", response_model=PmReportOut)
async def get_report(
    report_id: str,
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    report = svc.get_report(space_id=resolved_space, report_id=report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail={"code": "REPORT_NOT_FOUND", "message": "Report not found"},
        )
    return PmReportOut(**report)


# ---------------------------------------------------------------------------
# Orchestration trigger (deterministic mock workflows)
# ---------------------------------------------------------------------------


@router.post("/types/{type_id}/runs/{run_id}/pm-operation", response_model=PmOutputOut)
async def run_pm_operation(
    type_id: str,
    run_id: str,
    body: TriggerPmOperationIn,
    user=Depends(require_admin_or_root),
):
    config = _require_pm_config(type_id)
    op = body.operation_type
    if op == "idea_triage":
        output = svc.run_idea_triage(run_id=run_id, agent_type_id=type_id, config=config, agent_sub=user.sub)
    elif op == "backlog_prioritize":
        output = svc.run_backlog_prioritize(run_id=run_id, agent_type_id=type_id, config=config, agent_sub=user.sub)
    elif op == "blocker_detect":
        output = svc.run_blocker_detect(run_id=run_id, agent_type_id=type_id, config=config, agent_sub=user.sub)
    else:  # report_generate
        output = svc.run_report_generate(
            run_id=run_id, agent_type_id=type_id, config=config, agent_sub=user.sub, report_type=body.report_type
        )
    return PmOutputOut(**output)


@router.get("/runs/{run_id}/pm-output", response_model=PmOutputOut)
async def get_pm_output(run_id: str, user=Depends(require_admin_or_root)):
    output = svc.get_pm_output(run_id=run_id)
    if output is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "RUN_NOT_FOUND", "message": "No PM output available for this run"},
        )
    return PmOutputOut(**output)


# ---------------------------------------------------------------------------
# Metrics & dashboard
# ---------------------------------------------------------------------------


@router.get("/pm/metrics", response_model=PmMetricsOut)
async def pm_metrics(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    period_days: int = Query(default=30, ge=1, le=365),
    user=Depends(require_admin_or_root),
):
    resolved_space = _resolve_space_id(space_id, type_id)
    metrics = svc.get_pm_metrics(space_id=resolved_space, period_days=period_days)
    return PmMetricsOut(**metrics)


@router.get("/pm/dashboard", response_model=ProjectDashboardOut)
async def pm_dashboard(
    type_id: Optional[str] = Query(default=None),
    space_id: Optional[str] = Query(default=None),
    user=Depends(require_admin_or_root),
):
    config = svc.get_pm_config(agent_type_id=type_id) if type_id else None
    resolved_space = _resolve_space_id(space_id, type_id)
    dashboard = svc.get_project_dashboard(space_id=resolved_space, config=config)
    return ProjectDashboardOut(
        sprint=SprintOut(**dashboard["sprint"]) if dashboard.get("sprint") else None,
        velocity_trend=dashboard["velocity_trend"],
        backlog_by_priority=dashboard["backlog_by_priority"],
        pipeline_funnel=dashboard["pipeline_funnel"],
        agent_utilization=[AgentCapacityOut(**u) for u in dashboard["agent_utilization"]],
        blockers=[BlockerOut(**b) for b in dashboard["blockers"]],
        recent_completions=dashboard["recent_completions"],
    )
