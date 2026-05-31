"""Accountant / Cost Tracking Agent router (AGENT-018).

Owner-scoped cost tracking endpoints: daily / period summaries, per-agent-type
and per-ticket breakdowns, cost trends, optimization recommendations, budget
CRUD, alert management, accountant config, and a manual collection trigger.

All data is scoped to the authenticated ``user_sub`` (ownership enforcement,
security §7). Cookie-auth non-GET requests require a valid ``x-csrf-token``
header (enforced by ``require_ui_session``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    AccountantConfigOut,
    AttributeTicketCostIn,
    CostAlertListOut,
    CostAlertOut,
    CostBudgetOut,
    CostDailySummaryOut,
    CostEntryOut,
    CostPeriodSummaryOut,
    CostTrendsOut,
    CreateCostBudgetIn,
    OptimizationRecommendationOut,
    RecordCostEntryIn,
    TicketCostListOut,
    TicketCostOut,
    UpdateAccountantConfigIn,
    UpdateCostBudgetIn,
)
from app.services import agent_accountant as svc
from app.services.sessions import require_ui_session

agent_accountant_router = APIRouter(prefix="/ui/agents/accountant", tags=["agent-accountant"])


def _uid(session: Dict[str, Any]) -> str:
    return str(session.get("user_sub") or "")


# ---------------------------------------------------------------------------
# Cost recording / attribution
# ---------------------------------------------------------------------------


@agent_accountant_router.post("/costs/entries", response_model=CostEntryOut, status_code=201)
async def record_cost_entry(
    body: RecordCostEntryIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.record_cost_entry(user_id=_uid(session), **body.model_dump())
    return CostEntryOut(**result)


@agent_accountant_router.post("/costs/by-ticket", response_model=TicketCostOut)
async def attribute_ticket_cost(
    body: AttributeTicketCostIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.attribute_cost_to_ticket(user_id=_uid(session), **body.model_dump())
    return TicketCostOut(**result)


@agent_accountant_router.post("/costs/by-ticket/{ticket_id}/complete", response_model=TicketCostOut)
async def complete_ticket_cost(
    ticket_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    try:
        result = svc.mark_ticket_completed(user_id=_uid(session), ticket_id=ticket_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "ticket_cost_not_found", "message": f"No cost data for ticket: {ticket_id}"},
        )
    return TicketCostOut(**result)


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------


@agent_accountant_router.get("/costs/summary/daily", response_model=CostDailySummaryOut)
async def daily_summary(
    date: Optional[str] = Query(default=None),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    target = date or svc._today()
    if not svc.is_valid_date(target):
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_date", "message": "Date must be in YYYY-MM-DD format"},
        )
    return CostDailySummaryOut(**svc.get_daily_summary(user_id=_uid(session), date=target))


@agent_accountant_router.get("/costs/summary/period", response_model=CostPeriodSummaryOut)
async def period_summary(
    start: str = Query(...),
    end: str = Query(...),
    period: str = Query(default="custom"),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    if not svc.is_valid_date(start) or not svc.is_valid_date(end):
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_date", "message": "Date must be in YYYY-MM-DD format"},
        )
    if period not in ("daily", "weekly", "monthly", "custom"):
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_period", "message": f"Invalid period: {period}"},
        )
    return CostPeriodSummaryOut(
        **svc.get_period_summary(user_id=_uid(session), period=period, start_date=start, end_date=end)
    )


@agent_accountant_router.get("/costs/by-agent-type")
async def by_agent_type(
    type: str = Query(..., alias="type"),
    days: int = Query(default=30, ge=1, le=366),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return svc.get_agent_type_costs(user_id=_uid(session), agent_type=type, days=days)


@agent_accountant_router.get("/costs/by-ticket", response_model=TicketCostListOut)
async def list_ticket_costs(
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return TicketCostListOut(**svc.list_ticket_costs(user_id=_uid(session), limit=limit, cursor=cursor))


@agent_accountant_router.get("/costs/by-ticket/{ticket_id}", response_model=TicketCostOut)
async def get_ticket_cost(
    ticket_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.get_ticket_cost(user_id=_uid(session), ticket_id=ticket_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "ticket_cost_not_found", "message": f"No cost data for ticket: {ticket_id}"},
        )
    return TicketCostOut(**result)


@agent_accountant_router.get("/costs/trends", response_model=CostTrendsOut)
async def cost_trends(
    days: int = Query(default=90, ge=7, le=366),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return CostTrendsOut(**svc.get_cost_trends(user_id=_uid(session), days=days))


@agent_accountant_router.get("/costs/optimizations", response_model=List[OptimizationRecommendationOut])
async def optimizations(
    session: Dict[str, Any] = Depends(require_ui_session),
):
    recs = svc.get_optimization_recommendations(user_id=_uid(session))
    return [OptimizationRecommendationOut(**r) for r in recs]


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------


@agent_accountant_router.get("/costs/budgets", response_model=List[CostBudgetOut])
async def list_budgets(
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return [CostBudgetOut(**b) for b in svc.list_budgets(user_id=_uid(session))]


@agent_accountant_router.post("/costs/budgets", response_model=CostBudgetOut, status_code=201)
async def create_budget(
    body: CreateCostBudgetIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    try:
        result = svc.create_budget(
            user_id=_uid(session),
            name=body.name,
            scope=body.scope,
            scope_ref=body.scope_ref,
            period=body.period,
            limit_cents=body.limit_cents,
            alert_threshold_pct=body.alert_threshold_pct,
            auto_pause_on_exceed=body.auto_pause_on_exceed,
        )
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={"code": "duplicate_budget", "message": f"A {body.period} budget already exists for this scope"},
        )
    return CostBudgetOut(**result)


@agent_accountant_router.put("/costs/budgets/{budget_id}", response_model=CostBudgetOut)
async def update_budget(
    budget_id: str,
    body: UpdateCostBudgetIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    try:
        result = svc.update_budget(
            user_id=_uid(session), budget_id=budget_id, **body.model_dump(exclude_unset=True)
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "budget_not_found", "message": "Budget not found"},
        )
    return CostBudgetOut(**result)


@agent_accountant_router.delete("/costs/budgets/{budget_id}")
async def delete_budget(
    budget_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    try:
        return svc.delete_budget(user_id=_uid(session), budget_id=budget_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "budget_not_found", "message": "Budget not found"},
        )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@agent_accountant_router.get("/costs/alerts", response_model=CostAlertListOut)
async def list_alerts(
    acknowledged: Optional[bool] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return CostAlertListOut(
        **svc.list_alerts(user_id=_uid(session), acknowledged=acknowledged, limit=limit)
    )


@agent_accountant_router.post("/costs/alerts/{alert_id}/acknowledge", response_model=CostAlertOut)
async def acknowledge_alert(
    alert_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    try:
        result = svc.acknowledge_alert(user_id=_uid(session), alert_id=alert_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "alert_not_found", "message": "Cost alert not found"},
        )
    return CostAlertOut(**result)


# ---------------------------------------------------------------------------
# Config + collection
# ---------------------------------------------------------------------------


@agent_accountant_router.get("/costs/config", response_model=AccountantConfigOut)
async def get_config(
    session: Dict[str, Any] = Depends(require_ui_session),
):
    config = svc.get_config(user_id=_uid(session))
    if config is None:
        # Return defaults rather than 404 so the dashboard always renders.
        config = dict(svc._CONFIG_DEFAULTS)
        config["updated_at"] = None
    return AccountantConfigOut(**config)


@agent_accountant_router.put("/costs/config", response_model=AccountantConfigOut)
async def update_config(
    body: UpdateAccountantConfigIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.update_config(user_id=_uid(session), fields=body.model_dump(exclude_unset=True))
    return AccountantConfigOut(**result)


@agent_accountant_router.post("/costs/collect")
async def collect(
    session: Dict[str, Any] = Depends(require_ui_session),
):
    return svc.collect_costs(user_id=_uid(session))
