"""Sales pipeline — Opportunities router (OPP-002..OPP-006)."""
from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.auth.roles import Role, normalize_role
from app.auth.policy import require_admin_or_root
from app.auth.deps import get_authenticated_user, AuthenticatedUser
from app.models import (
    ForecastWorksheetIn,
    ForecastWorksheetOut,
    OppContactRoleIn,
    OppContactRoleOut,
    OpportunityCreateIn,
    OpportunityOut,
    OpportunityUpdateIn,
    PipelineReportOut,
    SalesQuotaIn,
    SalesQuotaListOut,
    SalesQuotaOut,
    StageConfigIn,
    StageConfigOut,
)
from app.services.sessions import require_ui_session
from app.services.opportunities import (
    _require_flag,
    add_contact_role,
    create_opportunity,
    delete_opportunity,
    get_forecast,
    get_opportunity,
    get_quota,
    get_stage_config,
    list_contact_roles,
    list_opportunities,
    list_quotas_for_user,
    pipeline_report,
    pipeline_report_all,
    remove_contact_role,
    set_quota,
    set_stage_config,
    update_opportunity,
    upsert_forecast,
)
from app.core.settings import S

router = APIRouter(prefix="/ui/sales", tags=["sales-pipeline"])
router_admin = APIRouter(prefix="/ui/admin/sales", tags=["sales-pipeline-admin"])


# ── Feature status (OPP-003/006) — must not call _require_flag ────────────────

@router.get("/feature-status")
async def feature_status(ctx: dict = Depends(require_ui_session)) -> dict:
    """Return whether the sales pipeline feature is enabled. Does not 503 when off."""
    return {"enabled": S.sales_pipeline_enabled}


# ── OPP-003: Stage config endpoints ──────────────────────────────────────────
# NOTE: declared BEFORE /{opp_id} to avoid FastAPI capturing "stages" as opp_id

@router.get("/stages", response_model=StageConfigOut)
async def list_stages(ctx: dict = Depends(require_ui_session)) -> StageConfigOut:
    """Return active stage list. Requires a valid session; no admin role needed."""
    return get_stage_config()


@router_admin.put("/stages", response_model=StageConfigOut)
async def update_stages(
    body: StageConfigIn,
    ctx: dict = Depends(require_ui_session),
) -> StageConfigOut:
    """Replace the stage list. Admin or Root role required."""
    if normalize_role(ctx.get("role")) not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(403, detail={"code": "admin_role_required"})
    return set_stage_config(ctx["user_sub"], body)


# ── OPP-005: Forecast worksheet endpoints ─────────────────────────────────────
# NOTE: declared BEFORE /{opp_id} to prevent "forecast" captured as opp_id

@router.put("/forecast/{period_key}", response_model=ForecastWorksheetOut)
async def put_forecast(
    period_key: str,
    body: ForecastWorksheetIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ForecastWorksheetOut:
    """Upsert a forecast worksheet for the authenticated rep."""
    _require_flag()
    return upsert_forecast(user.sub, period_key, body)


@router.get("/forecast/{period_key}", response_model=ForecastWorksheetOut)
async def read_forecast(
    period_key: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ForecastWorksheetOut:
    """Get a forecast worksheet for the authenticated rep."""
    _require_flag()
    return get_forecast(user.sub, period_key)


# ── OPP-006: Pipeline report endpoints ───────────────────────────────────────
# NOTE: declared BEFORE /{opp_id} to prevent "reports" captured as opp_id

@router.get("/reports/pipeline", response_model=PipelineReportOut)
async def get_pipeline_report(
    from_ts: Optional[int] = Query(None),
    to_ts: Optional[int] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> PipelineReportOut:
    """Per-rep pipeline funnel report."""
    _require_flag()
    return pipeline_report(ctx["user_sub"], from_ts, to_ts)


@router_admin.get("/reports/pipeline", response_model=PipelineReportOut)
async def get_admin_pipeline_report(
    from_ts: Optional[int] = Query(None),
    to_ts: Optional[int] = Query(None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> PipelineReportOut:
    """Admin cross-user pipeline funnel report."""
    _require_flag()
    return pipeline_report_all(user.sub, from_ts, to_ts)


# ── OPP-002: Opportunity CRUD endpoints ───────────────────────────────────────

@router.post("/opportunities", response_model=OpportunityOut, status_code=201)
async def create_opp(
    body: OpportunityCreateIn,
    ctx: dict = Depends(require_ui_session),
    request=None,
) -> OpportunityOut:
    _require_flag()
    return create_opportunity(ctx["user_sub"], body, request)


@router.get("/opportunities", response_model=Dict)
async def list_opps(
    stage: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_flag()
    items, next_cursor = list_opportunities(ctx["user_sub"], stage, cursor, limit)
    return {"items": [i.model_dump() for i in items], "next_cursor": next_cursor}


@router.get("/opportunities/{opp_id}", response_model=OpportunityOut)
async def read_opp(
    opp_id: str,
    include_contacts: bool = Query(default=False),
    ctx: dict = Depends(require_ui_session),
) -> OpportunityOut:
    _require_flag()
    opp = get_opportunity(ctx["user_sub"], opp_id)
    if include_contacts:
        opp.contact_roles = list_contact_roles(ctx["user_sub"], opp_id)
    return opp


@router.patch("/opportunities/{opp_id}", response_model=OpportunityOut)
async def patch_opp(
    opp_id: str,
    body: OpportunityUpdateIn,
    ctx: dict = Depends(require_ui_session),
    request=None,
) -> OpportunityOut:
    _require_flag()
    return update_opportunity(ctx["user_sub"], opp_id, body, request)


@router.delete("/opportunities/{opp_id}", status_code=204, response_class=Response)
def delete_opp(
    opp_id: str,
    ctx: dict = Depends(require_ui_session),
):
    _require_flag()
    delete_opportunity(ctx["user_sub"], opp_id)


# ── OPP-004: Contact-role junction endpoints ──────────────────────────────────

@router.post("/opportunities/{opp_id}/contacts", response_model=OppContactRoleOut, status_code=201)
def create_contact_role(
    opp_id: str,
    body: OppContactRoleIn,
    ctx: dict = Depends(require_ui_session),
) -> OppContactRoleOut:
    _require_flag()
    return add_contact_role(ctx["user_sub"], opp_id, body)


@router.get("/opportunities/{opp_id}/contacts", response_model=List[OppContactRoleOut])
def get_contact_roles(
    opp_id: str,
    ctx: dict = Depends(require_ui_session),
) -> List[OppContactRoleOut]:
    _require_flag()
    return list_contact_roles(ctx["user_sub"], opp_id)


@router.delete("/opportunities/{opp_id}/contacts/{contact_ref}", status_code=204, response_class=Response)
def delete_contact_role(
    opp_id: str,
    contact_ref: str,
    ctx: dict = Depends(require_ui_session),
):
    _require_flag()
    remove_contact_role(ctx["user_sub"], opp_id, contact_ref)


# ── OPP-005: Admin quota endpoints (on admin router) ─────────────────────────

@router_admin.post("/quotas", response_model=SalesQuotaOut, status_code=201)
async def create_quota(
    body: SalesQuotaIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> SalesQuotaOut:
    _require_flag()
    return set_quota(user.sub, body)


@router_admin.get("/quotas/{user_sub}", response_model=SalesQuotaListOut)
async def list_user_quotas(
    user_sub: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> SalesQuotaListOut:
    _require_flag()
    limit = min(limit, 200)
    items, next_cursor = list_quotas_for_user(user_sub, cursor, limit)
    return SalesQuotaListOut(items=items, next_cursor=next_cursor)
