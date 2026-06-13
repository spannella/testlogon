"""CRM Custom Report Builder router (RPT-002, RPT-003, RPT-004, RPT-005).

Endpoints:
  POST   /ui/crm/reports
  GET    /ui/crm/reports
  GET    /ui/crm/reports/{report_id}/run  (latest cached run)
  GET    /ui/crm/reports/{report_id}
  PATCH  /ui/crm/reports/{report_id}
  DELETE /ui/crm/reports/{report_id}
  POST   /ui/crm/reports/{report_id}/run

  POST   /ui/crm/reports/{report_id}/schedules
  GET    /ui/crm/reports/{report_id}/schedules
  PATCH  /ui/crm/reports/{report_id}/schedules/{sid}
  DELETE /ui/crm/reports/{report_id}/schedules/{sid}

All endpoints return 404 when S.crm_reports_enabled is False.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/crm", tags=["crm-reports"])


def _require_flag() -> None:
    if not S.crm_reports_enabled:
        raise HTTPException(status_code=404, detail="Not found")


# ---------------------------------------------------------------------------
# Report CRUD + run
# ---------------------------------------------------------------------------

@router.post("/reports", status_code=201)
async def create_report_endpoint(
    body: Any,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.models import ReportCreateIn
    from app.services import crm_reports
    payload = ReportCreateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return crm_reports.create_report(ctx["user_sub"], payload)


@router.get("/reports")
async def list_reports_endpoint(
    cursor: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=50),
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services import crm_reports
    return crm_reports.list_reports(ctx["user_sub"], cursor=cursor, limit=limit)


@router.post("/reports/{report_id}/run", status_code=200)
async def run_report_endpoint(
    report_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services import crm_reports
    from app.services.rate_limit import _bucket_limit
    user_sub = ctx["user_sub"]
    if not _bucket_limit(user_sub, "rl#crm_report_run", S.crm_reports_run_rate_limit, S.crm_reports_run_rate_window):
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": str(S.crm_reports_run_rate_window)})
    return await asyncio.to_thread(crm_reports.run_report, report_id, user_sub)


@router.get("/reports/{report_id}")
async def get_report_endpoint(
    report_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services import crm_reports
    return crm_reports.get_report(report_id, ctx["user_sub"])


@router.patch("/reports/{report_id}")
async def update_report_endpoint(
    report_id: str,
    body: Any,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.models import ReportUpdateIn
    from app.services import crm_reports
    patch = ReportUpdateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return crm_reports.update_report(report_id, ctx["user_sub"], patch)


@router.delete("/reports/{report_id}", status_code=200)
async def delete_report_endpoint(
    report_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services import crm_reports
    crm_reports.delete_report(report_id, ctx["user_sub"])
    return {"ok": True}


# ---------------------------------------------------------------------------
# Report schedules (RPT-004)
# ---------------------------------------------------------------------------

@router.post("/reports/{report_id}/schedules", status_code=201)
async def create_schedule(
    report_id: str,
    body: Any,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.models import ReportScheduleCreateIn
    from app.services import crm_report_scheduler
    from app.services.rate_limit import _bucket_limit
    user_sub = ctx["user_sub"]
    if not _bucket_limit(user_sub, "rl#rpt_schedule_create", 10, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": "60"})
    payload = ReportScheduleCreateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return crm_report_scheduler.create_report_schedule(
        owner_sub=user_sub,
        report_id=report_id,
        cadence=payload.cadence,
        recipients=payload.recipients,
        fmt=payload.format,
    )


@router.get("/reports/{report_id}/schedules")
async def list_schedules(
    report_id: str,
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services import crm_report_scheduler
    return crm_report_scheduler.list_report_schedules(ctx["user_sub"], report_id=report_id, cursor=cursor)


@router.patch("/reports/{report_id}/schedules/{sid}")
async def update_schedule(
    report_id: str,
    sid: str,
    body: Any,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.models import ReportScheduleUpdateIn
    from app.services import crm_report_scheduler
    patch = ReportScheduleUpdateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return crm_report_scheduler.update_report_schedule(
        sid, ctx["user_sub"],
        cadence=patch.cadence,
        recipients=patch.recipients,
        fmt=patch.format,
        enabled=patch.enabled,
    )


@router.delete("/reports/{report_id}/schedules/{sid}", status_code=200)
async def delete_schedule(
    report_id: str,
    sid: str,
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services import crm_report_scheduler
    crm_report_scheduler.delete_report_schedule(sid, ctx["user_sub"])
    return {"ok": True}
