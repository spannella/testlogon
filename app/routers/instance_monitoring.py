"""Instance Monitoring & Health API router (INFRA-008).

Prefix: /ui/compute/monitoring
Owner-scoped per-instance metrics + derived health. All endpoints use
cookie-based session auth (require_ui_session). Ownership is verified by the
service layer (the metric instance must belong to the caller).
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    InstanceHealthOut,
    InstanceMetricIngestIn,
    InstanceMetricLatestOut,
    InstanceMetricPoint,
    InstanceMetricSeriesOut,
    InstanceMonitoringIngestOut,
    InstanceMonitoringSeedIn,
)
from app.services.sessions import require_ui_session
from app.services import instance_monitoring as svc

logger = logging.getLogger(__name__)

instance_monitoring_router = APIRouter(
    prefix="/ui/compute/monitoring", tags=["instance-monitoring"]
)


def _enabled_guard() -> None:
    if not S.instance_monitoring_enabled:
        raise HTTPException(status_code=400, detail="Instance monitoring is disabled")


def _point_out(p: Dict) -> InstanceMetricPoint:
    return InstanceMetricPoint(
        instance_id=p["instance_id"],
        ts=p["ts"],
        cpu_pct=p["cpu_pct"],
        mem_pct=p["mem_pct"],
        disk_pct=p["disk_pct"],
        net_in_kbps=p["net_in_kbps"],
        net_out_kbps=p["net_out_kbps"],
        status=p["status"],
    )


# ─── Ingest a metric datapoint ───────────────────────────────────
@instance_monitoring_router.post(
    "/instances/{instance_id}/metrics",
    status_code=201,
    response_model=InstanceMonitoringIngestOut,
)
async def ingest_metric(
    instance_id: str,
    body: InstanceMetricIngestIn,
    session: Dict = Depends(require_ui_session),
):
    _enabled_guard()
    user_sub = session["user_sub"]
    try:
        result = svc.ingest_datapoint(
            user_sub,
            instance_id,
            cpu_pct=body.cpu_pct,
            mem_pct=body.mem_pct,
            disk_pct=body.disk_pct,
            net_in_kbps=body.net_in_kbps,
            net_out_kbps=body.net_out_kbps,
            status=body.status,
            ts=body.ts,
        )
    except svc.InstanceNotOwned:
        raise HTTPException(status_code=404, detail="Instance not found")
    return InstanceMonitoringIngestOut(
        instance_id=instance_id,
        ts=result["ts"],
        health_status=result["health_status"],
        stored=True,
    )


# ─── Deterministic seed (tests / demos) ──────────────────────────
@instance_monitoring_router.post(
    "/instances/{instance_id}/seed",
    status_code=201,
)
async def seed_metrics_endpoint(
    instance_id: str,
    body: InstanceMonitoringSeedIn,
    session: Dict = Depends(require_ui_session),
):
    _enabled_guard()
    user_sub = session["user_sub"]
    try:
        written = svc.seed_metrics(
            user_sub,
            instance_id,
            points=body.points,
            interval_seconds=body.interval_seconds,
            base_cpu_pct=body.base_cpu_pct,
            base_mem_pct=body.base_mem_pct,
            base_disk_pct=body.base_disk_pct,
        )
    except svc.InstanceNotOwned:
        raise HTTPException(status_code=404, detail="Instance not found")
    return {"instance_id": instance_id, "written": written}


# ─── Latest datapoint ────────────────────────────────────────────
@instance_monitoring_router.get(
    "/instances/{instance_id}/metrics/latest",
    response_model=InstanceMetricLatestOut,
)
async def latest_metric(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    _enabled_guard()
    user_sub = session["user_sub"]
    try:
        point = svc.get_latest(user_sub, instance_id)
    except svc.InstanceNotOwned:
        raise HTTPException(status_code=404, detail="Instance not found")
    return InstanceMetricLatestOut(
        instance_id=instance_id,
        has_data=point is not None,
        point=_point_out(point) if point else None,
    )


# ─── Time-series ─────────────────────────────────────────────────
@instance_monitoring_router.get(
    "/instances/{instance_id}/metrics",
    response_model=InstanceMetricSeriesOut,
)
async def metric_series(
    instance_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    since: Optional[int] = Query(default=None, ge=0),
    session: Dict = Depends(require_ui_session),
):
    _enabled_guard()
    user_sub = session["user_sub"]
    try:
        points = svc.get_timeseries(user_sub, instance_id, limit=limit, since=since)
    except svc.InstanceNotOwned:
        raise HTTPException(status_code=404, detail="Instance not found")
    out = [_point_out(p) for p in points]
    return InstanceMetricSeriesOut(instance_id=instance_id, points=out, count=len(out))


# ─── Derived health ──────────────────────────────────────────────
@instance_monitoring_router.get(
    "/instances/{instance_id}/health",
    response_model=InstanceHealthOut,
)
async def instance_health(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    _enabled_guard()
    user_sub = session["user_sub"]
    try:
        summary = svc.get_health(user_sub, instance_id)
    except svc.InstanceNotOwned:
        raise HTTPException(status_code=404, detail="Instance not found")
    return InstanceHealthOut(**summary)
