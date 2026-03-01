from __future__ import annotations

from fastapi import APIRouter, Depends

from app.services.auth import Principal, get_authenticated_principal, require_role
from app.services.metrics import COLLECTOR

router = APIRouter(prefix='/ops', tags=['ops'])


@router.get('/metrics')
def get_metrics(principal: Principal = Depends(get_authenticated_principal)) -> dict[str, object]:
    require_role(principal, {'admin'})
    return COLLECTOR.snapshot()


@router.get('/alerts')
def get_alerts(principal: Principal = Depends(get_authenticated_principal)) -> dict[str, object]:
    require_role(principal, {'admin'})
    snapshot = COLLECTOR.snapshot()
    return {'alerts': snapshot['active_alerts']}


@router.get('/dashboard-template')
def get_dashboard_template(principal: Principal = Depends(get_authenticated_principal)) -> dict[str, object]:
    require_role(principal, {'admin'})
    return COLLECTOR.dashboard_template()
