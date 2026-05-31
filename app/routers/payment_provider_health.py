"""Payment Provider Health router (FIN-014).

Admin dashboard for payment provider health (Stripe, PayPal, CCBill).
Read endpoints require ADMIN or ROOT; configuration updates and provider
enable/disable toggles require ROOT (destructive operations).

Prefix: /ui/admin/payment-health
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root
from app.core.settings import S
from app.models import (
    PaymentHealthConfigUpdate,
    PaymentHealthErrorDrilldown,
    PaymentHealthIncident,
    PaymentHealthIncidentCreate,
    PaymentHealthProviderConfig,
    PaymentHealthProviderStatus,
    PaymentHealthTimeline,
    PaymentHealthToggleIn,
    PaymentHealthToggleOut,
    PaymentHealthUptimeReport,
)
from app.services import payment_provider_health as svc

payment_provider_health_router = APIRouter(
    prefix="/ui/admin/payment-health",
    tags=["payment-provider-health"],
)


def _check_enabled() -> None:
    if not S.payment_provider_health_enabled:
        raise HTTPException(status_code=404, detail="Payment provider health disabled")


def _require_known_provider(provider: str) -> str:
    prov = svc.normalize_provider(provider)
    if not svc.is_known_provider(prov):
        raise HTTPException(
            status_code=404,
            detail={"code": "provider_not_found", "message": "Provider not found"},
        )
    return prov


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@payment_provider_health_router.get("", response_model=list[PaymentHealthProviderStatus])
async def list_provider_status(
    hours: int = Query(default=24, ge=1, le=720),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return svc.get_all_providers_status(hours=hours)


@payment_provider_health_router.get("/incidents", response_model=list[PaymentHealthIncident])
async def list_incidents(
    provider: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    if provider is not None:
        _require_known_provider(provider)
    return svc.get_incidents(provider=provider, limit=limit)


@payment_provider_health_router.get("/{provider}", response_model=PaymentHealthProviderStatus)
async def get_provider_status(
    provider: str,
    hours: int = Query(default=24, ge=1, le=720),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.get_provider_status(prov, hours=hours)


@payment_provider_health_router.get("/{provider}/timeline", response_model=PaymentHealthTimeline)
async def get_timeline(
    provider: str,
    hours: int = Query(default=24, ge=1, le=720),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.get_health_timeline(prov, hours=hours)


@payment_provider_health_router.get("/{provider}/errors", response_model=PaymentHealthErrorDrilldown)
async def get_errors(
    provider: str,
    hours: int = Query(default=24, ge=1, le=720),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.get_error_drilldown(prov, hours=hours)


@payment_provider_health_router.get("/{provider}/uptime", response_model=PaymentHealthUptimeReport)
async def get_uptime(
    provider: str,
    days: int = Query(default=30, ge=1, le=365),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.get_uptime_report(prov, days=days)


@payment_provider_health_router.get("/{provider}/config", response_model=PaymentHealthProviderConfig)
async def get_config(
    provider: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.get_provider_config(prov)


# ---------------------------------------------------------------------------
# Config + toggle (ROOT only)
# ---------------------------------------------------------------------------

@payment_provider_health_router.patch("/{provider}/config", response_model=PaymentHealthProviderConfig)
async def update_config(
    provider: str,
    body: PaymentHealthConfigUpdate,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.update_provider_config(
        prov,
        admin_sub=user.sub,
        alert_error_rate_threshold=body.alert_error_rate_threshold,
        alert_latency_threshold_ms=body.alert_latency_threshold_ms,
        alert_email=body.alert_email,
    )


@payment_provider_health_router.post("/{provider}/toggle", response_model=PaymentHealthToggleOut)
async def toggle(
    provider: str,
    body: PaymentHealthToggleIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.toggle_provider(
        prov,
        enabled=body.enabled,
        admin_sub=user.sub,
        reason=body.reason,
    )


# ---------------------------------------------------------------------------
# Incident management (ROOT only)
# ---------------------------------------------------------------------------

@payment_provider_health_router.post("/{provider}/incidents", response_model=PaymentHealthIncident)
async def open_incident(
    provider: str,
    body: PaymentHealthIncidentCreate,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    return svc.create_incident(
        prov,
        status=body.status,
        peak_error_rate=body.peak_error_rate,
        affected_webhooks=body.affected_webhooks,
    )


@payment_provider_health_router.post(
    "/{provider}/incidents/{incident_id}/resolve", response_model=PaymentHealthIncident
)
async def resolve_incident(
    provider: str,
    incident_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    prov = _require_known_provider(provider)
    out = svc.resolve_incident(prov, incident_id)
    if out is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "incident_not_found", "message": "Incident not found"},
        )
    return out
