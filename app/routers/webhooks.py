"""Webhook management endpoints (PLATFORM-002)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.models import (
    AdminEndpointDisableReq,
    WebhookDeliveryOut,
    WebhookEndpointCreateReq,
    WebhookEndpointOut,
    WebhookEndpointUpdateReq,
    WebhookHealthSummary,
    WebhookTestResult,
)
from app.services.webhook_service import (
    WEBHOOK_EVENT_TYPES,
    admin_disable_endpoint,
    admin_get_health_summary,
    admin_list_all_endpoints,
    admin_list_dead_letters,
    delete_endpoint,
    get_delivery_log,
    get_endpoint,
    list_endpoints,
    register_endpoint,
    rotate_secret,
    test_endpoint,
    update_endpoint,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _require_webhooks_enabled():
    if not S.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks feature is disabled")


# ─── User endpoints ─────────────────────────────────────────────────────────

@router.post("/ui/webhooks", status_code=201, response_model=WebhookEndpointOut)
async def create_webhook_endpoint(
    body: WebhookEndpointCreateReq,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    user_sub = ctx["user_sub"]
    try:
        result = register_endpoint(
            user_sub=user_sub,
            url=body.url,
            event_types=body.event_types,
            description=body.description,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OverflowError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/ui/webhooks", response_model=List[WebhookEndpointOut])
async def list_webhook_endpoints(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    return list_endpoints(ctx["user_sub"])


@router.get("/ui/webhooks/event-types")
async def list_event_types(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    return {
        "event_types": [
            {"type": k, "description": v} for k, v in WEBHOOK_EVENT_TYPES.items()
        ]
    }


@router.get("/ui/webhooks/{endpoint_id}", response_model=WebhookEndpointOut)
async def get_webhook_endpoint(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return ep


@router.patch("/ui/webhooks/{endpoint_id}", response_model=WebhookEndpointOut)
async def patch_webhook_endpoint(
    endpoint_id: str,
    body: WebhookEndpointUpdateReq,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    try:
        result = update_endpoint(
            user_sub=ctx["user_sub"],
            endpoint_id=endpoint_id,
            url=body.url,
            description=body.description,
            event_types=body.event_types,
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not result:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return result


@router.delete("/ui/webhooks/{endpoint_id}", status_code=204)
async def delete_webhook_endpoint(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    deleted = delete_endpoint(ctx["user_sub"], endpoint_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Endpoint not found")


@router.post("/ui/webhooks/{endpoint_id}/test", response_model=WebhookTestResult)
async def test_webhook(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    result = await test_endpoint(ctx["user_sub"], endpoint_id)
    if result.get("error") == "Endpoint not found":
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return result


@router.post("/ui/webhooks/{endpoint_id}/rotate-secret")
async def rotate_webhook_secret(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    new_secret = rotate_secret(ctx["user_sub"], endpoint_id)
    if not new_secret:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"secret": new_secret}


@router.get("/ui/webhooks/{endpoint_id}/deliveries")
async def list_deliveries(
    endpoint_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    # Verify endpoint belongs to user
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    deliveries, next_cursor = get_delivery_log(endpoint_id, limit=limit, cursor=cursor)
    return {
        "deliveries": deliveries,
        "cursor": next_cursor,
    }


# ─── Admin endpoints ────────────────────────────────────────────────────────

@router.get("/ui/admin/webhooks/endpoints")
async def admin_list_endpoints(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"endpoints": admin_list_all_endpoints()}


@router.get("/ui/admin/webhooks/health", response_model=WebhookHealthSummary)
async def admin_health(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return admin_get_health_summary()


@router.get("/ui/admin/webhooks/dead-letter")
async def admin_dead_letter(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"deliveries": admin_list_dead_letters()}


@router.post("/ui/admin/webhooks/endpoints/{endpoint_id}/disable")
async def admin_disable(
    endpoint_id: str,
    body: AdminEndpointDisableReq,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")

    # Find endpoint owner by scanning
    all_endpoints = admin_list_all_endpoints()
    target = None
    for ep in all_endpoints:
        if ep["endpoint_id"] == endpoint_id:
            target = ep
            break

    if not target:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    success = admin_disable_endpoint(endpoint_id, target["user_sub"], body.reason)
    if not success:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"ok": True, "endpoint_id": endpoint_id, "disabled_reason": body.reason}
