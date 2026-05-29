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
    get_event_types,
    list_endpoints,
    register_endpoint,
    rotate_secret,
    test_endpoint,
    update_endpoint,
)
from app.services.webhook_circuit_breaker import reset_circuit
from app.services.webhook_dlq import (
    acknowledge_dead_letter,
    list_endpoint_dead_letters,
    purge_dead_letters,
    replay_all_dead_letters,
    replay_dead_letter,
)
from app.services.webhook_stats import get_endpoint_stats, get_global_stats

logger = logging.getLogger(__name__)

router = APIRouter()


def _require_webhooks_enabled():
    if not S.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks feature is disabled")


# ─── User endpoints ─────────────────────────────────────────────────────────

@router.post("/ui/webhooks", status_code=201)
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
            retry_policy=body.retry_policy,
            signature_version=body.signature_version,
            circuit_failure_threshold=body.circuit_failure_threshold,
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
    types = get_event_types()
    return {
        "event_types": [
            {"type": k, "description": v} for k, v in types.items()
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


@router.patch("/ui/webhooks/{endpoint_id}")
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
            retry_policy=body.retry_policy,
            signature_version=body.signature_version,
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


# ─── v2 User endpoints (ENTERPRISE-005) ──────────────────────────────────────

@router.get("/ui/webhooks/{endpoint_id}/stats")
async def get_webhook_stats(
    endpoint_id: str,
    hours: int = Query(24, ge=1, le=168),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return get_endpoint_stats(endpoint_id, hours=hours)


@router.get("/ui/webhooks/{endpoint_id}/dead-letters")
async def list_dead_letters_for_endpoint(
    endpoint_id: str,
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"dead_letters": list_endpoint_dead_letters(endpoint_id, limit)}


@router.post("/ui/webhooks/{endpoint_id}/dead-letters/{delivery_id}/replay")
async def replay_single_dead_letter(
    endpoint_id: str,
    delivery_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    try:
        result = replay_dead_letter(delivery_id, endpoint_id, ctx["user_sub"], ctx["user_sub"])
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/ui/webhooks/{endpoint_id}/dead-letters/replay-all")
async def replay_all_dead_letters_route(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    count = replay_all_dead_letters(endpoint_id, ctx["user_sub"], ctx["user_sub"])
    return {"replayed_count": count}


@router.post("/ui/webhooks/{endpoint_id}/dead-letters/{delivery_id}/acknowledge")
async def acknowledge_dead_letter_route(
    endpoint_id: str,
    delivery_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    acknowledge_dead_letter(delivery_id, endpoint_id, ctx["user_sub"], ctx["user_sub"])
    return {"ok": True}


@router.delete("/ui/webhooks/{endpoint_id}/dead-letters", status_code=204)
async def purge_dead_letters_route(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    purge_dead_letters(endpoint_id, ctx["user_sub"], ctx["user_sub"])


@router.post("/ui/webhooks/{endpoint_id}/reset-circuit")
async def reset_circuit_breaker(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    ep = get_endpoint(ctx["user_sub"], endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    reset_circuit(endpoint_id, ctx["user_sub"])
    return {"ok": True, "circuit_state": "closed"}


# ─── v2 Admin endpoints (ENTERPRISE-005) ─────────────────────────────────────

@router.get("/ui/admin/webhooks/stats")
async def admin_global_stats(
    hours: int = Query(24, ge=1, le=168),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_global_stats(hours=hours)


@router.post("/ui/admin/webhooks/endpoints/{endpoint_id}/enable")
async def admin_enable_endpoint(
    endpoint_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_webhooks_enabled()
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")

    # Find endpoint owner
    all_endpoints = admin_list_all_endpoints()
    target = None
    for ep in all_endpoints:
        if ep["endpoint_id"] == endpoint_id:
            target = ep
            break
    if not target:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    from app.core.tables import T
    from app.core.time import now_ts
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{target['user_sub']}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression=(
            "SET enabled = :e, updated_at = :u, "
            "circuit_state = :cs, circuit_consecutive_failures = :zero, "
            "failure_count = :zero2"
        ),
        ExpressionAttributeValues={
            ":e": True,
            ":u": now_ts(),
            ":cs": "closed",
            ":zero": 0,
            ":zero2": 0,
        },
    )
    # Remove disabled_reason
    try:
        T.webhook_endpoints.update_item(
            Key={"pk": f"USER#{target['user_sub']}", "sk": f"ENDPOINT#{endpoint_id}"},
            UpdateExpression="REMOVE disabled_reason",
        )
    except Exception:
        pass
    return {"ok": True, "endpoint_id": endpoint_id}
