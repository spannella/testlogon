"""ORD-011 — order-lifecycle router (transitions, lifecycle read, history, cancel).

Thin HTTP layer over ``app.services.order_lifecycle``. Every handler 503s when
``S.order_lifecycle_enabled`` is off (default). Adjustment / ship-group routes
(ORD-008/009 services) are intentionally NOT mounted here — those services are
out of the lifecycle-core scope and deferred.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    OrderCancelIn,
    OrderLifecycleOut,
    OrderStatusHistoryEntry,
    OrderTransitionRequest,
    OrderTransitionResult,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/orders", tags=["order-lifecycle"])


def _require_enabled() -> None:
    if not S.order_lifecycle_enabled:
        raise HTTPException(
            status_code=503,
            detail={"code": "feature_disabled", "message": "Order lifecycle is disabled"},
        )


def _require_order_owner_or_admin(order_header: Dict[str, Any], ctx: Dict[str, Any]) -> None:
    role = normalize_role(ctx.get("role"))
    if role in (Role.ADMIN, Role.ROOT):
        return
    if order_header.get("user_id") != ctx.get("user_sub"):
        raise HTTPException(status_code=404, detail={"code": "order_not_found"})


@router.post("/{order_id}/transition", response_model=OrderTransitionResult)
async def transition_order_endpoint(
    order_id: str,
    body: OrderTransitionRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> OrderTransitionResult:
    _require_enabled()
    from app.services import order_lifecycle

    try:
        return order_lifecycle.transition_order(
            order_id,
            body.target_status.value,
            actor=user.sub,
            reason=body.reason,
            idempotency_key=body.idempotency_key,
        )
    except order_lifecycle.OrderNotFoundError:
        raise HTTPException(404, {"code": "order_not_found"})
    except order_lifecycle.OrderTransitionError as exc:
        raise HTTPException(409, {"code": "illegal_transition", "detail": str(exc)})
    except order_lifecycle.OrderConflictError as exc:
        raise HTTPException(409, {"code": "conflict", "detail": str(exc)})


@router.get("/{order_id}/lifecycle", response_model=OrderLifecycleOut)
async def get_order_lifecycle_endpoint(
    order_id: str,
    include: str = Query(default="", description="Comma-separated: history,adjustments,ship_groups"),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> OrderLifecycleOut:
    _require_enabled()
    from app.services import order_lifecycle

    header = order_lifecycle.get_order_header(order_id)
    if header is None:
        raise HTTPException(404, {"code": "order_not_found"})
    _require_order_owner_or_admin(header, ctx)
    include_set = {s.strip() for s in include.split(",") if s.strip()}
    return order_lifecycle.get_order_lifecycle(order_id, include=include_set)


@router.get("/{order_id}/history", response_model=List[OrderStatusHistoryEntry])
async def get_order_history(
    order_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> List[Dict[str, Any]]:
    _require_enabled()
    from app.services import order_lifecycle

    header = order_lifecycle.get_order_header(order_id)
    if header is None:
        raise HTTPException(404, {"code": "order_not_found"})
    _require_order_owner_or_admin(header, ctx)
    return order_lifecycle.list_status_history(order_id)


@router.post("/{order_id}/cancel", response_model=OrderLifecycleOut)
async def cancel_order_endpoint(
    order_id: str,
    body: OrderCancelIn,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> OrderLifecycleOut:
    _require_enabled()
    from app.services import order_lifecycle

    header = order_lifecycle.get_order_header(order_id)
    if header is None:
        raise HTTPException(404, {"code": "order_not_found"})

    role = normalize_role(ctx.get("role"))
    is_admin = role in (Role.ADMIN, Role.ROOT)
    if not is_admin and header.get("user_id") != ctx.get("user_sub"):
        raise HTTPException(404, {"code": "order_not_found"})

    current_status = header.get("lifecycle_status", "")
    owner_cancellable = {"created", "approved"}
    if not is_admin and current_status not in owner_cancellable:
        raise HTTPException(
            409,
            {
                "code": "cancel_not_allowed",
                "detail": f"Owners can only cancel orders in status {sorted(owner_cancellable)}",
            },
        )

    try:
        return order_lifecycle.cancel_order(
            order_id,
            reason=body.reason,
            refund=body.refund,
            actor=ctx["user_sub"],
        )
    except order_lifecycle.OrderTransitionError as exc:
        raise HTTPException(409, {"code": "illegal_transition", "detail": str(exc)})
    except order_lifecycle.OrderConflictError as exc:
        raise HTTPException(409, {"code": "conflict", "detail": str(exc)})
