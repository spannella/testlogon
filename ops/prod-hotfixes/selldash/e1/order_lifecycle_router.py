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
    OrderListItem,
    OrderListOut,
    OrderStatusHistoryEntry,
    OrderTransitionRequest,
    OrderTransitionResult,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/orders", tags=["order-lifecycle"])


def _header_to_list_item(header: Dict[str, Any]) -> OrderListItem:
    return OrderListItem(
        order_id=str(header.get("order_id") or ""),
        user_id=str(header.get("user_id") or ""),
        status=str(header.get("status") or "pending_payment"),
        lifecycle_status=(str(header["lifecycle_status"]) if header.get("lifecycle_status") else None),
        created_at=str(header.get("created_at") or ""),
        updated_at=str(header.get("updated_at") or ""),
        source_system=str(header.get("source_system") or ""),
        correlation_id=str(header.get("correlation_id") or ""),
        amount_cents=int(header.get("amount_cents") or 0),
        currency=str(header.get("currency") or "USD"),
        line_item_count=int(header.get("line_item_count") or 0),
    )


@router.get("", response_model=OrderListOut)
async def list_orders_endpoint(
    user_id: str | None = Query(default=None, description="Admin-only cross-user filter"),
    status: str | None = Query(default=None, description="Legacy status partition filter"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> OrderListOut:
    """List orders for the caller. Admins may pass ?user_id= / ?status=."""
    _require_enabled()
    from app.services import order_store

    role = normalize_role(ctx.get("role"))
    is_admin = role in (Role.ADMIN, Role.ROOT)

    # Normal users are always scoped to their own orders; the user_id query
    # param is admin-only (a non-admin passing someone else's id is ignored).
    if is_admin:
        target_user = user_id  # may be None → status-only cross-user listing
    else:
        target_user = ctx.get("user_sub")

    if not target_user and not status:
        # No explicit scope supplied. For BOTH non-admins and admins, default to
        # the caller's own orders (the SPA Orders page lists "your orders" and
        # calls GET /ui/orders?limit=50 with no filters). Previously an admin with
        # no user_id/status got a 400 scope_required, which surfaced in the SPA as
        # a raw "Bad Request". Admins can still pass ?user_id=/?status= to widen.
        target_user = ctx.get("user_sub")

    headers, next_cursor = order_store.list_orders(
        user_id=target_user,
        status=status,
        limit=limit,
        cursor=cursor,
    )
    # ECOMX-E1: enrich each list row with its inline shipments (carrier /
    # tracking# / status) joined from the seller ship group(s) so the buyer sees
    # tracking straight on the Orders list WITHOUT opening each order or knowing
    # any ship_group_id. Scoped to the callers own ship groups (admin/root =
    # unscoped). Bounded to a page (limit<=200) and skips headers that cannot yet
    # have shipped (still created/pending) so the extra joins stay cheap.
    from app.services import order_fulfillment_bridge as _bridge
    from app.models import OrderShipmentOut

    role = normalize_role(ctx.get("role"))
    is_admin = role in (Role.ADMIN, Role.ROOT)
    _PRE_SHIP = {"", "pending_payment", "created", "cancelled"}
    items: List[OrderListItem] = []
    for h in headers:
        li = _header_to_list_item(h)
        # header already carries the stamped fulfilment aggregate when present.
        li.fulfillment_status = (str(h.get("fulfillment_status")) if h.get("fulfillment_status") else None)
        lc = str(h.get("lifecycle_status") or h.get("status") or "")
        if lc not in _PRE_SHIP:
            buyer_scope = None if is_admin else str(h.get("user_id") or ctx.get("user_sub"))
            try:
                inline = _bridge.order_shipments_inline(li.order_id, buyer_sub=buyer_scope)
                li.shipments = [OrderShipmentOut(**sh) for sh in inline.get("shipments", [])]
                if inline.get("fulfillment_status"):
                    li.fulfillment_status = inline.get("fulfillment_status")
            except Exception:
                pass
        items.append(li)
    return OrderListOut(orders=items, next_cursor=next_cursor)


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
    # ECOMX-E1: scope the inline shipments join to the buyers OWN ship groups
    # (admin/root pass None to aggregate every seller group on the order).
    role = normalize_role(ctx.get("role"))
    is_admin = role in (Role.ADMIN, Role.ROOT)
    buyer_scope = None if is_admin else ctx.get("user_sub")
    return order_lifecycle.get_order_lifecycle(order_id, include=include_set, buyer_sub=buyer_scope)


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


@router.post("/admin/reconcile-stuck")
async def reconcile_stuck_orders_endpoint(
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    """ECOMX-24: admin-triggered orphan/stuck-order self-heal sweep. Promotes a
    `created` header that already carries a captured buyer-debit txn (crash mid
    purchase) to `approved` + populates its ship groups, then reconciles any
    order whose header lags its ship groups. Idempotent; schedulable."""
    _require_enabled()
    from app.services import order_fulfillment_bridge as _bridge

    return _bridge.reconcile_stuck_orders(limit=limit)


@router.get("/{order_id}/tracking")
async def get_order_tracking_endpoint(
    order_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    """ECOMX-23: the ONE canonical buyer order-tracking read. Aggregates ALL of
    the order's seller ship-group tracking records so the buyer's tracking
    populates off the ORDER (not the never-populated txn shipping key), and the
    header, ship groups and tracking can never contradict."""
    _require_enabled()
    from app.services import order_lifecycle
    from app.services import order_fulfillment_bridge as _bridge

    header = order_lifecycle.get_order_header(order_id)
    if header is None:
        raise HTTPException(404, {"code": "order_not_found"})
    role = normalize_role(ctx.get("role"))
    is_admin = role in (Role.ADMIN, Role.ROOT)
    _require_order_owner_or_admin(header, ctx)
    buyer_scope = None if is_admin else ctx.get("user_sub")
    return _bridge.order_tracking(order_id, buyer_sub=buyer_scope)


@router.post("/{order_id}/confirm-delivery", response_model=OrderLifecycleOut)
async def confirm_delivery_endpoint(
    order_id: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> OrderLifecycleOut:
    """ECOMX-21: buyer "Confirm delivery" affordance — marks every ship group
    delivered and advances the header aggregate to completed. Owner-or-admin;
    idempotent."""
    _require_enabled()
    from app.services import order_lifecycle
    from app.services import order_fulfillment_bridge as _bridge

    header = order_lifecycle.get_order_header(order_id)
    if header is None:
        raise HTTPException(404, {"code": "order_not_found"})
    _require_order_owner_or_admin(header, ctx)
    _bridge.confirm_delivery(order_id, actor=ctx["user_sub"])
    role = normalize_role(ctx.get("role"))
    is_admin = role in (Role.ADMIN, Role.ROOT)
    buyer_scope = None if is_admin else ctx.get("user_sub")
    return order_lifecycle.get_order_lifecycle(order_id, buyer_sub=buyer_scope)


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
