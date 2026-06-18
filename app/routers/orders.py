"""ORD-008/009 — order adjustments + ship groups HTTP endpoints.

All routes are under ``/ui/orders`` and gated by ``S.order_lifecycle_enabled``
(501 when off).  Auth: ``require_ui_session``.

Adjustment routes (ORD-008)
---------------------------
  POST   /ui/orders/{order_id}/adjustments                — add adjustment
  GET    /ui/orders/{order_id}/adjustments                — list + totals
  DELETE /ui/orders/{order_id}/adjustments/{adj_id}       — remove adjustment

Ship-group routes (ORD-009)
----------------------------
  POST   /ui/orders/{order_id}/ship-groups                — create ship group
  GET    /ui/orders/{order_id}/ship-groups                — list ship groups
  PATCH  /ui/orders/{order_id}/ship-groups/{sg_id}        — update ship group
  DELETE /ui/orders/{order_id}/ship-groups/{sg_id}        — delete ship group
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.core.settings import S
from app.models import (
    OrderAdjustmentAddIn,
    OrderAdjustmentListOut,
    OrderAdjustmentOut,
    ShipGroupCreateBodyIn,
    ShipGroupFullOut,
    ShipGroupListOut,
    ShipGroupUpdateIn,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/orders", tags=["orders"])


def _require_enabled() -> None:
    if not S.order_lifecycle_enabled:
        raise HTTPException(
            status_code=501,
            detail={"code": "order_lifecycle_not_enabled", "message": "Order lifecycle is not enabled"},
        )


# ── ORD-008: adjustments ──────────────────────────────────────────────────────

@router.post("/{order_id}/adjustments", response_model=OrderAdjustmentOut, status_code=201)
async def add_adjustment_endpoint(
    order_id: str,
    body: OrderAdjustmentAddIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    """Add an adjustment (discount, surcharge, tax, or shipping) to an order."""
    _require_enabled()
    from app.services import order_adjustments

    row = order_adjustments.add_adjustment(
        order_id=order_id,
        adj_type=body.adj_type,
        description=body.description,
        amount_cents=body.amount_cents,
        percentage=body.percentage,
        actor_sub=ctx.get("user_sub", "system"),
    )
    return row


@router.get("/{order_id}/adjustments", response_model=OrderAdjustmentListOut)
async def list_adjustments_endpoint(
    order_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    """List all adjustments for an order, together with computed totals."""
    _require_enabled()
    from app.services import order_adjustments

    totals = order_adjustments.compute_order_total(order_id)
    rows = order_adjustments.list_adjustments(order_id)

    adjustments = [
        OrderAdjustmentOut(
            adjustment_id=str(r.get("adjustment_id", "")),
            order_id=str(r.get("order_id", order_id)),
            adj_type=str(r.get("adj_type", "")),
            description=str(r.get("description", "")),
            amount_cents=int(r.get("amount_cents", 0)),
            percentage=float(r["percentage"]) if r.get("percentage") is not None else None,
            created_at=int(r.get("created_at", 0)),
            created_by=str(r.get("created_by", "")),
        )
        for r in rows
    ]

    return OrderAdjustmentListOut(
        order_id=order_id,
        adjustments=adjustments,
        total_adjustments_cents=totals["total_adjustments_cents"],
        base_amount_cents=totals["base_amount_cents"],
        total_cents=totals["total_cents"],
    )


@router.delete("/{order_id}/adjustments/{adj_id}", status_code=204)
async def remove_adjustment_endpoint(
    order_id: str,
    adj_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> None:
    """Remove an adjustment row.  No-op if it no longer exists."""
    _require_enabled()
    from app.services import order_adjustments

    order_adjustments.remove_adjustment(order_id, adj_id)


# ── ORD-009: ship groups ──────────────────────────────────────────────────────

def _sg_row_to_out(row: Dict[str, Any], order_id: str) -> ShipGroupFullOut:
    return ShipGroupFullOut(
        ship_group_id=str(row.get("ship_group_id", "")),
        order_id=str(row.get("order_id", order_id)),
        ship_to=dict(row.get("ship_to", {})),
        carrier=row.get("carrier"),
        tracking_number=row.get("tracking_number"),
        ship_method=str(row.get("ship_method", "standard")),
        estimated_ship_date=row.get("estimated_ship_date"),
        item_ids=list(row.get("item_ids", [])),
        status=str(row.get("status", "pending")),
        created_at=int(row.get("created_at", 0)),
        updated_at=int(row.get("updated_at", 0)),
    )


@router.post("/{order_id}/ship-groups", response_model=ShipGroupFullOut, status_code=201)
async def create_ship_group_endpoint(
    order_id: str,
    body: ShipGroupCreateBodyIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ShipGroupFullOut:
    """Create a ship group for an order."""
    _require_enabled()
    from app.services import order_ship_groups

    row = order_ship_groups.create_ship_group(
        order_id=order_id,
        ship_to=body.ship_to,
        carrier=body.carrier,
        ship_method=body.ship_method,
        item_ids=body.item_ids,
        estimated_ship_date=body.estimated_ship_date,
    )
    return _sg_row_to_out(row, order_id)


@router.get("/{order_id}/ship-groups", response_model=ShipGroupListOut)
async def list_ship_groups_endpoint(
    order_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ShipGroupListOut:
    """List all ship groups for an order."""
    _require_enabled()
    from app.services import order_ship_groups

    rows = order_ship_groups.list_ship_groups(order_id)
    return ShipGroupListOut(
        order_id=order_id,
        ship_groups=[_sg_row_to_out(r, order_id) for r in rows],
    )


@router.patch("/{order_id}/ship-groups/{sg_id}", response_model=ShipGroupFullOut)
async def update_ship_group_endpoint(
    order_id: str,
    sg_id: str,
    body: ShipGroupUpdateIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ShipGroupFullOut:
    """Update tracking number, status, carrier, or estimated_ship_date on a ship group."""
    _require_enabled()
    from app.services import order_ship_groups

    row = order_ship_groups.update_ship_group(
        order_id=order_id,
        ship_group_id=sg_id,
        tracking_number=body.tracking_number,
        status=body.status,
        carrier=body.carrier,
        estimated_ship_date=body.estimated_ship_date,
    )
    return _sg_row_to_out(row, order_id)


@router.delete("/{order_id}/ship-groups/{sg_id}", status_code=204)
async def delete_ship_group_endpoint(
    order_id: str,
    sg_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> None:
    """Delete a ship group row.  No-op if it no longer exists."""
    _require_enabled()
    from app.services import order_ship_groups

    order_ship_groups.delete_ship_group(order_id, sg_id)
