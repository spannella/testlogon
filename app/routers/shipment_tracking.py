"""ECOM D4 - shipment tracking router.

  GET  /ui/orders/tracking/{ship_group_id}          -> buyer tracking view
  GET  /ui/shipping/tracking/{tracking_number}/poll -> poller stub (seam)
  POST /ui/shipping/tracking/webhook                -> ingestion webhook (seam)
  POST /ui/admin/shipment-tracking/{sg}/simulate    -> DEMO progression driver

The webhook + poller are the real-feed drop-in seam (a USPS/UPS/FedEx/DHL or
EasyPost/Shippo/AfterShip feed drives them later); the simulate endpoint is the
demo driver so the buyer pushes are demonstrable without carrier creds.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Query
from pydantic import BaseModel

from app.core.settings import S
from app.services.sessions import require_ui_session
from app.services import shipment_tracking as st

router = APIRouter(tags=["shipment-tracking"])


class TrackingEventOut(BaseModel):
    ts: int = 0
    status: str = ""
    location: str = ""
    description: str = ""
    source: str = ""


class TrackingOut(BaseModel):
    ship_group_id: str
    order_id: str = ""
    carrier: str = ""
    tracking_number: str = ""
    tracking_url: str = ""
    status: str = ""
    events: List[TrackingEventOut] = []
    created_at: int = 0
    updated_at: int = 0


def _to_out(pub: Dict[str, Any]) -> TrackingOut:
    return TrackingOut(
        ship_group_id=str(pub.get("ship_group_id") or ""),
        order_id=str(pub.get("order_id") or ""),
        carrier=str(pub.get("carrier") or ""),
        tracking_number=str(pub.get("tracking_number") or ""),
        tracking_url=str(pub.get("tracking_url") or ""),
        status=str(pub.get("status") or ""),
        events=[TrackingEventOut(
            ts=int(e.get("ts", 0) or 0), status=str(e.get("status") or ""),
            location=str(e.get("location") or ""), description=str(e.get("description") or ""),
            source=str(e.get("source") or ""),
        ) for e in pub.get("events", [])],
        created_at=int(pub.get("created_at", 0) or 0),
        updated_at=int(pub.get("updated_at", 0) or 0),
    )


@router.get("/ui/orders/tracking/{ship_group_id}", response_model=TrackingOut)
async def buyer_tracking_view(ship_group_id: str,
                              ctx: Dict[str, str] = Depends(require_ui_session)) -> TrackingOut:
    """Buyer tracking view - only the buyer on the shipment can see it."""
    rec = st.get_tracking(ship_group_id)
    if not rec or str(rec.get("buyer_id")) != str(ctx["user_sub"]):
        raise HTTPException(404, {"code": "tracking_not_found"})
    return _to_out(st.to_public(rec))


@router.get("/ui/shipping/tracking/{tracking_number}/poll")
async def poll_view(tracking_number: str,
                    ctx: Dict[str, str] = Depends(require_ui_session)) -> Dict[str, Any]:
    """Poller seam stub (query-by-tracking#). Scoped to the buyer or an admin."""
    rec = st.get_by_tracking_number(tracking_number)
    if rec and str(rec.get("buyer_id")) != str(ctx["user_sub"]) and ctx.get("role") not in ("admin", "root"):
        raise HTTPException(404, {"code": "tracking_not_found"})
    return st.poll_tracking(tracking_number)


class WebhookIn(BaseModel):
    tracking_number: Optional[str] = None
    ship_group_id: Optional[str] = None
    status: str
    location: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None


@router.post("/ui/shipping/tracking/webhook")
async def tracking_webhook(payload: WebhookIn,
                           x_webhook_secret: Optional[str] = Header(default=None, alias="X-Webhook-Secret")) -> Dict[str, Any]:
    """Ingestion SEAM: a carrier/aggregator POSTs a status update here. When a
    shared secret is configured it is enforced; otherwise the seam is open (dev)."""
    secret = getattr(S, "shipment_webhook_secret", "") or ""
    if secret and str(x_webhook_secret or "") != secret:
        raise HTTPException(401, {"code": "invalid_webhook_secret"})
    res = st.ingest_webhook(payload.model_dump())
    if not res.get("ok"):
        code = 404 if res.get("reason") == "tracking_not_found" else 400
        raise HTTPException(code, res)
    return res


@router.post("/ui/admin/shipment-tracking/{ship_group_id}/simulate", response_model=TrackingOut)
async def simulate(ship_group_id: str,
                   to: Optional[str] = Query(default=None),
                   ctx: Dict[str, str] = Depends(require_ui_session)) -> TrackingOut:
    """DEMO driver (admin): advance one step, or to an explicit `to` status."""
    if ctx.get("role") not in ("admin", "root"):
        raise HTTPException(403, {"code": "admin_required"})
    if to:
        rec = st.advance(ship_group_id=ship_group_id, status=to, source="simulate")
    else:
        rec = st.simulate_step(ship_group_id)
    if not rec:
        raise HTTPException(404, {"code": "tracking_not_found"})
    return _to_out(st.to_public(rec))
