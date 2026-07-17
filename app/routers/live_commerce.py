"""Live-stream commerce router (LIVECOM L1/L2).

Host pins/unpins products to a live broadcast session (own OR affiliate-any),
viewers read the "shop this stream" list, and a seller sets the per-listing
affiliate commission. Host-only surfaces resolve the host from the broadcast
session's created_by; the seller commission set is owner-scoped.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.services.broadcast_store import get_session
from app.services import live_stream_products as lsp

router = APIRouter(prefix="/ui/live-commerce", tags=["live-commerce"])


def _require_host(session_id: str, ctx: dict):
    """Return the session; 403 unless caller is the broadcaster (or admin)."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by and ctx.get("role") not in {"admin", "root"}:
        raise HTTPException(status_code=403, detail={"code": "NOT_SESSION_HOST",
                            "message": "Only the broadcaster can manage stream products."})
    return session


class PinProductIn(BaseModel):
    product_id: str = Field(min_length=1)
    category_id: str = Field(min_length=1)


class AffiliateCommissionIn(BaseModel):
    affiliate_commission_bps: int = Field(ge=0, le=10000)


# ─── L1: pin / unpin / shop-this-stream ────────────────────────────────────────

@router.post("/sessions/{session_id}/products")
def pin_product_route(session_id: str, body: PinProductIn, ctx: dict = Depends(require_ui_session)):
    session = _require_host(session_id, ctx)
    return lsp.pin_product(
        session_id=session_id,
        host_sub=session.created_by,
        product_id=body.product_id,
        category_id=body.category_id,
    )


@router.delete("/sessions/{session_id}/products/{product_id}")
def unpin_product_route(session_id: str, product_id: str, ctx: dict = Depends(require_ui_session)):
    _require_host(session_id, ctx)
    removed = lsp.unpin_product(session_id, product_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Product not pinned to this session.")
    return {"ok": True, "session_id": session_id, "product_id": product_id}


@router.get("/sessions/{session_id}/products")
def list_stream_products_route(session_id: str, ctx: dict = Depends(require_ui_session)):
    # Any authenticated viewer can shop the stream.
    get_session(session_id)  # 404 if the session does not exist
    return {"session_id": session_id, "products": lsp.list_stream_products(session_id)}


# ─── L2: per-stream sales / commission summary (host-scoped) ────────────────────

@router.get("/sessions/{session_id}/summary")
def stream_summary_route(session_id: str, ctx: dict = Depends(require_ui_session)):
    """ECOMX-55 (E7): the broadcaster (or admin) sees what a shopping stream
    earned - GMV, host commission, seller net, platform fee, order count -
    aggregated over the session's settled order settlements."""
    _require_host(session_id, ctx)
    from app.services.live_commerce_split import session_summary
    return session_summary(session_id)


# ─── L2: seller-set per-listing affiliate commission (owner-scoped) ────────────

@router.post("/listings/{category_id}/{item_id}/affiliate-commission")
def set_affiliate_commission_route(category_id: str, item_id: str, body: AffiliateCommissionIn,
                                   ctx: dict = Depends(require_ui_session)):
    return lsp.set_affiliate_commission_bps(category_id, item_id, ctx["user_sub"],
                                            body.affiliate_commission_bps)


@router.get("/listings/{category_id}/{item_id}/affiliate-commission")
def get_affiliate_commission_route(category_id: str, item_id: str,
                                   ctx: dict = Depends(require_ui_session)):
    return {"category_id": category_id, "item_id": item_id,
            "affiliate_commission_bps": lsp.get_affiliate_commission_bps(category_id, item_id)}
