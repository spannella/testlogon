"""BCAST-010 — Broadcast Newsfeed Promotion router.

Wires the broadcast + newsfeed subsystems: a broadcaster can promote a
broadcast to their newsfeed, sync its status, unpromote it, fetch the promotion
status, and any authenticated user can discover currently-live promoted
broadcasts.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    BroadcastPromoLinkResponse,
    BroadcastPromoLiveResponse,
    BroadcastPromoDeleteResponse,
)
from app.services.sessions import require_ui_session
from app.services import broadcast_store
from app.services import broadcast_newsfeed_promo as svc

broadcast_promo_router = APIRouter(prefix="/ui/broadcast/promo", tags=["broadcast-promo"])


def _owner_id(session: dict) -> str:
    return session.get("user_sub") or session.get("sub") or ""


def _require_owned_broadcast(broadcast_id: str, session: dict):
    try:
        bsession = broadcast_store.get_session(broadcast_id)
    except Exception:
        bsession = None
    if bsession is None:
        raise HTTPException(status_code=404, detail="broadcast not found")
    if getattr(bsession, "created_by", None) != _owner_id(session):
        raise HTTPException(status_code=403, detail="not the broadcast owner")
    return bsession


@broadcast_promo_router.get("/live", response_model=BroadcastPromoLiveResponse)
def list_live(
    session: dict = Depends(require_ui_session),
):
    """List currently-live promoted broadcasts. Any authenticated user."""
    return BroadcastPromoLiveResponse(items=svc.list_live())


@broadcast_promo_router.post("/{broadcast_id}", response_model=BroadcastPromoLinkResponse)
def promote(
    broadcast_id: str,
    session: dict = Depends(require_ui_session),
):
    """Promote a broadcast to the newsfeed (idempotent). Broadcaster-only."""
    _require_owned_broadcast(broadcast_id, session)
    link = svc.promote(broadcast_id, _owner_id(session))
    return BroadcastPromoLinkResponse(link=link)


@broadcast_promo_router.get("/{broadcast_id}", response_model=BroadcastPromoLinkResponse)
def get_promotion(
    broadcast_id: str,
    session: dict = Depends(require_ui_session),
):
    """Return the promotion link row, or 404 if not promoted. Broadcaster-only."""
    _require_owned_broadcast(broadcast_id, session)
    link = svc.get_link(broadcast_id)
    if link is None or link.removed:
        raise HTTPException(status_code=404, detail="broadcast not promoted")
    return BroadcastPromoLinkResponse(link=link)


@broadcast_promo_router.post("/{broadcast_id}/sync", response_model=BroadcastPromoLinkResponse)
def sync_promotion(
    broadcast_id: str,
    session: dict = Depends(require_ui_session),
):
    """Re-sync the promoted post to the broadcast's current status. Broadcaster-only."""
    _require_owned_broadcast(broadcast_id, session)
    link = svc.sync(broadcast_id)
    if link is None:
        raise HTTPException(status_code=404, detail="broadcast not promoted")
    return BroadcastPromoLinkResponse(link=link)


@broadcast_promo_router.delete("/{broadcast_id}", response_model=BroadcastPromoDeleteResponse)
def unpromote(
    broadcast_id: str,
    session: dict = Depends(require_ui_session),
):
    """Unpromote a broadcast: remove the link + delete the post. Broadcaster-only."""
    _require_owned_broadcast(broadcast_id, session)
    svc.unpromote(broadcast_id)
    return BroadcastPromoDeleteResponse(ok=True)
