"""Sponsored content & creator partnerships endpoints (ADS-013).

Brand <-> creator sponsorship deals: advertiser proposes a paid deal; creator
accepts/rejects/counters; creator submits sponsored content; advertiser completes
the deal (payment via the billing ledger). Full state machine with 409s on invalid
transitions.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    SponsorshipCancelRequest,
    SponsorshipContentSubmit,
    SponsorshipCounterRequest,
    SponsorshipDealCreate,
    SponsorshipRejectRequest,
)
from app.services.sessions import require_ui_session
from app.services.sponsorship_deals import (
    SponsorshipError,
    accept_deal,
    cancel_deal,
    complete_deal,
    counter_deal,
    create_deal,
    get_deal,
    list_deal_events,
    list_deals_by_advertiser_sub,
    list_deals_by_creator,
    reject_deal,
    submit_content,
)

sponsorship_deals_router = APIRouter(prefix="/ui/ads/sponsorships", tags=["sponsorship-deals"])


def _handle(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except SponsorshipError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


def _require_participant(deal: dict, user_sub: str) -> None:
    if user_sub not in (deal.get("advertiser_sub"), deal.get("creator_sub")):
        raise HTTPException(status_code=404, detail="Deal not found")


@sponsorship_deals_router.post("", status_code=201)
@sponsorship_deals_router.post("/", status_code=201)
async def propose_deal(body: SponsorshipDealCreate, ctx=Depends(require_ui_session)):
    return _handle(
        create_deal,
        advertiser_sub=ctx["user_sub"],
        advertiser_account_id=body.advertiser_account_id,
        creator_sub=body.creator_sub,
        content_type=body.content_type,
        brief=body.brief,
        deliverables=body.deliverables,
        compensation_cents=body.compensation_cents,
        cpm_bonus_cents=body.cpm_bonus_cents,
        deadline=body.deadline,
    )


@sponsorship_deals_router.get("")
@sponsorship_deals_router.get("/")
async def list_deals(
    status: Optional[str] = Query(default=None),
    role: Optional[str] = Query(default=None, pattern=r"^(advertiser|creator)$"),
    ctx=Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]
    if role == "advertiser":
        deals = list_deals_by_advertiser_sub(user_sub)
    elif role == "creator":
        deals = list_deals_by_creator(user_sub)
    else:
        # Default: union of deals where the user is either party.
        by_creator = list_deals_by_creator(user_sub)
        by_advertiser = list_deals_by_advertiser_sub(user_sub)
        seen = set()
        deals = []
        for d in by_creator + by_advertiser:
            if d["deal_id"] not in seen:
                seen.add(d["deal_id"])
                deals.append(d)
    if status:
        deals = [d for d in deals if d.get("status") == status]
    deals.sort(key=lambda d: int(d.get("created_at", 0)), reverse=True)
    return deals


@sponsorship_deals_router.get("/{deal_id}")
async def get_deal_endpoint(deal_id: str, ctx=Depends(require_ui_session)):
    deal = get_deal(deal_id)
    if not deal:
        raise HTTPException(status_code=404, detail="Deal not found")
    _require_participant(deal, ctx["user_sub"])
    return deal


@sponsorship_deals_router.get("/{deal_id}/history")
async def deal_history(deal_id: str, ctx=Depends(require_ui_session)):
    deal = get_deal(deal_id)
    if not deal:
        raise HTTPException(status_code=404, detail="Deal not found")
    _require_participant(deal, ctx["user_sub"])
    return list_deal_events(deal_id)


@sponsorship_deals_router.post("/{deal_id}/accept")
async def accept_deal_endpoint(deal_id: str, ctx=Depends(require_ui_session)):
    return _handle(accept_deal, deal_id=deal_id, creator_sub=ctx["user_sub"])


@sponsorship_deals_router.post("/{deal_id}/reject")
async def reject_deal_endpoint(
    deal_id: str, body: SponsorshipRejectRequest | None = None, ctx=Depends(require_ui_session)
):
    reason = body.reason if body else ""
    return _handle(reject_deal, deal_id=deal_id, creator_sub=ctx["user_sub"], reason=reason)


@sponsorship_deals_router.post("/{deal_id}/counter")
async def counter_deal_endpoint(
    deal_id: str, body: SponsorshipCounterRequest, ctx=Depends(require_ui_session)
):
    return _handle(
        counter_deal,
        deal_id=deal_id,
        creator_sub=ctx["user_sub"],
        compensation_cents=body.compensation_cents,
        note=body.note,
    )


@sponsorship_deals_router.post("/{deal_id}/submit-content")
async def submit_content_endpoint(
    deal_id: str, body: SponsorshipContentSubmit, ctx=Depends(require_ui_session)
):
    return _handle(
        submit_content, deal_id=deal_id, creator_sub=ctx["user_sub"], content_id=body.content_id
    )


@sponsorship_deals_router.post("/{deal_id}/complete")
async def complete_deal_endpoint(deal_id: str, ctx=Depends(require_ui_session)):
    return _handle(complete_deal, deal_id=deal_id, advertiser_sub=ctx["user_sub"])


@sponsorship_deals_router.post("/{deal_id}/cancel")
async def cancel_deal_endpoint(
    deal_id: str, body: SponsorshipCancelRequest, ctx=Depends(require_ui_session)
):
    return _handle(cancel_deal, deal_id=deal_id, actor_sub=ctx["user_sub"], reason=body.reason)
