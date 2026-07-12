

# ── Ad-messaging: shared engine + F5 sponsored mass-messaging (ADV2-E5) ─────
from typing import Optional as _AMOptional
from pydantic import BaseModel as _AMBase, Field as _AMField
from app.services import ad_messaging as _admsg


class SponsoredMessageOfferIn(_AMBase):
    creator_sub: str = _AMField(..., min_length=1, max_length=128)
    body: str = _AMField(..., min_length=1, max_length=20000)
    cta_url: str = _AMField("", max_length=2000)
    image_url: str = _AMField("", max_length=2000)
    account_id: str = _AMField("", max_length=128)
    campaign_id: str = _AMField("", max_length=128)
    creative_id: str = _AMField("", max_length=128)
    sponsor_label: str = _AMField("", max_length=200)
    segment: str = _AMField("followers", max_length=32)


class SponsoredMessageApproveIn(_AMBase):
    body: str = _AMField("", max_length=20000)  # optional creator wording override (D3)


class SponsoredMessageRejectIn(_AMBase):
    reason: str = _AMField("", max_length=500)


class AdMessagePrefsIn(_AMBase):
    allow_ad_messages: bool = True


def _admsg_http(exc):
    return HTTPException(status_code=getattr(exc, "status_code", 400),
                         detail=getattr(exc, "detail", str(exc)))


@router.post("/sponsored-messages/offers", status_code=201)
async def create_sponsored_message_offer_endpoint(body: SponsoredMessageOfferIn, ctx=Depends(require_ui_session)):
    """ADV2-501: an advertiser drafts a sponsored MESSAGE and offers it to a
    creator. Does NOT send until the creator approves (D3)."""
    if body.account_id:
        _require_account_owner(body.account_id, ctx["user_sub"])
    try:
        return _admsg.create_offer(
            advertiser_sub=ctx["user_sub"], advertiser_account_id=body.account_id,
            creator_sub=body.creator_sub, body=body.body, cta_url=body.cta_url,
            image_url=body.image_url, campaign_id=body.campaign_id, creative_id=body.creative_id,
            sponsor_account_id=body.account_id, sponsor_label=body.sponsor_label, segment=body.segment,
        )
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/sponsored-messages/offers/inbox")
async def sponsored_message_inbox_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-507: the targeted creator's review queue (pending offers)."""
    return {"offers": _admsg.list_pending_for_creator(ctx["user_sub"])}


@router.get("/sponsored-messages/offers/outbox")
async def sponsored_message_outbox_endpoint(ctx=Depends(require_ui_session)):
    return {"offers": _admsg.list_for_advertiser(ctx["user_sub"])}


@router.post("/sponsored-messages/offers/{offer_id}/approve")
async def approve_sponsored_message_endpoint(offer_id: str, body: _AMOptional[SponsoredMessageApproveIn] = None, ctx=Depends(require_ui_session)):
    """ADV2-501/503: ONLY the targeted creator may approve -> the message is sent
    to the creator's audience AS the creator; advertiser billed hybrid (delivered
    2c), creator credited the 70% placement share."""
    try:
        return _admsg.approve_and_send(
            offer_id=offer_id, creator_sub=ctx["user_sub"],
            body_override=(body.body if body else None),
        )
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.post("/sponsored-messages/offers/{offer_id}/reject")
async def reject_sponsored_message_endpoint(offer_id: str, body: _AMOptional[SponsoredMessageRejectIn] = None, ctx=Depends(require_ui_session)):
    try:
        return _admsg.reject_offer(offer_id=offer_id, creator_sub=ctx["user_sub"], reason=(body.reason if body else ""))
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/sponsored-messages/sends/{send_id}")
async def sponsored_message_send_endpoint(send_id: str, ctx=Depends(require_ui_session)):
    """ADV2-509: campaign progress -- delivered/opened/clicked + spend."""
    send = _admsg.get_send(send_id)
    if not send:
        raise HTTPException(status_code=404, detail="Send not found")
    if ctx["user_sub"] not in (str(send.get("advertiser_sub") or ""), str(send.get("creator_sub") or "")):
        raise HTTPException(status_code=403, detail="Not authorized for this send")
    return send


@router.post("/messages/{ad_click_id}/open")
async def ad_message_open_endpoint(ad_click_id: str, ctx=Depends(require_ui_session)):
    """ADV2-504/605: recipient opened/read the ad message -> +open surcharge
    (once, idempotent)."""
    try:
        return _admsg.record_open(ad_click_id=ad_click_id, actor_sub=ctx["user_sub"])
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.post("/messages/{ad_click_id}/click")
async def ad_message_click_endpoint(ad_click_id: str, ctx=Depends(require_ui_session)):
    """ADV2-504/605: recipient tapped the CTA/link -> +click surcharge (once,
    idempotent)."""
    try:
        return _admsg.record_click(ad_click_id=ad_click_id, actor_sub=ctx["user_sub"])
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/messages/ad-preferences")
async def get_ad_message_prefs_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-511/601: per-user ad-messages opt-out state."""
    return {"allow_ad_messages": _admsg.user_accepts_ad_messages(ctx["user_sub"])}


@router.put("/messages/ad-preferences")
async def set_ad_message_prefs_endpoint(body: AdMessagePrefsIn, ctx=Depends(require_ui_session)):
    """ADV2-511/601: set the per-user ad-messages opt-out. A user with a
    relationship receives ad DMs UNLESS they opt out here."""
    return _admsg.set_ad_messages_optout(ctx["user_sub"], bool(body.allow_ad_messages))
