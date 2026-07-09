"""ADV2-E5 (F5 + F6 shared) -- ad-messaging billing engine + sponsored mass-messaging.

SHARED ENGINE
-------------
A sponsored/ad message is DELIVERED to a recipient, then may be OPENed and
CLICKed. The advertiser is billed a HYBRID, FUNNEL-STACKING amount per recipient:

    delivered  -> AD_MSG_DELIVERED_CENTS (default 2c)  [on send]
    open       -> AD_MSG_OPEN_CENTS      (default 5c)  [+ when the message is read]
    click      -> AD_MSG_CLICK_CENTS     (default 10c) [+ when a CTA/link is tapped]

Each event bills at most ONCE per (message, recipient) and is idempotent -- a
re-open / re-click never double-charges. The stages STACK (a clicked message =
2 + 5 + 10 = 17c). Every charge flows through ``ad_billing._process_charge`` so
it is FUNDS-GUARDED (the advertiser balance can never go negative; on
insufficient funds the send loop STOPS) and split via ``ad_billing._split_revenue``:

    F5 (creator-sent sponsored message)  content_owner = creator -> creator 70% / platform 30%
    F6 (advertiser direct mass-DM)        no content owner        -> platform 100%

The per-recipient delivery state (delivered/opened/clicked + timestamps) lives on
the minted AdClicks row (surface="ad_message"); the send record + counters live
on the ``sponsorship_deals`` table under a DISTINCT key space (``AMSG#``) so they
never mix with the ADS-013 brand deals or the ADV2-E4 SPCP proposals.

F5 -- SPONSORED MASS-MESSAGING (ADV2-501..506)
----------------------------------------------
Reuses the E4 proposal/approve pattern (``sponsored_creator_posts``): an
advertiser drafts an OFFER to a creator; ONLY the TARGETED creator may approve
(D3 -- no forced sponsorship label; wording is the creator's); on approve the
message is sent to the creator's own audience AS the creator and the advertiser
is billed the hybrid stack while the creator earns the 70% placement share on
every event (delivered/open/click).
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_billing

logger = logging.getLogger(__name__)

SURFACE = "ad_message"
TTL_SECONDS = 604800  # 7d, matches serve_ad AdClicks TTL
MAX_RECIPIENTS_DEFAULT = 500  # audience cap (DEC F5-3); larger audiences logged + capped

# Config-driven hybrid rates (cents). Locked E5 Standard rates: 2 / 5 / 10.
_DEFAULT_CENTS = {"delivered": 2, "open": 5, "click": 10}
_ENV = {
    "delivered": "AD_MSG_DELIVERED_CENTS",
    "open": "AD_MSG_OPEN_CENTS",
    "click": "AD_MSG_CLICK_CENTS",
}


def event_cents(event: str) -> int:
    """Config-driven per-event charge (cents). Reads env at call time so a live
    price change needs no redeploy; falls back to the locked Standard rate."""
    default = _DEFAULT_CENTS.get(event, 0)
    try:
        return max(0, int(os.getenv(_ENV.get(event, ""), str(default))))
    except Exception:
        return default


class AdMessagingError(Exception):
    def __init__(self, status_code: int, detail: Any) -> None:
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


# ── Key helpers ────────────────────────────────────────────────────────
def _offer_pk(offer_id: str) -> str:
    return "AMSGOFFER#%s" % offer_id


def _send_pk(send_id: str) -> str:
    return "AMSG#%s" % send_id


_META = "META"


def _click_id(send_id: str, recipient_sub: str) -> str:
    """Deterministic per-(send, recipient) ad-click id -> the delivery-state row
    is idempotent (a re-send never mints a second row / bills twice)."""
    return "amsg_" + hashlib.sha1(("%s#%s" % (send_id, recipient_sub)).encode()).hexdigest()[:28]


# ── Per-user ad-message opt-out (ADV2-511 / shared ADV2-601) ────────────
def user_accepts_ad_messages(sub: str) -> bool:
    """Honor the per-user ad-messages opt-out stored on the message_privacy
    record. Default True (a user with a relationship receives ad DMs UNLESS they
    opt out)."""
    try:
        item = T.profile.get_item(Key={"user_sub": sub}).get("Item") or {}
    except Exception:
        return True
    mp = item.get("message_privacy") or {}
    return bool(mp.get("allow_ad_messages", True))


def set_ad_messages_optout(sub: str, allow: bool) -> Dict[str, Any]:
    """Set the per-user ad-messages opt-out on the shared message_privacy map
    (coexists with require_tip_to_message / allowlist)."""
    try:
        item = T.profile.get_item(Key={"user_sub": sub}).get("Item") or {}
    except Exception:
        item = {}
    mp = dict(item.get("message_privacy") or {})
    mp["allow_ad_messages"] = bool(allow)
    T.profile.update_item(
        Key={"user_sub": sub},
        UpdateExpression="SET message_privacy = :mp",
        ExpressionAttributeValues={":mp": mp},
    )
    return {"allow_ad_messages": bool(allow)}


# ── Audience resolution (ADV2-505) ─────────────────────────────────────
def resolve_creator_audience(
    creator_sub: str, *, segment: str = "followers", max_recipients: int = MAX_RECIPIENTS_DEFAULT
) -> Dict[str, Any]:
    """Resolve the creator's own audience minus per-user ad opt-outs.

    F5's audience is the creator's EXISTING relationship graph, so D1's cold-DM
    restriction is inherently satisfied. Followers are fully enumerable via
    social.get_followers (GSI5). Pure-subscriber enumeration is a known schema
    gap (DEC-2: subscriptions has no ByCreator GSI -- get_subscribers is a
    time-series rollup, not an id list), so this path resolves FOLLOWERS
    (subscribers who also follow are included) and logs the cap; the
    subscriber-only slice is deferred to the DEC-2 GSI/snapshot decision.
    """
    from app.services import social

    seen: set = set()
    recipients: List[str] = []
    excluded_optout: List[str] = []
    capped = False
    cursor: Optional[str] = None
    pages = 0
    while True:
        pages += 1
        followers, cursor = social.get_followers(creator_sub, limit=100, cursor=cursor)
        for f in followers:
            sub = str(f.get("user_id") or "")
            if not sub or sub == creator_sub or sub in seen:
                continue
            seen.add(sub)
            if not user_accepts_ad_messages(sub):
                excluded_optout.append(sub)
                continue
            recipients.append(sub)
            if len(recipients) >= max_recipients:
                capped = True
                break
        if capped or not cursor or pages > 200:
            break
    if capped:
        logger.info(
            "ad_messaging_audience_capped creator=%s cap=%s", creator_sub, max_recipients
        )
    return {
        "segment": "followers",
        "recipients": recipients,
        "count": len(recipients),
        "excluded_optout": excluded_optout,
        "excluded_optout_count": len(excluded_optout),
        "capped": capped,
        "subscriber_enumeration": "deferred_dec2_followers_only",
    }


# ── Offer store (ADV2-501, reuses the E4 proposal/approve pattern) ──────
def get_offer(offer_id: str) -> Optional[Dict[str, Any]]:
    resp = T.sponsorship_deals.get_item(Key={"pk": _offer_pk(offer_id), "sk": _META})
    return resp.get("Item")


def _creator_accepts(creator_sub: str) -> bool:
    try:
        from app.services.sponsored_creator_posts import _creator_accepts_ads
        return bool(_creator_accepts_ads(creator_sub))
    except Exception:
        return True


def create_offer(
    *,
    advertiser_sub: str,
    advertiser_account_id: str,
    creator_sub: str,
    body: str = "",
    cta_url: str = "",
    image_url: str = "",
    campaign_id: str = "",
    creative_id: str = "",
    sponsor_account_id: str = "",
    sponsor_label: str = "",
    segment: str = "followers",
) -> Dict[str, Any]:
    """ADV2-501: advertiser drafts a sponsored-message OFFER to a creator (does
    NOT send). Approve is the ONLY path that can send (D3)."""
    if not creator_sub:
        raise AdMessagingError(400, "creator_sub is required")
    if creator_sub == advertiser_sub:
        raise AdMessagingError(400, "Cannot sponsor a message to yourself")
    if not (body or "").strip():
        raise AdMessagingError(400, "Offer must include a message body")
    if not _creator_accepts(creator_sub):
        raise AdMessagingError(403, "This creator does not accept advertiser proposals")

    sponsor_account_id = sponsor_account_id or advertiser_account_id
    offer_id = "amsg_%s" % uuid.uuid4().hex[:12]
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _offer_pk(offer_id), "sk": _META, "Entity": "AdMessageOffer",
        "offer_id": offer_id,
        "advertiser_sub": advertiser_sub,
        "advertiser_account_id": advertiser_account_id,
        "sponsor_account_id": sponsor_account_id,
        "creator_sub": creator_sub,
        "body": body or "",
        "cta_url": cta_url or "",
        "image_url": image_url or "",
        "campaign_id": campaign_id or "",
        "creative_id": creative_id or "",
        "sponsor_label": sponsor_label or "",
        "segment": segment or "followers",
        "status": "pending_creator",
        "send_id": None,
        "published": False,
        "created_at": ts, "updated_at": ts,
        "GSI1PK": "AMSG_ADV#%s" % advertiser_sub, "GSI1SK": ts,
        "GSI2PK": "AMSG_CREATOR#%s" % creator_sub, "GSI2SK": ts,
    }
    T.sponsorship_deals.put_item(Item=item)
    _notify(creator_sub, event="sponsored_message.offered",
            title="A brand wants you to send a sponsored message",
            details={"offer_id": offer_id, "advertiser_sub": advertiser_sub})
    return item


def list_pending_for_creator(creator_sub: str) -> List[Dict[str, Any]]:
    resp = T.sponsorship_deals.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq("AMSG_CREATOR#%s" % creator_sub),
        ScanIndexForward=False,
    )
    return [i for i in resp.get("Items", []) if i.get("status") == "pending_creator"]


def list_for_advertiser(advertiser_sub: str) -> List[Dict[str, Any]]:
    resp = T.sponsorship_deals.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("AMSG_ADV#%s" % advertiser_sub),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def reject_offer(*, offer_id: str, creator_sub: str, reason: str = "") -> Dict[str, Any]:
    offer = get_offer(offer_id)
    if not offer:
        raise AdMessagingError(404, "Offer not found")
    if str(offer.get("creator_sub", "")) != creator_sub:
        raise AdMessagingError(403, "Only the targeted creator can reject this offer")
    if offer.get("status") != "pending_creator":
        raise AdMessagingError(409, "Offer is not pending (status=%s)" % offer.get("status"))
    try:
        T.sponsorship_deals.update_item(
            Key={"pk": _offer_pk(offer_id), "sk": _META},
            UpdateExpression="SET #s = :rejected, reject_reason = :r, updated_at = :ts",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":rejected": "rejected", ":pending": "pending_creator",
                ":r": reason or "", ":ts": now_ts(),
            },
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in str(type(exc).__name__) or "ConditionalCheckFailed" in str(exc):
            raise AdMessagingError(409, "Offer already resolved")
        raise
    _notify(offer.get("advertiser_sub") or "", event="sponsored_message.rejected",
            title="Your sponsored-message offer was declined",
            details={"offer_id": offer_id})
    return {"offer_id": offer_id, "status": "rejected"}


def approve_and_send(
    *, offer_id: str, creator_sub: str, body_override: Optional[str] = None,
    max_recipients: int = MAX_RECIPIENTS_DEFAULT,
) -> Dict[str, Any]:
    """ADV2-501/502/503: ONLY the targeted creator may approve. On approve the
    offer is atomically claimed, the audience is resolved, and the message is
    sent to the creator's audience AS the creator with delivered billing +
    creator 70% share per event (D3 no forced label)."""
    offer = get_offer(offer_id)
    if not offer:
        raise AdMessagingError(404, "Offer not found")
    if str(offer.get("creator_sub", "")) != creator_sub:
        raise AdMessagingError(403, "Only the targeted creator can approve this offer")
    if offer.get("status") != "pending_creator":
        raise AdMessagingError(409, "Offer is not pending (status=%s)" % offer.get("status"))
    # Atomic claim so a double-approve never double-sends.
    try:
        T.sponsorship_deals.update_item(
            Key={"pk": _offer_pk(offer_id), "sk": _META},
            UpdateExpression="SET #s = :approved, updated_at = :ts",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":approved": "approved", ":pending": "pending_creator", ":ts": now_ts(),
            },
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in str(type(exc).__name__) or "ConditionalCheckFailed" in str(exc):
            raise AdMessagingError(409, "Offer already resolved")
        raise

    body = (body_override or "").strip() or (offer.get("body") or "")
    aud = resolve_creator_audience(
        creator_sub, segment=offer.get("segment") or "followers", max_recipients=max_recipients
    )
    send = _run_send(
        product="F5", offer=offer, creator_sub=creator_sub,
        sender_sub=creator_sub, content_owner_sub=creator_sub,
        body=body, recipients=aud["recipients"],
    )
    T.sponsorship_deals.update_item(
        Key={"pk": _offer_pk(offer_id), "sk": _META},
        UpdateExpression="SET send_id = :sid, published = :t, updated_at = :ts",
        ExpressionAttributeValues={":sid": send["send_id"], ":t": True, ":ts": now_ts()},
    )
    send["offer_id"] = offer_id
    send["audience"] = aud
    _notify(offer.get("advertiser_sub") or "", event="sponsored_message.sent",
            title="Your sponsored message was approved and sent",
            details={"offer_id": offer_id, "send_id": send["send_id"],
                     "delivered": send["delivered_count"]})
    return send


# ── Shared send engine (F5 today; F6 reuses _run_send/deliver/charge) ──
def get_send(send_id: str) -> Optional[Dict[str, Any]]:
    resp = T.sponsorship_deals.get_item(Key={"pk": _send_pk(send_id), "sk": _META})
    return resp.get("Item")


def _run_send(
    *, product: str, offer: Dict[str, Any], creator_sub: str, sender_sub: str,
    content_owner_sub: str, body: str, recipients: List[str],
) -> Dict[str, Any]:
    send_id = "amsgsend_%s" % uuid.uuid4().hex[:12]
    account_id = str(offer.get("sponsor_account_id") or offer.get("advertiser_account_id") or "")
    campaign_id = str(offer.get("campaign_id") or "")
    creative_id = str(offer.get("creative_id") or "")
    advertiser_sub = str(offer.get("advertiser_sub") or "")
    ts = now_ts()
    T.sponsorship_deals.put_item(Item={
        "pk": _send_pk(send_id), "sk": _META, "Entity": "AdMessageSend",
        "send_id": send_id, "offer_id": offer.get("offer_id"),
        "product": product, "creator_sub": creator_sub, "advertiser_sub": advertiser_sub,
        "account_id": account_id, "campaign_id": campaign_id, "creative_id": creative_id,
        "content_owner_sub": content_owner_sub or "",
        "recipient_count": len(recipients),
        "delivered_count": 0, "opened_count": 0, "clicked_count": 0, "spend_cents": 0,
        "status": "sending", "created_at": ts, "updated_at": ts,
    })

    results: List[Dict[str, Any]] = []
    stopped = False
    for recipient in recipients:
        r = deliver_to_recipient(
            send_id=send_id, product=product, creator_sub=content_owner_sub,
            account_id=account_id, campaign_id=campaign_id, creative_id=creative_id,
            advertiser_sub=advertiser_sub, sender_sub=sender_sub, recipient_sub=recipient,
            body=body, cta_url=offer.get("cta_url") or "", image_url=offer.get("image_url") or "",
            sponsor_label=offer.get("sponsor_label") or "",
        )
        results.append(r)
        if r.get("state") == "insufficient_funds":
            stopped = True
            break  # funds-guard: STOP sending further

    delivered = [r for r in results if r.get("state") == "sent"]
    spend = sum(int(r.get("charge_cents", 0)) for r in delivered)
    status = "paused_insufficient_funds" if stopped else "sent"
    T.sponsorship_deals.update_item(
        Key={"pk": _send_pk(send_id), "sk": _META},
        UpdateExpression="SET delivered_count = :d, spend_cents = :s, #st = :status, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":d": len(delivered), ":s": spend, ":status": status, ":ts": now_ts()},
    )
    return {
        "send_id": send_id, "product": product, "status": status,
        "recipient_count": len(recipients), "delivered_count": len(delivered),
        "spend_cents": spend, "stopped_insufficient_funds": stopped, "results": results,
    }


def deliver_to_recipient(
    *, send_id: str, product: str, creator_sub: str, account_id: str, campaign_id: str,
    creative_id: str, advertiser_sub: str, sender_sub: str, recipient_sub: str, body: str,
    cta_url: str = "", image_url: str = "", sponsor_label: str = "",
) -> Dict[str, Any]:
    """SHARED per-recipient delivery: mint the delivery-state row, charge the
    DELIVERED stage (funds-guarded), and -- only if the charge cleared -- send
    the message. ``creator_sub`` is the content owner ("" -> platform 100%, F6);
    ``sender_sub`` is who the message is FROM (creator for F5, advertiser for
    F6)."""
    ad_click_id = _click_id(send_id, recipient_sub)
    _mint_click(
        ad_click_id=ad_click_id, send_id=send_id, recipient_sub=recipient_sub,
        account_id=account_id, campaign_id=campaign_id, creative_id=creative_id,
        content_owner_sub=creator_sub, content_id=send_id,
    )
    res = charge_event(
        event="delivered", ad_click_id=ad_click_id, account_id=account_id,
        campaign_id=campaign_id, creative_id=creative_id, creator_sub=creator_sub,
        content_id=send_id,
    )
    if not res.get("ok"):
        return {"recipient_sub": recipient_sub, "ad_click_id": ad_click_id,
                "state": "insufficient_funds", "reason": res.get("reason"), "charge_cents": 0}
    conv_id, message_id = _send_message(
        sender_sub=sender_sub, recipient_sub=recipient_sub, body=body, cta_url=cta_url,
        image_url=image_url, sponsor_label=sponsor_label, ad_click_id=ad_click_id,
        account_id=account_id, campaign_id=campaign_id, send_id=send_id,
        content_owner_sub=creator_sub,
    )
    _mark_delivery(ad_click_id, conversation_id=conv_id, message_id=message_id)
    return {"recipient_sub": recipient_sub, "ad_click_id": ad_click_id,
            "conversation_id": conv_id, "message_id": message_id,
            "state": "sent", "charge_cents": int(res.get("charge_cents", 0))}


def charge_event(
    *, event: str, ad_click_id: str, account_id: str, campaign_id: str,
    creative_id: str, creator_sub: str, content_id: str,
) -> Dict[str, Any]:
    """THE billing engine: one hybrid stage (delivered/open/click), config cents,
    idempotent per (message,recipient,event) via idempotency_key
    ``{ad_click_id}#{event}``, funds-guarded + split by ad_billing._process_charge
    (creator_sub present -> 70/30; "" -> platform 100%)."""
    cents = event_cents(event)
    if cents <= 0 or not account_id or not campaign_id:
        return {"ok": False, "reason": "not_billable", "charge_cents": 0}
    return ad_billing._process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="ad_message_%s_charge" % event, charge_cents=cents,
        creator_id=creator_sub or "", reason="Ad message %s" % event,
        meta={"creative_id": creative_id, "content_id": content_id, "model": "ad_message",
              "event": event, "ad_click_id": ad_click_id},
        idempotency_key="%s#%s" % (ad_click_id, event),
    )


def record_open(*, ad_click_id: str, actor_sub: Optional[str] = None) -> Dict[str, Any]:
    """Charge the OPEN surcharge once (idempotent) when the recipient reads the
    message."""
    return _record_engagement(ad_click_id=ad_click_id, event="open", actor_sub=actor_sub)


def record_click(*, ad_click_id: str, actor_sub: Optional[str] = None) -> Dict[str, Any]:
    """Charge the CLICK surcharge once (idempotent) when the recipient taps the
    CTA/link."""
    return _record_engagement(ad_click_id=ad_click_id, event="click", actor_sub=actor_sub)


def _record_engagement(*, ad_click_id: str, event: str, actor_sub: Optional[str]) -> Dict[str, Any]:
    row = _get_click(ad_click_id)
    if not row:
        raise AdMessagingError(404, "Ad message not found")
    if actor_sub and str(row.get("viewer_sub", "")) != str(actor_sub):
        raise AdMessagingError(403, "Not the recipient of this ad message")
    res = charge_event(
        event=event, ad_click_id=ad_click_id, account_id=str(row.get("account_id") or ""),
        campaign_id=str(row.get("campaign_id") or ""), creative_id=str(row.get("creative_id") or ""),
        creator_sub=str(row.get("content_owner_sub") or ""), content_id=str(row.get("content_id") or ""),
    )
    _mark_event(ad_click_id, event)
    charged = int(res.get("charge_cents", 0) or 0)
    if res.get("ok") and charged > 0:
        _bump_send_counter(str(row.get("content_id") or ""),
                           "opened_count" if event == "open" else "clicked_count", charged)
    return {"event": event, "ad_click_id": ad_click_id, **res}


# ── AdClicks delivery-state row ────────────────────────────────────────
def _mint_click(
    *, ad_click_id: str, send_id: str, recipient_sub: str, account_id: str,
    campaign_id: str, creative_id: str, content_owner_sub: str, content_id: str,
) -> None:
    cpm, cpc, cpa = 500, 50, 500
    try:
        from app.services.ad_campaigns import get_campaign
        camp = get_campaign(account_id, campaign_id) or {}
        cpm = int(camp.get("bid_cpm_cents") or 500)
        cpc = int(camp.get("bid_cpc_cents") or 50)
        cpa = int(camp.get("bid_cpa_cents") or 500)
    except Exception:
        pass
    now = now_ts()
    try:
        T.ad_clicks.put_item(
            Item={
                "ad_click_id": ad_click_id, "viewer_sub": recipient_sub,
                "campaign_id": campaign_id, "account_id": account_id, "creative_id": creative_id,
                "content_owner_sub": content_owner_sub or "", "surface": SURFACE, "slot_type": SURFACE,
                "content_id": content_id, "send_id": send_id, "status": "delivered",
                "self_promo": False, "effective_price_cents": cpm, "effective_cpm_cents": cpm,
                "bid_cpc_cents": cpc, "bid_cpa_cents": cpa, "gross_bid_cpm_cents": cpm,
                "delivered_at": now, "opened_at": 0, "clicked_at": 0,
                "created_at": now, "expires_at": now + TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(ad_click_id)",
        )
    except Exception:
        pass  # idempotent: row already minted


def _get_click(ad_click_id: str) -> Optional[Dict[str, Any]]:
    try:
        return T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id}).get("Item")
    except Exception:
        return None


def _mark_delivery(ad_click_id: str, *, conversation_id: str, message_id: str) -> None:
    try:
        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression="SET conversation_id = :c, message_id = :m",
            ExpressionAttributeValues={":c": conversation_id, ":m": message_id},
        )
    except Exception:
        pass


def _mark_event(ad_click_id: str, event: str) -> None:
    field = "opened_at" if event == "open" else "clicked_at"
    try:
        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression="SET %s = :ts" % field,
            ExpressionAttributeValues={":ts": now_ts()},
        )
    except Exception:
        pass


def _bump_send_counter(send_id: str, field: str, spend_delta: int) -> None:
    if not send_id:
        return
    try:
        T.sponsorship_deals.update_item(
            Key={"pk": _send_pk(send_id), "sk": _META},
            UpdateExpression="ADD %s :one, spend_cents :sp SET updated_at = :ts" % field,
            ExpressionAttributeValues={":one": 1, ":sp": int(spend_delta), ":ts": now_ts()},
        )
    except Exception:
        pass


# ── Send AS the sender (creator for F5) ────────────────────────────────
def _send_message(
    *, sender_sub: str, recipient_sub: str, body: str, cta_url: str, image_url: str,
    sponsor_label: str, ad_click_id: str, account_id: str, campaign_id: str,
    send_id: str, content_owner_sub: str,
) -> Tuple[str, str]:
    """Ensure a DM (sender<->recipient) and write the ad message AS the sender,
    stamping the sponsor fields + ad_click_id onto the message item."""
    from app.routers import messaging as M

    conv_id = M._find_existing_dm(sender_sub, recipient_sub)
    ts = M.now_ts()
    if not conv_id:
        conv_id = "c_" + M.new_id()
        try:
            M.tbl_convos.put_item(
                Item={
                    "conversation_id": conv_id, "created_at": ts, "created_by": sender_sub,
                    "type": "dm", "title": "", "description": "", "icon": "", "topic": "",
                    "retention_days": 0, "participant_count": 2, "last_message_at": 0,
                    "last_message_preview": "", "routing_mode": "none", "routing_group_id": "",
                    "routing_state": "none", "active_agent_user_id": "", "active_agent_claimed_at": 0,
                    "last_failover_at": 0, "assignment_version": 0, "no_agents_notice_sent_at": 0,
                    "routing_state_group_pk": "none#", "routing_state_group_sk": conv_id,
                },
                ConditionExpression="attribute_not_exists(conversation_id)",
            )
        except Exception:
            pass
        for pid in (sender_sub, recipient_sub):
            try:
                M.tbl_parts.put_item(Item={
                    "user_id": pid, "conversation_id": conv_id, "status": "active",
                    "role": "admin" if pid == sender_sub else "member", "muted_until": 0,
                    "last_read_at": 0, "unread_count": 0, "joined_at": ts, "left_at": 0,
                    "GSI1PK": conv_id, "GSI1SK": pid,
                })
            except Exception:
                pass

    mid = "m_" + M.new_id()
    item: Dict[str, Any] = {
        "conversation_id": conv_id, "message_id": mid, "sender_id": sender_sub,
        "created_at": ts, "kind": "text", "text": body, "is_encrypted": False, "reactions": {},
        "ad_message": True, "ad_click_id": ad_click_id, "ad_account_id": account_id,
        "ad_campaign_id": campaign_id, "ad_send_id": send_id, "cta_url": cta_url or "",
        "ad_image_url": image_url or "", "sponsor_label": sponsor_label or "",
        "content_owner_sub": content_owner_sub or "",
    }
    M.tbl_msgs.put_item(Item=item)
    try:
        M.tbl_convos.update_item(
            Key={"conversation_id": conv_id},
            UpdateExpression="SET last_message_at = :ts, last_message_id = :mid, last_message_preview = :p",
            ExpressionAttributeValues={":ts": ts, ":mid": mid, ":p": (body or "")[:140]},
        )
    except Exception:
        pass
    try:
        M._sync_gallery_index_message(item)
    except Exception:
        pass
    try:
        participants = M.tbl_parts.query(
            IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conv_id)
        ).get("Items", [])
        M._send_mass_message_destination(
            conversation_id=conv_id, sender_id=sender_sub, message_id=mid, created_at=ts,
            message_item=item, participants=participants, preview_text=(body or "")[:140],
        )
    except Exception:
        pass  # realtime/receipts best-effort; money path already settled
    return conv_id, mid


def _notify(user_sub: str, *, event: str, title: str, details: Dict[str, Any]) -> None:
    if not user_sub:
        return
    try:
        from app.services.sponsored_creator_posts import _notify as _spcp_notify
        _spcp_notify(user_sub, event=event, title=title, details=details)
    except Exception:
        pass
