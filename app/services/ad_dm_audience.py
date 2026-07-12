"""ADV2-E5 (F6) -- advertiser direct mass-DM: audience resolution + send.

Builds the eligible audience for an advertiser's OWN mass-DM and sends it AS the
advertiser through the shared ``ad_messaging`` billing engine (PLATFORM-100%, no
content owner). It reuses the shared per-recipient delivery + hybrid funnel-stack
billing (delivered 2c / open +5c / click +10c, idempotent, funds-guarded) built
for F5 -- the ONLY F6-specific pieces are (a) the advertiser-scoped audience
resolution + D1 relationship gate and (b) sending AS the advertiser with an empty
content owner so ``_split_revenue`` books it entirely to the platform.

D1 (relationship gate, STRICTLY enforced): the audience is ONLY users who have an
EXISTING RELATIONSHIP with the advertiser account -- they FOLLOW or actively
SUBSCRIBE the advertiser -- (or explicitly opted into ad messages), MINUS anyone
with the per-user ad opt-out (``message_privacy.allow_ad_messages`` False). Never
a broad cold-DM. The relationship AND the opt-out are RE-VERIFIED at the send
moment (ADV2-606) so an unfollow/opt-out between resolve and dispatch DROPS the
destination (no charge, no send).

Subscriber enumeration (ADV2 R4): the audience is followers UNION active
SUBSCRIBERS of the advertiser (a pure-subscriber who does NOT follow is now
reached too), MINUS the per-user ad opt-outs. Followers enumerate via GSI5;
subscribers enumerate via the existing ``CREATOR#{advertiser}`` index partition
(SUB# items -- the same index ``count_active_subscribers`` reads), so NO new
GSI/backfill was required. Every candidate is RE-VERIFIED as a live relationship
(``_has_relationship`` accepts a follow OR an active subscription) and the
send-time re-gate (ADV2-606) still drops any edge/opt-out change before dispatch.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.time import now_ts
from app.services import ad_messaging as _admsg

logger = logging.getLogger(__name__)

MAX_RECIPIENTS_DEFAULT = _admsg.MAX_RECIPIENTS_DEFAULT
SEGMENT = "advertiser_audience"


class AdDmError(_admsg.AdMessagingError):
    """F6 error (shares the status_code/detail shape so the router maps it the
    same way as the F5 AdMessagingError)."""


# ── D1 relationship gate ───────────────────────────────────────────────
def _has_relationship(advertiser_sub: str, recipient_sub: str) -> bool:
    """Live relationship check: recipient FOLLOWS or actively SUBSCRIBES the
    advertiser account. Re-verified against source-of-truth (never a stale
    snapshot) so a cold / lapsed user is never eligible."""
    try:
        from app.services import social
        if social.is_following(recipient_sub, advertiser_sub):
            return True
    except Exception:
        pass
    try:
        from app.services import subscription_access
        if subscription_access.has_active_subscription(recipient_sub, advertiser_sub):
            return True
    except Exception:
        pass
    return False


def is_recipient_eligible(advertiser_sub: str, recipient_sub: str) -> bool:
    """FULL F6 send gate (D1 + opt-out), used both at resolve and, as the
    send-time re-gate (ADV2-606), immediately before each delivery: an existing
    relationship AND not opted-out. Never true for the advertiser themselves or a
    non-relationship."""
    if not recipient_sub or recipient_sub == advertiser_sub:
        return False
    if not _admsg.user_accepts_ad_messages(recipient_sub):
        return False
    return _has_relationship(advertiser_sub, recipient_sub)


# ── Audience resolution (ADV2-602) ─────────────────────────────────────
def resolve_advertiser_audience(
    advertiser_sub: str, *, max_recipients: int = MAX_RECIPIENTS_DEFAULT
) -> Dict[str, Any]:
    """Resolve the advertiser's eligible mass-DM audience: enumerable followers of
    the advertiser account, each RE-VERIFIED as a live relationship, MINUS the
    per-user ad opt-outs. A non-follower is inherently absent (never enumerated);
    an opted-out follower is excluded and reported."""
    from app.services import social

    seen: set = set()
    recipients: List[str] = []
    excluded_optout: List[str] = []
    excluded_non_relationship: List[str] = []
    capped = False
    cursor: Optional[str] = None
    pages = 0
    while True:
        pages += 1
        followers, cursor = social.get_followers(advertiser_sub, limit=100, cursor=cursor)
        for f in followers:
            sub = str(f.get("user_id") or "")
            if not sub or sub == advertiser_sub or sub in seen:
                continue
            seen.add(sub)
            # Defensive relationship re-verify (GSI5 already implies a follow, but
            # honor a since-removed edge and keep parity with the send-time gate).
            if not _has_relationship(advertiser_sub, sub):
                excluded_non_relationship.append(sub)
                continue
            if not _admsg.user_accepts_ad_messages(sub):
                excluded_optout.append(sub)
                continue
            recipients.append(sub)
            if len(recipients) >= max_recipients:
                capped = True
                break
        if capped or not cursor or pages > 200:
            break
    # ADV2 R4: subscriber enumeration -- UNION active SUBSCRIBERS of the
    # advertiser (who may NOT follow) into the audience. Reads the CREATOR#
    # index partition (no GSI needed). Each is re-verified via _has_relationship
    # (which accepts an active subscription) + opt-out filtered + deduped against
    # followers, honoring the same cap. The send-time re-gate still applies.
    subscribers_added = 0
    if not capped:
        try:
            from app.services import subscription_access as _subacc
            _sub_ids = _subacc.list_active_subscriber_ids(advertiser_sub)
        except Exception:
            _sub_ids = []
        for sub in _sub_ids:
            sub = str(sub or "")
            if not sub or sub == advertiser_sub or sub in seen:
                continue
            seen.add(sub)
            if not _has_relationship(advertiser_sub, sub):
                excluded_non_relationship.append(sub)
                continue
            if not _admsg.user_accepts_ad_messages(sub):
                excluded_optout.append(sub)
                continue
            recipients.append(sub)
            subscribers_added += 1
            if len(recipients) >= max_recipients:
                capped = True
                break
    if capped:
        logger.info("ad_dm_audience_capped advertiser=%s cap=%s", advertiser_sub, max_recipients)
    return {
        "segment": SEGMENT,
        "recipients": recipients,
        "count": len(recipients),
        "excluded_optout": excluded_optout,
        "excluded_optout_count": len(excluded_optout),
        "excluded_non_relationship": excluded_non_relationship,
        "excluded_non_relationship_count": len(excluded_non_relationship),
        "capped": capped,
        "subscriber_enumeration": "creator_index_partition",
        "subscribers_added": subscribers_added,
    }


# ── Advertiser mass-DM campaign flavor (ADV2-603/604/605/606) ──────────
def send_mass_dm(
    *,
    advertiser_sub: str,
    account_id: str,
    body: str,
    cta_url: str = "",
    image_url: str = "",
    campaign_id: str = "",
    creative_id: str = "",
    sponsor_label: str = "",
    max_recipients: int = MAX_RECIPIENTS_DEFAULT,
) -> Dict[str, Any]:
    """Compose + send an advertiser direct mass-DM AS the advertiser to the
    resolved eligible audience. Bills the hybrid stack PLATFORM-100% (empty
    content owner) and re-gates each recipient at the send moment (ADV2-606)."""
    if not (body or "").strip():
        raise AdDmError(400, "Message body is required")
    if not account_id or not campaign_id:
        raise AdDmError(400, "account_id and campaign_id are required (billing)")

    aud = resolve_advertiser_audience(advertiser_sub, max_recipients=max_recipients)

    # Synthetic "offer" so we reuse the shared _run_send / deliver_to_recipient
    # path unchanged. content_owner_sub="" + creator_sub="" => PLATFORM 100%.
    offer: Dict[str, Any] = {
        "offer_id": "f6dm_%s" % uuid.uuid4().hex[:12],
        "advertiser_sub": advertiser_sub,
        "advertiser_account_id": account_id,
        "sponsor_account_id": account_id,
        "campaign_id": campaign_id,
        "creative_id": creative_id,
        "body": body,
        "cta_url": cta_url or "",
        "image_url": image_url or "",
        "sponsor_label": sponsor_label or "",
        "segment": SEGMENT,
    }

    def _gate(recipient_sub: str) -> bool:
        return is_recipient_eligible(advertiser_sub, recipient_sub)

    send = _admsg._run_send(
        product="F6",
        offer=offer,
        creator_sub="",            # no creator -> send record creator_sub ""
        sender_sub=advertiser_sub,  # message is FROM the advertiser
        content_owner_sub="",       # no content owner -> platform 100%
        body=body,
        recipients=aud["recipients"],
        eligibility_fn=_gate,       # ADV2-606 send-time re-gate
    )

    # Stamp the advertiser GSI on the send record so list_advertiser_sends is a
    # query (not a scan). Reuses the AMSG_ADV# partition the F5 offers use;
    # callers filter by Entity/product.
    try:
        from app.core.tables import T
        T.sponsorship_deals.update_item(
            Key={"pk": _admsg._send_pk(send["send_id"]), "sk": _admsg._META},
            UpdateExpression="SET GSI1PK = :p, GSI1SK = :s",
            ExpressionAttributeValues={
                ":p": "AMSG_ADV#%s" % advertiser_sub, ":s": now_ts(),
            },
        )
    except Exception:
        pass

    send["audience"] = aud
    return send


def list_advertiser_sends(advertiser_sub: str) -> List[Dict[str, Any]]:
    """List the advertiser's F6 mass-DM sends (query on the AMSG_ADV# GSI,
    filtered to send records)."""
    from boto3.dynamodb.conditions import Key
    from app.core.tables import T
    resp = T.sponsorship_deals.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("AMSG_ADV#%s" % advertiser_sub),
        ScanIndexForward=False,
    )
    return [
        i for i in resp.get("Items", [])
        if i.get("Entity") == "AdMessageSend" and str(i.get("product") or "") == "F6"
    ]


def get_send(send_id: str) -> Optional[Dict[str, Any]]:
    return _admsg.get_send(send_id)


def cancel_send(*, send_id: str, advertiser_sub: str) -> Dict[str, Any]:
    """Best-effort cancel. F6 sends complete synchronously, so this only flips a
    still-'sending' record (or one already paused) to 'cancelled'; an already-sent
    campaign returns 409 (its deliveries + charges are final)."""
    from app.core.tables import T
    send = _admsg.get_send(send_id)
    if not send:
        raise AdDmError(404, "Send not found")
    if str(send.get("advertiser_sub") or "") != advertiser_sub:
        raise AdDmError(403, "Not authorized for this send")
    if str(send.get("status") or "") == "sent":
        raise AdDmError(409, "Campaign already sent -- deliveries are final")
    try:
        T.sponsorship_deals.update_item(
            Key={"pk": _admsg._send_pk(send_id), "sk": _admsg._META},
            UpdateExpression="SET #st = :c, updated_at = :ts",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":c": "cancelled", ":ts": now_ts()},
        )
    except Exception:
        pass
    return {"send_id": send_id, "status": "cancelled"}
