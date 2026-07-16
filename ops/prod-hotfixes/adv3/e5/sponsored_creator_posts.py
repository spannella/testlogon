"""Sponsored-as-creator posts (ADV2-E4 / F4).

An ADVERTISER drafts a post (body/media) and PROPOSES it to a target CREATOR.
The creator must APPROVE before it publishes. On approval the post is published
**authored by the creator** (author_id = creator, in the creator's voice) and
carries a DISTINCT ``paid_partnership`` / ``promoted_by_advertiser`` flag plus a
``sponsor_account_id`` -- deliberately NOT the standalone ``is_sponsored``
ad-unit flag. Consequences of the distinct flag (LOCKED E4 design):
  * the post BEHAVES LIKE A NORMAL CREATOR POST -- tippable, likeable,
    commentable, shows the normal engagement bar, NO forced "Sponsored" label
    (D3). A viewer tip credits the CREATOR (never blocked).
  * ``paid_partnership`` drives advertiser BILLING + attribution + analytics
    ONLY, never to strip the post UI.

BILLING (Rail B, engagement ad-money-path): the advertiser is billed PER
ENGAGEMENT (impression + click) via the existing ad ledger (``ad_billing``
funds-guarded, idempotent) with ``content_owner_sub = creator`` so the creator
earns the placement share (~70/30) through ``_split_revenue``. No new escrow;
the advertiser needs a FUNDED ad account.

Storage reuses the ``sponsorship_deals`` DDB table with a DISTINCT key space
(``SPCP#{proposal_id}``) + isolated GSI partitions (``SPCP_CREATOR#`` review
queue, ``SPCP_ADV#`` advertiser outbox) so proposals never mix with the ADS-013
brand-deal inbox.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

PROPOSAL_STATUSES = ["draft_proposed", "approved", "rejected"]
SURFACE = "sponsored_creator_post"
_ATTRIBUTION_TTL_SECONDS = 604800  # 7d, matches serve_ad AdClicks TTL


class SponsoredPostError(Exception):
    def __init__(self, status_code: int, detail: Any) -> None:
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def _pk(proposal_id: str) -> str:
    return "SPCP#%s" % proposal_id


def _meta_sk() -> str:
    return "META"


def get_proposal(proposal_id: str) -> Optional[Dict[str, Any]]:
    resp = T.sponsorship_deals.get_item(Key={"pk": _pk(proposal_id), "sk": _meta_sk()})
    return resp.get("Item")


def _notify(user_sub: str, *, event: str, title: str, details: Dict[str, Any]) -> None:
    if not user_sub:
        return
    try:
        from app.services.alerts import write_alert
        write_alert(user_sub, event=event, outcome="success", title=title, details=details)
    except Exception:
        pass


def _creator_accepts_ads(creator_sub: str) -> bool:
    """ADV2-405 eligibility: a creator may opt out of advertiser proposals.
    Default = accepts (allow_ads absent/True). Only an explicit False blocks."""
    try:
        prof = T.profile.get_item(Key={"user_sub": creator_sub}).get("Item") or {}
    except Exception:
        return True
    val = prof.get("allow_ads")
    if val is None:
        return True
    return bool(val)


def create_proposal(
    *,
    advertiser_sub: str,
    advertiser_account_id: str,
    creator_sub: str,
    body: str = "",
    body_format: str = "plain",
    image_urls: Optional[List[str]] = None,
    video_id: Optional[str] = None,
    campaign_id: str = "",
    creative_id: str = "",
    sponsor_account_id: str = "",
    sponsor_label: str = "",
    disclosure: str = "",
) -> Dict[str, Any]:
    """ADV2-401: advertiser drafts a proposal to a creator (does NOT publish)."""
    if not creator_sub:
        raise SponsoredPostError(400, "creator_sub is required")
    if creator_sub == advertiser_sub:
        raise SponsoredPostError(400, "Cannot propose a sponsored post to yourself")
    if not (body or "").strip() and not (image_urls or []) and not video_id:
        raise SponsoredPostError(400, "Proposal must include body text and/or media")
    if not _creator_accepts_ads(creator_sub):
        raise SponsoredPostError(403, "This creator does not accept advertiser proposals")

    sponsor_account_id = sponsor_account_id or advertiser_account_id
    proposal_id = "spcp_%s" % uuid.uuid4().hex[:12]
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(proposal_id), "sk": _meta_sk(),
        "Entity": "SponsoredPostProposal",
        "proposal_id": proposal_id,
        "advertiser_sub": advertiser_sub,
        "advertiser_account_id": advertiser_account_id,
        "sponsor_account_id": sponsor_account_id,
        "creator_sub": creator_sub,
        "body": body or "",
        "body_format": body_format if body_format in ("plain", "markdown", "rich") else "plain",
        "image_urls": list(image_urls or []),
        "video_id": video_id,
        "campaign_id": campaign_id or "",
        "creative_id": creative_id or "",
        "sponsor_label": sponsor_label or "",
        "disclosure": disclosure or "",
        "status": "draft_proposed",
        "published_post_id": None,
        "created_at": ts, "updated_at": ts,
        "GSI1PK": "SPCP_ADV#%s" % advertiser_sub, "GSI1SK": ts,
        "GSI2PK": "SPCP_CREATOR#%s" % creator_sub, "GSI2SK": ts,
    }
    T.sponsorship_deals.put_item(Item=item)
    _notify(creator_sub, event="sponsored_post.proposed",
            title="A brand wants to sponsor a post",
            details={"proposal_id": proposal_id, "advertiser_sub": advertiser_sub})
    return item


def list_pending_for_creator(creator_sub: str) -> List[Dict[str, Any]]:
    """ADV2-403: the targeted creator's review queue (pending proposals only)."""
    resp = T.sponsorship_deals.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq("SPCP_CREATOR#%s" % creator_sub),
        ScanIndexForward=False,
    )
    return [i for i in resp.get("Items", []) if i.get("status") == "draft_proposed"]


def list_for_advertiser(advertiser_sub: str) -> List[Dict[str, Any]]:
    resp = T.sponsorship_deals.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("SPCP_ADV#%s" % advertiser_sub),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def _persist_post(
    *,
    author_id: str,
    body_plain: str = "",
    body_format: str = "plain",
    image_urls: Optional[List[str]] = None,
    video_id: Optional[str] = None,
    visibility: str = "followers",
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Reusable publish tail extracted from ``newsfeed.create_post`` for an
    author that may DIFFER from the API caller (ADV2-402). Build item ->
    ddb_put -> profile post_count -> feed ref -> fan-out. ``extra_fields`` merges
    additive columns (paid_partnership linkage). Deliberately does NOT set
    ``is_sponsored`` -- the caller passes the DISTINCT paid_partnership flag."""
    from app.routers.newsfeed import (
        pk_post, sk_post, new_id, now_iso, ddb_put_item,
        _write_feed_ref_for_published_post,
    )
    post_id = new_id("post")
    created_at = now_iso()
    body_plain = (body_plain or "").strip()
    fmt = body_format if body_format in ("plain", "markdown", "rich") else "plain"
    vis = visibility if visibility in ("followers", "public") else "followers"
    post_item: Dict[str, Any] = {
        "pk": pk_post(post_id), "sk": sk_post(), "Entity": "Post",
        "post_id": post_id, "user_id": author_id,
        "created_at": created_at, "published_at": created_at,
        "status": "published", "publish_at": None,
        "GSI2PK": "POST_AUTHOR#%s" % author_id,
        "GSI2SK": "%s#POST#%s" % (created_at, post_id),
        "body": body_plain, "body_plain": body_plain,
        "body_markdown": None, "body_markdown_html": None, "body_rich": None,
        "body_format": fmt, "body_version": 1,
        "image_urls": list(image_urls or []), "image_variants": [],
        "video_id": video_id, "visibility": vis,
        "locked": False, "lock_type": None, "unlock_price_cents": None,
        "like_count": 0, "comment_count": 0, "file_attachments": [],
        "tags": [], "allow_ads_near": True,
        "body_plain_lc": body_plain.lower(),
    }
    if extra_fields:
        post_item.update(extra_fields)
    ddb_put_item(post_item)
    try:
        T.profile.update_item(
            Key={"user_sub": author_id},
            UpdateExpression="ADD post_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except Exception:
        pass
    _write_feed_ref_for_published_post(user_id=author_id, post_id=post_id, created_at=created_at)
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers
        fan_out_post_to_followers(author_id=author_id, post_id=post_id, created_at=created_at)
    except Exception:
        pass
    return post_item


def approve_and_publish(*, proposal_id: str, creator_sub: str) -> Dict[str, Any]:
    """ADV2-402: ONLY the targeted creator may approve -> publish a post
    authored-by-creator carrying the DISTINCT paid_partnership flag (not
    is_sponsored)."""
    proposal = get_proposal(proposal_id)
    if not proposal:
        raise SponsoredPostError(404, "Proposal not found")
    if str(proposal.get("creator_sub", "")) != creator_sub:
        raise SponsoredPostError(403, "Only the targeted creator can approve this proposal")
    if proposal.get("status") != "draft_proposed":
        raise SponsoredPostError(409, "Proposal is not pending (status=%s)" % proposal.get("status"))

    # ADV3-10 (E3): a sponsored-as-creator post publishes to the PUBLIC feed
    # authored as a trusted creator -- it previously bypassed the ad-review
    # pipeline entirely (only the creator's tap gated it) and shipped an
    # OPTIONAL, advertiser-supplied disclosure. Close both, BEFORE claiming the
    # proposal (so a block never strands it in "approved" without a post):
    #   1. run the automated policy pass on the post body -> HARD violation 422s;
    #   2. if a creative_id is linked, it MUST be admin-approved (never publish
    #      an unreviewed creative under a creator's name);
    #   3. enforce a NON-EMPTY platform-standard disclosure/label server-side.
    _policy_meta: Dict[str, Any] = {}
    from app.core.settings import S as _S
    if getattr(_S, "ad_policy_screening_enabled", True):
        try:
            from app.services.ad_policy import screen_text_blob
            _pr = screen_text_blob(proposal.get("body") or "")
            _policy_meta = _pr.to_dict()
            _hard = _pr.hard_violation
        except Exception:
            _hard = False
        if _hard:
            raise SponsoredPostError(
                422, {"code": "policy_violation",
                       "message": "Post content violates ad policy and cannot be published.",
                       "policy": _policy_meta})

    linked_creative_id = str(proposal.get("creative_id") or "")
    if linked_creative_id:
        try:
            from app.services.ad_creatives import get_creative_by_id
            _cr = get_creative_by_id(linked_creative_id)
        except Exception:
            _cr = None
        if not _cr or str(_cr.get("status")) != "approved":
            raise SponsoredPostError(
                409, {"code": "creative_not_approved",
                       "message": "Linked creative must be admin-approved before publishing."})

    # Server-forced disclosure: never allow an empty/optional label.
    _default_label = getattr(_S, "ad_default_disclosure_label", "Paid partnership")
    _sponsor_label = str(proposal.get("sponsor_label") or "").strip() or _default_label
    _disclosure = str(proposal.get("disclosure") or "").strip() or _default_label

    try:
        T.sponsorship_deals.update_item(
            Key={"pk": _pk(proposal_id), "sk": _meta_sk()},
            UpdateExpression="SET #s = :approved, updated_at = :ts",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":approved": "approved", ":pending": "draft_proposed", ":ts": now_ts()},
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
            raise SponsoredPostError(409, "Proposal already resolved")
        raise
    extra = {
        "paid_partnership": True,
        "promoted_by_advertiser": True,
        "sponsor_account_id": proposal.get("sponsor_account_id") or "",
        "account_id": proposal.get("sponsor_account_id") or "",
        "campaign_id": proposal.get("campaign_id") or "",
        "creative_id": proposal.get("creative_id") or "",
        "content_owner_id": creator_sub,
        "sponsor_label": _sponsor_label,
        "paid_partnership_disclosure": _disclosure,
        "sponsor_proposal_id": proposal_id,
        "advertiser_sub": proposal.get("advertiser_sub") or "",
    }
    post = _persist_post(
        author_id=creator_sub,
        body_plain=proposal.get("body") or "",
        body_format=proposal.get("body_format") or "plain",
        image_urls=proposal.get("image_urls") or [],
        video_id=proposal.get("video_id"),
        visibility="public",
        extra_fields=extra,
    )
    post_id = post["post_id"]
    T.sponsorship_deals.update_item(
        Key={"pk": _pk(proposal_id), "sk": _meta_sk()},
        UpdateExpression="SET published_post_id = :p, updated_at = :ts",
        ExpressionAttributeValues={":p": post_id, ":ts": now_ts()},
    )
    _notify(proposal.get("advertiser_sub") or "", event="sponsored_post.approved",
            title="Your sponsored post was approved",
            details={"proposal_id": proposal_id, "post_id": post_id})
    return {"proposal_id": proposal_id, "status": "approved", "post_id": post_id, "post": post}


def reject_proposal(*, proposal_id: str, creator_sub: str, reason: str = "") -> Dict[str, Any]:
    proposal = get_proposal(proposal_id)
    if not proposal:
        raise SponsoredPostError(404, "Proposal not found")
    if str(proposal.get("creator_sub", "")) != creator_sub:
        raise SponsoredPostError(403, "Only the targeted creator can reject this proposal")
    if proposal.get("status") != "draft_proposed":
        raise SponsoredPostError(409, "Proposal is not pending (status=%s)" % proposal.get("status"))
    try:
        T.sponsorship_deals.update_item(
            Key={"pk": _pk(proposal_id), "sk": _meta_sk()},
            UpdateExpression="SET #s = :rejected, reject_reason = :r, updated_at = :ts",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":rejected": "rejected", ":pending": "draft_proposed", ":r": reason or "", ":ts": now_ts()},
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
            raise SponsoredPostError(409, "Proposal already resolved")
        raise
    _notify(proposal.get("advertiser_sub") or "", event="sponsored_post.rejected",
            title="Your sponsored post proposal was declined",
            details={"proposal_id": proposal_id})
    return {"proposal_id": proposal_id, "status": "rejected"}


def mint_post_ad_click(*, viewer_sub: str, post: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """ADV2-404: lazy-mint (idempotent per viewer+post) an AdClicks row so an
    impression/click on a paid_partnership post bills the advertiser via the ad
    ledger (surface=sponsored_creator_post, which track_ad_event's charge gate
    does NOT skip) and credits the creator the placement share
    (content_owner_sub=creator). Returns tracking handles, or None when not
    billable (organic post, or a self-view by the creator/advertiser)."""
    if not post or not post.get("paid_partnership"):
        return None
    author_id = str(post.get("user_id") or post.get("content_owner_id") or "")
    account_id = str(post.get("sponsor_account_id") or post.get("account_id") or "")
    campaign_id = str(post.get("campaign_id") or "")
    creative_id = str(post.get("creative_id") or "")
    advertiser_sub = str(post.get("advertiser_sub") or "")
    post_id = str(post.get("post_id") or "")
    if not (account_id and campaign_id and post_id and author_id):
        return None
    if viewer_sub == author_id or (advertiser_sub and viewer_sub == advertiser_sub):
        return None
    ad_click_id = "spcp_" + hashlib.sha1(("%s#%s" % (viewer_sub, post_id)).encode()).hexdigest()[:28]
    cpm, cpc, cpa = 500, 50, 500
    try:
        from app.services.ad_campaigns import get_campaign
        camp = get_campaign(account_id, campaign_id) or {}
        cpm = int(camp.get("bid_cpm_cents") or 500)
        cpc = int(camp.get("bid_cpc_cents") or 50)
        cpa = int(camp.get("bid_cpa_cents") or 500)
    except Exception:
        pass
    _now = now_ts()
    try:
        T.ad_clicks.put_item(
            Item={
                "ad_click_id": ad_click_id,
                "viewer_sub": viewer_sub,
                "campaign_id": campaign_id,
                "account_id": account_id,
                "creative_id": creative_id,
                "content_owner_sub": author_id,
                "surface": SURFACE,
                "slot_type": SURFACE,
                "content_id": post_id,
                "status": "served",
                "self_promo": False,
                "effective_price_cents": cpm,
                "effective_cpm_cents": cpm,
                "bid_cpc_cents": cpc,
                "bid_cpa_cents": cpa,
                "gross_bid_cpm_cents": cpm,
                "created_at": _now,
                "expires_at": _now + _ATTRIBUTION_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(ad_click_id)",
        )
    except Exception:
        pass
    base = "/ui/ads/track"
    params = (
        "creative_id=%s&campaign_id=%s&account_id=%s&surface=%s&slot_type=%s"
        "&content_id=%s&creator_id=%s&ad_click_id=%s"
        % (creative_id, campaign_id, account_id, SURFACE, SURFACE, post_id, author_id, ad_click_id)
    )
    return {
        "ad_click_id": ad_click_id,
        "campaign_id": campaign_id,
        "account_id": account_id,
        "creative_id": creative_id,
        "content_owner_id": author_id,
        "impression_url": "%s?event=impression&%s" % (base, params),
        "click_url": "%s?event=click&%s" % (base, params),
    }
