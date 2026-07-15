"""Shared sponsored-ad feed injector (ADV: group + syndicate feed ads).

Extends the newsfeed sponsored-injection pattern (see
``app.routers.newsfeed._inject_sponsored_posts`` / ``_fetch_sponsored_post``)
to additional feed surfaces (group + syndicate). Each injected unit is a
STANDALONE sponsored unit (no content owner) so the money-path books
platform-100% on charge (``ad_billing._split_revenue`` with an empty
creator_id), matching the main newsfeed sponsored card.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from app.core.settings import S

logger = logging.getLogger(__name__)


def _interval_max():
    interval = int(getattr(S, "sponsored_post_interval", 5) or 5)
    max_sponsored = int(getattr(S, "sponsored_post_max_per_page", 3) or 3)
    return max(1, interval), max(1, max_sponsored)


def build_sponsored_unit(
    *,
    viewer_id: str,
    surface: str,
    content_id: str,
    position: int,
    hidden_ids: Optional[Set[str]] = None,
    exclude_campaign_ids: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Serve one STANDALONE sponsored unit for ``surface`` (platform-100%)."""
    try:
        from app.services.ad_serving import commit_ad_click, serve_ad

        ad = serve_ad(
            surface=surface,
            content_type="post",
            creator_id="platform",
            content_id=content_id,
            slot_type="sponsored_post",
            user_id=viewer_id,
            exclude_campaign_ids=exclude_campaign_ids,
            defer_ad_click=True,
        )
        if not ad.get("filled") or ad.get("is_house_ad"):
            return None

        creative_id = ad.get("creative_id", "")
        if hidden_ids and creative_id in hidden_ids:
            return None

        # ADV3-7 (C4): commit the deferred AdClicks row only for a kept unit.
        commit_ad_click(ad)

        ts = int(time.time())
        return {
            "post_id": f"sponsored_{surface}_{creative_id}_{position}",
            "is_sponsored": True,
            "sponsor_account_id": ad.get("campaign_id", ""),
            "sponsor_label": ad.get("title", "Sponsored"),
            "headline": ad.get("headline"),
            "body": ad.get("body_text", ""),
            "cta_text": ad.get("cta_text"),
            "cta_url": ad.get("cta_url"),
            "ctas": ad.get("ctas") or [],
            "image_urls": [ad["image_url"]] if ad.get("image_url") else [],
            "impression_url": ad.get("impression_url"),
            "click_url": ad.get("click_url"),
            "creative_id": creative_id,
            "campaign_id": ad.get("campaign_id"),
            "account_id": ad.get("account_id", ""),
            "ad_click_id": ad.get("ad_click_id", ""),
            "content_owner_id": ad.get("content_owner_id", ""),
            "reactions_counts": {},
            "comment_count": 0,
            "comments_enabled": False,
            "created_at": ts,
            "author_id": "",
            "like_count": 0,
            "tip_total_cents": 0,
            "liked_by_me": False,
            "my_reactions": [],
            "tags": [],
            "allow_ads_near": False,
        }
    except Exception:
        logger.debug("sponsored_feed.serve_error surface=%s", surface, exc_info=True)
        return None


def _hidden_ids(viewer_id: str) -> Set[str]:
    try:
        from app.services.ad_feedback import get_hidden_ad_ids

        return set(get_hidden_ad_ids(viewer_id) or [])
    except Exception:
        return set()


def inject_sponsored(
    items: List[Dict[str, Any]],
    viewer_id: Optional[str],
    *,
    surface: str,
    content_prefix: str,
) -> List[Dict[str, Any]]:
    """Inject canonical sponsored units into an untyped feed every N items."""
    if not items or not viewer_id:
        return items
    if not getattr(S, "sponsored_posts_enabled", False):
        return items

    interval, max_sponsored = _interval_max()
    hidden = _hidden_ids(viewer_id)

    result: List[Dict[str, Any]] = []
    count = 0
    won_campaign_ids: Set[str] = set()  # ADV3-7 (C4): per-page advertiser diversity
    for i, post in enumerate(items):
        result.append(post)
        if (i + 1) % interval == 0 and count < max_sponsored:
            if isinstance(post, dict) and not post.get("allow_ads_near", True):
                continue
            unit = build_sponsored_unit(
                viewer_id=viewer_id,
                surface=surface,
                content_id=f"{content_prefix}_slot_{i}",
                position=i,
                hidden_ids=hidden,
                exclude_campaign_ids=won_campaign_ids,
            )
            if unit:
                result.append(unit)
                count += 1
                _cid = unit.get("campaign_id")
                if _cid:
                    won_campaign_ids.add(str(_cid))
    return result


def _to_syndicate_shape(unit: Dict[str, Any], *, syndicate_id: str) -> Dict[str, Any]:
    """Map a canonical sponsored unit onto the SyndicatePostOut field set."""
    imgs = unit.get("image_urls") or []
    return {
        "post_id": unit.get("post_id", ""),
        "author_id": "",
        "author_name": unit.get("sponsor_label", "Sponsored"),
        "author_avatar": "",
        "text": unit.get("body", "") or "",
        "image_url": imgs[0] if imgs else "",
        "syndicate_id": syndicate_id,
        "visibility": "public",
        "created_at": int(unit.get("created_at", 0) or 0),
        "comment_count": 0,
        "reaction_counts": {},
        "tip_total_cents": 0,
        "is_sponsored": True,
        "sponsor_label": unit.get("sponsor_label", "Sponsored"),
        "headline": unit.get("headline"),
        "body": unit.get("body", "") or "",
        "cta_text": unit.get("cta_text"),
        "cta_url": unit.get("cta_url"),
        "ctas": unit.get("ctas") or [],
        "image_urls": imgs,
        "impression_url": unit.get("impression_url"),
        "click_url": unit.get("click_url"),
        "creative_id": unit.get("creative_id", "") or "",
        "campaign_id": unit.get("campaign_id") or "",
        "account_id": unit.get("account_id", "") or "",
        "ad_click_id": unit.get("ad_click_id", "") or "",
        "content_owner_id": unit.get("content_owner_id", "") or "",
    }


def inject_sponsored_syndicate(
    items: List[Dict[str, Any]],
    viewer_sub: Optional[str],
    *,
    syndicate_id: str,
) -> List[Dict[str, Any]]:
    """Inject SyndicatePostOut-shaped sponsored units into a syndicate feed."""
    if not items or not viewer_sub:
        return items
    if not getattr(S, "sponsored_posts_enabled", False):
        return items

    interval, max_sponsored = _interval_max()
    hidden = _hidden_ids(viewer_sub)

    result: List[Dict[str, Any]] = []
    count = 0
    won_campaign_ids: Set[str] = set()  # ADV3-7 (C4): per-page advertiser diversity
    for i, post in enumerate(items):
        result.append(post)
        if (i + 1) % interval == 0 and count < max_sponsored:
            unit = build_sponsored_unit(
                viewer_id=viewer_sub,
                surface="syndicate_feed",
                content_id=f"synd_{syndicate_id}_slot_{i}",
                position=i,
                hidden_ids=hidden,
                exclude_campaign_ids=won_campaign_ids,
            )
            if unit:
                result.append(_to_syndicate_shape(unit, syndicate_id=syndicate_id))
                count += 1
                _cid = unit.get("campaign_id")
                if _cid:
                    won_campaign_ids.add(str(_cid))
    return result
