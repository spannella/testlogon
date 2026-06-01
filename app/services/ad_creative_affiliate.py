"""
Ad Creative Affiliate Discounts service (ADS-015).

Links an ad creative to an affiliate tracking code (for click/conversion
attribution) and/or a promo discount code (for checkout discounts). This is a
thin *link* layer: it does NOT reinvent discounts or affiliate tracking.

- Discount validation/redemption is delegated to ``app.services.promo_codes``.
- Affiliate click/conversion attribution is delegated to
  ``app.services.affiliate_links``.

Storage: a dedicated ``ad_creative_affiliates`` table.
    pk = CREATIVE#{creative_id}
    sk = CONFIG                       -> the link config (one per creative)
    sk = CLICK#{ts}#{id}              -> a click attribution record
    sk = REDEEM#{ts}#{id}            -> a redemption attribution record

Ownership: the advertiser who owns the ad account that owns the creative may
attach/edit/remove the discount. Verified via the creative -> account -> owner
chain.

MONEY = int cents.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_accounts, ad_creatives, affiliate_links, promo_codes

logger = logging.getLogger(__name__)

_SOURCE = "ad_creative"


# ─── Key helpers ──────────────────────────────────────────────────

def _pk(creative_id: str) -> str:
    return f"CREATIVE#{creative_id}"


def _owner_scope(owner_sub: str) -> str:
    return f"OWNER#{owner_sub}"


# ─── Ownership resolution ─────────────────────────────────────────

def _resolve_creative(campaign_id: str, creative_id: str) -> Optional[Dict[str, Any]]:
    """Look up a creative, preferring the (campaign, creative) key, falling
    back to the by-id GSI when campaign is unknown/empty."""
    if campaign_id:
        cr = ad_creatives.get_creative(campaign_id, creative_id)
        if cr:
            return cr
    return ad_creatives.get_creative_by_id(creative_id)


def _owner_of_creative(creative: Dict[str, Any]) -> Optional[str]:
    """Return the advertiser owner_sub for the account that owns the creative."""
    account_id = creative.get("account_id")
    if not account_id:
        return None
    acct = ad_accounts.get_ad_account(account_id)
    if not acct:
        return None
    return acct.get("owner_sub")


# ─── Code-ownership validation (reuse promo_codes / affiliate_links) ───

def validate_codes(
    *,
    affiliate_code: Optional[str],
    promo_code: Optional[str],
    advertiser_id: str,
) -> Optional[Tuple[int, str]]:
    """Validate that the affiliate/promo codes exist and belong to the
    advertiser. Returns ``None`` on success or ``(status_code, message)`` on
    failure."""
    if affiliate_code:
        link = affiliate_links.get_link_by_code(affiliate_code)
        if not link:
            return 400, "Affiliate code not found"
        if link.get("affiliate_user_id") != advertiser_id:
            return 403, "Affiliate code does not belong to this account"

    if promo_code:
        promo = promo_codes.get_promo_code_by_string(promo_code)
        if not promo:
            return 400, "Promo code not found"
        if promo.get("creator_user_id") != advertiser_id:
            return 403, "Promo code does not belong to this account"
        ts = now_ts()
        exp = int(promo.get("expires_at") or 0)
        if exp > 0 and exp < ts:
            return 400, "Promo code has expired"
        if not promo.get("active", True):
            return 400, "Promo code is not active"

    return None


# ─── Config CRUD ──────────────────────────────────────────────────

def _config_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "creative_id": item.get("creative_id", ""),
        "campaign_id": item.get("campaign_id", ""),
        "owner_sub": item.get("owner_sub", ""),
        "affiliate_code": item.get("affiliate_code"),
        "promo_code": item.get("promo_code"),
        "promo_value_display": item.get("promo_value_display"),
        "click_through_url": item.get("click_through_url"),
        "click_count": int(item.get("click_count") or 0),
        "redemption_count": int(item.get("redemption_count") or 0),
        "created_at": int(item.get("created_at") or 0),
        "updated_at": int(item.get("updated_at") or 0),
    }


def get_config(creative_id: str) -> Optional[Dict[str, Any]]:
    resp = T.ad_creative_affiliates.get_item(Key={"pk": _pk(creative_id), "sk": "CONFIG"})
    item = resp.get("Item")
    return _config_out(item) if item else None


def list_configs(owner_sub: str) -> List[Dict[str, Any]]:
    resp = T.ad_creative_affiliates.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("owner_scope").eq(_owner_scope(owner_sub)),
        ScanIndexForward=False,
    )
    return [_config_out(i) for i in resp.get("Items", []) if i.get("sk") == "CONFIG"]


def attach_discount(
    *,
    creative_id: str,
    campaign_id: str,
    advertiser_id: str,
    affiliate_code: Optional[str],
    promo_code: Optional[str],
    promo_value_display: Optional[str],
    click_through_url: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
    """Attach (or replace) an affiliate/promo discount on a creative.

    Returns ``(config_out, None)`` on success or ``(None, (status, message))``.
    """
    creative = _resolve_creative(campaign_id, creative_id)
    if not creative:
        return None, (404, "Ad creative not found")

    owner = _owner_of_creative(creative)
    if owner is None:
        return None, (404, "Ad creative not found")
    if owner != advertiser_id:
        return None, (403, "You do not own this creative")

    err = validate_codes(
        affiliate_code=affiliate_code,
        promo_code=promo_code,
        advertiser_id=advertiser_id,
    )
    if err:
        return None, err

    resolved_campaign = creative.get("campaign_id") or campaign_id
    existing = T.ad_creative_affiliates.get_item(
        Key={"pk": _pk(creative_id), "sk": "CONFIG"}
    ).get("Item")
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(creative_id),
        "sk": "CONFIG",
        "creative_id": creative_id,
        "campaign_id": resolved_campaign,
        "owner_sub": advertiser_id,
        "owner_scope": _owner_scope(advertiser_id),
        "affiliate_code": (affiliate_code.upper().strip() if affiliate_code else None),
        "promo_code": (promo_code.upper().strip() if promo_code else None),
        "promo_value_display": promo_value_display,
        "click_through_url": click_through_url or creative.get("cta_url") or "/",
        "click_count": int(existing.get("click_count") or 0) if existing else 0,
        "redemption_count": int(existing.get("redemption_count") or 0) if existing else 0,
        "created_at": int(existing.get("created_at") or ts) if existing else ts,
        "updated_at": ts,
    }
    T.ad_creative_affiliates.put_item(Item=item)
    logger.info(
        "ad_affiliate_attached creative_id=%s affiliate_code=%s promo_code=%s owner=%s",
        creative_id, item["affiliate_code"], item["promo_code"], advertiser_id,
    )
    return _config_out(item), None


def update_discount(
    *,
    creative_id: str,
    advertiser_id: str,
    affiliate_code: Optional[str],
    promo_code: Optional[str],
    promo_value_display: Optional[str],
    click_through_url: Optional[str],
    clear_affiliate_code: bool,
    clear_promo_code: bool,
) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
    """Patch mutable fields on an attached discount."""
    resp = T.ad_creative_affiliates.get_item(Key={"pk": _pk(creative_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return None, (404, "No affiliate discount attached to this creative")
    if item.get("owner_sub") != advertiser_id:
        return None, (403, "You do not own this creative")

    new_affiliate = item.get("affiliate_code")
    new_promo = item.get("promo_code")
    if clear_affiliate_code:
        new_affiliate = None
    elif affiliate_code is not None:
        new_affiliate = affiliate_code.upper().strip() or None
    if clear_promo_code:
        new_promo = None
    elif promo_code is not None:
        new_promo = promo_code.upper().strip() or None

    err = validate_codes(
        affiliate_code=new_affiliate,
        promo_code=new_promo,
        advertiser_id=advertiser_id,
    )
    if err:
        return None, err

    item["affiliate_code"] = new_affiliate
    item["promo_code"] = new_promo
    if promo_value_display is not None:
        item["promo_value_display"] = promo_value_display
    if click_through_url is not None:
        item["click_through_url"] = click_through_url
    item["updated_at"] = now_ts()
    T.ad_creative_affiliates.put_item(Item=item)
    return _config_out(item), None


def remove_discount(
    *, creative_id: str, advertiser_id: str
) -> Optional[Tuple[int, str]]:
    """Remove an attached discount config. Returns ``None`` on success."""
    resp = T.ad_creative_affiliates.get_item(Key={"pk": _pk(creative_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return 404, "No affiliate discount attached to this creative"
    if item.get("owner_sub") != advertiser_id:
        return 403, "You do not own this creative"
    T.ad_creative_affiliates.delete_item(Key={"pk": _pk(creative_id), "sk": "CONFIG"})
    logger.info("ad_affiliate_removed creative_id=%s owner=%s", creative_id, advertiser_id)
    return None


# ─── Click handling + attribution ─────────────────────────────────

def _increment_config(creative_id: str, field: str) -> None:
    try:
        T.ad_creative_affiliates.update_item(
            Key={"pk": _pk(creative_id), "sk": "CONFIG"},
            UpdateExpression=f"SET {field} = if_not_exists({field}, :z) + :one, updated_at = :ts",
            ExpressionAttributeValues={":one": 1, ":z": 0, ":ts": now_ts()},
        )
    except Exception:
        logger.warning("ad_affiliate_increment_failed creative_id=%s field=%s", creative_id, field)


def handle_click(
    *,
    creative_id: str,
    user_id: str,
    ip_address: str,
    user_agent: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
    """Process an ad-creative click: record click attribution, record an
    affiliate click (reuse affiliate_links), build a redirect URL with the
    ``?ref=`` tracking param, and report the promo code for a cookie.

    Returns ``(result_dict, None)`` or ``(None, (status, message))``.
    The affiliate-click recording is best-effort (failures don't block the
    redirect)."""
    config = get_config(creative_id)
    if not config:
        return None, (404, "Ad creative not found")

    affiliate_code = config.get("affiliate_code")
    promo_code = config.get("promo_code")
    redirect_url = config.get("click_through_url") or "/"

    if S.ad_creative_affiliate_enabled and affiliate_code:
        # Reuse affiliate_links click tracking for attribution.
        try:
            link = affiliate_links.get_link_by_code(affiliate_code)
            if link:
                affiliate_links.record_click(
                    link_id=link["link_id"],
                    tracking_code=affiliate_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    referrer=f"{_SOURCE}:{creative_id}",
                )
        except Exception:
            logger.warning("ad_affiliate_click_record_failed creative_id=%s", creative_id)
        # Append ?ref= tracking param.
        sep = "&" if "?" in redirect_url else "?"
        redirect_url = f"{redirect_url}{sep}ref={affiliate_code}"

    # Record click attribution row on our table.
    ts = now_ts()
    click_id = f"acc_{uuid.uuid4().hex[:12]}"
    T.ad_creative_affiliates.put_item(Item={
        "pk": _pk(creative_id),
        "sk": f"CLICK#{ts}#{click_id}",
        "creative_id": creative_id,
        "click_id": click_id,
        "user_id": user_id,
        "affiliate_code": affiliate_code,
        "promo_code": promo_code,
        "created_at": ts,
    })
    _increment_config(creative_id, "click_count")

    result = {
        "redirect_url": redirect_url,
        "affiliate_code": affiliate_code,
        "promo_code": promo_code if S.ad_creative_affiliate_enabled else None,
        "promo_value_display": config.get("promo_value_display"),
    }
    logger.info(
        "ad_click_redirect creative_id=%s affiliate_code=%s promo_code=%s user_id=%s",
        creative_id, affiliate_code, promo_code, user_id,
    )
    return result, None


# ─── Redemption / checkout validation (reuse promo_codes) ──────────

def redeem(
    *,
    creative_id: str,
    user_id: str,
    checkout_type: str,
    item_price_cents: int,
    creator_user_id: str,
    order_id: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
    """Validate the creative's promo code at checkout and, when valid, record
    the redemption (reuse promo_codes) + an affiliate conversion (reuse
    affiliate_links) for closed-loop attribution."""
    config = get_config(creative_id)
    if not config:
        return None, (404, "Ad creative not found")

    promo_code = config.get("promo_code")
    affiliate_code = config.get("affiliate_code")
    if not promo_code:
        return {
            "valid": False,
            "creative_id": creative_id,
            "promo_code": None,
            "affiliate_code": affiliate_code,
            "discount_type": None,
            "discount_cents": 0,
            "final_price_cents": item_price_cents,
            "message": "No promo code attached to this creative",
        }, None

    # Reuse promo_codes validation.
    result = promo_codes.validate_promo_code(
        code=promo_code,
        user_id=user_id,
        checkout_type=checkout_type,
        item_price_cents=item_price_cents,
        creator_user_id=creator_user_id,
    )

    out = {
        "valid": bool(result.get("valid")),
        "creative_id": creative_id,
        "promo_code": promo_code,
        "affiliate_code": affiliate_code,
        "discount_type": result.get("discount_type"),
        "discount_cents": int(result.get("discount_cents") or 0),
        "final_price_cents": int(result.get("final_price_cents") or item_price_cents),
        "message": result.get("message"),
    }

    if not out["valid"]:
        return out, None

    # Record redemption via promo_codes (best-effort).
    code_id = result.get("code_id")
    if code_id:
        try:
            promo_codes.redeem_promo_code(
                code_id=code_id,
                user_id=user_id,
                original_price_cents=item_price_cents,
                final_price_cents=out["final_price_cents"],
                checkout_type=checkout_type,
                checkout_item_id=order_id or creative_id,
            )
        except Exception:
            logger.warning("ad_affiliate_redeem_failed creative_id=%s", creative_id)

    # Record affiliate conversion for ROAS-style attribution (best-effort).
    if affiliate_code:
        try:
            link = affiliate_links.get_link_by_code(affiliate_code)
            if link:
                affiliate_links.record_conversion(
                    link_id=link["link_id"],
                    order_id=order_id or f"ad_{creative_id}",
                    amount_cents=out["final_price_cents"],
                )
        except Exception:
            logger.warning("ad_affiliate_conversion_failed creative_id=%s", creative_id)

    # Record redemption attribution row on our table.
    ts = now_ts()
    redeem_id = f"acr_{uuid.uuid4().hex[:12]}"
    T.ad_creative_affiliates.put_item(Item={
        "pk": _pk(creative_id),
        "sk": f"REDEEM#{ts}#{redeem_id}",
        "creative_id": creative_id,
        "redeem_id": redeem_id,
        "user_id": user_id,
        "promo_code": promo_code,
        "affiliate_code": affiliate_code,
        "discount_cents": int(out["discount_cents"]),
        "final_price_cents": int(out["final_price_cents"]),
        "order_id": order_id or "",
        "created_at": ts,
    })
    _increment_config(creative_id, "redemption_count")
    logger.info(
        "ad_affiliate_redeemed creative_id=%s promo_code=%s user_id=%s discount_cents=%d",
        creative_id, promo_code, user_id, out["discount_cents"],
    )
    return out, None


# ─── Stats ────────────────────────────────────────────────────────

def get_stats(creative_id: str, advertiser_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
    config = get_config(creative_id)
    if not config:
        return None, (404, "No affiliate discount attached to this creative")
    if config.get("owner_sub") != advertiser_id:
        return None, (403, "You do not own this creative")

    resp = T.ad_creative_affiliates.query(
        KeyConditionExpression=Key("pk").eq(_pk(creative_id)) & Key("sk").begins_with("REDEEM#"),
    )
    redeems = resp.get("Items", [])
    total_discount = sum(int(r.get("discount_cents") or 0) for r in redeems)
    return {
        "creative_id": creative_id,
        "click_count": int(config.get("click_count") or 0),
        "redemption_count": int(config.get("redemption_count") or 0),
        "total_discount_cents": total_discount,
    }, None
