"""
Affiliate Links service (CREATOR-004).

Provides CRUD for affiliate links, click tracking, conversion recording,
and stats aggregation.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import string
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_ALPHABET = string.ascii_uppercase + string.digits


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _affiliate_gsi1pk(user_id: str) -> str:
    return f"AFFILIATE#{user_id}"


def _code_gsi2pk(code: str) -> str:
    return f"CODE#{code.upper()}"


def _product_gsi3pk(target_type: str, target_id: str) -> str:
    return f"PRODUCT#{target_type}#{target_id}"


# ---------------------------------------------------------------------------
# Tracking code generation
# ---------------------------------------------------------------------------

def generate_tracking_code(affiliate_user_id: str) -> str:
    """Generate a unique 8-char tracking code with collision detection."""
    prefix = hashlib.sha256(affiliate_user_id.encode()).hexdigest()[:3].upper()
    for _ in range(10):
        suffix = "".join(secrets.choice(_ALPHABET) for _ in range(5))
        code = prefix + suffix
        existing = get_link_by_code(code)
        if not existing:
            return code
    raise RuntimeError("Failed to generate unique tracking code after 10 attempts")


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_affiliate_link(
    *,
    creator_id: str,
    target_type: str,
    target_id: str,
    commission_percent: Optional[int] = None,
    custom_code: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Create an affiliate link. Returns (link_dict, error_string)."""
    if not S.affiliate_links_enabled:
        return None, "Affiliate links are not enabled"

    # Validate commission
    if commission_percent is not None:
        if commission_percent < 1 or commission_percent > S.affiliate_max_commission_percent:
            return None, f"Commission must be between 1 and {S.affiliate_max_commission_percent}%"

    effective_commission = commission_percent if commission_percent is not None else S.affiliate_default_commission_percent

    # Validate product exists in catalog
    product = _lookup_product(target_type, target_id)
    if not product:
        return None, f"Product not found: {target_id}"

    # Generate or validate code
    if custom_code:
        code = custom_code.upper().strip()
        if len(code) < 3 or len(code) > 20:
            return None, "Custom code must be 3-20 characters"
        existing = get_link_by_code(code)
        if existing:
            return None, f"Code '{code}' already exists"
    else:
        code = generate_tracking_code(creator_id)

    now = now_ts()
    link_id = f"afl_{uuid.uuid4().hex[:12]}"
    product_name = product.get("name") or product.get("title") or target_id
    destination_url = f"/shop/{target_id}"

    item: Dict[str, Any] = {
        "link_id": link_id,
        "affiliate_user_id": creator_id,
        "product_owner_id": product.get("owner_id", creator_id),
        "target_type": target_type,
        "target_id": target_id,
        "target_name": product_name,
        "tracking_code": code,
        "short_url": f"/r/{code}",
        "destination_url": destination_url,
        "commission_percent": effective_commission,
        "status": "active",
        "click_count": 0,
        "unique_click_count": 0,
        "conversion_count": 0,
        "revenue_cents": 0,
        "commission_earned_cents": 0,
        "created_at": now,
        "updated_at": now,
        # GSI keys
        "GSI1PK": _affiliate_gsi1pk(creator_id),
        "GSI1SK": now,
        "GSI2PK": _code_gsi2pk(code),
        "GSI2SK": link_id,
        "GSI3PK": _product_gsi3pk(target_type, target_id),
        "GSI3SK": now,
    }

    T.affiliate_links.put_item(Item=item)
    return item, None


def get_link(link_id: str) -> Optional[Dict[str, Any]]:
    """Get a link by its ID."""
    resp = T.affiliate_links.get_item(Key={"link_id": link_id})
    return resp.get("Item")


def get_link_by_code(code: str) -> Optional[Dict[str, Any]]:
    """Look up a link by tracking code via GSI."""
    resp = T.affiliate_links.query(
        IndexName="ByCode",
        KeyConditionExpression=Key("GSI2PK").eq(_code_gsi2pk(code)),
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def list_creator_links(creator_id: str) -> List[Dict[str, Any]]:
    """List all affiliate links for a creator."""
    resp = T.affiliate_links.query(
        IndexName="ByAffiliate",
        KeyConditionExpression=Key("GSI1PK").eq(_affiliate_gsi1pk(creator_id)),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def delete_link(creator_id: str, link_id: str) -> Tuple[bool, Optional[str]]:
    """Soft-delete a link (set status=revoked). Returns (success, error)."""
    link = get_link(link_id)
    if not link:
        return False, "Link not found"
    if link["affiliate_user_id"] != creator_id:
        return False, "Not authorized"

    T.affiliate_links.update_item(
        Key={"link_id": link_id},
        UpdateExpression="SET #s = :s, updated_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "revoked", ":now": now_ts()},
    )
    return True, None


# ---------------------------------------------------------------------------
# Click tracking
# ---------------------------------------------------------------------------

_BOT_INDICATORS = [
    "googlebot", "bingbot", "yandexbot", "baiduspider",
    "facebookexternalhit", "twitterbot", "linkedinbot",
    "whatsapp", "telegrambot", "discordbot", "applebot",
]


def record_click(
    *,
    link_id: str,
    tracking_code: str,
    ip_address: str,
    user_agent: str,
    referrer: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a click on an affiliate link."""
    now = now_ts()
    click_id = f"clk_{uuid.uuid4().hex[:12]}"

    # Hash IP for privacy
    raw = f"{ip_address}:{user_agent}"
    visitor_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]

    ua_lower = (user_agent or "").lower()
    is_bot = any(bot in ua_lower for bot in _BOT_INDICATORS)
    ua_category = "bot" if is_bot else _classify_ua(ua_lower)

    is_unique = _is_first_visit(link_id, visitor_hash)

    click: Dict[str, Any] = {
        "link_id": link_id,
        "click_id": click_id,
        "visitor_hash": visitor_hash,
        "clicked_at": now,
        "referrer": (referrer or "")[:500] if referrer else None,
        "user_agent_category": ua_category,
        "is_unique": is_unique,
        "converted": False,
        "GSI1PK": f"VISITOR#{visitor_hash}",
        "GSI1SK": now,
    }

    T.affiliate_clicks.put_item(Item=click)
    _increment_link_clicks(link_id, is_unique)
    return click


def _classify_ua(ua: str) -> str:
    mobile_keywords = ["mobile", "android", "iphone", "ipad"]
    return "mobile" if any(kw in ua for kw in mobile_keywords) else "desktop"


def _is_first_visit(link_id: str, visitor_hash: str) -> bool:
    """Check if this visitor has clicked this link before."""
    from boto3.dynamodb.conditions import Attr
    try:
        resp = T.affiliate_clicks.query(
            KeyConditionExpression=Key("link_id").eq(link_id),
            FilterExpression=Attr("visitor_hash").eq(visitor_hash),
            Limit=1,
            Select="COUNT",
        )
        return int(resp.get("Count", 0)) == 0
    except Exception:
        return True


def _increment_link_clicks(link_id: str, is_unique: bool) -> None:
    """Atomically increment click counters on the link."""
    update_expr = "SET click_count = if_not_exists(click_count, :zero) + :one, updated_at = :now"
    values: Dict[str, Any] = {":one": 1, ":zero": 0, ":now": now_ts()}

    if is_unique:
        update_expr += ", unique_click_count = if_not_exists(unique_click_count, :zero) + :one"

    try:
        T.affiliate_links.update_item(
            Key={"link_id": link_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=values,
        )
    except Exception:
        logger.warning("Failed to increment click counters", extra={"link_id": link_id})


# ---------------------------------------------------------------------------
# Conversion recording
# ---------------------------------------------------------------------------

def record_conversion(
    *,
    link_id: str,
    order_id: str,
    amount_cents: int,
) -> Optional[Dict[str, Any]]:
    """Record a conversion and calculate commission."""
    link = get_link(link_id)
    if not link or link.get("status") != "active":
        return None

    commission_percent = int(link.get("commission_percent", S.affiliate_default_commission_percent))
    commission_cents = amount_cents * commission_percent // 100

    now = now_ts()
    conv_id = f"conv_{uuid.uuid4().hex[:12]}"
    conv: Dict[str, Any] = {
        "link_id": link_id,
        "click_id": f"CONV#{conv_id}",
        "order_id": order_id,
        "amount_cents": amount_cents,
        "commission_cents": commission_cents,
        "commission_percent": commission_percent,
        "converted_at": now,
        "GSI1PK": f"CONV#{link_id}",
        "GSI1SK": now,
    }
    T.affiliate_clicks.put_item(Item=conv)

    # Update link stats
    try:
        T.affiliate_links.update_item(
            Key={"link_id": link_id},
            UpdateExpression=(
                "SET conversion_count = if_not_exists(conversion_count, :zero) + :one, "
                "revenue_cents = if_not_exists(revenue_cents, :zero) + :rev, "
                "commission_earned_cents = if_not_exists(commission_earned_cents, :zero) + :comm, "
                "updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":one": 1,
                ":zero": 0,
                ":rev": amount_cents,
                ":comm": commission_cents,
                ":now": now,
            },
        )
    except Exception:
        logger.warning("Failed to update link conversion stats", extra={"link_id": link_id})

    return {
        "conversion_id": conv_id,
        "link_id": link_id,
        "order_id": order_id,
        "amount_cents": amount_cents,
        "commission_cents": commission_cents,
        "commission_percent": commission_percent,
    }


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_link_stats(link_id: str) -> Optional[Dict[str, Any]]:
    """Get aggregated stats for a link."""
    link = get_link(link_id)
    if not link:
        return None

    click_count = int(link.get("click_count", 0))
    unique_clicks = int(link.get("unique_click_count", 0))
    conversions = int(link.get("conversion_count", 0))
    revenue = int(link.get("revenue_cents", 0))
    commission = int(link.get("commission_earned_cents", 0))
    conversion_rate = round((conversions / unique_clicks * 100), 2) if unique_clicks > 0 else 0.0

    return {
        "link_id": link_id,
        "click_count": click_count,
        "unique_click_count": unique_clicks,
        "conversion_count": conversions,
        "revenue_cents": revenue,
        "commission_earned_cents": commission,
        "conversion_rate_pct": conversion_rate,
    }


# ---------------------------------------------------------------------------
# Product lookup helper
# ---------------------------------------------------------------------------

def _lookup_product(target_type: str, target_id: str) -> Optional[Dict[str, Any]]:
    """Look up a product from the catalog table."""
    if target_type == "catalog_item":
        try:
            resp = T.catalog.get_item(Key={
                "PK": f"ITEM#{target_id}",
                "SK": f"ITEM#{target_id}",
            })
            item = resp.get("Item")
            if item:
                return {
                    "name": item.get("name", target_id),
                    "owner_id": item.get("creator_id", item.get("user_id", "")),
                }
        except Exception:
            pass
    # Fallback: accept any target_type and create a minimal product record
    # This supports subscription_plan, vod, post target types
    return {"name": target_id, "owner_id": ""}
