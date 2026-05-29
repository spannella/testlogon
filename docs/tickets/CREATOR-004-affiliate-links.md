# CREATOR-004: Affiliate Link System

**Ticket**: CREATOR-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Creators on the platform sell products via the catalog system and earn revenue through subscriptions, tips, and unlocks. However, there is no mechanism for creators to:

- Generate trackable referral links to specific products or content
- Earn commission on sales driven by their referral traffic
- Measure the performance of promotional links shared on social media, emails, or other channels
- Participate in cross-creator promotion (Creator A promotes Creator B's product for a commission)

Without an affiliate system, creators resort to off-platform link shorteners that provide no conversion attribution and no automatic commission payment.

### 1.2 Goals

1. **Trackable Link Generation**: Creators generate unique affiliate links to products, subscription plans, or content pages. Each link has a unique tracking code.
2. **Click Tracking**: Every click on an affiliate link is recorded with timestamp, referrer, user agent, and IP (hashed for privacy).
3. **Conversion Attribution**: When a tracked visitor completes a purchase (catalog order, subscription signup, VOD purchase), the conversion is attributed to the affiliate link within a configurable attribution window.
4. **Commission Calculation**: Configurable commission rates per creator, per product, or globally. Commission is a percentage of the attributed sale.
5. **Performance Dashboard**: Creators view their link performance (clicks, conversions, revenue, conversion rate) in a dedicated analytics page.

### 1.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to generate an affiliate link to a product in my catalog. | POST returns a unique short URL with tracking code embedded. |
| Creator | I want to generate an affiliate link to another creator's product (cross-promotion). | POST returns link if the product creator has affiliate partnerships enabled. |
| Creator | I want to see how many clicks my affiliate links have received. | Dashboard shows total clicks, unique clicks, and click trend chart. |
| Creator | I want to see which clicks converted to purchases. | Dashboard shows conversion count, conversion rate, and attributed revenue. |
| Creator | I want to receive commission automatically when a sale is attributed to my link. | Billing ledger shows a credit entry with reason "Affiliate commission" upon conversion. |
| Creator | I want to customize commission rates for affiliates promoting my products. | Settings page allows setting global rate and per-product overrides. |
| Admin | I want to see platform-wide affiliate activity and detect abuse. | Admin endpoint returns top affiliates, suspicious patterns, and conversion audit trail. |
| Admin | I want to configure the attribution window and default commission rate. | Platform settings control defaults that creators can override within limits. |
| Creator | I want to see daily click and conversion trends for my links. | Dashboard shows a time-series chart of daily clicks and conversions for the past 30 days. |
| Creator | I want to share an affiliate link via a QR code. | Link detail page includes a QR code image that encodes the short URL. |
| Creator | I want to bulk-create affiliate links for all products in a category. | POST accepts a `category_id` and returns links for all active products in that category. |

---

## 2. Current State Analysis

### 2.1 Catalog and Purchase Flow

The catalog router (`app/routers/catalog.py`) manages product CRUD under `/ui/catalog/`. Products are stored in the `T.catalog` table with composite keys (lines 54-63):
(see `app/routers/catalog.py:54` cat_pk, `:58` item_pk, `:62` item_sk)

```python
def cat_pk(category_id: str) -> str:
    return f"CAT#{category_id}"

def item_pk(item_id: str) -> str:
    return f"ITEM#{item_id}"

def item_sk(item_id: str) -> str:
    return f"ITEM#{item_id}"
```

The commerce order service (`app/services/commerce_order_service.py`, line 39+) creates orders with line items:
(see `app/services/commerce_order_service.py:39`)

```python
def create_order(
    self,
    *,
    user_id: str,
    source_system: str,
    line_items: Iterable[Dict[str, Any] | CommercialLineItem],
    correlation_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    parsed: List[CommercialLineItem] = []
    for item in line_items:
        if isinstance(item, CommercialLineItem):
            parsed.append(item)
        else:
            parsed.append(validate_commercial_line_item(dict(item)))
    if not parsed:
        raise ValueError("line_items must not be empty")
    normalized_source = str(source_system or "").strip()
    if normalized_source not in {"shopping_cart", "commercial_direct", "subscription_cycle"}:
        raise ValueError("source_system must be shopping_cart, commercial_direct, or subscription_cycle")
```

The order creation flow writes to `T.orders` and `T.order_items` tables and records an audit event. The affiliate system will hook into this flow to check for affiliate attribution before order completion.

The order record includes `amount_cents`, `currency`, `line_items`, and `metadata`. The `metadata` dict is already used for `checkout_session_id` (line 129) and can carry `affiliate_tracking_code` and `affiliate_link_id` for attribution tracking.

### 2.2 Promo Code Pattern (Similar Tracking)

The promo codes system (`app/routers/promo_codes.py`, `app/services/promo_codes.py`) provides a useful pattern for tracking and attribution. Promo codes are stored with creator ownership, usage tracking, and validation logic (line 85+):
(see `app/services/promo_codes.py:85`)

```python
def create_promo_code(
    creator_id: str,
    code: str,
    discount_type: str,
    discount_value: int = 0,
    free_trial_days: int = 0,
    applies_to: Optional[List[str]] = None,
    min_purchase_cents: int = 0,
    max_uses: int = 0,
    max_uses_per_user: int = 1,
    expires_at: int = 0,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
```

The promo code table uses GSIs for creator listing and global code lookup:

```python
def _promo_pk(code_id: str) -> str:
    return f"PROMO#{code_id}"

def _code_lookup_pk(code: str) -> str:
    return f"CODE#{code.upper()}"

def _creator_scope(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"
```

The affiliate link system will follow a similar pattern: unique code generation, creator-scoped listing, and global lookup for attribution. However, affiliate links differ in that they track clicks (high volume) and conversions (attributed after the fact), while promo codes are applied at checkout time.

### 2.3 Billing Ledger for Commission Payments

The tip ledger (`app/services/tip_ledger.py`, lines 88-150) writes paired debit/credit entries.
(see `app/services/tip_ledger.py:88`) Commission payments will follow the same pattern:

```python
def write_tip_ledger(entry: TipLedgerEntry) -> Dict[str, str]:
    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = _reason_for_content_type(entry.content_type)
    meta = _build_meta(entry)
    # 1. Write debit entry (charge to payer)
    T.billing.put_item(Item={
        "pk": f"USER#{entry.tipper_user_id}",
        "sk": f"LEDGER#{ts}#{debit_id}",
        "entry_id": debit_id,
        "ts": ts,
        "type": "debit",
        "amount_cents": entry.amount_cents,
        "currency": entry.currency,
        "state": "settled",
        "reason": reason,
        "meta": meta,
    })
```

For affiliate commissions, the "debit" is to the product owner (reduced revenue) and the "credit" is to the affiliate (commission earned). This maintains the ledger's zero-sum property.

The commission payment flow:
1. Buyer purchases product for $50 (debit to buyer, credit to product owner)
2. Affiliate attribution found: tracking code -> link -> affiliate user
3. Commission calculated: $50 * 10% = $5
4. Commission ledger entries: debit $5 from product owner, credit $5 to affiliate
5. Net to product owner: $50 - $5 = $45; affiliate earns: $5

### 2.4 Creator Earnings Categories

The earnings service (`app/services/creator_earnings.py`, lines 22-33) maps reasons to categories:
(see `app/services/creator_earnings.py:22`)

```python
def _reason_to_category(reason: str) -> str:
    reason_lower = reason.lower() if reason else ""
    if "subscription" in reason_lower:
        return "subscriptions"
    if reason_lower.startswith("tip"):
        return "tips"
    if "unlock" in reason_lower:
        return "unlocks"
    if "vod" in reason_lower:
        return "vod_purchases"
    return "other"
```

A new category `"affiliate"` will be added, triggered by the reason string `"Affiliate commission"`:

```python
if "affiliate" in reason_lower:
    return "affiliate"
```

This ensures affiliate earnings appear as a separate line in the earnings dashboard breakdown, distinct from tips, subscriptions, and unlocks.

### 2.5 Subscription Server Discount Pattern

The subscription server (`app/routers/subscription_server.py`, line 190+) has a discount application pattern:
<!-- CORRECTED: was "lines 182-195"; `_apply_discount` is at line 190 (see app/routers/subscription_server.py:190) -->

```python
def _discount_sk(code: str) -> str:
    return f"DISCOUNT#{code.upper()}"

def _get_discount(creator_id: str, code: str) -> Optional[Dict[str, Any]]:
    return ddb_get_item(pk_creator(creator_id), _discount_sk(code))

def _apply_discount(amount_cents: int, discount: Dict[str, Any]) -> int:
    percent = int(discount.get("percent_off", 0))
    if percent <= 0:
        return amount_cents
    discounted = int(amount_cents * (100 - percent) / 100)
    return max(0, discounted)
```

The commission calculation will follow a similar percentage-based computation pattern, but in basis points (BPS) for finer granularity:

```python
def compute_commission(order_amount_cents: int, rate_bps: int) -> int:
    """Compute commission in cents from order amount and rate in basis points.

    1 BPS = 0.01%, so 1000 BPS = 10%.
    Uses floor division to avoid overpaying commissions.
    """
    return order_amount_cents * rate_bps // 10000
```

---

## 3. Technical Design

### 3.1 Affiliate Link Data Model

```python
# Table: affiliate_links
# PK: link_id (UUID)
# GSI1: ByAffiliate — GSI1PK=AFFILIATE#{affiliate_user_id}, GSI1SK=created_at (N)
# GSI2: ByCode — GSI2PK=CODE#{tracking_code}, GSI2SK=link_id
# GSI3: ByProduct — GSI3PK=PRODUCT#{target_type}#{target_id}, GSI3SK=created_at (N)

{
    "link_id": "afl_abc123def456",
    "affiliate_user_id": "user_alice",       # creator who generates the link
    "product_owner_id": "user_bob",          # creator who owns the product (may be same)
    "target_type": "catalog_item",           # catalog_item | subscription_plan | vod | post
    "target_id": "item_xyz",                 # ID of the target entity
    "target_name": "Premium Widget",         # denormalized name for display
    "tracking_code": "ALICE7XY3",            # unique short code (8 chars, alphanumeric)
    "short_url": "https://app.example.com/r/ALICE7XY3",
    "destination_url": "/shop/items/item_xyz",
    "commission_rate_bps": 1000,             # 10% (basis points)
    "attribution_window_seconds": 604800,    # 7 days
    "status": "active",                      # active | paused | expired | revoked
    "click_count": 0,
    "unique_click_count": 0,
    "conversion_count": 0,
    "revenue_cents": 0,                      # total revenue attributed
    "commission_earned_cents": 0,            # total commission earned
    "expires_at": null,                      # optional expiry timestamp
    "created_at": 1748390400,
    "updated_at": 1748390400,
    "GSI1PK": "AFFILIATE#user_alice",
    "GSI1SK": 1748390400,
    "GSI2PK": "CODE#ALICE7XY3",
    "GSI2SK": "afl_abc123def456",
    "GSI3PK": "PRODUCT#catalog_item#item_xyz",
    "GSI3SK": 1748390400,
}
```

### 3.2 Click Tracking

Clicks are stored in a separate high-volume table:

```python
# Table: affiliate_clicks
# PK: link_id
# SK: click_id (UUID)
# GSI: ByVisitor — GSI1PK=VISITOR#{visitor_hash}, GSI1SK=clicked_at (N)

{
    "link_id": "afl_abc123def456",
    "click_id": "clk_9876543210ab",
    "visitor_hash": "sha256(ip + user_agent)[:16]",  # privacy-preserving
    "user_id": null,                       # populated if visitor is logged in
    "clicked_at": 1748395000,
    "referrer": "https://twitter.com/alice/status/123",
    "user_agent_category": "mobile",       # mobile | desktop | bot
    "country_code": "US",                  # from IP geolocation
    "is_unique": true,                     # first click from this visitor_hash
    "converted": false,
    "conversion_order_id": null,
    "conversion_amount_cents": null,
    "commission_cents": null,
}
```

#### 3.2.1 Click Recording Implementation

```python
# app/services/affiliate_clicks.py

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Known bot user agent substrings
BOT_INDICATORS = [
    "googlebot", "bingbot", "yandexbot", "baiduspider", "duckduckbot",
    "slurp", "facebookexternalhit", "twitterbot", "linkedinbot",
    "whatsapp", "telegrambot", "discordbot", "applebot",
]


def record_click(
    *,
    link_id: str,
    tracking_code: str,
    ip_address: str,
    user_agent: str,
    referrer: Optional[str] = None,
    user_id: Optional[str] = None,
    daily_salt: str = "",
) -> Dict[str, Any]:
    """Record a click on an affiliate link.

    Returns the click record including is_unique and user_agent_category.
    """
    now = now_ts()
    click_id = f"clk_{uuid.uuid4().hex[:12]}"

    # Hash IP for privacy
    raw = f"{ip_address}:{user_agent}:{daily_salt}"
    visitor_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]

    # Detect bot
    ua_lower = (user_agent or "").lower()
    is_bot = any(bot in ua_lower for bot in BOT_INDICATORS)
    ua_category = "bot" if is_bot else _classify_ua(ua_lower)

    # Check uniqueness (first click from this visitor for this link)
    is_unique = _is_first_visit(link_id, visitor_hash)

    click = {
        "link_id": link_id,
        "click_id": click_id,
        "visitor_hash": visitor_hash,
        "user_id": user_id,
        "clicked_at": now,
        "referrer": _truncate(referrer, 500) if referrer else None,
        "user_agent_category": ua_category,
        "is_unique": is_unique,
        "converted": False,
        "conversion_order_id": None,
        "GSI1PK": f"VISITOR#{visitor_hash}",
        "GSI1SK": now,
    }

    try:
        T.affiliate_clicks.put_item(Item=click)
    except Exception:
        logger.warning("Failed to record affiliate click", extra={"link_id": link_id})
        return click

    # Update link counters (async-safe via atomic increment)
    _increment_link_clicks(link_id, is_unique)

    return click


def _classify_ua(ua: str) -> str:
    """Classify user agent as mobile or desktop."""
    mobile_keywords = ["mobile", "android", "iphone", "ipad", "ipod"]
    if any(kw in ua for kw in mobile_keywords):
        return "mobile"
    return "desktop"


def _is_first_visit(link_id: str, visitor_hash: str) -> bool:
    """Check if this is the first visit from this visitor to this link."""
    from boto3.dynamodb.conditions import Key
    try:
        resp = T.affiliate_clicks.query(
            IndexName="ByVisitor",
            KeyConditionExpression=Key("GSI1PK").eq(f"VISITOR#{visitor_hash}"),
            Limit=1,
            Select="COUNT",
        )
        return int(resp.get("Count", 0)) == 0
    except Exception:
        return True  # Assume unique on error


def _increment_link_clicks(link_id: str, is_unique: bool) -> None:
    """Atomically increment click counters on the affiliate link."""
    update_expr = "SET click_count = click_count + :one, updated_at = :now"
    values: Dict[str, Any] = {":one": 1, ":now": now_ts()}

    if is_unique:
        update_expr += ", unique_click_count = unique_click_count + :one"

    try:
        T.affiliate_links.update_item(
            Key={"link_id": link_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=values,
        )
    except Exception:
        logger.warning("Failed to increment click counters", extra={"link_id": link_id})


def _truncate(s: Optional[str], max_len: int) -> Optional[str]:
    if not s:
        return s
    return s[:max_len] if len(s) > max_len else s
```

### 3.3 Attribution Flow

When a visitor clicks an affiliate link:

1. **Record click**: Write click record to `affiliate_clicks` table.
2. **Set attribution cookie**: Set `afl_ref={tracking_code}` cookie with TTL matching `attribution_window_seconds`. This survives session changes.
3. **Redirect**: 302 redirect to the destination URL.

When a purchase is made (order created via `commerce_order_service.create_order`):

1. **Check attribution**: Read `afl_ref` cookie from the request.
2. **Validate window**: Look up the link, verify `clicked_at` is within `attribution_window_seconds` of now.
3. **Record conversion**: Update click record with `converted=true`, `conversion_order_id`.
4. **Calculate commission**: `commission = order_amount_cents * commission_rate_bps / 10000`.
5. **Write ledger**: Credit to affiliate, debit to product owner.
6. **Update link stats**: Increment `conversion_count`, `revenue_cents`, `commission_earned_cents`.

```python
# app/services/affiliate_attribution.py

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

logger = logging.getLogger(__name__)


def attribute_conversion(
    *,
    tracking_code: str,
    order_id: str,
    order_amount_cents: int,
    buyer_user_id: str,
) -> Optional[Dict[str, Any]]:
    """Attempt to attribute a conversion to an affiliate link.

    Returns commission details if attribution succeeds, None otherwise.

    Attribution rules:
    1. Link must exist and be active
    2. Buyer must have clicked the link within the attribution window
    3. Buyer cannot be the affiliate (self-attribution prevention)
    4. Link cannot be paused or expired
    5. Bot clicks are excluded from attribution
    """
    # Look up link by tracking code
    link = _get_link_by_code(tracking_code)
    if not link or link["status"] != "active":
        return None

    # Check if link has expired
    if link.get("expires_at") and now_ts() > link["expires_at"]:
        return None

    # Prevent self-attribution
    if buyer_user_id == link["affiliate_user_id"]:
        logger.info("Self-attribution blocked", extra={"link_id": link["link_id"], "buyer": buyer_user_id})
        return None

    # Find the most recent non-bot click from this buyer
    latest_click = _get_latest_click_for_user(link["link_id"], buyer_user_id)
    if not latest_click:
        return None

    # Check attribution window
    elapsed = now_ts() - latest_click["clicked_at"]
    if elapsed > link["attribution_window_seconds"]:
        logger.info("Attribution window expired", extra={
            "link_id": link["link_id"], "elapsed": elapsed,
            "window": link["attribution_window_seconds"],
        })
        return None

    # Calculate commission
    rate_bps = _resolve_commission_rate(link)
    commission_cents = order_amount_cents * rate_bps // 10000

    if commission_cents <= 0:
        return None

    # Write commission to billing ledger
    _write_affiliate_commission(
        affiliate_user_id=link["affiliate_user_id"],
        product_owner_id=link["product_owner_id"],
        commission_cents=commission_cents,
        order_id=order_id,
        link_id=link["link_id"],
        order_amount_cents=order_amount_cents,
        rate_bps=rate_bps,
    )

    # Update link stats
    _increment_link_conversions(link["link_id"], order_amount_cents, commission_cents)

    # Mark click as converted
    _mark_click_converted(
        latest_click["link_id"],
        latest_click["click_id"],
        order_id,
        order_amount_cents,
        commission_cents,
    )

    return {
        "link_id": link["link_id"],
        "affiliate_user_id": link["affiliate_user_id"],
        "commission_cents": commission_cents,
        "rate_bps": rate_bps,
        "order_id": order_id,
        "order_amount_cents": order_amount_cents,
    }


def _get_link_by_code(tracking_code: str) -> Optional[Dict[str, Any]]:
    """Look up an affiliate link by its tracking code."""
    from boto3.dynamodb.conditions import Key
    resp = T.affiliate_links.query(
        IndexName="ByCode",
        KeyConditionExpression=Key("GSI2PK").eq(f"CODE#{tracking_code.upper()}"),
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _get_latest_click_for_user(link_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Find the most recent click for a user on a specific link."""
    from boto3.dynamodb.conditions import Key, Attr
    resp = T.affiliate_clicks.query(
        KeyConditionExpression=Key("link_id").eq(link_id),
        FilterExpression=Attr("user_id").eq(user_id) & Attr("user_agent_category").ne("bot"),
        ScanIndexForward=False,
        Limit=10,  # Fetch a few to account for filter
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _write_affiliate_commission(
    *,
    affiliate_user_id: str,
    product_owner_id: str,
    commission_cents: int,
    order_id: str,
    link_id: str,
    order_amount_cents: int,
    rate_bps: int,
) -> None:
    """Write paired debit/credit entries for an affiliate commission."""
    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = "Affiliate commission"
    meta = {
        "link_id": link_id,
        "order_id": order_id,
        "order_amount_cents": order_amount_cents,
        "rate_bps": rate_bps,
        "affiliate_user_id": affiliate_user_id,
        "product_owner_id": product_owner_id,
    }

    # Debit to product owner (commission deducted from their revenue)
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{product_owner_id}",
            "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": commission_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Affiliate commission paid",
            "meta": meta,
        })
    except Exception:
        logger.warning("Failed to write affiliate commission debit", extra=meta)

    # Credit to affiliate (commission earned)
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{affiliate_user_id}",
            "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": commission_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Affiliate commission",
            "meta": meta,
        })
    except Exception:
        logger.warning("Failed to write affiliate commission credit", extra=meta)


def _increment_link_conversions(link_id: str, revenue_cents: int, commission_cents: int) -> None:
    """Atomically increment conversion stats on the link."""
    try:
        T.affiliate_links.update_item(
            Key={"link_id": link_id},
            UpdateExpression=(
                "SET conversion_count = conversion_count + :one, "
                "revenue_cents = revenue_cents + :rev, "
                "commission_earned_cents = commission_earned_cents + :comm, "
                "updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":one": 1,
                ":rev": revenue_cents,
                ":comm": commission_cents,
                ":now": now_ts(),
            },
        )
    except Exception:
        logger.warning("Failed to increment link conversions", extra={"link_id": link_id})


def _mark_click_converted(link_id: str, click_id: str, order_id: str, amount: int, commission: int) -> None:
    """Mark a click record as converted."""
    try:
        T.affiliate_clicks.update_item(
            Key={"link_id": link_id, "click_id": click_id},
            UpdateExpression="SET converted = :true, conversion_order_id = :oid, conversion_amount_cents = :amt, commission_cents = :comm",
            ExpressionAttributeValues={
                ":true": True,
                ":oid": order_id,
                ":amt": amount,
                ":comm": commission,
            },
        )
    except Exception:
        logger.warning("Failed to mark click as converted", extra={"click_id": click_id})


def _resolve_commission_rate(link: Dict[str, Any]) -> int:
    """Resolve effective commission rate for a link."""
    # Link-level override takes priority
    if link.get("commission_rate_bps") is not None:
        return int(link["commission_rate_bps"])

    # Product-owner's default rate
    settings = _get_affiliate_settings(link["product_owner_id"])
    return int(settings.get("default_commission_bps", 1000))
```

### 3.4 Commission Rate Resolution

Commission rates are resolved with a priority hierarchy:

1. **Per-link override** (set on the link itself)
2. **Per-product override** (product owner sets rate for their product)
3. **Per-affiliate override** (product owner sets rate for a specific affiliate)
4. **Creator global rate** (product owner's default affiliate commission)
5. **Platform default** (env var `AFFILIATE_DEFAULT_COMMISSION_BPS`, default 1000 = 10%)

```python
def resolve_commission_rate(
    *,
    link: Dict[str, Any],
    product_owner_id: str,
    affiliate_user_id: str,
    target_id: str,
) -> int:
    """Resolve the effective commission rate in basis points.

    Priority (highest first):
    1. Link-level override
    2. Per-product override
    3. Per-affiliate override
    4. Creator global rate
    5. Platform default (1000 BPS = 10%)
    """
    # 1. Link-level override
    if link.get("commission_rate_bps") is not None:
        return int(link["commission_rate_bps"])

    # 2. Per-product override
    product_rate = get_product_affiliate_rate(product_owner_id, target_id)
    if product_rate is not None:
        return product_rate

    # 3. Per-affiliate override
    affiliate_rate = get_affiliate_specific_rate(product_owner_id, affiliate_user_id)
    if affiliate_rate is not None:
        return affiliate_rate

    # 4. Creator global rate
    creator_rate = get_creator_affiliate_rate(product_owner_id)
    if creator_rate is not None:
        return creator_rate

    # 5. Platform default
    return int(os.environ.get("AFFILIATE_DEFAULT_COMMISSION_BPS", "1000"))
```

### 3.5 Tracking Code Generation

Tracking codes are 8-character alphanumeric strings with collision detection:

```python
import string
import secrets

_ALPHABET = string.ascii_uppercase + string.digits  # 36 chars, 8 length = 2.8T combinations

def generate_tracking_code(affiliate_user_id: str) -> str:
    """Generate a unique tracking code.

    Format: first 3 chars from username hash + 5 random chars.
    This makes codes somewhat memorable while being unique.

    Collision probability: ~1 in 60M per attempt for 8-char codes.
    Retry loop ensures uniqueness even under high concurrency.
    """
    prefix = hashlib.sha256(affiliate_user_id.encode()).hexdigest()[:3].upper()
    for _ in range(10):  # retry on collision
        suffix = "".join(secrets.choice(_ALPHABET) for _ in range(5))
        code = prefix + suffix
        existing = _get_link_by_code(code)
        if not existing:
            return code
    raise RuntimeError("Failed to generate unique tracking code after 10 attempts")
```

### 3.6 Redirect Endpoint Implementation

```python
# app/routers/affiliate.py

from fastapi import APIRouter, Request, Response
from starlette.responses import RedirectResponse

router = APIRouter(tags=["affiliate"])


@router.get("/r/{tracking_code}")
def affiliate_redirect(
    tracking_code: str,
    request: Request,
):
    """Public redirect endpoint for affiliate links.

    1. Look up link by tracking code
    2. Record click
    3. Set attribution cookie
    4. 302 redirect to destination
    """
    link = _get_link_by_code(tracking_code)
    if not link:
        return RedirectResponse(url="/", status_code=302)

    if link["status"] != "active":
        return RedirectResponse(url=link.get("destination_url", "/"), status_code=302)

    # Record click (best-effort, non-blocking)
    ip = request.client.host if request.client else "0.0.0.0"
    ua = request.headers.get("user-agent", "")
    referrer = request.headers.get("referer")
    user_id = _get_user_id_from_session(request)  # None if not logged in

    record_click(
        link_id=link["link_id"],
        tracking_code=tracking_code,
        ip_address=ip,
        user_agent=ua,
        referrer=referrer,
        user_id=user_id,
    )

    # Build redirect response with attribution cookie
    destination = link.get("destination_url", "/")
    response = RedirectResponse(url=destination, status_code=302)

    # Set attribution cookie
    window_seconds = int(link.get("attribution_window_seconds", 604800))
    response.set_cookie(
        key="afl_ref",
        value=tracking_code,
        max_age=window_seconds,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    # Prevent caching of the redirect
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    return response
```

### 3.7 Order Hook for Attribution

The affiliate attribution check is integrated into the order creation flow:

```python
# In app/services/commerce_order_service.py, after create_order:

def create_order_with_affiliate_check(
    self,
    *,
    user_id: str,
    source_system: str,
    line_items: Iterable[Dict[str, Any] | CommercialLineItem],
    tracking_code: Optional[str] = None,  # from afl_ref cookie
    **kwargs,
) -> Dict[str, Any]:
    """Create an order and attempt affiliate attribution."""
    order = self.create_order(
        user_id=user_id,
        source_system=source_system,
        line_items=line_items,
        **kwargs,
    )

    if tracking_code:
        try:
            from app.services.affiliate_attribution import attribute_conversion
            attribution = attribute_conversion(
                tracking_code=tracking_code,
                order_id=order["order_id"],
                order_amount_cents=order["amount_cents"],
                buyer_user_id=user_id,
            )
            if attribution:
                order["affiliate_attribution"] = attribution
        except Exception:
            logger.warning("Affiliate attribution failed", extra={
                "order_id": order["order_id"],
                "tracking_code": tracking_code,
            })

    return order
```

### 3.8 Affiliate Settings Storage

```python
# Stored in affiliate_links table with special PK pattern
{
    "link_id": "SETTINGS",  # PK
    "owner_id": "user_bob",
    "affiliate_enabled": True,
    "default_commission_bps": 1000,           # 10%
    "default_attribution_window_seconds": 604800,  # 7 days
    "min_commission_bps": 100,                # 1%
    "max_commission_bps": 5000,               # 50%
    "product_overrides": {                    # {product_id: rate_bps}
        "item_xyz": 1500,
    },
    "affiliate_overrides": {                  # {affiliate_user_id: rate_bps}
        "user_alice": 2000,
    },
    "updated_at": 1748390400,
}
```

---

## 4. API Endpoints

### 4.1 Affiliate Link Management

<!-- NOTE: Actual endpoint paths use `/ui/affiliates/links` (plural), not `/ui/affiliate/links`. See app/routers/affiliate_links.py:66-175. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/affiliates/links` | `require_ui_session` | Create a new affiliate link (see `:66`) |
| GET | `/ui/affiliates/links` | `require_ui_session` | List creator's affiliate links (see `:96`) |
| GET | `/ui/affiliates/links/{link_id}` | `require_ui_session` | Get link detail with stats (see `:106`) |
| DELETE | `/ui/affiliates/links/{link_id}` | `require_ui_session` | Revoke a link (see `:120`) |
| GET | `/ui/affiliates/links/{link_id}/stats` | `require_ui_session` | Get link stats (see `:133`) |
| POST | `/ui/affiliates/links/{link_id}/conversions` | `require_ui_session` | Record a conversion (see `:148`) |

### 4.2 Click Tracking (Public)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/r/{tracking_code}` | None | Redirect endpoint: records click, sets cookie, redirects to destination (see `app/routers/affiliate_links.py:174`) |

### 4.3 Commission Settings (Product Owner)

<!-- NOTE: Settings endpoints are NOT yet implemented in app/routers/affiliate_links.py — new implementation required. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/affiliates/settings` | `require_ui_session` | Get creator's affiliate settings |
| PATCH | `/ui/affiliates/settings` | `require_ui_session` | Update default commission rate, attribution window |
| PUT | `/ui/affiliates/settings/products/{item_id}` | `require_ui_session` | Set per-product commission rate |
| DELETE | `/ui/affiliates/settings/products/{item_id}` | `require_ui_session` | Remove per-product override |
| PUT | `/ui/affiliates/settings/affiliates/{user_id}` | `require_ui_session` | Set per-affiliate commission rate |
| DELETE | `/ui/affiliates/settings/affiliates/{user_id}` | `require_ui_session` | Remove per-affiliate override |

### 4.4 Performance Dashboard

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/affiliate/dashboard` | `require_ui_session` | Aggregate performance metrics |
| GET | `/ui/affiliate/links/{link_id}/clicks` | `require_ui_session` | Paginated click log for a link |
| GET | `/ui/affiliate/links/{link_id}/conversions` | `require_ui_session` | Paginated conversions for a link |
| GET | `/ui/affiliate/links/{link_id}/daily-stats` | `require_ui_session` | Daily click/conversion time series |

### 4.5 Admin Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/affiliate/overview` | `require_admin_session` | Platform-wide affiliate stats |
| GET | `/ui/admin/affiliate/suspicious` | `require_admin_session` | Suspicious activity report |
| POST | `/ui/admin/affiliate/links/{link_id}/revoke` | `require_admin_session` | Admin revoke a link |

### 4.6 Request/Response Models

```python
class AffiliateLinkCreateIn(BaseModel):
    target_type: Literal["catalog_item", "subscription_plan", "vod", "post"] = Field(..., description="Type of content being linked")
    target_id: str = Field(..., min_length=1, max_length=128, description="ID of the target entity")
    commission_rate_bps: Optional[int] = Field(default=None, ge=100, le=5000, description="Override commission rate in basis points (100=1%, 5000=50%)")
    attribution_window_seconds: Optional[int] = Field(default=None, ge=3600, le=2592000, description="Override attribution window (1h to 30d)")
    expires_at: Optional[int] = Field(default=None, description="Unix timestamp for link expiry")
    custom_slug: Optional[str] = Field(default=None, min_length=3, max_length=20, pattern=r"^[A-Za-z0-9_-]+$", description="Custom tracking code suffix")

class AffiliateLinkUpdateIn(BaseModel):
    status: Optional[Literal["active", "paused"]] = None
    expires_at: Optional[int] = None
    commission_rate_bps: Optional[int] = Field(default=None, ge=100, le=5000)

class AffiliateLinkOut(BaseModel):
    link_id: str
    affiliate_user_id: str
    product_owner_id: str
    target_type: str
    target_id: str
    target_name: str
    tracking_code: str
    short_url: str
    destination_url: str
    commission_rate_bps: int
    attribution_window_seconds: int
    status: str
    click_count: int = 0
    unique_click_count: int = 0
    conversion_count: int = 0
    revenue_cents: int = 0
    commission_earned_cents: int = 0
    conversion_rate_pct: float = 0.0  # computed: conversion_count / unique_click_count * 100
    expires_at: Optional[int] = None
    created_at: int
    updated_at: int

class AffiliateSettingsIn(BaseModel):
    affiliate_enabled: Optional[bool] = None
    default_commission_bps: Optional[int] = Field(default=None, ge=100, le=5000)
    default_attribution_window_seconds: Optional[int] = Field(default=None, ge=3600, le=2592000)

class AffiliateSettingsOut(BaseModel):
    affiliate_enabled: bool = True
    default_commission_bps: int = 1000
    default_attribution_window_seconds: int = 604800
    min_commission_bps: int = 100
    max_commission_bps: int = 5000
    product_overrides: List[Dict[str, Any]] = Field(default_factory=list)
    affiliate_overrides: List[Dict[str, Any]] = Field(default_factory=list)

class AffiliateDashboardOut(BaseModel):
    total_clicks: int = 0
    total_unique_clicks: int = 0
    total_conversions: int = 0
    total_revenue_cents: int = 0
    total_commission_cents: int = 0
    overall_conversion_rate_pct: float = 0.0
    links_count: int = 0
    top_links: List[AffiliateLinkOut] = Field(default_factory=list)
    currency: str = "USD"

class AffiliateClickOut(BaseModel):
    click_id: str
    clicked_at: int
    referrer: Optional[str] = None
    user_agent_category: str
    is_unique: bool
    converted: bool
    conversion_order_id: Optional[str] = None
    conversion_amount_cents: Optional[int] = None
    commission_cents: Optional[int] = None

class AffiliateDailyStats(BaseModel):
    date: str  # YYYY-MM-DD
    clicks: int = 0
    unique_clicks: int = 0
    conversions: int = 0
    revenue_cents: int = 0
    commission_cents: int = 0
```

---

## 5. Frontend Components

### 5.1 New Pages and Components

<!-- NOTE: The actual page directory is `frontend/src/pages/affiliates/` (plural), not `frontend/src/pages/affiliate/`. Only AffiliateDashboard.tsx exists as a single file. -->

| Component | Path | Status |
|-----------|------|--------|
| `AffiliateDashboard` | `frontend/src/pages/affiliates/AffiliateDashboard.tsx` | **EXISTS** (all-in-one page) |
| `CreateLinkDialog` | inline in AffiliateDashboard.tsx | NOT separate |
| `LinkPerformanceCard` | inline in AffiliateDashboard.tsx | NOT separate |
| `AffiliateSettingsPanel` | — | NOT YET IMPLEMENTED |
| `ConversionLog` | — | NOT YET IMPLEMENTED |
| `ClickChart` | — | NOT YET IMPLEMENTED |
| `CopyLinkButton` | — | NOT YET IMPLEMENTED |
| `QRCodeDisplay` | — | NOT YET IMPLEMENTED |
| `CommissionRateEditor` | — | NOT YET IMPLEMENTED |

### 5.2 Integration Points

- **CatalogItemOut detail page**: Add "Create Affiliate Link" button for product owners and partner creators
- **Earnings Dashboard**: Add `"affiliate"` category to the breakdown chart
- **Product shelf (broadcast)**: Affiliate links generated for shelf products during live commerce
- **Sidebar.tsx**: Add "Affiliate Links" nav item under Creator Tools
- **MobileNav.tsx**: Add to `MORE_LINKS`
- **Shop product detail page**: Show "Share & Earn" button for creators

### 5.3 Route

```tsx
// App.tsx — VERIFIED at line 78 (lazy import) and line 189 (route)
const AffiliateDashboard = lazy(() => import("@/pages/affiliates/AffiliateDashboard"));
// ...
<Route path="affiliates" element={<AffiliateDashboard />} />
// NOTE: route path is "/affiliates" (plural), not "/affiliate"
```

---

## 6. DynamoDB Table Definitions

### 6.1 affiliate_links Table

```python
# scripts/local-ddb-init.py — VERIFIED at line 990
# NOTE: default table name is "AffiliateLinks" (camelCase), not "affiliate_links"
TableDef(
    _resolve_table_name(S.affiliate_links_table_name, "AffiliateLinks"),
    "link_id",
    gsi=[  # NOTE: actual field is `gsi=`, not `gsis=`
        {"index_name": "ByAffiliate", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "ByCode", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
        {"index_name": "ByProduct", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI3SK": "N"},
),
```

### 6.2 affiliate_clicks Table

```python
# scripts/local-ddb-init.py — VERIFIED at line 1001
# NOTE: default table name is "AffiliateClicks" (camelCase)
TableDef(
    _resolve_table_name(S.affiliate_clicks_table_name, "AffiliateClicks"),
    "link_id",
    "click_id",
    gsi=[
        {"index_name": "ByVisitor", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"GSI1SK": "N"},
),
```

### 6.3 Table Handle Registration

```python
# app/core/tables.py — VERIFIED: declarations at lines 112-113, initialization at lines 236-237
affiliate_links=ddb.Table(S.affiliate_links_table_name),
affiliate_clicks=ddb.Table(S.affiliate_clicks_table_name),
```

```python
# app/core/settings.py — VERIFIED at lines 1436-1441
affiliate_links_enabled: bool = ...
affiliate_default_commission_percent: int = 10
affiliate_max_commission_percent: int = 50
affiliate_cookie_duration_days: int = 30
affiliate_links_table_name: str = os.environ.get("DDB_AFFILIATE_LINKS", "AffiliateLinks")
affiliate_clicks_table_name: str = os.environ.get("DDB_AFFILIATE_CLICKS", "AffiliateClicks")
```

### 6.4 Capacity Estimates

- **affiliate_links**: Low volume (10-100 per creator). On-demand billing.
- **affiliate_clicks**: High volume for popular links. Estimated 1K-100K clicks/day for top creators. On-demand billing with auto-scaling. Consider TTL on old click records (e.g., 90 days).
- **GSI2 (ByCode)**: Single-item lookup, very fast. Critical path for redirect performance.

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/affiliate-links.spec.ts`

### 7.2 Test Sections

| Section | Title | Tests |
|---------|-------|-------|
| 1 | Link CRUD API | 7 tests: create link, list links, get link detail, pause link, resume link, revoke link, validate tracking code uniqueness |
| 2 | Click Tracking API | 5 tests: redirect with tracking code, click recorded in DB, attribution cookie set, duplicate click counted, bot detection (user agent filtering) |
| 3 | Conversion Attribution API | 6 tests: conversion attributed correctly, commission calculated, ledger entries written, attribution window expired (no attribution), self-click not attributed, paused link not attributed |
| 4 | Commission Settings API | 4 tests: update default rate, set per-product override, set per-affiliate override, resolution priority verified |
| 5 | Performance Dashboard API | 4 tests: dashboard aggregates correct, top links sorted by revenue, click chart data correct, conversion log paginated |
| 6 | Affiliate Page UI | 5 tests: page loads with tabs, create link dialog, link card shows stats, copy button works, settings panel updates |
| 7 | Refund Clawback | 3 tests: refunded order creates clawback entries, affiliate commission reversed, link stats adjusted |
| 8 | Cross-Creator Affiliate | 3 tests: Alice creates link to Bob's product, Bob's affiliate_enabled checked, commission flows correctly |

**Estimated total**: ~37 tests

### 7.3 Test Data Setup

```typescript
const TS = Date.now();
let aliceLinkId: string;
let aliceTrackingCode: string;
let bobProductId: string;

test.beforeAll(async ({ browser }) => {
  // 1. Bob creates a catalog product
  const bobPage = await browser.newPage();
  await injectAuth(bobPage, "bob");

  const prodResp = await bobPage.request.post("/ui/catalog/items", {
    headers: { "x-csrf-token": sessions.bob.csrf_token },
    data: {
      name: `Affiliate Test Product ${TS}`,
      price_cents: 2500,
      currency: "USD",
      category_id: "cat_default",
    },
  });
  bobProductId = (await prodResp.json()).item_id;

  // 2. Bob enables affiliates with 15% commission
  await bobPage.request.patch("/ui/affiliate/settings", {
    headers: { "x-csrf-token": sessions.bob.csrf_token },
    data: {
      affiliate_enabled: true,
      default_commission_bps: 1500,
    },
  });

  // 3. Alice generates an affiliate link to Bob's product
  const alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  const linkResp = await alicePage.request.post("/ui/affiliate/links", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      target_type: "catalog_item",
      target_id: bobProductId,
    },
  });
  const link = await linkResp.json();
  aliceLinkId = link.link_id;
  aliceTrackingCode = link.tracking_code;

  await Promise.all([bobPage.close(), alicePage.close()]);
});
```

---

## 8. Edge Cases

| Case | Behavior |
|------|----------|
| Creator promotes own product | Allowed (self-affiliate). Commission is zero (debit and credit to same user cancel out) or configurable. Default: self-affiliate disabled. |
| Cross-creator affiliate not enabled | Product owner must set `affiliate_enabled=true` in settings. Attempting to create a link to a non-enabled product returns 403. |
| Click from logged-out visitor | `user_id` is null in click record. Attribution uses the cookie when/if the visitor logs in and makes a purchase. |
| Multiple affiliate links for same product | Each link tracks independently. If a visitor clicks multiple links from different affiliates, last-click attribution wins (most recent cookie). |
| Attribution window expires | Conversion not attributed. No commission. |
| Order refunded after commission paid | Commission clawback: write a negative credit (debit) to affiliate and negative debit (credit) to product owner. |
| Bot traffic | Clicks from known bot user agents (Googlebot, etc.) are recorded but marked `user_agent_category=bot` and excluded from conversion attribution. |
| Tracking code collision | Retry loop (10 attempts). If all fail, return 500. Probability: 1 in 60M per attempt for 8-char codes. |
| Link to deleted product | Link remains but redirect shows "Product unavailable" page. No conversions possible. |
| Very high commission (>50%) | Platform-enforced max: 5000 BPS (50%). Creator settings capped. |
| Circular affiliate (A promotes B, B promotes A) | Allowed. Each direction is independent. No infinite loops since attribution is one-way per transaction. |
| Click rate limit exceeded | Excess clicks from same IP still count in click metrics but are flagged. Attribution is not affected (only the most recent click matters). |
| Cookie blocked by browser | No attribution possible. The system degrades gracefully -- clicks are recorded but conversions are not attributed. |
| Multiple products in one order | Attribution applies to the entire order amount, not per-line-item. This simplifies commission calculation but means the affiliate earns commission on all items in the order, not just the linked product. |
| Affiliate link created during checkout | Click is recorded but the attribution window starts from the click, not from link creation. If the buyer was already in checkout, the conversion is still attributed if within the window. |
| Extremely high click volume | The click table uses on-demand capacity. For links with >100K clicks/day, consider batch writes or a dedicated click analytics service. |

---

## 9. Security Considerations

### 9.1 Click Fraud Prevention

- **Rate limiting**: Max 10 clicks per IP per link per hour (excess silently discarded from conversion tracking but still counted for click metrics)
- **Bot detection**: Known bot user agents excluded from attribution
- **IP hashing**: Only `sha256(ip + salt)[:16]` is stored -- no raw IPs in the database
- **Self-click exclusion**: Clicks from the affiliate's own user_id are recorded but never attributed
- **Anomaly detection**: Admin endpoint flags links with conversion rates >30% (suspicious)

### 9.2 Commission Integrity

- Commission is calculated server-side from the order amount at purchase time (not from click-time price)
- Commission rate is snapshotted on the link at creation time. Subsequent rate changes apply to new links only.
- Ledger entries are immutable. Disputes are handled via refund/clawback entries, not modification.
- Maximum commission rate enforced platform-wide (5000 BPS = 50%)

### 9.3 Privacy

- Visitor IP addresses are hashed with a rotating daily salt before storage
- No PII stored in click records beyond optional `user_id` (for attribution)
- GDPR: click records can be bulk-deleted for a user upon account deletion
- Referrer URLs are truncated to 500 characters to avoid storing sensitive query parameters

### 9.4 Redirect Security

- Destination URLs are validated at link creation time to ensure they point to platform-internal paths only (no open redirect)
- Tracking code lookup uses the `ByCode` GSI for O(1) lookup (no table scan)
- Redirect response includes `Cache-Control: no-store` to prevent browser caching of the 302
- The redirect endpoint does not accept arbitrary URLs as parameters

### 9.5 Cookie Security

- Attribution cookie `afl_ref` uses `HttpOnly`, `Secure`, `SameSite=Lax` flags
- Cookie value is the tracking code only (no sensitive data)
- TTL matches the attribution window (default 7 days)
- Cookie path is `/` to ensure it is sent with all requests to the platform

### 9.6 Admin Abuse Detection

- Admin dashboard shows top affiliates by click volume, conversion rate, and commission earned
- Suspicious patterns flagged: conversion rate >30%, same buyer converting multiple times for same affiliate, clicks from a small number of IPs
- Admin can revoke any affiliate link immediately, which stops all future clicks and conversions

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/routers/catalog.py` | 54-62 | `cat_pk`, `item_pk`, `item_sk` helpers |
| `app/services/commerce_order_service.py` | 39 | `create_order` method |
| `app/services/promo_codes.py` | 85 | `create_promo_code` |
| `app/services/tip_ledger.py` | 88-150 | `write_tip_ledger` — paired debit/credit |
| `app/services/creator_earnings.py` | 22-33 | `_reason_to_category` (no "affiliate" category yet) |
| `app/routers/subscription_server.py` | 190 | `_apply_discount` |
| `scripts/local-ddb-init.py` | 990-999 | `AffiliateLinks` TableDef with 3 GSIs |
| `scripts/local-ddb-init.py` | 1001-1009 | `AffiliateClicks` TableDef |
| `app/core/settings.py` | 1436-1441 | Affiliate feature flags and settings |
| `app/core/tables.py` | 112-113, 236-237 | Affiliate table handles |
| `app/main.py` | 117, 452 | Import + registration of `affiliate_links_router` |
| `app/routers/affiliate_links.py` | 27 | Router: `tags=["affiliate-links"]` |
| `app/routers/affiliate_links.py` | 66-175 | All endpoint definitions (CRUD, stats, redirect) |
| `app/services/affiliate_links.py` | 63 | `create_affiliate_link` |
| `app/services/affiliate_links.py` | 135 | `get_link` |
| `app/services/affiliate_links.py` | 141 | `get_link_by_code` |
| `app/services/affiliate_links.py` | 152 | `list_creator_links` |
| `app/services/affiliate_links.py` | 162 | `delete_link` |
| `app/services/affiliate_links.py` | 190 | `record_click` |
| `app/services/affiliate_links.py` | 272 | `record_conversion` |
| `app/services/affiliate_links.py` | 336 | `get_link_stats` |
| `frontend/src/App.tsx` | 78, 189 | Lazy import + route for `/affiliates` |
| `frontend/src/pages/affiliates/AffiliateDashboard.tsx` | all | Main affiliate page |
| `frontend/src/api/endpoints/affiliates.ts` | all | Frontend API functions |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_affiliate_links.py`

| Test Function | What It Validates | Mock Setup |
|---|---|---|
| `test_create_affiliate_link` | Link record created with correct fields, tracking code generated | moto DDB `affiliate_links` table |
| `test_create_link_duplicate_code` | 409 when tracking code already exists | Pre-seed link with same code |
| `test_list_creator_links` | Paginated links for creator, sorted by created_at | Pre-seed 5 links |
| `test_pause_resume_revoke_link` | Status transitions: active->paused->active->revoked | Pre-seed active link |
| `test_record_click` | Click record written to `affiliate_clicks`, counter incremented | moto DDB |
| `test_record_click_bot_filtered` | Bot user-agent clicks not counted toward conversions | Set UA to known bot pattern |
| `test_record_conversion_attributed` | Conversion attributed, commission calculated, ledger entries written | Seed click within attribution window |
| `test_conversion_expired_window` | No attribution when click outside window | Seed old click |
| `test_conversion_self_click_ignored` | Self-referral not attributed | Click from link creator |
| `test_conversion_paused_link` | Paused links do not attribute | Seed paused link |
| `test_commission_calculation` | `amount_cents * rate / 100` with correct rounding | Direct function call |
| `test_per_product_override` | Per-product rate overrides default | Seed override |
| `test_refund_clawback` | Refunded order reverses commission with negative ledger entry | Seed conversion then refund |
| `test_get_link_stats` | Aggregates clicks, conversions, revenue, commission | Seed clicks + conversions |

**Mock Setup**: `moto.mock_dynamodb` with `affiliate_links`, `affiliate_clicks`, `billing` tables.

### E2E Tests (Playwright)

**File**: `frontend/e2e/affiliate-links.spec.ts`

**Auth Pattern**: `injectAuth(page, "alice")` / `injectAuth(page, "bob")`. CSRF headers on all mutations.

| Section | Title | Tests | Key Assertions |
|---|---|---|---|
| 1 | Link CRUD API | 7 | `expect(body.tracking_code).toBeTruthy()`, `expect(body.status).toBe("active")` |
| 2 | Click Tracking API | 5 | Redirect 302, click count incremented, attribution cookie set |
| 3 | Conversion Attribution API | 6 | Commission > 0, ledger entries present, expired window no attribution |
| 4 | Commission Settings API | 4 | Default rate persists, per-product override, per-affiliate override priority |
| 5 | Performance Dashboard API | 4 | Aggregates correct, top links sorted, pagination |
| 6 | Affiliate Page UI | 5 | `page.getByRole("tab", { name: /links/i })`, create dialog, copy button |
| 7 | Refund Clawback | 3 | Negative commission entry, stats adjusted |
| 8 | Cross-Creator Affiliate | 3 | Alice link to Bob product, commission flows to Alice |

**Negative Tests**: 409 (duplicate code), 403 (non-affiliate-enabled product), 404 (revoked link redirect), 400 (invalid rate).

**Setup/Teardown**: `beforeAll` creates Bob's catalog product via API, Alice creates affiliate link. TS-prefixed names.

### Test Data Requirements

| Data | Table | Seeded By |
|---|---|---|
| Alice, Bob sessions | `sessions` | `e2e_session_setup.py` |
| Catalog product | Catalog tables | API in `beforeAll` |
| Affiliate links | `affiliate_links` | API in `beforeAll` |

### CI / Pipeline

- **Feature flag**: `AFFILIATE_LINKS_ENABLED=true` (default).
- **Serial execution**: Required -- conversion tests depend on click data.
- **Retry safety**: Tracking codes and product names include `TS` suffix.
- **DDB tables**: `affiliate_links`, `affiliate_clicks` in `scripts/local-ddb-init.py`.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| Catalog System (`app/routers/catalog.py`) | Product records for link targets | Implemented (core) | Yes |
| Billing Ledger (`app/services/tip_ledger.py`) | Commission debit/credit writes | Implemented (core) | Yes |
| Creator Earnings (`app/services/creator_earnings.py`) | Needs new "affiliate" category in `_reason_to_category` | Implemented (core) | Yes |

### Depended On By

| Ticket | What It Needs |
|---|---|
| None currently | Standalone affiliate feature |

### Merge Strategy

**Independent**. Introduces two new DDB tables, new router + services. All modifications additive. No existing behavior changed.

### Merge Checklist

- [ ] `affiliate_links` and `affiliate_clicks` tables in `scripts/local-ddb-init.py`
- [ ] Feature flag `AFFILIATE_LINKS_ENABLED` in `.env.local.example`
- [ ] `_reason_to_category` includes "affiliate" category
- [ ] Redirect endpoint (`GET /a/{code}`) does not require auth
- [ ] All 37 E2E tests pass
- [ ] `just test` passes
