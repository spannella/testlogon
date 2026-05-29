# ADS-015: Ad Creative with Affiliate Links & Discounts

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 6-8 days  
**Dependencies**: ADS-002 (ad creative management — sibling ticket, not yet implemented), ADS-004 (ad serving engine — sibling ticket, not yet implemented), AFFILIATE-001 (referral system)
<!-- NOTE: ADS-002 and ADS-004 are sibling tickets not yet in the codebase. Existing: affiliate_links.py (app/services/affiliate_links.py), promo_codes.py (app/services/promo_codes.py). -->

---

## 1. Overview & Motivation

### The Gap

The platform has three independent systems that should work together but currently do not:

1. **Ad creatives** (ADS-002): Images/videos displayed as advertisements, with click-through URLs
2. **Affiliate links** (`app/services/affiliate_links.py`): Tracking codes that attribute clicks and conversions to affiliates, with commission payments
3. **Promo codes** (`app/services/promo_codes.py`): Discount codes that reduce purchase prices, with redemption tracking

These systems exist in silos. An advertiser who wants to run an ad that offers a discount and tracks conversions via affiliate attribution must manage three separate workflows: create the ad creative, set up the affiliate tracking code, and configure the promo code — with no connection between them. There is no way to:

- Attach an affiliate tracking code to an ad creative so that clicks are attributed
- Attach a promo code to an ad so that viewers see a discount badge
- Auto-apply a promo code when a user clicks through from an ad to checkout
- Calculate ROAS (Return on Ad Spend) by linking affiliate conversions back to ad campaigns
- Pay creators both ad revenue share AND affiliate commissions when their content hosts an ad with affiliate tracking

### Why This Is Needed

1. **Conversion tracking**: Advertisers need to know which ad clicks lead to actual purchases. Linking affiliate tracking codes to ad creatives enables closed-loop conversion attribution.

2. **Higher CTR**: Ads showing discount badges ("Save 20%", "$10 OFF") have significantly higher click-through rates than generic ads. Promo code integration directly increases ad effectiveness.

3. **Frictionless user experience**: When a user clicks an ad with a promo code, the discount should auto-apply at checkout — not require manual code entry. Reducing checkout friction increases conversion rates.

4. **Creator dual revenue**: When an ad with an affiliate code runs on a creator's content, the creator earns both the ad placement revenue (CPM) and the affiliate commission on conversions. This makes hosting ads more attractive for creators.

5. **ROAS measurement**: Advertisers need Return on Ad Spend to evaluate campaign effectiveness. Without conversion attribution linked to ad spend, ROAS is impossible to calculate.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Ad Creative + Affiliate + Promo Integration                 │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │                  Ad Creative Record                      │            │
│  │                  (ad_creatives table)                     │            │
│  │                                                          │            │
│  │  creative_id: "creat_xyz789"                             │            │
│  │  image_url: "https://cdn/ad.png"                         │            │
│  │  click_through_url: "https://shop.com/product"           │            │
│  │  affiliate_code: "ABC12345"          ← NEW               │            │
│  │  promo_code: "SUMMER20"             ← NEW               │            │
│  │  promo_value_display: "20% OFF"     ← NEW               │            │
│  └─────────────┬───────────────────────────────────────────┘            │
│                │                                                        │
│                │ Ad Served to Viewer                                     │
│                ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │  Ad Render (browser)                                     │            │
│  │  ┌───────────────────────────────┐                      │            │
│  │  │  [Ad Image/Video]             │                      │            │
│  │  │         ┌──────────────┐      │                      │            │
│  │  │         │ Save 20% OFF │      │ ← Promo badge        │            │
│  │  │         └──────────────┘      │                      │            │
│  │  │  [Click to Shop ->]           │                      │            │
│  │  └───────────────────────────────┘                      │            │
│  └─────────────┬───────────────────────────────────────────┘            │
│                │ User clicks ad                                         │
│                ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │  Click Handler (backend)                                  │            │
│  │  app/services/ad_click_handler.py                         │            │
│  │                                                           │            │
│  │  1. Record ad click (ad_impressions table)                │            │
│  │  2. Record affiliate click (affiliate_links table)        │            │
│  │  3. Set promo cookie: ad_promo_code=SUMMER20              │            │
│  │  4. 302 Redirect → shop.com/product?ref=ABC12345         │            │
│  └─────────────┬───────────────────────────────────────────┘            │
│                │                                                        │
│                ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │  Checkout Page (browser)                                  │            │
│  │                                                           │            │
│  │  Reads ad_promo_code cookie                               │            │
│  │  Auto-fills: [SUMMER20] Applied                          │            │
│  │  Subtotal: $50.00  Discount: -$10.00 (20%)              │            │
│  │  Total: $40.00                                            │            │
│  │                                                           │            │
│  │  On purchase → record_affiliate_conversion(ABC12345)      │            │
│  │             → link campaign_id for ROAS                   │            │
│  └─────────────────────────────────────────────────────────┘            │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │  ROAS Calculation                                         │            │
│  │  app/services/ad_roas.py                                  │            │
│  │                                                           │            │
│  │  ROAS = conversion_revenue / ad_spend                     │            │
│  │  Per campaign: sum conversions linked via affiliate_code  │            │
│  │                                                           │            │
│  │  Creator gets: CPM revenue + affiliate commission         │            │
│  └─────────────────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Ad Creatives (ADS-002)

Ad creative records (stored in the `ad_creatives` table from ADS-002) contain:
- `creative_id`, `advertiser_account_id`, `name`
- `type` (image, video, text)
- `asset_url` (S3 URL for the creative asset)
- `click_through_url` (destination URL when ad is clicked)
- `status` (draft, pending_review, approved, rejected)

**Missing fields**: `affiliate_code`, `promo_code`, `promo_value_display`.

### 2.2 Affiliate Links (`app/services/affiliate_links.py`)

The affiliate system provides:
- `create_affiliate_link()`: Creates tracking codes with commission percentages
- `record_affiliate_click()`: Records a click event for a tracking code
- `record_affiliate_conversion()`: Records a conversion (purchase) linked to a tracking code
- `get_affiliate_stats()`: Returns click count, conversion count, commission earned
- `generate_tracking_code()`: Generates unique 8-char tracking codes

Tracking codes are stored in the `AffiliateLinks` table (`T.affiliate_links`, `S.affiliate_links_table_name`).

**Key functions** used by this feature:
- `get_link_by_code(code)`: Look up affiliate link by tracking code
- `record_affiliate_click(code, ip, user_agent)`: Record a click on a tracking code
- `record_affiliate_conversion(code, transaction_id, amount_cents)`: Record a conversion

### 2.3 Promo Codes (`app/services/promo_codes.py`)

The promo code system provides:
- `create_promo_code()`: Creates a discount code with type (percentage, fixed_amount, free_trial)
- `validate_promo_code()`: Checks if a code is valid, not expired, not at max redemptions
- `redeem_promo_code()`: Records redemption and applies discount
- `get_promo_stats()`: Returns redemption count, total discount applied

Promo codes stored in the `PromoCodes` table (`T.promo_codes`, `S.promo_codes_table_name`).

**Checkout types** supported by promo codes: `subscription`, `vod`, `shop`.

### 2.4 Ad Click Handling

Currently, ad clicks are tracked in the `AdImpressions` table with `event_type="click"`. There is no redirect mechanism, no affiliate attribution on click, and no promo code attachment.

### 2.5 Checkout Flow

The existing checkout flow (catalog purchases, subscriptions, VOD purchases) reads a promo code from the request body. There is no mechanism to auto-fill the promo code from a cookie or session state.

### 2.6 Gaps

1. No `affiliate_code`, `promo_code`, or `promo_value_display` fields on ad creatives
2. No affiliate click recording when an ad is clicked
3. No promo code cookie mechanism for auto-apply at checkout
4. No promo badge overlay rendering on ad creatives
5. No ROAS calculation linking affiliate conversions to ad campaigns
6. No dual revenue (ad CPM + affiliate commission) for creators hosting ads

---

## 3. Technical Design

### 3.1 DynamoDB Access Patterns

| Access Pattern | Table | Key | Operation | Description |
|---|---|---|---|---|
| Get creative with affiliate/promo fields | `ad_creatives` | PK=`ACCT#{account_id}`, SK=`CREATIVE#{creative_id}` | GetItem | Read creative including new fields |
| Update creative with affiliate/promo | `ad_creatives` | PK=`ACCT#{account_id}`, SK=`CREATIVE#{creative_id}` | UpdateItem | Set affiliate_code, promo_code, promo_value_display |
| Validate affiliate code exists | `affiliate_links` | PK=`CODE#{code}`, SK=`META` | GetItem | Check code exists and belongs to advertiser |
| Validate promo code exists | `promo_codes` | PK=`CODE#{code}`, SK=`META` | GetItem | Check code exists and belongs to advertiser |
| Record affiliate click | `affiliate_links` | PK=`CODE#{code}`, SK=`CLICK#{ts}#{id}` | PutItem | Click event record |
| Record affiliate conversion | `affiliate_links` | PK=`CODE#{code}`, SK=`CONV#{ts}#{id}` | PutItem | Conversion record with campaign_id |
| Get ROAS data | `ad_billing` (GSI ByCampaign) + `affiliate_links` | PK=campaign_id | Query | Ad spend + affiliate conversions |
| Write ad click event | `ad_impressions` | PK=`AD_IMP#{date}`, SK=event key | PutItem | Click event |

#### Example DynamoDB Items (JSON)

**Ad Creative with Affiliate/Promo Fields**:
```json
{
  "pk": {"S": "ACCT#acct_adv001"},
  "sk": {"S": "CREATIVE#creat_xyz789"},
  "creative_id": {"S": "creat_xyz789"},
  "advertiser_account_id": {"S": "acct_adv001"},
  "name": {"S": "Summer Sale Banner"},
  "type": {"S": "image"},
  "asset_url": {"S": "https://cdn.example.com/ads/summer-sale.png"},
  "click_through_url": {"S": "https://shop.com/summer-sale"},
  "status": {"S": "approved"},
  "affiliate_code": {"S": "ABC12345"},
  "promo_code": {"S": "SUMMER20"},
  "promo_value_display": {"S": "20% OFF"},
  "created_at": {"N": "1748534400"}
}
```

**Affiliate Conversion with Campaign Attribution**:
```json
{
  "pk": {"S": "CODE#ABC12345"},
  "sk": {"S": "CONV#1748534900#conv_g7h8i9"},
  "conversion_id": {"S": "conv_g7h8i9"},
  "code": {"S": "ABC12345"},
  "transaction_id": {"S": "txn_12345"},
  "amount_cents": {"N": "4000"},
  "campaign_id": {"S": "camp_abc123"},
  "creative_id": {"S": "creat_xyz789"},
  "source": {"S": "ad_creative"},
  "created_at": {"N": "1748534900"}
}
```

### 3.2 Creative Schema Extension

**Ad creative record** — add fields:

```python
# New fields on ad creative record (ad_creatives table)
affiliate_code: Optional[str]        # Tracking code from affiliate_links
promo_code: Optional[str]            # Discount code from promo_codes
promo_value_display: Optional[str]   # Display text: "20% OFF", "$10 OFF"
```

### 3.3 Creative Validation

When creating/updating a creative with `affiliate_code` or `promo_code`, the service validates:

```python
def validate_creative_affiliate_promo(
    *, affiliate_code: Optional[str], promo_code: Optional[str],
    advertiser_id: str,
) -> tuple[Optional[str], Optional[str]]:
    """Validate affiliate code and promo code exist and belong to advertiser.

    Returns (error_message, None) or (None, validated_data).
    """
    if affiliate_code:
        link = get_link_by_code(affiliate_code)
        if not link:
            return "Affiliate code not found", None
        if link.get("creator_id") != advertiser_id:
            return "Affiliate code does not belong to this account", None

    if promo_code:
        code_record = get_promo_by_code(promo_code)
        if not code_record:
            return "Promo code not found", None
        if code_record.get("creator_id") != advertiser_id:
            return "Promo code does not belong to this account", None

    return None, {"affiliate_code": affiliate_code, "promo_code": promo_code}
```

### 3.4 Ad Click Handler with Attribution

**File**: `app/services/ad_click_handler.py`

```python
"""Ad click handler with affiliate attribution and promo cookie (ADS-015).

When a user clicks an ad creative:
1. Record the ad click event (existing)
2. If creative has affiliate_code: record affiliate click
3. If creative has promo_code: set promo auto-apply cookie
4. Redirect to click_through_url with tracking params
"""

def handle_ad_click(
    *,
    creative_id: str,
    user_id: str,
    ip_address: str,
    user_agent: str,
    campaign_id: str,
) -> Dict[str, Any]:
    """Process an ad click event.

    Returns redirect URL and any cookies to set.
    """
    creative = get_creative(creative_id)
    if not creative:
        raise HTTPException(404, "Creative not found")

    # 1. Record ad click
    record_ad_impression(
        video_id="",  # Not always a video context
        user_id=user_id,
        slot_type="click",
        slot_index=0,
        creative_id=creative_id,
        event_type="click",
        campaign_id=campaign_id,
    )

    # 2. Record affiliate click if applicable
    affiliate_code = creative.get("affiliate_code")
    if affiliate_code:
        from app.services.affiliate_links import record_affiliate_click
        record_affiliate_click(
            code=affiliate_code,
            ip_address=ip_address,
            user_agent=user_agent,
            source="ad_creative",
            source_id=creative_id,
        )

    # 3. Prepare redirect URL with tracking params
    redirect_url = creative.get("click_through_url", "/")
    if affiliate_code:
        separator = "&" if "?" in redirect_url else "?"
        redirect_url += f"{separator}ref={affiliate_code}"

    # 4. Prepare promo cookie
    promo_code = creative.get("promo_code")
    cookies = {}
    if promo_code:
        cookies["ad_promo_code"] = {
            "value": promo_code,
            "max_age": 86400,  # 24 hours
            "path": "/",
            "httponly": False,  # JS needs to read it
            "samesite": "lax",
        }

    return {
        "redirect_url": redirect_url,
        "cookies": cookies,
        "affiliate_code": affiliate_code,
        "promo_code": promo_code,
    }
```

### 3.5 Ad Click Endpoint

**File**: `app/routers/ad_serving.py` (extend existing ad serving router)

```python
@router.get("/ui/ads/click/{creative_id}")
async def ad_click_redirect(
    creative_id: str,
    campaign_id: str = "",
    request: Request = None,
    session: dict = Depends(require_ui_session),
):
    """Handle ad click: record click, set cookies, redirect.

    Returns 302 redirect to click_through_url.
    Sets ad_promo_code cookie if creative has a promo code.
    """
    result = handle_ad_click(
        creative_id=creative_id,
        user_id=session["user_sub"],
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        campaign_id=campaign_id,
    )

    response = RedirectResponse(url=result["redirect_url"], status_code=302)
    for name, cookie_config in result.get("cookies", {}).items():
        response.set_cookie(name, **cookie_config)

    return response
```

### 3.6 Promo Code Auto-Apply

**Frontend**: Read `ad_promo_code` cookie and auto-fill in checkout forms.

**File**: `frontend/src/pages/shop/CheckoutPage.tsx` (and similar checkout pages)

```typescript
useEffect(() => {
  // Check for ad promo code cookie
  const adPromo = document.cookie
    .split("; ")
    .find(row => row.startsWith("ad_promo_code="))
    ?.split("=")[1];
  if (adPromo && !promoCode) {
    setPromoCode(adPromo);
    // Clear the cookie after applying
    document.cookie = "ad_promo_code=; max-age=0; path=/";
    // Validate the code
    validatePromoMutation.mutate(adPromo);
  }
}, []);
```

### 3.7 ROAS Calculation

**File**: `app/services/ad_roas.py`

```python
"""Return on Ad Spend (ROAS) calculation (ADS-015).

Links affiliate conversions back to ad campaigns for ROAS metrics.
ROAS = conversion_revenue / ad_spend
"""

def calculate_campaign_roas(
    *, campaign_id: str, start_date: str, end_date: str
) -> Dict[str, Any]:
    """Calculate ROAS for a campaign over a date range.

    Steps:
    1. Get total ad spend for campaign
    2. Get all creatives for campaign
    3. For each creative with affiliate_code: sum affiliate conversions
    4. ROAS = total_conversion_revenue / total_ad_spend

    Returns:
    {
        "campaign_id": str,
        "ad_spend_cents": int,
        "conversion_revenue_cents": int,
        "roas": float,  # e.g., 3.5 means $3.50 revenue per $1 spent
        "conversions": int,
        "conversion_rate": float,
    }
    """
    ...
```

### 3.8 Creator Dual Revenue

When an ad with an affiliate code runs on a creator's content:

```
Ad impression "complete" event
    │
    ├── CPM ad revenue → creator wallet (existing, ad_placement.py)
    │
    └── If affiliate conversion occurs:
        └── Affiliate commission → creator wallet (existing, affiliate_links.py)
```

Both revenue streams are tracked independently:
- Ad revenue: billing ledger entry with `entry_type="ad_revenue_credit"`
- Affiliate commission: billing ledger entry with `entry_type="affiliate_commission"`

The creator's earnings dashboard should show both streams. The ROAS calculation includes both.

### 3.9 Promo Badge Rendering

**Frontend**: Ad display components render a promo badge overlay when the creative has `promo_value_display`.

**File**: `frontend/src/components/shared/AdCreativeDisplay.tsx`

```tsx
interface AdCreativeDisplayProps {
  creative: AdCreative;
  onClick: () => void;
}

function AdCreativeDisplay({ creative, onClick }: AdCreativeDisplayProps) {
  return (
    <div className="relative cursor-pointer" onClick={onClick}>
      {creative.type === "image" ? (
        <img src={creative.asset_url} alt={creative.name} />
      ) : (
        <video src={creative.asset_url} />
      )}

      {creative.promo_value_display && (
        <div className="absolute top-2 right-2 bg-red-600 text-white text-xs
                        font-bold px-2 py-1 rounded-md shadow-lg">
          {creative.promo_value_display}
        </div>
      )}
    </div>
  );
}
```

### 3.10 Pydantic Models

**File**: `app/models.py`

```python
class AdCreativeAffiliatePromo(BaseModel):
    """Fields for affiliate/promo attachment to ad creatives."""
    affiliate_code: Optional[str] = Field(default=None, max_length=20)
    promo_code: Optional[str] = Field(default=None, max_length=30)
    promo_value_display: Optional[str] = Field(default=None, max_length=50)

class AdClickResult(BaseModel):
    redirect_url: str
    affiliate_code: Optional[str] = None
    promo_code: Optional[str] = None

class CampaignRoasOut(BaseModel):
    campaign_id: str
    ad_spend_cents: int
    conversion_revenue_cents: int
    roas: float
    conversions: int
    conversion_rate: float
    period_start: str
    period_end: str
```

### 3.11 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdCreativeAffiliatePromo {
  affiliate_code?: string | null;
  promo_code?: string | null;
  promo_value_display?: string | null;
}

export interface CampaignRoas {
  campaign_id: string;
  ad_spend_cents: number;
  conversion_revenue_cents: number;
  roas: number;
  conversions: number;
  conversion_rate: number;
  period_start: string;
  period_end: string;
}
```

### 3.12 Frontend Component Tree

```
AdCreativeDisplay (shared component)
├── Props: { creative: AdCreative, onClick: () => void }
├── ImageAdCreative | VideoAdCreative (based on creative.type)
├── PromoBadge (overlay, visible when promo_value_display is set)
│   ├── Positioned: absolute top-2 right-2
│   ├── Style: bg-red-600 text-white text-xs font-bold
│   └── Content: creative.promo_value_display (e.g., "20% OFF")
└── ClickHandler
    └── Navigates to /ui/ads/click/{creative_id}?campaign_id=...

CheckoutPage (modified)
├── PromoCodeInput (existing)
│   └── useEffect: reads ad_promo_code cookie and auto-fills
├── PromoValidation: validatePromoMutation
└── PromoDisplay: shows applied discount

CreativeEditorForm (modified, in ads management page)
├── Existing fields (name, type, asset, click_through_url)
├── AffiliateCodeField (NEW)
│   ├── Input with autocomplete from user's affiliate links
│   └── Validation: code exists and belongs to advertiser
├── PromoCodeField (NEW)
│   ├── Input with autocomplete from user's promo codes
│   └── Validation: code exists and belongs to advertiser
└── PromoValueDisplayField (NEW)
    ├── Input: "Enter display text, e.g., 20% OFF"
    └── Preview: renders PromoBadge with entered text

CampaignRoasCard (in campaign detail view)
├── Props: { campaignId, startDate, endDate }
├── State: useQuery(["campaign-roas", campaignId])
├── ROAS value: "3.5x" (conversion revenue / ad spend)
├── Conversions: count
├── Conversion rate: percentage
├── Ad spend: formatted cents
└── Conversion revenue: formatted cents
```

---

## 4. API Request/Response Examples

### 4.1 Create Creative with Affiliate & Promo

```bash
curl -X POST http://localhost:8000/ui/ads/accounts/acct_adv001/creatives \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001" \
  -d '{
    "name": "Summer Sale Banner",
    "type": "image",
    "asset_url": "https://cdn.example.com/ads/summer-sale.png",
    "click_through_url": "https://shop.com/summer-sale",
    "affiliate_code": "ABC12345",
    "promo_code": "SUMMER20",
    "promo_value_display": "20% OFF"
  }'

# Response (201 Created)
{
  "creative_id": "creat_xyz789",
  "name": "Summer Sale Banner",
  "type": "image",
  "asset_url": "https://cdn.example.com/ads/summer-sale.png",
  "click_through_url": "https://shop.com/summer-sale",
  "affiliate_code": "ABC12345",
  "promo_code": "SUMMER20",
  "promo_value_display": "20% OFF",
  "status": "draft"
}
```

### 4.2 Ad Click Redirect

```bash
# Browser navigates to this URL when user clicks an ad
curl -v http://localhost:8000/ui/ads/click/creat_xyz789?campaign_id=camp_abc123 \
  -H "Cookie: ui_session=sess_bob; ui_access_token=eyJ..."

# Response (302 Found)
# Location: https://shop.com/summer-sale?ref=ABC12345
# Set-Cookie: ad_promo_code=SUMMER20; Max-Age=86400; Path=/; SameSite=Lax
```

### 4.3 Get Campaign ROAS

```bash
curl "http://localhost:8000/ui/ads/campaigns/camp_abc123/roas?start_date=2026-05-01&end_date=2026-05-31" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ..."

# Response (200 OK)
{
  "campaign_id": "camp_abc123",
  "ad_spend_cents": 5000,
  "conversion_revenue_cents": 17500,
  "roas": 3.5,
  "conversions": 12,
  "conversion_rate": 0.023,
  "period_start": "2026-05-01",
  "period_end": "2026-05-31"
}
```

---

## 5. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Affiliate code not found | 400 | `invalid_affiliate_code` | "Affiliate code not found" | Create the affiliate link first |
| Affiliate code belongs to another user | 403 | `affiliate_code_mismatch` | "Affiliate code does not belong to this account" | Use your own affiliate code |
| Promo code not found | 400 | `invalid_promo_code` | "Promo code not found" | Create the promo code first |
| Promo code belongs to another user | 403 | `promo_code_mismatch` | "Promo code does not belong to this account" | Use your own promo code |
| Creative not found (click handler) | 404 | `creative_not_found` | "Ad creative not found" | Check creative ID |
| Non-owner views ROAS | 403 | `forbidden` | "You do not own this campaign" | Use your own campaign |
| ROAS with no ad spend | 200 | — | `roas: 0, conversions: 0` | Run the campaign to accumulate spend |
| Invalid date range for ROAS | 400 | `invalid_date_range` | "start_date must be before end_date" | Fix date parameters |
| Promo code expired at checkout auto-apply | 200 | — | Cookie auto-fills but validation returns "expired" | User sees "Code expired" message |
| Affiliate click recording failure | 200 | — | (best-effort; redirect still works) | Log warning; affiliate stats may be slightly low |
| Session expired | 401 | `unauthorized` | "Session expired" | Re-authenticate |

---

## 6. Implementation Plan

### 6.1 Backend — Phase 1: Creative Extension (Days 1-2)

1. **Ad creative schema**: Add `affiliate_code`, `promo_code`, `promo_value_display` fields to ad creative records.
2. **`app/services/ad_creative_affiliate.py`**: New file. Validation of affiliate/promo code ownership, creative update helpers.
3. **Creative CRUD update**: Extend creative create/update endpoints to accept and validate affiliate/promo fields.

### 6.2 Backend — Phase 2: Click Handler & Attribution (Days 3-4)

4. **`app/services/ad_click_handler.py`**: New file. Ad click processing with affiliate click recording and promo cookie preparation.
5. **`app/routers/ad_serving.py`**: Add `/ui/ads/click/{creative_id}` redirect endpoint.
6. **`app/services/affiliate_links.py`**: Extend `record_affiliate_click()` to accept `source` and `source_id` params for attribution.

### 6.3 Backend — Phase 3: ROAS & Conversion Linking (Days 5-6)

7. **`app/services/ad_roas.py`**: New file. ROAS calculation linking affiliate conversions to ad campaigns.
8. **ROAS endpoint**: Add `GET /ui/ads/campaigns/{id}/roas` to the ads router.
9. **Conversion attribution**: Extend `record_affiliate_conversion()` to store `campaign_id` when the affiliate code is linked to a creative.

### 6.4 Frontend (Days 6-7)

10. **`frontend/src/components/shared/AdCreativeDisplay.tsx`**: Add promo badge overlay rendering.
11. **Creative editor**: Add affiliate code and promo code fields to the creative creation/editing form.
12. **Checkout auto-apply**: Add `ad_promo_code` cookie reading and auto-fill in checkout pages.
13. **ROAS display**: Add ROAS metrics to campaign detail view.

### 6.5 E2E Tests (Days 7-8)

14. **`frontend/e2e/ad-affiliate-promo.spec.ts`**: New file. 18 tests across 4 sections.

---

## 7. Security Considerations

### 7.1 Affiliate Code Ownership

- Creative can only use affiliate codes that belong to the same advertiser account.
- Server-side validation prevents using another advertiser's tracking codes.

### 7.2 Promo Code Cookie

- `ad_promo_code` cookie is `httponly: false` (frontend JS needs to read it) but `samesite: lax`.
- Cookie cleared after auto-apply to prevent stale discounts.
- Max-age: 24 hours (promo only applies if checkout happens within a day of the ad click).

### 7.3 Redirect URL Safety

- `click_through_url` is validated at creative creation time (must be HTTPS or relative path).
- Redirect endpoint uses 302 (not 301) to prevent browser caching.

### 7.4 ROAS Data Access

- ROAS metrics are visible only to the campaign's advertiser.
- Creators see their own ad revenue and affiliate commissions but not advertiser ROAS.

---

## 8. Testing Strategy

### 8.1 Unit Tests (`tests/test_ad_affiliate_promo.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Creative with valid affiliate code stores correctly | Code saved on creative record |
| 2 | Creative with invalid affiliate code rejected | 400: code not found |
| 3 | Creative with another user's code rejected | 403: code ownership mismatch |
| 4 | Ad click records affiliate click | Affiliate click count increases |
| 5 | Ad click sets promo cookie | Response includes set-cookie header |
| 6 | ROAS calculation correct | spend=1000, conversions=500 -> ROAS=0.5 |

### 8.2 E2E Tests (`frontend/e2e/ad-affiliate-promo.spec.ts`)

**Test File**: `frontend/e2e/ad-affiliate-promo.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (advertiser/creator), Bob (consumer)
- Create an affiliate link as Alice (tracking code)
- Create a promo code as Alice (20% off)
- Create an ad creative as Alice with affiliate_code and promo_code

**Section 405: Creative Affiliate & Promo Fields (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Create creative with affiliate code` | POST creative with affiliate_code -> 201, affiliate_code saved |
| 2 | `Create creative with promo code and badge text` | POST with promo_code + promo_value_display -> 201, both saved |
| 3 | `Invalid affiliate code rejected` | POST with nonexistent affiliate_code -> 400 |
| 4 | `Get creative includes affiliate and promo fields` | GET creative -> response has affiliate_code, promo_code, promo_value_display |
| 5 | `Another user's affiliate code rejected` | POST with Bob's affiliate_code -> 403 |

**Section 406: Ad Click Attribution (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | `Ad click records affiliate click` | GET /ads/click/{creative_id} -> 302 redirect; affiliate click count increased |
| 7 | `Redirect URL includes ref param` | 302 Location header contains ?ref={affiliate_code} |
| 8 | `Ad click without affiliate code still redirects` | Creative without affiliate_code -> 302 to click_through_url, no ref param |
| 9 | `Multiple clicks from same user tracked` | 3 clicks -> affiliate click count = 3 |
| 10 | `Click on creative without promo sets no cookie` | Verify no ad_promo_code cookie in response |

**Section 407: ROAS Calculation (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | `ROAS with no conversions returns 0` | GET /campaigns/{id}/roas -> roas=0, conversions=0 |
| 12 | `ROAS calculated after conversion` | Record affiliate conversion -> GET /roas -> roas > 0 |
| 13 | `ROAS includes conversion count and revenue` | Response has conversions, conversion_revenue_cents fields |
| 14 | `Non-owner cannot view campaign ROAS` | GET /campaigns/{id}/roas as Bob -> 403 |

**Section 408: Edge Cases & Concurrent Access (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 15 | `Creative with both affiliate and promo stored correctly` | Both fields present in GET response |
| 16 | `Update creative to remove affiliate code` | PATCH with affiliate_code=null -> field cleared |
| 17 | `Promo code validation at creative creation` | Expired promo code -> 400 |
| 18 | `ROAS calculation with zero ad spend returns 0` | No impressions -> ad_spend_cents=0, roas=0 |

---

## 9. Observability & Monitoring

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ad_click_redirect_total` | Counter | `has_affiliate`, `has_promo` | Total ad click redirects |
| `ad_affiliate_click_total` | Counter | — | Affiliate clicks attributed to ads |
| `ad_promo_cookie_set_total` | Counter | — | Promo cookies set via ad clicks |
| `ad_roas_queries_total` | Counter | — | ROAS calculation requests |
| `ad_promo_auto_applied_total` | Counter | — | Promo codes auto-applied from cookie at checkout |

### 9.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `ad_click_redirect` | INFO | `creative_id`, `campaign_id`, `affiliate_code`, `promo_code`, `user_id` | Ad click processed |
| `ad_affiliate_click_recorded` | INFO | `affiliate_code`, `creative_id`, `user_id` | Affiliate click recorded from ad |
| `ad_promo_auto_applied` | INFO | `promo_code`, `user_id`, `checkout_type` | Promo code auto-applied at checkout |
| `ad_roas_calculated` | INFO | `campaign_id`, `roas`, `conversions`, `ad_spend_cents` | ROAS calculation completed |

### 9.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Click redirect failures | `rate(5xx on /ui/ads/click) > 5/min` | Warning | Check creative lookup or affiliate service |
| Low conversion rate | ROAS < 0.5 for campaigns spending > $100 | Info | Review targeting and creative quality |

---

## 10. Rollout Plan

### 10.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AD_AFFILIATE_PROMO_ENABLED` | `false` | When false, affiliate/promo fields are ignored on creatives |
| `AD_PROMO_COOKIE_ENABLED` | `false` | When false, no promo cookie is set on ad clicks |
| `AD_ROAS_ENABLED` | `false` | When false, ROAS endpoint returns 404 |

### 10.2 Migration Steps

1. **Phase 1 — Schema extension**: Add nullable `affiliate_code`, `promo_code`, `promo_value_display` to ad creative records. No application behavior change.
2. **Phase 2 — Click handler**: Deploy click redirect endpoint. Clicks are processed but affiliate/promo features gated by flags.
3. **Phase 3 — Enable affiliate attribution**: Set `AD_AFFILIATE_PROMO_ENABLED=true`. Affiliate clicks recorded on ad clicks.
4. **Phase 4 — Enable promo cookies**: Set `AD_PROMO_COOKIE_ENABLED=true`. Checkout auto-apply begins.
5. **Phase 5 — Enable ROAS**: Set `AD_ROAS_ENABLED=true`. Advertisers can view conversion attribution.

### 10.3 Rollback Procedure

1. Set all flags to `false`. Affiliate/promo features disabled.
2. Existing creatives retain their affiliate_code/promo_code fields (harmless).
3. Promo cookies already set expire within 24 hours.

---

## 11. Performance Considerations

### 11.1 Click Handler Latency

The click handler must respond quickly (user is waiting for redirect):
- GetItem for creative: ~5ms
- PutItem for click event: ~5ms (fire-and-forget)
- PutItem for affiliate click: ~5ms (fire-and-forget)
- **Total target: < 50ms**

The affiliate click and ad event recordings are fire-and-forget (logged but non-blocking for the redirect).

### 11.2 ROAS Calculation Cost

ROAS queries the `ad_billing` GSI (ByCampaign) for ad spend and the `affiliate_links` table for conversions. For campaigns with >10K entries, the query may take 200-500ms. Pre-aggregate ROAS daily using a background task for frequently-queried campaigns.

### 11.3 Cookie Overhead

The `ad_promo_code` cookie adds ~30 bytes to each subsequent request. It is cleared after first use at checkout, limiting the overhead to a single session.

---

## 12. Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_click_handler.py` | Ad click processing with attribution |
| `app/services/ad_creative_affiliate.py` | Creative affiliate/promo validation |
| `app/services/ad_roas.py` | ROAS calculation |
| `frontend/src/components/shared/AdCreativeDisplay.tsx` | Ad display with promo badge |
| `frontend/e2e/ad-affiliate-promo.spec.ts` | E2E tests (18 tests, sections 405-408) |
| `tests/test_ad_affiliate_promo.py` | Unit tests |

## 13. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add affiliate/promo Pydantic models |
| `app/services/affiliate_links.py` | Extend `record_affiliate_click()` with source params |
| `app/routers/ad_serving.py` | Add `/ui/ads/click/{creative_id}` endpoint |
| `frontend/src/api/types.ts` | Add affiliate/promo TypeScript types |
| `frontend/src/pages/shop/CheckoutPage.tsx` | Add promo cookie auto-apply logic |

## 14. Acceptance Criteria

1. Ad creatives can be created with optional `affiliate_code`, `promo_code`, and `promo_value_display` fields
2. Affiliate and promo codes are validated for existence and ownership at creative creation time
3. Ad clicks record an affiliate click event when the creative has an `affiliate_code`
4. Redirect URL includes `?ref={affiliate_code}` parameter for attribution tracking
5. Promo code cookie is set on ad click and auto-fills at checkout
6. Promo badge overlay renders on ad creatives that have `promo_value_display`
7. ROAS calculation links affiliate conversions to ad campaign spend
8. Creators hosting ads with affiliate codes earn both ad CPM revenue and affiliate commissions
9. All 18 E2E tests pass in `frontend/e2e/ad-affiliate-promo.spec.ts`

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/affiliate_links.py` | — | Existing affiliate link service (click tracking, conversions, commissions) |
| `app/services/promo_codes.py` | — | Existing promo code service (discount codes, redemption tracking) |
| `app/core/tables.py` | 103, 112 | `promo_codes` table handle (line 103), `affiliate_links` table handle (line 112) |
| `app/core/settings.py` | 1366, 1440 | `promo_codes_table_name` (line 1366), `affiliate_links_table_name` (line 1440) |
| `app/services/ad_creative_affiliate.py` | — | Does not exist yet — new implementation required |
