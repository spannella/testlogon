# GROUP-003: Group Advertising & External Fundraising

**Ticket**: GROUP-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days
**Dependencies**: GROUP-001 (Membership), GROUP-004 (Treasury), ADS-001 (Advertiser Accounts)

---

## 1. Overview & Motivation

### 1.1 Purpose

GROUP-003 adds two capabilities: (1) group-level advertising campaigns funded by the group treasury, and (2) external fundraising via a public donation page. Advertising lets groups promote themselves to attract new members. External fundraising lets groups accept donations from anyone — including non-platform-users — via a public page with optional goal tracking and a progress bar. Donations flow into the group treasury (GROUP-004).

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Admin | As an admin, I want to create an ad campaign to promote my group. | POST creates campaign; budget drawn from group treasury. |
| Admin | As an admin, I want to set a daily and total budget. | Budget fields validated; campaign pauses when exhausted. |
| Admin | As an admin, I want to pause and resume campaigns. | PATCH status; ads stop/start serving. |
| Admin | As an admin, I want to see campaign performance. | GET stats; impressions, clicks, spend displayed. |
| Admin | As an admin, I want to create a fundraiser with an optional goal. | POST creates fundraiser; goal + description stored. |
| Donor | As a non-member, I want to donate via a public page. | Public page; payment form; receipt returned. |
| Donor | As a donor, I want to see the goal and progress. | Progress bar shows raised vs. goal. |
| Admin | As an admin, I want to see all donations. | GET donation list; sorted by date. |

### 1.3 Why This Is Needed

Groups need a way to grow membership and fund activities. Advertising uses the platform's existing ad infrastructure (ADS-001). External fundraising opens a revenue channel for community projects, charity drives, and operational costs. Together, these turn groups from passive communities into active organizations.

### 1.4 Fundraising Flow

```
Donor visits public donation page -> sees group info + progress bar
  -> enters amount + optional name/email -> payment processed (Stripe)
  -> donation record created -> treasury credited -> receipt shown
```

---

## 2. Architecture & Data Flow

### 2.1 Advertising Campaign Creation Flow

```
Admin clicks "Create Campaign" on GroupAdsPage
  |
  v
POST /ui/groups/{group_id}/campaigns
  { name, daily_budget_cents, lifetime_budget_cents, creative_text, creative_image_url }
  |
  v
+-----------------------------------+
| group_advertising.py              |
| create_group_campaign()           |
+-----------------------------------+
  |
  +---> 1. Verify admin role
  |        PK=GROUP#{group_id}, SK=MEMBER#{user_id}
  |        role must be "admin"
  |
  +---> 2. Check linked advertiser account
  |        PK=GROUP#{group_id}, SK=ADVERTISER
  |        If not found -> 400 "No linked advertiser account"
  |
  +---> 3. Check treasury balance (GROUP-004)
  |        get_treasury_balance(group_id)
  |        If balance < lifetime_budget_cents -> 400 "Insufficient treasury"
  |
  +---> 4. Reserve funds from treasury
  |        spend_treasury(group_id, admin_id, lifetime_budget_cents,
  |                       reason="Ad campaign budget", category="ad_spend")
  |
  +---> 5. Create campaign in ad_campaigns table
  |        (Uses ADS-001 campaign hierarchy)
  |
  +---> 6. Return campaign details
  |
  v
201 Created { campaign_id, name, status, budget, ... }
```

### 2.2 External Donation Flow

```
Donor visits /donate/{fundraiser_id} (no auth required)
  |
  v
GET /public/fundraisers/{fundraiser_id}
  -> Returns title, description, goal, raised_cents, group_name
  |
  v
Donor fills amount + optional name/email + submits
  |
  v
POST /public/fundraisers/{fundraiser_id}/donate
  { amount_cents, donor_name?, donor_email? }
  |
  v
+-----------------------------------+
| group_fundraising.py              |
| create_donation()                 |
+-----------------------------------+
  |
  +---> 1. Validate fundraiser is active
  |        PK=GROUP#{group_id}, SK=FUNDRAISER#{fundraiser_id}
  |        status must be "active"
  |
  +---> 2. Create Stripe Checkout Session
  |        (stripe-mock on port 12111 in dev)
  |        -> Returns checkout_session_id + payment_intent_id
  |
  +---> 3. Write DONATION record (status=pending)
  |        PK=FUNDRAISER#{fundraiser_id}, SK=DONATION#{donation_id}
  |
  +---> 4. Return donation_id + checkout_url
  |
  v
201 { donation_id, checkout_url }
  |
  v
Stripe webhook / confirm endpoint
  |
  v
+-----------------------------------+
| group_fundraising.py              |
| confirm_donation()                |
+-----------------------------------+
  |
  +---> 1. Set donation status=completed
  +---> 2. Atomic increment raised_cents on fundraiser
  +---> 3. Credit treasury via GROUP-004 credit_donation()
  +---> 4. If raised_cents >= goal_cents, auto-set status=completed
  |
  v
200 { ok: true, receipt_url }
```

### 2.3 Campaign Performance Query Flow

```
GET /ui/groups/{group_id}/campaigns/{campaign_id}/stats
  |
  v
+-----------------------------------+
| group_advertising.py              |
| get_group_campaign_stats()        |
+-----------------------------------+
  |
  +---> Query ad_impressions table
  |        PK=CAMPAIGN#{campaign_id}
  |        Aggregate: impressions, clicks, spend
  |
  +---> Compute CTR = clicks / impressions
  +---> Compute remaining_budget = lifetime_budget - spent
  |
  v
200 { impressions, clicks, ctr, spent_cents, remaining_cents }
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

- **Ad platform** (`app/services/ad_placement.py`): VOD ad slot calculation, `record_ad_impression()` (see `app/services/ad_placement.py:222`), `_credit_ad_revenue()` (see `:279`). ADS-001 defines campaign hierarchy (Account > Campaign > Ad Group > Creative) and budget tracking. <!-- NOTE: ad_placement.py is VOD-specific (video ads); no generic campaign management or group-campaign linking exists yet -->
- **Advertiser accounts** (ADS-001): `ad_accounts` table. <!-- NOTE: ad_accounts table does not exist in scripts/local-ddb-init.py — must be created by ADS-001 dependency --> Any user can create an advertiser account. Group campaigns create a group-linked account.
- **Stripe** (`app/services/billing_shared.py`): Mock Stripe on port 12111. For external donations, Stripe Checkout Session handles payment method collection without requiring a platform account. <!-- NOTE: Stripe Checkout Session API is not currently used in the codebase; existing Stripe usage is PaymentIntent-based (see app/services/billing_reconcile.py:86, app/services/payment_incident_stripe_adapter.py:159). Checkout Session will be a new integration. -->
- **Billing ledger**: `new_ledger_entry()` (see `app/services/billing_shared.py:217`) with `pk`, `sk=LEDGER#{ts}#{entry_id}`, `amount_cents`, `reason`, `type` (NOT `direction` — field is `type`, see `:217`). Group treasury uses the same pattern with `pk=GROUP#{group_id}`.

### 3.2 Gaps

1. No group-to-advertiser-account link.
2. No treasury-to-ad-budget flow.
3. No fundraising model or donation records.
4. No public donation page or payment flow.
5. No fundraising goal tracking.
6. No frontend for group ads or fundraising.

---

## 4. Detailed DynamoDB Access Patterns

| # | Operation | Table | PK | SK / GSI | Condition / Filter | Notes |
|---|-----------|-------|-----|----------|-------------------|-------|
| 1 | Link advertiser account | `user_groups` | `GROUP#{group_id}` | `SK=ADVERTISER` | `attribute_not_exists(sk)` (no overwrite) | One-time link | <!-- NOTE: user_groups table does not exist yet — must be created by GROUP-001 -->
| 2 | Get advertiser link | `user_groups` | `GROUP#{group_id}` | `SK=ADVERTISER` | None | Check before campaign create |
| 3 | Create fundraiser | `user_groups` | `GROUP#{group_id}` | `SK=FUNDRAISER#{fundraiser_id}` | None | New item |
| 4 | List fundraisers | `user_groups` | `GROUP#{group_id}` | `SK begins_with FUNDRAISER#` | None | Paginated query |
| 5 | Get fundraiser | `user_groups` | `GROUP#{group_id}` | `SK=FUNDRAISER#{fundraiser_id}` | None | Single get |
| 6 | Update fundraiser | `user_groups` | `GROUP#{group_id}` | `SK=FUNDRAISER#{fundraiser_id}` | `attribute_exists(sk)` | Admin-only fields |
| 7 | Create donation | `user_groups` | `FUNDRAISER#{fundraiser_id}` | `SK=DONATION#{donation_id}` | None | New item |
| 8 | Confirm donation (increment) | `user_groups` | `GROUP#{group_id}` | `SK=FUNDRAISER#{fundraiser_id}` | None | `ADD raised_cents :amt, donation_count :one` |
| 9 | List donations | `user_groups` | `FUNDRAISER#{fundraiser_id}` | `SK begins_with DONATION#` | `ScanIndexForward=False` | Admin/mod only; paginated |
| 10 | Get donation receipt | `user_groups` | `FUNDRAISER#{fundraiser_id}` | `SK=DONATION#{donation_id}` | `status = completed` | Public, requires completed status |
| 11 | Campaign stats | `ad_impressions` | `CAMPAIGN#{campaign_id}` | Aggregate | None | Pre-aggregated | <!-- NOTE: AdImpressions table exists (local-ddb-init.py:831) but GSIs are ByVideoCreatedAt and ByCreatorCreatedAt — no CAMPAIGN# PK pattern exists; would need new access pattern or GSI -->
| 12 | List campaigns | `ad_campaigns` | By `advertiser_account_id` GSI | None | None | Via ADS-001 infrastructure | <!-- NOTE: ad_campaigns table does not exist yet — must be created by ADS-001 dependency -->

**Key query example -- fundraiser atomic increment:**
```python
T.user_groups.update_item(  # NOTE: T.user_groups table handle does not exist yet in app/core/tables.py — must be added by GROUP-001
    Key={"pk": f"GROUP#{group_id}", "sk": f"FUNDRAISER#{fundraiser_id}"},
    UpdateExpression="ADD raised_cents :amt, donation_count :one SET updated_at = :now",
    ExpressionAttributeValues={
        ":amt": amount_cents,
        ":one": 1,
        ":now": now_ts(),
    },
)
```

---

## 5. Technical Design

### 5.1 Data Model (in `user_groups` table)

**Group advertiser link** (`pk=GROUP#{group_id}`, `sk=ADVERTISER`):

| Field | Type | Description |
|-------|------|-------------|
| `advertiser_account_id` | S | Link to `ad_accounts` table |
| `created_at` | N | Unix timestamp |
| `created_by` | S | Admin user_sub |

**Fundraiser** (`pk=GROUP#{group_id}`, `sk=FUNDRAISER#{fundraiser_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `fundraiser_id` | S | `fr_<uuid4_hex>` |
| `title` | S | 3-200 chars |
| `description` | S | Max 5000 chars |
| `goal_cents` | N (optional) | Target amount (null = open-ended) |
| `raised_cents` | N | Atomically incremented |
| `donation_count` | N | Number of donations |
| `currency` | S | `usd` |
| `status` | S | `active`, `paused`, `completed`, `cancelled` |
| `cover_image_url` | S (optional) | Cover image |
| `created_at` | N | Unix timestamp |
| `ends_at` | N (optional) | End date |

**Donation** (`pk=FUNDRAISER#{fundraiser_id}`, `sk=DONATION#{donation_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `donation_id` | S | `don_<uuid4_hex>` |
| `group_id` | S | Denormalized |
| `amount_cents` | N | Donation amount |
| `donor_name` | S (optional) | Anonymous if omitted |
| `donor_email` | S (optional) | For receipt |
| `donor_user_id` | S (optional) | Platform user if logged in |
| `stripe_payment_intent_id` | S | Stripe PI |
| `status` | S | `pending`, `completed`, `failed`, `refunded` |
| `created_at` | N | Unix timestamp |
| `is_external` | BOOL | True for non-platform donors |

No additional GSI needed -- donations queried via `pk=FUNDRAISER#{fundraiser_id}` with `sk begins_with DONATION#`.

### 5.2 Backend Service: Advertising (`app/services/group_advertising.py`)
<!-- NOTE: app/services/group_advertising.py does not exist yet — new implementation required -->

| Function | Description |
|----------|-------------|
| `link_advertiser_account(group_id, admin_id, advertiser_account_id)` | Verify admin + account ownership; write ADVERTISER record |
| `create_group_campaign(group_id, admin_id, name, daily_budget, lifetime_budget, ...)` | Verify admin + linked account; check treasury balance; reserve funds via GROUP-004 `spend_treasury`; create campaign in `ad_campaigns` |
| `list_group_campaigns(group_id)` | Query campaigns by linked advertiser_account_id |
| `get_group_campaign_stats(group_id, campaign_id)` | Aggregate impressions, clicks, spend |
| `pause_group_campaign(group_id, admin_id, campaign_id)` | Set campaign status to paused |
| `resume_group_campaign(group_id, admin_id, campaign_id)` | Set campaign status to active |

### 5.3 Backend Service: Fundraising (`app/services/group_fundraising.py`)
<!-- NOTE: app/services/group_fundraising.py does not exist yet — new implementation required -->

| Function | Description |
|----------|-------------|
| `create_fundraiser(group_id, admin_id, title, description, goal_cents, ...)` | Verify admin; create FUNDRAISER record |
| `get_fundraiser(fundraiser_id)` | Public info: title, description, goal, raised, group name |
| `update_fundraiser(fundraiser_id, group_id, admin_id, **updates)` | Admin-only update |
| `list_fundraisers(group_id)` | Query `GROUP#{group_id}` with `SK begins_with FUNDRAISER#` |
| `create_donation(fundraiser_id, amount_cents, donor_name, donor_email)` | Validate active; create Stripe session; write DONATION with status=pending |
| `confirm_donation(donation_id, stripe_pi_id)` | Set completed; increment raised_cents; credit treasury via GROUP-004 |
| `list_donations(fundraiser_id, cursor, limit)` | Admin/mod only; paginated |
| `get_donation_receipt(donation_id)` | Public: amount, date, group name, fundraiser title |

### 5.4 Backend Routers

**Advertising** (`app/routers/group_advertising.py`): <!-- NOTE: does not exist yet — new implementation required -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups/{group_id}/advertiser` | `require_ui_session` | Link advertiser account |
| POST | `/ui/groups/{group_id}/campaigns` | `require_ui_session` | Create campaign |
| GET | `/ui/groups/{group_id}/campaigns` | `require_ui_session` | List campaigns |
| GET | `/ui/groups/{group_id}/campaigns/{id}/stats` | `require_ui_session` | Campaign stats |
| PATCH | `/ui/groups/{group_id}/campaigns/{id}` | `require_ui_session` | Pause/resume |

**Fundraising** (`app/routers/group_fundraising.py`): <!-- NOTE: does not exist yet — new implementation required -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups/{group_id}/fundraisers` | `require_ui_session` | Create fundraiser |
| GET | `/ui/groups/{group_id}/fundraisers` | `require_ui_session` | List fundraisers |
| PATCH | `/ui/groups/{group_id}/fundraisers/{id}` | `require_ui_session` | Update fundraiser |
| GET | `/ui/groups/{group_id}/fundraisers/{id}/donations` | `require_ui_session` | List donations |
| GET | `/public/fundraisers/{id}` | None | Public fundraiser info |
| POST | `/public/fundraisers/{id}/donate` | None | Submit donation |
| GET | `/public/donations/{id}/receipt` | None | Donation receipt |

---

## 6. API Request/Response Examples

### 6.1 Link Advertiser Account

**Request:**
```http
POST /ui/groups/grp_abc123/advertiser
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "advertiser_account_id": "adacc_xyz789"
}
```

**Response (201):**
```json
{
  "ok": true,
  "group_id": "grp_abc123",
  "advertiser_account_id": "adacc_xyz789",
  "created_at": 1748534400
}
```

### 6.2 Create Group Campaign

**Request:**
```http
POST /ui/groups/grp_abc123/campaigns
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "name": "Summer Membership Drive",
  "daily_budget_cents": 500,
  "lifetime_budget_cents": 5000,
  "creative_text": "Join our vibrant community! Discussions, events, and more.",
  "creative_image_url": "/mock/s3/uploads/campaign-banner.jpg"
}
```

**Response (201):**
```json
{
  "campaign_id": "camp_a1b2c3d4",
  "group_id": "grp_abc123",
  "name": "Summer Membership Drive",
  "status": "active",
  "daily_budget_cents": 500,
  "lifetime_budget_cents": 5000,
  "spent_cents": 0,
  "impressions": 0,
  "clicks": 0,
  "creative_text": "Join our vibrant community! Discussions, events, and more.",
  "creative_image_url": "/mock/s3/uploads/campaign-banner.jpg",
  "created_at": 1748534500
}
```

### 6.3 Create Fundraiser

**Request:**
```http
POST /ui/groups/grp_abc123/fundraisers
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "title": "Community Server Fund",
  "description": "Help us fund dedicated servers for our community projects.",
  "goal_cents": 50000,
  "cover_image_url": "/mock/s3/uploads/fundraiser-cover.jpg",
  "ends_at": 1751212800
}
```

**Response (201):**
```json
{
  "fundraiser_id": "fr_e5f6a7b8c9d0",
  "group_id": "grp_abc123",
  "title": "Community Server Fund",
  "description": "Help us fund dedicated servers for our community projects.",
  "goal_cents": 50000,
  "raised_cents": 0,
  "donation_count": 0,
  "currency": "usd",
  "status": "active",
  "cover_image_url": "/mock/s3/uploads/fundraiser-cover.jpg",
  "created_at": 1748534600,
  "ends_at": 1751212800
}
```

### 6.4 Public Fundraiser Info

**Request:**
```http
GET /public/fundraisers/fr_e5f6a7b8c9d0
```

**Response (200):**
```json
{
  "fundraiser_id": "fr_e5f6a7b8c9d0",
  "group_name": "Tech Enthusiasts",
  "title": "Community Server Fund",
  "description": "Help us fund dedicated servers for our community projects.",
  "goal_cents": 50000,
  "raised_cents": 12500,
  "donation_count": 8,
  "currency": "usd",
  "status": "active",
  "cover_image_url": "/mock/s3/uploads/fundraiser-cover.jpg",
  "ends_at": 1751212800
}
```

### 6.5 Submit Donation

**Request:**
```http
POST /public/fundraisers/fr_e5f6a7b8c9d0/donate
Content-Type: application/json

{
  "amount_cents": 2500,
  "donor_name": "Jane Smith",
  "donor_email": "jane@example.com"
}
```

**Response (201):**
```json
{
  "donation_id": "don_1a2b3c4d5e6f",
  "amount_cents": 2500,
  "status": "pending",
  "checkout_url": "https://checkout.stripe.com/pay/cs_test_..."
}
```

### 6.6 Get Donation Receipt

**Request:**
```http
GET /public/donations/don_1a2b3c4d5e6f/receipt
```

**Response (200):**
```json
{
  "donation_id": "don_1a2b3c4d5e6f",
  "amount_cents": 2500,
  "currency": "usd",
  "donor_name": "Jane Smith",
  "group_name": "Tech Enthusiasts",
  "fundraiser_title": "Community Server Fund",
  "created_at": 1748534700,
  "status": "completed"
}
```

### 6.7 Campaign Stats

**Request:**
```http
GET /ui/groups/grp_abc123/campaigns/camp_a1b2c3d4/stats
Cookie: ui_session=...; ui_access_token=...
```

**Response (200):**
```json
{
  "campaign_id": "camp_a1b2c3d4",
  "impressions": 4520,
  "clicks": 186,
  "ctr": 0.0411,
  "spent_cents": 1850,
  "remaining_cents": 3150,
  "daily_spent_cents": 320,
  "daily_budget_cents": 500,
  "status": "active"
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|---|----------|-------------|------------|---------------|-----------------|
| 1 | Not admin | 403 | `NOT_ADMIN` | "Only the group admin can perform this action" | Request admin role from current admin |
| 2 | No advertiser account linked | 400 | `NO_ADVERTISER` | "Group does not have a linked advertiser account" | Link an account first |
| 3 | Advertiser account already linked | 409 | `ALREADY_LINKED` | "Group already has a linked advertiser account" | Use existing account |
| 4 | Insufficient treasury | 400 | `INSUFFICIENT_FUNDS` | "Insufficient group treasury balance" | Contribute more funds or reduce budget |
| 5 | Fundraiser not found | 404 | `FUNDRAISER_NOT_FOUND` | "Fundraiser not found" | Verify fundraiser_id |
| 6 | Fundraiser not active | 400 | `FUNDRAISER_INACTIVE` | "This fundraiser is no longer accepting donations" | Check status; may be paused or completed |
| 7 | Fundraiser expired | 400 | `FUNDRAISER_EXPIRED` | "This fundraiser has ended" | ends_at has passed |
| 8 | Donation below minimum | 422 | `VALIDATION_ERROR` | "amount_cents: Input should be >= 100" | Donate at least $1.00 |
| 9 | Donation above maximum | 422 | `VALIDATION_ERROR` | "amount_cents: Input should be <= 10000000" | Max $100,000 per donation |
| 10 | Stripe payment failure | 400 | `PAYMENT_FAILED` | "Payment could not be processed" | Try different payment method |
| 11 | Campaign not found | 404 | `CAMPAIGN_NOT_FOUND` | "Campaign not found" | Verify campaign_id |
| 12 | Group dissolved | 410 | `GROUP_DISSOLVED` | "This group has been dissolved" | No recovery |
| 13 | CSRF token mismatch | 403 | `CSRF_MISMATCH` | "CSRF validation failed" | Refresh page |
| 14 | Rate limit (donations) | 429 | `RATE_LIMITED` | "Too many donation attempts. Try again in 60 seconds." | Wait and retry |
| 15 | Invalid donor email format | 422 | `VALIDATION_ERROR` | "donor_email: Invalid email format" | Correct email |
| 16 | Donation receipt not found | 404 | `RECEIPT_NOT_FOUND` | "Donation receipt not found" | Verify donation_id |
| 17 | Donation not yet completed | 400 | `RECEIPT_NOT_READY` | "Receipt not available until payment is confirmed" | Wait for Stripe confirmation |

---

## 8. Pydantic Model Definitions

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, List


class LinkAdvertiserIn(BaseModel):
    advertiser_account_id: str = Field(..., min_length=1, max_length=100)


class CreateCampaignIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    daily_budget_cents: int = Field(..., ge=100)     # min $1.00/day
    lifetime_budget_cents: int = Field(..., ge=1000)  # min $10.00 total
    creative_text: Optional[str] = Field(default=None, max_length=500)
    creative_image_url: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("lifetime_budget_cents")
    @classmethod
    def lifetime_gte_daily(cls, v: int, info) -> int:
        daily = info.data.get("daily_budget_cents", 0)
        if daily and v < daily:
            raise ValueError("Lifetime budget must be >= daily budget")
        return v


class UpdateCampaignIn(BaseModel):
    status: Optional[Literal["active", "paused"]] = None
    daily_budget_cents: Optional[int] = Field(default=None, ge=100)


class CampaignOut(BaseModel):
    campaign_id: str
    group_id: str
    name: str
    status: Literal["active", "paused", "completed", "draft"]
    daily_budget_cents: int
    lifetime_budget_cents: int
    spent_cents: int = 0
    impressions: int = 0
    clicks: int = 0
    creative_text: Optional[str] = None
    creative_image_url: Optional[str] = None
    created_at: int


class CampaignStatsOut(BaseModel):
    campaign_id: str
    impressions: int
    clicks: int
    ctr: float = 0.0
    spent_cents: int
    remaining_cents: int
    daily_spent_cents: int = 0
    daily_budget_cents: int
    status: str


class CreateFundraiserIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    goal_cents: Optional[int] = Field(default=None, ge=100)  # min $1.00
    cover_image_url: Optional[str] = Field(default=None, max_length=2048)
    ends_at: Optional[int] = None

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Title cannot be blank")
        return v


class UpdateFundraiserIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    goal_cents: Optional[int] = Field(default=None, ge=100)
    status: Optional[Literal["active", "paused", "cancelled"]] = None
    ends_at: Optional[int] = None


class FundraiserOut(BaseModel):
    fundraiser_id: str
    group_id: str
    title: str
    description: str
    goal_cents: Optional[int] = None
    raised_cents: int = 0
    donation_count: int = 0
    currency: str = "usd"
    status: Literal["active", "paused", "completed", "cancelled"]
    cover_image_url: Optional[str] = None
    created_at: int
    ends_at: Optional[int] = None


class DonateIn(BaseModel):
    amount_cents: int = Field(..., ge=100, le=10000000)  # $1.00 - $100,000.00
    donor_name: Optional[str] = Field(default=None, max_length=100)
    donor_email: Optional[str] = Field(default=None, max_length=254)

    @field_validator("donor_email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and "@" not in v:
            raise ValueError("Invalid email format")
        return v


class DonationOut(BaseModel):
    donation_id: str
    amount_cents: int
    donor_name: Optional[str] = None
    status: Literal["pending", "completed", "failed", "refunded"]
    created_at: int
    is_external: bool = True


class DonationReceiptOut(BaseModel):
    donation_id: str
    amount_cents: int
    currency: str = "usd"
    donor_name: Optional[str] = None
    group_name: str
    fundraiser_title: str
    created_at: int
    status: str
```

---

## 9. Frontend Component Tree

```
GroupAdsPage (route: /groups/:groupId/ads)
├── PageHeader ("Advertising Campaigns")
│   ├── TreasuryBalanceBadge (current balance)
│   └── CreateCampaignButton
├── CampaignList
│   └── CampaignCard[]
│       ├── CampaignName
│       ├── StatusBadge (active/paused/completed)
│       ├── BudgetBar (spent / lifetime)
│       ├── StatsRow (impressions, clicks, CTR)
│       └── ActionButtons (Pause/Resume, View Stats)
└── EmptyState ("No campaigns yet")

GroupFundraisingPage (route: /groups/:groupId/fundraising)
├── PageHeader ("Fundraising")
│   └── CreateFundraiserButton
├── FundraiserList
│   └── FundraiserCard[]
│       ├── Title + Description
│       ├── ProgressBar (raised / goal)
│       ├── DonationCount
│       ├── StatusBadge
│       ├── ShareLink (copy public URL)
│       └── ActionButtons (Edit, Pause, View Donations)
└── DonationListDialog (modal, per fundraiser)
    └── DonationRow[] (amount, donor, date, status)

PublicDonationPage (route: /donate/:fundraiserId)
├── GroupBranding (name, cover image)
├── FundraiserInfo (title, description)
├── ProgressBar (raised / goal, with percentage)
├── DonationForm
│   ├── AmountPresets ($5, $10, $25, $50)
│   ├── CustomAmountInput
│   ├── DonorNameInput (optional)
│   ├── DonorEmailInput (optional)
│   └── SubmitButton ("Donate $X.XX")
└── ReceiptView (shown after successful donation)
    └── ReceiptDetails (amount, date, group, fundraiser)
```

### TypeScript Props Interfaces

```typescript
interface CampaignCardProps {
  campaign: GroupCampaign;
  onPause: (campaignId: string) => void;
  onResume: (campaignId: string) => void;
  onViewStats: (campaignId: string) => void;
}

interface FundraiserCardProps {
  fundraiser: GroupFundraiser;
  isAdmin: boolean;
  onEdit: (fundraiserId: string) => void;
  onPause: (fundraiserId: string) => void;
  onViewDonations: (fundraiserId: string) => void;
  onCopyShareLink: (fundraiserId: string) => void;
}

interface DonationFormProps {
  fundraiserId: string;
  fundraiserTitle: string;
  groupName: string;
  onDonationComplete: (donationId: string) => void;
}

interface ProgressBarProps {
  raisedCents: number;
  goalCents?: number;
  currency: string;
  showPercentage?: boolean;
}

interface AmountPresetProps {
  amounts: number[];
  selectedAmount: number | null;
  onSelect: (cents: number) => void;
  currency: string;
}

interface DonationListDialogProps {
  fundraiserId: string;
  groupId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}
```

---

## 10. Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface GroupFundraiser {
  fundraiser_id: string; group_id: string; title: string; description: string;
  goal_cents?: number; raised_cents: number; donation_count: number;
  status: "active" | "paused" | "completed" | "cancelled";
  cover_image_url?: string; created_at: number; ends_at?: number;
}
export interface Donation {
  donation_id: string; amount_cents: number; donor_name?: string;
  status: "pending" | "completed" | "failed" | "refunded";
  created_at: number; is_external: boolean;
}
export interface DonationReceipt {
  donation_id: string; amount_cents: number; donor_name?: string;
  group_name: string; fundraiser_title: string; created_at: number;
}
export interface GroupCampaign {
  campaign_id: string; group_id: string; name: string;
  status: "active" | "paused" | "completed" | "draft";
  daily_budget_cents: number; lifetime_budget_cents: number;
  spent_cents: number; impressions: number; clicks: number; created_at: number;
}
```

### Frontend API (`frontend/src/api/endpoints/groups.ts`)

```typescript
// Advertising (authenticated)
export const linkAdvertiser = (groupId: string, accountId: string) =>
  api.post(`/ui/groups/${groupId}/advertiser`, { advertiser_account_id: accountId });
export const createGroupCampaign = (groupId: string, data: {
  name: string; daily_budget_cents: number; lifetime_budget_cents: number;
}) => api.post<GroupCampaign>(`/ui/groups/${groupId}/campaigns`, data);
export const listGroupCampaigns = (groupId: string) =>
  api.get<GroupCampaign[]>(`/ui/groups/${groupId}/campaigns`);
export const getGroupCampaignStats = (groupId: string, campaignId: string) =>
  api.get(`/ui/groups/${groupId}/campaigns/${campaignId}/stats`);
export const updateGroupCampaign = (groupId: string, campaignId: string, data: {
  status?: string;
}) => api.patch(`/ui/groups/${groupId}/campaigns/${campaignId}`, data);

// Fundraising (authenticated)
export const createFundraiser = (groupId: string, data: {
  title: string; description?: string; goal_cents?: number;
}) => api.post<GroupFundraiser>(`/ui/groups/${groupId}/fundraisers`, data);
export const listFundraisers = (groupId: string) =>
  api.get<GroupFundraiser[]>(`/ui/groups/${groupId}/fundraisers`);
export const listDonations = (groupId: string, fundraiserId: string) =>
  api.get<Donation[]>(`/ui/groups/${groupId}/fundraisers/${fundraiserId}/donations`);

// Fundraising (public, no auth -- use axios directly)
export const getPublicFundraiser = (fundraiserId: string) =>
  axios.get(`/public/fundraisers/${fundraiserId}`);
export const submitDonation = (fundraiserId: string, data: {
  amount_cents: number; donor_name?: string; donor_email?: string;
}) => axios.post(`/public/fundraisers/${fundraiserId}/donate`, data);
export const getDonationReceipt = (donationId: string) =>
  axios.get(`/public/donations/${donationId}/receipt`);
```

---

## 11. Frontend Pages

- **GroupAdsPage** (`frontend/src/pages/groups/GroupAdsPage.tsx`): Route `/groups/:groupId/ads`. Admin only. Campaign list with status, spend/budget, impressions, clicks. Create + pause/resume. Treasury balance header. `data-testid="group-ads-page"`.
- **GroupFundraisingPage** (`frontend/src/pages/groups/GroupFundraisingPage.tsx`): Route `/groups/:groupId/fundraising`. Fundraiser list with progress bars. Create/edit fundraisers. Donation list per fundraiser. Share link to public page. `data-testid="group-fundraising-page"`.
- **PublicDonationPage** (`frontend/src/pages/groups/PublicDonationPage.tsx`): Route `/donate/:fundraiserId`. No auth. Group name, title, description, progress bar. Amount input (presets: $5, $10, $25, $50, custom). Optional donor name/email. Receipt on success. `data-testid="public-donation-page"`.
- **FundraisingWidget**: Embeddable on GroupPage. Shows active fundraiser progress + "Donate" link.

---

## 12. Observability

### 12.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `group_campaign_created_total` | Counter | `group_id` | Campaigns created |
| `group_campaign_spend_cents` | Counter | `group_id`, `campaign_id` | Ad spend in cents |
| `group_fundraiser_created_total` | Counter | `group_id` | Fundraisers created |
| `group_donation_total` | Counter | `group_id`, `fundraiser_id` | Donations received |
| `group_donation_amount_cents` | Histogram | `group_id` | Donation amounts distribution |
| `group_donation_stripe_latency_ms` | Histogram | None | Stripe checkout session creation latency |
| `group_donation_confirm_latency_ms` | Histogram | None | Time from donation creation to confirmation |
| `group_public_page_views` | Counter | `fundraiser_id` | Public donation page visits |

### 12.2 Structured Logging

```python
logger.info("group_advertising.campaign_created",
    extra={
        "group_id": group_id,
        "campaign_id": campaign_id,
        "admin_id": admin_id,
        "daily_budget_cents": daily_budget_cents,
        "lifetime_budget_cents": lifetime_budget_cents,
    })

logger.info("group_fundraising.donation_confirmed",
    extra={
        "fundraiser_id": fundraiser_id,
        "donation_id": donation_id,
        "amount_cents": amount_cents,
        "is_external": is_external,
        "new_raised_total": new_raised_cents,
        "goal_cents": goal_cents,
        "goal_reached": goal_cents and new_raised_cents >= goal_cents,
    })

logger.warning("group_fundraising.stripe_failure",
    extra={
        "fundraiser_id": fundraiser_id,
        "error": str(e),
        "amount_cents": amount_cents,
    })
```

### 12.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Stripe checkout failure rate > 5% | `rate(stripe_failures) / rate(donations) > 0.05` for 15 min | Critical | Check Stripe connectivity and API key |
| Donation confirmation delay > 5 min | `p95(donation_confirm_latency_ms) > 300000` for 10 min | Warning | Check Stripe webhook delivery |
| Fundraiser raised exceeds goal by 2x | `raised_cents > 2 * goal_cents` | Info | Notify admin; may want to close fundraiser |
| Campaign overspend | `spent_cents > lifetime_budget_cents` | Critical | Pause campaign immediately; investigate budget enforcement |

---

## 13. Rollout Plan

### 13.1 Feature Flags

```python
# app/core/settings.py
group_advertising_enabled: bool = True   # GROUP_ADVERTISING_ENABLED env var
group_fundraising_enabled: bool = True   # GROUP_FUNDRAISING_ENABLED env var
```
<!-- NOTE: Neither setting exists yet in app/core/settings.py — must be added -->

### 13.2 Phased Rollout

| Phase | Scope | Duration | Flag State | Success Criteria |
|-------|-------|----------|------------|-----------------|
| 1 - Internal | Dev team only | 3 days | Both enabled in dev only | All E2E pass; Stripe mock works |
| 2 - Fundraising Beta | 10% of groups | 5 days | Fundraising on; advertising off | Donations flow correctly; receipts generated |
| 3 - Advertising Beta | 10% of groups | 5 days | Both on for beta groups | Treasury debits accurate; campaign stats match |
| 4 - General | All groups | 5 days | Both on for all | Error rate < 0.1%; donation confirmation < 30s |
| 5 - Stable | Remove flags | 1 day | Flags removed | Clean up |

### 13.3 Rollback Plan

1. Set `GROUP_ADVERTISING_ENABLED=false` / `GROUP_FUNDRAISING_ENABLED=false`.
2. Active campaigns pause automatically (no new spending).
3. Active fundraisers show "temporarily unavailable" on public page.
4. Existing donations and campaign data remain in DDB.
5. Treasury balances are not affected.

---

## 14. Performance Considerations

| # | Concern | Target | Mitigation |
|---|---------|--------|------------|
| 1 | `raised_cents` accuracy under concurrent donations | Exact | Atomic increment via DDB `ADD` expression; no read-modify-write |
| 2 | Donation list for popular fundraisers | < 200ms | Cursor-based pagination with `Limit=20` |
| 3 | Campaign stats aggregation | < 500ms | Pre-aggregated in `ad_impressions` table by campaign_id |
| 4 | Public donation page load | < 100ms | Single DDB `get_item` for fundraiser; no auth overhead |
| 5 | Concurrent donations (popular fundraiser) | No lost writes | DDB atomic `ADD` handles concurrent updates without locking |
| 6 | Stripe Checkout Session creation | < 2s | Async creation; return pending status immediately |
| 7 | Receipt generation | < 100ms | Single DDB get; no external API call |

### 14.1 Caching Strategy

- **Public fundraiser info**: React Query `staleTime: 60_000` (1 minute) for public page.
- **Campaign stats**: `staleTime: 30_000` (30 seconds); stats are approximate.
- **Donation list**: `staleTime: 10_000` (10 seconds) for admin view.

---

## 15. Implementation Plan

### 15.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/group_advertising.py` | Advertiser link, campaign CRUD | <!-- new -->
| `app/services/group_fundraising.py` | Fundraiser CRUD, donation processing | <!-- new -->
| `app/routers/group_advertising.py` | Campaign endpoints | <!-- new -->
| `app/routers/group_fundraising.py` | Fundraiser + public donation endpoints | <!-- new -->
| `frontend/src/pages/groups/GroupAdsPage.tsx` | Campaign manager | <!-- new -->
| `frontend/src/pages/groups/GroupFundraisingPage.tsx` | Fundraiser management | <!-- new -->
| `frontend/src/pages/groups/PublicDonationPage.tsx` | Public donation page | <!-- new -->
| `frontend/src/pages/groups/FundraisingWidget.tsx` | Progress widget | <!-- new -->

### 15.2 Files to Modify

| File | Changes |
|------|---------|
| `app/main.py` | Register ad + fundraising routers |
| `app/models.py` | Add fundraiser, donation, campaign models |
| `frontend/src/api/types.ts` | Add types |
| `frontend/src/api/endpoints/groups.ts` | Add API functions |
| `frontend/src/App.tsx` | Add routes |
| `frontend/src/pages/groups/GroupPage.tsx` | Add FundraisingWidget + nav links |

---

## 16. E2E Test Plan

### 16.1 Test File

`frontend/e2e/group-ads-fundraising.spec.ts` -- 24 tests across 6 sections.

### 16.2 Test Setup

```typescript
const TS = Date.now();
let groupId: string;
let fundraiserId: string;
let openEndedFundraiserId: string;
let donationId: string;
let campaignId: string;
// Alice = admin, Bob = member
// Seed group treasury with funds via DDB
```

### 16.3 Section 455: Group Advertising API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 455.1 | Link advertiser account | POST `/ui/groups/{id}/advertiser`; 201; `advertiser_account_id` stored |
| 455.2 | Create group campaign | POST `/ui/groups/{id}/campaigns`; 201; `campaign_id`, budget fields match |
| 455.3 | List campaigns | GET; 200; array includes campaign |
| 455.4 | Pause and resume | PATCH paused; 200; PATCH active; 200 |

### 16.4 Section 456: Fundraiser CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 456.1 | Create fundraiser with goal | POST; 201; `fundraiser_id`, `goal_cents`, `raised_cents=0` |
| 456.2 | Create open-ended fundraiser | POST without `goal_cents`; 201; `goal_cents=null` |
| 456.3 | Update fundraiser | PATCH; 200; description updated |
| 456.4 | List fundraisers | GET; 200; both fundraisers present |

### 16.5 Section 457: Public Donation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 457.1 | Get public fundraiser info | GET `/public/fundraisers/{id}`; 200; `title`, `group_name`, `raised_cents` |
| 457.2 | Submit donation | POST `/public/fundraisers/{id}/donate`; 201; `donation_id` returned |
| 457.3 | Donation increments raised_cents | GET fundraiser; `raised_cents` increased |
| 457.4 | Get receipt | GET `/public/donations/{id}/receipt`; 200; `amount_cents`, `group_name` |

### 16.6 Section 458: Ads & Fundraising UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 458.1 | Ads page shows campaigns | Navigate `/groups/{id}/ads`; `[data-testid="group-ads-page"]`; campaign listed |
| 458.2 | Fundraising page shows fundraisers | Navigate fundraising; progress bar visible |
| 458.3 | Public donation page shows form | Navigate `/donate/{id}`; amount input + submit button |
| 458.4 | Group page shows fundraising widget | Navigate group; progress bar widget visible |

### 16.7 Section 459: Advertising Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 459.1 | Create campaign without linked account fails | POST campaign before linking; 400 "No linked advertiser account" |
| 459.2 | Create campaign with insufficient treasury fails | Set treasury to 0; POST; 400 "Insufficient treasury" |
| 459.3 | Non-admin cannot create campaign | POST as Bob (member); 403 |
| 459.4 | Campaign stats return zeros for new campaign | GET stats; impressions=0, clicks=0, spent_cents=0 |

### 16.8 Section 460: Fundraising Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 460.1 | Donate to paused fundraiser fails | Pause fundraiser; POST donate; 400 "no longer accepting" |
| 460.2 | Donate below minimum fails | POST with amount_cents=50; 422 |
| 460.3 | Donation to non-existent fundraiser returns 404 | POST to random ID; 404 |
| 460.4 | Receipt for pending donation fails | Create donation but don't confirm; GET receipt; 400 "not available" |

---

## 17. Security Considerations

- **Authorization**: Campaign management admin-only. Donation list admin/mod only. Public endpoints rate-limited.
- **Payment security**: External donations use Stripe Checkout Sessions. No PII stored beyond optional donor name/email.
- **Treasury spending**: Budget reserved from treasury at campaign creation. Remaining returned on cancellation.
- **Rate limiting**: Donations 5/min per IP. Campaigns 10/hour per group. Public info 60/min per IP.
- **Information disclosure**: Public fundraiser endpoint does not reveal admin identity or internal group data.

---

## 18. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| GROUP-001 (Membership) | GROUP-001 | Required |
| GROUP-004 (Treasury) | GROUP-004 | Required -- balance check + debit/credit |
| ADS-001 (Advertiser Accounts) | ADS-001 | Required -- campaign hierarchy |
| Stripe integration | Existing | Available (mock port 12111) |
| Billing ledger | Existing | Available |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| `record_ad_impression()` | `app/services/ad_placement.py` | 222 | VOD-specific ad impression tracking; uses AdImpressions table |
| `_credit_ad_revenue()` | `app/services/ad_placement.py` | 279 | Credits creator billing ledger for ad revenue |
| `AdImpressions` DDB table | `scripts/local-ddb-init.py` | 831 | PK=pk, SK=sk; GSIs: ByVideoCreatedAt, ByCreatorCreatedAt — no campaign-level GSI |
| `ad_impressions_table_name` setting | `app/core/settings.py` | 1242 | `DDB_AD_IMPRESSIONS` env var, defaults to "AdImpressions" |
| `T.ad_impressions` | `app/core/tables.py` | 93, 217 | Table handle exists for ad impressions |
| `new_ledger_entry()` | `app/services/billing_shared.py` | 217 | Fields: `type`, `amount_cents`, `state`, `reason`, `ts`, `entry_id` (NOT `direction`) |
| `ledger_sk()` | `app/services/billing_shared.py` | 213 | Constructs `LEDGER#{ts}#{entry_id}` sort key |
| Stripe mock | — | — | Port 12111; existing usage is PaymentIntent-based, not Checkout Session |
| `user_groups` table | — | — | Does not exist yet; must be created by GROUP-001 |
| `ad_accounts` table | — | — | Does not exist yet; must be created by ADS-001 |
| `ad_campaigns` table | — | — | Does not exist yet; must be created by ADS-001 |
| `group_advertising_enabled` setting | — | — | Does not exist yet in settings.py |
| `group_fundraising_enabled` setting | — | — | Does not exist yet in settings.py |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_group_advertising.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_create_campaign_requires_admin_role`
  - `test_create_campaign_insufficient_treasury_400`
  - `test_pause_resume_campaign`
  - `test_create_fundraiser_with_goal`
  - `test_donate_increments_raised_cents`
  - `test_donate_public_no_auth_required`
  - `test_list_donations_sorted_by_date`

### Integration Tests

  - Campaign creation reserves funds from group treasury
  - Donation via public page credits group treasury balance
  - Campaign stats aggregate impressions and clicks from ad service

### E2E Tests (Playwright)

**File**: `frontend/e2e/group-advertising.spec.ts`
**Test count**: 14

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `user_groups (campaign and fundraiser records)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `GROUP_ADS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| GROUP-001 | User Group Creation & Membership | Requires admin role verification |
| GROUP-004 | Group Treasury Management | Campaigns funded from group treasury |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after GROUP-001, GROUP-004. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 14 E2E tests pass with `npx playwright test group-advertising.spec.ts`
