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
Donor visits public donation page → sees group info + progress bar
  → enters amount + optional name/email → payment processed (Stripe)
  → donation record created → treasury credited → receipt shown
```

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Ad platform** (`app/services/ad_placement.py`): VOD ad slot calculation, `record_ad_impression()`, `_credit_ad_revenue()`. ADS-001 defines campaign hierarchy (Account > Campaign > Ad Group > Creative) and budget tracking.
- **Advertiser accounts** (ADS-001): `ad_accounts` table. Any user can create an advertiser account. Group campaigns create a group-linked account.
- **Stripe** (`app/services/billing_shared.py`): Mock Stripe on port 12111. For external donations, Stripe Checkout Session handles payment method collection without requiring a platform account.
- **Billing ledger**: `new_ledger_entry()` with `pk`, `sk=LEDGER#{ts}#{entry_id}`, `amount_cents`, `reason`, `direction`. Group treasury uses the same pattern with `pk=GROUP#{group_id}`.

### 2.2 Gaps

1. No group-to-advertiser-account link.
2. No treasury-to-ad-budget flow.
3. No fundraising model or donation records.
4. No public donation page or payment flow.
5. No fundraising goal tracking.
6. No frontend for group ads or fundraising.

---

## 3. Technical Design

### 3.1 Data Model (in `user_groups` table)

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

No additional GSI needed — donations queried via `pk=FUNDRAISER#{fundraiser_id}` with `sk begins_with DONATION#`.

### 3.2 Backend Service: Advertising (`app/services/group_advertising.py`)

| Function | Description |
|----------|-------------|
| `link_advertiser_account(group_id, admin_id, advertiser_account_id)` | Verify admin + account ownership; write ADVERTISER record |
| `create_group_campaign(group_id, admin_id, name, daily_budget, lifetime_budget, ...)` | Verify admin + linked account; check treasury balance; reserve funds via GROUP-004 `spend_treasury`; create campaign in `ad_campaigns` |
| `list_group_campaigns(group_id)` | Query campaigns by linked advertiser_account_id |
| `get_group_campaign_stats(group_id, campaign_id)` | Aggregate impressions, clicks, spend |
| `pause_group_campaign(group_id, admin_id, campaign_id)` | Set campaign status to paused |
| `resume_group_campaign(group_id, admin_id, campaign_id)` | Set campaign status to active |

### 3.3 Backend Service: Fundraising (`app/services/group_fundraising.py`)

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

### 3.4 Backend Routers

**Advertising** (`app/routers/group_advertising.py`):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups/{group_id}/advertiser` | `require_ui_session` | Link advertiser account |
| POST | `/ui/groups/{group_id}/campaigns` | `require_ui_session` | Create campaign |
| GET | `/ui/groups/{group_id}/campaigns` | `require_ui_session` | List campaigns |
| GET | `/ui/groups/{group_id}/campaigns/{id}/stats` | `require_ui_session` | Campaign stats |
| PATCH | `/ui/groups/{group_id}/campaigns/{id}` | `require_ui_session` | Pause/resume |

**Fundraising** (`app/routers/group_fundraising.py`):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups/{group_id}/fundraisers` | `require_ui_session` | Create fundraiser |
| GET | `/ui/groups/{group_id}/fundraisers` | `require_ui_session` | List fundraisers |
| PATCH | `/ui/groups/{group_id}/fundraisers/{id}` | `require_ui_session` | Update fundraiser |
| GET | `/ui/groups/{group_id}/fundraisers/{id}/donations` | `require_ui_session` | List donations |
| GET | `/public/fundraisers/{id}` | None | Public fundraiser info |
| POST | `/public/fundraisers/{id}/donate` | None | Submit donation |
| GET | `/public/donations/{id}/receipt` | None | Donation receipt |

**Request models**: `CreateCampaignIn(name, daily_budget_cents ge=100, lifetime_budget_cents ge=1000, creative_text?, creative_image_url?)`, `CreateFundraiserIn(title, description, goal_cents? ge=100, cover_image_url?, ends_at?)`, `DonateIn(amount_cents ge=100 le=10000000, donor_name?, donor_email?)`.

### 3.5 Frontend Types (`frontend/src/api/types.ts`)

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

### 3.6 Frontend API (`frontend/src/api/endpoints/groups.ts`)

Extend with: `linkAdvertiser`, `createGroupCampaign`, `listGroupCampaigns`, `getGroupCampaignStats`, `updateGroupCampaign`, `createFundraiser`, `listFundraisers`, `updateFundraiser`, `listDonations`, `getPublicFundraiser` (axios, no auth), `submitDonation` (axios), `getDonationReceipt` (axios).

### 3.7 Frontend Pages

- **GroupAdsPage** (`frontend/src/pages/groups/GroupAdsPage.tsx`): Route `/groups/:groupId/ads`. Admin only. Campaign list with status, spend/budget, impressions, clicks. Create + pause/resume. Treasury balance header. `data-testid="group-ads-page"`.
- **GroupFundraisingPage** (`frontend/src/pages/groups/GroupFundraisingPage.tsx`): Route `/groups/:groupId/fundraising`. Fundraiser list with progress bars. Create/edit fundraisers. Donation list per fundraiser. Share link to public page. `data-testid="group-fundraising-page"`.
- **PublicDonationPage** (`frontend/src/pages/groups/PublicDonationPage.tsx`): Route `/donate/:fundraiserId`. No auth. Group name, title, description, progress bar. Amount input (presets: $5, $10, $25, $50, custom). Optional donor name/email. Receipt on success. `data-testid="public-donation-page"`.
- **FundraisingWidget**: Embeddable on GroupPage. Shows active fundraiser progress + "Donate" link.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/group_advertising.py` | Advertiser link, campaign CRUD |
| `app/services/group_fundraising.py` | Fundraiser CRUD, donation processing |
| `app/routers/group_advertising.py` | Campaign endpoints |
| `app/routers/group_fundraising.py` | Fundraiser + public donation endpoints |
| `frontend/src/pages/groups/GroupAdsPage.tsx` | Campaign manager |
| `frontend/src/pages/groups/GroupFundraisingPage.tsx` | Fundraiser management |
| `frontend/src/pages/groups/PublicDonationPage.tsx` | Public donation page |
| `frontend/src/pages/groups/FundraisingWidget.tsx` | Progress widget |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/main.py` | Register ad + fundraising routers |
| `app/models.py` | Add fundraiser, donation, campaign models |
| `frontend/src/api/types.ts` | Add types |
| `frontend/src/api/endpoints/groups.ts` | Add API functions |
| `frontend/src/App.tsx` | Add routes |
| `frontend/src/pages/groups/GroupPage.tsx` | Add FundraisingWidget + nav links |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/group-ads-fundraising.spec.ts` — 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let groupId: string;
let fundraiserId: string;
let donationId: string;
let campaignId: string;
// Alice = admin, Bob = member
// Seed group treasury with funds via DDB
```

### 5.3 Section 455: Group Advertising API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 455.1 | Link advertiser account | POST `/ui/groups/{id}/advertiser`; 201; `advertiser_account_id` stored |
| 455.2 | Create group campaign | POST `/ui/groups/{id}/campaigns`; 201; `campaign_id`, budget fields match |
| 455.3 | List campaigns | GET; 200; array includes campaign |
| 455.4 | Pause and resume | PATCH paused; 200; PATCH active; 200 |

### 5.4 Section 456: Fundraiser CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 456.1 | Create fundraiser with goal | POST; 201; `fundraiser_id`, `goal_cents`, `raised_cents=0` |
| 456.2 | Create open-ended fundraiser | POST without `goal_cents`; 201; `goal_cents=null` |
| 456.3 | Update fundraiser | PATCH; 200; description updated |
| 456.4 | List fundraisers | GET; 200; both fundraisers present |

### 5.5 Section 457: Public Donation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 457.1 | Get public fundraiser info | GET `/public/fundraisers/{id}`; 200; `title`, `group_name`, `raised_cents` |
| 457.2 | Submit donation | POST `/public/fundraisers/{id}/donate`; 201; `donation_id` returned |
| 457.3 | Donation increments raised_cents | GET fundraiser; `raised_cents` increased |
| 457.4 | Get receipt | GET `/public/donations/{id}/receipt`; 200; `amount_cents`, `group_name` |

### 5.6 Section 458: Ads & Fundraising UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 458.1 | Ads page shows campaigns | Navigate `/groups/{id}/ads`; `[data-testid="group-ads-page"]`; campaign listed |
| 458.2 | Fundraising page shows fundraisers | Navigate fundraising; progress bar visible |
| 458.3 | Public donation page shows form | Navigate `/donate/{id}`; amount input + submit button |
| 458.4 | Group page shows fundraising widget | Navigate group; progress bar widget visible |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Not admin | 403 | "Only the group admin can perform this action" |
| No advertiser account linked | 400 | "Group does not have a linked advertiser account" |
| Insufficient treasury | 400 | "Insufficient group treasury balance" |
| Fundraiser not found | 404 | "Fundraiser not found" |
| Fundraiser not active | 400 | "This fundraiser is no longer accepting donations" |
| Donation below minimum | 422 | Pydantic: `ge=100` |
| Stripe payment failure | 400 | "Payment could not be processed" |

---

## 7. Security Considerations

- **Authorization**: Campaign management admin-only. Donation list admin/mod only. Public endpoints rate-limited.
- **Payment security**: External donations use Stripe Checkout Sessions. No PII stored beyond optional donor name/email.
- **Treasury spending**: Budget reserved from treasury at campaign creation. Remaining returned on cancellation.
- **Rate limiting**: Donations 5/min per IP. Campaigns 10/hour per group. Public info 60/min per IP.
- **Information disclosure**: Public fundraiser endpoint does not reveal admin identity or internal group data.

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| GROUP-001 (Membership) | GROUP-001 | Required |
| GROUP-004 (Treasury) | GROUP-004 | Required — balance check + debit/credit |
| ADS-001 (Advertiser Accounts) | ADS-001 | Required — campaign hierarchy |
| Stripe integration | Existing | Available (mock port 12111) |
| Billing ledger | Existing | Available |
