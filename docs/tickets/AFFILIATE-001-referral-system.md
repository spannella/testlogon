# AFFILIATE-001: Affiliate & Referral System

**Ticket**: AFFILIATE-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 12-14 days

---

## 1. Executive Summary

The platform has no organic growth mechanism beyond word-of-mouth. Users who refer friends receive no incentive, and there is no way to attribute new signups or purchases to the person who shared the link. Creators with large external audiences (social media, email lists) cannot monetize their ability to drive traffic to the platform beyond their own content.

This feature implements a complete affiliate and referral system: every registered user can generate referral codes and shareable links, new users clicking those links are tracked via a 30-day attribution cookie, and the referrer earns a configurable commission percentage (5% standard, 10% premium tier) on the referred user's qualifying purchases for 12 months. Commissions accumulate in the referrer's affiliate wallet and can be withdrawn through the existing creator payout system (MON-004).

The system is built on the existing `app_single_table` DynamoDB pattern with three entity types (ReferralCode, ReferralAttribution, AffiliateCommission), integrates with the billing ledger for commission tracking, and hooks into the registration flow for attribution. Fraud prevention includes self-referral blocking, a 7-day holdback on referral confirmation, and automatic revocation if the referred account is banned within 30 days.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Referrer | I want to generate a unique referral link to share with friends. | Dashboard shows referral code + copyable link. |
| Referrer | I want to see how many people signed up using my link. | Dashboard shows referral count, pending, and confirmed. |
| Referrer | I want to earn commission when my referrals make purchases. | Commission entries appear in affiliate wallet with amounts and status. |
| Referrer | I want to withdraw my accumulated commissions. | Withdraw button triggers payout through existing MON-004 system. |
| Referred User | I signed up via a referral link and want to see who referred me. | Account settings shows "Referred by: [username]". |
| Admin | I want to see referral program analytics and detect fraud. | Admin panel shows top referrers, conversion rates, and flagged accounts. |
| Creator | I want a premium referral tier with higher commission rates. | Premium tier (10%) available for approved creators. |

### 2.2 Pain Points

1. **No growth incentive**: Users have no reason to share the platform with friends. Word-of-mouth is the only acquisition channel.
2. **No attribution**: Even if a user shares a link, there is no way to track which signups came from that share.
3. **Creator monetization gap**: Creators with large audiences on other platforms (Twitter, YouTube, Twitch) cannot earn by sending traffic to this platform.
4. **No viral loop**: Modern platforms use referral bonuses to create exponential growth loops. Without them, growth is linear.

### 2.3 Competitive Analysis

| Platform | Referral Mechanism | Commission Model | Cookie Window | Commission Duration |
|----------|-------------------|-----------------|---------------|---------------------|
| OnlyFans | Referral links | 5% of referred creator earnings | N/A (explicit link) | 12 months |
| Fansly | Referral codes | 1-5% tiered | 30 days | Lifetime |
| Twitch | Affiliate program | Revenue share on subs | N/A | Per-sub |
| Stripe | Partner referrals | $10/user + rev share | 90 days | 12 months |
| **This platform** | **None** | **None** | **N/A** | **N/A** |

---

## 3. Current State Analysis

### 3.1 Creator Payouts (MON-004)

The existing payout system handles creator earnings withdrawals via Stripe Connect (or manual bank transfer in dev). Key components:
- `app/services/creator_payouts.py`: Payout request creation, approval, processing. <!-- VERIFIED: file exists -->
- `app/routers/creator_payouts.py`: Payout API endpoints. <!-- VERIFIED: registered in main.py -->
- Payout records stored in a dedicated `creator_payouts` table (handle `T.creator_payouts`, settings `S.creator_payouts_table_name`). <!-- CORRECTED: was "billing table with pk=PAYOUT#{user_id}", actually a separate creator_payouts table (tables.py:86/169, settings.py:1129) -->

The affiliate payout will integrate with this system by adding affiliate commission as a payout source alongside content earnings.

### 3.2 Billing Ledger

`app/services/billing_shared.py` tracks financial transactions in the `billing` DynamoDB table (handle `T.billing`, settings `S.billing_table_name`). The `new_ledger_entry` function (billing_shared.py:217) creates ledger entries. <!-- CORRECTED: was app/services/billing.py, which does not exist. Billing is split across billing_shared.py, billing_ccbill.py, billing_dunning.py, billing_reconcile.py --> Entries have `pk=USER#{user_id}`, `sk=LEDGER#{timestamp}#{tx_id}`. The affiliate system writes commission entries to this ledger.

### 3.3 Registration Flow

`app/routers/register.py` handles user registration (functions: `register_start` at line 61, `register_check` at line 154, `register_confirm` at line 188, `register_resend` at line 233). <!-- CORRECTED: was app/routers/auth.py, which does not exist. Registration is in app/routers/register.py --> The registration endpoint must be extended to check for a `ref_attribution` cookie and record the referral relationship.

### 3.4 Gaps

1. No referral code generation or storage
2. No attribution cookie mechanism
3. No commission calculation on referred user purchases
4. No affiliate wallet or commission ledger
5. No referral dashboard UI
6. No fraud detection (self-referral, duplicate attribution)

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+-------------------+       +---------------------+       +----------------------+
|   Referral Page   |       |   Backend API       |       |   DynamoDB           |
| (/referrals)      |       |  (referrals.py)     |       |   app_single_table   |
|                   |       |                     |       |                      |
| +---------------+ |       |  POST /code         |------>| pk:REFCODE#{code}    |
| | Code Card     | |------>|  GET /codes         |<------| GSI1: REFCODES#{uid} |
| | [ABC12345]    | |       |  GET /dashboard     |       |                      |
| | [Copy Link]   | |       |  GET /commissions   |<------| pk:AFFILIATE#{uid}   |
| +---------------+ |       |  POST /withdraw     |       |                      |
|                   |       +---------------------+       | pk:REFERRAL#{ref_uid}|
| +---------------+ |              |                      |   (attribution)      |
| | Stats Cards   | |              v                      +----------------------+
| | 12 referrals  | |       +---------------------+
| | $450 earned   | |       |   Registration Flow |       +----------------------+
| +---------------+ |       |   (auth.py)         |       |   Billing Hook       |
|                   |       |                     |       |   (billing.py)       |
| +---------------+ |       | Check ref cookie    |       |                      |
| | Commission    | |       | Call attribute_      |       | On qualifying purchase|
| | History Table | |       |   referral()        |       | Call record_affiliate_|
| +---------------+ |       +---------------------+       |   commission()       |
+-------------------+                                     +----------------------+

+-------------------+       +---------------------+
| External Traffic  |       |   Frontend Entry    |
|                   |       |   (main.tsx)        |
| platform.com/     |------>| Check ?ref=CODE     |
|  ?ref=ABC12345    |       | Set ref_attribution |
|                   |       |   cookie (30 days)  |
+-------------------+       +---------------------+
```

### 4.2 Data Flow -- Referral Attribution

1. Referrer generates code via `POST /ui/referrals/code`
2. Referrer shares link: `https://platform.com/?ref=ABC12345`
3. Prospect clicks link
4. Frontend `main.tsx` detects `?ref=` param, sets `ref_attribution=ABC12345` cookie (30-day max-age)
5. Prospect registers via `/ui/register`
6. Backend registration handler reads `ref_attribution` cookie from request
7. Backend calls `attribute_referral(referred_user_id, referral_code, ip_address)`
8. Attribution service validates code, blocks self-referral, writes `REFERRAL#{referred_user_id}` item
9. Attribution status = `pending` (becomes `confirmed` after 7-day holdback)

### 4.3 Data Flow -- Commission

1. Referred user makes a qualifying purchase (subscription, PPV, tip, shop purchase, unlock)
2. Billing service calls `record_affiliate_commission(referred_user_id, transaction_id, ...)`
3. Commission service looks up `REFERRAL#{referred_user_id}` attribution
4. If attribution exists, is not revoked, and commission window hasn't expired:
   - Calculate commission: `net_amount * rate_bps / 10000`
   - Write `AFFILIATE#{referrer_id}/COMMISSION#{ts}#{tx_id}` item
5. Commission status = `pending` (becomes `confirmed` after holdback period)

---

## 5. Data Model Deep Dive

### 5.1 Referral Code (DynamoDB `app_single_table`)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `REFCODE#{code}` | `"REFCODE#ABC12345"` |
| `sk` | S | `META` | `"META"` |
| `Entity` | S | `ReferralCode` | `"ReferralCode"` |
| `code` | S | 8-char alphanumeric, unique | `"ABC12345"` |
| `owner_user_id` | S | The referrer's user sub | `"alice@test.local"` |
| `created_at` | S | ISO 8601 | `"2026-05-27T10:00:00Z"` |
| `active` | BOOL | Can be deactivated | `true` |
| `commission_tier` | S | `"standard"` (5%) or `"premium"` (10%) | `"standard"` |
| `GSI1PK` | S | `REFCODES#{owner_user_id}` | `"REFCODES#alice@test.local"` |
| `GSI1SK` | S | `{created_at}#REFCODE#{code}` | `"2026-05-27T10:00:00Z#REFCODE#ABC12345"` |

**Example item:**

```json
{
  "pk": "REFCODE#ABC12345",
  "sk": "META",
  "Entity": "ReferralCode",
  "code": "ABC12345",
  "owner_user_id": "alice@test.local",
  "created_at": "2026-05-27T10:00:00Z",
  "active": true,
  "commission_tier": "standard",
  "GSI1PK": "REFCODES#alice@test.local",
  "GSI1SK": "2026-05-27T10:00:00Z#REFCODE#ABC12345"
}
```

### 5.2 Referral Attribution

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `REFERRAL#{referred_user_id}` | `"REFERRAL#bob@test.local"` |
| `sk` | S | `META` | `"META"` |
| `Entity` | S | `ReferralAttribution` | `"ReferralAttribution"` |
| `referred_user_id` | S | The new user | `"bob@test.local"` |
| `referrer_user_id` | S | The referrer | `"alice@test.local"` |
| `referral_code` | S | Code used | `"ABC12345"` |
| `attributed_at` | S | ISO 8601 of signup | `"2026-05-28T14:00:00Z"` |
| `attribution_source` | S | `"cookie"` or `"code_entry"` | `"cookie"` |
| `status` | S | `"pending"`, `"confirmed"`, `"revoked"` | `"pending"` |
| `confirmed_at` | S (optional) | When confirmed (after 7-day holdback) | `null` |
| `commission_window_ends_at` | S | 12 months after attributed_at | `"2027-05-28T14:00:00Z"` |
| `ip_address` | S | For fraud detection | `"203.0.113.42"` |
| `revoke_reason` | S (optional) | Reason if revoked | `null` |
| `GSI1PK` | S | `REFERRALS#{referrer_user_id}` | `"REFERRALS#alice@test.local"` |
| `GSI1SK` | S | `{attributed_at}#REF#{referred_user_id}` | `"2026-05-28T14:00:00Z#REF#bob@test.local"` |

### 5.3 Affiliate Commission Entry

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `AFFILIATE#{referrer_user_id}` | `"AFFILIATE#alice@test.local"` |
| `sk` | S | `COMMISSION#{timestamp}#{tx_id}` | `"COMMISSION#1748476800#tx_abc123"` |
| `Entity` | S | `AffiliateCommission` | `"AffiliateCommission"` |
| `referrer_user_id` | S | Who earns the commission | `"alice@test.local"` |
| `referred_user_id` | S | Whose purchase generated it | `"bob@test.local"` |
| `source_transaction_id` | S | The underlying purchase ID | `"tx_abc123"` |
| `source_type` | S | `"subscription"`, `"ppv"`, `"tip"`, `"shop"`, `"unlock"` | `"subscription"` |
| `gross_amount_cents` | N | Total transaction amount | `999` |
| `net_amount_cents` | N | After platform fee deduction | `799` |
| `commission_rate_bps` | N | Rate in basis points (500 = 5%) | `500` |
| `commission_cents` | N | Actual commission earned | `40` |
| `currency` | S | `"usd"` | `"usd"` |
| `status` | S | `"pending"`, `"confirmed"`, `"paid"`, `"revoked"` | `"pending"` |
| `created_at` | S | ISO 8601 | `"2026-06-15T10:00:00Z"` |

### 5.4 Access Patterns

| Access Pattern | Table/Index | Key Condition |
|---------------|-------------|---------------|
| Get referral code by code | Table PK/SK | `pk = REFCODE#{code}, sk = META` |
| List user's referral codes | GSI1 | `GSI1PK = REFCODES#{user_id}` |
| Get attribution for referred user | Table PK/SK | `pk = REFERRAL#{referred_user_id}, sk = META` |
| List referrals by referrer | GSI1 | `GSI1PK = REFERRALS#{referrer_user_id}` |
| List commissions for referrer | Table PK | `pk = AFFILIATE#{referrer_user_id}` |
| Sum commissions (dashboard) | Table PK | `pk = AFFILIATE#{referrer_user_id}` (scan all, aggregate in code) |

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/referrals/code` | `require_ui_session` | Generate a new referral code |
| GET | `/ui/referrals/codes` | `require_ui_session` | List own referral codes |
| DELETE | `/ui/referrals/codes/{code}` | `require_ui_session` | Deactivate a referral code |
| GET | `/ui/referrals/dashboard` | `require_ui_session` | Referral stats (signups, conversions, earnings) |
| GET | `/ui/referrals/commissions` | `require_ui_session` | List commission entries with pagination |
| GET | `/ui/referrals/attribution` | `require_ui_session` | See who referred the current user (if anyone) |
| POST | `/ui/referrals/withdraw` | `require_ui_session` | Request payout of accumulated commissions |
| POST | `/internal/referrals/attribute` | Internal API | Record referral attribution at signup |
| POST | `/internal/referrals/commission` | Internal API | Calculate and record commission on a purchase |

### 6.2 POST `/ui/referrals/code`

**Response (201):**

```json
{
  "code": "ABC12345",
  "link": "https://platform.com/?ref=ABC12345",
  "commission_tier": "standard",
  "created_at": "2026-05-27T10:00:00Z"
}
```

**Error responses:**
- `429`: Maximum 5 active referral codes

### 6.3 GET `/ui/referrals/dashboard`

**Response (200):**

```json
{
  "total_referrals": 12,
  "confirmed_referrals": 8,
  "pending_referrals": 4,
  "total_earned_cents": 45000,
  "pending_commission_cents": 5000,
  "paid_commission_cents": 30000,
  "available_for_withdrawal_cents": 15000,
  "referral_codes": [
    {
      "code": "ABC12345",
      "active": true,
      "commission_tier": "standard",
      "referral_count": 8,
      "created_at": "2026-05-27T10:00:00Z"
    }
  ]
}
```

### 6.4 GET `/ui/referrals/commissions`

**Query parameters:**
- `limit` (int, default 50): Page size
- `cursor` (string, optional): Pagination cursor
- `status` (string, optional): Filter by status

**Response (200):**

```json
{
  "commissions": [
    {
      "source_type": "subscription",
      "referred_user_id": "bob@test.local",
      "gross_amount_cents": 999,
      "commission_cents": 40,
      "commission_rate_bps": 500,
      "status": "confirmed",
      "created_at": "2026-06-15T10:00:00Z"
    }
  ],
  "next_cursor": null
}
```

### 6.5 POST `/ui/referrals/withdraw`

**Request:**

```json
{
  "amount_cents": 10000
}
```

**Response (200):**

```json
{
  "ok": true,
  "payout_request_id": "payout_xyz789",
  "amount_cents": 10000,
  "status": "pending"
}
```

**Error responses:**
- `400`: Amount below minimum ($10)
- `400`: Insufficient confirmed balance

### 6.6 GET `/ui/referrals/attribution`

**Response (200) -- user was referred:**

```json
{
  "referred_by": {
    "user_id": "alice@test.local",
    "display_name": "Alice",
    "attributed_at": "2026-05-28T14:00:00Z"
  }
}
```

**Response (200) -- user was not referred:**

```json
{
  "referred_by": null
}
```

### 6.7 Rate Limits

| Endpoint | Per-user | Notes |
|----------|----------|-------|
| POST /code | 5 active codes max | Not time-based; count-based |
| GET /dashboard | 60/min | Standard |
| POST /withdraw | 5/day | Prevent withdrawal spam |

---

## 7. Backend Implementation

### 7.1 Referral Code Generation

```python
@router.post("/referrals/code", status_code=201)
def create_referral_code(ctx=Depends(require_ui_session)):
    user_id = ctx["user_sub"]

    # Rate limit: max 5 active codes per user
    existing = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk",
        ExpressionAttributeValues={":pk": f"REFCODES#{user_id}"},
    )
    active_count = sum(1 for item in existing.get("Items", []) if item.get("active"))
    if active_count >= S.referral_max_codes_per_user:
        raise HTTPException(status_code=429, detail="maximum active referral codes reached")

    code = _generate_unique_code()  # 8-char alphanumeric
    now = now_iso()
    item = {
        "pk": f"REFCODE#{code}",
        "sk": "META",
        "Entity": "ReferralCode",
        "code": code,
        "owner_user_id": user_id,
        "created_at": now,
        "active": True,
        "commission_tier": "standard",
        "GSI1PK": f"REFCODES#{user_id}",
        "GSI1SK": f"{now}#REFCODE#{code}",
    }
    tbl.put_item(Item=item)
    return {"code": code, "link": f"{S.public_base_url}/?ref={code}"}  # <!-- VERIFIED: S.public_base_url exists in settings.py:286 -->
```

### 7.2 Attribution at Signup

```python
def attribute_referral(referred_user_id: str, referral_code: str, ip_address: str):
    code_item = tbl.get_item(Key={"pk": f"REFCODE#{referral_code}", "sk": "META"}).get("Item")
    if not code_item or not code_item.get("active"):
        return None

    referrer_id = code_item["owner_user_id"]

    # Self-referral prevention
    if referrer_id == referred_user_id:
        logger.warning("Self-referral blocked: %s", referrer_id)
        return None

    # Check if user already has attribution
    existing = tbl.get_item(Key={"pk": f"REFERRAL#{referred_user_id}", "sk": "META"}).get("Item")
    if existing:
        return None

    now = now_iso()
    commission_window_end = (datetime.fromisoformat(now.replace("Z", "+00:00")) + timedelta(days=365)).isoformat()

    item = {
        "pk": f"REFERRAL#{referred_user_id}",
        "sk": "META",
        "Entity": "ReferralAttribution",
        "referred_user_id": referred_user_id,
        "referrer_user_id": referrer_id,
        "referral_code": referral_code,
        "attributed_at": now,
        "attribution_source": "cookie",
        "status": "pending",
        "commission_window_ends_at": commission_window_end,
        "ip_address": ip_address,
        "GSI1PK": f"REFERRALS#{referrer_id}",
        "GSI1SK": f"{now}#REF#{referred_user_id}",
    }
    tbl.put_item(Item=item)
    return item
```

### 7.3 Commission Calculation

```python
def record_affiliate_commission(
    referred_user_id: str, transaction_id: str, source_type: str,
    gross_amount_cents: int, platform_fee_cents: int,
):
    attribution = tbl.get_item(
        Key={"pk": f"REFERRAL#{referred_user_id}", "sk": "META"}
    ).get("Item")
    if not attribution or attribution["status"] == "revoked":
        return None

    if now_iso() > attribution["commission_window_ends_at"]:
        return None

    referrer_id = attribution["referrer_user_id"]
    net_amount = gross_amount_cents - platform_fee_cents

    code_item = tbl.get_item(
        Key={"pk": f"REFCODE#{attribution['referral_code']}", "sk": "META"}
    ).get("Item")
    tier = (code_item or {}).get("commission_tier", "standard")
    rate_bps = S.referral_standard_rate_bps if tier == "standard" else S.referral_premium_rate_bps

    commission_cents = max(1, (net_amount * rate_bps) // 10000)

    entry = {
        "pk": f"AFFILIATE#{referrer_id}",
        "sk": f"COMMISSION#{now_ts()}#{transaction_id}",
        "Entity": "AffiliateCommission",
        "referrer_user_id": referrer_id,
        "referred_user_id": referred_user_id,
        "source_transaction_id": transaction_id,
        "source_type": source_type,
        "gross_amount_cents": gross_amount_cents,
        "net_amount_cents": net_amount,
        "commission_rate_bps": rate_bps,
        "commission_cents": commission_cents,
        "currency": "usd",
        "status": "pending",
        "created_at": now_iso(),
    }
    tbl.put_item(Item=entry)
    return entry
```

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
ReferralDashboard (/referrals)
  |-- StatsCards
  |     |-- TotalReferrals card
  |     |-- ConfirmedReferrals card
  |     |-- TotalEarned card
  |     |-- AvailableForWithdrawal card
  |-- ReferralCodeSection
  |     |-- ReferralCodeCard[] (existing codes)
  |     |     |-- Code display (monospace font)
  |     |     |-- CopyLinkButton (copies full URL to clipboard)
  |     |     |-- DeactivateButton
  |     |     |-- ReferralCount badge
  |     |-- GenerateNewCodeButton
  |-- CommissionHistory
  |     |-- Table
  |     |     |-- Columns: Date, Source Type, Amount, Commission, Status
  |     |     |-- Rows: paginated commission entries
  |     |-- LoadMoreButton
  |-- WithdrawSection
        |-- Available balance display
        |-- AmountInput
        |-- WithdrawButton (disabled if < $10)
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/referrals/ReferralDashboard.tsx` | Main referral page: stats, codes, commissions |
| `frontend/src/pages/referrals/ReferralCodeCard.tsx` | Referral code display with copy-to-clipboard |
| `frontend/src/pages/referrals/CommissionHistory.tsx` | Paginated commission entries table |
| `frontend/src/api/endpoints/referrals.ts` | API client for referral endpoints |

### 8.3 React Query Hooks

```typescript
export const useReferralDashboard = () => useQuery({
  queryKey: ["referrals", "dashboard"],
  queryFn: () => client.get("/ui/referrals/dashboard").then(r => r.data),
});

export const useReferralCodes = () => useQuery({
  queryKey: ["referrals", "codes"],
  queryFn: () => client.get("/ui/referrals/codes").then(r => r.data),
});

export const useCommissions = (filters?: { status?: string }) => useInfiniteQuery({
  queryKey: ["referrals", "commissions", filters],
  queryFn: ({ pageParam }) =>
    client.get("/ui/referrals/commissions", { params: { ...filters, cursor: pageParam } }).then(r => r.data),
  getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
});

export const useCreateCode = () => useMutation({
  mutationFn: () => client.post("/ui/referrals/code"),
  onSuccess: () => {
    queryClient.invalidateQueries(["referrals", "codes"]);
    queryClient.invalidateQueries(["referrals", "dashboard"]);
  },
});

export const useWithdraw = () => useMutation({
  mutationFn: (body: { amount_cents: number }) => client.post("/ui/referrals/withdraw", body),
  onSuccess: () => queryClient.invalidateQueries(["referrals", "dashboard"]),
});
```

### 8.4 Attribution Cookie (main.tsx)

```tsx
useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const refCode = params.get("ref");
  if (refCode && /^[A-Za-z0-9]{8}$/.test(refCode)) {
    document.cookie = `ref_attribution=${refCode}; path=/; max-age=${30 * 86400}; SameSite=Lax`;
  }
}, []);
```

### 8.5 Route

Add to `App.tsx`:
```tsx
<Route path="/referrals" element={<ReferralDashboard />} />
```

Add "Referrals" to the sidebar navigation under a "Growth" group with the `Share2` icon from lucide-react.

---

## 9. Security & Privacy Considerations

### 9.1 Fraud Prevention

- **Self-referral**: Blocked by comparing `referrer_user_id == referred_user_id`. Also checked via IP address (same IP for referrer and referred within 24 hours is flagged).
- **Referral farming**: If a referrer generates many signups from the same IP prefix, flag for manual review.
- **Ban-and-revoke**: If a referred account is banned within 30 days, the referral attribution is revoked and all pending commissions are cancelled.
- **Holdback period**: Referrals are `pending` for 7 days before becoming `confirmed`. This prevents commission on accounts that sign up and immediately chargeback.

### 9.2 Data Protection

- IP addresses stored for fraud detection only; not displayed in the UI or included in data exports (except the user's own IP).
- Commission entries include `referred_user_id` which reveals a relationship. This is necessary for transparency but should be masked in public-facing views (show display name, not user ID).

### 9.3 Input Validation

- Referral codes: 8-character alphanumeric only (`^[A-Za-z0-9]{8}$`).
- Attribution cookie: Validated against the same regex before processing.
- Withdrawal amount: Must be >= `REFERRAL_MIN_WITHDRAWAL_CENTS` (default $10) and <= available balance.

---

## 10. Performance & Scalability

### 10.1 DynamoDB Costs

| Operation | Reads/Writes | Frequency |
|-----------|-------------|-----------|
| Create referral code | 1 GSI query + 1 put | Rare (once per code) |
| Attribution at signup | 2 get_items + 1 put | Once per signup |
| Record commission | 2 get_items + 1 put | Per qualifying purchase |
| Dashboard stats | 1 GSI query + 1 PK query | On page load |
| Commission list | 1 PK query (paginated) | On page load |

All operations are single-digit millisecond latency. No hot partitions expected unless a single referrer has millions of commissions (mitigated by pagination).

### 10.2 Billing Hook Performance

The `record_affiliate_commission` function adds 2 DDB reads to every qualifying purchase. This adds ~10ms to purchase processing. The function exits early (no-op) if no attribution exists for the buyer.

### 10.3 Known Bottlenecks

- **Dashboard aggregation**: The dashboard sums all commissions for a referrer by scanning `AFFILIATE#{user_id}`. For referrers with 10,000+ commissions, this becomes slow. Mitigation: maintain a denormalized running total (updated atomically on each commission write).
- **Code uniqueness check**: `_generate_unique_code()` generates a random 8-char code and checks for collisions. With 36^8 = ~2.8 trillion possible codes, collisions are extremely unlikely but the check is still needed.

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `REFERRAL_ENABLED` | `true` | Master feature flag |
| `REFERRAL_COOKIE_MAX_AGE_DAYS` | `30` | Attribution cookie lifetime |
| `REFERRAL_COMMISSION_WINDOW_DAYS` | `365` | Commission duration after signup |
| `REFERRAL_STANDARD_RATE_BPS` | `500` | Standard tier (5%) |
| `REFERRAL_PREMIUM_RATE_BPS` | `1000` | Premium tier (10%) |
| `REFERRAL_MAX_CODES_PER_USER` | `5` | Max active codes |
| `REFERRAL_HOLDBACK_DAYS` | `7` | Days before pending becomes confirmed |
| `REFERRAL_MIN_WITHDRAWAL_CENTS` | `1000` | Min withdrawal ($10) |

### 11.2 Incremental Deployment

1. **Phase 1**: Deploy DDB schema + attribution service. Start recording attributions silently (no UI).
2. **Phase 2**: Deploy commission hook in billing. Start recording commissions (no UI).
3. **Phase 3**: Deploy referral dashboard frontend. Users can see their codes and stats.
4. **Phase 4**: Deploy withdrawal integration with MON-004 payout system.

### 11.3 Rollback

- Set `REFERRAL_ENABLED=false`. Referral dashboard hidden. Attribution cookie ignored. Commission hook is a no-op.
- Existing data remains in `app_single_table` and can be re-activated.
- No database migration needed.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| # | Test | File |
|---|------|------|
| 1 | Code generation produces 8-char alphanumeric codes | `tests/test_referrals.py` |
| 2 | Self-referral is blocked | `tests/test_referrals.py` |
| 3 | Duplicate attribution is ignored | `tests/test_referrals.py` |
| 4 | Attribution with deactivated code is blocked | `tests/test_referrals.py` |
| 5 | Commission calculation: 5% of net amount | `tests/test_referrals.py` |
| 6 | Commission blocked after window expires | `tests/test_referrals.py` |
| 7 | Commission blocked for revoked attribution | `tests/test_referrals.py` |
| 8 | Dashboard stats aggregate correctly | `tests/test_referrals.py` |
| 9 | Max 5 active codes enforced | `tests/test_referrals.py` |
| 10 | Withdrawal minimum enforced | `tests/test_referrals.py` |

### 12.2 E2E Tests

**Test File:** `frontend/e2e/referrals.spec.ts`

**Section 1: Referral Code CRUD API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Generate referral code | 201; response has `code` (8 chars) and `link` with `ref=` param |
| 2 | List own referral codes | 200; contains the generated code |
| 3 | Deactivate referral code | 200; re-list shows code with `active: false` |
| 4 | Max 5 active codes enforced | 6th code creation returns 429 |
| 5 | Code is globally unique | Two users' codes do not collide |

**Section 2: Attribution API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | Attribution recorded at signup | Internal attribute call; GET attribution returns referrer info |
| 7 | Self-referral blocked | Attribute with own user ID; returns null / no record created |
| 8 | Duplicate attribution ignored | Attribute same user twice; only first attribution stored |
| 9 | Attribution with deactivated code blocked | Deactivate code; attribute with it; returns null |

**Section 3: Commission API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | Commission recorded on referred user purchase | Record commission; GET commissions; entry present with correct `commission_cents` |
| 11 | Commission rate is 5% (500 bps) for standard tier | `commission_cents = floor(net_amount * 0.05)` |
| 12 | Commission blocked after window expires | Set `commission_window_ends_at` in past; no commission recorded |
| 13 | Commission revoked when attribution is revoked | Revoke attribution; existing commissions status = "revoked" |

**Section 4: Dashboard API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | Dashboard shows correct referral counts | `total_referrals`, `confirmed_referrals`, `pending_referrals` match expected |
| 15 | Dashboard shows correct earnings | `total_earned_cents`, `pending_commission_cents` match sum |
| 16 | Dashboard shows available withdrawal amount | `available_for_withdrawal_cents = total_earned - paid` |

**Section 5: Referral Dashboard UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 17 | Referral page renders stats cards | Navigate to `/referrals`; stats cards visible |
| 18 | Copy referral link button works | Click copy; clipboard contains URL with `ref=` |
| 19 | Commission history table shows entries | Table rows with source type, amount, status columns |

---

## 13. Monitoring & Alerting

### 13.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `referral_code_created_total` | Counter | - | Codes generated |
| `referral_attribution_total` | Counter | `status` (recorded/blocked/self_referral) | Attribution attempts |
| `referral_commission_total` | Counter | `source_type` | Commissions recorded |
| `referral_commission_cents` | Counter | `source_type` | Total commission value |
| `referral_withdrawal_total` | Counter | `status` (success/insufficient/below_min) | Withdrawal attempts |
| `referral_revocation_total` | Counter | `reason` (ban/fraud) | Attributions revoked |

### 13.2 Dashboard Queries

- **Conversion rate**: `referral_attribution_total{status="recorded"} / total_signups` -- referral-driven signups
- **Commission value**: `rate(referral_commission_cents[1d])` -- daily commission volume
- **Fraud rate**: `referral_revocation_total / referral_attribution_total{status="recorded"}`

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| High self-referral rate | `referral_attribution_total{status="self_referral"}` > 50/hour | Warning |
| Unusual commission volume | Daily commission_cents > 5x 7-day average | Warning |
| Withdrawal processing failure | Withdrawal errors > 5% | Critical |
| Single referrer spike | One user generates > 100 referrals in 24h | Warning (possible fraud) |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **Premium tier eligibility**: Who qualifies for the 10% premium tier? Options: (a) all creators with >100 subscribers, (b) manual admin approval, (c) creators who reach a spending threshold. Recommendation: start with admin-approved premium tier.
2. **Multi-level referrals**: Should there be a second-tier commission (e.g., 1% on referrals of referrals)? This adds complexity and potential for pyramid-scheme optics. Recommendation: single-tier only.
3. **Referral bonuses for the referred user**: Should the new user also receive a benefit (e.g., $5 credit)? This increases conversion but costs money. Recommendation: defer to a separate promo system.
4. **Cookie vs. code entry**: Should users be able to manually enter a referral code during registration (for cases where cookies are blocked)? Recommendation: yes, add optional `referral_code` field to registration form.

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Cookie blocked by browser privacy settings | Medium | Medium | Support manual code entry in registration form |
| Commission gaming via fake purchases + chargebacks | Medium | High | 7-day holdback; revoke on chargeback |
| High-volume referrer creates DDB hot partition | Low | Medium | `AFFILIATE#{user_id}` partition; DDB on-demand handles burst |
| Race condition on code uniqueness check | Very Low | Low | Conditional put with `attribute_not_exists(pk)` |

### 14.3 Dependency Risks

- **MON-004 (Creator Payouts)**: Required for withdrawals. If not deployed, commissions accumulate but cannot be withdrawn. <!-- VERIFIED: app/services/creator_payouts.py exists -->
- **Registration Flow**: Attribution hook must be added to `app/routers/register.py`. <!-- CORRECTED: was "app/routers/auth.py or app/routers/register.py". app/routers/auth.py does not exist; registration is only in register.py -->
- **Billing Service**: Commission hook must be added to every qualifying purchase path in `app/services/billing_shared.py`. <!-- CORRECTED: was app/services/billing.py, which does not exist. The billing services are: billing_shared.py, billing_ccbill.py, billing_dunning.py, billing_reconcile.py -->

---

## 15. Implementation Timeline

### Phase 1: Data Model + Core Backend (Days 1-4)

| Day | Task |
|-----|------|
| 1 | Add `REFERRAL_*` settings to `app/core/settings.py`. No new table needed (uses `app_single_table`). |
| 2 | Create `app/services/referrals.py` with code generation, attribution, commission calculation. |
| 3 | Create `app/routers/referrals.py` with user-facing endpoints. Register in `app/main.py`. |
| 4 | Integrate attribution hook into registration flow. Integrate commission hook into billing service. |

### Phase 2: Dashboard Backend + Frontend (Days 5-8)

| Day | Task |
|-----|------|
| 5 | Implement dashboard stats endpoint, commission list endpoint, withdrawal endpoint. |
| 6 | Create `ReferralDashboard.tsx` with stats cards and code management. |
| 7 | Create `ReferralCodeCard.tsx` with copy-to-clipboard. Create `CommissionHistory.tsx`. |
| 8 | Add attribution cookie capture to `main.tsx`. Add route + sidebar link. Add TypeScript types. |

### Phase 3: Frontend Polish + API Client (Days 9-10)

| Day | Task |
|-----|------|
| 9 | Create `api/endpoints/referrals.ts` with all hooks. Wire withdrawal flow to MON-004 payout UI. |
| 10 | Handle empty states, loading states, error states. Test cookie behavior across browsers. |

### Phase 4: E2E Tests + QA (Days 11-14)

| Day | Task |
|-----|------|
| 11 | Write E2E tests sections 1-2 (code CRUD, attribution). |
| 12 | Write E2E tests sections 3-4 (commission, dashboard). |
| 13 | Write E2E tests section 5 (UI). Run full suite. |
| 14 | Manual QA, fraud scenario testing, code review. |

---

## 16. Files to Create

| File | Purpose |
|------|---------|
| `app/services/referrals.py` | Referral code CRUD, attribution, commission calculation |
| `app/routers/referrals.py` | API endpoints for referral management |
| `frontend/src/pages/referrals/ReferralDashboard.tsx` | Dashboard page |
| `frontend/src/pages/referrals/ReferralCodeCard.tsx` | Code card component |
| `frontend/src/pages/referrals/CommissionHistory.tsx` | Commission table component |
| `frontend/src/api/endpoints/referrals.ts` | API client |
| `frontend/e2e/referrals.spec.ts` | E2E tests |

## 17. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register referrals router |
| `app/core/settings.py` | Add `REFERRAL_*` settings |
| `app/routers/register.py` | Check `ref_attribution` cookie at registration; call `attribute_referral()` | <!-- CORRECTED: app/routers/auth.py does not exist; only register.py -->
| `app/services/billing_shared.py` | Add hook to call `record_affiliate_commission()` on qualifying purchases | <!-- CORRECTED: app/services/billing.py does not exist; billing functions are in billing_shared.py -->
| `frontend/src/main.tsx` | Attribution cookie capture from URL `ref` parameter |
| `frontend/src/api/types.ts` | Add `ReferralCode`, `ReferralAttribution`, `AffiliateCommission`, `ReferralDashboardStats` interfaces |
| `frontend/src/App.tsx` | Add `/referrals` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Referrals" nav link |

---

## 18. Dependencies

- **MON-004 (Creator Payouts)**: Affiliate commissions are withdrawn through the existing payout pipeline.
- **Billing Ledger**: Commission entries integrate with the existing ledger system.
- **Registration Flow**: Attribution requires hooking into the signup process.

---

## 19. Acceptance Criteria

1. User can generate a referral code and copy a shareable link.
2. Clicking a referral link sets a 30-day attribution cookie.
3. Signing up with an active attribution cookie creates a referral attribution record.
4. Self-referral is blocked (same user ID).
5. Referrer earns 5% commission on referred user's qualifying purchases.
6. Commission entries appear in the referrer's commission history.
7. Dashboard shows referral counts (total, pending, confirmed) and earnings breakdown.
8. Referrer can withdraw accumulated confirmed commissions (min $10).
9. Referral attribution is revoked if the referred account is banned within 30 days.
10. Commission window expires 12 months after the referred user's signup.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `app/services/creator_payouts.py` | `app/services/creator_payouts.py` | exists | VERIFIED |
| `app/routers/creator_payouts.py` | `app/routers/creator_payouts.py` | exists | VERIFIED (registered in main.py) |
| Payout records in billing table | `app/core/tables.py` | 22/106 (billing), 86/169 (creator_payouts) | CORRECTED: payouts use a separate `creator_payouts` table, not the billing table |
| `app/services/billing.py` | N/A | N/A | DOES NOT EXIST (CORRECTED to `app/services/billing_shared.py` + `billing_ccbill.py` + `billing_dunning.py` + `billing_reconcile.py`) |
| `new_ledger_entry` billing function | `app/services/billing_shared.py` | 217 | VERIFIED |
| `app/routers/auth.py` | N/A | N/A | DOES NOT EXIST (CORRECTED to `app/routers/register.py`) |
| Registration functions | `app/routers/register.py` | 61 (register_start), 154 (register_check), 188 (register_confirm), 233 (register_resend) | VERIFIED |
| `S.public_base_url` | `app/core/settings.py` | 286 | VERIFIED |
| `billing` table handle | `app/core/tables.py` | 22/106 | VERIFIED: `T.billing` |
| `S.billing_table_name` | `app/core/settings.py` | 306 | VERIFIED |
| `app_single_table` DDB table | `scripts/local-ddb-init.py` | 217 | VERIFIED: PK=pk, SK=sk, GSI1-GSI5 (referral entities use this table) |
| `app/core/settings.py` | `app/core/settings.py` | 1-1197 | VERIFIED: frozen dataclass; no `REFERRAL_*` settings exist yet |
| `require_ui_session` auth dependency | `app/auth/deps.py` | 184+ | VERIFIED |

### Key Corrections Summary

1. **`app/routers/auth.py` does not exist** -- registration is in `app/routers/register.py`.
2. **`app/services/billing.py` does not exist** -- billing services are split across `billing_shared.py`, `billing_ccbill.py`, `billing_dunning.py`, `billing_reconcile.py`.
3. **Payout records are in a dedicated `creator_payouts` table**, not in the `billing` table with `pk=PAYOUT#{user_id}` as claimed.
