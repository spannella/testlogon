# ADS-001: Advertiser Accounts & Campaign Manager

**Ticket**: ADS-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: Billing ledger (`app/services/billing_shared.py`), Admin moderation (`app/auth/deps.py`)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-001 establishes the foundation of the advertising platform: advertiser accounts and a campaign hierarchy. An advertiser account is a separate entity from a regular user account — any user can create an advertiser account, which grants access to the campaign manager. The hierarchy follows the industry-standard structure: Account > Campaigns > Ad Groups > Ads (Creatives).

This ticket covers advertiser account creation and lifecycle, campaign CRUD with approval workflows, and the frontend campaign manager dashboard. Ad groups and creatives are defined here structurally but their full implementation is split to ADS-002 (creatives) and ADS-003 (targeting via ad groups).

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to create an advertiser account so I can run ads. | POST to create account; status starts as `pending_review`. |
| Advertiser | As an advertiser, I want to create campaigns with names, objectives, and budgets. | Campaign CRUD with validation; campaign appears in dashboard. |
| Advertiser | As an advertiser, I want to pause and resume campaigns. | PATCH status to `paused`/`active`; serving stops/resumes. |
| Advertiser | As an advertiser, I want to set daily and lifetime budget caps. | Budget fields enforced; campaign auto-pauses when exhausted. |
| Admin | As an admin, I want to review and approve new advertiser accounts. | Admin endpoint to approve/reject; status transitions. |
| Admin | As an admin, I want to review and approve new campaigns before they serve. | Campaign review endpoint; campaigns start in `pending_review`. |

### 1.3 Why This Is Needed

The existing `ad_placement.py` service serves VOD-only ads using hardcoded dev placeholders. There is no concept of an advertiser, no campaign management, and no budget tracking. Every other ADS ticket depends on this foundational account and campaign infrastructure. Without it, the ad system cannot scale beyond static dev-mode placeholders.

### 1.4 Campaign Hierarchy

```
Advertiser Account (ad_accounts)
    │
    ├── Campaign 1 (ad_campaigns)
    │   ├── Ad Group A (ad_groups — ADS-003)
    │   │   ├── Ad/Creative 1 (ad_creatives — ADS-002)
    │   │   └── Ad/Creative 2
    │   └── Ad Group B
    │       └── Ad/Creative 3
    │
    └── Campaign 2
        └── Ad Group C
            └── Ad/Creative 4
```

### 1.5 Account & Campaign Lifecycle

```
Advertiser Account Lifecycle:
  pending_review ──→ active ──→ suspended
       │                │           │
       └── rejected     │           └── active (reinstated by admin)
                        └── suspended (by admin for policy violation)

Campaign Lifecycle:
  draft ──→ pending_review ──→ active ──→ paused ──→ active
    │              │              │           │
    │              └── rejected   └── completed (budget exhausted or end_date passed)
    └── archived                  └── archived
```

---

## 2. Current State Analysis

### 2.1 User Roles (`app/auth/roles.py`)

The role system defines `USER`, `ADMIN`, `ROOT`. There is no `ADVERTISER` role. Rather than adding a new auth role, advertiser capability is modeled as an account ownership relationship — any `USER` can own an advertiser account. Admin/root users can review and approve advertiser accounts.

### 2.2 Billing Infrastructure (`app/services/billing_shared.py`)

The `billing` table stores per-user ledger entries with pattern `pk=USER#{user_sub}`, `sk=LEDGER#{ts}#{entry_id}`. The `new_ledger_entry()` helper generates ledger entries. The `user_pk()` helper generates the PK. This infrastructure is reused for ad account deposits (ADS-007), but ad billing uses a separate `ad_billing` table to keep advertiser spend isolated from user wallet transactions.

### 2.3 Admin Moderation Pattern

Content moderation uses admin endpoints gated by `Depends(require_admin_session)`. The same pattern applies to advertiser account and campaign review. Admin endpoints live alongside regular endpoints in the same router, distinguished by path prefix (`/v1/admin/ads/...`).

### 2.4 Existing Ad Placement (`app/services/ad_placement.py`)

The current ad placement service uses `DEV_AD_CREATIVES` — a hardcoded list of three placeholder creatives. It has no concept of campaigns, budgets, or advertiser accounts. The `record_ad_impression()` function writes to the `ad_impressions` table and credits creator revenue, but does not debit any advertiser account. ADS-001 provides the account structure that later tickets (ADS-004, ADS-007) will integrate with impression tracking and billing.

### 2.5 Gaps

1. **No advertiser account model** — users cannot register as advertisers.
2. **No campaign model** — no campaign CRUD or lifecycle management.
3. **No ad group model** — no grouping structure between campaigns and creatives.
4. **No admin review workflow** — no approval flow for accounts or campaigns.
5. **No advertiser dashboard** — no frontend for managing campaigns.
6. **No budget tracking** — no daily/lifetime budget enforcement.

---

## 3. Technical Design

### 3.1 DynamoDB Tables

#### 3.1.1 `ad_accounts` Table

| PK | SK | Fields |
|----|----|--------|
| `ACCT#{account_id}` | `META` | `account_id`, `owner_sub`, `company_name`, `billing_email`, `status`, `balance_cents`, `lifetime_spend_cents`, `created_at`, `updated_at`, `reviewed_by`, `review_notes`, `suspended_reason` |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByOwner` | `owner_sub` (S) | `created_at` (N) | List accounts owned by a user |
| `ByStatus` | `status` (S) | `created_at` (N) | Admin: list accounts by status for review |

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_ACCOUNTS", "AdAccounts"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByOwner", "partition_key": "owner_sub", "sort_key": "created_at"},
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

#### 3.1.2 `ad_campaigns` Table

| PK | SK | Fields |
|----|----|--------|
| `ACCT#{account_id}` | `CAMPAIGN#{campaign_id}` | `campaign_id`, `account_id`, `name`, `objective`, `budget_cents`, `budget_type`, `daily_budget_cents`, `spent_today_cents`, `lifetime_spent_cents`, `status`, `start_date`, `end_date`, `created_at`, `updated_at`, `reviewed_by`, `review_notes` |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByStatusCreatedAt` | `status` (S) | `created_at` (N) | Admin: list campaigns by status |
| `ByCampaignId` | `campaign_id` (S) | `created_at` (N) | Lookup campaign by ID without knowing account |

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_CAMPAIGNS", "AdCampaigns"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByCampaignId", "partition_key": "campaign_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

### 3.2 Backend Models

**File**: `app/models.py`

```python
class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=5, max_length=254)

class AdAccountOut(BaseModel):
    account_id: str
    owner_sub: str
    company_name: str
    billing_email: str
    status: str  # pending_review, active, suspended, rejected
    balance_cents: int = 0
    lifetime_spend_cents: int = 0
    created_at: int
    updated_at: int

class AdAccountReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approve|reject|suspend)$")
    notes: Optional[str] = Field(default=None, max_length=1000)

class CampaignCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(..., pattern=r"^(awareness|traffic|conversions)$")
    budget_cents: int = Field(..., ge=100)  # Minimum $1
    budget_type: str = Field(..., pattern=r"^(daily|lifetime)$")
    start_date: Optional[int] = None  # Unix timestamp
    end_date: Optional[int] = None    # Unix timestamp

class CampaignUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    budget_cents: Optional[int] = Field(default=None, ge=100)
    budget_type: Optional[str] = Field(default=None, pattern=r"^(daily|lifetime)$")
    status: Optional[str] = Field(default=None, pattern=r"^(draft|active|paused|archived)$")
    start_date: Optional[int] = None
    end_date: Optional[int] = None

class CampaignOut(BaseModel):
    campaign_id: str
    account_id: str
    name: str
    objective: str
    budget_cents: int
    budget_type: str
    daily_budget_cents: int = 0
    spent_today_cents: int = 0
    lifetime_spent_cents: int = 0
    status: str
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    created_at: int
    updated_at: int

class CampaignReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approve|reject)$")
    notes: Optional[str] = Field(default=None, max_length=1000)
```

### 3.3 Backend Service

**File**: `app/services/ad_accounts.py`

```python
def create_ad_account(owner_sub: str, data: AdAccountCreateIn) -> dict:
    """Create a new advertiser account in pending_review status."""
    account_id = f"adacct_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": owner_sub,
        "company_name": data.company_name,
        "billing_email": data.billing_email,
        "status": "pending_review",
        "balance_cents": 0,
        "lifetime_spend_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_accounts.put_item(Item=item)
    return item

def get_ad_account(account_id: str) -> Optional[dict]:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    return resp.get("Item")

def list_accounts_by_owner(owner_sub: str) -> list[dict]:
    resp = T.ad_accounts.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("owner_sub").eq(owner_sub),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])

def list_accounts_by_status(status: str) -> list[dict]:
    resp = T.ad_accounts.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])

def review_ad_account(account_id: str, reviewer_sub: str, decision: str, notes: str = "") -> dict:
    new_status = "active" if decision == "approve" else decision  # "reject" or "suspend"
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status, ":r": reviewer_sub, ":n": notes, ":u": now_ts()},
    )
    return {"ok": True, "status": new_status}
```

**File**: `app/services/ad_campaigns.py`

```python
def create_campaign(account_id: str, data: CampaignCreateIn) -> dict:
    """Create a new campaign in draft status."""
    campaign_id = f"camp_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    daily = data.budget_cents if data.budget_type == "daily" else 0
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": f"CAMPAIGN#{campaign_id}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "name": data.name,
        "objective": data.objective,
        "budget_cents": data.budget_cents,
        "budget_type": data.budget_type,
        "daily_budget_cents": daily,
        "spent_today_cents": 0,
        "lifetime_spent_cents": 0,
        "status": "draft",
        "start_date": data.start_date,
        "end_date": data.end_date,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_campaigns.put_item(Item={k: v for k, v in item.items() if v is not None})
    return item

def get_campaign(account_id: str, campaign_id: str) -> Optional[dict]:
    resp = T.ad_campaigns.get_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"}
    )
    return resp.get("Item")

def list_campaigns(account_id: str) -> list[dict]:
    resp = T.ad_campaigns.query(
        KeyConditionExpression=Key("pk").eq(f"ACCT#{account_id}") & Key("sk").begins_with("CAMPAIGN#"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])

def update_campaign(account_id: str, campaign_id: str, data: CampaignUpdateIn) -> dict:
    updates = {k: v for k, v in data.dict(exclude_none=True).items()}
    updates["updated_at"] = now_ts()
    # Validate status transitions
    if "status" in updates:
        current = get_campaign(account_id, campaign_id)
        _validate_campaign_transition(current["status"], updates["status"])
    expr_parts, attr_values, attr_names = [], {}, {}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#f{i}"
        val_alias = f":v{i}"
        attr_names[alias] = k
        attr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )
    return {"ok": True}

def submit_campaign_for_review(account_id: str, campaign_id: str) -> dict:
    """Transition campaign from draft to pending_review."""
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET #s = :s, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "pending_review", ":u": now_ts()},
        ConditionExpression="#s = :draft",
    )
    return {"ok": True}

def review_campaign(campaign_id: str, reviewer_sub: str, decision: str, notes: str = "") -> dict:
    """Admin review: approve or reject a campaign."""
    # Look up campaign by ID via GSI
    resp = T.ad_campaigns.query(
        IndexName="ByCampaignId",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    item = items[0]
    new_status = "active" if decision == "approve" else "rejected"
    T.ad_campaigns.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status, ":r": reviewer_sub, ":n": notes, ":u": now_ts()},
    )
    return {"ok": True, "status": new_status}

_CAMPAIGN_TRANSITIONS = {
    "draft": {"pending_review", "archived"},
    "pending_review": {"active", "rejected"},
    "active": {"paused", "completed", "archived"},
    "paused": {"active", "archived"},
    "completed": {"archived"},
    "rejected": {"draft"},
    "archived": set(),
}

def _validate_campaign_transition(current: str, target: str) -> None:
    allowed = _CAMPAIGN_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise ValueError(f"Cannot transition campaign from {current} to {target}")
```

### 3.4 Backend Router

**File**: `app/routers/ads.py`

```python
from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import require_ui_session, require_admin_session

router = APIRouter(prefix="/ui/ads", tags=["ads"])
admin_router = APIRouter(prefix="/v1/admin/ads", tags=["ads-admin"])

# ── Advertiser Accounts ──

@router.post("/accounts", status_code=201)
def create_account(body: AdAccountCreateIn, ctx=Depends(require_ui_session)):
    return create_ad_account(ctx["user_sub"], body)

@router.get("/accounts")
def list_my_accounts(ctx=Depends(require_ui_session)):
    return list_accounts_by_owner(ctx["user_sub"])

@router.get("/accounts/{account_id}")
def get_account(account_id: str, ctx=Depends(require_ui_session)):
    acct = get_ad_account(account_id)
    if not acct or acct["owner_sub"] != ctx["user_sub"]:
        raise HTTPException(status_code=404, detail="Account not found")
    return acct

# ── Campaigns ──

@router.post("/accounts/{account_id}/campaigns", status_code=201)
def create_campaign_endpoint(account_id: str, body: CampaignCreateIn, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return create_campaign(account_id, body)

@router.get("/accounts/{account_id}/campaigns")
def list_campaigns_endpoint(account_id: str, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return list_campaigns(account_id)

@router.get("/accounts/{account_id}/campaigns/{campaign_id}")
def get_campaign_endpoint(account_id: str, campaign_id: str, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    campaign = get_campaign(account_id, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign

@router.patch("/accounts/{account_id}/campaigns/{campaign_id}")
def update_campaign_endpoint(account_id: str, campaign_id: str, body: CampaignUpdateIn, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return update_campaign(account_id, campaign_id, body)

@router.post("/accounts/{account_id}/campaigns/{campaign_id}/submit")
def submit_for_review_endpoint(account_id: str, campaign_id: str, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return submit_campaign_for_review(account_id, campaign_id)

# ── Admin ──

@admin_router.get("/accounts/pending")
def list_pending_accounts(ctx=Depends(require_admin_session)):
    return list_accounts_by_status("pending_review")

@admin_router.post("/accounts/{account_id}/review")
def review_account(account_id: str, body: AdAccountReviewIn, ctx=Depends(require_admin_session)):
    return review_ad_account(account_id, ctx["user_sub"], body.decision, body.notes or "")

@admin_router.get("/campaigns/pending")
def list_pending_campaigns(ctx=Depends(require_admin_session)):
    return list_campaigns_by_status("pending_review")

@admin_router.post("/campaigns/{campaign_id}/review")
def review_campaign_endpoint(campaign_id: str, body: CampaignReviewIn, ctx=Depends(require_admin_session)):
    return review_campaign(campaign_id, ctx["user_sub"], body.decision, body.notes or "")
```

**Registration** in `app/main.py`:
```python
from app.routers.ads import router as ads_router, admin_router as ads_admin_router
app.include_router(ads_router)
app.include_router(ads_admin_router)
```

### 3.5 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdAccount {
  account_id: string;
  owner_sub: string;
  company_name: string;
  billing_email: string;
  status: "pending_review" | "active" | "suspended" | "rejected";
  balance_cents: number;
  lifetime_spend_cents: number;
  created_at: number;
  updated_at: number;
}

export interface Campaign {
  campaign_id: string;
  account_id: string;
  name: string;
  objective: "awareness" | "traffic" | "conversions";
  budget_cents: number;
  budget_type: "daily" | "lifetime";
  daily_budget_cents: number;
  spent_today_cents: number;
  lifetime_spent_cents: number;
  status: "draft" | "pending_review" | "active" | "paused" | "completed" | "rejected" | "archived";
  start_date?: number | null;
  end_date?: number | null;
  created_at: number;
  updated_at: number;
}
```

### 3.6 Frontend API

**File**: `frontend/src/api/endpoints/ads.ts`

```typescript
import api from "../client";
import type { AdAccount, Campaign } from "../types";

export const createAdAccount = (data: { company_name: string; billing_email: string }) =>
  api.post<AdAccount>("/ui/ads/accounts", data);

export const listMyAdAccounts = () =>
  api.get<AdAccount[]>("/ui/ads/accounts");

export const getAdAccount = (accountId: string) =>
  api.get<AdAccount>(`/ui/ads/accounts/${accountId}`);

export const createCampaign = (accountId: string, data: Partial<Campaign>) =>
  api.post<Campaign>(`/ui/ads/accounts/${accountId}/campaigns`, data);

export const listCampaigns = (accountId: string) =>
  api.get<Campaign[]>(`/ui/ads/accounts/${accountId}/campaigns`);

export const getCampaign = (accountId: string, campaignId: string) =>
  api.get<Campaign>(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}`);

export const updateCampaign = (accountId: string, campaignId: string, data: Partial<Campaign>) =>
  api.patch<{ ok: boolean }>(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}`, data);

export const submitCampaignForReview = (accountId: string, campaignId: string) =>
  api.post(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}/submit`);
```

### 3.7 Frontend Pages

**File**: `frontend/src/pages/ads/AdvertiserDashboard.tsx`

- Route: `/ads/dashboard`
- Shows list of advertiser accounts owned by the current user
- "Create Advertiser Account" button opens dialog with company_name + billing_email fields
- Account cards show status badge, balance, lifetime spend
- Click account card navigates to `/ads/campaigns?account={id}`
- Pending/rejected accounts show status badge with review notes

**File**: `frontend/src/pages/ads/CampaignList.tsx`

- Route: `/ads/campaigns`
- Lists campaigns for the selected account
- "Create Campaign" button opens CampaignEditor dialog
- Campaign cards show name, objective, budget, status, spend progress bar
- Actions: Edit, Pause/Resume, Submit for Review, Archive

**File**: `frontend/src/pages/ads/CampaignEditor.tsx`

- Modal/dialog for creating and editing campaigns
- Fields: name, objective (select), budget_cents (currency input), budget_type (toggle), start_date (date picker), end_date (date picker)
- Validation: budget >= $1, end_date > start_date, name required

### 3.8 Routes

**File**: `frontend/src/App.tsx`

```tsx
<Route path="/ads/dashboard" element={<AdvertiserDashboard />} />
<Route path="/ads/campaigns" element={<CampaignList />} />
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_accounts.py` | Advertiser account CRUD + review |
| `app/services/ad_campaigns.py` | Campaign CRUD + review + status transitions |
| `app/routers/ads.py` | Advertiser + campaign endpoints + admin review endpoints |
| `frontend/src/api/endpoints/ads.ts` | API client functions |
| `frontend/src/pages/ads/AdvertiserDashboard.tsx` | Account list + create |
| `frontend/src/pages/ads/CampaignList.tsx` | Campaign list + manage |
| `frontend/src/pages/ads/CampaignEditor.tsx` | Campaign create/edit dialog |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/main.py` | Register `ads_router` and `ads_admin_router` |
| `app/models.py` | Add ad account + campaign Pydantic models |
| `app/core/settings.py` | Add `ad_accounts_table_name`, `ad_campaigns_table_name` |
| `app/core/tables.py` | Add `ad_accounts`, `ad_campaigns` table handles |
| `scripts/local-ddb-init.py` | Add `AdAccounts`, `AdCampaigns` table definitions |
| `frontend/src/api/types.ts` | Add `AdAccount`, `Campaign` types |
| `frontend/src/App.tsx` | Add `/ads/dashboard`, `/ads/campaigns` routes |

### 4.3 Step-by-Step Order

1. Add DDB table definitions to `local-ddb-init.py`
2. Add settings + table handles
3. Implement `ad_accounts.py` service
4. Implement `ad_campaigns.py` service
5. Add Pydantic models to `models.py`
6. Implement `ads.py` router
7. Register router in `main.py`
8. Add frontend types + API endpoints
9. Build AdvertiserDashboard page
10. Build CampaignList + CampaignEditor pages
11. Add routes to App.tsx
12. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-accounts-campaigns.spec.ts` — 22 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser), Bob (viewer), Root (admin reviewer)
  // via getOrCreateSession / getOrCreateAdminSession
});
```

### 5.3 Section 340: Advertiser Account API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 340.1 | Create advertiser account | POST `/ui/ads/accounts` with company_name + billing_email; 201; response has `account_id`, `status=pending_review` |
| 340.2 | List own accounts | GET `/ui/ads/accounts`; 200; array includes created account |
| 340.3 | Get account by ID | GET `/ui/ads/accounts/{id}`; 200; matches created account fields |
| 340.4 | Non-owner cannot access account | Bob GET `/ui/ads/accounts/{alice_id}`; 404 |
| 340.5 | Duplicate account creation allowed | POST second account; 201; different `account_id` |

### 5.4 Section 341: Admin Account Review API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 341.1 | List pending accounts | Root GET `/v1/admin/ads/accounts/pending`; 200; includes Alice's account |
| 341.2 | Approve account | Root POST `/v1/admin/ads/accounts/{id}/review` decision=approve; 200; status=active |
| 341.3 | Account status updated after approval | Alice GET account; status=active |
| 341.4 | Reject account | Create new account; Root POST review decision=reject; status=rejected |

### 5.5 Section 342: Campaign CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 342.1 | Create campaign | POST `/ui/ads/accounts/{id}/campaigns` with name, objective, budget; 201; status=draft |
| 342.2 | List campaigns | GET `/ui/ads/accounts/{id}/campaigns`; 200; includes created campaign |
| 342.3 | Get campaign by ID | GET `/ui/ads/accounts/{id}/campaigns/{cid}`; 200; fields match |
| 342.4 | Update campaign name | PATCH campaign with new name; 200; GET confirms name changed |
| 342.5 | Update campaign budget | PATCH budget_cents=5000; 200; GET confirms new budget |

### 5.6 Section 343: Campaign Lifecycle API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 343.1 | Submit campaign for review | POST `.../submit`; 200; status=pending_review |
| 343.2 | Admin approve campaign | Root POST review decision=approve; status=active |
| 343.3 | Pause active campaign | PATCH status=paused; 200; GET confirms paused |
| 343.4 | Resume paused campaign | PATCH status=active; 200; GET confirms active |

### 5.7 Section 344: Advertiser Dashboard UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 344.1 | Dashboard shows account list | Navigate to `/ads/dashboard`; account card visible with company name |
| 344.2 | Create account via dialog | Click "Create Advertiser Account"; fill form; submit; new card appears |
| 344.3 | Campaign list shows campaigns | Navigate to `/ads/campaigns`; campaign name visible |
| 344.4 | Campaign status badge displays correctly | Active campaign shows "Active" badge; paused shows "Paused" |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Account not found | 404 | "Account not found" |
| Not account owner | 404 | "Account not found" (do not leak existence) |
| Account not active (create campaign) | 403 | "Account is not active" |
| Campaign not found | 404 | "Campaign not found" |
| Invalid status transition | 400 | "Cannot transition campaign from {X} to {Y}" |
| Budget below minimum | 422 | Pydantic validation |
| Non-admin accessing admin endpoints | 403 | "Forbidden" |

---

## 7. Security Considerations

- Account ownership enforced on all campaign operations via `_require_account_owner()` helper
- Admin review endpoints gated by `require_admin_session`
- Account `balance_cents` is never directly settable via API (only via deposit endpoint in ADS-007)
- Campaign budgets are validated server-side; client-side validation is cosmetic only
- Rate limiting: max 5 accounts per user, max 50 campaigns per account

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Admin auth | — | Existing (`require_admin_session`) |
| Billing ledger | — | Existing (`billing_shared.py`) |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-002 (Creatives) | Campaign structure from ADS-001 |
| ADS-003 (Targeting) | Campaign structure from ADS-001 |
| ADS-004 (Ad Serving) | Account + campaign status checks |
| ADS-007 (Billing) | Account balance + budget fields |
| ADS-008 (Analytics) | Campaign hierarchy for breakdown |
