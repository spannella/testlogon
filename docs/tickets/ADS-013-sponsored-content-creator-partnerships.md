# ADS-013: Sponsored Content & Creator Partnerships

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 10-12 days  
**Dependencies**: ADS-001 (advertiser accounts), ADS-007 (ad billing), ADS-008 (ad analytics) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets. Existing: app/routers/newsfeed.py, app/services/billing_shared.py. -->

---

## 1. Overview & Motivation

### The Gap

The platform currently has two monetization channels for creators: direct payments from consumers (subscriptions, PPV, tips, unlocks) and ad revenue from ad-supported content (VOD-018, ADS-005). There is no mechanism for brands/advertisers to sponsor specific creators — paying a creator directly to feature their product or brand in content. This is one of the most lucrative monetization channels in the creator economy (Instagram influencer deals, YouTube brand sponsorships, TikTok Creator Marketplace).

Sponsorship deals are fundamentally different from regular ads: they involve a negotiation between advertiser and creator, content creation obligations, compliance requirements (FTC disclosure), and milestone-based payments. The existing ad campaign system (ADS-001) is designed for automated ad placement, not for human-negotiated content partnerships.

### Why This Is Needed

1. **Creator earnings**: Brand deals are the highest-paying monetization channel for most creators. A single sponsorship can pay more than months of ad revenue. Offering this natively keeps deals (and platform commission) in-house rather than on external platforms.

2. **Advertiser value**: Sponsored content from trusted creators has 8-10x higher engagement than display ads. Advertisers get authentic product endorsements rather than banner blindness.

3. **Platform revenue**: The platform takes a commission (configurable, e.g., 15%) on each deal, creating a revenue stream that scales with creator success.

4. **FTC compliance**: Currently there is no system to ensure sponsored content is properly disclosed. The platform could face regulatory risk if creators post paid content without disclosure. Automatic "#ad" / "Paid partnership" labels solve this.

5. **Messaging integration**: Deal negotiation happens naturally via the existing DM system, keeping communication centralized.

### Architecture After This Change

```
Advertiser                         Platform                          Creator
    │                                 │                                 │
    │── Browse creator profiles ─────>│                                 │
    │                                 │                                 │
    │── Propose sponsorship deal ────>│                                 │
    │   {creator, content_type,       │── Notification ────────────────>│
    │    brief, deliverables,         │   (email + in-app)              │
    │    compensation, deadline}      │                                 │
    │                                 │                                 │
    │                                 │<── Creator reviews deal ────────│
    │                                 │                                 │
    │                                 │    ┌─────────────────────┐      │
    │                                 │    │ Deal States:        │      │
    │                                 │    │                     │      │
    │                                 │    │ proposed            │      │
    │                                 │    │   ↓                 │      │
    │                                 │    │ negotiating         │      │
    │                                 │    │   ↓                 │      │
    │                                 │    │ accepted            │      │
    │                                 │    │   ↓                 │      │
    │                                 │    │ content_submitted   │      │
    │                                 │    │   ↓                 │      │
    │                                 │    │ completed           │      │
    │                                 │    │                     │      │
    │                                 │    │ (or cancelled at    │      │
    │                                 │    │  any stage)         │      │
    │                                 │    └─────────────────────┘      │
    │                                 │                                 │
    │                                 │<── Creator accepts deal ────────│
    │<── Deal accepted notification ──│                                 │
    │                                 │                                 │
    │                                 │<── Creator submits content ─────│
    │                                 │    (links post/video to deal)   │
    │                                 │                                 │
    │── Advertiser approves content ─>│                                 │
    │                                 │── Payment: advertiser wallet ──>│
    │                                 │   → platform commission (15%)   │
    │                                 │   → creator wallet (85%)        │
    │                                 │                                 │
    │                                 │── Mark content as sponsored ───>│
    │                                 │   "#ad" label auto-applied      │
    │                                 │                                 │
    │── View deal analytics ─────────>│                                 │
    │   impressions, engagement,      │                                 │
    │   CPM bonus calculation         │                                 │
```

### Data Flow — Deal Lifecycle

```
Browser                          Backend                              DynamoDB
  │                                 │                                    │
  │── POST /ui/ads/sponsorships ───>│                                    │
  │   { creator_sub, content_type,  │                                    │
  │     brief, deliverables,        │                                    │
  │     compensation_cents: 50000,  │                                    │
  │     cpm_bonus_cents: 100,       │                                    │
  │     deadline: "2026-07-01" }    │                                    │
  │                                 │── validate advertiser account ────>│
  │                                 │── check advertiser wallet ────────>│
  │                                 │── hold compensation amount ───────>│
  │                                 │   (escrow: wallet → hold)          │
  │                                 │                                    │
  │                                 │── create deal record ─────────────>│
  │                                 │   sponsorship_deals table          │
  │                                 │   status = "proposed"              │
  │                                 │                                    │
  │                                 │── send notification to creator ───>│
  │                                 │   alerts table                     │
  │                                 │                                    │
  │<── 201 { deal_id, status }     │                                    │
  │                                 │                                    │
  │  ... creator reviews deal ...   │                                    │
  │                                 │                                    │
  │── POST /ui/ads/sponsorships/   │                                    │
  │   {deal_id}/accept ───────────>│                                    │
  │                                 │── update status → "accepted" ─────>│
  │                                 │── create DM conversation ─────────>│
  │                                 │   (advertiser <-> creator)         │
  │                                 │── notify advertiser ──────────────>│
  │<── 200 { deal_id, status,      │                                    │
  │     dm_conversation_id }        │                                    │
  │                                 │                                    │
  │  ... creator creates content .. │                                    │
  │                                 │                                    │
  │── POST /ui/ads/sponsorships/   │                                    │
  │   {deal_id}/submit-content ───>│                                    │
  │   { post_id: "abc" }           │                                    │
  │                                 │── link post to deal ──────────────>│
  │                                 │── update status → "content_submitted"│
  │                                 │── add "#ad" label to post ────────>│
  │                                 │── notify advertiser ──────────────>│
  │<── 200 { deal_id, status }     │                                    │
  │                                 │                                    │
  │  ... advertiser reviews ...     │                                    │
  │                                 │                                    │
  │── POST /ui/ads/sponsorships/   │                                    │
  │   {deal_id}/complete ─────────>│                                    │
  │                                 │── release escrow ─────────────────>│
  │                                 │   platform_commission = 15%        │
  │                                 │   creator_payment = 85%            │
  │                                 │── credit creator wallet ──────────>│
  │                                 │── update status → "completed" ────>│
  │<── 200 { deal_id, status,      │                                    │
  │     payment_details }           │                                    │
```

---

## 2. Current State Analysis

### 2.1 Messaging System (`app/routers/messaging.py`)

The existing DM system supports one-on-one and group conversations. `getOrCreateDm()` creates or retrieves an existing DM between two users. The deal discussion can use this existing infrastructure — when a creator accepts a deal, the system creates a DM between advertiser and creator with a system message explaining the deal.

### 2.2 Newsfeed Posts (`app/routers/newsfeed.py`)

Posts have `user_id`, `text`, `image_url`, and metadata fields. The `_post_to_dict()` function serializes posts. Currently there is no `sponsored_by`, `deal_id`, or `ftc_disclosure` field on posts. Adding these fields enables automatic sponsorship labeling.

### 2.3 Billing & Wallet (`app/services/billing_shared.py`)

The billing system supports:
- `new_ledger_entry()` for debit/credit entries
- Wallet balance tracking (`USER#{sub}/WALLET`)
- The wallet can be used for escrow holds by creating a "hold" ledger entry with state "held" and releasing it as "settled" when the deal completes.

### 2.4 Notifications (`app/services/alerts.py`)

The alert system supports in-app notifications. `create_alert()` sends notifications to users. Sponsorship events (new proposal, acceptance, content submission, completion) trigger alerts.

### 2.5 Gaps

1. No sponsorship deal data model or storage
2. No deal workflow (propose/negotiate/accept/submit/complete)
3. No escrow mechanism for deal payments
4. No FTC compliance labeling on sponsored content
5. No commission split logic for deal payments
6. No sponsorship inbox UI for creators
7. No sponsorship manager UI for advertisers

---

## 3. Technical Design

### 3.1 DynamoDB Table: `sponsorship_deals`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="sponsorship_deals",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),  # By advertiser
        GsiDef("GSI2", "GSI2PK", "GSI2SK"),  # By creator
        GsiDef("GSI3", "GSI3PK", "GSI3SK"),  # By status
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
)
```

**Schema:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `DEAL#{deal_id}` | `"DEAL#deal_abc123"` |
| `sk` | S | `META` | `"META"` |
| `deal_id` | S | Unique deal identifier | `"deal_abc123"` |
| `advertiser_account_id` | S | Advertiser's account | `"adv_xyz789"` |
| `advertiser_sub` | S | Advertiser's user ID | `"advertiser@brand.com"` |
| `creator_sub` | S | Creator's user ID | `"creator@platform.com"` |
| `content_type` | S | `"post"`, `"video"`, `"broadcast"` | `"post"` |
| `brief` | S | Text description of what the advertiser wants | `"Feature our new product..."` |
| `deliverables` | L | List of deliverable descriptions | `["1 feed post", "1 story"]` |
| `compensation_cents` | N | Flat fee payment | `5000000` ($50,000) |
| `cpm_bonus_cents` | N | Optional CPM bonus per 1000 views | `100` ($1 CPM bonus) |
| `platform_commission_bps` | N | Platform commission in basis points | `1500` (15%) |
| `status` | S | Deal state | `"proposed"` |
| `deadline` | S | Content submission deadline | `"2026-07-01"` |
| `content_id` | S | Linked post/video/broadcast ID (set on submit) | `"post_abc"` |
| `dm_conversation_id` | S | DM conversation for deal discussion | `"conv_xyz"` |
| `escrow_hold_id` | S | Billing ledger entry ID for escrow hold | `"hold_abc"` |
| `created_at` | N | Unix timestamp | `1748534400` |
| `updated_at` | N | Unix timestamp | `1748534400` |
| `completed_at` | N | Unix timestamp (set on completion) | `0` |
| `cancelled_at` | N | Unix timestamp (set on cancellation) | `0` |
| `cancel_reason` | S | Reason for cancellation | `""` |
| `GSI1PK` | S | `ADV#{advertiser_account_id}` | `"ADV#adv_xyz789"` |
| `GSI1SK` | N | `created_at` | `1748534400` |
| `GSI2PK` | S | `CREATOR#{creator_sub}` | `"CREATOR#creator@platform.com"` |
| `GSI2SK` | N | `created_at` | `1748534400` |
| `GSI3PK` | S | `STATUS#{status}` | `"STATUS#proposed"` |
| `GSI3SK` | N | `created_at` | `1748534400` |

**Access Patterns:**

| Pattern | Table/Index | Key Condition |
|---------|-------------|---------------|
| Get deal by ID | Table PK/SK | `pk = DEAL#{deal_id}, sk = META` |
| List deals by advertiser | GSI1 | `GSI1PK = ADV#{advertiser_id}` |
| List deals by creator | GSI2 | `GSI2PK = CREATOR#{creator_sub}` |
| List deals by status | GSI3 | `GSI3PK = STATUS#{status}` |
| Deal history events | Table PK | `pk = DEAL#{deal_id}, sk begins_with EVENT#` |

**Settings** in `app/core/settings.py`:
```python
sponsorship_deals_table_name: str = os.environ.get("DDB_SPONSORSHIP_DEALS", "sponsorship_deals")
```

**Table handle** in `app/core/tables.py`:
```python
sponsorship_deals=ddb.Table(S.sponsorship_deals_table_name),
```

### 3.2 Deal History Events

Each state transition is recorded as a history event in the same table:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `DEAL#{deal_id}` |
| `sk` | S | `EVENT#{ts}#{event_id}` |
| `event_type` | S | `"proposed"`, `"negotiation_message"`, `"accepted"`, `"content_submitted"`, `"completed"`, `"cancelled"` |
| `actor_sub` | S | Who triggered the event |
| `details` | M | Event-specific metadata |
| `created_at` | N | Unix timestamp |

### 3.3 Sponsorship Service: `app/services/sponsorship_deals.py`

```python
"""Sponsored content & creator partnerships (ADS-013).

Manages the full lifecycle of brand sponsorship deals:
propose → negotiate → accept → submit content → complete.
"""

DEAL_STATUSES = [
    "proposed",           # Advertiser created the deal
    "negotiating",        # Creator counter-offered or messaged
    "accepted",           # Creator accepted terms
    "content_submitted",  # Creator linked content to deal
    "completed",          # Advertiser approved, payment released
    "cancelled",          # Either party cancelled
]

PLATFORM_COMMISSION_BPS = 1500  # 15% default

def create_deal(
    *, advertiser_sub: str, advertiser_account_id: str,
    creator_sub: str, content_type: str, brief: str,
    deliverables: List[str], compensation_cents: int,
    cpm_bonus_cents: int = 0, deadline: str,
) -> Dict[str, Any]:
    """Propose a new sponsorship deal.

    Steps:
    1. Validate advertiser has sufficient wallet balance
    2. Create escrow hold (debit advertiser wallet, hold state)
    3. Create deal record in DDB
    4. Create history event (proposed)
    5. Send notification to creator
    6. Return deal details
    """
    ...

def accept_deal(*, deal_id: str, creator_sub: str) -> Dict[str, Any]:
    """Creator accepts a proposed deal.

    Steps:
    1. Validate deal exists and status = proposed/negotiating
    2. Validate creator_sub matches deal.creator_sub
    3. Update status → accepted
    4. Create DM conversation between advertiser and creator
    5. Send system message in DM with deal summary
    6. Notify advertiser
    7. Return deal with dm_conversation_id
    """
    ...

def reject_deal(*, deal_id: str, creator_sub: str, reason: str = "") -> Dict[str, Any]:
    """Creator rejects a proposed deal.

    Releases escrow hold back to advertiser wallet.
    """
    ...

def submit_content(
    *, deal_id: str, creator_sub: str, content_id: str
) -> Dict[str, Any]:
    """Creator submits content linked to the deal.

    Steps:
    1. Validate deal status = accepted
    2. Validate content ownership
    3. Add FTC disclosure label to content metadata
    4. Update deal with content_id, status → content_submitted
    5. Notify advertiser for review
    """
    ...

def complete_deal(*, deal_id: str, advertiser_sub: str) -> Dict[str, Any]:
    """Advertiser approves content and completes the deal.

    Steps:
    1. Validate deal status = content_submitted
    2. Calculate platform commission
    3. Release escrow: commission → platform, remainder → creator wallet
    4. Update status → completed
    5. Notify creator of payment
    """
    ...

def cancel_deal(*, deal_id: str, actor_sub: str, reason: str) -> Dict[str, Any]:
    """Either party cancels the deal.

    If status < content_submitted: release full escrow to advertiser.
    If status = content_submitted: partial release (50% to each as dispute settlement).
    """
    ...

def _add_ftc_label(content_type: str, content_id: str, brand_name: str) -> None:
    """Add FTC compliance label to content.

    Updates content metadata with:
    - sponsored_by: brand name
    - deal_id: sponsorship deal ID
    - ftc_disclosure: "Paid partnership with {brand_name}"
    """
    ...
```

### 3.4 Escrow Pattern

```python
def _create_escrow_hold(
    *, advertiser_sub: str, amount_cents: int, deal_id: str
) -> str:
    """Create escrow hold by debiting advertiser wallet.

    Uses billing ledger with state="held" (not "settled").
    Returns hold_id for later release.
    """
    sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(advertiser_sub),
        entry_type="sponsorship_escrow_hold",
        amount_cents=amount_cents,
        state="held",
        reason=f"Sponsorship deal escrow: {deal_id}",
        meta={"deal_id": deal_id},
    )
    T.billing.put_item(Item=item)
    return item.get("ledger_id", sk)

def _release_escrow(
    *, hold_id: str, advertiser_sub: str, creator_sub: str,
    total_cents: int, commission_bps: int
) -> Dict[str, Any]:
    """Release escrow: split between platform commission and creator payment.

    commission_cents = total_cents * commission_bps / 10000
    creator_cents = total_cents - commission_cents
    """
    commission_cents = total_cents * commission_bps // 10000
    creator_cents = total_cents - commission_cents

    # Settle the hold
    # Credit creator wallet
    # Credit platform revenue
    return {
        "total_cents": total_cents,
        "commission_cents": commission_cents,
        "creator_cents": creator_cents,
    }
```

### 3.5 FTC Compliance

When content is submitted to a deal, the system automatically adds disclosure:

**Post metadata fields:**
```python
sponsored_by: Optional[str]       # Brand name
deal_id: Optional[str]            # Sponsorship deal ID
ftc_disclosure: Optional[str]     # "Paid partnership with {brand}"
```

**Frontend rendering** (PostCard.tsx):
```tsx
{post.ftc_disclosure && (
  <div className="flex items-center gap-1 text-xs text-muted-foreground">
    <BadgeCheck className="h-3 w-3" />
    <span>{post.ftc_disclosure}</span>
  </div>
)}
```

### 3.6 Router: `app/routers/sponsorship_deals.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/ads/sponsorships` | `require_ui_session` | Propose a deal |
| GET | `/ui/ads/sponsorships` | `require_ui_session` | List deals (filtered by role) |
| GET | `/ui/ads/sponsorships/{deal_id}` | `require_ui_session` | Get deal details |
| POST | `/ui/ads/sponsorships/{deal_id}/accept` | `require_ui_session` | Creator accepts |
| POST | `/ui/ads/sponsorships/{deal_id}/reject` | `require_ui_session` | Creator rejects |
| POST | `/ui/ads/sponsorships/{deal_id}/submit-content` | `require_ui_session` | Creator submits content |
| POST | `/ui/ads/sponsorships/{deal_id}/complete` | `require_ui_session` | Advertiser completes |
| POST | `/ui/ads/sponsorships/{deal_id}/cancel` | `require_ui_session` | Either party cancels |
| GET | `/ui/ads/sponsorships/{deal_id}/history` | `require_ui_session` | Deal event history |

### 3.7 Pydantic Models

**File**: `app/models.py`

```python
class SponsorshipDealCreate(BaseModel):
    creator_sub: str
    content_type: str = Field(pattern=r"^(post|video|broadcast)$")
    brief: str = Field(min_length=10, max_length=5000)
    deliverables: List[str] = Field(min_length=1, max_length=10)
    compensation_cents: int = Field(ge=1000)  # min $10
    cpm_bonus_cents: int = Field(default=0, ge=0)
    deadline: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")

class SponsorshipDealOut(BaseModel):
    deal_id: str
    advertiser_account_id: str
    advertiser_sub: str
    creator_sub: str
    content_type: str
    brief: str
    deliverables: List[str]
    compensation_cents: int
    cpm_bonus_cents: int
    platform_commission_bps: int
    status: str
    deadline: str
    content_id: Optional[str] = None
    dm_conversation_id: Optional[str] = None
    created_at: int
    updated_at: int
    completed_at: Optional[int] = None

class SponsorshipContentSubmit(BaseModel):
    content_id: str

class SponsorshipCancelRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
```

### 3.8 Frontend Components

#### SponsorshipInbox (`frontend/src/pages/ads/SponsorshipInbox.tsx`)

Creator-facing page showing incoming deal proposals, active deals, and completed deals. Tabs: "Pending", "Active", "Completed", "Cancelled".

Each deal card shows: brand name, brief summary, compensation amount, deadline, status badge, and action buttons (Accept/Reject for pending, Submit Content for accepted).

#### SponsorshipManager (`frontend/src/pages/ads/SponsorshipManager.tsx`)

Advertiser-facing page for managing outgoing deals. Shows deal pipeline with status columns. "New Deal" button opens creation form.

#### DealDetailPage (`frontend/src/pages/ads/DealDetailPage.tsx`)

Full detail view for a single deal. Shows: deal terms, deliverables checklist, timeline of events, linked content preview, payment status, DM conversation link.

#### Frontend API (`frontend/src/api/endpoints/sponsorships.ts`)

```typescript
export const createDeal = (data: SponsorshipDealCreate) =>
  client.post("/ui/ads/sponsorships", data);
export const listDeals = (params?: { status?: string }) =>
  client.get("/ui/ads/sponsorships", { params });
export const getDeal = (dealId: string) =>
  client.get(`/ui/ads/sponsorships/${dealId}`);
export const acceptDeal = (dealId: string) =>
  client.post(`/ui/ads/sponsorships/${dealId}/accept`);
export const rejectDeal = (dealId: string) =>
  client.post(`/ui/ads/sponsorships/${dealId}/reject`);
export const submitContent = (dealId: string, data: { content_id: string }) =>
  client.post(`/ui/ads/sponsorships/${dealId}/submit-content`, data);
export const completeDeal = (dealId: string) =>
  client.post(`/ui/ads/sponsorships/${dealId}/complete`);
export const cancelDeal = (dealId: string, data: { reason: string }) =>
  client.post(`/ui/ads/sponsorships/${dealId}/cancel`, data);
```

### 3.9 Frontend Routes

**File**: `frontend/src/App.tsx`

```tsx
<Route path="/ads/sponsorships" element={<SponsorshipInbox />} />
<Route path="/ads/sponsorships/manage" element={<SponsorshipManager />} />
<Route path="/ads/sponsorships/:dealId" element={<DealDetailPage />} />
```

---

## 4. Implementation Plan

### 4.1 Backend — Phase 1: Data Model & Service (Days 1-3)

1. **`scripts/local-ddb-init.py`**: Add `sponsorship_deals` table definition with 3 GSIs.
2. **`app/core/settings.py`**: Add `sponsorship_deals_table_name`.
3. **`app/core/tables.py`**: Add `sponsorship_deals` table handle.
4. **`app/models.py`**: Add Pydantic models for deal CRUD.
5. **`app/services/sponsorship_deals.py`**: New file. Full deal lifecycle logic: create, accept, reject, submit content, complete, cancel. Escrow hold/release. FTC label application.

### 4.2 Backend — Phase 2: Router & Integration (Days 4-5)

6. **`app/routers/sponsorship_deals.py`**: New router. Nine endpoints. Register in `app/main.py`.
7. **`app/main.py`**: Register router with prefix `/ui/ads/sponsorships`.
8. **Integration**: Wire up DM creation on deal acceptance, alert notifications on state changes.

### 4.3 Frontend — Phase 1: Core Components (Days 6-8)

9. **`frontend/src/api/types.ts`**: Add TypeScript types for deals.
10. **`frontend/src/api/endpoints/sponsorships.ts`**: New file. API wrappers.
11. **`frontend/src/pages/ads/SponsorshipInbox.tsx`**: New page. Creator-facing deal inbox.
12. **`frontend/src/pages/ads/SponsorshipManager.tsx`**: New page. Advertiser-facing deal manager.
13. **`frontend/src/pages/ads/DealDetailPage.tsx`**: New page. Deal detail view.

### 4.4 Frontend — Phase 2: Integration (Days 9-10)

14. **`frontend/src/App.tsx`**: Add routes for sponsorship pages.
15. **`frontend/src/pages/feed/PostCard.tsx`**: Add FTC disclosure label rendering.
16. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Sponsorships" link under Ads section.

### 4.5 E2E Tests (Days 10-12)

17. **`frontend/e2e/sponsorship-deals.spec.ts`**: New file. 18 tests across 5 sections.

---

## 5. Security Considerations

### 5.1 Authorization

- Only the advertiser can propose and complete deals.
- Only the targeted creator can accept, reject, or submit content.
- Either party can cancel (with different escrow release rules).
- Deal details visible only to the advertiser and creator involved.

### 5.2 Escrow Security

- Compensation held in escrow at proposal time (advertiser cannot withdraw).
- Escrow released only on completion (to creator) or cancellation (back to advertiser).
- Partial release on disputed cancellations (50/50 split).
- Atomic DDB operations prevent double-release.

### 5.3 FTC Compliance

- Sponsored content is automatically labeled — creators cannot remove the disclosure.
- The `ftc_disclosure` field is set server-side and cannot be modified via the post update API.
- Platform operators can audit all sponsored content via the `STATUS#completed` GSI.

---

## 6. Testing Strategy

### 6.1 Unit Tests (`tests/test_sponsorship_deals.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Create deal creates escrow hold | Advertiser wallet debited, hold entry created |
| 2 | Accept deal creates DM conversation | DM exists between advertiser and creator |
| 3 | Reject deal releases escrow | Advertiser wallet credited back |
| 4 | Submit content adds FTC label | Post metadata has ftc_disclosure |
| 5 | Complete deal splits payment correctly | Commission 15%, creator 85% |
| 6 | Cancel before content releases full escrow | Advertiser gets full refund |
| 7 | Cancel after content splits 50/50 | Both parties get 50% |
| 8 | Non-creator cannot accept deal | 403 response |

### 6.2 E2E Tests (`frontend/e2e/sponsorship-deals.spec.ts`)

**Test File**: `frontend/e2e/sponsorship-deals.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (advertiser), Bob (creator), Root (admin)
- Seed Alice's wallet with 10000000 cents ($100,000)
- Create a newsfeed post as Bob (for content submission)

**Section 396: Deal Proposal API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Advertiser proposes sponsorship deal` | POST /sponsorships → 201, deal_id present, status="proposed" |
| 2 | `Deal creates escrow hold on advertiser wallet` | GET wallet → balance decreased by compensation_cents |
| 3 | `Deal with insufficient balance returns 402` | Set compensation > balance → 402 |
| 4 | `Invalid content_type rejected` | content_type="invalid" → 422 |

**Section 397: Deal Acceptance & Rejection API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Creator accepts deal` | POST /sponsorships/{id}/accept → 200, status="accepted", dm_conversation_id present |
| 6 | `Non-creator cannot accept deal` | POST as Alice (advertiser) → 403 |
| 7 | `Creator rejects deal` | POST /sponsorships/{id}/reject → 200, status="cancelled", escrow released |
| 8 | `Cannot accept already-cancelled deal` | POST accept on rejected deal → 409 |

**Section 398: Content Submission API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Creator submits content to accepted deal` | POST /sponsorships/{id}/submit-content → 200, status="content_submitted" |
| 10 | `Submitted content has FTC disclosure label` | GET post → ftc_disclosure = "Paid partnership with ..." |
| 11 | `Cannot submit content to non-accepted deal` | POST submit on proposed deal → 409 |
| 12 | `Cannot submit content owned by another user` | POST with Alice's post_id → 403 |

**Section 399: Deal Completion & Payment API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Advertiser completes deal` | POST /sponsorships/{id}/complete → 200, status="completed" |
| 14 | `Creator wallet credited with 85% of compensation` | GET creator wallet → increased by compensation * 0.85 |
| 15 | `Platform commission recorded in billing ledger` | Query ledger → entry with type="sponsorship_commission" |

**Section 400: Deal Listing & History API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | `Creator lists own deals` | GET /sponsorships as Bob → array includes the created deal |
| 17 | `Advertiser lists own deals` | GET /sponsorships as Alice → array includes the created deal |
| 18 | `Deal history shows all state transitions` | GET /sponsorships/{id}/history → events array with proposed, accepted, content_submitted, completed |

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/sponsorship_deals.py` | Deal lifecycle logic, escrow, FTC labeling |
| `app/routers/sponsorship_deals.py` | Deal API endpoints |
| `frontend/src/api/endpoints/sponsorships.ts` | API wrappers |
| `frontend/src/pages/ads/SponsorshipInbox.tsx` | Creator deal inbox |
| `frontend/src/pages/ads/SponsorshipManager.tsx` | Advertiser deal manager |
| `frontend/src/pages/ads/DealDetailPage.tsx` | Deal detail view |
| `frontend/e2e/sponsorship-deals.spec.ts` | E2E tests (18 tests, sections 396-400) |
| `tests/test_sponsorship_deals.py` | Unit tests |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add sponsorship Pydantic models |
| `app/main.py` | Register `sponsorship_deals_router` |
| `app/core/settings.py` | Add `sponsorship_deals_table_name` |
| `app/core/tables.py` | Add `sponsorship_deals` table handle |
| `scripts/local-ddb-init.py` | Add `sponsorship_deals` table with 3 GSIs |
| `frontend/src/api/types.ts` | Add TypeScript types for deals |
| `frontend/src/App.tsx` | Add sponsorship routes |
| `frontend/src/pages/feed/PostCard.tsx` | Add FTC disclosure label rendering |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Sponsorships" nav link |

## 9. Acceptance Criteria

1. Advertisers can propose sponsorship deals with compensation, brief, deliverables, and deadline
2. Compensation is held in escrow from advertiser wallet at proposal time
3. Creators can accept or reject deals; acceptance creates a DM for discussion
4. Creators can submit content linked to accepted deals
5. Submitted content is automatically labeled with FTC disclosure
6. Completing a deal releases escrow with 15% platform commission and 85% to creator
7. Deal cancellation releases escrow appropriately (full return before content, 50/50 after)
8. Deal history records all state transitions
9. All 18 E2E tests pass in `frontend/e2e/sponsorship-deals.spec.ts`

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/routers/newsfeed.py` | — | Existing newsfeed router — sponsored content appears in feed |
| `app/services/billing_shared.py` | — | Existing billing ledger — escrow and payout patterns |
| `app/services/sponsorship_deals.py` | — | Does not exist yet — new implementation required |
| `sponsorship_deals` DDB table | — | Does not exist yet — new implementation required |
