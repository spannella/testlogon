# FIN-015: Fraud Detection Dashboard

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 10-12 days  
**Dependencies**: Billing ledger (`billing_shared.py`), payment providers (`billing.py`, `billing_ccbill.py`), rate limiting (`rate_limit.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

The platform processes financial transactions (tips, unlocks, deposits, subscriptions, catalog purchases) but has no fraud detection system. There are no velocity checks, risk scoring, anomaly detection, or manual review queues. A malicious user can:

- Execute hundreds of small transactions in minutes (velocity abuse)
- Create a new account and immediately make large purchases (new account + high value)
- Use stolen payment methods across multiple accounts
- Perform chargebacks on legitimate transactions after consuming content
- Exploit locked-message unlocks with fraudulent payment methods

Without fraud detection, the platform absorbs losses from chargebacks, refund abuse, and payment fraud. These losses come directly from creator earnings and platform revenue.

### Why This Is Needed

1. **Velocity detection**: Legitimate users do not send 50 tips in 2 minutes. Abnormal transaction velocity is the strongest fraud signal — catching it automatically prevents most automated fraud.

2. **Risk scoring**: Assigning a 0-100 risk score per user based on behavioral signals (transaction patterns, account age, device fingerprint, geo anomalies) enables automated flagging without blocking legitimate users.

3. **Manual review queue**: Not all fraud is clear-cut. A review queue lets admins inspect flagged transactions, examine context, and make approve/block decisions before funds are released.

4. **User freeze**: When fraud is suspected, temporarily freezing a user's financial operations prevents further damage while the case is investigated.

5. **Chargeback management**: Tracking chargebacks per user reveals serial abusers. Users exceeding a chargeback threshold should be auto-flagged for review.

6. **Audit trail**: Every fraud case (flag, review, decision) must be recorded for compliance, dispute resolution, and pattern analysis.

### User Stories

- As a **platform admin**, I want transactions with abnormal velocity to be automatically flagged so I can review them before funds settle.
- As a **platform admin**, I want each user to have a risk score so I can prioritize high-risk accounts for review.
- As a **platform admin**, I want a review queue showing flagged transactions so I can approve or block them.
- As a **platform admin**, I want to freeze a user's financial operations pending investigation so I can prevent further fraud.
- As a **platform admin**, I want to see chargeback history per user so I can identify serial abusers.

### Architecture After This Change

```
Fraud Detection System
│
├── Real-Time Rule Engine
│   ├── Velocity check (N tx in M minutes)
│   ├── Large amount check (single tx > threshold)
│   ├── New account + high value check
│   ├── Multiple failed payments check
│   ├── Geographic anomaly check (IP country mismatch)
│   └── Chargeback rate check
│
├── Risk Score Engine
│   ├── Per-user score (0-100)
│   ├── Score components: velocity, amount, account_age, chargeback_rate, geo
│   ├── Auto-flag at threshold (e.g., score >= 70)
│   └── Score history over time
│
├── Admin Review Queue (/admin/fraud)
│   ├── Flagged transactions list
│   ├── User risk profile (score, history, tx patterns)
│   ├── Actions: approve, block, investigate, freeze user
│   └── Case notes + resolution history
│
├── User Financial Freeze
│   ├── Block all outgoing payments
│   ├── Block payouts
│   ├── Freeze notification to user
│   └── Unfreeze by admin
│
└── Fraud Case Management
    ├── Case lifecycle: open → investigating → resolved
    ├── Case assignment to admin
    ├── Case notes + evidence attachments
    └── Resolution: false_positive, confirmed_fraud, inconclusive
```

### Data Flow — Fraud Check on Transaction

```
User Transaction                  Fraud Engine                         Admin
      │                              │                                   │
      │── POST /tip ────────────────>│                                   │
      │                              │── run_fraud_rules(tx) ───>        │
      │                              │   velocity_check: PASS            │
      │                              │   amount_check: PASS              │
      │                              │   new_account_check: FAIL (3d)    │
      │                              │   score = 72 (>= 70 threshold)    │
      │                              │                                   │
      │                              │── flag_transaction(tx) ──────────>│
      │                              │── create_fraud_case() ──────────>│
      │<── 200 { ok: true,           │                                   │
      │    flagged: true }           │                  ┌────────────────│
      │                              │                  │ Admin reviews  │
      │                              │                  │ and approves   │
      │                              │                  └────────────────│
      │                              │<── resolve_case("false_positive")─│
      │                              │── clear_flag(tx) ─────────────────│
```

---

## 2. Current State Analysis

### 2.1 Billing Ledger (`app/services/billing_shared.py`)

All financial transactions are recorded as ledger entries with `entry_type`, `amount_cents`, `user_id`, `created_at`. The ledger provides the raw data source for velocity analysis.

### 2.2 Rate Limiting (`app/services/rate_limit.py`)

The rate limiter tracks request counts per IP/user but does not track financial transaction velocity. Its `check_rate_limit` function uses sliding window counters.

### 2.3 Payment Providers

Payment failures (declined cards, insufficient funds) are returned as HTTP error responses but not tracked for fraud pattern analysis.

### 2.4 Gaps

1. No transaction velocity tracking or limits
2. No risk score computation per user
3. No automated fraud flagging rules
4. No admin review queue for flagged transactions
5. No user financial freeze mechanism
6. No chargeback tracking or thresholds
7. No fraud case management lifecycle
8. No fraud detection admin dashboard

---

## 3. Technical Design

### 3.1 Fraud Data Table: `fraud_detection`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="fraud_detection",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),
        GsiDef("GSI2", "GSI2PK", "GSI2SK"),
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
)
```

**Risk score row** (one per user):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `RISK#USER#{user_id}` |
| `sk` | S | `SCORE` |
| `score` | N | Current risk score (0-100) |
| `components` | M | `{velocity: 15, amount: 10, account_age: 30, chargeback: 0, geo: 5}` |
| `flagged` | BOOL | Whether user is currently flagged |
| `frozen` | BOOL | Whether user's finances are frozen |
| `frozen_at` | N | When frozen (null if not frozen) |
| `frozen_by` | S | Admin who froze |
| `tx_count_24h` | N | Transaction count in last 24h |
| `tx_total_24h` | N | Transaction total in last 24h |
| `chargeback_count` | N | Lifetime chargeback count |
| `last_scored_at` | N | When score was last recomputed |

**Flagged transaction rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `FLAG#{flag_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `FLAGS#PENDING` or `FLAGS#RESOLVED` |
| `GSI1SK` | N | `created_at` (Unix timestamp) |
| `GSI2PK` | S | `FLAGS#USER#{user_id}` |
| `GSI2SK` | N | `created_at` |
| `flag_id` | S | Unique flag ID |
| `user_id` | S | User who triggered the flag |
| `tx_id` | S | Ledger entry ID that triggered the flag |
| `rule_triggered` | S | Which rule fired (e.g., `velocity`, `amount`, `new_account`) |
| `risk_score` | N | User's risk score at time of flag |
| `amount_cents` | N | Transaction amount |
| `status` | S | `"pending"`, `"approved"`, `"blocked"`, `"investigating"` |
| `reviewed_by` | S | Admin who reviewed |
| `reviewed_at` | N | When reviewed |
| `resolution` | S | `"false_positive"`, `"confirmed_fraud"`, `"inconclusive"` |
| `notes` | S | Admin notes |
| `created_at` | N | When flagged |

**Fraud case rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `CASE#{case_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `CASES#OPEN` or `CASES#CLOSED` |
| `GSI1SK` | N | `created_at` |
| `case_id` | S | Unique case ID |
| `user_id` | S | User under investigation |
| `status` | S | `"open"`, `"investigating"`, `"resolved"` |
| `assigned_to` | S | Admin handling the case |
| `flags` | L | List of flag_ids linked to this case |
| `resolution` | S | Resolution when closed |
| `notes` | S | Admin case notes |
| `created_at` | N | When case was opened |
| `resolved_at` | N | When case was resolved |

### 3.2 Fraud Rules Engine: `app/services/fraud_rules.py`

```python
"""Fraud detection rule engine (FIN-015).

Evaluates transactions against configurable rules.
Returns a risk assessment with triggered rules and score delta.
"""

# Default thresholds (overridable via DDB config)
VELOCITY_MAX_TX_PER_HOUR = 20
VELOCITY_MAX_AMOUNT_PER_HOUR = 50000  # $500
LARGE_TX_THRESHOLD = 25000  # $250
NEW_ACCOUNT_AGE_DAYS = 7
NEW_ACCOUNT_HIGH_VALUE = 10000  # $100
CHARGEBACK_THRESHOLD = 3
FLAG_SCORE_THRESHOLD = 70

def evaluate_transaction(
    *, user_id: str, amount_cents: int, entry_type: str,
    ip_address: str = None, account_age_days: int = 0,
) -> Dict[str, Any]:
    """Run all fraud rules against a transaction.

    Returns {
        "triggered_rules": [...],
        "risk_score": int,
        "flagged": bool,
        "action": "allow" | "flag" | "block"
    }
    """
    ...

def velocity_check(user_id: str) -> Optional[str]:
    """Check if user exceeded transaction velocity limits."""
    ...

def large_amount_check(amount_cents: int) -> Optional[str]:
    """Check if single transaction exceeds large amount threshold."""
    ...

def new_account_check(
    account_age_days: int, amount_cents: int
) -> Optional[str]:
    """Check if new account is making high-value transaction."""
    ...

def chargeback_check(user_id: str) -> Optional[str]:
    """Check if user has excessive chargebacks."""
    ...

def compute_risk_score(user_id: str) -> Dict[str, Any]:
    """Recompute the full risk score for a user.

    Returns {score, components, flagged}.
    """
    ...

def get_fraud_config() -> Dict[str, Any]:
    """Get current fraud detection thresholds."""
    ...

def update_fraud_config(*, admin_sub: str, **thresholds) -> Dict[str, Any]:
    """Update fraud detection thresholds."""
    ...
```

### 3.3 Fraud Management Service: `app/services/fraud_management.py`

```python
"""Fraud case and flag management (FIN-015).

Handles the admin review queue, user freeze/unfreeze,
and fraud case lifecycle.
"""

def list_flagged_transactions(
    *, status: str = "pending", limit: int = 50, cursor: str = None,
) -> Dict[str, Any]:
    """List flagged transactions for admin review queue."""
    ...

def review_flag(
    *, flag_id: str, action: str, admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Admin reviews a flagged transaction: approve, block, or investigate."""
    ...

def freeze_user(
    *, user_id: str, admin_sub: str, reason: str
) -> Dict[str, Any]:
    """Freeze a user's financial operations."""
    ...

def unfreeze_user(
    *, user_id: str, admin_sub: str
) -> Dict[str, Any]:
    """Unfreeze a user's financial operations."""
    ...

def get_user_risk_profile(user_id: str) -> Dict[str, Any]:
    """Get full risk profile for a user (score, history, flags, cases)."""
    ...

def create_fraud_case(
    *, user_id: str, flag_ids: List[str], admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Open a new fraud investigation case."""
    ...

def resolve_fraud_case(
    *, case_id: str, resolution: str, admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Resolve a fraud case."""
    ...

def list_fraud_cases(
    *, status: str = "open", limit: int = 50
) -> List[Dict[str, Any]]:
    """List fraud cases filtered by status."""
    ...
```

### 3.4 Router: `app/routers/admin_fraud.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/fraud/queue` | `require_admin_session` | Flagged transaction queue |
| POST | `/v1/admin/fraud/flags/{flag_id}/review` | `require_admin_session` | Review flagged tx |
| GET | `/v1/admin/fraud/users/{user_id}/risk` | `require_admin_session` | User risk profile |
| POST | `/v1/admin/fraud/users/{user_id}/freeze` | `require_admin_session` | Freeze user |
| POST | `/v1/admin/fraud/users/{user_id}/unfreeze` | `require_admin_session` | Unfreeze user |
| POST | `/v1/admin/fraud/cases` | `require_admin_session` | Create fraud case |
| GET | `/v1/admin/fraud/cases` | `require_admin_session` | List fraud cases |
| GET | `/v1/admin/fraud/cases/{case_id}` | `require_admin_session` | Get case details |
| POST | `/v1/admin/fraud/cases/{case_id}/resolve` | `require_admin_session` | Resolve case |
| GET | `/v1/admin/fraud/config` | `require_admin_session` | Get fraud config |
| PATCH | `/v1/admin/fraud/config` | `require_root_session` | Update fraud config |
| GET | `/v1/admin/fraud/stats` | `require_admin_session` | Dashboard statistics |

### 3.5 Pydantic Models (`app/models.py`)

```python
class FraudFlagOut(BaseModel):
    flag_id: str
    user_id: str
    tx_id: str
    rule_triggered: str
    risk_score: int
    amount_cents: int
    status: str
    reviewed_by: Optional[str] = None
    resolution: Optional[str] = None
    notes: Optional[str] = None
    created_at: int

class FraudFlagReview(BaseModel):
    action: str = Field(pattern=r"^(approve|block|investigate)$")
    notes: str = Field(default="", max_length=1000)

class UserRiskProfile(BaseModel):
    user_id: str
    score: int
    components: Dict[str, int]
    flagged: bool
    frozen: bool
    tx_count_24h: int
    tx_total_24h: int
    chargeback_count: int
    last_scored_at: int

class FreezeUserRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)

class FraudCaseCreate(BaseModel):
    user_id: str
    flag_ids: List[str] = Field(min_length=1)
    notes: str = Field(default="", max_length=2000)

class FraudCaseOut(BaseModel):
    case_id: str
    user_id: str
    status: str
    assigned_to: Optional[str] = None
    flags: List[str]
    resolution: Optional[str] = None
    notes: Optional[str] = None
    created_at: int
    resolved_at: Optional[int] = None

class FraudCaseResolve(BaseModel):
    resolution: str = Field(pattern=r"^(false_positive|confirmed_fraud|inconclusive)$")
    notes: str = Field(default="", max_length=2000)

class FraudConfigUpdate(BaseModel):
    velocity_max_tx_per_hour: Optional[int] = Field(default=None, ge=1, le=1000)
    velocity_max_amount_per_hour: Optional[int] = Field(default=None, ge=1000)
    large_tx_threshold: Optional[int] = Field(default=None, ge=1000)
    new_account_age_days: Optional[int] = Field(default=None, ge=1, le=90)
    flag_score_threshold: Optional[int] = Field(default=None, ge=10, le=100)

class FraudStatsOut(BaseModel):
    pending_flags: int
    open_cases: int
    frozen_users: int
    flags_resolved_today: int
    avg_resolution_hours: float
```

### 3.6 Frontend: Fraud Detection Dashboard

**Route**: `/admin/fraud` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/fraud/FraudDashboard.tsx`

Tabbed layout:
- **Queue**: Flagged transactions table with risk score badge, approve/block/investigate actions
- **Cases**: Fraud case list with status, assignment, linked flags
- **Users**: User risk search — enter user ID, view risk profile, freeze/unfreeze
- **Config**: Fraud rule thresholds form
- **Stats**: KPI cards (pending flags, open cases, frozen users, avg resolution time)

### 3.7 Frontend API (`frontend/src/api/endpoints/adminFraud.ts`)

```typescript
export const getFraudQueue = (params?: { status?: string; limit?: number }) =>
  client.get("/v1/admin/fraud/queue", { params });

export const reviewFlag = (flagId: string, data: { action: string; notes?: string }) =>
  client.post(`/v1/admin/fraud/flags/${flagId}/review`, data);

export const getUserRisk = (userId: string) =>
  client.get(`/v1/admin/fraud/users/${userId}/risk`);

export const freezeUser = (userId: string, data: { reason: string }) =>
  client.post(`/v1/admin/fraud/users/${userId}/freeze`, data);

export const unfreezeUser = (userId: string) =>
  client.post(`/v1/admin/fraud/users/${userId}/unfreeze`);

export const createFraudCase = (data: { user_id: string; flag_ids: string[]; notes?: string }) =>
  client.post("/v1/admin/fraud/cases", data);

export const listFraudCases = (params?: { status?: string }) =>
  client.get("/v1/admin/fraud/cases", { params });

export const getFraudCase = (caseId: string) =>
  client.get(`/v1/admin/fraud/cases/${caseId}`);

export const resolveCase = (caseId: string, data: { resolution: string; notes?: string }) =>
  client.post(`/v1/admin/fraud/cases/${caseId}/resolve`, data);

export const getFraudConfig = () =>
  client.get("/v1/admin/fraud/config");

export const updateFraudConfig = (data: FraudConfigUpdate) =>
  client.patch("/v1/admin/fraud/config", data);

export const getFraudStats = () =>
  client.get("/v1/admin/fraud/stats");
```

---

## 4. Implementation Plan

### Phase 1: Backend — Fraud Rules (Days 1-3)

1. **`scripts/local-ddb-init.py`**: Add `fraud_detection` table with GSIs.
2. **`app/core/settings.py`**: Add `fraud_detection_table_name`.
3. **`app/core/tables.py`**: Add `fraud_detection` table handle.
4. **`app/services/fraud_rules.py`**: New file. Rule engine with velocity, amount, new account, chargeback checks. Risk score computation.

### Phase 2: Backend — Management (Days 3-5)

5. **`app/services/fraud_management.py`**: New file. Flag queue, case lifecycle, freeze/unfreeze, risk profiles.
6. **Integrate with billing**: Add `evaluate_transaction` call to billing endpoints (tip, unlock, deposit) to check before processing.

### Phase 3: Backend — Router (Days 5-7)

7. **`app/models.py`**: Add fraud detection Pydantic models.
8. **`app/routers/admin_fraud.py`**: New router with 12 endpoints.
9. **`app/main.py`**: Register router with prefix `/v1/admin/fraud`.

### Phase 4: Frontend (Days 7-10)

10. **`frontend/src/api/types.ts`**: Add TypeScript types.
11. **`frontend/src/api/endpoints/adminFraud.ts`**: New file.
12. **`frontend/src/pages/admin/fraud/FraudDashboard.tsx`**: New page.
13. **`frontend/src/App.tsx`**: Add `/admin/fraud` route.
14. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Fraud Detection" admin nav link.

### Phase 5: E2E Tests (Days 10-12)

15. **`frontend/e2e/admin-fraud.spec.ts`**: 16 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-fraud.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root (admin), Alice (user), Charlie (admin)
- Seed a risk score row for Alice (score=75, flagged=true)
- Seed 3 flagged transactions for Alice (2 pending, 1 resolved)
- Seed 1 open fraud case for Alice

**Section 531: Fraud Queue API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves fraud flag queue` | GET `/v1/admin/fraud/queue` as Root -> 200; array with 2 pending flags, each has `flag_id`, `user_id`, `risk_score`, `amount_cents`, `status` |
| 2 | `Queue filters by status` | GET `?status=resolved` -> 200; returns 1 resolved flag |
| 3 | `Admin approves a flagged transaction` | POST `/v1/admin/fraud/flags/{id}/review` with `{action: "approve"}` -> 200; re-GET queue shows flag no longer pending |
| 4 | `Non-admin cannot access fraud queue` | GET as Alice -> 403 |

**Section 532: User Risk & Freeze API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Admin views user risk profile` | GET `/v1/admin/fraud/users/{alice}/risk` as Root -> 200; `score >= 0`, `components` is object, `flagged` is boolean |
| 6 | `Admin freezes a user` | POST `/v1/admin/fraud/users/{alice}/freeze` with `{reason: "investigation"}` -> 200; re-GET shows `frozen: true` |
| 7 | `Admin unfreezes a user` | POST `/v1/admin/fraud/users/{alice}/unfreeze` -> 200; re-GET shows `frozen: false` |
| 8 | `Freeze requires reason` | POST freeze with `{reason: ""}` -> 422 |

**Section 533: Fraud Case Management API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Admin lists open fraud cases` | GET `/v1/admin/fraud/cases?status=open` as Root -> 200; array with seeded case |
| 10 | `Admin creates a fraud case` | POST `/v1/admin/fraud/cases` with `{user_id, flag_ids: [...]}` -> 201; `case_id` present |
| 11 | `Admin resolves a fraud case` | POST `/v1/admin/fraud/cases/{id}/resolve` with `{resolution: "false_positive"}` -> 200; `status: "resolved"` |
| 12 | `Case detail includes linked flags` | GET `/v1/admin/fraud/cases/{id}` -> 200; `flags` is non-empty array |

**Section 534: Fraud Config & Stats API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Admin views fraud stats` | GET `/v1/admin/fraud/stats` as Root -> 200; has `pending_flags`, `open_cases`, `frozen_users` |
| 14 | `Admin views fraud config` | GET `/v1/admin/fraud/config` -> 200; has `velocity_max_tx_per_hour`, `flag_score_threshold` |
| 15 | `Root updates fraud thresholds` | PATCH `/v1/admin/fraud/config` with `{flag_score_threshold: 80}` as Root -> 200; re-GET confirms value |
| 16 | `Non-root cannot update config` | PATCH as Charlie -> 403 |

---

## 6. Security Considerations

### 6.1 Role-Based Access
- All fraud endpoints require ADMIN role
- Configuration changes require ROOT role
- Fraud data is highly sensitive and must not be exposed to regular users

### 6.2 Freeze Safety
- Freeze blocks new outgoing payments, tips, unlocks, and payouts
- Freeze does NOT block incoming payments (other users can still tip/pay frozen user)
- Freeze notification sent to user with generic message (does not reveal fraud investigation)
- Unfreeze requires admin action (no auto-unfreeze)

### 6.3 Rule Engine Integration
- Fraud checks run synchronously before transaction processing
- If `action=block`, transaction is rejected with generic "payment declined" error
- If `action=flag`, transaction proceeds but is added to review queue
- Rule evaluation must complete within 100ms to avoid degrading user experience

### 6.4 Audit Trail
- All flag reviews, freeze/unfreeze actions, and case resolutions logged with admin identity
- Fraud case notes and evidence are immutable after case resolution
- Risk score history preserved for post-incident analysis

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/fraud_rules.py` | Fraud detection rule engine |
| `app/services/fraud_management.py` | Flag queue, case management, freeze |
| `app/routers/admin_fraud.py` | Admin fraud API (12 endpoints) |
| `frontend/src/api/endpoints/adminFraud.ts` | API wrappers |
| `frontend/src/pages/admin/fraud/FraudDashboard.tsx` | Dashboard page |
| `frontend/e2e/admin-fraud.spec.ts` | E2E tests (16 tests, sections 531-534) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add fraud detection Pydantic models |
| `app/main.py` | Register `admin_fraud_router` |
| `app/core/settings.py` | Add `fraud_detection_table_name` |
| `app/core/tables.py` | Add `fraud_detection` table handle |
| `scripts/local-ddb-init.py` | Add `fraud_detection` table with GSIs |
| `app/routers/billing.py` | Add `evaluate_transaction` call before tip/unlock/deposit |
| `frontend/src/api/types.ts` | Add fraud detection TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/fraud` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Fraud Detection" admin nav link |

## 9. Acceptance Criteria

1. Fraud rules engine evaluates transactions for velocity, amount, new account, and chargeback anomalies
2. Risk score (0-100) computed per user with breakdown by component
3. Transactions exceeding score threshold auto-flagged and added to review queue
4. Admin queue lists pending flags with approve/block/investigate actions
5. User freeze/unfreeze blocks/restores financial operations
6. Fraud cases can be created, assigned, and resolved with audit trail
7. Stats endpoint returns pending flags, open cases, frozen users count
8. Fraud config thresholds updatable by ROOT only
9. All 16 E2E tests pass in `frontend/e2e/admin-fraud.spec.ts`
