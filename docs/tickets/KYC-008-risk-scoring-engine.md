# KYC-008: KYC Risk Scoring Engine

**Ticket**: KYC-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 14-18 days
**Dependencies**: KYC-001 (Admin Dashboard), KYC-002 (Doc Verification), KYC-004 (Residency), KYC-005 (Source of Funds), KYC-006 (Screening)

---

## 1. Overview & Motivation

### Problem Statement

The existing KYC system uses a simple `intake_profile` field (standard/enhanced/high_risk)
set at case creation time to determine review requirements. This is a static, coarse-grained
risk classification that does not account for evidence gathered during the KYC process.
There is no automated risk scoring based on document quality, screening results, source-of-funds
answers, verification call outcomes, or profile completeness. Admins must manually assess
risk for each case, which is inconsistent and does not scale.

Modern AML compliance frameworks require **risk-based approach** (RBA) with quantifiable risk
scores that determine the level of due diligence applied to each customer. Without automated
scoring, the platform cannot:
- Auto-approve low-risk cases to reduce reviewer workload
- Auto-escalate critical-risk cases to senior compliance staff
- Track risk trends across the customer base
- Demonstrate to regulators that risk assessment is systematic and evidence-based

### Goals

1. Compute an automated risk score (0-100) based on multiple weighted factors.
2. Define risk tiers: low (0-30), medium (31-60), high (61-80), critical (81-100).
3. Auto-approve cases scoring in the low tier with all verification checks passed.
4. Auto-escalate critical-risk cases to senior admin / ROOT for review.
5. Track risk score history for each user (scores change over time).
6. Support continuous risk monitoring: re-score on profile changes and new transactions.
7. Provide admin dashboard with risk distribution charts and score trends.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Platform | Auto-approve low-risk KYC cases with all checks passed | Reviewer workload is reduced |
| 2 | Platform | Auto-escalate critical-risk cases to senior reviewers | High-risk cases get appropriate attention |
| 3 | KYC reviewer | See the computed risk score and contributing factors | My review is informed by data |
| 4 | Compliance lead | See risk distribution across all users | I can report to regulators |
| 5 | Compliance lead | Track how a user's risk score changes over time | I can detect risk escalation |
| 6 | Platform | Re-score users when their profile or transaction patterns change | Risk assessment stays current |
| 7 | Developer | Adjust factor weights via configuration | Scoring can be tuned without code changes |

---

## 2. Current State Analysis

### 2.1 Existing Risk Classification

The KYC case `intake_profile` field accepts `standard`, `enhanced`, or `high_risk`. This
is set by the user at case creation and determines which documents and signatures are
required. There is no computed numeric score.

The admin queue (`STORE.list_admin_queue()` — see `app/services/kyc_cases.py:646`)
supports filtering by `risk_tier`, but currently this just maps from `intake_profile` (see `:664` for `_risk`):
```python
def _risk(case: dict) -> str:
    ip = str(case.get("intake_profile") or "standard").lower()
    if ip == "high_risk": return "high"
    if ip == "enhanced": return "medium"
    return "low"
```

### 2.2 Available Risk Signals

After KYC-002 through KYC-006 are implemented, the following signals are available:

| Source | Signal | Location |
|--------|--------|----------|
| KYC-002 | Document extraction confidence | `kyc_document_extractions` table |
| KYC-002 | Name/DOB match status | `match_results` in extraction |
| KYC-003 | Verification call result | `case.verification_call.result` |
| KYC-004 | Residency document recency | `residency_meta.recency_valid` |
| KYC-004 | Address match status | `residency_meta.address_match.status` |
| KYC-005 | Source-of-funds risk flags | `source_of_funds.risk_flags` |
| KYC-006 | Screening results | `kyc_screening_results` table |
| Profile | Profile completeness | Profile fields populated count |
| Profile | Account age | `created_at` on user record |
| Config | Country risk | Country-based risk lookup |

### 2.3 KYC Case Status Transitions

The scoring engine can influence status transitions:
- `submitted` -> `approved` (auto-approve for low risk)
- `submitted` -> `under_review` (normal flow)
- `under_review` -> auto-escalate flag (critical risk)

### 2.4 Metrics Endpoint

`get_admin_kyc_metrics()` (see `app/routers/kyc_cases.py:947`) returns funnel counts and latency.
Risk distribution metrics will be added to this response.

---

## 3. Technical Design

### 3.1 New DDB Table: `kyc_risk_scores`

**Table name**: `kyc_risk_scores` (env: `KYC_RISK_SCORES_TABLE_NAME`)
**Partition key**: `user_sub` (String)
**Sort key**: `timestamp` (Number)

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | User being scored |
| `timestamp` | N (SK) | Unix timestamp of scoring |
| `score_id` | S | `"rs_" + uuid4().hex[:12]` |
| `case_id` | S | KYC case this score is associated with (or "continuous" for monitoring) |
| `total_score` | N | Computed risk score (0-100) |
| `risk_tier` | S | `low`, `medium`, `high`, `critical` |
| `factors` | M | Map of factor_name -> { score, weight, raw_value, description } |
| `trigger` | S | `submission`, `profile_change`, `continuous`, `manual`, `rescoring` |
| `previous_score` | N | Score before this computation (null for first score) |
| `previous_tier` | S | Tier before this computation |
| `auto_action_taken` | S | `auto_approved`, `auto_escalated`, `none` |
| `model_version` | S | Scoring model version (e.g., "v1.0") |
| `created_at` | N | Unix timestamp |

Each factor in `factors` map:
```json
{
    "country_risk": {
        "score": 15,
        "weight": 0.15,
        "weighted_score": 2.25,
        "raw_value": "NG",
        "description": "High-risk country: Nigeria"
    },
    "screening_result": {
        "score": 0,
        "weight": 0.25,
        "weighted_score": 0,
        "raw_value": "all_clear",
        "description": "All screening checks clear"
    }
}
```

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByCaseId` | `case_id` | `timestamp` (N) | All scores for a specific case |
| `ByTier` | `risk_tier` | `timestamp` (N) | Query users by risk tier |

**DDB init** (`scripts/local-ddb-init.py`):
```python
TableDef(
    _resolve_table_name(S.kyc_risk_scores_table_name, "kyc_risk_scores"),
    partition_key="user_sub",
    sort_key="timestamp",
    gsis=[
        {"index_name": "case-timestamp-index", "partition_key": "case_id", "sort_key": "timestamp"},
        {"index_name": "tier-timestamp-index", "partition_key": "risk_tier", "sort_key": "timestamp"},
    ],
    attr_types={"timestamp": "N"},
)
```

### 3.2 New Service: `app/services/kyc_risk_scoring.py`

```python
RISK_TIERS = {
    "low": (0, 30),
    "medium": (31, 60),
    "high": (61, 80),
    "critical": (81, 100),
}

DEFAULT_FACTOR_WEIGHTS = {
    "country_risk": 0.15,
    "document_quality": 0.15,
    "screening_result": 0.25,
    "source_of_funds": 0.15,
    "verification_call": 0.10,
    "profile_completeness": 0.05,
    "account_age": 0.05,
    "address_match": 0.10,
}

class KycRiskScoringService:
    def __init__(self, table=None, weights=None):
        self._table = table or T.kyc_risk_scores
        self._weights = weights or DEFAULT_FACTOR_WEIGHTS

    def compute_score(self, *, case_id: str, user_sub: str,
                      trigger: str = "submission") -> dict:
        """Compute risk score based on all available signals.
        Stores result in DDB and returns the score record."""

    def get_latest_score(self, *, user_sub: str) -> dict | None:
        """Get the most recent risk score for a user."""

    def get_score_history(self, *, user_sub: str, limit: int = 25) -> list[dict]:
        """Get risk score history for a user, newest first."""

    def get_scores_for_case(self, *, case_id: str) -> list[dict]:
        """Get all scores associated with a specific case."""

    def get_tier_distribution(self) -> dict:
        """Get count of users in each risk tier for dashboard."""

    def _compute_country_risk(self, *, user_sub: str) -> dict:
        """Score based on user's country/nationality against risk list."""

    def _compute_document_quality(self, *, case_id: str) -> dict:
        """Score based on extraction confidence from KYC-002."""

    def _compute_screening_result(self, *, case_id: str) -> dict:
        """Score based on sanctions/PEP screening from KYC-006."""

    def _compute_source_of_funds(self, *, case_id: str) -> dict:
        """Score based on SOF risk flags from KYC-005."""

    def _compute_verification_call(self, *, case_id: str) -> dict:
        """Score based on verification call result from KYC-003."""

    def _compute_profile_completeness(self, *, user_sub: str) -> dict:
        """Score based on how many profile fields are populated."""

    def _compute_account_age(self, *, user_sub: str) -> dict:
        """Score: newer accounts are higher risk."""

    def _compute_address_match(self, *, case_id: str) -> dict:
        """Score based on residency address match from KYC-004."""

    def _determine_tier(self, total_score: int) -> str:
        """Map numeric score to risk tier."""

    def _apply_auto_action(self, *, case_id: str, score: int, tier: str,
                           all_checks_passed: bool) -> str:
        """Apply auto-approve or auto-escalate based on score and tier."""
```

### 3.3 Factor Scoring Rules

| Factor | Score Range | Logic |
|--------|-----------|-------|
| `country_risk` | 0-100 | 0 for low-risk countries (US, UK, CA, AU, EU), 50 for medium-risk, 100 for high-risk (sanctioned/FATF gray list) |
| `document_quality` | 0-100 | 0 if all extractions `high` confidence; 30 if `medium`; 60 if `low`; 100 if `failed` |
| `screening_result` | 0-100 | 0 if all `clear`; 50 if `potential_match` (reviewed as false_positive); 80 if unreviewed `potential_match`; 100 if `confirmed_match` |
| `source_of_funds` | 0-100 | Sum of risk flag weights from KYC-005 (capped at 100) |
| `verification_call` | 0-100 | 0 if `passed`; 40 if not conducted; 60 if `inconclusive`; 100 if `failed` |
| `profile_completeness` | 0-100 | 0 if all fields populated; +20 per missing critical field (name, DOB, address, email) |
| `account_age` | 0-100 | 0 if > 180 days; 30 if 30-180 days; 60 if 7-30 days; 100 if < 7 days |
| `address_match` | 0-100 | 0 if `match`; 40 if `partial`; 80 if `mismatch`; 100 if no residency doc |

**Weighted total**: `sum(factor_score * factor_weight)` (weights sum to 1.0)

### 3.4 Auto-Action Rules

```python
def _apply_auto_action(self, *, case_id: str, score: int, tier: str,
                       all_checks_passed: bool) -> str:
    if tier == "low" and all_checks_passed and score <= 20:
        # Auto-approve: all screenings clear, all docs verified, low risk
        STORE.update_case_status(
            case_id=case_id,
            expected_version=case["version"],
            new_status="approved",
            actor_sub="system_auto_approve",
            reason_codes=["auto_approved_low_risk"],
            decision_note=f"Auto-approved: risk score {score} (tier: low), all checks passed",
        )
        return "auto_approved"

    if tier == "critical":
        # Auto-escalate: flag for senior review
        # Set assigned_admin to ROOT or senior compliance admin
        review = dict(case.get("review") or {})
        review["escalated"] = True
        review["escalation_reason"] = f"Critical risk score: {score}"
        review["escalated_at"] = now_ts()
        STORE.update_case_links(
            case_id=case_id,
            owner_sub=case["user_sub"],
            expected_version=case["version"],
            review_ticket_id=review.get("ticket_id"),
        )
        audit_event("kyc_auto_escalated", "system", None,
                     case_id=case_id, score=score, tier=tier)
        return "auto_escalated"

    return "none"
```

### 3.5 Continuous Monitoring

A background task (or admin-triggered endpoint) re-scores all approved users periodically:

```python
@router.post("/admin/risk/rescore-approved")
def admin_rescore_approved_users(
    request: Request,
    batch_size: int = Query(default=50, ge=1, le=200),
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Re-score all approved users. Processes in batches.
    If any user's tier changes to high or critical, flags for review."""
```

### 3.6 New Router Endpoints

**File: `app/routers/kyc_cases.py`** -- add endpoints:

```python
@router.get("/{case_id}/risk-score")
def get_case_risk_score(case_id: str, ...):
    """Get latest risk score for a case. Available to case owner (summary) and admins (full)."""

@router.get("/admin/risk/user/{user_sub}/history")
def get_user_risk_history(user_sub: str, ...):
    """Get full risk score history for a user. Admin only."""

@router.post("/admin/risk/cases/{case_id}/rescore")
def admin_rescore_case(case_id: str, ...):
    """Manually trigger re-scoring for a specific case. Admin only."""

@router.get("/admin/risk/distribution")
def get_risk_distribution(...):
    """Get count of users in each risk tier. For dashboard charts."""

@router.post("/admin/risk/rescore-approved")
def admin_rescore_approved_users(...):
    """Batch re-score all approved users for continuous monitoring."""

@router.get("/admin/risk/tier/{tier}")
def list_users_by_risk_tier(tier: str, ...):
    """List users in a specific risk tier with their latest scores."""
```

### 3.7 Settings

**File: `app/core/settings.py`** -- add:

```python
kyc_risk_scores_table_name: str = os.environ.get("KYC_RISK_SCORES_TABLE_NAME", "kyc_risk_scores")
kyc_risk_auto_approve_enabled: bool = os.environ.get("KYC_RISK_AUTO_APPROVE_ENABLED", "true").lower() == "true"
kyc_risk_auto_approve_max_score: int = int(os.environ.get("KYC_RISK_AUTO_APPROVE_MAX_SCORE", "20"))
kyc_risk_auto_escalate_min_score: int = int(os.environ.get("KYC_RISK_AUTO_ESCALATE_MIN_SCORE", "81"))
kyc_risk_scoring_model_version: str = os.environ.get("KYC_RISK_SCORING_MODEL_VERSION", "v1.0")
```

### 3.8 Submission Integration

In `submit_kyc_case()` (line 830 of `app/routers/kyc_cases.py`), after screening (KYC-006)
completes, trigger risk scoring:

```python
# After screening results are available
scoring_service = KycRiskScoringService()
score_result = scoring_service.compute_score(
    case_id=case_id,
    user_sub=case["user_sub"],
    trigger="submission",
)

# Auto-action based on score
auto_action = score_result.get("auto_action_taken", "none")
if auto_action == "auto_approved":
    audit_event("kyc_auto_approved", case["user_sub"], request,
                case_id=case_id, score=score_result["total_score"])
elif auto_action == "auto_escalated":
    audit_event("kyc_auto_escalated", case["user_sub"], request,
                case_id=case_id, score=score_result["total_score"])
```

### 3.9 Frontend Changes

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add "Risk Assessment" panel:
- Overall risk score gauge (0-100 with color gradient)
- Risk tier badge (low=green, medium=yellow, high=orange, critical=red)
- Factor breakdown table: factor name, raw value, weighted score, description
- "Re-score" button to trigger manual rescoring
- Score history chart (line chart showing score over time)

**File: `frontend/src/pages/admin/KycMetricsDashboard.tsx`** -- extend:

Add risk distribution section:
- Pie chart: percentage of users in each risk tier
- Bar chart: risk score distribution histogram (buckets of 10)
- Auto-approve rate card: percentage of cases auto-approved
- Auto-escalate rate card: percentage of cases auto-escalated

---

## 4. E2E Test Plan

**File**: `frontend/e2e/kyc-risk-scoring.spec.ts`
**Total**: ~18 tests across 4 sections (178-181)

### Section 178: Risk Score Computation API (6 tests)

```typescript
test("178.1 Submitting case computes risk score", async () => {
  // Create case with standard profile, submit
  // GET /v1/kyc/cases/{id}/risk-score
  // Verify total_score is numeric (0-100), risk_tier present
});

test("178.2 Low-risk case produces low tier", async () => {
  // Normal user, all clear screenings, matching documents
  // Verify risk_tier = "low", total_score <= 30
});

test("178.3 Factors include all 8 scoring dimensions", async () => {
  // GET risk score
  // Verify factors map has keys: country_risk, document_quality,
  //   screening_result, source_of_funds, verification_call,
  //   profile_completeness, account_age, address_match
});

test("178.4 Each factor has score, weight, and description", async () => {
  // Verify each factor in factors map has required fields
  // Verify all weights sum to approximately 1.0
});

test("178.5 Screening match increases risk score", async () => {
  // User with OFAC potential match (from KYC-006 mock)
  // Verify screening_result factor score > 0
  // Verify total_score higher than 178.2
});

test("178.6 Score stored in DDB with correct trigger", async () => {
  // Verify score record has trigger="submission"
  // Verify model_version present
});
```

### Section 179: Auto-Actions (4 tests)

```typescript
test("179.1 Low-risk case with all checks passed is auto-approved", async () => {
  // Normal user, all clear, score <= 20
  // Verify case status = "approved"
  // Verify auto_action_taken = "auto_approved"
});

test("179.2 Auto-approved case has audit trail", async () => {
  // GET case detail timeline
  // Verify contains auto_approved event with score
});

test("179.3 Critical-risk case is auto-escalated", async () => {
  // User with multiple risk flags + screening match
  // Verify auto_action_taken = "auto_escalated"
  // Verify review.escalated = true
});

test("179.4 Medium-risk case goes to normal review (no auto-action)", async () => {
  // User with some risk flags but not extreme
  // Verify case status = "submitted" (not auto-approved or escalated)
  // Verify auto_action_taken = "none"
});
```

### Section 180: Score History & Re-scoring (4 tests)

```typescript
test("180.1 Risk score history shows all scores for a user", async () => {
  // GET /v1/kyc/cases/admin/risk/user/{sub}/history
  // Verify list of scores ordered by timestamp descending
});

test("180.2 Manual re-score creates new history entry", async () => {
  // POST /v1/kyc/cases/admin/risk/cases/{id}/rescore
  // Verify new score entry with trigger="manual"
  // Verify previous_score and previous_tier set
});

test("180.3 Re-score with changed factors produces different score", async () => {
  // Change a signal (e.g., add screening match review as false_positive)
  // Re-score
  // Verify score decreased (screening factor now lower)
});

test("180.4 Non-admin gets 403 on risk history", async () => {
  // Alice tries to view risk history
  // Expect 403
});
```

### Section 181: Risk Distribution Dashboard API (4 tests)

```typescript
test("181.1 Risk distribution returns tier counts", async () => {
  // GET /v1/kyc/cases/admin/risk/distribution
  // Verify response has low, medium, high, critical counts
  // Verify counts are non-negative integers
});

test("181.2 List users by risk tier returns matching users", async () => {
  // GET /v1/kyc/cases/admin/risk/tier/low
  // Verify returned users have risk_tier=low
});

test("181.3 Batch re-score approved users creates new scores", async () => {
  // POST /v1/kyc/cases/admin/risk/rescore-approved?batch_size=10
  // Verify response includes count of users re-scored
});

test("181.4 Non-admin gets 403 on distribution", async () => {
  // Alice tries to view distribution
  // Expect 403
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_risk_scoring.py` | **New** | Risk scoring engine with 8 factors, tiers, auto-actions |
| `app/routers/kyc_cases.py` | Modify | Add 6 risk scoring endpoints; integrate with submission |
| `app/contracts/kyc_cases_contract.py` | Modify | Add risk score response models |
| `app/core/settings.py` | Modify | Add risk scoring table and config settings |
| `app/core/tables.py` | Modify | Add `kyc_risk_scores` table handle |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_risk_scores` table with 2 GSIs |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add Risk Assessment panel with gauge and factors |
| `frontend/src/pages/admin/KycMetricsDashboard.tsx` | Modify | Add risk distribution charts |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add risk scoring API functions |
| `frontend/e2e/kyc-risk-scoring.spec.ts` | **New** | 18 E2E tests across sections 178-181 |

---

## 6. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Frontend                                         │
│                                                                            │
│  KycCaseDetailPage.tsx (admin)              KycMetricsDashboard.tsx        │
│  ┌──────────────────────────────┐          ┌──────────────────────────┐   │
│  │ RiskAssessmentPanel           │          │ RiskDistributionSection   │   │
│  │  ├─ ScoreGauge (0-100)       │          │  ├─ TierPieChart          │   │
│  │  │   (color gradient:        │          │  ├─ ScoreHistogram        │   │
│  │  │    green→yellow→orange→red)│          │  ├─ AutoApproveRateCard  │   │
│  │  ├─ TierBadge (low/med/...)  │          │  └─ AutoEscalateRateCard │   │
│  │  ├─ FactorBreakdownTable     │          └──────────────────────────┘   │
│  │  │   └─ FactorRow[]          │                                         │
│  │  │       ├─ FactorName       │                                         │
│  │  │       ├─ RawValue         │                                         │
│  │  │       ├─ WeightedScore    │                                         │
│  │  │       └─ Description      │                                         │
│  │  ├─ "Re-score" Button        │                                         │
│  │  └─ ScoreHistoryChart        │                                         │
│  │      (line chart over time)  │                                         │
│  └──────────────────────────────┘                                          │
└──────────────────┬────────────────────────────┬────────────────────────────┘
                   │                            │
                   ▼                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                                      │
│                                                                            │
│  submit_kyc_case() integration:                                           │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ 1. KYC-006 screening completes                                    │     │
│  │ 2. → KycRiskScoringService.compute_score(trigger="submission")   │     │
│  │ 3. → Gather 8 factor signals from DDB tables                     │     │
│  │ 4. → Compute weighted total: sum(factor_score * weight)           │     │
│  │ 5. → Determine tier: low(0-30) | medium(31-60) | high(61-80) |  │     │
│  │ │                     critical(81-100)                            │     │
│  │ 6. → Apply auto-action:                                          │     │
│  │ │    score<=20 + all_clear → auto_approve                        │     │
│  │ │    tier=critical → auto_escalate                                │     │
│  │ │    otherwise → none                                             │     │
│  │ 7. → Store score record in kyc_risk_scores DDB                   │     │
│  │ 8. → audit_event(kyc_auto_approved | kyc_auto_escalated)         │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  Factor computation (8 factors, weights sum to 1.0):                      │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ country_risk     (0.15) ← user profile nationality               │     │
│  │ document_quality (0.15) ← KYC-002 extraction confidence          │     │
│  │ screening_result (0.25) ← KYC-006 screening outcomes             │     │
│  │ source_of_funds  (0.15) ← KYC-005 risk flags                    │     │
│  │ verification_call(0.10) ← KYC-003 call result                   │     │
│  │ profile_complete (0.05) ← profile fields populated               │     │
│  │ account_age      (0.05) ← days since account creation            │     │
│  │ address_match    (0.10) ← KYC-004 residency match                │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  Router endpoints:                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ GET  /{case_id}/risk-score                                        │     │
│  │ GET  /admin/risk/user/{user_sub}/history                          │     │
│  │ POST /admin/risk/cases/{case_id}/rescore                         │     │
│  │ GET  /admin/risk/distribution                                     │     │
│  │ POST /admin/risk/rescore-approved                                 │     │
│  │ GET  /admin/risk/tier/{tier}                                      │     │
│  └──────────────────────────────────────────────────────────────────┘     │
└──────────────────┬─────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  DynamoDB                                                                  │
│  ┌─────────────────────────────────────────────┐                          │
│  │ kyc_risk_scores                              │                          │
│  │   PK = user_sub                              │                          │
│  │   SK = timestamp (N)                         │                          │
│  │                                              │                          │
│  │   GSI ByCaseId:  PK=case_id, SK=timestamp    │                          │
│  │   GSI ByTier:    PK=risk_tier, SK=timestamp  │                          │
│  │                                              │                          │
│  │   Attributes:                                │                          │
│  │     score_id, total_score, risk_tier,         │                          │
│  │     factors (M), trigger, previous_score,     │                          │
│  │     previous_tier, auto_action_taken,         │                          │
│  │     model_version                             │                          │
│  └─────────────────────────────────────────────┘                          │
│                                                                            │
│  Signal source tables:                                                    │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐     │
│  │ kyc_cases    │ │ kyc_document │ │ kyc_screening│ │ users        │     │
│  │ (all fields) │ │ _extractions │ │ _results     │ │ (profile)    │     │
│  └─────────────┘ └──────────────┘ └──────────────┘ └──────────────┘     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. DynamoDB Access Patterns

| # | Access Pattern | Table / Index | Key Condition | Notes |
|---|---------------|---------------|---------------|-------|
| 1 | Store risk score | `kyc_risk_scores` | PK=`{user_sub}`, SK=`{timestamp}` | PutItem with all factor data |
| 2 | Get latest score for user | `kyc_risk_scores` | PK=`{user_sub}`, SK desc, Limit=1 | ScanIndexForward=False |
| 3 | Get score history for user | `kyc_risk_scores` | PK=`{user_sub}`, SK desc | Paginated, newest first |
| 4 | Get scores for case | GSI `ByCaseId` | PK=`{case_id}`, SK desc | All scoring events for a case |
| 5 | Get users by tier | GSI `ByTier` | PK=`{tier}`, SK desc | For tier distribution and listing |
| 6 | Tier distribution | GSI `ByTier` x 4 | PK=`low`/`medium`/`high`/`critical`, Select=COUNT | 4 count queries |
| 7 | Read document extraction confidence | `kyc_document_extractions` | PK=`{case_id}` | For document_quality factor |
| 8 | Read screening results | `kyc_screening_results` | PK=`{case_id}` | For screening_result factor |
| 9 | Read case SOF flags | `kyc_cases` | PK=`KYC#{case_id}`, SK=`META` | For source_of_funds factor |
| 10 | Read user profile | `users` | PK=`USER#{user_sub}`, SK=`PROFILE` | For country_risk + profile_completeness |

---

## 8. API Request/Response Examples

### 8.1 Get Case Risk Score

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/risk-score" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "score_id": "rs_a1b2c3d4e5f6",
  "case_id": "kyc_a1b2c3d4",
  "user_sub": "e2e_alice@test.local",
  "total_score": 18,
  "risk_tier": "low",
  "factors": {
    "country_risk": {
      "score": 0,
      "weight": 0.15,
      "weighted_score": 0.0,
      "raw_value": "US",
      "description": "Low-risk country: United States"
    },
    "document_quality": {
      "score": 0,
      "weight": 0.15,
      "weighted_score": 0.0,
      "raw_value": "high",
      "description": "All extractions high confidence"
    },
    "screening_result": {
      "score": 0,
      "weight": 0.25,
      "weighted_score": 0.0,
      "raw_value": "all_clear",
      "description": "All screening checks clear"
    },
    "source_of_funds": {
      "score": 0,
      "weight": 0.15,
      "weighted_score": 0.0,
      "raw_value": "no_flags",
      "description": "No SOF risk flags"
    },
    "verification_call": {
      "score": 40,
      "weight": 0.10,
      "weighted_score": 4.0,
      "raw_value": "not_conducted",
      "description": "Verification call not conducted"
    },
    "profile_completeness": {
      "score": 0,
      "weight": 0.05,
      "weighted_score": 0.0,
      "raw_value": "complete",
      "description": "All profile fields populated"
    },
    "account_age": {
      "score": 60,
      "weight": 0.05,
      "weighted_score": 3.0,
      "raw_value": "14_days",
      "description": "Account 7-30 days old"
    },
    "address_match": {
      "score": 0,
      "weight": 0.10,
      "weighted_score": 0.0,
      "raw_value": "match",
      "description": "Address fully matched"
    }
  },
  "trigger": "submission",
  "auto_action_taken": "auto_approved",
  "model_version": "v1.0",
  "created_at": 1716681600
}
```

### 8.2 Get Risk Score History

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/risk/user/e2e_alice@test.local/history?limit=10" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "items": [
    {
      "score_id": "rs_latest123456",
      "total_score": 22,
      "risk_tier": "low",
      "trigger": "manual",
      "previous_score": 18,
      "previous_tier": "low",
      "auto_action_taken": "none",
      "model_version": "v1.0",
      "created_at": 1716768000
    },
    {
      "score_id": "rs_a1b2c3d4e5f6",
      "total_score": 18,
      "risk_tier": "low",
      "trigger": "submission",
      "previous_score": null,
      "previous_tier": null,
      "auto_action_taken": "auto_approved",
      "model_version": "v1.0",
      "created_at": 1716681600
    }
  ],
  "cursor": null
}
```

### 8.3 Get Risk Distribution

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/risk/distribution" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "distribution": {
    "low": 42,
    "medium": 15,
    "high": 5,
    "critical": 1
  },
  "total_scored": 63,
  "auto_approve_rate": 0.67,
  "auto_escalate_rate": 0.02
}
```

### 8.4 Admin Re-score a Case

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/risk/cases/kyc_a1b2c3d4/rescore" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r"
```

**Response (200):**
```json
{
  "ok": true,
  "score_id": "rs_rescore789012",
  "total_score": 22,
  "risk_tier": "low",
  "previous_score": 18,
  "previous_tier": "low",
  "trigger": "manual",
  "auto_action_taken": "none"
}
```

---

## 9. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Get score for non-existent case | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| Get score before any scoring | 200 | — | Returns null/empty (no score yet) | Submit case first |
| Non-owner views full score details | 403 | `kyc_access_forbidden` | "Access denied." | Owner sees summary only |
| Non-admin accesses admin endpoints | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| Re-score case without submitted status | 400 | `kyc_invalid_status` | "Case must be submitted for scoring." | Check case status |
| Invalid tier in tier list endpoint | 422 | `validation_error` | "Tier must be one of: low, medium, high, critical." | Use valid tier |
| Batch re-score exceeds limit | 422 | `validation_error` | "batch_size must be between 1 and 200." | Use valid batch_size |
| Factor weight config sums != 1.0 | 500 | `kyc_scoring_config_error` | "Risk scoring configuration error." | Fix weights config |
| Auto-approve disabled but score qualifies | 200 | — | Score computed but `auto_action_taken=none` | Enable auto-approve flag |

---

## 10. Pydantic Models

### 10.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class RescoreRequest(BaseModel):
    """Request to re-score a single KYC case."""
    trigger: Literal["manual", "continuous", "profile_change"] = Field(
        default="manual",
        description="What triggered the re-score.",
    )


class BatchRescoreRequest(BaseModel):
    """Request to batch re-score multiple cases."""
    batch_size: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Number of cases to re-score in this batch.",
    )
    status_filter: Literal["submitted", "under_review", "needs_more_info", "approved"] | None = Field(
        default=None,
        description="Only re-score cases in this status.",
    )
    tier_filter: Literal["low", "medium", "high", "critical"] | None = Field(
        default=None,
        description="Only re-score cases currently in this risk tier.",
    )


class UpdateFactorWeightsRequest(BaseModel):
    """Request to update risk factor weights (admin only)."""
    country_risk: float = Field(ge=0, le=1, default=0.15)
    document_quality: float = Field(ge=0, le=1, default=0.15)
    screening_result: float = Field(ge=0, le=1, default=0.25)
    source_of_funds: float = Field(ge=0, le=1, default=0.10)
    occupation_risk: float = Field(ge=0, le=1, default=0.10)
    transaction_velocity: float = Field(ge=0, le=1, default=0.10)
    age_of_account: float = Field(ge=0, le=1, default=0.05)
    behavioral_signals: float = Field(ge=0, le=1, default=0.10)

    @model_validator(mode="after")
    def weights_sum_to_one(self):
        total = (
            self.country_risk + self.document_quality + self.screening_result
            + self.source_of_funds + self.occupation_risk + self.transaction_velocity
            + self.age_of_account + self.behavioral_signals
        )
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Factor weights must sum to 1.0; got {total:.4f}")
        return self
```

### 10.2 Response Models

```python
from pydantic import BaseModel, Field
from typing import Any, Literal


class FactorScoreOut(BaseModel):
    """Score for a single risk factor."""
    factor_name: str = Field(description="Factor identifier (e.g., 'country_risk')")
    raw_value: str = Field(description="Raw input value (e.g., 'US', 'high')")
    weight: float = Field(ge=0, le=1, description="Factor weight in final score")
    factor_score: int = Field(ge=0, le=100, description="Unweighted factor score")
    weighted_score: float = Field(ge=0, le=100, description="factor_score * weight")
    description: str = Field(description="Human-readable explanation")


class AutoActionOut(BaseModel):
    """Auto-action taken by the scoring engine."""
    action: Literal["auto_approved", "auto_escalated", "none"]
    reason: str | None = None
    timestamp: int | None = None


class RiskScoreOut(BaseModel):
    """Full risk score for a KYC case."""
    case_id: str
    user_sub: str
    total_score: int = Field(ge=0, le=100, description="Composite risk score (0=lowest risk, 100=highest)")
    tier: Literal["low", "medium", "high", "critical"]
    factors: list[FactorScoreOut]
    auto_action: AutoActionOut | None = None
    scored_at: int = Field(description="Unix timestamp of when the score was computed")
    trigger: str = Field(description="What triggered this score computation")
    version: int = Field(ge=1, description="Score computation version (for schema evolution)")


class RiskScoreSummaryOut(BaseModel):
    """Simplified risk score summary for user-facing views."""
    tier: Literal["low", "medium", "high", "critical"]
    total_score: int = Field(ge=0, le=100)
    scored_at: int


class ScoreHistoryEntryOut(BaseModel):
    """A single entry in the score history."""
    total_score: int = Field(ge=0, le=100)
    tier: Literal["low", "medium", "high", "critical"]
    trigger: str
    auto_action: Literal["auto_approved", "auto_escalated", "none"]
    scored_at: int
    delta: int | None = Field(default=None, description="Change from previous score")


class ScoreHistoryOut(BaseModel):
    """Score history for a case."""
    case_id: str
    entries: list[ScoreHistoryEntryOut]
    total_entries: int


class RiskDistributionOut(BaseModel):
    """Risk tier distribution across all cases (admin metrics)."""
    low_count: int = Field(ge=0)
    medium_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    total: int = Field(ge=0)
    auto_approve_rate: float = Field(ge=0, le=100, description="Percentage auto-approved in period")
    auto_escalate_rate: float = Field(ge=0, le=100, description="Percentage auto-escalated in period")


class BatchRescoreResultOut(BaseModel):
    """Result of a batch re-score operation."""
    rescored_count: int = Field(ge=0)
    errors: int = Field(ge=0)
    tier_changes: int = Field(ge=0, description="Cases that changed tier during re-score")
    duration_ms: int = Field(ge=0)


class TierListOut(BaseModel):
    """List of cases in a specific risk tier."""
    tier: Literal["low", "medium", "high", "critical"]
    cases: list[dict[str, Any]] = Field(description="Case summaries in this tier")
    total: int = Field(ge=0)
    cursor: str | None = None
```

---

## 11. Frontend Component Tree

```
KycCaseDetailPage (admin, extended)
└── RiskAssessmentPanel
    ├── SectionHeader ("Risk Assessment")
    ├── ScoreGauge
    │   ├── CircularGauge (0-100, color: green<30, yellow<60, orange<80, red>=80)
    │   ├── ScoreNumber (large, centered)
    │   └── TierBadge (below gauge)
    │       ├── variant="low" → green "Low Risk"
    │       ├── variant="medium" → yellow "Medium Risk"
    │       ├── variant="high" → orange "High Risk"
    │       └── variant="critical" → red "Critical Risk"
    ├── AutoActionBadge (if applicable)
    │   ├── "Auto-Approved" (green check icon)
    │   └── "Auto-Escalated" (red alert icon)
    ├── FactorBreakdownTable
    │   ├── TableHeader: Factor | Raw Value | Weight | Score | Weighted | Description
    │   └── FactorRow[] (8 rows)
    │       ├── FactorName (country_risk, document_quality, ...)
    │       ├── RawValue (US, high, all_clear, ...)
    │       ├── Weight (0.15, 0.15, 0.25, ...)
    │       ├── FactorScore (0-100)
    │       ├── WeightedScore (factor_score * weight)
    │       └── Description (human-readable explanation)
    ├── Button "Re-score" → POST /rescore → refetch
    ├── ScoreHistorySection
    │   ├── ScoreHistoryChart (Recharts line chart)
    │   │   ├── X-axis: timestamp
    │   │   ├── Y-axis: total_score (0-100)
    │   │   ├── Tier bands (colored horizontal zones)
    │   │   └── Data points with trigger labels
    │   └── HistoryTable (collapsible)
    │       └── HistoryRow[]
    │           ├── Timestamp
    │           ├── Score (with delta from previous)
    │           ├── Tier
    │           ├── Trigger
    │           └── AutoAction

KycMetricsDashboard (admin, extended)
└── RiskDistributionSection
    ├── SectionHeader ("Risk Distribution")
    ├── TierPieChart (Recharts PieChart)
    │   ├── Slice: low (green) with count
    │   ├── Slice: medium (yellow) with count
    │   ├── Slice: high (orange) with count
    │   └── Slice: critical (red) with count
    ├── ScoreHistogram (Recharts BarChart)
    │   ├── X-axis: score buckets (0-10, 11-20, ..., 91-100)
    │   └── Y-axis: count of users
    ├── AutoApproveRateCard
    │   ├── Rate percentage (large number)
    │   ├── Count (auto-approved / total)
    │   └── Trend arrow (up/down vs previous period)
    └── AutoEscalateRateCard
        ├── Rate percentage
        ├── Count
        └── Trend arrow
```

---

## 12. Observability & Monitoring

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_risk_score_computed` | Counter | `trigger`, `tier` | Scores computed per trigger type and resulting tier |
| `kyc_risk_score_value` | Histogram | `trigger` | Distribution of total_score values |
| `kyc_risk_auto_approved` | Counter | — | Cases auto-approved by scoring engine |
| `kyc_risk_auto_escalated` | Counter | — | Cases auto-escalated by scoring engine |
| `kyc_risk_tier_gauge` | Gauge | `tier` | Current count of users per tier |
| `kyc_risk_factor_score` | Histogram | `factor_name` | Per-factor score distribution |
| `kyc_risk_rescore_total` | Counter | `trigger` | Re-scoring events (manual, continuous, profile_change) |
| `kyc_risk_scoring_latency_ms` | Histogram | — | Time to compute full 8-factor score |

### Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.risk.scored` | INFO | `case_id`, `user_sub`, `total_score`, `tier`, `trigger` | Every scoring computation |
| `kyc.risk.auto_approved` | INFO | `case_id`, `score`, `all_checks_passed` | Auto-approve triggered |
| `kyc.risk.auto_escalated` | WARN | `case_id`, `score`, `tier` | Auto-escalate triggered |
| `kyc.risk.tier_change` | WARN | `user_sub`, `previous_tier`, `new_tier`, `trigger` | User's tier changed |
| `kyc.risk.factor_anomaly` | WARN | `factor_name`, `score`, `case_id` | Individual factor scores >= 80 |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Critical risk case | `tier == critical` on any new score | P1 (immediate admin notification) |
| Scoring failure | `compute_score` raises exception | P2 |
| Auto-approve rate anomaly | `auto_approve_rate > 90%` in 24h | P3 (review thresholds) |
| Tier migration spike | > 10 users move to `high` or `critical` in 1h | P2 |

---

## 13. Performance Considerations

| Operation | Latency Target | DDB Cost | Notes |
|-----------|---------------|----------|-------|
| Compute full score (8 factors) | < 500ms | ~10-15 RCU + 1 WCU | Reads from 4-5 tables + 1 write |
| Get latest score | < 50ms | 1 RCU | Single query with Limit=1 |
| Get score history | < 100ms | 5-10 RCU | Query with limit |
| Tier distribution | < 200ms | 4 RCU (4 count queries) | One count per tier |
| Batch re-score (50 users) | < 10s | ~500-750 RCU + 50 WCU | Sequential processing |
| Re-score single case | < 500ms | ~10-15 RCU + 1 WCU | Same as initial compute |

### Optimization Notes

- Factor computations can be parallelized with `asyncio.gather()` since they read from independent tables.
- The `ByTier` GSI count query for distribution can be cached for 5 minutes (tier counts change slowly).
- Batch re-score processes users sequentially to avoid DDB throttling. A semaphore limits concurrent DDB reads.
- Factor weights are in-memory constants; no DDB lookup needed for scoring configuration.
- Previous score is read from the same table (latest query) before storing new score, adding 1 RCU per computation.

---

## 14. Rollout Plan

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_RISK_SCORING_ENABLED` | `false` | Gates risk score computation at submission |
| `KYC_RISK_AUTO_APPROVE_ENABLED` | `false` | Gates auto-approve action |
| `KYC_RISK_AUTO_ESCALATE_ENABLED` | `false` | Gates auto-escalate action |
| `KYC_RISK_CONTINUOUS_ENABLED` | `false` | Gates continuous monitoring re-scoring |

### Phases

| Phase | Description | Duration |
|-------|-------------|----------|
| 1 | Deploy scoring service + DDB table behind flag | 2 days |
| 2 | Enable scoring in staging; validate factor computations | 1 day |
| 3 | Enable scoring in production (compute-only, no auto-actions) | 1 week |
| 4 | Enable auto-approve with conservative threshold (score <= 15) | after 2 weeks |
| 5 | Enable auto-escalate for critical tier | after 1 month |
| 6 | Enable continuous monitoring | after 2 months |
| 7 | Tune factor weights based on production data | ongoing |

### Rollback

1. Set `KYC_RISK_SCORING_ENABLED=false` -- scores not computed at submission.
2. Existing scores remain in DDB for audit trail.
3. Auto-actions disabled independently via their own flags.
4. Dashboard shows historical data only (no new scores computed).
5. Cases in `submitted` status proceed to normal manual review.

---

## 15. Expanded E2E Tests

### Section 178 Additions: Factor Computation Edge Cases (4 additional tests)

```typescript
test("178.7 New account (< 7 days) gets highest account_age factor score", async () => {
  // Create user with very recent account
  // Submit case
  // Verify account_age factor score = 100
});

test("178.8 Incomplete profile increases profile_completeness factor", async () => {
  // User with missing DOB, address, and phone
  // Verify profile_completeness factor score = 60 (3 * 20)
});

test("178.9 Address mismatch increases address_match factor", async () => {
  // User with residency doc showing different city
  // Verify address_match factor score = 80
});

test("178.10 Factor weights sum to exactly 1.0", async () => {
  // GET risk score
  // Sum all factor weights
  // Verify equals 1.0 (within floating point tolerance)
});
```

### Section 179 Additions: Auto-Action Edge Cases (3 additional tests)

```typescript
test("179.5 Auto-approve disabled when flag is false even if score qualifies", async () => {
  // Set KYC_RISK_AUTO_APPROVE_ENABLED=false (or mock)
  // Submit low-risk case
  // Verify auto_action_taken = "none" even though score <= 20
  // Verify case status remains "submitted" (not "approved")
});

test("179.6 Score of exactly 20 still qualifies for auto-approve", async () => {
  // Craft a case with factors summing to exactly 20
  // Verify auto_action_taken = "auto_approved"
});

test("179.7 Score of 81 triggers auto-escalate (boundary)", async () => {
  // Multiple high-risk factors summing to 81
  // Verify tier = "critical"
  // Verify auto_action_taken = "auto_escalated"
});
```

### Section 180 Additions: History Edge Cases (3 additional tests)

```typescript
test("180.5 Score history tracks tier changes across re-scores", async () => {
  // First score: low tier
  // Add screening match, re-score: medium tier
  // Verify history shows previous_tier = "low", current = "medium"
});

test("180.6 Model version is recorded on each score", async () => {
  // Compute score
  // Verify model_version = "v1.0"
});

test("180.7 Multiple cases for same user all have independent scores", async () => {
  // Create two cases for Alice, submit both
  // Verify each case has its own score record
  // Verify user history includes scores from both cases
});
```

### Section 181 Additions: Dashboard API Edge Cases (3 additional tests)

```typescript
test("181.5 Distribution with no scored users returns all zeros", async () => {
  // Fresh DDB table with no risk scores
  // GET distribution
  // Verify all tier counts = 0, total_scored = 0
});

test("181.6 Batch re-score returns count of users processed", async () => {
  // POST rescore-approved with batch_size=5
  // Verify response has processed_count, new_scores_count
});

test("181.7 List users by invalid tier returns 422", async () => {
  // GET /admin/risk/tier/extreme
  // Expect 422 validation_error
});
```

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | all | VERIFIED (1294 lines) |
| `get_admin_kyc_metrics()` | `app/routers/kyc_cases.py` | 947 | VERIFIED (ticket cites line 946 -- off by 1) |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines) |
| `_risk()` function | `app/services/kyc_cases.py` | 664 | VERIFIED |
| `_ALLOWED_STATUSES` | `app/services/kyc_cases.py` | 17 | VERIFIED |
| `create_case()` | `app/services/kyc_cases.py` | 97 | VERIFIED |
| `apply_admin_decision()` | `app/services/kyc_cases.py` | 534 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| `require_root_session` | `app/auth/deps.py` | 273 | VERIFIED |

### Not Yet Implemented (requires new code)

<!-- NOTE: The ticket references `get_admin_kyc_metrics()` at line 946 -- actual line is 947. -->

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `app/services/kyc_risk_scoring.py` | `app/services/` | NOT FOUND -- new service required |
| `kyc_risk_scores` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| Risk scoring settings (table name, weights) | `app/core/settings.py` | NOT FOUND -- new settings required |
| Risk scoring admin endpoints | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoints required |
| Risk tier assignment logic | `app/services/kyc_cases.py` | NOT FOUND -- new logic required (extends `_risk()`) |
| `frontend/src/pages/admin/KycRiskDashboard.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |
