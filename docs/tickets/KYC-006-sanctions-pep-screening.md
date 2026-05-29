# KYC-006: Sanctions & PEP Screening

**Ticket**: KYC-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 14-18 days
**Dependencies**: KYC-001 (Admin Review Dashboard), KYC-002 (Identity Document Verification)

---

## 1. Overview & Motivation

### Problem Statement

The platform has no mechanism to screen users against sanctions lists (OFAC, EU, UN) or
Politically Exposed Person (PEP) databases. AML regulations require financial platforms to
screen all customers against sanctions lists before onboarding and continuously thereafter.
PEP screening identifies individuals who hold or have held prominent public positions, which
requires enhanced due diligence.

The existing KYC flow (`app/routers/kyc_cases.py`, `app/services/kyc_cases.py`) processes
identity verification but does not perform any name-based or identity-based screening against
external watchlists. This creates significant regulatory risk.

### Goals

1. Build a mock sanctions/PEP screening service for development and testing.
2. Screen all KYC cases automatically upon submission.
3. Support multiple screen types: OFAC, EU sanctions, UN sanctions, PEP check, adverse media.
4. Store screening results with match details in a dedicated DDB table.
5. Require admin review for potential matches before case approval.
6. Implement re-screening on profile changes (name, DOB, nationality).
7. Support continuous monitoring: periodic re-screening of approved users.
8. Mock returns deterministic matches based on test names for testability.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Platform | Auto-screen every KYC submission against sanctions lists | No sanctioned person is onboarded |
| 2 | KYC reviewer | See screening results with match details | I can evaluate potential matches |
| 3 | KYC reviewer | Clear a false-positive potential match | The case can proceed to approval |
| 4 | Compliance officer | Re-screen approved users periodically | Ongoing compliance is maintained |
| 5 | Platform | Re-screen users when their profile changes | Name changes trigger new checks |
| 6 | Developer | Use deterministic mock screening in dev mode | E2E tests produce predictable results |
| 7 | KYC reviewer | See screening history for a user over time | Audit trail is complete |

---

## 2. Current State Analysis

### 2.1 KYC Case Submission Flow

`submit_kyc_case()` (line 830 of `app/routers/kyc_cases.py`) transitions the case from
`draft` to `submitted`, builds an evidence snapshot with evidence hash, creates a review
ticket, and emits audit events. This is the integration point for triggering automatic
screening.

### 2.2 Case Status Transitions

From `app/services/kyc_cases.py` (line 17):
```python
_ALLOWED_STATUSES = {
    "draft", "submitted", "under_review", "needs_more_info",
    "approved", "rejected", "expired",
}
```

Screening results will influence the transition from `submitted` to `under_review` or
`needs_more_info` depending on match outcomes.

### 2.3 User Profile Access

User profile data (full name, DOB, nationality) is accessible via `app/services/profiles.py`.
Profile change events are tracked via `audit_event()` in profile update endpoints.

### 2.4 Audit Event Infrastructure

`audit_event()` in `app/services/alerts.py` (line 695) supports arbitrary key-value fields.
Screening events will use namespace `kyc_screening` for filtering and audit trail.

---

## 3. Technical Design

### 3.1 New DDB Table: `kyc_screening_results`

**Table name**: `kyc_screening_results` (env: `KYC_SCREENING_RESULTS_TABLE_NAME`)
**Partition key**: `case_id` (String)
**Sort key**: `screen_key` (String) -- format: `{screen_type}#{timestamp}`

| Field | Type | Description |
|-------|------|-------------|
| `case_id` | S (PK) | FK to KYC case, or `USER#{user_sub}` for continuous monitoring |
| `screen_key` | S (SK) | `{screen_type}#{iso_timestamp}` e.g. `sanctions_ofac#2026-05-29T10:00:00Z` |
| `screening_id` | S | `"scr_" + uuid4().hex[:12]` |
| `screen_type` | S | `sanctions_ofac`, `sanctions_eu`, `sanctions_un`, `pep_check`, `adverse_media` |
| `user_sub` | S | Subject user |
| `screened_name` | S | Full name as screened |
| `screened_dob` | S | Date of birth as screened |
| `screened_nationality` | S | Nationality as screened |
| `result` | S | `clear`, `potential_match`, `confirmed_match` |
| `match_details` | L | List of match records (empty if clear) |
| `reviewed_by` | S | Admin sub who reviewed (null if unreviewed) |
| `review_decision` | S | `false_positive`, `true_match`, null |
| `review_note` | S | Admin notes on review |
| `reviewed_at` | N | Timestamp of review |
| `provider` | S | `mock_screening` in dev |
| `trigger` | S | `submission`, `profile_change`, `continuous_monitoring`, `manual` |
| `created_at` | N | Unix timestamp |

Each match in `match_details`:
```json
{
    "list_name": "OFAC SDN",
    "matched_name": "ALICE SMITH",
    "matched_dob": "1990-05-15",
    "match_score": 0.95,
    "entity_id": "SDN-12345",
    "entity_type": "individual",
    "listed_since": "2020-01-01",
    "source_url": "https://sanctionssearch.ofac.treas.gov/"
}
```

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByUserSub` | `user_sub` | `created_at` (N) | All screenings for a user across cases |
| `ByResult` | `result` | `created_at` (N) | Query potential_match for admin review queue |

**DDB init** (`scripts/local-ddb-init.py`):
```python
TableDef(
    _resolve_table_name(S.kyc_screening_results_table_name, "kyc_screening_results"),
    partition_key="case_id",
    sort_key="screen_key",
    gsis=[
        {"index_name": "user-created-index", "partition_key": "user_sub", "sort_key": "created_at"},
        {"index_name": "result-created-index", "partition_key": "result", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

### 3.2 New Service: `app/services/kyc_screening.py`

```python
SCREEN_TYPES = ["sanctions_ofac", "sanctions_eu", "sanctions_un", "pep_check", "adverse_media"]

class KycScreeningService:
    def __init__(self, table=None):
        self._table = table or T.kyc_screening_results

    def screen_case(self, *, case_id: str, user_sub: str, trigger: str = "submission") -> list[dict]:
        """Run all screen types for a case. Returns list of screening results."""

    def screen_single(self, *, case_id: str, user_sub: str, screen_type: str, trigger: str) -> dict:
        """Run a single screen type. Returns screening result."""

    def get_results_for_case(self, *, case_id: str) -> list[dict]:
        """Get all screening results for a case."""

    def get_results_for_user(self, *, user_sub: str, limit: int = 50) -> list[dict]:
        """Get screening history for a user across all cases."""

    def get_pending_reviews(self, *, limit: int = 50, cursor: str | None = None) -> dict:
        """Get potential_match results that need admin review."""

    def review_match(self, *, case_id: str, screen_key: str, admin_sub: str,
                     decision: str, note: str) -> dict:
        """Admin reviews a potential match (false_positive or true_match)."""

    def rescreen_user(self, *, user_sub: str, trigger: str = "profile_change") -> list[dict]:
        """Re-screen a user across all screen types. Used for profile changes."""

    def _run_mock_screening(self, *, screen_type: str, name: str, dob: str,
                            nationality: str) -> dict:
        """Mock screening provider. Deterministic results based on name patterns."""
```

### 3.3 Mock Screening Provider

Deterministic results for testability:

| Name pattern | Screen type | Result |
|-------------|-------------|--------|
| `*OFAC Test*` | `sanctions_ofac` | `potential_match` with 0.92 score |
| `*Sanctioned Person*` | All sanctions types | `confirmed_match` with 1.0 score |
| `*PEP Official*` | `pep_check` | `potential_match` with 0.88 score |
| `*Media Flagged*` | `adverse_media` | `potential_match` with 0.75 score |
| Any other name | All types | `clear` |

Mock response structure for a match:
```python
{
    "result": "potential_match",
    "match_details": [
        {
            "list_name": f"Mock {screen_type.upper()} List",
            "matched_name": name,
            "matched_dob": dob,
            "match_score": 0.92,
            "entity_id": f"MOCK-{uuid4().hex[:8]}",
            "entity_type": "individual",
            "listed_since": "2023-01-01",
            "source_url": "https://mock-screening.example.com/"
        }
    ]
}
```

### 3.4 Submission Integration

In `submit_kyc_case()` (line 830 of `app/routers/kyc_cases.py`), after successful
submission and review ticket creation, trigger screening:

```python
# After submission success
screening_service = KycScreeningService()
results = screening_service.screen_case(
    case_id=case_id,
    user_sub=case["user_sub"],
    trigger="submission",
)

# If any result is potential_match or confirmed_match, auto-flag
has_matches = any(r["result"] != "clear" for r in results)
if has_matches:
    # Add screening_flags to the review ticket
    audit_event("kyc_screening_matches_found", case["user_sub"], request,
                match_count=sum(1 for r in results if r["result"] != "clear"),
                case_id=case_id)
```

### 3.5 Profile Change Re-screening

Add a hook in `app/routers/settings.py` profile update endpoint. When a user updates their
`display_name`, `date_of_birth`, or `nationality`, and they have an approved KYC case,
trigger re-screening:

```python
# In profile update handler
if any(field in changed_fields for field in ("display_name", "date_of_birth", "nationality")):
    screening_service = KycScreeningService()
    screening_service.rescreen_user(user_sub=user_sub, trigger="profile_change")
```

### 3.6 New Router Endpoints

**File: `app/routers/kyc_cases.py`** -- add endpoints:

```python
@router.get("/{case_id}/screening-results")
def get_case_screening_results(case_id: str, ...):
    """Get screening results for a case. Available to case owner (summary) and admins (full)."""

@router.get("/admin/screening/pending-reviews")
def list_pending_screening_reviews(...):
    """List potential_match results that need admin review."""

@router.post("/admin/screening/{case_id}/{screen_key}/review")
def review_screening_match(case_id: str, screen_key: str, body: KycScreeningReviewRequest, ...):
    """Admin reviews a screening match (false_positive or true_match)."""

@router.post("/admin/screening/{case_id}/rescreen")
def admin_trigger_rescreen(case_id: str, ...):
    """Admin manually triggers a re-screen for a case."""

@router.get("/admin/screening/user/{user_sub}/history")
def get_user_screening_history(user_sub: str, ...):
    """Get full screening history for a user across all cases."""
```

### 3.7 Request Models

**File: `app/contracts/kyc_cases_contract.py`** -- add:

```python
class KycScreeningReviewRequest(BaseModel):
    decision: Literal["false_positive", "true_match"]
    note: str = Field(..., min_length=1, max_length=2000)

class KycScreeningResultOut(BaseModel):
    screening_id: str
    screen_type: str
    result: Literal["clear", "potential_match", "confirmed_match"]
    match_details: list[dict] = Field(default_factory=list)
    reviewed_by: str | None = None
    review_decision: str | None = None
    trigger: str
    created_at: int
```

### 3.8 Frontend Changes

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add "Screening Results" tab:
- Table of screening results per screen type (OFAC, EU, UN, PEP, Adverse Media)
- Status badges: green "Clear", yellow "Potential Match", red "Confirmed Match"
- Expandable match detail rows showing list_name, matched_name, match_score
- "Review" button for potential_match rows -> opens dialog with false_positive/true_match radio
- "Re-screen" button to trigger manual re-screening

**File: `frontend/src/pages/admin/KycScreeningQueuePage.tsx`** (new):

Dedicated page listing all pending screening reviews across all cases:
- Table: Case ID, User, Screen Type, Match Score, Waiting Time, Actions
- Filter by screen type
- Bulk review support (select multiple, mark all as false_positive)

---

## 4. E2E Test Plan

**File**: `frontend/e2e/kyc-screening.spec.ts`
**Total**: ~20 tests across 4 sections (170-173)

### Section 170: Automatic Screening on Submission (5 tests)

```typescript
test("170.1 Submitting KYC case triggers screening for all types", async () => {
  // Create case, submit
  // GET /v1/kyc/cases/{id}/screening-results
  // Verify 5 results (one per screen type), all "clear"
});

test("170.2 User with OFAC-triggering name gets potential_match", async () => {
  // Set user display_name to "OFAC Test Person"
  // Create and submit case
  // Verify sanctions_ofac result = "potential_match" with match_details
});

test("170.3 User with Sanctioned name gets confirmed_match on all sanctions", async () => {
  // Set display_name to "Sanctioned Person Alpha"
  // Submit case
  // Verify sanctions_ofac, sanctions_eu, sanctions_un all = "confirmed_match"
});

test("170.4 PEP check triggers on PEP name pattern", async () => {
  // Set display_name to "PEP Official Jones"
  // Submit case
  // Verify pep_check = "potential_match"
});

test("170.5 Normal name produces all clear results", async () => {
  // Regular name like "Jane Smith"
  // Submit case
  // Verify all 5 screen types = "clear"
});
```

### Section 171: Admin Screening Review (5 tests)

```typescript
test("171.1 Admin lists pending screening reviews", async () => {
  // GET /v1/kyc/cases/admin/screening/pending-reviews as Root
  // Verify includes the potential_match from 170.2
});

test("171.2 Admin marks match as false positive", async () => {
  // POST /v1/kyc/cases/admin/screening/{case_id}/{screen_key}/review
  // { decision: "false_positive", note: "Name similarity only, different DOB" }
  // Verify review_decision = "false_positive", reviewed_by set
});

test("171.3 Admin marks match as true match", async () => {
  // { decision: "true_match", note: "Confirmed sanctioned entity" }
  // Verify review_decision = "true_match"
});

test("171.4 Reviewed match no longer appears in pending reviews", async () => {
  // GET pending-reviews
  // Verify reviewed match is not in the list
});

test("171.5 Non-admin gets 403 on screening review", async () => {
  // Alice tries to review screening
  // Expect 403
});
```

### Section 172: Re-screening (5 tests)

```typescript
test("172.1 Admin triggers manual re-screen for a case", async () => {
  // POST /v1/kyc/cases/admin/screening/{case_id}/rescreen
  // Verify new screening results created with trigger="manual"
});

test("172.2 Re-screen creates new results alongside existing ones", async () => {
  // GET screening results
  // Verify results from both original screening and re-screen
  // Verify different timestamps on screen_key
});

test("172.3 User screening history shows all screenings chronologically", async () => {
  // GET /v1/kyc/cases/admin/screening/user/{sub}/history
  // Verify results ordered by created_at descending
  // Verify multiple entries from submission + re-screen
});

test("172.4 Profile name change triggers re-screening for approved user", async () => {
  // Approve Alice's case
  // Update Alice's display_name via profile API
  // GET screening history
  // Verify new screening with trigger="profile_change"
});

test("172.5 Re-screen with changed name produces different result", async () => {
  // Change name to "OFAC Test Updated"
  // Verify re-screen now shows potential_match (was clear before)
});
```

### Section 173: Screening UI (5 tests)

```typescript
test("173.1 Case detail shows screening results tab", async ({ page }) => {
  // Navigate to /admin/kyc/cases/{id} as Root
  // Click "Screening Results" tab
  // Verify table with 5 rows (one per screen type)
});

test("173.2 Potential match row shows expandable details", async ({ page }) => {
  // Click expand on potential_match row
  // Verify match details: list_name, matched_name, match_score
});

test("173.3 Review button opens review dialog", async ({ page }) => {
  // Click "Review" on potential_match row
  // Verify dialog with false_positive/true_match options
  // Select false_positive, enter note, submit
  // Verify badge changes to "Reviewed - False Positive"
});

test("173.4 Re-screen button triggers new screening", async ({ page }) => {
  // Click "Re-screen" button
  // Verify loading indicator, then refreshed results
});

test("173.5 Screening queue page lists pending reviews", async ({ page }) => {
  // Navigate to /admin/kyc/screening
  // Verify table with pending review items
  // Verify filter by screen type works
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_screening.py` | **New** | Screening service with mock provider and match review |
| `app/routers/kyc_cases.py` | Modify | Add 5 screening endpoints; integrate with submission |
| `app/contracts/kyc_cases_contract.py` | Modify | Add screening review request/response models |
| `app/core/settings.py` | Modify | Add screening table name and provider settings |
| `app/core/tables.py` | Modify | Add `kyc_screening_results` table handle |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_screening_results` table with 2 GSIs |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add Screening Results tab |
| `frontend/src/pages/admin/KycScreeningQueuePage.tsx` | **New** | Pending screening review queue |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add screening API functions |
| `frontend/src/App.tsx` | Modify | Add /admin/kyc/screening route |
| `frontend/e2e/kyc-screening.spec.ts` | **New** | 20 E2E tests across sections 170-173 |
