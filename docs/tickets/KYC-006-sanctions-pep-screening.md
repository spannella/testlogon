# KYC-006: Sanctions & PEP Screening

**Ticket**: KYC-006
**Author**: Engineering
**Status**: Implemented
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

The existing KYC flow (see `app/routers/kyc_cases.py:830` for `submit_kyc_case`, `app/services/kyc_cases.py:534` for `apply_admin_decision`) processes
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

## 2. Architecture Diagram

```
+-------------------------------------------------------------------------+
|                            Frontend (React)                             |
|                                                                         |
|  KycCaseDetailPage.tsx (admin)        KycScreeningQueuePage.tsx (admin) |
|  +-------------------------------+   +-------------------------------+  |
|  | ScreeningResultsTab            |   | PendingReviewsTable            |  |
|  |  +--ScreenTypeTable           |   |  +--FilterByType               |  |
|  |  |  Row[OFAC] StatusBadge     |   |  +--ReviewRow[]                |  |
|  |  |  Row[EU]   StatusBadge     |   |  |  CaseLink | Score | Time   |  |
|  |  |  Row[UN]   StatusBadge     |   |  |  ReviewButton               |  |
|  |  |  Row[PEP]  StatusBadge     |   |  +--BulkReviewBar              |  |
|  |  |  Row[Media] StatusBadge    |   |     "Mark All False Positive"  |  |
|  |  +--MatchDetailsExpander      |   +-------------------------------+  |
|  |  +--ReviewDialog              |                                      |
|  |  +--ReScreenButton            |                                      |
|  +-------------------------------+                                      |
+------------------|------------------------------|------------------------+
                   |                              |
          POST/GET |                     POST/GET |
                   v                              v
+-------------------------------------------------------------------------+
|                       FastAPI Backend (8000)                             |
|                                                                         |
|  Submission Integration                                                 |
|  +-------------------------------------------------------------------+ |
|  | submit_kyc_case()                                                  | |
|  |   -> after status transition to "submitted"                       | |
|  |   -> KycScreeningService.screen_case(case_id, user_sub)           | |
|  |      -> runs 5 screen types in sequence (mock) or parallel (prod) | |
|  |      -> stores results in kyc_screening_results table             | |
|  |      -> if any match: audit_event("kyc_screening_matches_found")  | |
|  +-------------------------------------------------------------------+ |
|                                                                         |
|  Profile Change Hook                                                    |
|  +-------------------------------------------------------------------+ |
|  | update_profile() (settings.py)                                     | |
|  |   -> if name/dob/nationality changed AND user has approved case   | |
|  |   -> KycScreeningService.rescreen_user(trigger="profile_change")  | |
|  +-------------------------------------------------------------------+ |
|                                                                         |
|  KycScreeningService (app/services/kyc_screening.py)                    |
|  +-------------------------------------------------------------------+ |
|  | screen_case()        -> run all 5 screen types for a case          | |
|  | screen_single()      -> run one screen type                        | |
|  | get_results_for_case -> query PK=case_id                           | |
|  | get_results_for_user -> GSI ByUserSub query                        | |
|  | get_pending_reviews  -> GSI ByResult PK=potential_match            | |
|  | review_match()       -> update reviewed_by, decision, note         | |
|  | rescreen_user()      -> find latest case, re-run all types         | |
|  | _run_mock_screening  -> deterministic name-pattern matching        | |
|  +-------------------------------------------------------------------+ |
|                                                                         |
|  Admin Endpoints (kyc_cases.py)                                         |
|  +-------------------------------------------------------------------+ |
|  | GET  /{case_id}/screening-results                                  | |
|  | GET  /admin/screening/pending-reviews                              | |
|  | POST /admin/screening/{case_id}/{screen_key}/review                | |
|  | POST /admin/screening/{case_id}/rescreen                           | |
|  | GET  /admin/screening/user/{user_sub}/history                      | |
|  +-------------------------------------------------------------------+ |
+-------------------------------|------------------------------------------+
                                |
                                v
+-------------------------------------------------------------------------+
|                          DynamoDB                                        |
|                                                                         |
|  kyc_screening_results table                                            |
|  +-------------------------------------------------------------------+ |
|  | PK: case_id (or "USER#{sub}" for continuous monitoring)            | |
|  | SK: {screen_type}#{iso_timestamp}                                  | |
|  |                                                                    | |
|  | Fields: screening_id, screen_type, result, match_details[],       | |
|  |   reviewed_by, review_decision, review_note, reviewed_at,         | |
|  |   user_sub, screened_name, screened_dob, screened_nationality,     | |
|  |   provider, trigger, created_at                                    | |
|  |                                                                    | |
|  | GSI ByUserSub: PK=user_sub, SK=created_at (N)                     | |
|  | GSI ByResult:  PK=result,   SK=created_at (N)                     | |
|  +-------------------------------------------------------------------+ |
|                                                                         |
|  Mock Screening Provider (deterministic lookup)                         |
|  +-------------------------------------------------------------------+ |
|  | "OFAC Test*"        -> sanctions_ofac:  potential_match (0.92)     | |
|  | "Sanctioned Person" -> ALL sanctions:   confirmed_match (1.0)     | |
|  | "PEP Official*"     -> pep_check:       potential_match (0.88)    | |
|  | "Media Flagged*"    -> adverse_media:   potential_match (0.75)    | |
|  | anything else       -> ALL:             clear                     | |
|  +-------------------------------------------------------------------+ |
+-------------------------------------------------------------------------+
```

---

## 3. Current State Analysis

### 3.1 KYC Case Submission Flow

`submit_kyc_case()` (see `app/routers/kyc_cases.py:830`) transitions the case from
`draft` to `submitted`, builds an evidence snapshot with evidence hash, creates a review
ticket, and emits audit events. This is the integration point for triggering automatic
screening.

### 3.2 Case Status Transitions

From `app/services/kyc_cases.py` (see `:17` for `_ALLOWED_STATUSES`):
```python
_ALLOWED_STATUSES = {
    "draft", "submitted", "under_review", "needs_more_info",
    "approved", "rejected", "expired",
}
```

Screening results will influence the transition from `submitted` to `under_review` or
`needs_more_info` depending on match outcomes.

### 3.3 User Profile Access

User profile data (full name, DOB, nationality) is accessible via `app/services/profiles.py` (see `:220` for `get_profile`, `:294` for `apply_profile_update`).
Profile change events are tracked via `audit_event()` in profile update endpoints.

### 3.4 Audit Event Infrastructure

`audit_event()` (see `app/services/alerts.py:695`) supports arbitrary key-value fields.
Screening events will use namespace `kyc_screening` for filtering and audit trail.

---

## 4. Technical Design

### 4.1 New DDB Table: `kyc_screening_results`

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

### 4.2 New Service: `app/services/kyc_screening.py`

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

### 4.3 Mock Screening Provider

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

### 4.4 Submission Integration

In `submit_kyc_case()` (see `app/routers/kyc_cases.py:830`), after successful
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

### 4.5 Profile Change Re-screening

Add a hook in `app/routers/settings.py` profile update endpoint. When a user updates their
`display_name`, `date_of_birth`, or `nationality`, and they have an approved KYC case,
trigger re-screening:

```python
# In profile update handler
if any(field in changed_fields for field in ("display_name", "date_of_birth", "nationality")):
    screening_service = KycScreeningService()
    screening_service.rescreen_user(user_sub=user_sub, trigger="profile_change")
```

### 4.6 New Router Endpoints

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

### 4.7 Frontend Changes

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

## 5. DynamoDB Access Patterns

| # | Access Pattern | Table / Index | Key Condition | Notes |
|---|---------------|---------------|---------------|-------|
| 1 | Get screening results for case | `kyc_screening_results` | PK=`{case_id}` | Returns all screen types with timestamps |
| 2 | Get single screening result | `kyc_screening_results` | PK=`{case_id}`, SK=`{screen_type}#{ts}` | Exact get for review operations |
| 3 | Get user screening history | GSI `ByUserSub` | PK=`{user_sub}`, SK desc | All screenings across cases |
| 4 | Get pending reviews | GSI `ByResult` | PK=`potential_match`, SK desc | Unreviewed matches for admin queue |
| 5 | Update review decision | `kyc_screening_results` | PK=`{case_id}`, SK=`{screen_key}` | Set `reviewed_by`, `review_decision`, `review_note`, `reviewed_at` |
| 6 | Store new screening result | `kyc_screening_results` | PK=`{case_id}`, SK=`{screen_type}#{iso_ts}` | PutItem for each screen type run |
| 7 | Count pending by type | GSI `ByResult` | PK=`potential_match`, filter `screen_type` | For admin queue filtering |

### 5.1 Example DynamoDB Item

```json
{
  "case_id": { "S": "kyc_a1b2c3d4" },
  "screen_key": { "S": "sanctions_ofac#2026-05-29T10:00:00Z" },
  "screening_id": { "S": "scr_a1b2c3d4e5f6" },
  "screen_type": { "S": "sanctions_ofac" },
  "user_sub": { "S": "e2e_alice@test.local" },
  "screened_name": { "S": "OFAC Test Person" },
  "screened_dob": { "S": "1990-01-15" },
  "screened_nationality": { "S": "US" },
  "result": { "S": "potential_match" },
  "match_details": {
    "L": [
      {
        "M": {
          "list_name": { "S": "Mock SANCTIONS_OFAC List" },
          "matched_name": { "S": "OFAC Test Person" },
          "matched_dob": { "S": "1990-01-15" },
          "match_score": { "N": "0.92" },
          "entity_id": { "S": "MOCK-a1b2c3d4" },
          "entity_type": { "S": "individual" },
          "listed_since": { "S": "2023-01-01" },
          "source_url": { "S": "https://mock-screening.example.com/" }
        }
      }
    ]
  },
  "reviewed_by": { "NULL": true },
  "review_decision": { "NULL": true },
  "review_note": { "NULL": true },
  "reviewed_at": { "NULL": true },
  "provider": { "S": "mock_screening" },
  "trigger": { "S": "submission" },
  "created_at": { "N": "1716681600" }
}
```

### 5.2 Write Patterns

| Operation | Update Expression | Condition | Notes |
|-----------|------------------|-----------|-------|
| Store screening result | PutItem | `attribute_not_exists(case_id) AND attribute_not_exists(screen_key)` | Prevents overwrite of existing result |
| Review match | `SET reviewed_by=:admin, review_decision=:dec, review_note=:note, reviewed_at=:ts` | `attribute_exists(case_id) AND attribute_not_exists(reviewed_by)` | Prevents double-review |
| Re-screen (new result) | PutItem with new timestamp in SK | None (always succeeds) | Append-only pattern |

---

## 6. API Request/Response Examples

### 6.1 Get Screening Results for Case

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/screening-results" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "results": [
    {
      "screening_id": "scr_a1b2c3d4e5f6",
      "screen_type": "sanctions_ofac",
      "result": "potential_match",
      "match_details": [
        {
          "list_name": "Mock SANCTIONS_OFAC List",
          "matched_name": "OFAC Test Person",
          "matched_dob": "1990-01-15",
          "match_score": 0.92,
          "entity_id": "MOCK-a1b2c3d4",
          "entity_type": "individual",
          "listed_since": "2023-01-01",
          "source_url": "https://mock-screening.example.com/"
        }
      ],
      "reviewed_by": null,
      "review_decision": null,
      "trigger": "submission",
      "provider": "mock_screening",
      "created_at": 1716681600
    },
    {
      "screening_id": "scr_f6e5d4c3b2a1",
      "screen_type": "sanctions_eu",
      "result": "clear",
      "match_details": [],
      "reviewed_by": null,
      "review_decision": null,
      "trigger": "submission",
      "provider": "mock_screening",
      "created_at": 1716681601
    },
    {
      "screening_id": "scr_111222333444",
      "screen_type": "sanctions_un",
      "result": "clear",
      "match_details": [],
      "trigger": "submission",
      "provider": "mock_screening",
      "created_at": 1716681602
    },
    {
      "screening_id": "scr_555666777888",
      "screen_type": "pep_check",
      "result": "clear",
      "match_details": [],
      "trigger": "submission",
      "provider": "mock_screening",
      "created_at": 1716681603
    },
    {
      "screening_id": "scr_999000111222",
      "screen_type": "adverse_media",
      "result": "clear",
      "match_details": [],
      "trigger": "submission",
      "provider": "mock_screening",
      "created_at": 1716681604
    }
  ]
}
```

### 6.2 Review a Screening Match

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/screening/kyc_a1b2c3d4/sanctions_ofac%232026-05-29T10:00:00Z/review" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "false_positive",
    "note": "Name similarity only. Different DOB and nationality. Verified against secondary source."
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "screening_id": "scr_a1b2c3d4e5f6",
  "review_decision": "false_positive",
  "reviewed_by": "root.admin@testdev.local",
  "reviewed_at": 1716768000
}
```

### 6.3 List Pending Screening Reviews

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/screening/pending-reviews?limit=20" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "items": [
    {
      "case_id": "kyc_a1b2c3d4",
      "screen_key": "sanctions_ofac#2026-05-29T10:00:00Z",
      "screening_id": "scr_a1b2c3d4e5f6",
      "screen_type": "sanctions_ofac",
      "result": "potential_match",
      "match_details": [{ "matched_name": "OFAC Test Person", "match_score": 0.92 }],
      "user_sub": "e2e_alice@test.local",
      "trigger": "submission",
      "created_at": 1716681600
    }
  ],
  "cursor": null
}
```

### 6.4 Trigger Manual Re-screen

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/screening/kyc_a1b2c3d4/rescreen" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r"
```

**Response (200):**
```json
{
  "ok": true,
  "case_id": "kyc_a1b2c3d4",
  "results_count": 5,
  "trigger": "manual",
  "matches_found": 1
}
```

### 6.5 Get User Screening History

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/screening/user/e2e_alice@test.local/history?limit=50" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "user_sub": "e2e_alice@test.local",
  "results": [
    {
      "case_id": "kyc_a1b2c3d4",
      "screening_id": "scr_new_manual_01",
      "screen_type": "sanctions_ofac",
      "result": "clear",
      "trigger": "manual",
      "created_at": 1716768000
    },
    {
      "case_id": "kyc_a1b2c3d4",
      "screening_id": "scr_a1b2c3d4e5f6",
      "screen_type": "sanctions_ofac",
      "result": "potential_match",
      "match_details": [{ "matched_name": "OFAC Test Person", "match_score": 0.92 }],
      "review_decision": "false_positive",
      "trigger": "submission",
      "created_at": 1716681600
    }
  ],
  "total": 2
}
```

### 6.6 Non-admin Attempts Admin Endpoint (403)

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/screening/pending-reviews" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (403):**
```json
{
  "detail": "Admin access required.",
  "error_code": "kyc_admin_role_required"
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|----------------|
| 1 | Get screening for non-existent case | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| 2 | Non-owner views screening results | 403 | `kyc_access_forbidden` | "Access denied." | Use correct session |
| 3 | Non-admin accesses admin endpoints | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| 4 | Review already-reviewed match | 409 | `kyc_screening_already_reviewed` | "This match has already been reviewed." | Refresh results |
| 5 | Review with invalid decision value | 422 | `validation_error` | "Decision must be 'false_positive' or 'true_match'." | Use valid decision |
| 6 | Re-screen case without submitted status | 400 | `kyc_invalid_status` | "Case must be submitted or under review for screening." | Check case status |
| 7 | Invalid screen_key format in URL | 400 | `kyc_invalid_screen_key` | "Invalid screening result key." | Use correct key from GET results |
| 8 | Screening provider timeout (production) | 502 | `kyc_screening_provider_error` | "Screening service unavailable. Please try later." | Retry or use manual review |
| 9 | User screening history for unknown user | 200 | -- | Returns empty array | Normal behavior |
| 10 | Review note empty | 422 | `validation_error` | "Note must be between 1 and 2000 characters." | Provide non-empty note |
| 11 | Review note exceeds 2000 chars | 422 | `validation_error` | "Note must be between 1 and 2000 characters." | Shorten note |
| 12 | Re-screen non-existent case | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| 13 | Screening result not found (review) | 404 | `kyc_screening_not_found` | "Screening result not found." | Verify case_id + screen_key |
| 14 | Case owner views full match details (non-admin) | 200 | -- | Returns summary only (match_details redacted) | Contact support for full details |

---

## 8. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class KycScreeningReviewRequest(BaseModel):
    """Admin review of a screening match."""

    decision: Literal["false_positive", "true_match"] = Field(
        ...,
        description="Review decision.",
        examples=["false_positive"],
    )
    note: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Justification for the review decision.",
        examples=["Name similarity only. Different DOB and nationality."],
    )


class KycScreeningMatchDetail(BaseModel):
    """A single match from a screening provider."""

    list_name: str = Field(..., description="Watchlist or database name.")
    matched_name: str = Field(..., description="Name matched on the list.")
    matched_dob: str | None = Field(None, description="DOB of matched entity (if available).")
    match_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0-1.0) of the match.",
    )
    entity_id: str = Field(..., description="Unique ID of the matched entity on the list.")
    entity_type: Literal["individual", "entity", "vessel", "aircraft"] = Field(
        ...,
        description="Type of matched entity.",
    )
    listed_since: str | None = Field(None, description="Date entity was added to the list.")
    source_url: str | None = Field(None, description="URL to the source list or entry.")


class KycScreeningResultOut(BaseModel):
    """A single screening result for one screen type."""

    screening_id: str = Field(..., description="Unique screening ID.")
    screen_type: Literal[
        "sanctions_ofac", "sanctions_eu", "sanctions_un",
        "pep_check", "adverse_media"
    ] = Field(..., description="Type of screening performed.")
    result: Literal["clear", "potential_match", "confirmed_match"] = Field(
        ...,
        description="Screening outcome.",
    )
    match_details: list[KycScreeningMatchDetail] = Field(
        default_factory=list,
        description="Match records (empty if clear).",
    )
    reviewed_by: str | None = Field(None, description="Admin who reviewed this match.")
    review_decision: Literal["false_positive", "true_match"] | None = Field(
        None,
        description="Admin review decision.",
    )
    review_note: str | None = Field(None, description="Admin review notes.")
    reviewed_at: int | None = Field(None, description="Unix timestamp of review.")
    trigger: Literal["submission", "profile_change", "continuous_monitoring", "manual"] = Field(
        ...,
        description="What triggered this screening.",
    )
    provider: str = Field("mock_screening", description="Screening provider name.")
    created_at: int = Field(..., description="Unix timestamp of screening.")


class KycScreeningResultsListOut(BaseModel):
    """List of screening results for a case."""

    results: list[KycScreeningResultOut] = Field(default_factory=list)


class KycPendingReviewsOut(BaseModel):
    """Paginated list of screening results needing admin review."""

    items: list[dict] = Field(default_factory=list, description="Pending review items.")
    cursor: str | None = Field(None, description="Pagination cursor for next page.")


class KycRescreenResponse(BaseModel):
    """Response from triggering a re-screen."""

    ok: bool = True
    case_id: str
    results_count: int = Field(..., description="Number of screen types executed.")
    trigger: str = Field(..., description="Trigger type for the re-screen.")
    matches_found: int = Field(..., description="Number of non-clear results.")


class KycReviewResponse(BaseModel):
    """Response from reviewing a screening match."""

    ok: bool = True
    screening_id: str
    review_decision: str
    reviewed_by: str
    reviewed_at: int


class KycUserScreeningHistoryOut(BaseModel):
    """Screening history for a user across all cases."""

    user_sub: str
    results: list[KycScreeningResultOut] = Field(default_factory=list)
    total: int = Field(0, description="Total number of results.")
```

---

## 9. Frontend Component Tree

```
KycCaseDetailPage (admin, extended)
└── Tabs
    └── TabsContent (value="screening-results")
        └── ScreeningResultsTab
            ├── SectionHeader ("Screening Results")
            │   ├── Text ("Screened at: {timestamp}")
            │   └── TriggerBadge ("submission" | "manual" | "profile_change")
            ├── ScreenTypeTable
            │   └── ScreeningRow[] (one per screen type)
            │       ├── ScreenTypeLabel
            │       │   ├── "OFAC SDN" (for sanctions_ofac)
            │       │   ├── "EU Sanctions" (for sanctions_eu)
            │       │   ├── "UN Sanctions" (for sanctions_un)
            │       │   ├── "PEP Check" (for pep_check)
            │       │   └── "Adverse Media" (for adverse_media)
            │       ├── ResultBadge
            │       │   ├── variant="success" -> green "Clear"
            │       │   ├── variant="warning" -> yellow "Potential Match (0.92)"
            │       │   └── variant="destructive" -> red "Confirmed Match"
            │       ├── ReviewStatusBadge (if reviewed)
            │       │   ├── green outline: "Reviewed - False Positive"
            │       │   └── red outline: "Reviewed - True Match"
            │       ├── ExpandButton (for rows with match_details.length > 0)
            │       │   └── MatchDetailsPanel (collapsible)
            │       │       └── MatchCard[] (per match)
            │       │           ├── Text ("List: {list_name}")
            │       │           ├── Text ("Matched: {matched_name}")
            │       │           ├── Text ("DOB: {matched_dob}")
            │       │           ├── ProgressBar (match_score, 0-100%)
            │       │           ├── Text ("Entity: {entity_id} ({entity_type})")
            │       │           ├── Text ("Listed since: {listed_since}")
            │       │           └── Link ("View Source" -> source_url)
            │       └── ReviewButton (for unreviewed potential_match rows)
            │           └── onClick -> open ReviewDialog
            ├── ReviewDialog
            │   ├── DialogTitle ("Review Screening Match")
            │   ├── DialogDescription (screen_type + matched_name)
            │   ├── RadioGroup
            │   │   ├── Radio ("False Positive - name similarity, not the same person")
            │   │   └── Radio ("True Match - confirmed match against watchlist")
            │   ├── Textarea (note, required, maxLength=2000, placeholder="Provide justification...")
            │   └── DialogFooter
            │       ├── Button ("Cancel")
            │       └── Button ("Submit Review")
            │           └── onClick -> useMutation(POST /review)
            └── ReScreenButton
                └── "Re-screen" -> useMutation(POST /rescreen) -> refetch results

KycScreeningQueuePage (/admin/kyc/screening)
├── PageHeader ("Screening Review Queue")
├── StatsSummary
│   ├── StatCard (total_pending)
│   ├── StatCard (oldest_pending_age)
│   └── StatCard (reviewed_today)
├── FilterBar
│   ├── Select (screen_type: All | OFAC | EU | UN | PEP | Adverse Media)
│   ├── Select (sort_by: "oldest_first" | "highest_score")
│   └── Button ("Refresh")
├── PendingReviewsTable
│   ├── TableHeader (Case | User | Type | Score | Waiting | Actions)
│   └── TableBody
│       └── ReviewRow[] (sortable by waiting_time, match_score)
│           ├── Cell: CaseId (link to case detail /admin/kyc/cases/{id})
│           ├── Cell: UserDisplayName
│           ├── Cell: ScreenTypeBadge (color-coded)
│           ├── Cell: MatchScoreBar (visual bar 0-1.0, color gradient)
│           ├── Cell: WaitingTimeBadge (relative: "2h ago", "3d ago")
│           └── Cell: ReviewButton -> opens ReviewDialog
├── BulkReviewBar (visible when rows selected via checkboxes)
│   ├── Text ("{N} selected")
│   ├── Button ("Mark All as False Positive")
│   │   └── onClick -> sequential review API calls
│   └── Button ("Clear Selection")
└── PaginationFooter (cursor-based)
    ├── Text ("Showing {count} of {total}")
    └── Button ("Load More")
```

### State Management (React Query)

```typescript
const screeningKeys = {
  caseResults: (caseId: string) => ["kyc", "screening", caseId] as const,
  pendingReviews: (filters: object) => ["kyc", "screening", "pending", filters] as const,
  userHistory: (userSub: string) => ["kyc", "screening", "history", userSub] as const,
};

function useScreeningResults(caseId: string) {
  return useQuery({
    queryKey: screeningKeys.caseResults(caseId),
    queryFn: () => getScreeningResults(caseId),
    staleTime: 60_000,
  });
}

function useReviewMatch(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { screenKey: string; decision: string; note: string }) =>
      reviewMatch(caseId, body.screenKey, { decision: body.decision, note: body.note }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: screeningKeys.caseResults(caseId) });
      qc.invalidateQueries({ queryKey: ["kyc", "screening", "pending"] });
    },
  });
}

function useRescreen(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => rescreenCase(caseId),
    onSuccess: () => qc.invalidateQueries({ queryKey: screeningKeys.caseResults(caseId) }),
  });
}
```

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_screening_run_total` | Counter | `screen_type`, `trigger` | Total screening runs per type and trigger |
| `kyc_screening_result_total` | Counter | `screen_type`, `result` | Result distribution per type |
| `kyc_screening_match_score_histogram` | Histogram | `screen_type` | Match score distribution for non-clear results |
| `kyc_screening_review_total` | Counter | `decision` | Reviews completed (false_positive / true_match) |
| `kyc_screening_pending_gauge` | Gauge | `screen_type` | Current pending review count per type |
| `kyc_screening_latency_seconds` | Histogram | `screen_type`, `provider` | Screening provider response time |
| `kyc_screening_rescreen_total` | Counter | `trigger` | Re-screens triggered |
| `kyc_screening_review_latency_hours` | Histogram | -- | Time from match creation to review |

### 10.2 Structured Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.screening.run_started` | INFO | `case_id`, `user_sub`, `trigger`, `screen_types` | screen_case() called |
| `kyc.screening.match_found` | WARN | `case_id`, `screen_type`, `match_score`, `matched_name`, `entity_id` | potential_match or confirmed_match |
| `kyc.screening.confirmed_match` | ERROR | `case_id`, `screen_type`, `matched_name`, `entity_id` | confirmed_match (requires immediate attention) |
| `kyc.screening.all_clear` | INFO | `case_id`, `trigger` | All 5 screen types clear |
| `kyc.screening.reviewed` | INFO | `case_id`, `screen_key`, `decision`, `reviewer` | Admin reviews match |
| `kyc.screening.rescreen_triggered` | INFO | `case_id`, `trigger`, `user_sub` | Re-screen requested |
| `kyc.screening.provider_error` | ERROR | `screen_type`, `provider`, `error_message` | Provider timeout/failure |
| `kyc.screening.bulk_review` | INFO | `reviewer`, `count`, `decision` | Bulk false-positive review |

### 10.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|----------|----------|--------|
| Confirmed match detected | Any `confirmed_match` result | P1 (Critical) | Immediate admin notification; block case approval |
| Pending review backlog | > 20 unreviewed `potential_match` older than 24h | P2 (Warning) | Escalate to compliance lead |
| Screening provider errors | > 5% failure rate in 1h (production only) | P2 (Warning) | Check provider status; fallback to manual review |
| False positive rate anomaly | FP rate > 95% over 7 days | P3 (Info) | Review screening quality; tune match thresholds |
| No screenings in 4h | Zero `kyc.screening.run_started` events | P3 (Info) | Check if submission flow is broken |

### 10.4 Dashboard Queries

```sql
-- Screening outcome distribution (last 30 days)
SELECT screen_type, result, count(*) as count
FROM structured_logs
WHERE event = 'kyc.screening.run_started'
  AND timestamp > now() - interval '30 days'
GROUP BY screen_type, result

-- Review backlog aging
SELECT
  screen_type,
  count(*) as pending,
  min(created_at) as oldest,
  avg(EXTRACT(EPOCH FROM (now() - to_timestamp(created_at)))) / 3600 as avg_hours
FROM kyc_screening_results
WHERE result = 'potential_match' AND reviewed_by IS NULL
GROUP BY screen_type

-- False positive rate by screen type
SELECT screen_type,
  count(CASE WHEN review_decision = 'false_positive' THEN 1 END) as fp,
  count(CASE WHEN review_decision = 'true_match' THEN 1 END) as tm,
  round(100.0 * count(CASE WHEN review_decision = 'false_positive' THEN 1 END) / count(*), 1) as fp_pct
FROM kyc_screening_results
WHERE review_decision IS NOT NULL
  AND created_at > EXTRACT(EPOCH FROM now() - interval '30 days')
GROUP BY screen_type
```

---

## 11. Rollout Plan

### 11.1 Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_SCREENING_ENABLED` | `false` | Gates screening integration at submission |
| `KYC_SCREENING_CONTINUOUS_ENABLED` | `false` | Gates profile-change re-screening |
| `KYC_SCREENING_PROVIDER` | `mock` | Provider selection (`mock` / `production`) |

### 11.2 Migration Steps

| Step | Action | Duration | Rollback |
|------|--------|----------|----------|
| 1 | Deploy backend + create `kyc_screening_results` DDB table | 1 day | Delete table |
| 2 | Deploy screening service behind `KYC_SCREENING_ENABLED=false` | 1 day | Revert deploy |
| 3 | Enable on staging with mock provider; run E2E suite | 2 days | Set false |
| 4 | Enable in production with mock provider (shadow mode -- results stored but not blocking) | 1 week | Set false |
| 5 | Verify mock results quality; train admin team on review queue UI | 1 week | N/A |
| 6 | Switch to production provider (`KYC_SCREENING_PROVIDER=production`) | 1 day | Set `mock` |
| 7 | Shadow-compare: run both mock + production, compare results for 2 weeks | 2 weeks | Revert to mock-only |
| 8 | Enable blocking mode (matches prevent auto-approval) | 1 day | Disable blocking |
| 9 | Enable `KYC_SCREENING_CONTINUOUS_ENABLED` for profile-change re-screening | after 1 month | Set false |

### 11.3 Canary Criteria

- Mock provider produces deterministic results for all test patterns
- Production provider response time < 2s for 99th percentile
- False positive rate for production provider < 20% (validated by manual spot-check)
- No increase in case processing latency > 500ms at submission
- Admin review queue functional and accessible
- Zero data leakage (match details not exposed to non-admin users)

### 11.4 Rollback Procedure

1. Set `KYC_SCREENING_ENABLED=false` -- submission proceeds without screening
2. Existing screening results remain in DDB for audit trail (never deleted)
3. Pending review queue becomes empty (no new matches created)
4. Admin screening endpoints return empty results (safe degradation)
5. If production provider caused issues, revert `KYC_SCREENING_PROVIDER=mock`
6. Post-mortem before re-enabling

---

## 12. Performance Considerations

### 12.1 Screening Latency Budget

| Operation | Latency Target | DDB Cost | Notes |
|-----------|---------------|----------|-------|
| Screen case (5 types, mock) | < 200ms total | 5 WCU | Mock: in-process, no HTTP |
| Screen case (5 types, production) | < 3s total | 5 WCU | HTTP calls parallelized with `asyncio.gather()` |
| Single screen type (mock) | < 30ms | 1 WCU | In-memory name pattern matching |
| Single screen type (production) | < 2s | 1 WCU | External HTTP call + DDB write |
| Get screening results | < 100ms | 5 RCU | Query PK=case_id |
| Review match | < 150ms | 2 WCU | Conditional update + audit event |
| Pending reviews list | < 200ms | 10 RCU | GSI query, limit 50 |
| User history | < 200ms | 10 RCU | GSI query, limit 50 |

### 12.2 Submission Latency Impact

Screening adds latency to the submission flow. To minimize impact:
- Mock provider runs synchronously in-process (< 200ms total)
- Production provider runs all 5 types in parallel via `asyncio.gather()`
- If any provider call times out (> 5s), the result is stored as `provider_error` and flagged for manual review
- Submission succeeds even if screening fails (screening is fire-and-forget with error tracking)

### 12.3 Storage Growth

- 5 screening results per case submission = ~5KB per case
- Re-screening adds another 5 results per trigger = ~5KB per re-screen
- With 1000 submissions/month: ~5MB/month of screening data
- GSI `ByResult` for pending reviews: hot partition on `potential_match` -- expected to be small (< 100 pending at any time)
- Old results are never deleted (audit trail requirement)

### 12.4 Rate Limiting

| Endpoint | Rate Limit | Window | Notes |
|----------|-----------|--------|-------|
| GET screening results | 60 req/user/min | 1m | Standard read rate |
| POST review | 30 req/admin/min | 1m | Allows bulk review pace |
| POST rescreen | 5 req/admin/hour | 1h | Expensive operation |
| GET pending reviews | 30 req/admin/min | 1m | Polling frequency |
| GET user history | 30 req/admin/min | 1m | Standard admin read rate |

---

## 13. E2E Test Plan

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

## 14. Expanded E2E Test Details

### Section 170a: Screening Edge Cases (5 additional tests)

```typescript
test("170.6 Adverse media match triggered by name pattern", async () => {
  // Set display_name to "Media Flagged Reporter"
  // Submit case
  // Verify adverse_media result = "potential_match"
  // Verify match_score = 0.75
  // Verify other 4 screen types = "clear"
});

test("170.7 Screening results include provider field", async () => {
  // GET screening results for any submitted case
  // Verify all 5 results have provider = "mock_screening"
});

test("170.8 Each screening result has unique screening_id", async () => {
  // GET results
  // Verify all 5 screening_ids are distinct
  // Verify format matches "scr_" + 12 hex chars
});

test("170.9 Case owner sees summary but match_details redacted", async () => {
  // Create case with OFAC-triggering name, submit
  // GET screening results as Alice (owner, non-admin)
  // Verify result status is visible ("potential_match")
  // Verify match_details is empty or redacted for non-admin
});

test("170.10 Multiple trigger patterns combine correctly", async () => {
  // Set display_name to "OFAC Test PEP Official Combined"
  // Submit case
  // Verify sanctions_ofac = "potential_match" (matches "OFAC Test")
  // Verify pep_check = "potential_match" (matches "PEP Official")
  // Verify sanctions_eu, sanctions_un, adverse_media = "clear"
});
```

### Section 171a: Review Edge Cases (4 additional tests)

```typescript
test("171.6 Review with empty note rejected (422)", async () => {
  // POST review with note=""
  // Expect 422 validation_error
});

test("171.7 Review note exceeding 2000 chars rejected (422)", async () => {
  // POST review with note of 2001 characters
  // Expect 422 validation_error
});

test("171.8 Double-review returns 409", async () => {
  // Review a match as false_positive (succeeds)
  // Attempt to review same match again as true_match
  // Expect 409 "kyc_screening_already_reviewed"
});

test("171.9 Reviewing confirmed_match as false_positive is allowed", async () => {
  // Admin can override even confirmed matches (compliance decision)
  // POST review on confirmed_match with decision="false_positive"
  // Verify 200 success
  // Verify review_decision = "false_positive"
});
```

### Section 172a: Re-screening Edge Cases (4 additional tests)

```typescript
test("172.6 Re-screen preserves original screening results", async () => {
  // GET results after re-screen
  // Verify both original (trigger="submission") and new (trigger="manual") results
  // Count total results: should be 10 (5 original + 5 re-screen)
  // Verify distinct screen_key timestamps
});

test("172.7 Multiple re-screens accumulate in history", async () => {
  // Re-screen twice more
  // GET user history
  // Verify 3 sets of results (submission + manual + manual)
  // Total results = 15
});

test("172.8 Re-screen on non-existent case returns 404", async () => {
  // POST rescreen for "kyc_nonexistent_case"
  // Expect 404
});

test("172.9 Re-screen on draft case returns 400", async () => {
  // Create case but don't submit it
  // POST rescreen
  // Expect 400 "kyc_invalid_status"
});
```

### Section 173a: UI Edge Cases (3 additional tests)

```typescript
test("173.6 Bulk false-positive review updates all selected rows", async ({ page }) => {
  // Select 3 pending review rows via checkboxes
  // Click "Mark All as False Positive"
  // Verify all 3 rows show "Reviewed - False Positive"
  // Verify pending count decreases by 3
});

test("173.7 Screening queue pagination loads more items", async ({ page }) => {
  // If > 20 pending reviews, verify "Load More" button appears
  // Click "Load More"
  // Verify additional rows are appended to the table
});

test("173.8 Filter by screen type updates table rows", async ({ page }) => {
  // Select "OFAC" in filter dropdown
  // Verify only sanctions_ofac rows visible
  // Select "All"
  // Verify all types visible again
});
```

---

## 15. File Change Summary

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
| `frontend/e2e/kyc-screening.spec.ts` | **New** | 20+ E2E tests across sections 170-173 |

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | all | VERIFIED (1294 lines) |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| `_admin_decide_case()` | `app/routers/kyc_cases.py` | 1099 | VERIFIED |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines) |
| `create_case()` | `app/services/kyc_cases.py` | 97 | VERIFIED |
| `apply_admin_decision()` | `app/services/kyc_cases.py` | 534 | VERIFIED |
| `_risk()` function | `app/services/kyc_cases.py` | 664 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| `write_alert()` | `app/services/alerts.py` | 355 | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `app/services/kyc_screening.py` | `app/services/` | NOT FOUND -- new service required |
| `kyc_screening_results` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| `kyc_screening_results` table handle | `app/core/tables.py` | NOT FOUND -- new handle required |
| Screening settings (table name, provider) | `app/core/settings.py` | NOT FOUND -- new settings required |
| 5 screening endpoints in KYC router | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoints required |
| Screening review request/response models | `app/contracts/kyc_cases_contract.py` | NOT FOUND -- new models required |
| `frontend/src/pages/admin/KycScreeningQueuePage.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |
| `/admin/kyc/screening` route | `frontend/src/App.tsx` | NOT FOUND -- new route required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_screening.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_screen_against_sanctions_list`
  - `test_screen_against_pep_list`
  - `test_fuzzy_name_matching`
  - `test_screen_result_match_found`
  - `test_screen_result_no_match`
  - `test_periodic_rescreening`
  - `test_false_positive_dismissal`
  - `test_screening_audit_trail`

### Integration Tests

  - New user registration triggers automatic screening
  - Screening match flags user for admin review
  - Dismissed false positive does not re-trigger on rescan
  - Screening results stored with match confidence score

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-screening.spec.ts`
**Test count**: 12

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

- **DDB seeds**: Seed `kyc_screening_results` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_SCREENING_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Screening results reviewed through dashboard |
| KYC-002 | Identity Document Verification | Extracted name/DOB from documents used for screening |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-008 | Risk Scoring Engine | Screening results feed risk score |
| KYC-012 | Compliance Reporting | Screening results included in compliance reports |
| KYC-015 | Business/Corporate KYB | Business entity screening uses same engine |

### Merge Strategy

**Sequential**

Merge after KYC-001, KYC-002. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 12 E2E tests pass with `npx playwright test kyc-screening.spec.ts`
