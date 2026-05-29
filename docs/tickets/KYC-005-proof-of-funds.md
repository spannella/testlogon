# KYC-005: Proof of Funds / Source of Funds

**Ticket**: KYC-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days
**Dependencies**: KYC-001 (Admin Review Dashboard)

---

## 1. Overview & Motivation

### Problem Statement

The existing KYC system verifies identity (selfie, ID documents) and optionally residency
(proof of address), but has **no mechanism for financial verification**. Anti-money laundering
(AML) regulations require platforms handling financial transactions to collect information
about the **source of funds** -- where a user's money comes from -- and in higher-risk
scenarios, **proof of funds** -- evidence that the user has the funds they claim.

The platform already has a questionnaire system (`app/services/questionnaires_repository.py`)
integrated with KYC cases. This ticket extends the KYC flow with a dedicated source-of-funds
questionnaire, financial document uploads with structured metadata, and risk scoring based
on the responses.

### Goals

1. Define accepted financial document types (bank statement, investment account, tax return, etc.).
2. Create a source-of-funds questionnaire template linked to the KYC case.
3. Capture: primary income source, annual income range, expected transaction volume.
4. Auto-flag high-risk responses (large volumes, high-risk income sources).
5. Add a `source_of_funds` nested object to the KYC case.
6. Allow admins to request additional financial documentation from the admin dashboard.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Applicant | Answer questions about my income source and expected usage | I can complete my KYC application |
| 2 | Applicant | Upload financial documents (bank statement, tax return) | I can prove my source of funds |
| 3 | KYC reviewer | See source-of-funds responses alongside financial documents | I can assess financial risk |
| 4 | KYC reviewer | See auto-flagged high-risk responses highlighted | I can prioritize review |
| 5 | Compliance lead | Require source-of-funds for high-risk intake profiles | Enhanced due diligence is enforced |
| 6 | KYC reviewer | Request additional financial documents from the applicant | I can get missing evidence |

---

## 2. Current State Analysis

### 2.1 Existing Questionnaire Integration

The KYC case has a `questionnaire` nested object:
```python
{
    "questionnaire_id": "...",
    "version_id": "...",
    "response_session_id": "...",
    "response_pdf_ref": "..."
}
```

`start_kyc_questionnaire()` (line 625 of `app/routers/kyc_cases.py`) creates a questionnaire
response session linked to the case via `POST /v1/kyc/cases/{id}/questionnaire/start`.
The questionnaire system (`app/services/questionnaires_repository.py`,
`DynamoQuestionnaireRepository`) supports arbitrary question sets with response tracking.

### 2.2 Current File Types

`_KYC_ALLOWED_FILE_TYPES` = `{"selfie", "id_front", "id_back", "proof_of_address"}`.
Financial documents are not currently in this set. This ticket adds new allowed types.

### 2.3 KYC Case Readiness

`_readiness_for_case()` (line 223) checks three requirements: `questionnaire_submitted`,
`required_files`, `signature_completed`. Source-of-funds will add a fourth requirement for
enhanced/high_risk profiles.

---

## 3. Technical Design

### 3.1 Financial Document Types

```python
FINANCIAL_DOC_TYPES = {
    "bank_statement",           # 3+ months of bank account statements
    "investment_account",       # Brokerage/investment account summary
    "crypto_wallet_proof",      # Wallet balance screenshot or exchange statement
    "employment_letter",        # Letter from employer confirming role and salary
    "tax_return",               # Annual tax return filing
}
```

Extend `_KYC_ALLOWED_FILE_TYPES`:
```python
_KYC_ALLOWED_FILE_TYPES = set(
    _KYC_REQUIRED_FILE_TYPES
    + ["proof_of_address"]
    + list(FINANCIAL_DOC_TYPES)
)
```

### 3.2 Source of Funds Case Field

New nested object on the KYC case:

```python
{
    "source_of_funds": {
        "questionnaire_id": "sof_q_abc123",
        "response_session_id": "sof_rs_def456",
        "response_pdf_ref": "...",
        "submitted": false,
        "documents": [
            {
                "type": "bank_statement",
                "path": "/uploads/kyc/alice_bank_stmt.pdf",
                "document_date": "2026-04-01",
                "period_months": 3,
                "issuing_entity": "Chase Bank",
                "attached_at": 1716681600,
            }
        ],
        "risk_flags": [],
        "risk_score_contribution": 0,
        "admin_requested_additional": false,
        "admin_request_note": null,
    }
}
```

### 3.3 Source-of-Funds Questionnaire Template

The questionnaire is created programmatically via `DynamoQuestionnaireRepository` when the
user starts the source-of-funds section. Questions:

```python
SOF_QUESTIONS = [
    {
        "id": "primary_income_source",
        "type": "single_choice",
        "text": "What is your primary source of income?",
        "choices": [
            "employment_salary",
            "self_employment",
            "investments",
            "inheritance",
            "pension_retirement",
            "government_benefits",
            "crypto_trading",
            "rental_income",
            "other",
        ],
    },
    {
        "id": "annual_income_range",
        "type": "single_choice",
        "text": "What is your estimated annual income range?",
        "choices": [
            "under_25k",
            "25k_50k",
            "50k_100k",
            "100k_250k",
            "250k_500k",
            "over_500k",
        ],
    },
    {
        "id": "expected_monthly_volume",
        "type": "single_choice",
        "text": "What is your expected monthly transaction volume on this platform?",
        "choices": [
            "under_500",
            "500_2000",
            "2000_5000",
            "5000_10000",
            "over_10000",
        ],
    },
    {
        "id": "funds_origin_description",
        "type": "text",
        "text": "Please briefly describe the origin of funds you intend to use on this platform.",
        "max_length": 1000,
    },
]
```

### 3.4 Risk Flag Logic

Automatic risk flags applied based on questionnaire responses:

| Response | Flag | Risk Weight |
|----------|------|-------------|
| `primary_income_source = "crypto_trading"` | `high_risk_income_source` | +20 |
| `primary_income_source = "other"` | `unspecified_income_source` | +15 |
| `annual_income_range = "over_500k"` | `high_income` | +10 |
| `expected_monthly_volume = "over_10000"` | `high_volume` | +25 |
| `expected_monthly_volume = "5000_10000"` | `elevated_volume` | +10 |
| Volume/income mismatch (high volume + low income) | `volume_income_mismatch` | +30 |

Flags are stored in `source_of_funds.risk_flags[]` and the total weight contributes to
the KYC-008 risk scoring engine.

### 3.5 New Router Endpoints

**File: `app/routers/kyc_cases.py`** -- add endpoints:

```python
@router.post("/{case_id}/source-of-funds/start")
def start_source_of_funds(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Initialize the source-of-funds questionnaire for a KYC case.
    Creates a questionnaire + response session using the SOF template."""

@router.get("/{case_id}/source-of-funds")
def get_source_of_funds_status(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get source-of-funds status including questionnaire completion and documents."""

@router.post("/{case_id}/source-of-funds/documents")
def attach_financial_document(
    case_id: str,
    body: KycFinancialDocAttachRequest,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Attach a financial document to the source-of-funds section."""

@router.post("/admin/cases/{case_id}/request-financial-docs")
def admin_request_financial_docs(
    case_id: str,
    body: KycAdminRequestFinancialDocsRequest,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Admin requests additional financial documentation from the applicant.
    Sets admin_requested_additional=true and sends notification."""
```

### 3.6 Request Models

**File: `app/contracts/kyc_cases_contract.py`** -- add:

```python
class KycFinancialDocAttachRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    path: str = Field(..., min_length=1, max_length=1024)
    document_type: Literal[
        "bank_statement", "investment_account", "crypto_wallet_proof",
        "employment_letter", "tax_return"
    ]
    issuing_entity: str = Field(..., min_length=1, max_length=200)
    document_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    period_months: int | None = Field(default=None, ge=1, le=24)

class KycAdminRequestFinancialDocsRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    requested_document_types: list[str] = Field(default_factory=list)
    note: str = Field(..., min_length=1, max_length=2000)
```

### 3.7 Readiness Gate Update

For `intake_profile in ("enhanced", "high_risk")`, add source-of-funds to readiness:

```python
checks["source_of_funds"] = bool(
    sof.get("submitted")
    and len(sof.get("documents") or []) >= 1
)
```

### 3.8 Frontend Changes

**File: `frontend/src/pages/kyc/KycCaseForm.tsx`** -- extend:

Add "Source of Funds" accordion section:
- "Start Questionnaire" button (calls `start_source_of_funds`)
- Embedded questionnaire form (inline rendering of SOF questions)
- Financial document upload area (document type dropdown, date picker, file upload)
- List of attached financial documents with type badge and remove button
- Risk flags display (yellow/red warning badges)

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add "Financial Verification" tab:
- Questionnaire responses displayed as read-only form
- Financial documents list with metadata
- Risk flags highlighted with colored badges
- "Request Additional Documents" button opening dialog

---

## 4. E2E Test Plan

**File**: `frontend/e2e/kyc-source-of-funds.spec.ts`
**Total**: ~15 tests across 3 sections (167-169)

### Section 167: Source-of-Funds Questionnaire API (5 tests)

```typescript
test("167.1 Start source-of-funds creates questionnaire session", async () => {
  // POST /v1/kyc/cases/{id}/source-of-funds/start
  // Verify 200, questionnaire_id and response_session_id returned
});

test("167.2 Get source-of-funds status shows unsubmitted questionnaire", async () => {
  // GET /v1/kyc/cases/{id}/source-of-funds
  // Verify submitted=false, questionnaire_id present
});

test("167.3 Submit questionnaire responses updates source-of-funds status", async () => {
  // Submit questionnaire via questionnaire API
  // GET source-of-funds status
  // Verify submitted=true
});

test("167.4 High-risk responses generate risk flags", async () => {
  // Submit with primary_income_source="crypto_trading", expected_monthly_volume="over_10000"
  // GET source-of-funds status
  // Verify risk_flags includes "high_risk_income_source" and "high_volume"
});

test("167.5 Volume-income mismatch flag triggered", async () => {
  // Submit with annual_income_range="under_25k", expected_monthly_volume="over_10000"
  // Verify risk_flags includes "volume_income_mismatch"
});
```

### Section 168: Financial Document Attachment API (5 tests)

```typescript
test("168.1 Attach bank statement with metadata", async () => {
  // POST /v1/kyc/cases/{id}/source-of-funds/documents
  // { document_type: "bank_statement", issuing_entity: "Chase",
  //   document_date: "2026-04-01", period_months: 3, path: "..." }
  // Verify 200, document added to source_of_funds.documents
});

test("168.2 Attach investment account statement", async () => {
  // { document_type: "investment_account", ... }
  // Verify documents array has 2 entries
});

test("168.3 Invalid document_type rejected", async () => {
  // { document_type: "payslip" }
  // Expect 422
});

test("168.4 Admin requests additional financial docs", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/request-financial-docs as Root
  // { requested_document_types: ["tax_return"], note: "Need tax filing" }
  // Verify admin_requested_additional=true
});

test("168.5 Non-owner cannot attach financial documents", async () => {
  // Bob tries to attach doc to Alice's case
  // Expect 403
});
```

### Section 169: Source-of-Funds Readiness Gate (5 tests)

```typescript
test("169.1 Standard profile does not require source of funds", async () => {
  // intake_profile="standard"
  // GET readiness -- no source_of_funds in checks
});

test("169.2 Enhanced profile requires source of funds", async () => {
  // intake_profile="enhanced", no SOF
  // GET readiness -- missing source_of_funds
});

test("169.3 Enhanced profile with submitted questionnaire but no docs fails", async () => {
  // Submit SOF questionnaire but no financial documents
  // GET readiness -- source_of_funds still missing
});

test("169.4 Enhanced profile with questionnaire + 1 doc passes gate", async () => {
  // Submit SOF questionnaire + attach 1 bank statement
  // GET readiness -- source_of_funds check passes
});

test("169.5 Risk flags do not block submission but are visible", async () => {
  // High-risk responses + valid docs
  // GET readiness -- ready_to_submit=true
  // Verify risk_flags are present for admin visibility
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/routers/kyc_cases.py` | Modify | Add 4 source-of-funds endpoints; update readiness gate |
| `app/services/kyc_cases.py` | Modify | Add source_of_funds field handling; risk flag computation |
| `app/contracts/kyc_cases_contract.py` | Modify | Add financial doc request models; SOF status response |
| `frontend/src/pages/kyc/KycCaseForm.tsx` | Modify | Add Source of Funds section with questionnaire and uploads |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add Financial Verification tab |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add source-of-funds API functions |
| `frontend/e2e/kyc-source-of-funds.spec.ts` | **New** | 15 E2E tests across sections 167-169 |
