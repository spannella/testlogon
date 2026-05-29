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

The platform already has a questionnaire system (see `app/services/questionnaires_repository.py:38` for `DynamoQuestionnaireRepository`)
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

## 2. Architecture Diagram

```
+-------------------------------------------------------------------+
|                         Frontend (React)                          |
|                                                                   |
|  KycCaseForm.tsx          KycCaseDetailPage.tsx (Admin)           |
|  +---------------------+ +------------------------------------+  |
|  | SofQuestionnairePanel| | FinancialVerificationTab           |  |
|  | - Start button       | | - Questionnaire responses (RO)    |  |
|  | - Inline questions   | | - Document list + metadata         |  |
|  | - Submit handler     | | - Risk flags (color-coded)         |  |
|  +---------------------+ | - "Request Docs" dialog            |  |
|  | FinancialDocUpload   | +------------------------------------+  |
|  | - Type dropdown      |                                        |
|  | - Date picker        |                                        |
|  | - Entity input       |                                        |
|  | - File picker        |                                        |
|  | - Doc list + delete  |                                        |
|  +---------------------+                                         |
+----------------------|------------|-------------------------------+
                       |            |
              POST/GET |            | POST/GET
                       v            v
+-------------------------------------------------------------------+
|                    FastAPI Backend (8000)                         |
|                                                                   |
|  kyc_cases.py Router                                              |
|  +-------------------------------------------------------------+ |
|  | POST /{id}/source-of-funds/start                             | |
|  |   -> create questionnaire + response session                 | |
|  | GET  /{id}/source-of-funds                                   | |
|  |   -> return status, docs, risk_flags                         | |
|  | POST /{id}/source-of-funds/documents                         | |
|  |   -> attach financial doc with metadata                      | |
|  | POST /admin/cases/{id}/request-financial-docs                | |
|  |   -> admin marks additional docs needed + sends notification | |
|  +-------------------------------------------------------------+ |
|                                                                   |
|  kyc_cases.py Service Layer                                       |
|  +-------------------------------------------------------------+ |
|  | start_sof()         -> init questionnaire, link to case      | |
|  | get_sof_status()    -> return nested source_of_funds object  | |
|  | attach_fin_doc()    -> append to documents[], validate type  | |
|  | compute_risk_flags()-> evaluate responses, return flags[]    | |
|  | update_readiness()  -> add source_of_funds gate for enhanced | |
|  +-------------------------------------------------------------+ |
|                       |                                           |
+-------------------------------------------------------------------+
                       |
          +------------+------------+
          |                         |
          v                         v
+-------------------+    +-------------------+
|   DynamoDB        |    |       S3          |
|                   |    |                   |
| kyc_cases table   |    | kyc-uploads/      |
| PK: CASE#{id}    |    |   {tenant}/       |
| SK: META          |    |     {case_id}/    |
|  .source_of_funds |    |       bank_*.pdf  |
|  .questionnaire   |    |       invest_*.pdf|
|  .risk_flags      |    |       tax_*.pdf   |
|                   |    |                   |
| questionnaires    |    +-------------------+
|   table           |
| PK: Q#{q_id}     |
| SK: RESP#{sess}   |
+-------------------+
```

**Data flow -- start source-of-funds:**

```
User clicks "Start" -> POST /source-of-funds/start
  -> Service creates questionnaire via DynamoQuestionnaireRepository
  -> Stores questionnaire_id + response_session_id in case.source_of_funds
  -> Returns { questionnaire_id, response_session_id, questions }
```

**Data flow -- submit + risk evaluation:**

```
User submits answers -> POST /questionnaires/{q_id}/responses/{sess}/submit
  -> Questionnaire service marks submitted
  -> KYC service triggers compute_risk_flags(case_id)
    -> Reads questionnaire responses
    -> Evaluates 6 risk rules (see section 4.4)
    -> Writes risk_flags[] + risk_score_contribution to case
    -> Updates readiness gate
```

**Data flow -- admin request additional docs:**

```
Admin clicks "Request Docs" -> POST /admin/cases/{id}/request-financial-docs
  -> Sets admin_requested_additional = true
  -> Writes admin_request_note + requested_document_types
  -> Queues notification to applicant (KYC-011 webhook/notification)
  -> Case status stays in_review (does not revert)
```

---

## 3. Current State Analysis

### 3.1 Existing Questionnaire Integration

The KYC case has a `questionnaire` nested object:
```python
{
    "questionnaire_id": "...",
    "version_id": "...",
    "response_session_id": "...",
    "response_pdf_ref": "..."
}
```

`start_kyc_questionnaire()` (see `app/routers/kyc_cases.py:625`) creates a questionnaire
response session linked to the case via `POST /v1/kyc/cases/{id}/questionnaire/start`.
The questionnaire system (see `app/services/questionnaires_repository.py:38`,
`DynamoQuestionnaireRepository`) supports arbitrary question sets with response tracking.

### 3.2 Current File Types

`_KYC_ALLOWED_FILE_TYPES` (see `app/routers/kyc_cases.py:51`) = `{"selfie", "id_front", "id_back", "proof_of_address"}`.
Financial documents are not currently in this set. This ticket adds new allowed types.

### 3.3 KYC Case Readiness

`_readiness_for_case()` (see `app/routers/kyc_cases.py:223`) checks three requirements: `questionnaire_submitted`,
`required_files`, `signature_completed`. Source-of-funds will add a fourth requirement for
enhanced/high_risk profiles.

---

## 4. Technical Design

### 4.1 Financial Document Types

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

### 4.2 Source of Funds Case Field

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

### 4.3 Source-of-Funds Questionnaire Template

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

### 4.4 Risk Flag Logic

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

Volume/income mismatch is defined as: `expected_monthly_volume in ("5000_10000", "over_10000")`
AND `annual_income_range in ("under_25k", "25k_50k")`. This catches users who declare low
income but high expected platform transaction volume -- a potential money laundering indicator.

### 4.5 New Router Endpoints

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

### 4.6 Readiness Gate Update

For `intake_profile in ("enhanced", "high_risk")`, add source-of-funds to readiness:

```python
checks["source_of_funds"] = bool(
    sof.get("submitted")
    and len(sof.get("documents") or []) >= 1
)
```

### 4.7 Frontend Changes

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

## 5. DynamoDB Access Patterns

### 5.1 KYC Cases Table -- Source of Funds Fields

The source-of-funds data is stored as a nested map within the existing KYC case item:

| Access Pattern | Table | PK | SK | Attributes |
|---------------|-------|----|----|-----------|
| Get case with SOF | kyc_cases | `CASE#{case_id}` | `META` | `source_of_funds` (map) |
| List cases needing SOF review | kyc_cases | GSI: `STATUS_IDX` PK=`STATUS#in_review` | SK=`{created_at}` | Filter: `source_of_funds.risk_flags` not empty |
| List flagged cases | kyc_cases | GSI: `RISK_IDX` PK=`RISK#flagged` | SK=`{risk_score}` | Sorted by risk score descending |

### 5.2 Example DynamoDB Item (Source of Funds Section)

```json
{
  "pk": { "S": "CASE#case_abc123" },
  "sk": { "S": "META" },
  "tenant_id": { "S": "tenant-a" },
  "user_sub": { "S": "alice-sub-001" },
  "status": { "S": "in_review" },
  "intake_profile": { "S": "enhanced" },
  "version": { "N": "5" },
  "source_of_funds": {
    "M": {
      "questionnaire_id": { "S": "sof_q_abc123" },
      "response_session_id": { "S": "sof_rs_def456" },
      "response_pdf_ref": { "S": "kyc-uploads/tenant-a/case_abc123/sof_responses.pdf" },
      "submitted": { "BOOL": true },
      "documents": {
        "L": [
          {
            "M": {
              "type": { "S": "bank_statement" },
              "path": { "S": "kyc-uploads/tenant-a/case_abc123/chase_stmt_q1_2026.pdf" },
              "document_date": { "S": "2026-04-01" },
              "period_months": { "N": "3" },
              "issuing_entity": { "S": "Chase Bank" },
              "attached_at": { "N": "1716681600" }
            }
          },
          {
            "M": {
              "type": { "S": "tax_return" },
              "path": { "S": "kyc-uploads/tenant-a/case_abc123/2025_tax_return.pdf" },
              "document_date": { "S": "2025-12-31" },
              "period_months": { "N": "12" },
              "issuing_entity": { "S": "IRS" },
              "attached_at": { "N": "1716685200" }
            }
          }
        ]
      },
      "risk_flags": {
        "L": [
          { "S": "high_risk_income_source" },
          { "S": "high_volume" }
        ]
      },
      "risk_score_contribution": { "N": "45" },
      "admin_requested_additional": { "BOOL": false },
      "admin_request_note": { "NULL": true }
    }
  }
}
```

### 5.3 Questionnaire Table -- SOF Session

```json
{
  "pk": { "S": "Q#sof_q_abc123" },
  "sk": { "S": "RESP#sof_rs_def456" },
  "questionnaire_id": { "S": "sof_q_abc123" },
  "session_id": { "S": "sof_rs_def456" },
  "user_sub": { "S": "alice-sub-001" },
  "submitted": { "BOOL": true },
  "submitted_at": { "N": "1716682800" },
  "answers": {
    "M": {
      "primary_income_source": { "S": "crypto_trading" },
      "annual_income_range": { "S": "100k_250k" },
      "expected_monthly_volume": { "S": "over_10000" },
      "funds_origin_description": { "S": "Proceeds from cryptocurrency trading on Binance and Coinbase." }
    }
  }
}
```

### 5.4 Write Patterns

| Operation | Condition Expression | Notes |
|-----------|---------------------|-------|
| Start SOF | `attribute_not_exists(source_of_funds.questionnaire_id)` | Prevents duplicate start |
| Attach doc | `version = :expected_version` | OCC prevents concurrent attachment |
| Admin request docs | `version = :expected_version AND attribute_exists(source_of_funds)` | Requires SOF already started |
| Submit questionnaire | `submitted = :false` | Prevents double-submit |

### 5.5 Update Expressions

**Attach document:**
```
UpdateExpression: SET source_of_funds.documents = list_append(
    if_not_exists(source_of_funds.documents, :empty_list), :new_doc
  ), version = version + :one
ConditionExpression: version = :expected_version
  AND attribute_exists(source_of_funds)
  AND size(source_of_funds.documents) < :max_docs
```

**Set risk flags after submission:**
```
UpdateExpression: SET
  source_of_funds.risk_flags = :flags,
  source_of_funds.risk_score_contribution = :score,
  source_of_funds.submitted = :true,
  version = version + :one
ConditionExpression: version = :expected_version
```

**Admin request additional docs:**
```
UpdateExpression: SET
  source_of_funds.admin_requested_additional = :true,
  source_of_funds.admin_request_note = :note,
  source_of_funds.requested_document_types = :types,
  version = version + :one
ConditionExpression: version = :expected_version
  AND attribute_exists(source_of_funds)
```

---

## 6. API Request/Response Examples

### 6.1 Start Source of Funds Questionnaire

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/source-of-funds/start" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{ "expected_version": 2 }'
```

**Response (200):**
```json
{
  "ok": true,
  "questionnaire_id": "sof_q_abc12345",
  "response_session_id": "sof_rs_def67890",
  "questions": [
    {
      "id": "primary_income_source",
      "type": "single_choice",
      "text": "What is your primary source of income?",
      "choices": ["employment_salary", "self_employment", "investments", "inheritance",
                  "pension_retirement", "government_benefits", "crypto_trading",
                  "rental_income", "other"]
    },
    {
      "id": "annual_income_range",
      "type": "single_choice",
      "text": "What is your estimated annual income range?",
      "choices": ["under_25k", "25k_50k", "50k_100k", "100k_250k", "250k_500k", "over_500k"]
    },
    {
      "id": "expected_monthly_volume",
      "type": "single_choice",
      "text": "What is your expected monthly transaction volume on this platform?",
      "choices": ["under_500", "500_2000", "2000_5000", "5000_10000", "over_10000"]
    },
    {
      "id": "funds_origin_description",
      "type": "text",
      "text": "Please briefly describe the origin of funds you intend to use on this platform.",
      "max_length": 1000
    }
  ]
}
```

### 6.2 Get Source of Funds Status

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/source-of-funds" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "questionnaire_id": "sof_q_abc12345",
  "response_session_id": "sof_rs_def67890",
  "submitted": true,
  "responses": {
    "primary_income_source": "crypto_trading",
    "annual_income_range": "under_25k",
    "expected_monthly_volume": "over_10000",
    "funds_origin_description": "Cryptocurrency trading profits"
  },
  "documents": [
    {
      "type": "bank_statement",
      "path": "/uploads/kyc/alice_bank_stmt.pdf",
      "document_date": "2026-04-01",
      "period_months": 3,
      "issuing_entity": "Chase Bank",
      "attached_at": 1716681600
    }
  ],
  "risk_flags": ["high_risk_income_source", "high_volume", "volume_income_mismatch"],
  "risk_score_contribution": 75,
  "admin_requested_additional": false,
  "admin_request_note": null
}
```

### 6.3 Attach Financial Document

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/source-of-funds/documents" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 3,
    "path": "/uploads/kyc/alice_investment_acct.pdf",
    "document_type": "investment_account",
    "issuing_entity": "Fidelity Investments",
    "document_date": "2026-05-01",
    "period_months": null
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "document_index": 1,
  "document": {
    "type": "investment_account",
    "path": "/uploads/kyc/alice_investment_acct.pdf",
    "document_date": "2026-05-01",
    "period_months": null,
    "issuing_entity": "Fidelity Investments",
    "attached_at": 1716768000
  }
}
```

### 6.4 Admin Request Additional Financial Docs

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/request-financial-docs" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 4,
    "requested_document_types": ["tax_return", "employment_letter"],
    "note": "Please provide your most recent tax filing and an employment verification letter."
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "admin_requested_additional": true,
  "requested_document_types": ["tax_return", "employment_letter"],
  "note": "Please provide your most recent tax filing and an employment verification letter."
}
```

### 6.5 Duplicate Start SOF (409)

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/source-of-funds/start" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{ "expected_version": 3 }'
```

**Response (409):**
```json
{
  "detail": "Source of funds questionnaire already started for this case.",
  "error_code": "kyc_sof_already_started",
  "existing_questionnaire_id": "sof_q_abc12345"
}
```

### 6.6 Version Conflict on Document Attach (409)

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/source-of-funds/documents" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 2,
    "path": "/uploads/kyc/alice_tax_return.pdf",
    "document_type": "tax_return",
    "issuing_entity": "IRS",
    "document_date": "2025-12-31",
    "period_months": 12
  }'
```

**Response (409):**
```json
{
  "detail": "Case was modified. Please refresh and retry.",
  "error_code": "kyc_case_update_conflict",
  "current_version": 5
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|----------------|
| 1 | Start SOF on non-existent case | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| 2 | Start SOF on already-started case | 409 | `kyc_sof_already_started` | "Source of funds questionnaire already started." | Use existing session |
| 3 | Start SOF when case not in draft/pending | 400 | `kyc_invalid_status` | "SOF can only be started on draft or pending cases." | Check case status |
| 4 | Start SOF on another user's case | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| 5 | Attach doc with invalid document_type | 422 | `validation_error` | "document_type must be one of: bank_statement, investment_account, crypto_wallet_proof, employment_letter, tax_return." | Select valid type |
| 6 | Attach doc with invalid date format | 422 | `validation_error` | "document_date must be in YYYY-MM-DD format." | Fix date format |
| 7 | Attach doc to case not owned by user | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| 8 | Attach doc with wrong expected_version | 409 | `kyc_case_update_conflict` | "Case was modified. Please refresh." | Reload case, get new version |
| 9 | Attach doc exceeding 5-document limit | 400 | `kyc_max_documents_exceeded` | "Maximum 5 financial documents allowed per case." | Remove a doc first |
| 10 | Attach doc before SOF is started | 400 | `kyc_sof_not_started` | "Start the source-of-funds questionnaire before attaching documents." | Call POST /start first |
| 11 | Non-admin requests additional docs | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| 12 | Request docs on non-existent case | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| 13 | period_months out of range (0 or >24) | 422 | `validation_error` | "period_months must be between 1 and 24." | Use valid range |
| 14 | Attach doc to finalized (approved/rejected) case | 400 | `kyc_case_finalized` | "Cannot modify source-of-funds for a finalized case." | No action |
| 15 | path field empty or exceeds 1024 chars | 422 | `validation_error` | "path must be between 1 and 1024 characters." | Fix path |
| 16 | issuing_entity empty or exceeds 200 chars | 422 | `validation_error` | "issuing_entity must be between 1 and 200 characters." | Fix entity name |

---

## 8. Pydantic Models

### 8.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class KycFinancialDocAttachRequest(BaseModel):
    """Request to attach a financial document to a KYC case's source-of-funds section."""

    expected_version: int = Field(
        ...,
        ge=1,
        description="Current case version for OCC. Obtain from GET /source-of-funds.",
        examples=[4],
    )
    path: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="S3 path to the uploaded financial document.",
        examples=["kyc-uploads/tenant-a/case_abc123/chase_stmt_q1_2026.pdf"],
    )
    document_type: Literal[
        "bank_statement",
        "investment_account",
        "crypto_wallet_proof",
        "employment_letter",
        "tax_return",
    ] = Field(
        ...,
        description="Type of financial document being attached.",
        examples=["bank_statement"],
    )
    issuing_entity: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Name of the entity that issued the document.",
        examples=["Chase Bank"],
    )
    document_date: str = Field(
        ...,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Date on the document (YYYY-MM-DD).",
        examples=["2026-04-01"],
    )
    period_months: int | None = Field(
        default=None,
        ge=1,
        le=24,
        description="Number of months the document covers (e.g. 3 for quarterly statement).",
        examples=[3],
    )


class KycAdminRequestFinancialDocsRequest(BaseModel):
    """Admin request for additional financial documents from the applicant."""

    expected_version: int = Field(
        ...,
        ge=1,
        description="Current case version for OCC.",
        examples=[5],
    )
    requested_document_types: list[Literal[
        "bank_statement",
        "investment_account",
        "crypto_wallet_proof",
        "employment_letter",
        "tax_return",
    ]] = Field(
        default_factory=list,
        description="Types of documents the admin is requesting.",
        examples=[["tax_return", "employment_letter"]],
    )
    note: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Note to the applicant explaining what is needed.",
        examples=["Please provide your most recent tax return filing."],
    )


class KycStartSofRequest(BaseModel):
    """Request to start the source-of-funds questionnaire."""

    expected_version: int = Field(
        ...,
        ge=1,
        description="Current case version for OCC.",
        examples=[2],
    )
```

### 8.2 Response Models

```python
class FinancialDocumentOut(BaseModel):
    """A financial document attached to a source-of-funds section."""

    type: str = Field(..., description="Document type.")
    path: str = Field(..., description="S3 path to document.")
    document_date: str = Field(..., description="Date on the document (YYYY-MM-DD).")
    period_months: int | None = Field(None, description="Coverage period in months.")
    issuing_entity: str = Field(..., description="Issuing entity name.")
    attached_at: int = Field(..., description="Unix timestamp of attachment.")


class SourceOfFundsStatusOut(BaseModel):
    """Full status of the source-of-funds section for a KYC case."""

    questionnaire_id: str | None = Field(None, description="SOF questionnaire ID.")
    response_session_id: str | None = Field(None, description="Questionnaire response session ID.")
    submitted: bool = Field(False, description="Whether the questionnaire has been submitted.")
    responses: dict | None = Field(None, description="Submitted questionnaire answers (if submitted).")
    documents: list[FinancialDocumentOut] = Field(
        default_factory=list,
        description="Attached financial documents.",
    )
    risk_flags: list[str] = Field(
        default_factory=list,
        description="Auto-detected risk flags from responses.",
    )
    risk_score_contribution: int = Field(
        0,
        description="Sum of risk flag weights contributed to case risk score.",
    )
    admin_requested_additional: bool = Field(
        False,
        description="Whether an admin has requested additional documents.",
    )
    admin_request_note: str | None = Field(
        None,
        description="Note from admin about what additional documents are needed.",
    )
    requested_document_types: list[str] = Field(
        default_factory=list,
        description="Document types requested by admin.",
    )


class SofStartOut(BaseModel):
    """Response from starting the source-of-funds questionnaire."""

    ok: bool = True
    questionnaire_id: str
    response_session_id: str
    questions: list[dict]


class SofDocAttachOut(BaseModel):
    """Response from attaching a financial document."""

    ok: bool = True
    document_index: int = Field(..., description="Index of the newly attached document in the documents array.")
    document: FinancialDocumentOut


class SofAdminRequestOut(BaseModel):
    """Response from admin requesting additional financial documents."""

    ok: bool = True
    admin_requested_additional: bool
    requested_document_types: list[str]
    note: str
```

### 8.3 Risk Flag Internal Model

```python
from dataclasses import dataclass


@dataclass
class RiskFlagRule:
    """Definition of an automatic risk flag rule."""
    question_id: str
    trigger_value: str | None  # None = computed rule (e.g. mismatch)
    flag_name: str
    weight: int
    description: str


RISK_FLAG_RULES = [
    RiskFlagRule("primary_income_source", "crypto_trading", "high_risk_income_source", 20,
                 "Primary income from cryptocurrency trading"),
    RiskFlagRule("primary_income_source", "other", "unspecified_income_source", 15,
                 "Primary income source is unspecified/other"),
    RiskFlagRule("annual_income_range", "over_500k", "high_income", 10,
                 "Declared annual income over $500k"),
    RiskFlagRule("expected_monthly_volume", "over_10000", "high_volume", 25,
                 "Expected monthly volume over $10,000"),
    RiskFlagRule("expected_monthly_volume", "5000_10000", "elevated_volume", 10,
                 "Expected monthly volume $5,000-$10,000"),
]

# Volume-income mismatch is a computed rule (not in RISK_FLAG_RULES)
VOLUME_INCOME_MISMATCH_LOW_INCOME = {"under_25k", "25k_50k"}
VOLUME_INCOME_MISMATCH_HIGH_VOLUME = {"5000_10000", "over_10000"}
VOLUME_INCOME_MISMATCH_WEIGHT = 30


def compute_sof_risk_flags(answers: dict) -> tuple[list[str], int]:
    """Evaluate questionnaire answers against risk flag rules.
    Returns (flag_names, total_weight)."""
    flags = []
    total_weight = 0

    for rule in RISK_FLAG_RULES:
        if answers.get(rule.question_id) == rule.trigger_value:
            flags.append(rule.flag_name)
            total_weight += rule.weight

    # Computed rule: volume-income mismatch
    income = answers.get("annual_income_range", "")
    volume = answers.get("expected_monthly_volume", "")
    if income in VOLUME_INCOME_MISMATCH_LOW_INCOME and volume in VOLUME_INCOME_MISMATCH_HIGH_VOLUME:
        flags.append("volume_income_mismatch")
        total_weight += VOLUME_INCOME_MISMATCH_WEIGHT

    return flags, total_weight
```

---

## 9. Frontend Component Tree

### 9.1 User-Facing Source of Funds Section (KycCaseForm.tsx)

```
KycCaseForm
└── Accordion (section="source-of-funds")
    └── SofSection
        ├── SofStatusBanner
        │   ├── Badge (status: "not_started" | "in_progress" | "submitted")
        │   └── AlertBox (if admin_requested_additional)
        │       ├── Icon (AlertTriangle)
        │       └── Text (admin_request_note)
        ├── SofQuestionnairePanel
        │   ├── Button ("Start Questionnaire")  [if not started]
        │   │   └── onClick -> useMutation(POST /source-of-funds/start)
        │   ├── SofQuestionForm  [if started, not submitted]
        │   │   ├── RadioGroup (primary_income_source, 9 choices)
        │   │   ├── RadioGroup (annual_income_range, 6 choices)
        │   │   ├── RadioGroup (expected_monthly_volume, 5 choices)
        │   │   ├── Textarea (funds_origin_description, maxLength=1000)
        │   │   └── Button ("Submit Questionnaire")
        │   │       └── onClick -> useMutation(POST /questionnaires/{id}/responses/{sess}/submit)
        │   └── SofResponsesSummary  [if submitted]
        │       ├── DescriptionItem (primary_income_source label + value)
        │       ├── DescriptionItem (annual_income_range label + value)
        │       ├── DescriptionItem (expected_monthly_volume label + value)
        │       └── DescriptionItem (funds_origin_description)
        ├── FinancialDocUpload
        │   ├── Form (react-hook-form + zod schema)
        │   │   ├── Select (document_type, 5 options)
        │   │   ├── Input (issuing_entity, text, placeholder="e.g. Chase Bank")
        │   │   ├── DatePicker (document_date, max=today)
        │   │   ├── Input (period_months, number, optional, range 1-24)
        │   │   ├── FilePickerDialog (path selection from file manager)
        │   │   └── Button ("Attach Document")
        │   │       └── onClick -> useMutation(POST /source-of-funds/documents)
        │   └── FinancialDocList
        │       └── FinancialDocCard[] (for each document)
        │           ├── Badge (type: "bank_statement" etc.)
        │           ├── Text (issuing_entity + document_date)
        │           ├── Text (period_months + " months" | "--")
        │           └── Button ("Remove")  [if case not finalized]
        └── RiskFlagsDisplay  [if risk_flags.length > 0]
            └── Alert (variant="warning")
                ├── Text ("Risk flags detected:")
                └── Badge[] (each flag with color coding)
                    ├── Red: high_risk_income_source, volume_income_mismatch
                    ├── Orange: high_volume, unspecified_income_source
                    └── Yellow: elevated_volume, high_income
```

### 9.2 Admin Financial Verification Tab (KycCaseDetailPage.tsx)

```
KycCaseDetailPage
└── Tabs
    └── TabsContent (value="financial-verification")
        └── FinancialVerificationTab
            ├── Card (title="Questionnaire Responses")
            │   ├── SofResponsesReadOnly
            │   │   ├── DescriptionList
            │   │   │   ├── Item (label="Income Source", value=... [highlighted if crypto/other])
            │   │   │   ├── Item (label="Annual Income", value=...)
            │   │   │   ├── Item (label="Monthly Volume", value=... [highlighted if >5k])
            │   │   │   └── Item (label="Funds Description", value=...)
            │   │   └── Badge (submitted_at timestamp)
            │   └── EmptyState  [if no questionnaire submitted]
            ├── Card (title="Financial Documents")
            │   └── Table
            │       ├── TableHeader (Type | Issuer | Date | Period | Attached)
            │       └── TableBody
            │           └── TableRow[] (for each document)
            │               ├── Cell (type badge)
            │               ├── Cell (issuing_entity)
            │               ├── Cell (document_date, formatted)
            │               ├── Cell (period_months or "--")
            │               ├── Cell (attached_at, relative time)
            │               └── Cell (Button "View" -> opens S3 pre-signed URL)
            ├── Card (title="Risk Assessment")
            │   ├── RiskFlagsList
            │   │   └── Badge[] (flag name + weight + description)
            │   ├── Text ("Total risk contribution: {risk_score_contribution}")
            │   └── EmptyState ("No risk flags detected.")  [if empty]
            └── Card (title="Request Additional Documents")
                ├── Dialog (trigger="Request Documents")
                │   ├── DialogContent
                │   │   ├── CheckboxGroup (requested_document_types)
                │   │   │   ├── Checkbox ("Bank Statement")
                │   │   │   ├── Checkbox ("Investment Account")
                │   │   │   ├── Checkbox ("Crypto Wallet Proof")
                │   │   │   ├── Checkbox ("Employment Letter")
                │   │   │   └── Checkbox ("Tax Return")
                │   │   ├── Textarea (note, maxLength=2000, required)
                │   │   └── Button ("Send Request")
                │   │       └── onClick -> useMutation(POST /admin/.../request-financial-docs)
                │   └── DialogClose
                └── AdminRequestStatus  [if admin_requested_additional]
                    ├── Badge (variant="warning", "Additional docs requested")
                    ├── Text (admin_request_note)
                    └── ChipGroup (requested_document_types)
```

### 9.3 State Management (React Query)

```typescript
// React Query keys
const sofKeys = {
  status: (caseId: string) => ["kyc", "sof", caseId] as const,
};

// Hooks
function useSofStatus(caseId: string) {
  return useQuery({
    queryKey: sofKeys.status(caseId),
    queryFn: () => getSofStatus(caseId),
    enabled: !!caseId,
    staleTime: 30_000,
  });
}

function useStartSof(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (version: number) => startSof(caseId, version),
    onSuccess: () => qc.invalidateQueries({ queryKey: sofKeys.status(caseId) }),
  });
}

function useAttachFinDoc(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: FinDocAttachRequest) => attachFinDoc(caseId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: sofKeys.status(caseId) }),
  });
}

function useAdminRequestDocs(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AdminRequestDocsRequest) => adminRequestDocs(caseId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: sofKeys.status(caseId) }),
  });
}
```

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_sof_questionnaire_started_total` | Counter | `tenant_id` | Questionnaire sessions started |
| `kyc_sof_questionnaire_submitted_total` | Counter | `tenant_id` | Questionnaire sessions completed |
| `kyc_sof_document_attached_total` | Counter | `tenant_id`, `document_type` | Financial documents attached by type |
| `kyc_sof_risk_flag_triggered_total` | Counter | `tenant_id`, `flag_name` | Risk flags triggered per type |
| `kyc_sof_admin_doc_request_total` | Counter | `tenant_id` | Admin requests for additional documents |
| `kyc_sof_risk_score_histogram` | Histogram | `tenant_id` | Distribution of SOF risk score contributions |
| `kyc_sof_attach_latency_seconds` | Histogram | `tenant_id` | Document attachment latency |
| `kyc_sof_version_conflict_total` | Counter | `tenant_id` | OCC version conflicts on writes |

### 10.2 Structured Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.sof.started` | INFO | `case_id`, `user_sub`, `questionnaire_id` | POST /start succeeds |
| `kyc.sof.submitted` | INFO | `case_id`, `user_sub`, `risk_flags`, `risk_score` | Questionnaire submitted |
| `kyc.sof.doc_attached` | INFO | `case_id`, `user_sub`, `document_type`, `issuing_entity` | Document attached |
| `kyc.sof.risk_flags_computed` | INFO | `case_id`, `flags`, `total_score` | After response processing |
| `kyc.sof.admin_request` | INFO | `case_id`, `admin_sub`, `requested_types`, `note_length` | Admin requests docs |
| `kyc.sof.duplicate_start` | WARN | `case_id`, `user_sub` | Attempt to start SOF twice |
| `kyc.sof.version_conflict` | WARN | `case_id`, `user_sub`, `expected`, `actual` | OCC failure |
| `kyc.sof.volume_income_mismatch` | WARN | `case_id`, `user_sub`, `income`, `volume` | Mismatch flag triggered |

### 10.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| High mismatch rate | > 20% of submissions flagged `volume_income_mismatch` in 24h | P2 (Warning) |
| SOF abandonment | > 50% of started SOFs not submitted within 48h | P3 (Info) |
| Document limit spike | > 10% of attach attempts return `kyc_max_documents_exceeded` in 1h | P3 (Info) |
| Admin request spike | > 10 admin doc requests in 1h (possible review backlog) | P3 (Info) |
| Version conflict spike | > 5% of writes produce OCC conflicts in 15min | P3 (Info) |

### 10.4 Dashboard Queries

```sql
-- SOF completion funnel (last 7 days)
SELECT
  count(CASE WHEN event = 'kyc.sof.started' THEN 1 END) as started,
  count(CASE WHEN event = 'kyc.sof.submitted' THEN 1 END) as submitted,
  count(CASE WHEN event = 'kyc.sof.doc_attached' THEN 1 END) as docs_attached,
  count(CASE WHEN event = 'kyc.sof.admin_request' THEN 1 END) as admin_requests
FROM structured_logs
WHERE timestamp > now() - interval '7 days'

-- Risk flag distribution (pie chart)
SELECT flag_name, count(*) as occurrences
FROM structured_logs
WHERE event = 'kyc.sof.risk_flags_computed'
  AND timestamp > now() - interval '30 days'
  AND flag_name IS NOT NULL
GROUP BY flag_name
ORDER BY occurrences DESC

-- Document type distribution
SELECT document_type, count(*) as count
FROM structured_logs
WHERE event = 'kyc.sof.doc_attached'
  AND timestamp > now() - interval '30 days'
GROUP BY document_type
```

---

## 11. Rollout Plan

### 11.1 Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_SOURCE_OF_FUNDS_ENABLED` | `false` | Gates SOF section visibility and all SOF endpoints |
| `KYC_SOF_RISK_FLAGS_ENABLED` | `false` | Gates automatic risk flag computation (can enable SOF without flags) |
| `KYC_SOF_READINESS_GATE_ENABLED` | `false` | Gates the readiness requirement (can collect SOF without blocking submission) |

### 11.2 Migration Steps

| Step | Action | Duration | Rollback |
|------|--------|----------|----------|
| 1 | Deploy backend with all SOF flags `false` | 1 hour | Revert deploy |
| 2 | Verify endpoints return 404 when disabled | 30 min | N/A |
| 3 | Enable `KYC_SOURCE_OF_FUNDS_ENABLED` on staging | 1 day | Set false |
| 4 | Run full E2E suite (sections 167-169) on staging | 2 hours | N/A |
| 5 | Enable `KYC_SOF_RISK_FLAGS_ENABLED` on staging | 1 day | Set false |
| 6 | Spot-check 20 risk flag computations with compliance | 2 hours | N/A |
| 7 | Enable SOF + risk flags on production (canary: 10% of tenants) | 3 days | Set false |
| 8 | Monitor metrics: completion rate, error rate, flag distribution | 3 days | N/A |
| 9 | Enable `KYC_SOF_READINESS_GATE_ENABLED` (requires SOF for enhanced/high_risk) | 1 week after step 8 | Set false |
| 10 | Full GA: enable all flags for all tenants | ongoing | Set false |

### 11.3 Canary Criteria

- SOF start-to-submit conversion rate > 70%
- Document attachment success rate > 95%
- No increase in overall KYC case abandonment rate
- Risk flag accuracy: compliance spot-checks 20 flagged cases, accuracy > 90%
- No P0/P1 bugs in first 72 hours

### 11.4 Rollback Procedure

1. Set `KYC_SOURCE_OF_FUNDS_ENABLED=false` in environment
2. Restart backend (SOF endpoints return 404 when disabled)
3. Frontend SOF section hidden (checks flag from `/v1/kyc/config` response)
4. Existing SOF data remains in DynamoDB `source_of_funds` map (not deleted)
5. Risk flags from SOF excluded from KYC-008 risk engine when flag is off
6. Readiness gate reverts to not requiring SOF (backward compatible)
7. Post-mortem to determine root cause before re-enabling

---

## 12. Performance Considerations

### 12.1 Read/Write Cost Estimates

| Operation | DDB Cost | Latency Target | Notes |
|-----------|----------|---------------|-------|
| Start SOF | 2 WCU (case update) + 2 WCU (questionnaire create) | < 200ms | Sequential: create session then update case |
| Submit questionnaire | 2 WCU (questionnaire) + 2 WCU (case flags) | < 200ms | Two writes in sequence |
| Attach document | 2 WCU (case update with OCC) | < 150ms | Single conditional update |
| Get SOF status | 1 RCU (eventually consistent) | < 100ms | Single GetItem on case record |
| Compute risk flags | 0 DDB (in-memory) | < 5ms | Pure computation from answers dict |
| Admin request docs | 2 WCU (case update) + 1 WCU (notification) | < 200ms | Notification is fire-and-forget |

### 12.2 S3 Storage

- Financial documents are PDFs (typical 100KB - 5MB each)
- Max 5 documents per case = max 25MB per case
- S3 lifecycle rule: move to Glacier after case is closed for 90 days
- Pre-signed URL for document viewing (15-minute expiry)
- Content-Type validation: only `application/pdf`, `image/jpeg`, `image/png` accepted

### 12.3 Caching Strategy

| Data | Cache Layer | TTL | Invalidation |
|------|------------|-----|-------------|
| SOF status | React Query (staleTime) | 30s | On mutation success (invalidateQueries) |
| SOF questions template | In-memory Python constant | Infinite (immutable) | Deploy new version |
| Risk flag rules | In-memory Python constant | Infinite (immutable) | Deploy new version |
| Document pre-signed URLs | None (generated per request) | N/A | 15-min URL expiry |

### 12.4 Rate Limiting

| Endpoint | Rate Limit | Window | Notes |
|----------|-----------|--------|-------|
| Start SOF | 5 req/user/hour | 1h | Normally called once per case |
| Attach document | 20 req/user/hour | 1h | Max 5 docs per case, allows retries |
| Admin request | 10 req/admin/hour | 1h | Low frequency |
| Get SOF status | 60 req/user/min | 1m | Standard read rate |

### 12.5 Payload Size Estimates

- SOF questionnaire template response: ~2KB
- SOF status response (full, with docs + flags): ~3KB
- Financial document metadata: ~200 bytes per document
- Admin request payload: ~2.5KB max (types + note)
- No pagination needed: max 5 documents, max 6 risk flags

---

## 13. E2E Test Plan

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

## 14. Expanded E2E Test Details

### Section 167a: Questionnaire Edge Cases (5 additional tests)

```typescript
test("167.6 Start SOF on non-draft case returns 400", async () => {
  // Create a case, submit it, then try to start SOF
  // Expect 400 with error_code "kyc_invalid_status"
  // Verify body: "SOF can only be started on draft or pending cases."
});

test("167.7 Start SOF twice returns 409 idempotent error", async () => {
  // Start SOF on a fresh case (succeeds, 200)
  // Attempt to start SOF again on same case
  // Expect 409 with error_code "kyc_sof_already_started"
  // Verify existing questionnaire_id is returned in error body
});

test("167.8 Questionnaire with all low-risk answers produces no flags", async () => {
  // Create case + start SOF
  // Submit with: employment_salary, 50k_100k, under_500, "Regular salary income"
  // GET SOF status
  // Verify risk_flags = [] (empty array)
  // Verify risk_score_contribution = 0
});

test("167.9 Multiple risk flags accumulate correctly", async () => {
  // Create case + start SOF
  // Submit with: crypto_trading (+20), under_25k, over_10000 (+25)
  // Volume-income mismatch triggers automatically (+30)
  // GET SOF status
  // Verify risk_flags contains all 3: high_risk_income_source, high_volume, volume_income_mismatch
  // Verify risk_score_contribution = 75
});

test("167.10 Bob cannot access Alice's SOF status", async () => {
  // Create case as Alice, start SOF
  // GET SOF status as Bob
  // Expect 403 with error_code "kyc_access_forbidden"
});
```

### Section 168a: Document Attachment Edge Cases (5 additional tests)

```typescript
test("168.6 Attach document before starting SOF returns 400", async () => {
  // Create a fresh case (no SOF started)
  // POST /source-of-funds/documents with valid body
  // Expect 400 with error_code "kyc_sof_not_started"
});

test("168.7 Version conflict on concurrent document attachment returns 409", async () => {
  // Create case, start SOF (version = N)
  // Attach doc with expected_version=N (succeeds, version -> N+1)
  // Attempt second attach with expected_version=N (stale)
  // Expect 409 with error_code "kyc_case_update_conflict"
  // Verify response includes current_version field
});

test("168.8 Attach 6th document exceeds limit returns 400", async () => {
  // Create case, start SOF
  // Attach 5 documents sequentially (incrementing expected_version each time)
  // Attempt to attach 6th document
  // Expect 400 with error_code "kyc_max_documents_exceeded"
  // GET SOF status; verify documents array has exactly 5 entries
});

test("168.9 Crypto wallet proof document type accepted", async () => {
  // Attach with document_type: "crypto_wallet_proof"
  // issuing_entity: "Coinbase", period_months: null
  // Expect 200
  // Verify document in status response
});

test("168.10 Attach document to approved (finalized) case returns 400", async () => {
  // Use a case with status="approved"
  // POST /source-of-funds/documents
  // Expect 400 with error_code "kyc_case_finalized"
});
```

### Section 169a: Readiness Gate Edge Cases (4 additional tests)

```typescript
test("169.6 High-risk profile requires SOF same as enhanced", async () => {
  // Create case with intake_profile="high_risk", no SOF
  // GET readiness
  // Verify source_of_funds check is present and = false
});

test("169.7 SOF with questionnaire + doc but wrong expected_version fails update", async () => {
  // Start SOF + submit questionnaire
  // Attempt to attach doc with expected_version=999
  // Expect 409 version conflict
  // Readiness still fails (no docs)
});

test("169.8 Admin-requested additional docs flag visible in SOF status", async () => {
  // Complete SOF (questionnaire + 1 doc)
  // Admin requests tax_return with a note
  // GET SOF status as user
  // Verify admin_requested_additional=true
  // Verify admin_request_note matches sent note
  // Verify requested_document_types includes "tax_return"
});

test("169.9 Risk flags visible to admin in case detail", async () => {
  // Submit high-risk SOF responses (crypto + high volume)
  // GET case detail as admin/root
  // Verify source_of_funds.risk_flags includes expected flags
  // Verify risk_score_contribution > 0
});
```

---

## 15. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/routers/kyc_cases.py` | Modify | Add 4 source-of-funds endpoints; update readiness gate |
| `app/services/kyc_cases.py` | Modify | Add source_of_funds field handling; risk flag computation |
| `app/contracts/kyc_cases_contract.py` | Modify | Add financial doc request models; SOF status response |
| `frontend/src/pages/kyc/KycCaseForm.tsx` | Modify | Add Source of Funds section with questionnaire and uploads |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add Financial Verification tab |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add source-of-funds API functions |
| `frontend/e2e/kyc-source-of-funds.spec.ts` | **New** | 15+ E2E tests across sections 167-169 |

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | all | VERIFIED (1294 lines) |
| `_readiness_for_case()` | `app/routers/kyc_cases.py` | 223 | VERIFIED |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| `start_kyc_questionnaire()` | `app/routers/kyc_cases.py` | 625 | VERIFIED |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines) |
| `_risk()` function | `app/services/kyc_cases.py` | 664 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |
| `DynamoQuestionnaireRepository` | `app/services/questionnaires_repository.py` | 38 | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| Source-of-funds endpoints (4 endpoints) | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoints required |
| `source_of_funds` field on KYC case | `app/services/kyc_cases.py` | NOT FOUND -- new field handling required |
| SOF risk flag computation | `app/services/kyc_cases.py` | NOT FOUND -- new logic in `_risk()` required |
| Financial doc request/response models | `app/contracts/kyc_cases_contract.py` | NOT FOUND -- new models required |
| `frontend/src/pages/kyc/KycCaseForm.tsx` | `frontend/src/pages/kyc/` | NOT FOUND -- new page required |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` financial tab | `frontend/src/pages/admin/` | NOT FOUND -- page does not exist yet (KYC-001 dependency) |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_funds.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_submit_funds_declaration`
  - `test_upload_supporting_document`
  - `test_validate_declared_source`
  - `test_high_value_threshold_triggers_enhanced`
  - `test_admin_approve_funds_declaration`
  - `test_admin_reject_with_reason`

### Integration Tests

  - Funds declaration with supporting documents stored in S3
  - High-value transactions trigger enhanced verification requirement
  - Approval updates user KYC tier for funds component

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-funds.spec.ts`
**Test count**: 10

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

- **DDB seeds**: Seed `kyc_submissions (funds verification records)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_FUNDS_VERIFICATION_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Funds verification reviewed through dashboard |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-008 | Risk Scoring Engine | Funds verification status feeds risk score |

### Merge Strategy

**Sequential**

Merge after KYC-001. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 10 E2E tests pass with `npx playwright test kyc-funds.spec.ts`
