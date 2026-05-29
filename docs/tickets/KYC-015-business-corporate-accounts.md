# KYC-015: KYC for Business/Corporate Accounts (KYB)

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 12-16 days  
**Dependencies**: KYC-009 (Tiered Verification Levels), KYC-006 (Sanctions & PEP Screening)

---

## 1. Overview & Motivation

### 1.1 The Gap

The existing KYC system (`app/routers/kyc_cases.py`, `app/services/kyc_cases.py`) is designed exclusively for individual identity verification. There is no mechanism to verify business entities, which require fundamentally different documentation, verification steps, and ownership structures.

Tier 4 (Institutional) in KYC-009 is gated on business KYC approval, but the infrastructure to perform business KYC does not exist. Business accounts need:
1. Company registration verification (certificate of incorporation, articles of association)
2. Ultimate Beneficial Owner (UBO) identification — individuals with >25% ownership
3. Each UBO linked to their own personal KYC case
4. Director/officer verification with role documentation
5. Company address verification (registered office and trading address)
6. Financial statement review for AML purposes

### 1.2 What This Ticket Adds

1. **KYB (Know Your Business) case system** — Separate case type for corporate verification with its own lifecycle.
2. **Company information model** — Legal name, trading name, registration number, jurisdiction, incorporation date, company type.
3. **UBO management** — Add/remove individuals with ownership percentage; each linked to a personal KYC case.
4. **Director/officer list** — Named individuals with their roles (director, secretary, CEO, etc.).
5. **Corporate document requirements** — Certificate of incorporation, articles of association, shareholder register, financial statements, board resolution.
6. **Dual-address verification** — Registered office and trading address as separate verification targets.
7. **KYB-to-KYC linking** — Each UBO's personal KYC status affects the business case status.
8. **New DDB table**: `kyc_business_cases` with GSIs for organization and status.
9. **Link to organizations** — The `app/routers/orgs.py` organizations system can optionally link to a KYB case.

### 1.3 Architecture

```
Business KYC (KYB) Flow:

  POST /v1/kyc/business-cases
  { company_name, registration_number, jurisdiction, ... }
       │
       ▼
  KYB Case Created (status: "draft")
       │
       ├── Company Info → PATCH /{id} (legal details)
       ├── Documents → POST /{id}/documents (corp docs)
       ├── UBOs → POST /{id}/ubos (add individuals)
       │            └── Each UBO → link to personal KYC case
       ├── Directors → POST /{id}/directors (add officers)
       └── Addresses → POST /{id}/addresses (registered + trading)
       │
       ▼
  POST /{id}/submit → status: "submitted"
       │
       ▼
  Admin Review:
       ├── Verify company registration
       ├── Verify all UBOs have approved personal KYC
       ├── Verify corporate documents
       ├── Run sanctions screening on company name
       └── Make decision
       │
       ▼
  status: "approved" | "rejected"
       │
       ▼
  If approved → User eligible for Tier 4 (KYC-009)

Data Model:

  kyc_business_cases table
  ┌─────────────────────────────────────────────────┐
  │ PK                    │ SK                       │
  ├───────────────────────┼─────────────────────────┤
  │ BIZ#{case_id}         │ META                     │ → Company info, status
  │ BIZ#{case_id}         │ UBO#{ubo_id}             │ → UBO record
  │ BIZ#{case_id}         │ DIR#{director_id}         │ → Director record
  │ BIZ#{case_id}         │ DOC#{doc_id}              │ → Corporate document
  │ BIZ#{case_id}         │ ADDR#{addr_type}           │ → Address verification
  │ OWNER#{user_sub}      │ BIZ#{case_id}             │ → GSI1: by owner
  │ STATUS#{status}       │ UPDATED#{ts}#BIZ#{id}     │ → GSI2: by status
  │ ORG#{org_id}          │ BIZ#{case_id}             │ → GSI3: by organization
  └───────────────────────┴─────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Personal KYC System (`app/services/kyc_cases.py`)

The existing `KycCaseStore` class provides the template for the business case store. Key patterns to reuse:
- `create_case()` with `pk=KYC#{case_id}`, `sk=META` and GSI key derivation functions
- Optimistic concurrency via `version` field and `ConditionExpression`
- Status transitions with audit logging
- Evidence snapshot on submission
- Admin queue and metrics

### 2.2 Organizations (`app/routers/orgs.py`)

The organizations system manages multi-user organizations. A business KYB case should link to an organization record so that approval grants Tier 4 to all organization members (or at least designated ones).

### 2.3 KYC Tiers (KYC-009)

Tier 4 requirements include `business_kyc_approved`. The `check_tier_requirements()` function in `app/services/kyc_tiers.py` (KYC-009) needs to query the `kyc_business_cases` table to check for approved business cases.

### 2.4 Sanctions Screening (KYC-006)

The screening system should apply to business names and UBO names. Corporate sanctions screening uses the same list-based matching but with entity names instead of individual names.

### 2.5 DynamoDB Table Patterns

The existing `kyc_cases` table uses:
- `pk=KYC#{case_id}`, `sk=META` for the main record
- GSI with `gsi_owner_pk=OWNER#{user_sub}` and `gsi_status_pk=STATUS#{status}`
- `_updated_sk()` for time-ordered sort keys

The business cases table follows the same pattern but with `BIZ#` prefix and additional GSI for organization linking.

---

## 3. Technical Design

### 3.1 New DDB Table: `kyc_business_cases`

**Table definition for `scripts/local-ddb-init.py`**:

```python
TableDef(
    _resolve_table_name(S.kyc_business_cases_table_name, "kyc_business_cases"),
    partition_key="pk",
    sort_key="sk",
    gsis=[
        {"index_name": "owner-updated-index", "partition_key": "gsi_owner_pk", "sort_key": "gsi_owner_sk"},
        {"index_name": "status-updated-index", "partition_key": "gsi_status_pk", "sort_key": "gsi_status_sk"},
        {"index_name": "org-index", "partition_key": "gsi_org_pk", "sort_key": "gsi_org_sk"},
    ],
),
```

### 3.2 Settings (`app/core/settings.py`)

```python
kyc_business_cases_table_name: str = os.environ.get("KYC_BUSINESS_CASES_TABLE_NAME", "kyc_business_cases")
```

### 3.3 Table Handle (`app/core/tables.py`)

```python
kyc_business_cases: Any
# In T initialization:
kyc_business_cases=ddb.Table(S.kyc_business_cases_table_name),
```

### 3.4 Data Models

**Company Types**:

```python
CompanyType = Literal["llc", "corp", "partnership", "sole_prop", "nonprofit", "cooperative", "trust"]
```

**Business Case META Item**:

```python
{
    "pk": "BIZ#{case_id}",
    "sk": "META",
    "entity_type": "kyb_case",
    "kyb_case_id": case_id,
    "user_sub": user_sub,           # Submitting user
    "status": "draft",              # draft | submitted | under_review | needs_more_info | approved | rejected | expired
    "company": {
        "legal_name": "Acme Corp LLC",
        "trading_name": "Acme",
        "registration_number": "12345678",
        "jurisdiction": "US-DE",     # ISO 3166-2 code
        "incorporation_date": "2020-01-15",
        "company_type": "llc",
        "tax_id": "XX-XXXXXXX",
        "website": "https://acme.example.com",
        "industry": "Technology",
    },
    "ubo_summary": {
        "total_ubos": 2,
        "all_kyc_approved": false,
        "total_ownership_pct": 100,
    },
    "director_count": 3,
    "document_count": 4,
    "submission": { ... },          # Same structure as personal KYC
    "review": { ... },              # Same structure as personal KYC
    "org_id": "org_xyz",            # Optional link to organization
    "created_at": ts,
    "updated_at": ts,
    "version": 1,
    "gsi_owner_pk": "OWNER#{user_sub}",
    "gsi_owner_sk": "UPDATED#{ts:013d}#BIZ#{case_id}",
    "gsi_status_pk": "STATUS#{status}",
    "gsi_status_sk": "UPDATED#{ts:013d}#BIZ#{case_id}",
    "gsi_org_pk": "ORG#{org_id}",
    "gsi_org_sk": "BIZ#{case_id}",
}
```

**UBO Item** (`SK=UBO#{ubo_id}`):

```python
{
    "pk": "BIZ#{case_id}",
    "sk": "UBO#{ubo_id}",
    "ubo_id": ubo_id,
    "full_name": "Jane Smith",
    "date_of_birth": "1985-03-20",
    "nationality": "US",
    "ownership_percentage": 51.0,
    "personal_kyc_case_id": "kyc_abc123",   # Link to personal KYC case
    "personal_kyc_status": "approved",       # Synced from personal case
    "added_at": ts,
    "added_by": user_sub,
}
```

**Director Item** (`SK=DIR#{director_id}`):

```python
{
    "pk": "BIZ#{case_id}",
    "sk": "DIR#{director_id}",
    "director_id": director_id,
    "full_name": "John Doe",
    "role": "director",              # director | secretary | ceo | cfo | coo | treasurer
    "date_of_birth": "1980-06-15",
    "nationality": "US",
    "personal_kyc_case_id": None,    # Optional link
    "added_at": ts,
}
```

**Corporate Document Item** (`SK=DOC#{doc_id}`):

```python
{
    "pk": "BIZ#{case_id}",
    "sk": "DOC#{doc_id}",
    "doc_id": doc_id,
    "document_type": "certificate_of_incorporation",
    # Types: certificate_of_incorporation, articles_of_association,
    #        shareholder_register, financial_statements, board_resolution,
    #        proof_of_address_registered, proof_of_address_trading
    "file_node_id": "node_xyz",
    "file_name": "cert_of_inc.pdf",
    "uploaded_at": ts,
    "uploaded_by": user_sub,
}
```

**Address Item** (`SK=ADDR#{addr_type}`):

```python
{
    "pk": "BIZ#{case_id}",
    "sk": "ADDR#{addr_type}",        # "registered" or "trading"
    "address_type": addr_type,
    "line1": "123 Business St",
    "line2": "Suite 400",
    "city": "Wilmington",
    "state": "DE",
    "postal_code": "19801",
    "country": "US",
    "verified": false,
    "verification_doc_id": None,     # Link to proof document
}
```

### 3.5 New Service: `app/services/kyc_business_cases.py`

```python
"""KYB (Know Your Business) case management service."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import uuid

from app.core.tables import T
from app.core.time import now_ts

_ALLOWED_STATUSES = {"draft", "submitted", "under_review", "needs_more_info", "approved", "rejected", "expired"}
_REQUIRED_DOCUMENT_TYPES = {"certificate_of_incorporation", "articles_of_association", "shareholder_register"}
_ALLOWED_COMPANY_TYPES = {"llc", "corp", "partnership", "sole_prop", "nonprofit", "cooperative", "trust"}
_ALLOWED_DIRECTOR_ROLES = {"director", "secretary", "ceo", "cfo", "coo", "treasurer"}
_ALLOWED_DOCUMENT_TYPES = {
    "certificate_of_incorporation", "articles_of_association", "shareholder_register",
    "financial_statements", "board_resolution",
    "proof_of_address_registered", "proof_of_address_trading",
}


@dataclass
class KybCaseStore:
    _table: Any = field(default_factory=lambda: T.kyc_business_cases)

    def create_case(self, *, user_sub: str, company: dict[str, Any], org_id: str | None = None) -> dict[str, Any]:
        ts = now_ts()
        case_id = f"kyb_{uuid.uuid4().hex[:12]}"
        item = {
            "pk": f"BIZ#{case_id}",
            "sk": "META",
            "entity_type": "kyb_case",
            "kyb_case_id": case_id,
            "user_sub": user_sub,
            "status": "draft",
            "company": _normalize_company(company),
            "ubo_summary": {"total_ubos": 0, "all_kyc_approved": False, "total_ownership_pct": 0},
            "director_count": 0,
            "document_count": 0,
            "submission": {},
            "review": {},
            "org_id": org_id,
            "created_at": ts,
            "updated_at": ts,
            "version": 1,
            "gsi_owner_pk": f"OWNER#{user_sub}",
            "gsi_owner_sk": f"UPDATED#{ts:013d}#BIZ#{case_id}",
            "gsi_status_pk": "STATUS#draft",
            "gsi_status_sk": f"UPDATED#{ts:013d}#BIZ#{case_id}",
        }
        if org_id:
            item["gsi_org_pk"] = f"ORG#{org_id}"
            item["gsi_org_sk"] = f"BIZ#{case_id}"
        self._table.put_item(Item=item)
        return item

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key={"pk": f"BIZ#{case_id}", "sk": "META"}).get("Item")

    def add_ubo(self, *, case_id: str, ubo_data: dict[str, Any], user_sub: str) -> dict[str, Any]:
        ubo_id = f"ubo_{uuid.uuid4().hex[:8]}"
        ts = now_ts()
        item = {
            "pk": f"BIZ#{case_id}",
            "sk": f"UBO#{ubo_id}",
            "ubo_id": ubo_id,
            "full_name": ubo_data["full_name"],
            "date_of_birth": ubo_data.get("date_of_birth"),
            "nationality": ubo_data.get("nationality"),
            "ownership_percentage": float(ubo_data["ownership_percentage"]),
            "personal_kyc_case_id": ubo_data.get("personal_kyc_case_id"),
            "personal_kyc_status": None,
            "added_at": ts,
            "added_by": user_sub,
        }
        self._table.put_item(Item=item)
        self._update_ubo_summary(case_id)
        return item

    def remove_ubo(self, *, case_id: str, ubo_id: str) -> bool:
        self._table.delete_item(Key={"pk": f"BIZ#{case_id}", "sk": f"UBO#{ubo_id}"})
        self._update_ubo_summary(case_id)
        return True

    def list_ubos(self, case_id: str) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key
        resp = self._table.query(
            KeyConditionExpression=Key("pk").eq(f"BIZ#{case_id}") & Key("sk").begins_with("UBO#"),
        )
        return resp.get("Items", [])

    def add_director(self, *, case_id: str, director_data: dict[str, Any], user_sub: str) -> dict[str, Any]:
        director_id = f"dir_{uuid.uuid4().hex[:8]}"
        ts = now_ts()
        item = {
            "pk": f"BIZ#{case_id}",
            "sk": f"DIR#{director_id}",
            "director_id": director_id,
            "full_name": director_data["full_name"],
            "role": director_data.get("role", "director"),
            "date_of_birth": director_data.get("date_of_birth"),
            "nationality": director_data.get("nationality"),
            "personal_kyc_case_id": director_data.get("personal_kyc_case_id"),
            "added_at": ts,
            "added_by": user_sub,
        }
        self._table.put_item(Item=item)
        # Update director count on META
        self._table.update_item(
            Key={"pk": f"BIZ#{case_id}", "sk": "META"},
            UpdateExpression="SET director_count = director_count + :one, updated_at = :ts",
            ExpressionAttributeValues={":one": 1, ":ts": ts},
        )
        return item

    def add_document(self, *, case_id: str, doc_data: dict[str, Any], user_sub: str) -> dict[str, Any]:
        doc_id = f"doc_{uuid.uuid4().hex[:8]}"
        ts = now_ts()
        item = {
            "pk": f"BIZ#{case_id}",
            "sk": f"DOC#{doc_id}",
            "doc_id": doc_id,
            "document_type": doc_data["document_type"],
            "file_node_id": doc_data["file_node_id"],
            "file_name": doc_data.get("file_name", ""),
            "uploaded_at": ts,
            "uploaded_by": user_sub,
        }
        self._table.put_item(Item=item)
        self._table.update_item(
            Key={"pk": f"BIZ#{case_id}", "sk": "META"},
            UpdateExpression="SET document_count = document_count + :one, updated_at = :ts",
            ExpressionAttributeValues={":one": 1, ":ts": ts},
        )
        return item

    def set_address(self, *, case_id: str, address_type: str, address: dict[str, Any]) -> dict[str, Any]:
        ts = now_ts()
        item = {
            "pk": f"BIZ#{case_id}",
            "sk": f"ADDR#{address_type}",
            "address_type": address_type,
            **address,
            "verified": False,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        return item

    def submit_case(self, *, case_id: str, user_sub: str, expected_version: int) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if not case or str(case.get("user_sub", "")) != user_sub:
            return None
        if case.get("status") != "draft":
            raise ValueError("can_only_submit_draft")

        # Validate requirements
        errors = self._validate_submit_requirements(case_id, case)
        if errors:
            raise ValueError(f"kyb_submit_prereq_failed:{','.join(errors)}")

        # ... status transition logic (same pattern as personal KYC)
        return self.get_case(case_id)

    def _validate_submit_requirements(self, case_id: str, case: dict) -> list[str]:
        errors = []
        company = case.get("company", {})
        if not company.get("legal_name"):
            errors.append("missing_legal_name")
        if not company.get("registration_number"):
            errors.append("missing_registration_number")

        ubos = self.list_ubos(case_id)
        if not ubos:
            errors.append("no_ubos_added")
        total_pct = sum(float(u.get("ownership_percentage", 0)) for u in ubos)
        if total_pct < 75:
            errors.append("ubo_ownership_below_75_percent")

        docs = self._list_documents(case_id)
        doc_types = {d.get("document_type") for d in docs}
        missing_docs = _REQUIRED_DOCUMENT_TYPES - doc_types
        if missing_docs:
            errors.append(f"missing_documents:{','.join(missing_docs)}")

        return errors

    def _update_ubo_summary(self, case_id: str) -> None:
        ubos = self.list_ubos(case_id)
        ts = now_ts()
        total_pct = sum(float(u.get("ownership_percentage", 0)) for u in ubos)
        all_approved = all(u.get("personal_kyc_status") == "approved" for u in ubos) if ubos else False
        self._table.update_item(
            Key={"pk": f"BIZ#{case_id}", "sk": "META"},
            UpdateExpression="SET ubo_summary = :summary, updated_at = :ts",
            ExpressionAttributeValues={
                ":summary": {
                    "total_ubos": len(ubos),
                    "all_kyc_approved": all_approved,
                    "total_ownership_pct": total_pct,
                },
                ":ts": ts,
            },
        )

    def _list_documents(self, case_id: str) -> list[dict]:
        from boto3.dynamodb.conditions import Key
        resp = self._table.query(
            KeyConditionExpression=Key("pk").eq(f"BIZ#{case_id}") & Key("sk").begins_with("DOC#"),
        )
        return resp.get("Items", [])


def _normalize_company(data: dict) -> dict:
    return {
        "legal_name": str(data.get("legal_name", "")).strip(),
        "trading_name": str(data.get("trading_name", "")).strip() or None,
        "registration_number": str(data.get("registration_number", "")).strip(),
        "jurisdiction": str(data.get("jurisdiction", "")).strip().upper(),
        "incorporation_date": str(data.get("incorporation_date", "")).strip() or None,
        "company_type": data.get("company_type", "llc"),
        "tax_id": str(data.get("tax_id", "")).strip() or None,
        "website": str(data.get("website", "")).strip() or None,
        "industry": str(data.get("industry", "")).strip() or None,
    }


KYB_STORE = KybCaseStore()
```

### 3.6 New Router: `app/routers/kyc_business.py`

```python
router = APIRouter(prefix="/v1/kyc/business-cases", tags=["kyc-business"])
```

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/` | `require_ui_session` | Create business KYC case |
| `GET` | `/` | `require_ui_session` | List user's business cases |
| `GET` | `/{case_id}` | `require_ui_session` | Get business case details |
| `PATCH` | `/{case_id}` | `require_ui_session` | Update company info |
| `POST` | `/{case_id}/ubos` | `require_ui_session` | Add UBO |
| `DELETE` | `/{case_id}/ubos/{ubo_id}` | `require_ui_session` | Remove UBO |
| `GET` | `/{case_id}/ubos` | `require_ui_session` | List UBOs |
| `POST` | `/{case_id}/directors` | `require_ui_session` | Add director |
| `DELETE` | `/{case_id}/directors/{dir_id}` | `require_ui_session` | Remove director |
| `POST` | `/{case_id}/documents` | `require_ui_session` | Upload corporate document |
| `POST` | `/{case_id}/addresses` | `require_ui_session` | Set address |
| `POST` | `/{case_id}/submit` | `require_ui_session` | Submit for review |
| `GET` | `/admin/queue` | `require_root_session` | Admin KYB review queue |
| `POST` | `/admin/{case_id}/approve` | `require_root_session` | Approve business case |
| `POST` | `/admin/{case_id}/reject` | `require_root_session` | Reject business case |

### 3.7 Pydantic Models

```python
class KybCreateRequest(BaseModel):
    legal_name: str = Field(min_length=2, max_length=200)
    trading_name: str | None = Field(default=None, max_length=200)
    registration_number: str = Field(min_length=1, max_length=50)
    jurisdiction: str = Field(min_length=2, max_length=10)
    company_type: Literal["llc", "corp", "partnership", "sole_prop", "nonprofit", "cooperative", "trust"]
    incorporation_date: str | None = None
    org_id: str | None = None


class UboAddRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    date_of_birth: str | None = None
    nationality: str | None = Field(default=None, max_length=3)
    ownership_percentage: float = Field(gt=0, le=100)
    personal_kyc_case_id: str | None = None


class DirectorAddRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    role: Literal["director", "secretary", "ceo", "cfo", "coo", "treasurer"] = "director"
    date_of_birth: str | None = None
    nationality: str | None = None


class KybDocumentRequest(BaseModel):
    document_type: Literal[
        "certificate_of_incorporation", "articles_of_association", "shareholder_register",
        "financial_statements", "board_resolution",
        "proof_of_address_registered", "proof_of_address_trading",
    ]
    file_node_id: str


class KybAddressRequest(BaseModel):
    address_type: Literal["registered", "trading"]
    line1: str = Field(min_length=1, max_length=200)
    line2: str | None = Field(default=None, max_length=200)
    city: str = Field(min_length=1, max_length=100)
    state: str | None = Field(default=None, max_length=100)
    postal_code: str = Field(min_length=1, max_length=20)
    country: str = Field(min_length=2, max_length=3)
```

### 3.8 Frontend Components

**File**: `frontend/src/pages/kyc/KybWizard.tsx` — Multi-step wizard for business verification (similar to KycWizard but with business-specific steps):
- Step 1: Company Information
- Step 2: UBO Management (add/remove individuals, link personal KYC)
- Step 3: Directors & Officers
- Step 4: Corporate Documents
- Step 5: Addresses (registered + trading)
- Step 6: Review & Submit

**File**: `frontend/src/api/endpoints/kyc-business.ts`

```typescript
export const createKybCase = (data: KybCreateRequest) =>
  client.post("/v1/kyc/business-cases", data);
export const getKybCases = () =>
  client.get("/v1/kyc/business-cases");
export const getKybCase = (caseId: string) =>
  client.get(`/v1/kyc/business-cases/${caseId}`);
export const addUbo = (caseId: string, data: UboAddRequest) =>
  client.post(`/v1/kyc/business-cases/${caseId}/ubos`, data);
export const addDirector = (caseId: string, data: DirectorAddRequest) =>
  client.post(`/v1/kyc/business-cases/${caseId}/directors`, data);
export const addDocument = (caseId: string, data: KybDocumentRequest) =>
  client.post(`/v1/kyc/business-cases/${caseId}/documents`, data);
export const submitKybCase = (caseId: string, data: { expected_version: number }) =>
  client.post(`/v1/kyc/business-cases/${caseId}/submit`, data);
```

**Route**: `/kyc/business` in `App.tsx`

### 3.9 Registration

```python
# app/main.py
from app.routers.kyc_business import router as kyc_business_router
app.include_router(kyc_business_router)
```

---

## 4. Implementation Plan

### Phase 1: DDB Table + Service (4 days)

| File | Change |
|------|--------|
| `scripts/local-ddb-init.py` | Add `kyc_business_cases` table with 3 GSIs |
| `app/core/settings.py` | Add `kyc_business_cases_table_name` setting |
| `app/core/tables.py` | Add `kyc_business_cases` table handle |
| `app/services/kyc_business_cases.py` | New: KYB case store (~450 lines) |

### Phase 2: Router + Models (3 days)

| File | Change |
|------|--------|
| `app/routers/kyc_business.py` | New: 15 endpoints (~400 lines) |
| `app/contracts/kyc_cases_contract.py` | Add: KYB request/response models |
| `app/main.py` | Register `kyc_business_router` |

### Phase 3: Frontend (3 days)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/KybWizard.tsx` | New: business KYC wizard (~350 lines) |
| `frontend/src/api/endpoints/kyc-business.ts` | New: API endpoint wrappers |
| `frontend/src/api/types.ts` | Add KYB types |
| `frontend/src/App.tsx` | Add `/kyc/business` route |

### Phase 4: E2E Tests (3 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-business.spec.ts` | New: ~20 tests, sections 206-209 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-business.spec.ts`)

**Test file**: `frontend/e2e/kyc-business.spec.ts`  
**Total tests**: ~20  
**Sections**: 206-209

### Section 206: Business Case CRUD API (5 tests)

1. `POST /v1/kyc/business-cases creates a draft KYB case` — Verify response has `status: "draft"`, `kyb_case_id` starts with `kyb_`, `company.legal_name` matches input.
2. `GET /v1/kyc/business-cases lists user's business cases` — After creation, list returns at least 1 case.
3. `GET /v1/kyc/business-cases/{id} returns case details` — Verify all company fields present.
4. `PATCH /v1/kyc/business-cases/{id} updates company info` — Update trading_name; verify updated.
5. `Invalid company_type returns 422` — Send `company_type: "invalid"`; verify Pydantic validation error.

### Section 207: UBO & Director Management API (6 tests)

1. `POST /{id}/ubos adds a UBO` — Add UBO with 51% ownership; verify response has `ubo_id`, `ownership_percentage: 51`.
2. `POST /{id}/ubos with personal KYC link` — Add UBO with `personal_kyc_case_id`; verify linked.
3. `DELETE /{id}/ubos/{ubo_id} removes UBO` — Delete UBO; GET ubos returns empty list.
4. `UBO summary updates automatically` — Add 2 UBOs (51% + 49%); verify META `ubo_summary.total_ownership_pct: 100`.
5. `POST /{id}/directors adds a director` — Add director with role "ceo"; verify response.
6. `Ownership percentage > 100 is allowed per UBO (validated on submit)` — Single UBO with 110% passes addition but will fail submit validation.

### Section 208: Document & Address API (5 tests)

1. `POST /{id}/documents attaches certificate of incorporation` — Verify `document_type: "certificate_of_incorporation"`.
2. `POST /{id}/documents with invalid document_type returns 422` — Send `document_type: "invalid"`; verify error.
3. `POST /{id}/addresses sets registered address` — Set address with `address_type: "registered"`; verify stored.
4. `POST /{id}/addresses sets trading address` — Same for trading; both addresses coexist.
5. `Document count increments on META` — After adding 2 documents, META shows `document_count: 2`.

### Section 209: Submit & Admin Review API (4 tests)

1. `POST /{id}/submit without required documents returns error` — Missing certificate_of_incorporation; verify error contains `missing_documents`.
2. `POST /{id}/submit without UBOs returns error` — No UBOs added; verify `no_ubos_added`.
3. `POST /{id}/submit with all requirements transitions to submitted` — Add all required docs, UBOs, addresses; submit; verify `status: "submitted"`.
4. `Admin approve transitions to approved` — Root approves KYB case; verify `status: "approved"`.

### Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});
```

---

## 6. Security Considerations

- Business case ownership is enforced by `user_sub` matching on all user-facing endpoints.
- UBO PII (name, DOB, nationality) is stored in the `kyc_business_cases` table. Retention follows the same policies as personal KYC.
- Admin endpoints require `require_root_session`.
- Company registration numbers and tax IDs are sensitive; they should be treated as PII for retention purposes.
- The `org_id` link allows querying business KYC status for an entire organization but does not grant access to case details.

---

## 7. Rollback Plan

- Remove `app/routers/kyc_business.py` from `app/main.py`.
- The `kyc_business_cases` DDB table can remain (empty or with orphaned records).
- Tier 4 requirement `business_kyc_approved` in KYC-009 would become unachievable, effectively capping max tier at 3.
