# KYC-021: KYC API for Third-Party Integration

**Ticket**: KYC-021
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Depends on**: KYC-011 (Webhooks & Notifications)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The existing KYC system (see `app/routers/kyc_cases.py:48`, prefix `/v1/kyc/cases`) is designed exclusively for the platform's own users and admins, authenticated via UI session cookies or admin sessions. There is no API surface for external partners, third-party services, or white-label integrations to submit KYC applications, upload documents, or query verification status programmatically.

As the platform grows to serve partners who embed the verification flow in their own applications (e.g., a fintech app that uses our KYC infrastructure as a service), a dedicated third-party API is required. This API must:

1. Authenticate via API keys (not session cookies) -- reusing the existing API key infrastructure (see `app/services/api_keys.py`, `app/services/api_key_auth_dependency.py` — both exist).
2. Support the full KYC lifecycle: create application, upload documents, check status, receive webhook callbacks.
3. Enforce per-key rate limits using the existing rate limiting infrastructure (see `app/services/rate_limit.py` — exists).
4. Provide idempotency guarantees for all mutation endpoints (partners may retry failed requests).
5. Offer a sandbox mode for integration testing that returns deterministic mock responses.

### 1.2 How It Works

1. A partner registers for an API key via the platform admin or self-service developer portal.
2. The API key is scoped with `kyc:submit`, `kyc:read`, `kyc:upload` permissions.
3. The partner sends `Authorization: Bearer {api_key}` headers to the `/api/v1/kyc/` endpoints.
4. Each mutation request includes an `Idempotency-Key` header. Duplicate requests with the same key return the original response without re-processing.
5. The partner registers a webhook callback URL. KYC status changes trigger HTTP POST callbacks to this URL with a signed payload.
6. In sandbox mode (`X-Sandbox: true` header or sandbox API key prefix), all responses are deterministic mocks -- useful for partner integration testing.

### 1.3 API Key Scopes

| Scope | Permissions |
|-------|------------|
| `kyc:submit` | Create application, submit for review |
| `kyc:read` | Check status, get verification result |
| `kyc:upload` | Upload documents (ID, selfie, proof of address) |
| `kyc:webhook` | Manage webhook endpoints |
| `kyc:admin` | Full access (intended for internal services) |

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Partner | Submit a KYC application via API | POST creates case, returns application_id |
| Partner | Upload identity documents for an application | POST with multipart document; file attached to case |
| Partner | Check verification status | GET returns current status, decision, reason codes |
| Partner | Receive webhook on status change | Webhook POST sent to registered URL with signed payload |
| Partner | Retry a failed request with same idempotency key | Second request returns original response, no duplicate side effects |
| Partner | Test integration in sandbox mode | Sandbox requests return deterministic mock responses |

---

## 2. Architecture & Data Flow

### 2.1 Request Flow

```
Partner App                 Platform API Gateway              KYC API Service
  │                              │                                  │
  │  POST /api/v1/kyc/applications                                  │
  │  Authorization: Bearer <api_key>                                │
  │  Idempotency-Key: <uuid>     │                                  │
  │─────────────────────────────►│                                  │
  │                              │  1. Extract API key              │
  │                              │  2. Validate scope (kyc:submit)  │
  │                              │  3. Rate limit check             │
  │                              │─────────────────────────────────►│
  │                              │                                  │
  │                              │  4. Check idempotency cache      │
  │                              │     ┌──────────────┐             │
  │                              │     │ DDB: IDEMP#  │             │
  │                              │     │ key_id+hash  │             │
  │                              │     └──────────────┘             │
  │                              │                                  │
  │                              │  5a. Cache HIT → return stored   │
  │                              │  5b. Cache MISS:                 │
  │                              │     6. Check sandbox mode        │
  │                              │     7a. Sandbox → mock response  │
  │                              │     7b. Real → create KYC case   │
  │                              │        ┌─────────────────┐       │
  │                              │        │ DDB: kyc_api_   │       │
  │                              │        │ submissions     │       │
  │                              │        └─────────────────┘       │
  │                              │     8. Store idempotency entry   │
  │                              │     9. Return response           │
  │◄─────────────────────────────│◄────────────────────────────────│
  │  201 { application_id, status: "draft" }                        │
```

### 2.2 Webhook Delivery Flow

```
KYC Status Change Event          Webhook Delivery Service
  │                                    │
  │  status: submitted → approved      │
  │───────────────────────────────────►│
  │                                    │
  │                     1. Look up partner webhooks
  │                        ┌──────────────────┐
  │                        │ DDB: WEBHOOK#    │
  │                        │ partner + events  │
  │                        └──────────────────┘
  │                                    │
  │                     2. Build payload JSON
  │                     3. Sign with HMAC-SHA256 (partner secret)
  │                     4. POST to partner callback URL
  │                        Headers: X-Webhook-Signature
  │                                    │
  │                     5a. Success → log delivery
  │                     5b. Failure → retry (3x exponential backoff)
  │                        5s → 30s → 120s
  │                     5c. All retries fail → log as failed
  │                        ┌──────────────────┐
  │                        │ DDB: WEBHOOK_LOG │
  │                        │ #{event_id}      │
  │                        └──────────────────┘
```

---

## 3. Current State Analysis

### 3.1 API Key Infrastructure

The platform has a mature API key system:

- **`app/services/api_keys.py`**: Key creation, hashing (with `API_KEY_PEPPER` from `app/core/settings.py:45`), revocation, lookup by hash.
- **`app/services/api_key_auth_dependency.py`**: FastAPI dependency that extracts and validates API keys from `Authorization: Bearer` headers.
- **`app/services/api_key_authorization.py`**: Scope-based authorization checks.
- **`app/services/api_key_capabilities.py`**: Feature-capability mapping for API keys.
- **`app/services/api_key_route_scope_registry.py`**: Route-to-scope mapping for policy enforcement.
- **`app/services/api_key_policy_enforcement.py`**: `maybe_enforce_api_key_route_policy` dependency used by existing routers.

API keys are stored in the `api_keys` table (`S.api_keys_table_name`, line 41 in settings) with a `user_sub-index` GSI (`S.api_keys_user_index`, line 44).

### 3.2 Rate Limiting (`app/services/rate_limit.py`)

The `rate_limit_or_429` function (line 17) checks rate limits using the `sessions` table with bucket-based windowing. It accepts `user_sub` and `factor` parameters. For API key rate limiting, `user_sub` would be the partner's API key ID, and `factor` would be `"kyc_api"`.

### 3.3 Existing KYC Case Service (`app/services/kyc_cases.py`)

The `KycCaseStore` class provides the core CRUD operations: `create_case`, `get_case`, `update_case_status`, `submit_case`, etc. The third-party API will delegate to these same service methods, adding a layer of API-key auth, idempotency, and webhook dispatch on top.

### 3.4 Webhook Pattern

The alert system (see `app/services/alerts.py`) supports in-app and email notifications. The webhook system exists (see `app/services/webhook_service.py`, `app/services/webhook_dispatcher.py`) but is not yet wired to KYC events. KYC-011 (Webhooks & Notifications) establishes the webhook infrastructure; this ticket adds the partner webhook management API.

---

## 4. Technical Design

### 4.1 New Router: `app/routers/kyc_api.py`
<!-- NOTE: app/routers/kyc_api.py does not exist yet — new implementation required -->

```python
router = APIRouter(prefix="/api/v1/kyc", tags=["kyc-api"])

# Application lifecycle
POST /applications
  — Create a new KYC application
  — Auth: API key with kyc:submit scope
  — Headers: Idempotency-Key (required)
  — Body: {
      "external_id": str,          # Partner's reference ID
      "applicant": {
        "first_name": str,
        "last_name": str,
        "date_of_birth": str,      # ISO date
        "email": str,
        "phone": str | None,
        "address": { ... }
      },
      "tier": "tier_1" | "tier_2" | "tier_3",
      "metadata": dict | None      # Partner-specific metadata
    }
  — Response 201: {
      "application_id": str,
      "status": "draft",
      "created_at": str
    }

GET /applications/{application_id}
  — Get application status and details
  — Auth: API key with kyc:read scope
  — Response: {
      "application_id": str,
      "external_id": str,
      "status": str,
      "decision": str | None,
      "reason_codes": [...],
      "applicant": { ... },
      "documents": [...],
      "created_at": str,
      "updated_at": str
    }

GET /applications?external_id={external_id}
  — Look up application by partner's external ID
  — Auth: API key with kyc:read scope

POST /applications/{application_id}/submit
  — Submit application for review
  — Auth: API key with kyc:submit scope
  — Headers: Idempotency-Key (required)
  — Response: { "status": "submitted" }

GET /applications/{application_id}/result
  — Get verification result (for approved/rejected cases)
  — Auth: API key with kyc:read scope
  — Response: {
      "decision": "approved" | "rejected",
      "decided_at": str,
      "reason_codes": [...],
      "risk_score": float | None,
      "verified_fields": { ... }
    }

# Document upload
POST /applications/{application_id}/documents
  — Upload a document (multipart/form-data)
  — Auth: API key with kyc:upload scope
  — Headers: Idempotency-Key (required)
  — Body: file + { "document_type": "id_front" | "id_back" | "selfie" | "proof_of_address" }
  — Response 201: { "document_id": str, "file_type": str }

# Webhook management
POST /webhooks
  — Register a webhook endpoint
  — Auth: API key with kyc:webhook scope
  — Body: { "url": str, "events": ["status_changed", "decision_made", "document_uploaded"], "secret": str }
  — Response 201: { "webhook_id": str }

GET /webhooks
  — List registered webhooks
  — Auth: API key with kyc:webhook scope

DELETE /webhooks/{webhook_id}
  — Remove a webhook
  — Auth: API key with kyc:webhook scope

POST /webhooks/{webhook_id}/test
  — Send a test webhook payload
  — Auth: API key with kyc:webhook scope
```

### 4.2 New DynamoDB Table: `kyc_api_submissions`

```
Table: kyc_api_submissions
  PK: partner_id#submission_id (S)  — Composite: API key owner + application ID
  SK: META (S)                      — "META" for main record

  Attributes:
    application_id (S)
    partner_id (S)                  — API key owner user_sub
    api_key_id (S)                  — Which API key was used
    external_id (S)                 — Partner's reference ID
    kyc_case_id (S)                — Linked internal KYC case ID
    status (S)
    tier (S)
    applicant (M)                   — Applicant details map
    metadata (M)                    — Partner-specific metadata
    created_at (N)
    updated_at (N)
    sandbox (BOOL)                  — Whether this is a sandbox submission

  GSI external-id-index:
    PK: partner_id (S)
    SK: external_id (S)
    Projection: ALL

  GSI status-index:
    PK: partner_id (S)
    SK: status (S)
    Projection: KEYS_ONLY
```

**Idempotency key storage:**

```
PK: IDEMPOTENCY#{api_key_id}
SK: {idempotency_key_hash}

Attributes:
  response_status (N)
  response_body (S)              — JSON-serialized response
  created_at (N)
  ttl (N)                        — DDB TTL, 24 hours from creation
```

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    _resolve_table_name(S.kyc_api_submissions_table_name, "kyc_api_submissions"),
    partition_key="pk",
    sort_key="sk",
    gsis=[
        {"index_name": "external-id-index", "partition_key": "partner_id", "sort_key": "external_id"},
        {"index_name": "status-index", "partition_key": "partner_id", "sort_key": "status"},
    ],
    attr_types={"created_at": "N", "updated_at": "N"},
),
```

### 4.3 Detailed DynamoDB Access Patterns

| # | Operation | Table | Key / Index | Condition | Frequency |
|---|-----------|-------|-------------|-----------|-----------|
| 1 | Create application | `kyc_api_submissions` | PK=`{partner_id}#{app_id}`, SK=`META` | `attribute_not_exists(pk)` | Per API call |
| 2 | Get application | `kyc_api_submissions` | PK=`{partner_id}#{app_id}`, SK=`META` | None | Per API call |
| 3 | Lookup by external_id | `kyc_api_submissions` | GSI `external-id-index`, PK=`{partner_id}`, SK=`{external_id}` | None | Per API call |
| 4 | List by status | `kyc_api_submissions` | GSI `status-index`, PK=`{partner_id}`, SK=`{status}` | None | Infrequent |
| 5 | Check idempotency | `kyc_api_submissions` | PK=`IDEMPOTENCY#{key_id}`, SK=`{hash}` | None | Every mutation |
| 6 | Store idempotency | `kyc_api_submissions` | PK=`IDEMPOTENCY#{key_id}`, SK=`{hash}` | `attribute_not_exists(pk)` | Every mutation |
| 7 | Register webhook | `kyc_api_submissions` | PK=`WEBHOOK#{partner_id}`, SK=`WH#{webhook_id}` | None | Rare |
| 8 | Log webhook delivery | `kyc_api_submissions` | PK=`WEBHOOK#{partner_id}`, SK=`LOG#{event_id}` | None | Per status change |

### 4.4 Idempotency Middleware

```python
class IdempotencyGuard:
    def check_and_store(self, *, api_key_id: str, idempotency_key: str,
                         handler: Callable) -> Response:
        """
        1. Hash the idempotency key.
        2. Check DDB for existing response.
        3. If found and not expired, return stored response.
        4. If not found, execute handler, store response, return it.
        5. TTL: 24 hours.
        """
```

Applied as a dependency on all mutation endpoints:

```python
@router.post("/applications")
async def create_application(
    body: CreateApplicationRequest,
    api_key: ApiKeyPrincipal = Depends(require_api_key("kyc:submit")),
    idempotency: str = Header(..., alias="Idempotency-Key"),
):
    return idempotency_guard.check_and_store(
        api_key_id=api_key.key_id,
        idempotency_key=idempotency,
        handler=lambda: _do_create_application(body, api_key),
    )
```

### 4.5 Sandbox Mode

When the request includes `X-Sandbox: true` header or the API key has a `sandbox_` prefix:

```python
class SandboxKycProvider:
    """Returns deterministic mock responses.
    - Application ID: "sandbox_app_{hash(external_id)[:12]}"
    - Status progression: draft -> submitted -> under_review -> approved (each call advances)
    - Documents always validate successfully
    - Webhook test payload uses sandbox application data
    """
```

### 4.6 Webhook Delivery

Webhook delivery follows the pattern established by KYC-011. The partner registers a callback URL and a shared secret. On KYC status changes, the system:

1. Constructs the webhook payload (application_id, event, data, timestamp).
2. Signs the payload with HMAC-SHA256 using the partner's secret.
3. Sends an HTTP POST with the payload and signature in `X-Webhook-Signature` header.
4. Retries on failure: 3 attempts with exponential backoff (5s, 30s, 120s).
5. Failed deliveries are logged in the `kyc_api_submissions` table under `WEBHOOK_LOG#{event_id}` SK.

### 4.7 Rate Limiting

Apply per-API-key rate limits using the existing infrastructure:

```python
def rate_limit_kyc_api(api_key_id: str, endpoint: str) -> None:
    rate_limit_or_429(
        user_sub=f"apikey:{api_key_id}",
        factor=f"kyc_api:{endpoint}",
    )
```

Default limits:
- `POST /applications`: 100/hour per API key
- `POST /documents`: 200/hour per API key
- `GET /applications/*`: 1000/hour per API key
- `POST /webhooks/test`: 10/hour per API key

### 4.8 Registration in `app/main.py`

```python
from app.routers.kyc_api import router as kyc_api_router
app.include_router(kyc_api_router)
```

---

## 5. Pydantic Model Definitions

```python
# --- app/contracts/kyc_api_contract.py ---

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator
import re

class ApplicantAddress(BaseModel):
    street: str = Field(..., min_length=1, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(default="", max_length=100)
    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=2, max_length=2)  # ISO 3166-1 alpha-2

class ApplicantIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    date_of_birth: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    email: str = Field(..., max_length=254)
    phone: Optional[str] = Field(None, max_length=20)
    address: Optional[ApplicantAddress] = None

    @validator("email")
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v.lower().strip()

class CreateApplicationRequest(BaseModel):
    external_id: str = Field(..., min_length=1, max_length=128)
    applicant: ApplicantIn
    tier: str = Field(default="tier_1", pattern=r"^tier_[123]$")
    metadata: Optional[Dict[str, Any]] = None

class ApplicationOut(BaseModel):
    application_id: str
    external_id: str
    status: str
    decision: Optional[str] = None
    reason_codes: List[str] = Field(default_factory=list)
    applicant: Dict[str, Any] = Field(default_factory=dict)
    documents: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str
    sandbox: bool = False

class ApplicationResultOut(BaseModel):
    decision: str  # "approved" | "rejected"
    decided_at: str
    reason_codes: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = None
    verified_fields: Dict[str, Any] = Field(default_factory=dict)

class WebhookRegisterIn(BaseModel):
    url: str = Field(..., min_length=10, max_length=2048)
    events: List[str] = Field(..., min_length=1)
    secret: str = Field(..., min_length=16, max_length=128)

    @validator("url")
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("https://", "http://localhost")):
            raise ValueError("Webhook URL must use HTTPS (or http://localhost in dev)")
        return v

    @validator("events", each_item=True)
    def validate_events(cls, v: str) -> str:
        allowed = {"status_changed", "decision_made", "document_uploaded"}
        if v not in allowed:
            raise ValueError(f"Invalid event: {v}. Allowed: {', '.join(allowed)}")
        return v

class WebhookOut(BaseModel):
    webhook_id: str
    url: str
    events: List[str]
    created_at: str

class IdempotencyConflictOut(BaseModel):
    detail: str = "Idempotency key used with different request body"
    original_request_hash: str
```

---

## 6. API Request/Response Examples

### 6.1 Create Application

**Request:**
```http
POST /api/v1/kyc/applications HTTP/1.1
Host: api.platform.com
Authorization: Bearer kyk_live_a1b2c3d4e5f6
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json

{
  "external_id": "partner-ref-2026-0529-001",
  "applicant": {
    "first_name": "Jane",
    "last_name": "Doe",
    "date_of_birth": "1992-03-15",
    "email": "jane.doe@example.com",
    "phone": "+14155551234",
    "address": {
      "street": "123 Main St",
      "city": "San Francisco",
      "state": "CA",
      "postal_code": "94105",
      "country": "US"
    }
  },
  "tier": "tier_2",
  "metadata": { "partner_user_id": "usr_98765", "source": "mobile_app" }
}
```

**Response (201):**
```json
{
  "application_id": "kycapp_a1b2c3d4e5f6789012345678",
  "status": "draft",
  "created_at": "2026-05-29T14:30:00Z"
}
```

### 6.2 Get Application Status

**Request:**
```http
GET /api/v1/kyc/applications/kycapp_a1b2c3d4e5f6789012345678 HTTP/1.1
Authorization: Bearer kyk_live_a1b2c3d4e5f6
```

**Response (200):**
```json
{
  "application_id": "kycapp_a1b2c3d4e5f6789012345678",
  "external_id": "partner-ref-2026-0529-001",
  "status": "under_review",
  "decision": null,
  "reason_codes": [],
  "applicant": {
    "first_name": "Jane",
    "last_name": "Doe",
    "date_of_birth": "1992-03-15",
    "email": "jane.doe@example.com"
  },
  "documents": [
    {
      "document_id": "doc_abc123",
      "document_type": "id_front",
      "file_type": "image/jpeg",
      "uploaded_at": "2026-05-29T14:35:00Z"
    }
  ],
  "created_at": "2026-05-29T14:30:00Z",
  "updated_at": "2026-05-29T14:40:00Z"
}
```

### 6.3 Webhook Payload

```json
{
  "event": "decision_made",
  "timestamp": "2026-05-29T15:00:00Z",
  "data": {
    "application_id": "kycapp_a1b2c3d4e5f6789012345678",
    "external_id": "partner-ref-2026-0529-001",
    "status": "approved",
    "decision": "approved",
    "reason_codes": [],
    "risk_score": 0.12
  }
}
```

**Signature header:**
```
X-Webhook-Signature: sha256=a1b2c3d4e5f6...
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Detail | Recovery |
|---|----------|-------------|------------|--------|----------|
| 1 | Missing Authorization header | 401 | `kyc_api_unauthorized` | "API key required" | Add Bearer token |
| 2 | Invalid/revoked API key | 401 | `kyc_api_unauthorized` | "Invalid or revoked API key" | Obtain new key |
| 3 | API key lacks required scope | 403 | `kyc_api_forbidden` | "Key does not have kyc:submit scope" | Request scope upgrade |
| 4 | Missing Idempotency-Key header | 400 | `kyc_api_missing_idempotency` | "Idempotency-Key header required" | Add header |
| 5 | Idempotency key body mismatch | 409 | `kyc_api_idempotency_conflict` | "Key used with different request body" | Use new key |
| 6 | Application not found | 404 | `kyc_api_application_not_found` | "Application not found for this partner" | Verify ID |
| 7 | Duplicate external_id | 409 | `kyc_api_duplicate_external_id` | "External ID already exists" | Use unique ID |
| 8 | Application not submittable | 409 | `kyc_api_submission_not_ready` | "Application is in {status} state" | Complete requirements |
| 9 | Rate limit exceeded | 429 | `kyc_api_rate_limited` | "Rate limit exceeded. Retry after {N}s" | Backoff and retry |
| 10 | Invalid document type | 400 | `kyc_api_invalid_document_type` | "Document type must be one of: ..." | Fix document_type |
| 11 | Webhook URL unreachable | 400 | `kyc_api_webhook_url_invalid` | "Webhook URL validation failed" | Fix URL |
| 12 | Sandbox not available | 400 | `kyc_api_sandbox_unavailable` | "Sandbox mode not enabled for this key" | Request sandbox key |

---

## 8. Frontend Component Tree

This ticket is primarily API-focused, but includes a partner developer portal page.

```
DeveloperPortalPage
├── PageHeader
│   ├── Title: "KYC API Integration"
│   └── Subtitle: "Manage API keys, webhooks, and test sandbox"
├── Card: "API Keys"
│   ├── ApiKeyList
│   │   └── For each key:
│   │       ├── Key ID (truncated)
│   │       ├── Scopes badges
│   │       ├── Created date
│   │       ├── Last used date
│   │       └── Button: "Revoke"
│   └── Button: "Create API Key" → CreateApiKeyDialog
├── Card: "Webhooks"
│   ├── WebhookList
│   │   └── For each webhook:
│   │       ├── URL
│   │       ├── Events badges
│   │       ├── Button: "Test"
│   │       └── Button: "Delete"
│   └── Button: "Add Webhook" → AddWebhookDialog
├── Card: "Sandbox Testing"
│   ├── SandboxStatusBadge
│   ├── Button: "Create Sandbox Application"
│   └── SandboxLogTable (recent sandbox requests)
└── Card: "API Documentation"
    └── Link to OpenAPI spec
```

### 8.1 Props Interfaces

```typescript
interface ApiKeyListProps {
  keys: ApiKeyInfo[];
  onRevoke: (keyId: string) => void;
}

interface WebhookListProps {
  webhooks: WebhookInfo[];
  onTest: (webhookId: string) => void;
  onDelete: (webhookId: string) => void;
}

interface CreateApiKeyDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: (key: ApiKeyInfo) => void;
  availableScopes: string[];
}
```

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_api_requests_total` | Counter | `endpoint`, `status_code`, `partner_id` | Total API requests |
| `kyc_api_request_duration_seconds` | Histogram | `endpoint` | Request latency |
| `kyc_api_idempotency_hits_total` | Counter | `endpoint` | Idempotency cache hits |
| `kyc_api_webhook_deliveries_total` | Counter | `event`, `outcome` | Webhook delivery attempts |
| `kyc_api_sandbox_requests_total` | Counter | `endpoint` | Sandbox mode requests |

### 9.2 Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc_api.application_created` | INFO | `application_id`, `partner_id`, `tier`, `sandbox` | New application |
| `kyc_api.application_submitted` | INFO | `application_id`, `partner_id` | Submitted for review |
| `kyc_api.webhook_delivered` | INFO | `webhook_id`, `event`, `response_code` | Successful delivery |
| `kyc_api.webhook_failed` | WARN | `webhook_id`, `event`, `attempt`, `error` | Failed delivery |
| `kyc_api.rate_limited` | WARN | `api_key_id`, `endpoint`, `limit` | Rate limit hit |

### 9.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High webhook failure rate | >10% failures in 1 hour | Warning | Investigate partner webhook endpoints |
| API error rate spike | >5% 5xx in 5 minutes | Critical | Check service health |
| Rate limit exhaustion | >50 keys hitting limits/hour | Warning | Review rate limit settings |

---

## 10. Rollout Plan

### Phase 1: Foundation (Days 1-3)
- **Feature flag**: `KYC_API_ENABLED=false`
- Implement `kyc_api_submissions` table and DDB init
- Implement `IdempotencyGuard` service
- Implement core CRUD endpoints (create, get, list, submit)
- Unit tests for idempotency logic

### Phase 2: Documents & Webhooks (Days 4-6)
- Implement document upload endpoint
- Implement webhook registration, listing, deletion
- Implement webhook delivery with retry logic
- Implement sandbox mode provider

### Phase 3: Integration & Hardening (Days 7-8)
- Wire API key scope validation for all endpoints
- Wire rate limiting per endpoint
- Add partner developer portal page (frontend)
- Integration testing with mock partner

### Phase 4: GA (Days 9-10)
- **Feature flag**: `KYC_API_ENABLED=true`
- E2E test suite
- Performance testing (100 concurrent requests)
- Documentation in OpenAPI spec
- Monitor webhook delivery success rate for first 24 hours

---

## 11. Performance Considerations

### 11.1 Latency Targets

| Operation | P50 Target | P99 Target | Notes |
|-----------|-----------|-----------|-------|
| Create application | <200ms | <500ms | Single DDB put + idempotency check |
| Get application | <100ms | <300ms | Single DDB get |
| Upload document | <500ms | <2000ms | S3 upload dominates |
| Idempotency check | <50ms | <150ms | Single DDB get |
| Webhook delivery | <2000ms | <5000ms | Async; partner endpoint latency |

### 11.2 Caching Strategy

- **Idempotency entries**: 24-hour TTL in DDB; no additional cache needed
- **API key lookups**: Cached per-request (FastAPI dependency injection)
- **Webhook endpoints**: Cached in memory for 5 minutes (avoid DDB query per webhook delivery)

### 11.3 Pagination

- `GET /applications` returns max 50 items per page with cursor-based pagination
- Webhook logs paginated with 100 items per page
- All pagination uses DDB `LastEvaluatedKey` via `app/core/cursor.py` (see `app/core/cursor.py` — exists)

---

## 12. E2E Test Plan

**Test file**: `frontend/e2e/kyc-api.spec.ts`
**Total**: ~28 tests across 6 sections (228-233)

### Section 228: Application Lifecycle API (6 tests)

```typescript
test("228.1 Create application with valid API key", async ({ request }) => {
  // POST /api/v1/kyc/applications with Bearer API key
  // Headers: Idempotency-Key: uuid
  // Expect 201 with application_id, status="draft"
});

test("228.2 Get application by ID", async ({ request }) => {
  // GET /api/v1/kyc/applications/{application_id}
  // Expect 200 with full application details
});

test("228.3 Look up application by external_id", async ({ request }) => {
  // GET /api/v1/kyc/applications?external_id=partner-ref-123
  // Expect matching application
});

test("228.4 Submit application transitions to submitted", async ({ request }) => {
  // POST /api/v1/kyc/applications/{id}/submit
  // Expect status="submitted"
});

test("228.5 Duplicate idempotency key returns original response", async ({ request }) => {
  // POST /applications with same Idempotency-Key as 228.1
  // Expect same application_id as 228.1 (no new case created)
});

test("228.6 Missing API key returns 401", async ({ request }) => {
  // POST /applications without Authorization header
  // Expect 401
});
```

### Section 229: Document Upload & Webhook Management (5 tests)

```typescript
test("229.1 Upload document with valid file and type", async ({ request }) => {
  // POST /api/v1/kyc/applications/{id}/documents
  // Multipart with PDF file, document_type="id_front"
  // Expect 201 with document_id
});

test("229.2 Upload with invalid document_type returns 400", async ({ request }) => {
  // document_type="invalid_type" -> 400
});

test("229.3 Register webhook endpoint", async ({ request }) => {
  // POST /api/v1/kyc/webhooks with url and events
  // Expect 201 with webhook_id
});

test("229.4 List registered webhooks", async ({ request }) => {
  // GET /api/v1/kyc/webhooks
  // Expect array containing registered webhook
});

test("229.5 Delete webhook", async ({ request }) => {
  // DELETE /api/v1/kyc/webhooks/{webhook_id}
  // GET webhooks -> webhook no longer in list
});
```

### Section 230: Sandbox Mode & Rate Limiting (4 tests)

```typescript
test("230.1 Sandbox request returns deterministic mock response", async ({ request }) => {
  // POST /applications with X-Sandbox: true header
  // Expect application_id starts with "sandbox_app_"
});

test("230.2 Sandbox submit returns approved status", async ({ request }) => {
  // Submit sandbox application
  // GET result -> decision="approved" (mock auto-approves)
});

test("230.3 Rate limit enforced per API key", async ({ request }) => {
  // Send 101 POST /applications in quick succession
  // Expect 429 on the 101st request (exceeds 100/hour limit)
  // Note: In practice, test sends a smaller burst and verifies rate_limit_or_429 is called
});

test("230.4 API key without kyc:submit scope cannot create application", async ({ request }) => {
  // API key with only kyc:read scope
  // POST /applications -> 403
});
```

### Section 231: Idempotency Edge Cases (5 tests)

```typescript
test("231.1 Same idempotency key with different body returns 409", async ({ request }) => {
  // POST /applications with Idempotency-Key from 228.1 but different body
  // Expect 409 with kyc_api_idempotency_conflict
});

test("231.2 Idempotency key is per-API-key scoped", async ({ request }) => {
  // Use same Idempotency-Key value with a different API key
  // Expect new application created (not a conflict)
});

test("231.3 Expired idempotency key allows re-use", async ({ request }) => {
  // Manually expire the idempotency DDB item (set TTL to past)
  // Re-send with same key → new application created
});

test("231.4 Document upload respects idempotency", async ({ request }) => {
  // Upload doc with Idempotency-Key; re-upload same key → same doc_id
});

test("231.5 Missing Idempotency-Key on mutation returns 400", async ({ request }) => {
  // POST /applications without Idempotency-Key header
  // Expect 400
});
```

### Section 232: Application Verification Result (4 tests)

```typescript
test("232.1 Get result for approved application", async ({ request }) => {
  // After sandbox auto-approval:
  // GET /applications/{id}/result
  // Expect decision="approved", decided_at set, risk_score present
});

test("232.2 Get result for pending application returns 404", async ({ request }) => {
  // Application in draft status
  // GET result → 404 (no decision yet)
});

test("232.3 Application includes document list", async ({ request }) => {
  // GET application after document upload
  // documents array includes uploaded document with document_id, file_type
});

test("232.4 External ID lookup returns correct application", async ({ request }) => {
  // GET /applications?external_id={value}
  // Expect matching application with correct external_id
});
```

### Section 233: Webhook Delivery & Testing (4 tests)

```typescript
test("233.1 Test webhook sends payload to registered URL", async ({ request }) => {
  // POST /webhooks/{id}/test
  // Expect 200 with test delivery result
});

test("233.2 Webhook secret must be >= 16 characters", async ({ request }) => {
  // POST /webhooks with secret="short"
  // Expect 422 validation error
});

test("233.3 Webhook URL must use HTTPS", async ({ request }) => {
  // POST /webhooks with url="http://insecure.example.com"
  // Expect 400 or 422
});

test("233.4 Webhook events must be valid event names", async ({ request }) => {
  // POST /webhooks with events=["invalid_event"]
  // Expect 422
});
```

---

## 13. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/routers/kyc_api.py` | **New** | Third-party KYC API router with all endpoints |
| `app/services/kyc_api_service.py` | **New** | Application mapping, idempotency guard, sandbox provider |
| `app/services/kyc_webhook_delivery.py` | **New** | Webhook payload signing, HTTP delivery, retry logic |
| `app/contracts/kyc_api_contract.py` | **New** | Request/response models for third-party API |
| `app/core/settings.py` | Modify | Add `kyc_api_submissions_table_name`, rate limit settings |
| `app/core/tables.py` | Modify | Add `kyc_api_submissions` table handle |
| `app/main.py` | Modify | Register `kyc_api_router` |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_api_submissions` table definition |
| `app/services/api_key_route_scope_registry.py` | Modify | Register `kyc:*` scopes |
| `app/services/rate_limit.py` | Modify | Add `kyc_api` factor limits |
| `frontend/e2e/kyc-api.spec.ts` | **New** | 28 E2E tests across sections 228-233 |

---

## 14. API Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `kyc_api_unauthorized` | 401 | Missing or invalid API key |
| `kyc_api_forbidden` | 403 | API key lacks required scope |
| `kyc_api_application_not_found` | 404 | Application ID not found for this partner |
| `kyc_api_duplicate_external_id` | 409 | External ID already exists for this partner |
| `kyc_api_invalid_document_type` | 400 | Document type not in allowed set |
| `kyc_api_submission_not_ready` | 409 | Application not in submittable state |
| `kyc_api_rate_limited` | 429 | Rate limit exceeded for this API key |
| `kyc_api_idempotency_conflict` | 409 | Idempotency key used with different request body |
| `kyc_api_webhook_url_invalid` | 400 | Webhook URL unreachable or invalid format |
| `kyc_api_missing_idempotency` | 400 | Idempotency-Key header required for mutations |
| `kyc_api_sandbox_unavailable` | 400 | Sandbox mode not enabled for this API key |

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | 48 | Exists |
| API keys service | `app/services/api_keys.py` | -- | Exists |
| API key auth dependency | `app/services/api_key_auth_dependency.py` | -- | Exists |
| API key authorization | `app/services/api_key_authorization.py` | -- | Exists |
| API key capabilities | `app/services/api_key_capabilities.py` | -- | Exists |
| API key route scope registry | `app/services/api_key_route_scope_registry.py` | -- | Exists |
| API key policy enforcement | `app/services/api_key_policy_enforcement.py` | -- | Exists |
| `API_KEY_PEPPER` | `app/core/settings.py` | 45 | Exists |
| Rate limiting | `app/services/rate_limit.py` | -- | Exists |
| KYC case store | `app/services/kyc_cases.py` | 94 | Exists |
| Cursor pagination | `app/core/cursor.py` | -- | Exists |
| Webhook system | `app/services/webhook_service.py` | -- | Exists |
| `app/routers/kyc_api.py` | -- | -- | Does NOT exist — new router required |
| `app/services/kyc_api_service.py` | -- | -- | Does NOT exist — new service required |
| `app/services/kyc_webhook_delivery.py` | -- | -- | Does NOT exist — new service required |
| `app/contracts/kyc_api_contract.py` | -- | -- | Does NOT exist — new contracts required |

---

## Testing Strategy

### Unit Tests (`tests/test_kyc_api.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_create_application_stores_record` | Create application stores record |
| 2 | `test_get_application_by_id` | Get application by id |
| 3 | `test_lookup_by_external_id` | Lookup by external id |
| 4 | `test_submit_transitions_status` | Submit transitions status |
| 5 | `test_idempotency_returns_existing` | Idempotency returns existing |
| 6 | `test_idempotency_conflict_different_body` | Idempotency conflict different body |
| 7 | `test_sandbox_returns_deterministic` | Sandbox returns deterministic |
| 8 | `test_webhook_register_stores` | Webhook register stores |
| 9 | `test_rate_limit_enforced` | Rate limit enforced |
| 10 | `test_scope_validation_rejects_missing` | Scope validation rejects missing |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/kyc-api.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~28 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `KYC_API_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| KYC-011 | Webhooks & Notifications for webhook delivery | Hard |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Feature-flag-gated -- KYC_API_ENABLED=false by default. New router at /api/v1/kyc with no overlap to existing /v1/kyc/cases prefix.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: KYC_API_ENABLED=true
- [ ] Service file created/modified: `app/services/kyc_api_service.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/kyc-api.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_kyc_api.py`
