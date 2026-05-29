# KYC-021: KYC API for Third-Party Integration

**Ticket**: KYC-021
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Depends on**: KYC-011 (Webhooks & Notifications)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The existing KYC system (`app/routers/kyc_cases.py`, prefix `/v1/kyc/cases`) is designed exclusively for the platform's own users and admins, authenticated via UI session cookies or admin sessions. There is no API surface for external partners, third-party services, or white-label integrations to submit KYC applications, upload documents, or query verification status programmatically.

As the platform grows to serve partners who embed the verification flow in their own applications (e.g., a fintech app that uses our KYC infrastructure as a service), a dedicated third-party API is required. This API must:

1. Authenticate via API keys (not session cookies) -- reusing the existing API key infrastructure (`app/services/api_keys.py`, `app/services/api_key_auth_dependency.py`).
2. Support the full KYC lifecycle: create application, upload documents, check status, receive webhook callbacks.
3. Enforce per-key rate limits using the existing rate limiting infrastructure (`app/services/rate_limit.py`).
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

## 2. Current State Analysis

### 2.1 API Key Infrastructure

The platform has a mature API key system:

- **`app/services/api_keys.py`**: Key creation, hashing (with `API_KEY_PEPPER` from `app/core/settings.py`, line 45), revocation, lookup by hash.
- **`app/services/api_key_auth_dependency.py`**: FastAPI dependency that extracts and validates API keys from `Authorization: Bearer` headers.
- **`app/services/api_key_authorization.py`**: Scope-based authorization checks.
- **`app/services/api_key_capabilities.py`**: Feature-capability mapping for API keys.
- **`app/services/api_key_route_scope_registry.py`**: Route-to-scope mapping for policy enforcement.
- **`app/services/api_key_policy_enforcement.py`**: `maybe_enforce_api_key_route_policy` dependency used by existing routers.

API keys are stored in the `api_keys` table (`S.api_keys_table_name`, line 41 in settings) with a `user_sub-index` GSI (`S.api_keys_user_index`, line 44).

### 2.2 Rate Limiting (`app/services/rate_limit.py`)

The `rate_limit_or_429` function (line 17) checks rate limits using the `sessions` table with bucket-based windowing. It accepts `user_sub` and `factor` parameters. For API key rate limiting, `user_sub` would be the partner's API key ID, and `factor` would be `"kyc_api"`.

### 2.3 Existing KYC Case Service (`app/services/kyc_cases.py`)

The `KycCaseStore` class provides the core CRUD operations: `create_case`, `get_case`, `update_case_status`, `submit_case`, etc. The third-party API will delegate to these same service methods, adding a layer of API-key auth, idempotency, and webhook dispatch on top.

### 2.4 Webhook Pattern

The alert system (`app/services/alerts.py`) supports in-app and email notifications. There is no HTTP webhook delivery mechanism yet. KYC-011 (Webhooks & Notifications) establishes the webhook infrastructure; this ticket adds the partner webhook management API.

---

## 3. Technical Design

### 3.1 New Router: `app/routers/kyc_api.py`

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

### 3.2 New DynamoDB Table: `kyc_api_submissions`

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

### 3.3 Idempotency Middleware

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

### 3.4 Sandbox Mode

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

### 3.5 Webhook Delivery

Webhook delivery follows the pattern established by KYC-011. The partner registers a callback URL and a shared secret. On KYC status changes, the system:

1. Constructs the webhook payload (application_id, event, data, timestamp).
2. Signs the payload with HMAC-SHA256 using the partner's secret.
3. Sends an HTTP POST with the payload and signature in `X-Webhook-Signature` header.
4. Retries on failure: 3 attempts with exponential backoff (5s, 30s, 120s).
5. Failed deliveries are logged in the `kyc_api_submissions` table under `WEBHOOK_LOG#{event_id}` SK.

### 3.6 Rate Limiting

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

### 3.7 Registration in `app/main.py`

```python
from app.routers.kyc_api import router as kyc_api_router
app.include_router(kyc_api_router)
```

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-api.spec.ts`
**Total**: ~15 tests across 3 sections (228-230)

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

---

## 5. File Change Summary

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
| `frontend/e2e/kyc-api.spec.ts` | **New** | 15 E2E tests across sections 228-230 |

---

## 6. API Error Codes

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
