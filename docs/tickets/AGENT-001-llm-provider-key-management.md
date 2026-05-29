# AGENT-001: LLM Provider Key Management

**Ticket**: AGENT-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 6-8 days
**Dependencies**: None (uses existing KMS encryption in `app/core/crypto.py`)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-001 provides a secure key vault for storing and managing API keys from multiple LLM providers (OpenAI, Anthropic/Claude, DeepSeek, Google Gemini, and custom OpenAI-compatible endpoints). These keys are the credentials that autonomous AI coding agents use to call LLM APIs when working through tickets. Keys are encrypted at rest using the existing KMS infrastructure (`app/core/crypto.py`), and each key carries metadata for provider routing, model preference, rate limits, and monthly budget caps.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to add my Anthropic API key so that my worker agents can use Claude to solve coding tickets. | POST key with provider=anthropic; key encrypted at rest; key appears in list. |
| User | As a user, I want to test that my API key works before assigning it to an agent so that I don't waste time debugging auth failures. | Click "Test"; backend makes a lightweight API call to the provider; returns success/failure + model list. |
| User | As a user, I want to set a monthly budget cap on each key so that a runaway agent doesn't exhaust my API credits. | Set `monthly_budget_cents`; backend tracks usage; agents stop when budget exceeded. |
| User | As a user, I want to rotate an API key without reconfiguring every agent that uses it so that key rotation is seamless. | Rotate key: old key marked inactive, new key assigned to same key_id; agents continue without config change. |
| User | As a user, I want to check my remaining balance/usage for an OpenAI key so that I can monitor spend. | GET usage endpoint; backend queries provider usage API; returns remaining balance where supported. |
| User | As a user, I want to add a custom OpenAI-compatible endpoint so that I can use self-hosted models (vLLM, Ollama). | POST key with provider=custom, base_url, model_name; test validates custom endpoint. |
| User | As a user, I want to assign specific keys to specific worker agents so that different agents can use different providers/models. | Worker config references key_id; agent startup injects the correct API key. |
| Admin | As an admin, I want to see all LLM keys across users for audit purposes so that I can monitor platform-wide LLM usage. | Admin endpoint returns all keys with usage stats (keys themselves are never exposed). |

### 1.3 Why This Is Needed

The Agent Orchestration Platform (AGENT-002 through AGENT-007) requires LLM API keys to power autonomous coding agents. Users bring their own keys (BYOK model) and need a secure way to store, test, rotate, and assign them to agents. Without centralized key management, users would need to manually paste keys into terminal sessions every time an agent spins up, which is error-prone, insecure (keys visible in terminal history), and blocks automated agent provisioning.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| KMS encrypt/decrypt | `app/core/crypto.py` | `kms_encrypt(plaintext) -> str`, `kms_decrypt(ct_b64) -> bytes`; used for encrypting LLM API keys at rest |
| API key service | `app/services/api_keys.py` (~400 lines) | Platform API key management; provides patterns for key hashing, CRUD, capabilities; LLM keys follow a similar but separate pattern |
| API key router | `app/routers/api_keys.py` | Platform API key endpoints; reference for router structure |
| Settings | `app/core/settings.py` | Configuration singleton `S`; will add `llm_provider_keys_table_name` |
| Tables | `app/core/tables.py` | DynamoDB table handles; will add `T.llm_provider_keys` |
| Mock KMS server | `scripts/mock_kms_server.py` (port 7999) | Provides KMS encrypt/decrypt in dev mode |
| Auth deps | `app/auth/deps.py` | `require_ui_session` for cookie auth; `require_admin_session` for admin endpoints |

### 2.2 Gaps

1. **No LLM key storage** -- the platform stores platform API keys but has no concept of third-party LLM provider keys.
2. **No key testing** -- no mechanism to validate a third-party API key by making a probe call.
3. **No usage tracking** -- no per-key usage or budget enforcement for external API keys.
4. **No provider abstraction** -- no registry of LLM provider configurations (endpoints, auth headers, model lists).
5. **No key-to-worker assignment** -- no way to bind an LLM key to a specific agent worker instance.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `llm_provider_keys`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.llm_provider_keys_table_name, "llm_provider_keys"),
    "pk",              # USER#{user_id}
    "sk",              # KEY#{key_id}
    gsis=[
        {"index_name": "ByProvider", "partition_key": "pk", "sort_key": "provider"},
        {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S (PK) | `USER#{user_id}` |
| `sk` | S (SK) | `KEY#{key_id}` |
| `key_id` | S | UUID hex identifier |
| `user_id` | S | Owner user_sub |
| `provider` | S | `openai`, `anthropic`, `deepseek`, `gemini`, `custom` |
| `label` | S | User-assigned name (e.g., "My Anthropic Production Key") |
| `encrypted_api_key` | S | KMS-encrypted API key (base64 ciphertext) |
| `key_suffix` | S | Last 4 characters of the API key (for display: `...xK7m`) |
| `base_url` | S | Provider API base URL (required for custom; default for known providers) |
| `model_preference` | S | Preferred model ID (e.g., `claude-sonnet-4-20250514`, `gpt-4o`) |
| `available_models` | L | List of models discovered during key test |
| `rate_limit_rpm` | N | Provider-side rate limit (requests per minute); user-reported or discovered |
| `monthly_budget_cents` | N | Max monthly spend in cents (0 = unlimited) |
| `current_month_usage_cents` | N | Accumulated usage this billing month |
| `usage_reset_at` | N | Unix timestamp when `current_month_usage_cents` resets |
| `total_requests` | N | Lifetime request count |
| `total_tokens_used` | N | Lifetime token count |
| `status` | S | `active`, `inactive`, `budget_exceeded`, `invalid` |
| `last_tested_at` | N | Unix timestamp of last successful test |
| `last_used_at` | N | Unix timestamp of last agent usage |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `assigned_worker_ids` | L | List of worker IDs this key is assigned to |

### 3.2 Provider Registry

```python
# In app/services/llm_provider_keys.py

PROVIDER_REGISTRY = {
    "openai": {
        "display_name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "test_endpoint": "/models",
        "test_method": "GET",
        "usage_endpoint": "/usage",
        "models": ["gpt-4o", "gpt-4o-mini", "o3", "o4-mini", "codex-mini-latest"],
    },
    "anthropic": {
        "display_name": "Anthropic (Claude)",
        "base_url": "https://api.anthropic.com/v1",
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "test_endpoint": "/models",
        "test_method": "GET",
        "extra_headers": {"anthropic-version": "2023-06-01"},
        "models": ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-3-5-20241022"],
    },
    "deepseek": {
        "display_name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
    },
    "gemini": {
        "display_name": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "auth_header": "x-goog-api-key",
        "auth_prefix": "",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
    },
    "custom": {
        "display_name": "Custom (OpenAI-compatible)",
        "base_url": "",  # User-provided
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": [],
    },
}
```

### 3.3 Backend Service

**New file**: `app/services/llm_provider_keys.py` (~450 lines)

```python
"""LLM Provider Key Management service (AGENT-001).

Secure storage, testing, rotation, and assignment of third-party
LLM API keys for use by autonomous agent workers.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def add_key(
    *,
    user_id: str,
    provider: str,
    label: str,
    api_key: str,
    base_url: str = "",
    model_preference: str = "",
    rate_limit_rpm: int = 60,
    monthly_budget_cents: int = 0,
) -> Dict[str, Any]:
    """Add a new LLM provider key.

    Encrypts the API key at rest using KMS. Validates provider
    is in the registry (or 'custom' with base_url).
    """
    if provider not in PROVIDER_REGISTRY:
        raise ValueError(f"Unknown provider: {provider}")
    if provider == "custom" and not base_url:
        raise ValueError("base_url is required for custom provider")

    key_id = uuid4().hex
    encrypted = kms_encrypt(api_key)
    key_suffix = api_key[-4:] if len(api_key) >= 4 else "****"
    ts = now_ts()

    item = {
        "pk": f"USER#{user_id}",
        "sk": f"KEY#{key_id}",
        "key_id": key_id,
        "user_id": user_id,
        "provider": provider,
        "label": label,
        "encrypted_api_key": encrypted,
        "key_suffix": key_suffix,
        "base_url": base_url or PROVIDER_REGISTRY[provider]["base_url"],
        "model_preference": model_preference,
        "available_models": [],
        "rate_limit_rpm": rate_limit_rpm,
        "monthly_budget_cents": monthly_budget_cents,
        "current_month_usage_cents": 0,
        "usage_reset_at": 0,
        "total_requests": 0,
        "total_tokens_used": 0,
        "status": "active",
        "last_tested_at": 0,
        "last_used_at": 0,
        "created_at": ts,
        "updated_at": ts,
        "assigned_worker_ids": [],
    }
    T.llm_provider_keys.put_item(Item=item)
    return _safe_out(item)


def list_keys(user_id: str) -> List[Dict[str, Any]]:
    """List all LLM keys for a user. Never returns the encrypted key."""
    resp = T.llm_provider_keys.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "KEY#"},
    )
    return [_safe_out(item) for item in resp.get("Items", [])]


def get_key(user_id: str, key_id: str) -> Dict[str, Any] | None:
    """Get a single key by ID. Never returns the encrypted key."""
    resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = resp.get("Item")
    return _safe_out(item) if item else None


def get_decrypted_api_key(user_id: str, key_id: str) -> str:
    """Decrypt and return the raw API key. Internal use only (agent provisioning)."""
    resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise ValueError("Key not found")
    if item.get("status") != "active":
        raise ValueError(f"Key is not active (status: {item['status']})")
    return kms_decrypt(item["encrypted_api_key"]).decode("utf-8")


def test_key(user_id: str, key_id: str) -> Dict[str, Any]:
    """Test an LLM key by making a lightweight probe call to the provider.

    For known providers, calls the /models endpoint.
    Returns: {ok: bool, models: [...], error: str, latency_ms: int}
    """
    # 1. Decrypt key
    # 2. Look up provider config from PROVIDER_REGISTRY
    # 3. Make HTTP GET to test_endpoint with auth header
    # 4. Parse response for model list
    # 5. Update last_tested_at and available_models
    # 6. If error, set status to "invalid"
    # In dev mode: return mock success with provider's default models


def rotate_key(
    user_id: str,
    key_id: str,
    new_api_key: str,
) -> Dict[str, Any]:
    """Rotate an API key in-place. Encrypts new key, keeps same key_id.

    Assigned workers continue using the same key_id reference.
    """
    encrypted = kms_encrypt(new_api_key)
    key_suffix = new_api_key[-4:] if len(new_api_key) >= 4 else "****"
    ts = now_ts()

    T.llm_provider_keys.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="SET encrypted_api_key = :ek, key_suffix = :ks, "
                        "updated_at = :ts, #st = :active",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":ek": encrypted, ":ks": key_suffix,
            ":ts": ts, ":active": "active",
        },
    )
    return get_key(user_id, key_id)


def delete_key(user_id: str, key_id: str) -> None:
    """Delete an LLM provider key permanently."""
    T.llm_provider_keys.delete_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )


def check_usage(user_id: str, key_id: str) -> Dict[str, Any]:
    """Check provider-side usage/balance where supported.

    OpenAI: GET /dashboard/billing/usage
    Others: return local tracking only.
    """
    # 1. Decrypt key
    # 2. If provider supports usage endpoint, query it
    # 3. Return merged local + provider usage data
    # In dev mode: return mock usage data


def record_usage(
    user_id: str,
    key_id: str,
    *,
    tokens: int,
    cost_cents: int,
) -> None:
    """Record token usage and cost from an agent session.

    Called by AGENT-003 after each LLM API call. Enforces budget.
    """
    T.llm_provider_keys.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="ADD total_requests :one, total_tokens_used :tok, "
                        "current_month_usage_cents :cost "
                        "SET last_used_at = :ts",
        ExpressionAttributeValues={
            ":one": 1, ":tok": tokens, ":cost": cost_cents, ":ts": now_ts(),
        },
    )
    # Check budget and set status to budget_exceeded if needed


def assign_key_to_worker(user_id: str, key_id: str, worker_id: str) -> None:
    """Associate an LLM key with a worker agent."""
    # Append worker_id to assigned_worker_ids list


def unassign_key_from_worker(user_id: str, key_id: str, worker_id: str) -> None:
    """Remove worker association from an LLM key."""
    # Remove worker_id from assigned_worker_ids list


def _safe_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Strip encrypted_api_key from output. Never expose raw/encrypted keys."""
    out = {k: v for k, v in item.items() if k not in ("encrypted_api_key", "pk", "sk")}
    return out
```

### 3.4 Backend Router

**New file**: `app/routers/llm_provider_keys.py` (~200 lines)

Prefix: `/ui/agent/llm-keys`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/agent/llm-keys` | `require_ui_session` | Add a new LLM provider key |
| `GET` | `/ui/agent/llm-keys` | `require_ui_session` | List user's LLM keys |
| `GET` | `/ui/agent/llm-keys/{key_id}` | `require_ui_session` | Get key details |
| `POST` | `/ui/agent/llm-keys/{key_id}/test` | `require_ui_session` | Test key connectivity |
| `POST` | `/ui/agent/llm-keys/{key_id}/rotate` | `require_ui_session` | Rotate key value |
| `DELETE` | `/ui/agent/llm-keys/{key_id}` | `require_ui_session` | Delete key |
| `GET` | `/ui/agent/llm-keys/{key_id}/usage` | `require_ui_session` | Check usage/balance |
| `GET` | `/ui/agent/llm-providers` | `require_ui_session` | List supported providers with metadata |
| `POST` | `/ui/agent/llm-keys/{key_id}/assign` | `require_ui_session` | Assign key to a worker |
| `DELETE` | `/ui/agent/llm-keys/{key_id}/assign/{worker_id}` | `require_ui_session` | Unassign key from worker |
| `GET` | `/ui/admin/agent/llm-keys` | `require_admin_session` | Admin: list all keys across users |

### 3.5 Pydantic Models

**Add to `app/models.py`**:

```python
# -- LLM Provider Keys (AGENT-001) --

class LlmKeyCreateIn(BaseModel):
    provider: str = Field(..., pattern="^(openai|anthropic|deepseek|gemini|custom)$")
    label: str = Field(..., min_length=1, max_length=200)
    api_key: str = Field(..., min_length=8, max_length=500)
    base_url: str = Field(default="", max_length=500)
    model_preference: str = Field(default="", max_length=200)
    rate_limit_rpm: int = Field(default=60, ge=1, le=10000)
    monthly_budget_cents: int = Field(default=0, ge=0)

class LlmKeyRotateIn(BaseModel):
    new_api_key: str = Field(..., min_length=8, max_length=500)

class LlmKeyAssignIn(BaseModel):
    worker_id: str = Field(..., min_length=1)

class LlmKeyOut(BaseModel):
    key_id: str
    provider: str
    label: str
    key_suffix: str = ""
    base_url: str = ""
    model_preference: str = ""
    available_models: List[str] = Field(default_factory=list)
    rate_limit_rpm: int = 60
    monthly_budget_cents: int = 0
    current_month_usage_cents: int = 0
    total_requests: int = 0
    total_tokens_used: int = 0
    status: str = "active"
    last_tested_at: int = 0
    last_used_at: int = 0
    created_at: int = 0
    assigned_worker_ids: List[str] = Field(default_factory=list)

class LlmKeyListOut(BaseModel):
    keys: List[LlmKeyOut]
    count: int

class LlmKeyTestOut(BaseModel):
    ok: bool
    models: List[str] = Field(default_factory=list)
    error: str = ""
    latency_ms: int = 0

class LlmKeyUsageOut(BaseModel):
    key_id: str
    provider: str
    local_usage_cents: int = 0
    local_total_requests: int = 0
    local_total_tokens: int = 0
    provider_balance_cents: Optional[int] = None
    provider_usage_cents: Optional[int] = None
    budget_remaining_cents: Optional[int] = None

class LlmProviderInfo(BaseModel):
    provider: str
    display_name: str
    base_url: str
    models: List[str] = Field(default_factory=list)
    supports_usage_api: bool = False

class LlmProviderListOut(BaseModel):
    providers: List[LlmProviderInfo]
```

### 3.6 Frontend Components

#### LlmKeysPage (`frontend/src/pages/agents/LlmKeysPage.tsx`)

New page (~400 lines):

- **Header**: "LLM API Keys" with "Add Key" button
- **Key table**: DataTable with columns: Label, Provider (icon + name), Model, Status badge, Usage (bar chart if budget set), Last Tested, Actions
- **Status badges**: `active` (green), `inactive` (gray), `budget_exceeded` (red), `invalid` (orange)
- **Actions**: Test, Rotate, Usage, Delete (with confirmation)
- **Empty state**: "No LLM keys configured. Add your first API key to start using AI agents."

#### AddLlmKeyDialog (`frontend/src/pages/agents/AddLlmKeyDialog.tsx`)

Dialog (~250 lines):

- **Step 1**: Provider selector (card grid with provider logos/icons and names)
- **Step 2**: Key configuration -- label, API key (password field with show/hide), model preference dropdown, base_url (for custom), rate limit, monthly budget
- **Add button**: Calls POST, shows test result inline

#### Route & Navigation

```tsx
<Route path="/agents/llm-keys" element={<LlmKeysPage />} />
```

Sidebar: "LLM Keys" with `KeyRound` icon under "AI Agents" group.

---

## 4. Implementation Plan

### Phase 1: Backend Service + DDB (2-3 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `llm_provider_keys_table_name` |
| `app/core/tables.py` | Add `llm_provider_keys` table handle |
| `scripts/local-ddb-init.py` | Add `llm_provider_keys` TableDef with GSIs |
| `app/services/llm_provider_keys.py` | New file: CRUD + test + rotate + usage + assign |
| `app/models.py` | Add LLM key Pydantic models |

### Phase 2: API Router (1-2 days)

| File | Change |
|------|--------|
| `app/routers/llm_provider_keys.py` | New file: 11 endpoints |
| `app/main.py` | Register `llm_provider_keys_router` |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add LLM key TypeScript types |
| `frontend/src/api/endpoints/llmKeys.ts` | New file: API wrappers |
| `frontend/src/pages/agents/LlmKeysPage.tsx` | New file: key management page |
| `frontend/src/pages/agents/AddLlmKeyDialog.tsx` | New file: add key dialog |
| `frontend/src/App.tsx` | Add `/agents/llm-keys` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "AI Agents" group with "LLM Keys" item |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/agent-llm-keys.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-llm-keys.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. Alice is the primary test user.

**Section 623: LLM Provider API (3 tests)**

1. `List supported providers returns registry` -- GET `/ui/agent/llm-providers`. Verify at least 5 providers with `display_name`, `base_url`, `models` populated. Verify `openai`, `anthropic`, `deepseek`, `gemini`, `custom` are present.
2. `Provider info includes correct base URLs` -- Verify `openai` has `base_url` containing `api.openai.com`, `anthropic` has `api.anthropic.com`.
3. `Custom provider has empty base_url` -- Verify `custom` provider entry has `base_url: ""`.

**Section 624: Key CRUD API (5 tests)**

4. `Alice adds an Anthropic API key` -- POST `/ui/agent/llm-keys` with `provider: "anthropic"`, `label: "Test Claude Key"`, `api_key: "sk-ant-test-1234567890abcdef"`. Verify 201 with `key_id`, `provider: "anthropic"`, `key_suffix: "cdef"`, `status: "active"`. Verify `encrypted_api_key` is NOT in response.
5. `Alice adds a custom OpenAI-compatible key` -- POST with `provider: "custom"`, `base_url: "https://my-vllm.example.com/v1"`, `api_key: "custom-key-abc123"`. Verify 201 with `base_url` set.
6. `Alice lists her LLM keys` -- GET `/ui/agent/llm-keys`. Verify `count >= 2`, each key has `key_id`, `provider`, `label`, `key_suffix`.
7. `Alice deletes an LLM key` -- DELETE `/ui/agent/llm-keys/{key_id}`. Verify 200. GET same key returns 404.
8. `Custom provider without base_url returns 400` -- POST with `provider: "custom"`, no `base_url`. Verify 400 error about `base_url required`.

**Section 625: Key Test, Rotate & Usage API (5 tests)**

9. `Alice tests an API key (dev mode mock)` -- POST `/ui/agent/llm-keys/{key_id}/test`. Verify response `ok: true` with `models` list and `latency_ms > 0`.
10. `Alice rotates an API key` -- POST `/ui/agent/llm-keys/{key_id}/rotate` with `new_api_key: "sk-ant-new-key-9876543210"`. Verify 200 with `key_suffix: "3210"`. Verify key_id unchanged.
11. `Alice checks key usage` -- GET `/ui/agent/llm-keys/{key_id}/usage`. Verify response with `local_usage_cents`, `local_total_requests`, `local_total_tokens`.
12. `Alice assigns a key to a worker` -- POST `/ui/agent/llm-keys/{key_id}/assign` with `worker_id: "worker_test_001"`. Verify 200. GET key, verify `assigned_worker_ids` contains `worker_test_001`.
13. `Alice unassigns a key from a worker` -- DELETE `/ui/agent/llm-keys/{key_id}/assign/worker_test_001`. Verify 200. GET key, verify `assigned_worker_ids` is empty.

**Section 626: LLM Keys UI (5 tests)**

14. `LlmKeysPage renders key table` -- Navigate to `/agents/llm-keys`. Verify heading "LLM API Keys" is visible. Verify table headers: Label, Provider, Status.
15. `Add Key dialog shows provider selector` -- Click "Add Key" button. Verify provider cards for "OpenAI", "Anthropic", "DeepSeek", "Gemini", "Custom" are visible.
16. `Add key through dialog creates key` -- Select Anthropic provider, fill label "E2E Key", paste API key, submit. Verify new row appears in table with provider "Anthropic" and status "active".
17. `Test button shows result` -- Click "Test" action on key row. Verify success toast or inline indicator appears.
18. `Delete button with confirmation removes key` -- Click "Delete" on key row. Verify confirmation dialog. Confirm. Verify row removed from table.

---

## 6. Security Considerations

### 6.1 Encryption at Rest

All API keys are encrypted using KMS (`kms_encrypt`) before storage. The `encrypted_api_key` field contains base64-encoded ciphertext. Decryption only occurs in two paths: (a) key testing and (b) agent provisioning (AGENT-002). Raw keys are never logged.

### 6.2 Key Never Exposed

The `_safe_out` function strips `encrypted_api_key` from all API responses. Only the `key_suffix` (last 4 chars) is returned for display. The full key is shown only once at creation time (if the frontend chooses to display it).

### 6.3 User Isolation

All DDB items use `USER#{user_id}` as the partition key. API endpoints validate `user_id` from the session. Cross-user access is impossible via the API.

### 6.4 Budget Enforcement

`record_usage` checks `current_month_usage_cents` against `monthly_budget_cents`. When budget is exceeded, key status is set to `budget_exceeded` and `get_decrypted_api_key` raises an error, preventing further agent usage.

### 6.5 Admin Audit

Admin endpoint lists all keys across users with usage stats but never exposes the encrypted key or key_suffix. Audit trail via `audit_event` on add, rotate, delete actions.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| `app/core/crypto.py` | Existing | KMS encrypt/decrypt for key storage |
| `scripts/mock_kms_server.py` | Existing | KMS mock for dev mode key testing |
| AGENT-002 | Downstream | Worker provisioning calls `get_decrypted_api_key` to inject keys |
| AGENT-003 | Downstream | Agent framework calls `record_usage` after LLM API calls |

---

## 8. Acceptance Criteria

1. Users can add API keys for OpenAI, Anthropic, DeepSeek, Gemini, and custom OpenAI-compatible endpoints.
2. Keys are encrypted at rest using KMS and never exposed in API responses.
3. Key testing makes a lightweight probe call and reports success/failure with discovered models.
4. Key rotation updates the encrypted key in-place without changing the key_id.
5. Monthly budget caps are enforced; keys transition to `budget_exceeded` status when exceeded.
6. Provider usage checking returns balance/usage data where the provider API supports it.
7. Keys can be assigned to and unassigned from worker agents.
8. Admin endpoint provides cross-user key audit data.
9. Frontend provides a complete key management interface with add, test, rotate, and delete flows.
10. All key lifecycle operations produce audit events.
