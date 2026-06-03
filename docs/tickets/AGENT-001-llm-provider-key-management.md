# AGENT-001: LLM Provider Key Management

**Ticket**: AGENT-001
**Author**: Engineering
**Status**: Implemented
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

### 1.3 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    LLM Provider Key Management                          │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │                   Frontend (Browser)                      │           │
│  │                                                           │           │
│  │  LlmKeysPage (/agents/llm-keys)                         │           │
│  │  ├── Key Table (label, provider, model, status, usage)   │           │
│  │  ├── "Add Key" → AddLlmKeyDialog                        │           │
│  │  │   ├── Step 1: Provider selector (card grid)           │           │
│  │  │   └── Step 2: Key config (label, API key, model)      │           │
│  │  ├── "Test" → POST /llm-keys/{id}/test                  │           │
│  │  ├── "Rotate" → POST /llm-keys/{id}/rotate              │           │
│  │  └── "Delete" → DELETE /llm-keys/{id}                    │           │
│  └──────────────────────────────────────────────────────────┘           │
│                              │                                          │
│               Vite Proxy /ui/* → :8000                                  │
│                              │                                          │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │                  Backend (FastAPI :8000)                   │           │
│  │                                                           │           │
│  │  app/routers/llm_provider_keys.py                         │           │
│  │  ├── POST   /ui/agent/llm-keys           (add key)       │           │
│  │  ├── GET    /ui/agent/llm-keys           (list keys)     │           │
│  │  ├── GET    /ui/agent/llm-keys/{id}      (get key)       │           │
│  │  ├── POST   /ui/agent/llm-keys/{id}/test (test key)      │           │
│  │  ├── POST   /ui/agent/llm-keys/{id}/rotate (rotate)      │           │
│  │  ├── DELETE  /ui/agent/llm-keys/{id}     (delete key)    │           │
│  │  ├── GET    /ui/agent/llm-keys/{id}/usage (usage)        │           │
│  │  ├── GET    /ui/agent/llm-providers       (providers)     │           │
│  │  ├── POST   /ui/agent/llm-keys/{id}/assign (assign)      │           │
│  │  ├── DELETE  /ui/agent/llm-keys/{id}/assign/{wid}        │           │
│  │  └── GET    /ui/admin/agent/llm-keys     (admin audit)   │           │
│  │                                                           │           │
│  │  app/services/llm_provider_keys.py                        │           │
│  │  ├── add_key()          → encrypt + store                │           │
│  │  ├── list_keys()        → query, strip encrypted key     │           │
│  │  ├── test_key()         → decrypt, probe provider API    │           │
│  │  ├── rotate_key()       → re-encrypt, same key_id        │           │
│  │  ├── record_usage()     → atomic increment + budget check│           │
│  │  └── get_decrypted_api_key() → for agent provisioning    │           │
│  └──────────────────────────────────────────────────────────┘           │
│                              │                                          │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │                    Infrastructure                         │           │
│  │                                                           │           │
│  │  DynamoDB: llm_provider_keys table                        │           │
│  │  ├── PK: USER#{user_id}                                  │           │
│  │  ├── SK: KEY#{key_id}                                    │           │
│  │  ├── encrypted_api_key (KMS ciphertext)                  │           │
│  │  └── GSIs: ByProvider, ByCreatedAt                       │           │
│  │                                                           │           │
│  │  KMS (mock_kms_server.py :7999)                          │           │
│  │  ├── Encrypt: plaintext API key → base64 ciphertext      │           │
│  │  └── Decrypt: ciphertext → plaintext (agent provisioning)│           │
│  └──────────────────────────────────────────────────────────┘           │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │          Downstream Consumers                             │           │
│  │                                                           │           │
│  │  AGENT-002 (Worker Provisioning)                          │           │
│  │  └── get_decrypted_api_key(user_id, key_id)              │           │
│  │      → injects API key as env var on compute instance     │           │
│  │                                                           │           │
│  │  AGENT-003 (Agent Framework)                              │           │
│  │  └── record_usage(user_id, key_id, tokens, cost_cents)   │           │
│  │      → tracks usage per LLM call, enforces budget         │           │
│  └──────────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.4 Why This Is Needed

The Agent Orchestration Platform (AGENT-002 through AGENT-007) requires LLM API keys to power autonomous coding agents. Users bring their own keys (BYOK model) and need a secure way to store, test, rotate, and assign them to agents. Without centralized key management, users would need to manually paste keys into terminal sessions every time an agent spins up, which is error-prone, insecure (keys visible in terminal history), and blocks automated agent provisioning.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| KMS encrypt/decrypt | `app/core/crypto.py` | `kms_encrypt(plaintext) -> str` (line 16), `kms_decrypt(ct_b64) -> bytes` (line 22); used for encrypting LLM API keys at rest (verified) |
| API key service | `app/services/api_keys.py` (~412 lines) | Platform API key management; provides patterns for key hashing, CRUD, capabilities; LLM keys follow a similar but separate pattern (verified) |
| API key router | `app/routers/api_keys.py` | Platform API key endpoints; reference for router structure (verified) |
| Settings | `app/core/settings.py` | Configuration singleton `S` (line 1494); will add `llm_provider_keys_table_name` (verified) |
| Tables | `app/core/tables.py` | DynamoDB table handles; will add `T.llm_provider_keys` (verified) |
| Mock KMS server | `scripts/mock_kms_server.py` (port 7999) | Provides KMS encrypt/decrypt in dev mode (verified) |
| Auth deps | `app/auth/deps.py`, `app/auth/policy.py` | `require_ui_session` for cookie auth; <!-- NOTE: `require_admin_session` does not exist. Use `require_admin_scope(AdminScope.XXX)` from `app/auth/policy.py:84` for admin endpoints, or `require_root_session` (deps.py:273) for root-only endpoints --> `require_admin_scope()` for admin endpoints |

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

### 3.2 DynamoDB Access Patterns

| Access Pattern | Key | GSI | Operation | Description |
|---|---|---|---|---|
| Add new key | PK=`USER#{user_id}`, SK=`KEY#{key_id}` | — | PutItem | Store encrypted key with metadata |
| List user's keys | PK=`USER#{user_id}`, SK begins_with `KEY#` | — | Query | All keys for a user |
| Get single key | PK=`USER#{user_id}`, SK=`KEY#{key_id}` | — | GetItem | Single key details |
| Filter by provider | PK=`USER#{user_id}` | ByProvider | Query GSI | Keys for a specific provider |
| List by creation date | PK=`USER#{user_id}` | ByCreatedAt | Query GSI | Keys sorted by creation time |
| Update key metadata | PK=`USER#{user_id}`, SK=`KEY#{key_id}` | — | UpdateItem | Test results, usage, status |
| Rotate key (re-encrypt) | PK=`USER#{user_id}`, SK=`KEY#{key_id}` | — | UpdateItem | New encrypted_api_key + key_suffix |
| Record usage (atomic) | PK=`USER#{user_id}`, SK=`KEY#{key_id}` | — | UpdateItem (ADD) | Increment tokens, requests, cost |
| Delete key | PK=`USER#{user_id}`, SK=`KEY#{key_id}` | — | DeleteItem | Permanent removal |
| Admin scan all keys | — | — | Scan (paginated) | Admin audit across all users |

#### Example DynamoDB Items (JSON)

**Active Anthropic Key**:
```json
{
  "pk": {"S": "USER#e2e_alice@test.local"},
  "sk": {"S": "KEY#a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"},
  "key_id": {"S": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"},
  "user_id": {"S": "e2e_alice@test.local"},
  "provider": {"S": "anthropic"},
  "label": {"S": "My Claude Production Key"},
  "encrypted_api_key": {"S": "AQICAHh...base64ciphertext...=="},
  "key_suffix": {"S": "cdef"},
  "base_url": {"S": "https://api.anthropic.com/v1"},
  "model_preference": {"S": "claude-sonnet-4-20250514"},
  "available_models": {"L": [
    {"S": "claude-sonnet-4-20250514"},
    {"S": "claude-opus-4-20250514"},
    {"S": "claude-haiku-3-5-20241022"}
  ]},
  "rate_limit_rpm": {"N": "60"},
  "monthly_budget_cents": {"N": "50000"},
  "current_month_usage_cents": {"N": "12340"},
  "usage_reset_at": {"N": "1751328000"},
  "total_requests": {"N": "4521"},
  "total_tokens_used": {"N": "1234567"},
  "status": {"S": "active"},
  "last_tested_at": {"N": "1748534000"},
  "last_used_at": {"N": "1748534400"},
  "created_at": {"N": "1748000000"},
  "updated_at": {"N": "1748534400"},
  "assigned_worker_ids": {"L": [{"S": "worker_coder_001"}, {"S": "worker_qa_002"}]}
}
```

**Custom OpenAI-Compatible Key**:
```json
{
  "pk": {"S": "USER#e2e_alice@test.local"},
  "sk": {"S": "KEY#f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2"},
  "key_id": {"S": "f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2"},
  "user_id": {"S": "e2e_alice@test.local"},
  "provider": {"S": "custom"},
  "label": {"S": "Local vLLM Server"},
  "encrypted_api_key": {"S": "AQICAHh...=="},
  "key_suffix": {"S": "c123"},
  "base_url": {"S": "https://my-vllm.example.com/v1"},
  "model_preference": {"S": "meta-llama/Llama-3.3-70B-Instruct"},
  "available_models": {"L": []},
  "rate_limit_rpm": {"N": "120"},
  "monthly_budget_cents": {"N": "0"},
  "current_month_usage_cents": {"N": "0"},
  "status": {"S": "active"},
  "created_at": {"N": "1748100000"},
  "assigned_worker_ids": {"L": []}
}
```

### 3.3 Provider Registry

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

### 3.4 Backend Service

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

### 3.5 Backend Router

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
| `GET` | `/ui/admin/agent/llm-keys` | `require_admin_scope` | Admin: list all keys across users <!-- NOTE: was `require_admin_session` which does not exist — use `require_admin_scope()` from app/auth/policy.py:84 --> |

### 3.6 Pydantic Models

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

### 3.7 Frontend Components

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

#### Frontend Component Tree

```
LlmKeysPage (/agents/llm-keys)
├── Props: none (page)
├── State: useQuery(["llm-keys"], listKeys)
│
├── PageHeader
│   ├── <h1>LLM API Keys</h1>
│   └── <Button>Add Key</Button> → opens AddLlmKeyDialog
│
├── KeyTable (DataTable)
│   ├── Columns: Label, Provider, Model, Status, Usage, Last Tested, Actions
│   ├── StatusBadge
│   │   ├── active → green Badge
│   │   ├── inactive → gray Badge
│   │   ├── budget_exceeded → red Badge
│   │   └── invalid → orange Badge
│   ├── UsageBar (when monthly_budget_cents > 0)
│   │   └── Progress bar: current_month_usage_cents / monthly_budget_cents
│   └── ActionsDropdown
│       ├── Test → useMutation(testKey)
│       ├── Rotate → opens RotateDialog
│       ├── Usage → opens UsageDialog
│       └── Delete → opens ConfirmDialog
│
├── AddLlmKeyDialog
│   ├── Step 1: ProviderSelector (card grid)
│   │   └── Cards: OpenAI, Anthropic, DeepSeek, Gemini, Custom
│   └── Step 2: KeyConfigForm
│       ├── Label input
│       ├── API Key (password input with show/hide toggle)
│       ├── Model preference (Select from provider.models)
│       ├── Base URL (visible only for custom provider)
│       ├── Rate limit (number input, default 60)
│       ├── Monthly budget (currency input, $0 = unlimited)
│       └── Submit → useMutation(addKey)
│
├── RotateKeyDialog
│   ├── Props: { keyId, currentSuffix }
│   ├── New API key input (password field)
│   └── Submit → useMutation(rotateKey)
│
└── EmptyState
    └── "No LLM keys configured. Add your first API key."

Route: /agents/llm-keys
Sidebar: "LLM Keys" with KeyRound icon under "AI Agents" group
```

---

## 4. API Request/Response Examples

### 4.1 Add Key

```bash
curl -X POST http://localhost:8000/ui/agent/llm-keys \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001" \
  -d '{
    "provider": "anthropic",
    "label": "My Claude Production Key",
    "api_key": "sk-ant-test-1234567890abcdef",
    "model_preference": "claude-sonnet-4-20250514",
    "monthly_budget_cents": 50000
  }'

# Response (201 Created)
{
  "key_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "provider": "anthropic",
  "label": "My Claude Production Key",
  "key_suffix": "cdef",
  "base_url": "https://api.anthropic.com/v1",
  "model_preference": "claude-sonnet-4-20250514",
  "available_models": [],
  "rate_limit_rpm": 60,
  "monthly_budget_cents": 50000,
  "current_month_usage_cents": 0,
  "total_requests": 0,
  "total_tokens_used": 0,
  "status": "active",
  "last_tested_at": 0,
  "last_used_at": 0,
  "created_at": 1748534400,
  "assigned_worker_ids": []
}
```

### 4.2 Test Key

```bash
curl -X POST http://localhost:8000/ui/agent/llm-keys/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4/test \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001"

# Response (200 OK)
{
  "ok": true,
  "models": ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-3-5-20241022"],
  "error": "",
  "latency_ms": 142
}
```

### 4.3 Rotate Key

```bash
curl -X POST http://localhost:8000/ui/agent/llm-keys/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4/rotate \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001" \
  -d '{"new_api_key": "sk-ant-new-key-9876543210"}'

# Response (200 OK)
{
  "key_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "provider": "anthropic",
  "label": "My Claude Production Key",
  "key_suffix": "3210",
  "status": "active"
}
```

### 4.4 List Providers

```bash
curl http://localhost:8000/ui/agent/llm-providers \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ..."

# Response (200 OK)
{
  "providers": [
    {"provider": "openai", "display_name": "OpenAI", "base_url": "https://api.openai.com/v1", "models": ["gpt-4o", "gpt-4o-mini", "o3", "o4-mini", "codex-mini-latest"], "supports_usage_api": true},
    {"provider": "anthropic", "display_name": "Anthropic (Claude)", "base_url": "https://api.anthropic.com/v1", "models": ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-3-5-20241022"], "supports_usage_api": false},
    {"provider": "deepseek", "display_name": "DeepSeek", "base_url": "https://api.deepseek.com/v1", "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"], "supports_usage_api": false},
    {"provider": "gemini", "display_name": "Google Gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta", "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"], "supports_usage_api": false},
    {"provider": "custom", "display_name": "Custom (OpenAI-compatible)", "base_url": "", "models": [], "supports_usage_api": false}
  ]
}
```

---

## 5. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Unknown provider | 400 | `invalid_provider` | "Unknown provider: {value}" | Use one of: openai, anthropic, deepseek, gemini, custom |
| Custom provider without base_url | 400 | `base_url_required` | "base_url is required for custom provider" | Provide base_url |
| API key too short (<8 chars) | 422 | `validation_error` | "api_key must be at least 8 characters" | Use full API key |
| Key not found | 404 | `key_not_found` | "LLM key not found" | Check key_id |
| Key test failed (invalid key) | 200 | — | `ok: false, error: "Authentication failed"` | Check API key validity |
| Key test failed (network error) | 200 | — | `ok: false, error: "Connection timeout"` | Check provider availability |
| Budget exceeded | 200 | — | Status changes to `budget_exceeded` | Increase budget or reset usage |
| Key already assigned to worker | 200 | — | Worker added to list (idempotent) | No action needed |
| Delete key with active workers | 200 | — | Key deleted; workers lose reference | Reassign workers to new key |
| Session expired | 401 | `unauthorized` | "Session expired" | Re-authenticate |
| Non-admin accessing admin endpoint | 403 | `forbidden` | "Admin access required" | Use admin account |

---

## 6. Implementation Plan

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
| `frontend/e2e/agent-llm-keys.spec.ts` | New file: ~18 tests in 4 sections |

---

## 7. E2E Test Plan (`frontend/e2e/agent-llm-keys.spec.ts`)

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

## 8. Observability & Monitoring

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `llm_key_operations_total` | Counter | `operation` (add/delete/test/rotate/assign) | Total key management operations |
| `llm_key_test_results_total` | Counter | `provider`, `result` (success/failure) | Key test outcomes |
| `llm_key_usage_tokens_total` | Counter | `provider`, `user_id` | Total tokens consumed across all keys |
| `llm_key_budget_exceeded_total` | Counter | `provider` | Times a key hit its budget cap |

### 8.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `llm_key_added` | INFO | `user_id`, `key_id`, `provider`, `label` | New key stored |
| `llm_key_tested` | INFO | `user_id`, `key_id`, `provider`, `ok`, `latency_ms` | Key test completed |
| `llm_key_rotated` | INFO | `user_id`, `key_id`, `provider` | Key rotated |
| `llm_key_deleted` | INFO | `user_id`, `key_id`, `provider` | Key deleted |
| `llm_key_budget_exceeded` | WARN | `user_id`, `key_id`, `budget_cents`, `usage_cents` | Budget cap hit |
| `llm_key_decrypted` | DEBUG | `user_id`, `key_id` | Key decrypted (agent provisioning) |

### 8.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Key test failure spike | `rate(llm_key_test_results_total{result="failure"}) > 10/min` | Warning | Check provider API status |
| Budget exceeded wave | `rate(llm_key_budget_exceeded_total) > 5/min` | Warning | Users hitting budget caps; may indicate agent cost spike |
| KMS decrypt failures | Any `kms_decrypt` error | Critical | Check KMS mock server (port 7999) is running |

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AGENT_LLM_KEYS_ENABLED` | `false` | Master switch for LLM key management feature |
| `AGENT_LLM_KEY_TESTING_ENABLED` | `true` | When false, test endpoint returns mock success without calling provider |

### 9.2 Migration Steps

1. **Phase 1**: Create DynamoDB table. Deploy backend service with `AGENT_LLM_KEYS_ENABLED=false`.
2. **Phase 2**: Enable for internal users. Test add/list/delete/rotate flows.
3. **Phase 3**: Enable `AGENT_LLM_KEYS_ENABLED=true` for all users. Frontend page visible.
4. **Phase 4**: Enable key testing against live provider APIs (after confirming no rate limit issues).

### 9.3 Rollback Procedure

1. Set `AGENT_LLM_KEYS_ENABLED=false`. Frontend hides LLM Keys page.
2. Existing keys remain encrypted in DDB (harmless).
3. Workers referencing key_ids will fail at provisioning time (AGENT-002 handles gracefully).

---

## 10. Performance Considerations

### 10.1 KMS Latency

- `kms_encrypt`: ~10ms (mock KMS). In production with AWS KMS: ~50-100ms.
- `kms_decrypt`: ~10ms (mock). In production: ~50-100ms.
- Key encryption/decryption happens only on add, rotate, test, and agent provisioning — not on every API call.

### 10.2 Key Listing

- `list_keys` is a DynamoDB Query (not Scan). Partition key = `USER#{user_id}`, SK prefix = `KEY#`. Even with 100 keys per user (unlikely), the query returns in < 10ms.

### 10.3 Usage Recording

- `record_usage` uses DynamoDB `ADD` (atomic increment). This is called after every LLM API call by the agent framework. At 100 API calls/minute per agent, this generates 100 WCUs/minute per active key — well within DDB limits.

### 10.4 Budget Check

- Budget check after `record_usage` is a conditional update: if `current_month_usage_cents >= monthly_budget_cents` then set `status = budget_exceeded`. This is an atomic operation piggy-backed on the usage recording write.

---

## 11. Security Considerations

### 11.1 Encryption at Rest

All API keys are encrypted using KMS (`kms_encrypt`) before storage. The `encrypted_api_key` field contains base64-encoded ciphertext. Decryption only occurs in two paths: (a) key testing and (b) agent provisioning (AGENT-002). Raw keys are never logged.

### 11.2 Key Never Exposed

The `_safe_out` function strips `encrypted_api_key` from all API responses. Only the `key_suffix` (last 4 chars) is returned for display. The full key is shown only once at creation time (if the frontend chooses to display it).

### 11.3 User Isolation

All DDB items use `USER#{user_id}` as the partition key. API endpoints validate `user_id` from the session. Cross-user access is impossible via the API.

### 11.4 Budget Enforcement

`record_usage` checks `current_month_usage_cents` against `monthly_budget_cents`. When budget is exceeded, key status is set to `budget_exceeded` and `get_decrypted_api_key` raises an error, preventing further agent usage.

### 11.5 Admin Audit

Admin endpoint lists all keys across users with usage stats but never exposes the encrypted key or key_suffix. Audit trail via `audit_event` on add, rotate, delete actions.

---

## 12. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| `app/core/crypto.py` | Existing | KMS encrypt/decrypt for key storage |
| `scripts/mock_kms_server.py` | Existing | KMS mock for dev mode key testing |
| AGENT-002 | Downstream | Worker provisioning calls `get_decrypted_api_key` to inject keys |
| AGENT-003 | Downstream | Agent framework calls `record_usage` after LLM API calls |

---

## 13. Acceptance Criteria

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

---

## Codebase References

| Reference | Path | Line(s) | Status |
|-----------|------|---------|--------|
| KMS encrypt | `app/core/crypto.py` | 16 (`kms_encrypt`) | Verified |
| KMS decrypt | `app/core/crypto.py` | 22 (`kms_decrypt`) | Verified |
| API key service (pattern ref) | `app/services/api_keys.py` | ~412 lines | Verified |
| API key router (pattern ref) | `app/routers/api_keys.py` | entire file | Verified |
| Settings singleton | `app/core/settings.py` | 1494 (`S = Settings()`) | Verified |
| Tables dataclass | `app/core/tables.py` | entire file | Verified |
| Mock KMS server | `scripts/mock_kms_server.py` | entire file (port 7999) | Verified |
| DDB init script | `scripts/local-ddb-init.py` | 42 (`_table_defs()`) | Verified — new TableDef entry needed |
| Router registration | `app/main.py` | 297-465 | Verified — new router must be registered |
| Admin auth pattern | `app/auth/policy.py` | 84 (`require_admin_scope`) | Verified — **not** `require_admin_session` |
| Root session auth | `app/auth/deps.py` | 273 (`require_root_session`) | Verified |
| `llm_provider_keys` table | — | — | **Does not exist** — new table required |
| `llm_provider_keys` service | — | — | **Does not exist** — new file required |
| `llm_provider_keys` router | — | — | **Does not exist** — new file required |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_llm_provider_keys.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_llm_provider_keys` | Creates record with correct fields and generated ID |
| `test_create_llm_provider_keys_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_llm_provider_keys_found` | Returns correct record by ID |
| `test_get_llm_provider_keys_not_found` | Returns None for non-existent ID |
| `test_list_llm_provider_keys` | Returns all records for the given scope/owner |
| `test_update_llm_provider_keys` | Updates mutable fields and sets updated_at |
| `test_delete_llm_provider_keys` | Removes record; subsequent get returns None |
| `test_llm_provider_keys_owner_check` | Rejects operations from non-owner users |
| `test_llm_provider_keys_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_llm_provider_keys_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-llm-keys.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**:


| Table | PK/SK Pattern | Notes |
|-------|--------------|-------|
| `LlmProviderKeys` | See DDB schema in technical design section | Created by `scripts/local-ddb-init.py` |

### CI/Pipeline


- **Feature flags**: None required for dev/test
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| KMS encryption | `app/core/crypto.py` | Implemented | N/A |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| AGENT-002 | LLM keys for worker provisioning |
| AGENT-003 | LLM keys for agent framework |
| AGENT-004 | Key display in fleet UI |
| AGENT-008 through AGENT-018 | LLM keys for all specialized agents |

### Merge Strategy


**Independent**


- Can be developed and merged independently on its own feature branch
- No other tickets must be merged first
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB table(s) added to `scripts/local-ddb-init.py`: `LlmProviderKeys`
- [ ] Settings added to `app/core/settings.py` + `app/core/tables.py`: `llm_provider_keys_table_name`
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/llm_provider_keys.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/settings/llm-keys`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
