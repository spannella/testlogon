# AGENT-001: LLM Provider Key Management — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

AGENT-001 implements a secure bring-your-own-key (BYOK) vault for third-party LLM API credentials. Users add API keys from OpenAI, Anthropic, DeepSeek, Google Gemini, or any OpenAI-compatible custom endpoint; the backend encrypts each key at rest with KMS, exposes only the last four characters for display, and provides test/rotate/budget-cap/assignment operations. The vault is the prerequisite for the entire agent orchestration chain: AGENT-002 provisioner calls `get_decrypted_api_key` to inject the credential into a worker instance at startup, and AGENT-003 calls `record_usage` after every LLM call to enforce per-key monthly spend caps.

- **Type**: Feature (new greenfield service)
- **Priority**: High — blocks AGENT-002 through AGENT-018
- **Status**: Implemented
- **Owning area**: AI Agents / Platform security
- **User persona**: Developer/creator user managing their own LLM spend; platform admin auditing cross-user usage
- **Cross-references**: [[SEC-022]] (credential exposure via API), [[SECOPS-007]] (dev/prod parity — mock KMS vs AWS KMS), [[AGENT-002]] (downstream provisioner), [[AGENT-003]] (downstream usage tracking)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Encryption infrastructure

`app/core/crypto.py:16` defines `kms_encrypt(plaintext: str) -> str` and `:22` defines `kms_decrypt(ct_b64: str) -> bytes`. In dev mode the calls hit `scripts/mock_kms_server.py` on port 7999; in prod they hit AWS KMS. The same two functions are already exercised by the SSH key manager, signing module, and API-key pepper logic — so the plumbing is proven.

### 2.2 The new service — what is actually implemented

`app/services/llm_provider_keys.py` (429 lines) is **fully present**:

- `add_key` (line 89): validates provider against `PROVIDER_REGISTRY`, calls `kms_encrypt`, stores ciphertext + last-4-char suffix in DynamoDB, returns `_safe_out` (strips ciphertext).
- `get_decrypted_api_key` (line 159): internal-only function; decrypts with `kms_decrypt`; raises `ValueError` if key absent or status ≠ `"active"`.
- `test_key` (line 173): in dev (`S.dev_mode` or `S.agent_llm_key_testing_enabled == False`, line 190) returns a mock success immediately using the provider registry's default model list — no outbound call, satisfying SECOPS-007. In prod, uses `httpx` to probe the provider's `/models` endpoint.
- `rotate_key` (line 249): re-encrypts a new value in-place; preserves `key_id` so worker config references remain valid.
- `record_usage` (line 310): DynamoDB `ADD` (atomic increment) for tokens, requests, cost; checks budget and transitions status to `"budget_exceeded"` when `current_month_usage_cents >= monthly_budget_cents`.
- `_safe_out` (line 408): strips `encrypted_api_key`, `pk`, `sk` from every API response. The raw key is never returned.
- `list_all_keys_admin` (line 392): cross-user scan for admin audit; also strips ciphertext.

**Known minor info leak (SEC-021):** `test_key` at line 234 builds `error_msg = f"HTTP {resp.status_code}: {resp.text[:200]}"` and returns it verbatim to the client. The first 200 bytes of the provider's error body can contain token prefixes, account identifiers, or diagnostic detail that narrows the attack surface. The proposed fix (SEC-021) is to return a generic "authentication failed" message instead.

### 2.3 Router

`app/routers/llm_provider_keys.py` (144 lines) provides 11 endpoints under `/ui/agent/llm-keys` and `/ui/agent/llm-providers`, all guarded by `require_ui_session`. The admin audit endpoint at `/ui/admin/agent/llm-keys` correctly uses `require_admin_scope` from `app/auth/policy.py:84` (not the non-existent `require_admin_session`). The router is registered in `app/main.py:668`.

### 2.4 Data model

`app/models.py:4196-4270` contains all Pydantic models: `LlmKeyCreateIn`, `LlmKeyRotateIn`, `LlmKeyAssignIn`, `LlmKeyOut`, `LlmKeyTestOut`, `LlmKeyUsageOut`, `LlmProviderInfo`, `LlmProviderListOut`. `LlmKeyCreateIn.api_key` has `min_length=8, max_length=500` — rejects obviously short test strings.

### 2.5 DynamoDB table

`scripts/local-ddb-init.py:1620` creates the `llm_provider_keys` table:
- PK `USER#{user_id}`, SK `KEY#{key_id}`
- GSIs `ByProvider` (pk + provider) and `ByCreatedAt` (pk + created_at)
- `attr_types={"created_at": "N"}` present — avoids the String-vs-Number GSI bug documented in CLAUDE.md

`app/core/settings.py:1984` adds `llm_provider_keys_table_name`; `app/core/tables.py:230,466` wires `T.llm_provider_keys`.

### 2.6 Frontend

`frontend/src/pages/agents/LlmKeysPage.tsx` and `AddLlmKeyDialog.tsx` are present. `AddLlmKeyDialog` has a two-step wizard: provider card grid → key config form with password input and show/hide toggle. The API key field is a `type="password"` input so it does not persist in browser history. The page is routed at `/agents/llm-keys` and added to the sidebar under an "AI Agents" group.

### 2.7 E2E tests

`frontend/e2e/agent-llm-keys.spec.ts` covers sections 623-626 (18 tests): provider registry, CRUD API, test/rotate/usage, and UI flows.

### 2.8 Dev vs prod parity (SECOPS-007)

| Operation | Dev path | Prod path |
|---|---|---|
| `kms_encrypt` / `kms_decrypt` | mock KMS `:7999` | AWS KMS |
| `test_key` | mock success, no outbound | `httpx` → real provider `/models` |
| `check_usage` | returns local-tracking only | queries provider billing API where supported |
| DynamoDB | DDB Local `:8001` | AWS DynamoDB |

All dev paths are selected via `S.dev_mode` (line 190 in the service), with no scattered `if/else` in the service itself — consistent with SECOPS-007's factory-selection requirement.

---

## 3. Gap / Threat Analysis

### 3.1 SEC-022: ciphertext exposure defense-in-depth

The `encrypted_api_key` is already stripped in `_safe_out`. However, a future developer adding a new query path could accidentally omit `_safe_out`. The defense-in-depth fix is to make the ciphertext field excluded at the Pydantic model level (add it to `LlmKeyOut.model_config` excludes), ensuring even if someone serializes the DDB item directly, the field is absent.

### 3.2 SEC-021: provider error body leakage

`test_key` returns `resp.text[:200]` on failure (line 234). An attacker who already holds a compromised key can probe different provider-side error messages to infer account metadata (quota exhausted, suspended account, wrong region). Fix: return `{"ok": false, "error": "authentication failed"}` for 401/403, `"provider unavailable"` for 5xx.

### 3.3 Budget bypass via race condition

`record_usage` uses two separate DynamoDB operations: an atomic `ADD` increment followed by a conditional `SET status="budget_exceeded"`. Between these two writes a second concurrent call could read `status="active"` and proceed with a new decryption. The safe fix is a single `UpdateItem` with a `ConditionExpression: current_month_usage_cents < monthly_budget_cents` or to check-then-set in one expression using `SET status = if(...)`. Currently the race window is small (milliseconds) but real for high-throughput agents.

### 3.4 Monthly reset not automated

The schema stores `usage_reset_at` but there is no background task that zeros `current_month_usage_cents` when the billing month turns over. If not implemented before prod, users who set a budget will see it never reset. A cron task or `record_usage` check against `usage_reset_at` is required.

### 3.5 Custom `base_url` SSRF (SEC-020 family)

For `provider="custom"`, the user supplies `base_url`. In prod, `test_key` will issue a GET to that URL. A malicious user could set `base_url=http://169.254.169.254/latest/meta-data/` (AWS IMDS) or an internal service and observe the response. The `test_key` path needs an SSRF guard: validate scheme (`https://` only), reject RFC-1918 / link-local / loopback ranges, and apply a domain allowlist or at minimum a denylist of metadata endpoints.

### 3.6 Key assignment / worker ownership

`assign_key_to_worker` (line 360) appends `worker_id` to `assigned_worker_ids` without verifying the worker belongs to the same user. A user who knows a foreign `worker_id` can associate their key with someone else's worker record. The fix is to call `get_worker(user_id, worker_id)` from the provisioner and 404 if not found.

---

## 4. Proposed Design / Fix

### 4.1 SEC-021 error sanitization (code change, no new tables)

```python
# app/services/llm_provider_keys.py ~line 234
# Replace:
error_msg = f"HTTP {resp.status_code}: {resp.text[:200]}"
# With:
if resp.status_code in (401, 403):
    error_msg = "Authentication failed — check your API key"
elif resp.status_code >= 500:
    error_msg = f"Provider returned HTTP {resp.status_code}"
else:
    error_msg = f"Unexpected HTTP {resp.status_code}"
```

### 4.2 Budget atomicity

Replace the two-step `record_usage` with a single UpdateItem that both increments and conditionally marks `budget_exceeded`:

```python
T.llm_provider_keys.update_item(
    Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
    UpdateExpression=(
        "ADD total_requests :one, total_tokens_used :tok, current_month_usage_cents :cost "
        "SET last_used_at = :ts, #st = if_not_exists(#st, :active)"
    ),
    # A post-write check via a second UpdateItem with ConditionExpression
    # is still needed; but two operations is already safe because the
    # counter increment is atomic — the budget enforcement is eventual,
    # not a hard real-time gate.
    ...
)
```

The cleanest fix is a Lambda expression or a two-phase approach: increment atomically, then in the same transaction (DDB transactions) mark exceeded. Until transactions are added, document the ~1-request race window as a known limitation.

### 4.3 SSRF guard for custom base_url

Add a validator in `LlmKeyCreateIn`:

```python
@field_validator("base_url")
@classmethod
def validate_base_url(cls, v: str) -> str:
    if not v:
        return v
    parsed = urlparse(v)
    if parsed.scheme != "https":
        raise ValueError("base_url must use https://")
    host = parsed.hostname or ""
    _check_ssrf_host(host)   # reuse existing SSRF guard
    return v
```

`_check_ssrf_host` should reject `169.254.x.x`, `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `127.x.x.x`, `::1`, `metadata.google.internal`.

### 4.4 Monthly usage reset background task

Add to `app/main.py` startup handlers: a daily task that scans `llm_provider_keys` for items where `usage_reset_at < now_ts()`, resets `current_month_usage_cents=0`, and sets `usage_reset_at` to the first second of next month.

### 4.5 Dev/Prod parity (SECOPS-007)

The current implementation already satisfies SECOPS-007: in `dev_mode`, no outbound HTTP call is made (line 190 checks `S.dev_mode`), and the mock KMS server is used for all encrypt/decrypt. No changes needed here.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_llm_provider_keys.py`)

Concrete cases to add or verify:

| Test | What it pins |
|---|---|
| `test_add_key_strips_ciphertext` | `"encrypted_api_key"` not in `add_key()` response |
| `test_test_key_dev_mode_no_outbound` | With `S.dev_mode=True`, `httpx.Client` never called (mock.assert_not_called) |
| `test_test_key_error_sanitized` | Mock provider returning 401 → `error` field is `"Authentication failed..."`, not raw body |
| `test_record_usage_budget_exceeded` | After usage reaches budget, `get_decrypted_api_key` raises `ValueError` |
| `test_custom_base_url_ssrf_rejected` | `base_url="http://169.254.169.254/"` → 422 from Pydantic validator |
| `test_rotate_preserves_key_id` | `rotate_key` → `key_id` unchanged, `key_suffix` updated |
| `test_admin_list_no_ciphertext` | `list_all_keys_admin()` items never contain `encrypted_api_key` |
| `test_assign_worker_owner_check` | Assign to foreign worker_id → 404 |

All tests use `moto` DynamoDB (`@mock_dynamodb`) and mock KMS — no AWS credentials, runs offline per SECOPS-007 rule 5.

### 5.2 E2E tests (Playwright)

`frontend/e2e/agent-llm-keys.spec.ts` sections 623-626. Key scenarios to verify manually:

1. Add Anthropic key → list shows `key_suffix` ending in last 4 chars, no `encrypted_api_key` field in XHR response.
2. Test key → toast shows success + model list (dev mock).
3. Rotate → `key_suffix` changes; old workers referencing same `key_id` continue to work.
4. Budget cap: set `monthly_budget_cents=1`; fire `record_usage(tokens=1000, cost_cents=2)` directly via API; key status → `budget_exceeded`.
5. Admin endpoint at `/ui/admin/agent/llm-keys` accessible with `root` cookie, 403 with `alice` cookie.

### 5.3 Manual QA steps

```bash
# Start dev stack
just restart

# Add key
curl -s -X POST http://localhost:8000/ui/agent/llm-keys \
  -H "x-csrf-token: $CSRF" -b "$COOKIES" \
  -d '{"provider":"anthropic","label":"test","api_key":"sk-ant-test-abcdefgh","model_preference":"claude-sonnet-4-20250514"}'

# Verify no encrypted_api_key in response
# Test key
curl -s -X POST http://localhost:8000/ui/agent/llm-keys/$KEY_ID/test -H "x-csrf-token: $CSRF" -b "$COOKIES"
```

### 5.4 Observability

Log events already present: `llm_key_tested`, `llm_key_rotated` at INFO level in the service. Missing: `llm_key_budget_exceeded` WARN log in `record_usage` — add so ops can alert on budget exhaustion spikes. Metrics stub (`llm_key_operations_total`) described in ticket but not yet wired to Prometheus — add in a follow-on.

### 5.5 Rollout

1. `AGENT_LLM_KEYS_ENABLED=true` already the default; no separate flag needed in current implementation.
2. `AGENT_LLM_KEY_TESTING_ENABLED=false` keeps test endpoint returning mock success until real provider probing is validated in staging.
3. Rollback: set `AGENT_LLM_KEY_TESTING_ENABLED=false`; frontend page remains functional for add/list/rotate. Existing encrypted keys are harmless in DDB.

### 5.6 Effort estimate: **S** (1-2 days) for the gap fixes described in §3-§4. The core feature is already implemented.
