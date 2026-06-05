# DELEGATE-005: Delegation API — Investigation & Implementation Write-up

## 1. Summary & Classification

DELEGATE-005 provides a programmatic REST API for external tools (chatbots, CRM systems, scheduling platforms) to perform delegated actions on behalf of creators. It extends the existing API key concept with a purpose-built `delegation_api_keys` DynamoDB table (`T.delegation_api_keys`), per-key rate limiting, scope discovery, and a `v1/*` endpoint surface that wraps DELEGATE-002 and DELEGATE-003 service functions. The key insight in the implementation is that rather than reusing `app/services/api_keys.py`, a separate table and service (`delegation_api.py`) were created with delegation-specific concerns separated from the general API key system.

- **Type**: Feature (external API access for delegation)
- **Priority**: Medium
- **Status**: Core API (key create/list/revoke, rate limiting, scope discovery, chat read/respond via `v1/*`) implemented. Several ticket-specified features are absent: webhook system, creator-approval flow (`delegation_status=pending`), per-key `rate_limit_rpm` at creation time, and `DelegationApiKeysPage` does not surface the creator-facing approval UI.
- **Owning area**: API / integration / authorization
- **User personas**: Developer (issue keys, call API), Creator (approve/revoke third-party keys)
- **Cross-references**: [[DELEGATE-001]] (required — `require_delegate_permission`, `get_delegate`), [[DELEGATE-002]] (chat service called directly), [[DELEGATE-003]] (feed service — only chat wrapped in `v1/*`), [[DELEGATE-004]] (broadcast service — not wrapped yet), [[SEC-005]] (IDOR — key scope prevents cross-creator access), [[SEC-018]] (ban bypass via API-key path), [[SECOPS-007]] (DDB Local vs prod parity)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/delegation_api.py` (357 lines)

**Implemented and working**:

| Function | Location | Notes |
|----------|----------|-------|
| `create_delegation_api_key` | `delegation_api.py:80` | Validates the owner is an active delegate; enforces least-privilege (key permissions must be a subset of the delegate's granted permissions, `delegation_api.py:106-110`); stores in `T.delegation_api_keys` with `GSI_OWNER_PK/SK` and `GSI_CREATOR_PK/SK`; returns one-time `key_secret` |
| `get_key_item` | `delegation_api.py:148` | Direct `get_item` by `key_id` |
| `list_keys_for_owner` | `delegation_api.py:152` | GSI `ByOwner` query |
| `list_keys_for_creator` | `delegation_api.py:163` | GSI `ByDelegationCreator` query |
| `revoke_key_by_owner` | `delegation_api.py:174` | Verifies `owner_sub` matches; calls `_do_revoke` |
| `revoke_key_by_creator` | `delegation_api.py:182` | Verifies `creator_id` matches; calls `_do_revoke` |
| `get_key_scope` | `delegation_api.py:190` | Only owner or creator may view; returns `_scope_view` with `available_actions` |
| `authenticate_key` | `delegation_api.py:208` | Validates format, existence, expiry, secret hash, **live delegation relationship check** (line 239), permission scope, rate limit, records usage |
| `rate_limit_headers` | `delegation_api.py:255` | Returns `X-RateLimit-*` headers |
| `_enforce_key_rate_limit` | `delegation_api.py:295` | In-memory sliding-window deque, keyed by `key_id` |
| `_record_usage` | `delegation_api.py:315` | Increments `total_calls`, updates `last_used_at` and `last_used_ip` |

**Key security design at `authenticate_key:239`**: after validating the key itself, the function calls `get_delegate(creator_id, owner_sub)` and checks `delegate.status == "active"`. This means if the creator revokes the delegation (DELEGATE-001 `revoke_delegate`), all API keys issued by that delegate are immediately invalidated on the next call — even if the key itself was not explicitly revoked. This is correct SEC-018 behavior for the API-key path.

**Missing from ticket design**:
1. **No webhook system** — no `webhook_url`, `webhook_events`, `webhook_secret` fields on keys; no `deliver_webhook` function; no `WEBHOOK#` delivery log items. The ticket's Section 3.7 (webhook architecture) is entirely absent.
2. **No creator-approval flow** — `create_delegation_api_key` creates keys with `status=active` immediately (line 127). The ticket specified a `delegation_status=pending` state requiring creator approval before the key activates. The approval endpoints (`/ui/delegation-api/pending/{key_id}/approve` etc.) do not exist in the router.
3. **No per-key `rate_limit_rpm` at creation** — `DelegationApiKeyCreateIn` at `models.py:9923` does not include `rate_limit_rpm`. The rate limit defaults to `_default_rate_limit_rpm()` (60 RPM from settings). A developer cannot request a higher or lower rate limit per key.
4. **Limited `v1/*` surface** — only chat (`v1/conversations`, `v1/conversations/{id}/messages`) is implemented in `delegation_api.py` router. Feed delegation (`v1/posts`, `v1/posts/{id}`, comment moderation, analytics) and broadcast delegation (`v1/broadcast/*`) are not exposed.

### 2.2 Router — `app/routers/delegation_api.py` (181 lines)

Single router `delegation_api_router` with prefix `/ui/delegation-api`, registered at `app/main.py:699`.

**Implemented endpoints**:
- `POST /keys` — create key
- `GET /keys` — list owner's keys
- `DELETE /keys/{key_id}` — owner revoke
- `GET /keys/{key_id}/scope` — scope discovery
- `GET /creator-keys` — creator view of keys scoped to them
- `DELETE /creator-keys/{key_id}` — creator revoke
- `GET /v1/scope` — programmatic scope discovery
- `GET /v1/conversations` — list creator conversations (chat_read)
- `GET /v1/conversations/{conversation_id}/messages` — list messages (chat_read)
- `POST /v1/conversations/{conversation_id}/messages` — send message (chat_respond)

**Missing endpoints** compared to ticket design:
- `GET /ui/delegation-api/pending` — list pending approval requests (creator view)
- `POST /ui/delegation-api/pending/{key_id}/approve`
- `POST /ui/delegation-api/pending/{key_id}/reject`
- `POST /ui/delegation-api/keys/{key_id}/webhook` — register webhook
- `GET /ui/delegation-api/keys/{key_id}/webhook/deliveries` — delivery log
- `POST /v1/posts`, `PUT /v1/posts/{id}`, `DELETE /v1/posts/{id}` — feed delegation
- `POST /v1/posts/{id}/comments/{cid}/moderate` — comment moderation
- `GET /v1/analytics` — feed analytics
- All `/v1/broadcast/*` endpoints

### 2.3 DynamoDB table — `delegation_api_keys`

Defined at `scripts/local-ddb-init.py:1641`:
```python
TableDef(
    "delegation_api_keys", "key_id",
    gsi=[
        {"index_name": "ByOwner", "partition_key": "GSI_OWNER_PK", "sort_key": "GSI_OWNER_SK"},
        {"index_name": "ByDelegationCreator", "partition_key": "GSI_CREATOR_PK", "sort_key": "GSI_CREATOR_SK"},
    ],
    attr_types={"GSI_OWNER_SK": "N", "GSI_CREATOR_SK": "N"},
)
```

Hash-key-only table (no SK, matching `get_item(Key={"key_id": key_id})`). GSIs use numeric sort keys with correct `attr_types`. No `WEBHOOK#` key pattern is defined here — webhooks would need either a separate table or an additional item pattern.

### 2.4 Frontend

**`DelegationApiKeysPage.tsx` (330 lines)**: Shows the developer's own keys and a "Creator Keys" tab listing keys scoped to the calling user as creator. Uses `createDelegationApiKey`, `listMyDelegationApiKeys`, `revokeMyDelegationApiKey`, `listCreatorDelegationApiKeys`, `revokeCreatorDelegationApiKey` from `delegationApi.ts`.

**Missing frontend components**:
- `CreateApiKeyDialog.tsx` as standalone — likely inlined
- `ApiKeyScopeView.tsx` — no standalone component
- `WebhookConfig.tsx` — absent (no webhook backend)
- `WebhookDeliveryLog.tsx` — absent
- `PendingApiKeys.tsx` — absent (no approval flow backend)

**Route**: `App.tsx:346` has `<Route path="delegation-api" element={<DelegationApiKeysPage />} />` — correctly registered.

### 2.5 SEC-018: Ban check bypass on delegation API path

`require_ui_session` at `sessions.py:284` has an early-return for API-key principals (lines 291-303) that returns BEFORE the ban check at line 309. The ban check is:
```python
if role not in {Role.ADMIN, Role.ROOT} and is_user_currently_banned(resolved_user_sub):
    raise HTTPException(403, "account is banned")
```

For delegation API calls, `request.state.api_key_principal` is populated by the API key middleware, triggering the early return at line 298 — the ban check is never reached. This means a banned delegate can still use their delegation API keys.

However, `authenticate_key` at `delegation_api.py:239` checks the delegation relationship itself:
```python
delegate = get_delegate(item.get("creator_id", ""), item.get("owner_sub", ""))
if not delegate or delegate.get("status") != "active":
    raise HTTPException(403, "Delegation relationship is no longer active")
```
This does NOT check whether the delegate's own account is banned — only whether the delegation record is active. If an admin bans delegate Bob, Bob's delegation API keys remain usable.

### 2.6 Dev vs Prod behavior (SECOPS-007)

`T.delegation_api_keys` uses `ddb_endpoint_url` → DDB Local in dev. `api_key_hash` from `app/services/api_keys.py` uses an HMAC function that works identically in dev and prod. `_enforce_key_rate_limit` uses in-memory deque — this is per-process, which is correct for both dev (single worker) and prod (uvicorn `--workers 1` as noted in CLAUDE.md). No AWS-specific calls. `delegation_api_enabled` flag in `settings.py:1947` defaults to `true`. Same code path in dev and prod.

---

## 3. Gap / Threat Analysis

### 3.1 Creator-approval flow absent (functional gap)

The ticket's acceptance criterion: "Keys require creator approval before activation." The current implementation creates keys as `status=active` immediately. There is no `delegation_status=pending` state. A developer can create a key and immediately start making API calls as the creator — without the creator ever being notified or approving.

The existing check at `authenticate_key:239` (live delegation relationship check) provides partial protection: if the creator revokes the delegation from DELEGATE-001, the key stops working. But a delegate could issue keys that persist even if the creator revokes the delegation, because key revocation is separate from delegate revocation — unless the `revoke_delegate` function in DELEGATE-001 also revokes all associated API keys, which it does not (no cross-reference between tables).

**Combined SEC-018 / gap**: `revoke_delegate` at `delegates.py:196` deletes the delegation record. `authenticate_key` at line 239 reads `get_delegate` — which returns nothing after deletion. So delegation revocation automatically invalidates keys on next use. This is correct, but only if the key's creator knows to revoke the delegation (which is the right mental model). If a creator wants to block a specific key without revoking the whole delegation, there is no mechanism.

### 3.2 Webhook system absent (feature gap)

No webhook infrastructure exists anywhere in the codebase. The ticket's Section 3.7 (signing, retry, delivery log) is entirely unimplemented. External tools using the delegation API cannot receive push events; they must poll.

### 3.3 v1/* surface limited to chat (feature gap)

The DELEGATE-003 and DELEGATE-004 service functions (`delegate_feed`, `delegate_broadcast`) are not wrapped in `v1/*` endpoints. External tools cannot create posts, moderate comments, or control broadcasts via the delegation API. The ticket's Section 3.4.2 endpoint table has 17 external API endpoints; only 4 are implemented.

### 3.4 SEC-018: Banned delegate can use API keys

`authenticate_key` checks delegation status but not the delegate's account ban status. A banned user (banned via the admin panel) retains delegation API key access. The fix: add `is_user_currently_banned(item["owner_sub"])` check in `authenticate_key` after the delegation check at line 241:

```python
from app.services.account_state import is_user_currently_banned
if is_user_currently_banned(item.get("owner_sub", "")):
    raise HTTPException(403, "Delegate account is banned")
```

This directly fixes the SEC-018 gap for the delegation API path. The general `require_ui_session` ban-bypass (for all API keys) is a separate SEC-018 issue that affects the broader API key system.

### 3.5 SEC-005: Key scope isolation

Each delegation API key stores `creator_id` and `permissions`. `authenticate_key` enforces `required_permission in item.get("permissions", [])`. `v1/conversations` calls `delegate_chat.list_creator_conversations(creator_id=key_item["creator_id"], delegate_id=key_item["owner_sub"])` — the `creator_id` comes from the key record, not from a user-supplied parameter. An external tool cannot supply an arbitrary `creator_id` to access another creator's data. This is correct IDOR defense.

### 3.6 Least-privilege enforcement at key creation

`create_delegation_api_key:106-110` enforces that requested permissions are a subset of the delegate's own granted permissions. A delegate cannot create an API key with `broadcast_control` if they only have `chat_read`. This is correct.

### 3.7 Code sites needing changes

| File | What | Priority |
|------|------|----------|
| `app/services/delegation_api.py:241` | Add `is_user_currently_banned(item["owner_sub"])` check | High — SEC-018 |
| `app/models.py:9923` | Add `rate_limit_rpm` to `DelegationApiKeyCreateIn` | Medium |
| `app/services/delegation_api.py:119` | Use `rate_limit_rpm` from request body at key creation | Medium |
| `app/routers/delegation_api.py` | Add `v1/posts/*` endpoints wrapping `delegate_feed` | Medium |
| `app/routers/delegation_api.py` | Add creator-approval flow (pending/approve/reject) | Medium |
| Webhook infrastructure | New `app/services/webhook_delivery.py`; background task; `WEBHOOK#` DDB items | Low (large effort) |
| `frontend/src/pages/delegates/DelegationApiKeysPage.tsx` | Add creator approval queue UI, webhook config | Medium (after backend) |

---

## 4. Proposed Design / Fix

### 4.1 SEC-018 ban check (immediate fix)

In `app/services/delegation_api.py`, in `authenticate_key` after line 241:

```python
from app.services.account_state import is_user_currently_banned
if is_user_currently_banned(item.get("owner_sub", "")):
    raise HTTPException(403, "Delegate account is suspended")
```

`is_user_currently_banned` is already used at `sessions.py:309`. This add one DDB read per API call — acceptable given delegation API calls are expected to be < 300 RPM per key.

### 4.2 Creator-approval flow

Add `delegation_status` field to key items: `"pending"` at creation, `"active"` after creator approval.

Modify `create_delegation_api_key:127` to set `"status": "pending"` (or add `"delegation_status": "pending"` as a separate field). Modify `authenticate_key` to check `delegation_status == "active"` before proceeding.

Add to `delegation_api_router`:
```python
@delegation_api_router.get("/pending", ...)
async def list_pending_keys(ctx=Depends(require_ui_session)):
    """Creator views keys awaiting their approval."""

@delegation_api_router.post("/pending/{key_id}/approve", ...)
async def approve_delegation_key(key_id: str, ctx=Depends(require_ui_session)):
    """Creator approves a pending delegation key."""

@delegation_api_router.post("/pending/{key_id}/reject", ...)
async def reject_delegation_key(key_id: str, ctx=Depends(require_ui_session)):
    """Creator rejects a pending delegation key."""
```

Add `list_pending_keys_for_creator`, `approve_key`, `reject_key` functions to `delegation_api.py`.

### 4.3 Per-key rate_limit_rpm at creation

Add `rate_limit_rpm: int = Field(default=60, ge=1, le=300)` to `DelegationApiKeyCreateIn` in `app/models.py:9923`. Pass it through `create_delegation_api_key` and store on the key item. `authenticate_key:248` already reads it from the item.

### 4.4 v1/* feed and broadcast endpoints

Add to `delegation_api_router`:
```python
@delegation_api_router.get("/v1/posts")
@delegation_api_router.post("/v1/posts")
@delegation_api_router.put("/v1/posts/{post_id}")
@delegation_api_router.delete("/v1/posts/{post_id}")
@delegation_api_router.post("/v1/posts/{post_id}/comments/{cid}/moderate")
@delegation_api_router.get("/v1/analytics")
```
Each wraps the corresponding `delegate_feed` service function, passing `creator_id=key_item["creator_id"]` and `delegate_id=key_item["owner_sub"]`.

### 4.5 Webhook system

The webhook system requires:
1. A webhook delivery background task (FastAPI background tasks or a separate worker).
2. New `webhook_url`, `webhook_events`, `webhook_secret` fields on key items.
3. `WEBHOOK#{key_id}` delivery log items in `delegation_api_keys` table (no new table needed — `key_id` is the hash key).
4. HMAC-SHA256 signing using `app/core/crypto.py` HMAC utilities.
5. `register_webhook`, `deliver_webhook`, `list_webhook_deliveries` functions in `delegation_api.py`.

This is a standalone sub-feature. Estimate **L** (3-5 days) for backend; **M** for frontend config UI. Can be deferred to a follow-on ticket.

### 4.6 Dev/Prod parity (SECOPS-007)

All fixes use DDB Local in dev. Webhook delivery requires outbound HTTP — in dev mode, webhook delivery should be a no-op or use a mock endpoint (`http://localhost/webhooks/test`). Add `WEBHOOK_DELIVERY_ENABLED` flag defaulting to `false` in dev, `true` in prod. This follows the SECOPS-007 principle of same code path, provider-selected behavior.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_delegation_api.py`)

| Case | Assertion |
|------|-----------|
| `test_create_key_requires_active_delegate` | 403 when caller is not an active delegate |
| `test_create_key_least_privilege` | 403 when requesting permissions beyond delegate's grants |
| `test_create_key_returns_secret_once` | `key_secret` present in create response; absent in subsequent list response |
| `test_authenticate_key_checks_delegation` | 403 when delegation is revoked after key creation |
| `test_authenticate_key_checks_ban` | 403 when delegate is banned (once SEC-018 fix applied) |
| `test_rate_limit_enforced` | 429 after RPM threshold; `Retry-After` header present |
| `test_rate_limit_headers_present` | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` in response |
| `test_revoke_by_creator` | Key marked revoked; `authenticate_key` returns 401 |
| `test_scope_view_restricted_to_owner_or_creator` | 403 when a third party requests scope |
| `test_key_expiry` | 401 when `expires_at` is in the past |

### 5.2 Playwright E2E (`frontend/e2e/delegation-api.spec.ts`)

File exists. Sections 503-506 per ticket (16 tests). Tests for creator approval (503.3 equivalent with `delegation_status=active`) will need updating once the approval flow is added. Rate limit tests (506.2) require a key with `rate_limit_rpm=2` — needs model update.

### 5.3 Manual verification

1. `just restart`.
2. Alice adds Bob as delegate with `chat_read` + `chat_respond`; Bob accepts.
3. Bob creates a delegation API key for Alice's chat.
4. Use `curl -H "Authorization: Bearer dak_..." GET /ui/delegation-api/v1/conversations` — verify Alice's conversations are returned.
5. Use `POST /v1/conversations/{cid}/messages` — verify message sent with `sender_id=alice, sent_by_delegate=bob`.
6. Alice revokes Bob (DELEGATE-001) — subsequent API key call returns 403.
7. Alice revokes the key directly (`DELETE /creator-keys/{key_id}`) — verify revoked status.

### 5.4 Rollout

`delegation_api_enabled` in `settings.py:1947` defaults to `true`. Setting to `false` disables the `delegation_api_router` registration at `main.py:699`.

### 5.5 Effort estimate

- SEC-018 ban check: **S** (1 hour)
- Per-key `rate_limit_rpm`: **S** (2 hours — model + service change)
- Creator-approval flow: **M** (1-2 days backend + 0.5 day frontend)
- v1/* feed/broadcast endpoints: **M** (1 day — wrapping existing services)
- Webhook system: **L** (deferred)
- E2E run and fixes: **S** (0.5 day after above changes)

Implementation order: SEC-018 fix → rate_limit_rpm → creator-approval → v1/* expansion → webhook (separate ticket).
