# DELEGATE-001: Delegate Management & Permissions — Investigation & Implementation Write-up

## 1. Summary & Classification

DELEGATE-001 introduces the foundational provider-delegation system: a mechanism for creators to grant named assistants and social-media managers granular, auditable, revocable permission to act on the creator's behalf across chat, newsfeed, and broadcast features. The ticket covers the new `delegates` DynamoDB table, the `app/services/delegates.py` service layer, a cookie-auth REST router, Pydantic models, DDB init changes, and a minimalist frontend `DelegatesPage`. All downstream DELEGATE-002 through DELEGATE-005 tickets call functions defined here.

- **Type**: Feature (foundational authz surface)
- **Priority/Severity**: High — blocks all delegation work
- **Status**: Implemented (service, router, DDB table, models, and partial frontend all shipped)
- **Owning area**: Identity & authorization
- **User persona**: Creator (add/manage/revoke), Delegate (accept/decline), Admin (audit)
- **Cross-references**: [[SEC-005]] (IDOR — every delegate endpoint must scope to session user), [[SEC-018]] (revocation propagation — revoke must be instant and terminate in-flight access), [[SECOPS-007]] (dev/prod parity), [[DELEGATE-002]], [[DELEGATE-003]], [[DELEGATE-004]], [[DELEGATE-005]]

---

## 2. Current-State Investigation (what exists today)

### 2.1 What exists

**Service layer — `app/services/delegates.py` (404 lines, fully implemented)**

Every function described in the ticket design is present and operational:

| Function | Location | What it does |
|----------|----------|--------------|
| `add_delegate` | `delegates.py:63` | Validates permissions, enforces self-check, dedup check, limit check, writes DDB item, writes audit |
| `respond_to_invite` | `delegates.py:112` | accept → sets `status=active`, updates `GSI1SK`; decline → deletes record |
| `update_delegate_permissions` | `delegates.py:155` | Updates `#perms` (reserved-keyword alias) + `preset`; writes audit with old/new diff |
| `revoke_delegate` | `delegates.py:196` | Atomic DDB `delete_item`; writes `delegate_revoked` audit entry |
| `list_delegates` | `delegates.py:207` | Queries `CREATOR#{id}` with `sk begins_with DELEGATE#` |
| `list_managed_creators` | `delegates.py:216` | GSI1 query on `DELEGATE#{id}`, filters `status == active` |
| `list_pending_invites` | `delegates.py:226` | Same GSI1 query, filters `status == pending` |
| `get_delegate` | `delegates.py:235` | `get_item` by exact PK+SK |
| `check_delegate_permission` | `delegates.py:243` | Returns bool; checks `status == active` + permission membership |
| `require_delegate_permission` | `delegates.py:256` | Raises `HTTPException(403)` if inactive or permission missing — called by all 002-004 services |
| `get_creator_settings` / `update_creator_settings` | `delegates.py:273` / `delegates.py:292` | Read/write `SETTINGS` item; validates `max_delegates` 1-20, preset key |
| `get_audit_log` | `delegates.py:320` | Queries `AUDIT#` prefix, `ScanIndexForward=False` |
| `get_presets` | `delegates.py:335` | Returns `PERMISSION_PRESETS` as list |
| `_write_audit` | `delegates.py:381` | Writes `AUDIT#{ts}#{evt_id}` item with `GSI2PK/GSI2SK` |

**Permission model** (`delegates.py:20-55`): `VALID_PERMISSIONS` set (7 permissions) and `PERMISSION_PRESETS` dict (6 presets, each with `label` + `permissions`) match the ticket design exactly.

**Router — `app/routers/delegates.py` (203 lines)**

All 12 endpoints in the ticket design are present, registered under `/ui/delegates`, using `require_ui_session` from `app/services/sessions.py:284` (the ticket's inline comment `"actual location"` is accurate — `require_ui_session` is indeed NOT in `app/auth/deps.py`).

**DynamoDB table** (`scripts/local-ddb-init.py:1629-1638`)

```python
TableDef(
    _resolve_table_name(S.delegates_table_name, "delegates"), "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
)
```

Both GSIs have the correct `attr_types` numeric declarations. `delegates_table_name` is set in `app/core/settings.py:1945`; `T.delegates` is in `app/core/tables.py:467`.

**Models** (`app/models.py`): `DelegateAddIn`, `DelegateUpdatePermissionsIn`, `DelegateInviteRespondIn`, `DelegateSettingsIn`, `DelegateOut`, `ManagedCreatorOut`, `DelegateSettingsOut`, `DelegateAuditOut`, `PermissionPresetOut` all present.

**Frontend**: `frontend/src/pages/delegates/DelegatesPage.tsx` exists; `frontend/src/api/endpoints/delegates.ts` exists. However several sub-components the ticket listed (`AddDelegateDialog.tsx`, `EditPermissionsDialog.tsx`, `DelegateSettingsCard.tsx`, `ManagedCreatorsPage.tsx`, `DelegateAuditLog.tsx`) are not present as standalone files — they appear to be inlined within `DelegatesPage.tsx`.

**Route**: `/delegates` is NOT found in `frontend/src/App.tsx` — only `delegation-api` (DELEGATE-005) is registered. The `DelegatesPage` is not yet routed.

**Sidebar**: Neither `Sidebar.tsx` nor `AppShell.tsx` has a "Delegates" entry.

**E2E tests**: `frontend/e2e/delegates-management.spec.ts` exists.

### 2.2 Dev vs Prod behavior

The `delegates` table is backed by DynamoDB Local (port 8001) in dev, and by real DynamoDB in prod, driven by `ddb_endpoint_url` in `.env.local`. There is no `delegates_enabled` feature flag — the feature is always on. `require_ui_session` uses the same code path in both modes (cookie + CSRF in browser; Bearer JWT for API clients). `app/services/sessions.py:284` handles both modes without `if dev:` branches, satisfying [[SECOPS-007]].

---

## 3. Gap / Threat Analysis

### 3.1 Authorization (SEC-005 / IDOR risk)

The service layer correctly enforces identity: creator-side operations (`add_delegate`, `revoke_delegate`, `update_delegate_permissions`) all verify the `creator_id` comes from `user["user_sub"]` in the router, not from the request body. The router (`delegates.py:135-188`) passes `user["user_sub"]` as `creator_id` for every mutation. No IDOR path exists at the service layer.

The `require_delegate_permission` function at `delegates.py:256` performs a hard DDB read on every call — no in-memory cache is used in DELEGATE-001. This means revocation (`revoke_delegate`) takes effect on the _next_ API call, which is the correct behavior for [[SEC-018]]. However: the router does not check if the delegate's own account is banned (a SEC-018 concern applying to all delegate actions). This gap is inherited by 002-004.

### 3.2 Revocation propagation (SEC-018)

`revoke_delegate` at `delegates.py:196` performs a single atomic `delete_item`. Downstream services (002-004) call `require_delegate_permission` which calls `get_delegate` — a `get_item` call that will return nothing after deletion, yielding a 403. SSE connections are not actively terminated on revocation; they close on the next heartbeat check. This is the residual exposure window per SEC-018.

### 3.3 Missing items

1. **Route missing**: `/delegates` is absent from `frontend/src/App.tsx`. The page exists but cannot be navigated to.
2. **Sidebar entry missing**: `Sidebar.tsx` and `AppShell.tsx` have no "Delegates" link.
3. **Sub-component files**: The ticket lists separate `AddDelegateDialog.tsx`, `EditPermissionsDialog.tsx`, etc. — these may be inlined in `DelegatesPage.tsx` rather than split into files as specified. This is a code organization gap, not a functional one.
4. **No ban-check on delegate** at the router/dependency layer: If a delegate's own account is banned (SEC-018), the cookie-auth path's ban check in `require_ui_session` (`sessions.py:284`) covers it, but the API-key auth path in DELEGATE-005 does not (see SEC-018 analysis there).
5. **No `CHAT_DELEGATION_ENABLED` / `FEED_DELEGATION_ENABLED` / `BROADCAST_DELEGATION_ENABLED` env flags** in `settings.py` — only `delegate_feed_enabled` (`settings.py:2100`) and `delegation_api_enabled` (`settings.py:1947`) exist. Chat and broadcast delegation have no individual feature flags.

### 3.4 Code sites that need attention

| File | Line(s) | Issue |
|------|---------|-------|
| `frontend/src/App.tsx` | near line 346 | Add `<Route path="delegates" element={<DelegatesPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | — | Add "Delegates" nav entry with `UserCog` icon |
| `frontend/src/components/layout/AppShell.tsx` | — | Add mobile sidebar entry |
| `app/core/settings.py` | ~2110 | Add `chat_delegation_enabled`, `broadcast_delegation_enabled` flags |

---

## 4. Proposed Design / Fix

### 4.1 Route and sidebar (immediate gaps)

Add to `frontend/src/App.tsx` alongside the `delegation-api` route (line 346):
```typescript
const DelegatesPage = lazy(() => import("@/pages/delegates/DelegatesPage"));
// ...
<Route path="delegates" element={<DelegatesPage />} />
```

Add to `Sidebar.tsx` in the Settings/Account group:
```typescript
{ label: "Delegates", icon: UserCog, to: "/delegates" }
```

### 4.2 Feature flags (SECOPS-007 parity)

Add `CHAT_DELEGATION_ENABLED` and `BROADCAST_DELEGATION_ENABLED` to `app/core/settings.py` alongside the existing `delegate_feed_enabled` at line 2100. These allow per-domain kill switches without blocking the foundational delegate management UI.

### 4.3 Revocation SSE termination (SEC-018 partial fix)

The correct fix for in-flight SSE is to maintain a per-creator revocation timestamp (a `revokedAt` watermark stored on the session entry or in a small in-memory dict) and validate it on each SSE heartbeat. This does not require changing DELEGATE-001 itself but should be tracked as a SEC-018 follow-on.

### 4.4 Dev/Prod parity (SECOPS-007)

No mock backend is required — the delegate service uses DynamoDB only (Local vs prod AWS via `ddb_endpoint_url`). All tests run fully offline against DDB Local. No AWS-specific APIs are called.

### 4.5 Alternatives considered

The ticket considered storing `DelegationContext` in the request scope via a `resolve_delegation_context` dependency using an `X-On-Behalf-Of` header. In the actual implementation, each domain service (002-004) calls `require_delegate_permission` directly with explicit `creator_id` from the URL path. This is simpler and more explicit but means the permission check is repeated rather than centralized. For the current scope (3 domains) this is acceptable.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_delegates.py`)

Key concrete cases the test suite must cover (may already exist — check before implementing):

| Case | What to assert |
|------|----------------|
| `test_add_delegate_creates_record` | DDB item has correct `pk`, `sk`, `status=pending`, `GSI1SK=0` |
| `test_add_delegate_self_rejected` | 400 with "Cannot delegate to yourself" |
| `test_add_delegate_duplicate_rejected` | 409 on second add with same pair |
| `test_delegate_limit_enforced` | 400 after `max_delegates` reached |
| `test_respond_invite_accept` | `status=active`, `GSI1SK=ts` after accept |
| `test_respond_invite_decline` | DDB item deleted |
| `test_update_permissions_audit_diff` | Audit `details` contains `old_permissions` and `new_permissions` |
| `test_revoke_creates_audit_entry` | Audit `action=delegate_revoked` written before delete |
| `test_require_delegate_permission_revoked` | 403 after delete |
| `test_check_permission_pending_not_active` | Returns False for status=pending |

### 5.2 Playwright E2E (`frontend/e2e/delegates-management.spec.ts`)

The spec file exists. It should cover sections 487-490 per the ticket (CRUD, invite flow, presets/settings, audit log — 16 tests total). Verify it actually runs: `cd frontend && npx playwright test e2e/delegates-management.spec.ts`.

The main risk is the `/delegates` route missing — tests that navigate to the page will fail until the route is added to `App.tsx`.

### 5.3 Manual verification steps

1. `just restart` to ensure the `delegates` DDB table is created fresh.
2. Navigate to `/delegates` (once route is added).
3. As Alice, add Bob as a delegate with `chat_agent` preset — confirm pending status.
4. As Bob, visit pending invites, accept — confirm `status=active`.
5. As Alice, revoke — confirm Bob's next call to a delegation endpoint returns 403.
6. Check audit log shows all three events.

### 5.4 Observability

Add a `delegate_actions_total` Prometheus counter (label: `action`) in `_write_audit` at `delegates.py:381`. This surfaces audit volume without requiring a separate metrics integration.

### 5.5 Rollback

The `delegates` table is additive. Removing the router registration from `app/main.py` lines 660 and 673 is sufficient to disable the feature without a data migration.

### 5.6 Effort and order

- Route + sidebar wiring: **S** (30 min)
- Feature flag additions: **S** (30 min)
- Sub-component file extraction (cosmetic): **M** (1 day) — optional
- SEC-018 SSE termination: **M** (tracked separately)
- E2E test run and fix: **S** (depends on route gap)

Implementation order: fix route → run E2E → then add flags.
