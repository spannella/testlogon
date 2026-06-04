# ADMIN-PERMS-001: Consolidate Admin Permissions (API scopes vs rootctl capabilities) — Investigation & Implementation Write-up

## 1. Summary & Classification

There are two parallel admin permission systems in the codebase that do not align. The system actually enforced at request time is `admin_profile.scopes` (written by `POST /admin/roles/grant` and `/admin/roles/update-profile`). A second system, `admin_capabilities`, is written only by `rootctl admin permissions set` and read back only by `rootctl admin permissions list` — it is never checked by any FastAPI endpoint in `app/`. An operator who uses the CLI to grant a capability therefore believes they have granted access when nothing enforces it. Compounding this, the CLI's `admin grant` command does not set `admin_profile.scopes` at all, so the only way to grant enforced scoped access is through the API. Additionally, `content_moderation_senior` is a real enforced scope absent from both the frontend grant UI and the frontend TypeScript type. This ticket is a security hardening item of high priority because it describes a false permission grant path.

**Type**: Security hardening (false permission grant / dead code). **Priority**: High. **Status**: Open (no implementation yet). **Owning area**: Auth / admin role management.

**Attacker class / affected persona**: Platform operators running `rootctl` who believe they have restricted an admin to specific capabilities. A wrongly-privileged admin (⚙️ config / 🛡️ admin-abuse).

Cross-referenced: ROOTCTL-001 (break-glass auth), ROOT-AUTH-001 (root login).

---

## 2. Current-State Investigation (what exists today)

### System 1: `admin_profile.scopes` — the enforced system

**Enum definition**: `app/auth/roles.py:14-18`
```python
class AdminScope(str, Enum):
    AUTH_SUPPORT = "auth_support"
    BILLING_SUPPORT = "billing_support"
    CONTENT_MODERATION = "content_moderation"
    CONTENT_MODERATION_SENIOR = "content_moderation_senior"
```
`CANONICAL_ADMIN_SCOPES` tuple at `app/auth/roles.py:26-31` lists all four values.

**Written by the API**: `POST /admin/roles/grant` (`app/routers/admin_roles.py:197-269`) and `POST /admin/roles/update-profile` (`app/routers/admin_roles.py:272-339`). Both call `_validate_admin_profile_input(admin_profile_type, admin_scopes)` which resolves and validates scope values against `AdminScope`, then write:
```python
T.users.update_item(..., UpdateExpression="SET ... admin_profile=:admin_profile ...")
```
The stored value is `{"type": "scoped", "scopes": ["auth_support", "billing_support"]}` or `{"type": "general"}`.

**Enforced by**: `require_admin_scope(scope)` in `app/auth/policy.py:122-169`. This is a FastAPI dependency factory that reads `user.admin_profile` from the `AuthenticatedUser` dataclass (populated from the `ui_access_token` JWT cookie or Cognito JWT by `app/auth/deps.py:148-149,228`). It calls `admin_profile_has_scope(profile, normalized_scope)` (`app/auth/roles.py:118-124`) — for `GENERAL` type profiles this always returns `True`; for `SCOPED` type it checks membership. On denial, it calls `record_admin_scope_denied()` (metrics) and `audit_event("admin_scope_denied", ...)`.

**Used in routers today**:
- `app/routers/admin_dmca.py:41` — `require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)`
- `app/routers/admin_impersonation.py:25` — `require_auth_support_admin = require_admin_scope("auth_support")`
- `app/routers/admin_appeals.py:37` — `require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)`
- `app/routers/admin_entitlements.py:21` — `require_billing_support_admin = require_admin_scope("billing_support")`
- `app/routers/admin_moderation.py:36` — `require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)`
- `app/routers/admin_moderation.py:47` — manual check for `CONTENT_MODERATION_SENIOR` via `admin_profile_has_scope(profile, AdminScope.CONTENT_MODERATION_SENIOR)` (used for permanent bans)
- `app/routers/admin_video_review.py:35` — `require_review_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)`
- `app/routers/billing.py:105` — `require_billing_support_admin = require_admin_scope("billing_support")`
- `app/routers/billing.py:445` — manual `admin_profile_has_scope(actor.admin_profile, AdminScope.BILLING_SUPPORT)` check

### System 2: `admin_capabilities` — the dead system

**Enum definition**: `app/cli/rootctl.py:51-58`
```python
ADMIN_CAPABILITIES = {
    "billing_ops",
    "billing_read",
    "file_metadata",
    "file_content",
    "user_support",
    "impersonation",
}
```
These six names have zero overlap with the four `AdminScope` values in System 1.

**Feature flag**: `ROOTCTL_ADMIN_CAPABILITIES_ENABLED` env var, checked by `_admin_capabilities_enabled()` at `rootctl.py:61-63`.

**Written by the CLI**: `rootctl admin permissions set --capability <name> ...` calls `_admin_capabilities_set_command` (rootctl.py around line 1658), which does:
```python
T.users.update_item(...,
    UpdateExpression="SET admin_capabilities=:caps, admin_caps_updated_at=:ts, ..."
)
```
at `rootctl.py:1703`. It writes to a completely different attribute (`admin_capabilities`) than the enforced system (`admin_profile`).

**Read by the CLI only**: `rootctl admin permissions list` calls `_admin_capabilities_list_command` at `rootctl.py:1748-1767`, which reads `item.get("admin_capabilities", [])` and prints it. This is the **only place** `admin_capabilities` is read back.

**Enforced by**: nothing. A full-text search for `admin_capabilities` in `app/` (excluding `app/cli/rootctl.py`) returns zero results. No FastAPI middleware, dependency, or endpoint checks `admin_capabilities`.

### Frontend type drift

`frontend/src/api/endpoints/adminRoles.ts:4`:
```typescript
export type AdminScope = "auth_support" | "billing_support" | "content_moderation";
```
`content_moderation_senior` is absent. It is enforced by the backend at `app/routers/admin_moderation.py:47` and `app/auth/roles.py:17`. The frontend grant UI (`frontend/src/pages/admin/RootRoleManagementPage.tsx:26-30`) has an `ADMIN_SCOPE_OPTIONS` array with exactly three entries:
```typescript
const ADMIN_SCOPE_OPTIONS = [
  { value: "auth_support", ... },
  { value: "billing_support", ... },
  { value: "content_moderation", ... },
];
```
`content_moderation_senior` cannot be granted from the admin UI. An operator wanting to grant senior moderation scope (required for permanent bans in `admin_moderation.py:43-57`) must use a raw API call.

### CLI grant command does not write `admin_profile`

`_admin_grant_command` in `rootctl.py:1303-1398` writes only:
```python
UpdateExpression="SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason"
```
There is no `admin_profile=:admin_profile` in this UpdateExpression. A user granted admin via the CLI gets `role=admin` but no `admin_profile`, which means `normalize_admin_profile()` falls back to `AdminProfileType.GENERAL` (line `app/auth/roles.py:104-105`: `if profile_type is not AdminProfileType.SCOPED: return AdminProfile(type=AdminProfileType.GENERAL)`). A `GENERAL` admin has `admin_profile_has_scope` return `True` for **all scopes** — so CLI-granted admins inadvertently get full admin access to all scoped features. The `require_admin_scope` check passes for them.

This means the CLI grant path is over-permissive by default. Combined with the dead `admin_capabilities` system that appears to restrict access but does not, an operator could believe they have tightly scoped an admin while actually granting them general (full) admin access.

### Dev vs Prod parity

The `admin_profile` read path (`app/auth/deps.py:148-149` cookie → JWT → `_extract_admin_profile_from_claims`) is identical in dev and prod. In dev mode the `X-User-Admin-Profile` header fallback at `deps.py:258-259` allows tests to inject an admin profile without a signed JWT. In prod, admin profile is baked into the `ui_access_token` cookie JWT at session creation time and verified by the HS256 signature. The `admin_capabilities` field in DynamoDB is never read in either environment.

---

## 3. Gap / Threat Analysis

### Threat 1: False permission restriction (security)

An operator runs `rootctl admin permissions set --capability user_support alice@example.com` believing they have limited Alice to user support tasks only. In reality:
1. `admin_capabilities: ["user_support"]` is written to Alice's DynamoDB user record.
2. No FastAPI endpoint reads this field.
3. Alice's `admin_profile` is either `GENERAL` (if she was CLI-granted, full access) or a previously-set scoped profile (if API-granted, scoped access).
4. `rootctl admin permissions list alice@example.com` shows `["user_support"]`, reinforcing the false belief.

**Impact**: An admin whom an operator believes is restricted to user support tasks may in fact have full admin access to billing, content moderation, impersonation, and DMCA endpoints. This is a privilege escalation vulnerability in the operational sense — the access control model is not what operators believe it is.

**Precondition**: Operator uses `rootctl admin permissions set` (requires `ROOTCTL_ADMIN_CAPABILITIES_ENABLED=1`). By default this flag is off, limiting blast radius.

### Threat 2: Implicit full-admin via CLI grant

An operator runs `rootctl admin grant alice@example.com` with no scopes specified. Alice gets `role=admin` with no `admin_profile`. The `require_admin_scope` dependency falls through to `GENERAL` and returns True for all scope checks. This means every CLI-granted admin has implicitly full admin access to all scoped features, including permanent bans and impersonation, regardless of the operator's intent.

### Threat 3: `content_moderation_senior` scope cannot be granted from UI

The backend enforces `CONTENT_MODERATION_SENIOR` at `admin_moderation.py:47` for permanent bans. The frontend `ADMIN_SCOPE_OPTIONS` array at `RootRoleManagementPage.tsx:26-30` does not include it. Any admin needing to issue permanent bans must be manually API-granted this scope by a root user via curl/Swagger — there is no UI path. This is a usability gap with a security dimension (scope must be granted explicitly, not guessable by trial-and-error in the UI).

### Code sites that must change

1. `app/cli/rootctl.py` — `_admin_grant_command` (line 1303), `_admin_capabilities_set_command` (~line 1658), `_admin_capabilities_list_command` (~line 1748), `ADMIN_CAPABILITIES` set (line 51), `ADMIN_CAPABILITY_FEATURE_FLAG` (line 50), `_admin_capabilities_enabled()` (line 61), argparse `permissions set/list` subcommands (~lines 2313-2336).
2. `frontend/src/api/endpoints/adminRoles.ts` — `AdminScope` type (line 4).
3. `frontend/src/pages/admin/RootRoleManagementPage.tsx` — `ADMIN_SCOPE_OPTIONS` array (lines 26-30).

---

## 4. Proposed Design / Fix

### 4.1 Make `admin_profile.scopes` the single source of truth

Remove the `admin_capabilities` write path from `rootctl.py` and optionally the whole `permissions set/list` subcommands, or repoint them to write `admin_profile` instead.

**Option A (recommended): Repoint `rootctl permissions set` to write `admin_profile.scopes`**

Replace the body of `_admin_capabilities_set_command` to call the same DynamoDB UpdateExpression used by the API:
```python
admin_profile = {"type": "scoped", "scopes": sorted(new_caps)}
T.users.update_item(
    Key={"user_sub": target_user_sub},
    UpdateExpression="SET admin_profile=:ap, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
    ExpressionAttributeValues={
        ":ap": admin_profile, ":ts": now_ts(), ":by": actor_sub, ":reason": reason
    },
)
```
Replace `ADMIN_CAPABILITIES` set with `AdminScope` values:
```python
ADMIN_CAPABILITIES = {s.value for s in AdminScope}
```
Change `_admin_capabilities_list_command` to read `admin_profile` instead of `admin_capabilities`.

This way `rootctl permissions set --capability content_moderation alice@example.com` writes `admin_profile={"type":"scoped","scopes":["content_moderation"]}` — exactly the same field the API writes and `require_admin_scope` enforces.

**Option B: Delete `permissions set/list` entirely**

Remove the subcommands and direct operators to use the API (`POST /admin/roles/grant` or `/admin/roles/update-profile`). Simpler but less backward-compatible.

### 4.2 Add `--scope` to `rootctl admin grant`

`_admin_grant_command` at `rootctl.py:1303` must be extended to optionally accept scopes and write `admin_profile`:

```python
# Add to argparse at line ~2285:
grant.add_argument("--scope", dest="scopes", action="append", default=[],
                   help="Admin scope (repeatable). Allowed: auth_support, billing_support, "
                        "content_moderation, content_moderation_senior")
grant.add_argument("--profile-type", dest="profile_type", default="general",
                   choices=("general", "scoped"))

# In _admin_grant_command body, after role is validated:
if args.profile_type == "scoped" and not args.scopes:
    raise CliPolicyError("scoped profile requires at least one --scope")
admin_profile = _build_admin_profile(args.profile_type, args.scopes or [])

# In UpdateExpression:
"SET #role=:role, admin_profile=:admin_profile, role_updated_at=:ts, ..."
```

Add a shared helper `_build_admin_profile(profile_type, scopes)` that mirrors `_validate_admin_profile_input` from `admin_roles.py`. This ensures CLI and API write identical structures.

### 4.3 One-off migration of `admin_capabilities` records

Scan the users table for items with `admin_capabilities` attribute. For each, convert the capability names to their nearest `AdminScope` equivalents (or drop them if no mapping exists) and write `admin_profile`. Suggested mapping:

| `admin_capabilities` (dead) | Nearest `AdminScope` |
|---|---|
| `user_support` | `auth_support` |
| `billing_ops`, `billing_read` | `billing_support` |
| `file_metadata`, `file_content` | `content_moderation` (closest available) |
| `impersonation` | `auth_support` + manual check |

After migration, remove the `admin_capabilities` attribute from DynamoDB records with a second scan + UpdateExpression `REMOVE admin_capabilities`.

### 4.4 Frontend: add `content_moderation_senior`

**`frontend/src/api/endpoints/adminRoles.ts:4`** — change:
```typescript
export type AdminScope = "auth_support" | "billing_support" | "content_moderation" | "content_moderation_senior";
```

**`frontend/src/pages/admin/RootRoleManagementPage.tsx:26-30`** — add:
```typescript
{ value: "content_moderation_senior", label: "Content moderation (senior)",
  guidance: "Permanent ban authority; dual-approval for irreversible moderation actions" },
```

### 4.5 Dev/Prod parity (SECOPS-007)

All proposed changes operate on DynamoDB user records via `T.users` handle — DynamoDB Local in dev, real DynamoDB in prod. No new AWS dependencies. The `admin_profile` JWT embedding (`e2e_admin_session_setup.py` creates role-bearing JWT cookies for E2E test identities) already handles the `admin_profile` field; extending it to include `content_moderation_senior` requires only a re-run of the session setup script.

### 4.6 Alternatives considered

**Keep `admin_capabilities` as a second enforcement point**: Rejected. Adding enforcement to a field whose name and values differ from the existing system would split the enforcement model further. The right design is one field, one enforcer.

**Make CLI-granted admins `scoped` with empty scopes**: Rejected. Empty scoped profile falls back to `GENERAL` anyway (`normalize_admin_profile` at `roles.py:111-112`). The correct default for a CLI-granted admin with no explicit scope should be `GENERAL` (full admin), consistent with the current implicit behaviour.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_admin_perms_consolidation.py`)

- `test_cli_grant_with_scopes_writes_admin_profile`: call `_admin_grant_command` with `--scope auth_support --profile-type scoped`; assert DynamoDB `admin_profile = {"type": "scoped", "scopes": ["auth_support"]}`.
- `test_cli_grant_without_scopes_writes_general_profile`: call without `--scope`; assert `admin_profile = {"type": "general"}`.
- `test_capabilities_set_aliases_to_admin_profile`: call `_admin_capabilities_set_command` with `--capability billing_ops`; assert `admin_profile.scopes` contains `billing_support` (or mapped value), not `admin_capabilities`.
- `test_require_admin_scope_respects_cli_set_scopes`: grant `billing_support` via CLI; create a fake session with the resulting `admin_profile`; inject into `require_admin_scope("billing_support")`; assert it passes. Inject into `require_admin_scope("auth_support")`; assert it returns 403.
- `test_content_moderation_senior_scope_can_be_granted`: call `POST /admin/roles/grant` with `admin_scopes=["content_moderation_senior"]`; assert stored `admin_profile.scopes` contains `content_moderation_senior`.
- `test_content_moderation_senior_enforced_for_permanent_ban`: call `_require_senior_moderation_for_permanent_ban(admin=user_without_senior_scope)`; assert 403. Call with `content_moderation_senior` in scopes; assert passes.
- `test_admin_capabilities_no_longer_written_after_migration`: after fix, call `permissions set`; assert `admin_capabilities` attribute is absent from DynamoDB item and only `admin_profile` is present.

### E2E tests (Playwright — extend `frontend/e2e/admin-roles.spec.ts`)

- `Grant content_moderation_senior in UI and verify enforcement`: in `GrantAdminForm`, select "Content moderation (senior)" scope; submit; assert `POST /admin/roles/grant` response contains `admin_profile.scopes: ["content_moderation_senior"]`.
- `Root grants scoped admin via API; verify CLI list shows same scopes`: API grant with `auth_support`; run `rootctl admin permissions list`; assert CLI output shows `auth_support` (not `admin_capabilities`).
- `Scoped admin without content_moderation_senior gets 403 on permanent ban endpoint`.

### Manual verification steps

1. Set `ROOTCTL_ADMIN_CAPABILITIES_ENABLED=1` in `.env.local`.
2. Run `python3 scripts/rootctl admin permissions set --capability billing_ops alice@test.local`.
3. Verify `T.users.get_item({"user_sub": "alice@test.local"})` shows `admin_profile = {"type": "scoped", "scopes": ["billing_support"]}` and no `admin_capabilities` field.
4. Make a request to a `require_admin_scope("billing_support")` endpoint as Alice; verify 200.
5. Make a request to a `require_admin_scope("auth_support")` endpoint as Alice; verify 403.
6. Grant `content_moderation_senior` through the updated UI; verify the scope appears in the grant dialog and the stored profile.

### Rollout

1. Merge the backend CLI fix and frontend type/UI change together (they are independent of each other but should ship together to avoid a window where the UI can't grant a scope that already exists in the backend).
2. Run the one-off migration script against the users table to convert any existing `admin_capabilities` records.
3. Deploy with `ROOTCTL_ADMIN_CAPABILITIES_ENABLED=0` (default) to ensure no operators use the old path during migration.
4. After migration is verified complete, optionally remove the `permissions set/list` commands entirely or leave them aliased to the new system.

**Effort estimate**: M (CLI changes ~100 lines; frontend type/UI changes ~5 lines; migration script ~50 lines; tests ~150 lines).

**Risks**: The migration mapping from capability names to scope names is imprecise (e.g., `file_metadata` → `content_moderation` is a stretch). In practice, if `ROOTCTL_ADMIN_CAPABILITIES_ENABLED` has never been set to `1` in production, there are likely no `admin_capabilities` records to migrate. Confirm with a DynamoDB scan before investing in migration logic.
