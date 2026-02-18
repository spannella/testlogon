# Admin permissions model extension plan

## Goal
Introduce scoped admin roles so support staff can be limited to specific operational domains:

- **Login & account recovery admins** can help with sign-in, MFA, passwordless, and recovery actions only.
- **Billing admins** can handle billing, payments, subscriptions, invoices, and refunds only.
- **Content moderation admins** can review and moderate user-generated content only.
- **General admins** keep broad admin access (non-root), while **root** remains the highest-privilege role.

## Current-state constraints

- Authorization is currently coarse-grained (`root`, `admin`, `user`) via `Role` enum and policy helpers.
- Role management APIs only grant/revoke the single `admin` role.
- Existing admin checks are endpoint-level (for example `require_admin_or_root`) and do not model domain scopes.

## Proposed authorization model

### 1) Split identity role from admin capability scope
Keep top-level identity roles:

- `root`
- `admin`
- `user`

Add a separate **admin capability profile** persisted on user records, for users where `role=admin`.

Example shape:

```json
{
  "role": "admin",
  "admin_profile": {
    "type": "scoped",
    "scopes": ["auth_support", "billing_support"]
  }
}
```

Alternative for general admins:

```json
{
  "role": "admin",
  "admin_profile": {
    "type": "general"
  }
}
```

### 2) Define capability vocabulary
Use stable scope keys:

- `auth_support` (login/account recovery/MFA/passwordless/device trust)
- `billing_support` (billing, subscriptions, payment methods, reconciliation assist tools)
- `content_moderation` (newsfeed moderation, abuse actions, moderation queue)
- `admin_general` (optional synthetic scope if you prefer explicit broad capability)

Rules:

- `root` bypasses scope checks.
- `admin` with `type=general` is allowed in all admin-gated domains.
- `admin` with `type=scoped` must have the required scope(s) for each domain action.
- `user` has no admin privileges.

## Implementation phases

### Phase 1 — Data model and policy primitives
1. Add an admin capability model in auth layer (`app/auth/roles.py` or a new `app/auth/admin_scopes.py`):
   - enum/constants for scopes
   - parser/normalizer for stored `admin_profile`
   - helper: `admin_has_scope(user, required_scope)`
2. Add policy dependencies in `app/auth/policy.py`:
   - `require_admin_scope(scope)`
   - `require_general_admin_or_root()` (for endpoints needing broad powers)
3. Keep `require_admin_or_root()` temporarily for backward compatibility while migrating endpoints.

**Deliverable:** policy helpers compiled and unit-tested without endpoint migration.

### Phase 2 — Role assignment API evolution
1. Extend admin role APIs (`app/routers/admin_roles.py`) to support profile assignment when granting admin:
   - grant payload accepts either `general` or `scoped` + scope list
   - validate allowed scopes, reject empty scoped set
2. Add targeted endpoint for updating scope/profile of existing admins (root-only):
   - `POST /admin/roles/update-profile`
3. Expand role audit event schema to include profile transitions:
   - `previous_admin_profile`, `new_admin_profile`

**Deliverable:** root can create any of the 4 admin types and audit changes.

### Phase 3 — Endpoint permission migration (backend)
Migrate routes by domain and replace broad checks with scope-aware dependencies.

1. **Auth support domain**
   - likely routers: `password_recovery`, `recovery`, `passwordless`, `mfa_devices`, `ui_mfa`, `device_trust`, session-security actions.
   - enforce `require_admin_scope("auth_support")` where admin intervention occurs.
2. **Billing domain**
   - likely routers: `billing`, `billing_ccbill`, `paypal`, `subscription_server`, receipts/reconcile utilities.
   - enforce `require_admin_scope("billing_support")`.
3. **Content moderation domain**
   - moderation/admin actions in content routers (for example newsfeed or messaging moderation endpoints).
   - enforce `require_admin_scope("content_moderation")`.
4. Keep sensitive cross-domain controls as general-admin/root only:
   - impersonation, role management, system-wide policy toggles, destructive global operations.

**Deliverable:** endpoint matrix mapped to scopes; deprecated broad checks minimized.

### Phase 4 — Frontend and operator UX
1. Update admin role management UI (`frontend/src/pages/admin/RootRoleManagementPage.tsx` + API client):
   - assign admin type: auth support / billing support / content moderation / general
   - edit scopes for scoped admins
2. Gate frontend admin features by returned capability profile to reduce accidental access attempts.
3. Improve error UX for scope denial (`403 role_required_scope`) with actionable messaging.

**Deliverable:** root can assign scoped/general admins from UI; scoped admins see only permitted controls.

### Phase 5 — Testing and migration hardening
1. Unit tests:
   - scope parsing and default behavior
   - policy dependency behavior for root/general/scoped/no-scope cases
2. Route tests:
   - domain-admin positive/negative authorization tests
3. Regression tests:
   - existing root behavior unchanged
   - existing general admin behavior remains broad
4. Data migration:
   - backfill existing `role=admin` users to `admin_profile.type=general`
   - idempotent migration script + rollback notes

**Deliverable:** deterministic migration with full auth regression coverage.

## Rollout strategy

1. **Release A:** ship policy/data model + compatibility mode (no endpoint behavior change yet).
2. **Release B:** enable scope-aware checks on low-risk endpoints behind a feature flag.
3. **Release C:** migrate remaining admin endpoints and enforce profile requirements in role assignment.
4. **Release D:** remove legacy broad checks where no longer needed.

## Security and operational safeguards

- Default-deny for scoped admins on unclassified endpoints until explicitly mapped.
- Root-only control for creating/updating admin profiles.
- Full audit trail for role/profile/scope changes.
- Add metrics for denied scope checks by route to catch misclassification quickly.
- Document incident break-glass process for temporary general-admin elevation.

## Suggested acceptance criteria

- Root can create all four admin categories.
- Login support admin can perform recovery/login actions but cannot access billing or moderation admin actions.
- Billing admin can perform billing actions but cannot access login support or moderation admin actions.
- Content moderation admin can perform moderation actions but cannot access login support or billing admin actions.
- General admin can access all non-root admin functions.
- All denied actions return a structured 403 with missing scope detail and are audit logged.
