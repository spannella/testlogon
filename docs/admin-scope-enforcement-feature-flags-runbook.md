# Admin Scope Enforcement Feature Flags Runbook (AP-016)

## Purpose
Use these feature flags to enable scoped-admin authorization checks by domain in controlled phases. Flags can be toggled independently for auth-support, billing, and moderation without reverting role/profile data.

## Flags
- `ADMIN_SCOPE_ENFORCE_AUTH_SUPPORT` (default: `1`)
  - `1`: enforce `auth_support` scoped checks for auth-support admin controls.
  - `0`: fallback to legacy broad `admin/root` behavior for those controls.
- `ADMIN_SCOPE_ENFORCE_BILLING_SUPPORT` (default: `1`)
  - `1`: enforce `billing_support` scoped checks on billing admin operations.
  - `0`: fallback to legacy broad `admin/root` behavior.
- `ADMIN_SCOPE_ENFORCE_CONTENT_MODERATION` (default: `1`)
  - `1`: enforce `content_moderation` scoped checks for moderation controls.
  - `0`: fallback to legacy broad `admin/root` behavior.

## Recommended progressive enablement
1. **Pre-checks**
   - Ensure AP-015 backfill completed for existing admins (`admin_profile.type=general`).
   - Verify API metrics/logs for `403 role_required_scope` are observable.
2. **Auth-support rollout**
   - Set only `ADMIN_SCOPE_ENFORCE_AUTH_SUPPORT=1` in target environment.
   - Keep billing/moderation flags at current desired state.
   - Validate auth-support scoped admins can access auth-support endpoints.
3. **Billing rollout**
   - Set `ADMIN_SCOPE_ENFORCE_BILLING_SUPPORT=1`.
   - Validate billing scoped admins can perform billing actions; non-billing scoped admins are denied.
4. **Moderation rollout**
   - Set `ADMIN_SCOPE_ENFORCE_CONTENT_MODERATION=1`.
   - Validate moderation scoped admins can perform moderation actions; non-moderation scoped admins are denied.

## Verification checklist
- Root retains access across all admin domains.
- General admins retain broad access.
- Scoped admins are granted only their assigned domain permissions.
- Denials return structured scope error payloads (`code=role_required_scope`) for operator UX mapping.

## Rollback
If a domain rollout causes operational issues:
1. Toggle the domain flag to `0`.
2. Redeploy/reload configuration.
3. Confirm legacy broad `admin/root` behavior restored for that domain.

No role-data rollback is required; admin profile records remain valid and can be re-used when the flag is turned back on.

## Scope-denied metrics and alerts (AP-017)

### Metric emitted
- `admin_scope_denied_total{route,required_scope,admin_profile_type}`
  - emitted whenever `require_admin_scope(...)` denies an admin request with `403 code=role_required_scope`.
  - dimensions:
    - `route`: normalized FastAPI route path (for example `/api/billing/_dev/add-charge`).
    - `required_scope`: one of `auth_support`, `billing_support`, `content_moderation`.
    - `admin_profile_type`: effective profile type of caller (`general` or `scoped`).

### Dashboard panels
Add these panels to the admin-scope rollout dashboard:
1. **Total scope denials (all domains)**
   - `sum(increase(admin_scope_denied_total[15m]))`
2. **Denials by route**
   - `topk(10, sum by (route) (increase(admin_scope_denied_total[15m])))`
3. **Denials by required scope**
   - `sum by (required_scope) (increase(admin_scope_denied_total[15m]))`
4. **Denials by profile type**
   - `sum by (admin_profile_type) (increase(admin_scope_denied_total[15m]))`

### Alert thresholds
Start with conservative rollout thresholds and tune per environment:
- **Warning: domain denial spike**
  - Trigger when any scope exceeds 20 denials in 15 minutes.
  - PromQL example:
    - `sum by (required_scope) (increase(admin_scope_denied_total[15m])) > 20`
- **Critical: endpoint denial spike**
  - Trigger when any single endpoint exceeds 30 denials in 10 minutes.
  - PromQL example:
    - `sum by (route, required_scope) (increase(admin_scope_denied_total[10m])) > 30`

### Alert response guidance
- Correlate spike scope/route with recent flag toggles (`ADMIN_SCOPE_ENFORCE_*`) and role-profile updates.
- If misclassification is suspected, disable only the impacted domain flag as an immediate rollback.
- Open a security review ticket for repeated spikes on the same route/scope pair.

