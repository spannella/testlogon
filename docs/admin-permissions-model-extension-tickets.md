# Admin permissions model extension — Implementation tickets

This backlog translates `docs/admin-permissions-model-extension-plan.md` into implementation-ready tickets.

## Delivery assumptions
- Keep existing top-level roles (`root`, `admin`, `user`) and add scoped admin capabilities via `admin_profile`.
- Ship with backward compatibility first; tighten enforcement in phased rollout.
- Root remains the only actor that can create/modify admin capability profiles.

---

## Epic AP-1 — Authorization model foundation

### AP-001: Define admin scope constants and profile schema
**Goal**: Introduce a canonical scope vocabulary and normalized admin profile structure.

**Scope**
- Add canonical scope keys and profile type enums/constants (`general`, `scoped`).
- Add parser/normalizer for persisted `admin_profile` values.
- Define deterministic fallback behavior for malformed/missing profile data.

**Acceptance criteria**
- Scope names are centralized and imported from one source of truth.
- Profile normalization is deterministic for valid/invalid input.
- Unit tests cover schema normalization and fallback behavior.

**Dependencies**: None.

---

### AP-002: Add policy helpers for scope-based authorization
**Goal**: Extend auth policy with reusable dependencies for scoped admin checks.

**Scope**
- Add `require_admin_scope(scope)` policy dependency.
- Add `require_general_admin_or_root()` policy dependency.
- Preserve `require_admin_or_root()` temporarily for compatibility while migration is in progress.

**Acceptance criteria**
- Root always passes scoped checks.
- General admins pass all admin-domain checks.
- Scoped admins are denied when required scope is missing with structured `403` payload.
- Unit tests cover root/general/scoped/user allow-deny matrix.

**Dependencies**: AP-001.

---

### AP-003: Add structured authorization denial contract for missing scopes
**Goal**: Standardize API error shape for scope-denied requests.

**Scope**
- Add/extend error payload to include fields like `code`, `required_scope`, and `actual_admin_profile` summary.
- Ensure denied scope checks are auditable.

**Acceptance criteria**
- All scope-denied responses use one canonical error contract.
- Tests assert response schema and status code consistency.

**Dependencies**: AP-002.

---

## Epic AP-2 — Role/profile lifecycle APIs and auditing

### AP-004: Extend admin grant API to accept capability profile
**Goal**: Allow root to create either general admins or scoped admins.

**Scope**
- Extend grant request payload with profile mode (`general` or `scoped`) and optional `scopes` list.
- Validate: allowed scope values, no duplicates, non-empty set for scoped mode.
- Preserve existing root-only guardrails and root immutability behavior.

**Acceptance criteria**
- Root can grant admin with `general` profile.
- Root can grant admin with `scoped` profile for any supported scope set.
- Invalid profile payloads fail with deterministic `400` errors.

**Dependencies**: AP-001, AP-002.

---

### AP-005: Add profile update endpoint for existing admins
**Goal**: Support changing admin capability profile after role grant.

**Scope**
- Add root-only endpoint: `POST /admin/roles/update-profile`.
- Enforce target eligibility (`role=admin`, not root, existing user).
- Support transitions: `general -> scoped`, `scoped -> general`, `scoped -> scoped`.

**Acceptance criteria**
- Root can update profile transitions safely.
- Non-root actors receive `403`.
- Invalid transitions or targets return explicit errors.

**Dependencies**: AP-004.

---

### AP-006: Expand role audit events to include profile transitions
**Goal**: Preserve a complete immutable audit trail for profile changes.

**Scope**
- Add profile fields to relevant audit events (`previous_admin_profile`, `new_admin_profile`).
- Apply to grant/revoke/update-profile events.
- Keep actor/target/request metadata intact.

**Acceptance criteria**
- Every role/profile mutation writes immutable event(s) with old/new profile values.
- Audit query endpoint returns profile transition data.

**Dependencies**: AP-004, AP-005.

---

## Epic AP-3 — Backend endpoint migration by domain

### AP-007: Build endpoint-to-scope authorization matrix
**Goal**: Classify all admin-gated routes before enforcing scoped checks.

**Scope**
- Inventory endpoints currently using broad admin checks.
- Map each endpoint to one of: `auth_support`, `billing_support`, `content_moderation`, or `general_admin_only`.
- Mark unresolved/ambiguous routes for security review.

**Acceptance criteria**
- Published matrix includes route, method, scope, and owner.
- All current admin-gated routes are classified or explicitly deferred.

**Dependencies**: AP-002.

---

### AP-008: Migrate auth-support routes to `auth_support` scope
**Goal**: Restrict admin intervention in login/recovery domains to appropriate admins.

**Scope**
- Apply `require_admin_scope("auth_support")` to designated auth-support endpoints.
- Keep root bypass behavior.
- Add positive/negative tests for scope-specific access.

**Acceptance criteria**
- Auth-support scoped admins can perform allowed auth-support actions.
- Billing/moderation scoped admins are denied on auth-support routes.

**Dependencies**: AP-007.

---

### AP-009: Migrate billing routes to `billing_support` scope
**Goal**: Restrict billing operations to billing-capable admins.

**Scope**
- Apply `require_admin_scope("billing_support")` to billing endpoints/services.
- Ensure shared billing helpers use consistent authorization paths.
- Add positive/negative tests.

**Acceptance criteria**
- Billing scoped admins can perform allowed billing actions.
- Auth/moderation scoped admins are denied on billing routes.

**Dependencies**: AP-007.

---

### AP-010: Migrate moderation routes to `content_moderation` scope
**Goal**: Restrict moderation controls to moderation-capable admins.

**Scope**
- Apply `require_admin_scope("content_moderation")` to moderation/admin content controls.
- Add tests for allow/deny behavior.

**Acceptance criteria**
- Moderation scoped admins can perform moderation actions.
- Non-moderation scoped admins are denied.

**Dependencies**: AP-007.

---

### AP-011: Enforce general-admin-or-root checks for cross-domain sensitive controls
**Goal**: Keep high-risk controls limited to broad admins/root.

**Scope**
- Replace broad legacy checks on designated sensitive endpoints with `require_general_admin_or_root()`.
- Candidate domains include impersonation controls, role management, and global policy toggles.

**Acceptance criteria**
- Scoped admins cannot access general-admin-only controls.
- General admins and root continue to access those controls.

**Dependencies**: AP-002, AP-007.

---

## Epic AP-4 — Frontend and operator workflows

### AP-012: Update root admin role management UI for profile assignment
**Goal**: Allow root operators to create/edit scoped or general admins from UI.

**Scope**
- Add profile mode selector and scope multi-select in role management page.
- Wire API request/response contracts for profile fields.
- Add form validation and clear operator guidance text.

**Acceptance criteria**
- Root can assign each of the 4 requested admin categories via UI.
- Invalid combinations are blocked client-side and handled server-side.

**Dependencies**: AP-004, AP-005.

---

### AP-013: Gate admin frontend surfaces by capability profile
**Goal**: Reduce accidental unauthorized actions and noisy 403s.

**Scope**
- Hide/disable admin controls not permitted by current profile.
- Keep server as source of truth (frontend gating is UX optimization, not security boundary).

**Acceptance criteria**
- Scoped admins only see relevant admin UI sections by default.
- General admins keep broad admin UI access.

**Dependencies**: AP-001, AP-012.

---

### AP-014: Add user-facing scope-denied error UX
**Goal**: Provide actionable denial messages for support operators.

**Scope**
- Map scope-denied API responses to human-readable explanations.
- Include recommended escalation path (for example request temporary elevation).

**Acceptance criteria**
- Scope-denied interactions show consistent actionable messaging.
- No raw/unparsed backend error payloads leak into UI.

**Dependencies**: AP-003, AP-013.

---

## Epic AP-5 — Migration, release controls, and observability

### AP-015: Backfill existing admins to `admin_profile.type=general`
**Goal**: Preserve existing admin capabilities during rollout.

**Scope**
- Create idempotent migration job/script for existing `role=admin` users.
- Add dry-run/report mode and rollback notes.

**Acceptance criteria**
- Migration can run repeatedly without duplicate/inconsistent writes.
- Existing admins retain broad access post-migration.

**Dependencies**: AP-001.

---

### AP-016: Add feature flags for phased enforcement
**Goal**: De-risk production rollout.

**Scope**
- Add flags to control per-domain scope enforcement activation.
- Add operational runbook for progressive enablement.

**Acceptance criteria**
- Teams can independently enable auth, billing, and moderation scope checks.
- Rollback is possible by toggling flags without data rollback.

**Dependencies**: AP-008, AP-009, AP-010.

---

### AP-017: Add metrics and alerts for denied scope checks
**Goal**: Detect misclassification and support friction early.

**Scope**
- Emit metrics for `scope_denied` by route/scope/profile type.
- Add alert thresholds for spikes post-rollout.

**Acceptance criteria**
- Dashboards show denial trends by endpoint and scope.
- Alerting triggers on abnormal denial spikes.

**Dependencies**: AP-003.

---

### AP-018: Build end-to-end authorization regression suite
**Goal**: Prevent permission regressions as route coverage expands.

**Scope**
- Add test matrix for user, scoped-admin variants, general admin, and root.
- Cover all migrated domains and general-admin-only controls.
- Verify audit event emission on denied and allowed privileged operations where applicable.

**Acceptance criteria**
- CI includes permission matrix tests for scoped/admin/root behavior.
- Regressions in scope enforcement block merge.

**Dependencies**: AP-008, AP-009, AP-010, AP-011.

---

## Requested admin categories mapping

- **Login/account recovery admin** = `role=admin`, `admin_profile.type=scoped`, `scopes=["auth_support"]`
- **Billing admin** = `role=admin`, `admin_profile.type=scoped`, `scopes=["billing_support"]`
- **Content moderation admin** = `role=admin`, `admin_profile.type=scoped`, `scopes=["content_moderation"]`
- **General admin** = `role=admin`, `admin_profile.type=general`

