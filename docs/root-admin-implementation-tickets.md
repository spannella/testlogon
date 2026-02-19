# Root/Admin Security Model — Implementation Ticket Backlog

This backlog translates the root/admin plan into actionable engineering tickets.

## Epic A — Role foundations and policy core

### RA-001: Add canonical role model (`root`, `admin`, `user`)
**Goal**: Introduce a single source of truth for role enums/typing used by auth and routers.

**Scope**
- Define role constants/types in auth domain.
- Replace stringly-typed role checks where present.
- Add migration/default behavior for existing users to `user`.

**Acceptance criteria**
- Role checks compile/use canonical definitions only.
- Existing non-privileged users continue to work without manual data fixes.

---

### RA-002: Create centralized authorization policy module
**Goal**: Stop per-route ad-hoc checks and enforce consistent authorization decisions.

**Scope**
- Add policy helpers: `require_root`, `require_admin_or_root`, `require_self_or_admin`, etc.
- Wire policy helpers into auth dependencies.
- Add shared error payloads/codes for role failures.

**Acceptance criteria**
- Billing and file routes can consume shared policy checks.
- Unauthorized calls return standardized `403 role_required` response.

---

### RA-003: Enforce single-root invariant
**Goal**: Ensure exactly one root identity exists.

**Scope**
- Add config/env source for immutable root subject (`ROOT_USER_SUB`).
- On startup/health checks, validate root subject configuration.
- Disallow API paths that could create additional root users.

**Acceptance criteria**
- Service rejects misconfigured startup if root subject is missing/invalid.
- No non-root endpoint can grant root role.

---

## Epic B — Root authentication hardening

### RA-004: Build dedicated root login endpoint
**Goal**: Separate root auth flow from standard login.

**Scope**
- Add `/auth/root/login` endpoint with root-subject validation.
- Require step-up MFA for root login.
- Deny root auth via regular login route (or require explicit root path).

**Acceptance criteria**
- Root can authenticate only through root endpoint.
- Root endpoint enforces MFA before session issuance.

---

### RA-005: Add root source IP/local-network gate
**Goal**: Restrict root authentication to trusted source networks.

**Scope**
- Implement guard for `ROOT_LOGIN_ALLOWED_IPS`, `ROOT_LOGIN_LOCAL_ONLY`.
- Support trusted proxy parsing via `TRUSTED_PROXY_CIDRS`.
- Add deterministic deny reason for unknown/untrusted source.

**Acceptance criteria**
- Allowed IPs succeed; non-allowlisted IPs fail with `403 root_network_restricted`.
- Proxy header spoofing is ignored when request not from trusted proxy.

---

### RA-006: Harden root session properties
**Goal**: Reduce blast radius of root compromise.

**Scope**
- Short root session TTL.
- Session rotation on MFA completion/elevation.
- Embed root assurance claims (`role=root`, `auth_level`).

**Acceptance criteria**
- Root session TTL is lower than admin/user TTL.
- Root sessions include required claims and rotate on elevation.

---

## Epic C — Root-managed admin role lifecycle

### RA-007: Implement admin grant/revoke APIs (root only)
**Goal**: Give root explicit APIs to manage admin assignments.

**Scope**
- `POST /admin/roles/grant`
- `POST /admin/roles/revoke`
- Validate target user existence and role transitions.

**Acceptance criteria**
- Only root can grant/revoke admin.
- Role transition validation errors are explicit and audited.

---

### RA-008: Add role assignment audit log + query endpoint
**Goal**: Make admin assignment actions immutable and reviewable.

**Scope**
- Persist role assignment events with actor/target/reason/IP/request-id.
- Add `GET /admin/roles/audit` with pagination and filtering.

**Acceptance criteria**
- Grant/revoke always generates immutable event record.
- Security reviewer can query events by actor and date range.

---

### RA-009: Add operational alerting for role changes
**Goal**: Notify security/ops immediately when admin roles change.

**Scope**
- Emit alert/event on grant/revoke.
- Integrate with existing notification/event pipeline.

**Acceptance criteria**
- Every grant/revoke yields alert with actor/target metadata.
- Alert delivery failures are logged with retries/backoff behavior.

---

## Epic D — Admin impersonation

### RA-010: Implement impersonation start/stop endpoints
**Goal**: Allow admins to act as user for support workflows.

**Scope**
- `POST /admin/impersonation/start`
- `POST /admin/impersonation/stop`
- Create short-lived impersonation session/token containing actor/effective identities.

**Acceptance criteria**
- Start returns impersonation context and token/session metadata.
- Stop invalidates impersonation context immediately.

---

### RA-011: Enforce impersonation guardrails
**Goal**: Prevent privilege abuse in impersonation.

**Scope**
- Default: admins can impersonate only `user` role.
- Block impersonation of `admin`/`root` without root-enabled emergency flag.
- Add max duration cap and auto-expiry.

**Acceptance criteria**
- Forbidden targets fail with `403 impersonation_not_allowed`.
- Expired impersonation sessions cannot perform actions.

---

### RA-012: Add impersonation-aware auditing across sensitive actions
**Goal**: Preserve accountability while acting as another user.

**Scope**
- Include `actor_sub` + `effective_sub` in audit metadata for privileged domains.
- Record impersonation start/stop and high-risk actions.

**Acceptance criteria**
- Audit events always preserve both identities when impersonating.
- Security queries can reconstruct full impersonation timeline.

---

## Epic E — Billing authorization expansion

### RA-013: Add admin/root bypass for billing read surfaces
**Goal**: Allow admins/root to view all user billing data.

**Scope**
- Update billing dependencies to allow admin/root global reads.
- Maintain user scoping for normal users.

**Acceptance criteria**
- Admin/root can query billing overview, ledger, subscriptions globally.
- User accounts remain restricted to own billing records.

---

### RA-014: Add admin/root permissions for billing write/ops actions
**Goal**: Allow support and finance operations from privileged roles.

**Scope**
- Extend permissions for payment-method ops where policy allows.
- Allow privileged reconcile/dunning/administrative billing operations.

**Acceptance criteria**
- Admin/root can execute configured billing ops successfully.
- All privileged writes include audit tags (`viewed-as-admin`/actor metadata).

---

## Epic F — File-management authorization expansion

### RA-015: Add admin/root override mode for file APIs
**Goal**: Allow privileged users to operate across user file scopes.

**Scope**
- Admin/root list/search across all users.
- Optional content-read flag separated from metadata access.

**Acceptance criteria**
- Admin/root can locate any user file metadata.
- Content access obeys configured policy tier.

---

### RA-016: Audit file operations performed with override/impersonation
**Goal**: Ensure forensic visibility for sensitive file actions.

**Scope**
- Log read/download/move/share/delete events with actor/effective context.
- Add correlation ids for bulk operations.

**Acceptance criteria**
- Every override or impersonated file action emits auditable event.
- Events are queryable by actor, target user, file id, and time range.

---

## Epic G — UI and operator workflows

### RA-017: Build root role-management console
**Goal**: Provide a UI for root to grant/revoke admin and inspect role audits.

**Scope**
- Root-only admin management page.
- Grant/revoke forms requiring reason field.
- Timeline/audit table integration.

**Acceptance criteria**
- Root can grant/revoke admin from UI.
- Audit table displays role changes with reason and actor metadata.

---

### RA-018: Add admin impersonation UX and context banners
**Goal**: Make impersonation explicit and safe in UI.

**Scope**
- Start/stop impersonation controls.
- Persistent “acting as user” banner with stop action.
- Route-level indicator in billing/files pages.

**Acceptance criteria**
- Banner appears on all pages while impersonating.
- One-click stop exits impersonation and restores admin context.

---

## Epic H — Security, QA, and rollout

### RA-019: Add automated tests for root/admin/impersonation policy matrix
**Goal**: Prevent regressions in privileged access controls.

**Scope**
- Unit tests for policy helpers.
- API tests for root network checks, role grants, impersonation restrictions.
- Regression tests for billing/file access matrix (`user` vs `admin` vs `root`).

**Acceptance criteria**
- Test matrix covers allow/deny cases for all privileged routes.
- CI blocks merges on policy regressions.

---

### RA-020: Security hardening and runbooks
**Goal**: Operationalize break-glass and incident handling.

**Scope**
- Document root account lifecycle and recovery controls.
- Add rate limiting, monitoring dashboards, and SIEM hooks.
- Publish incident response playbook for compromised admin/root session.

**Acceptance criteria**
- Security runbook approved by ops/security stakeholders.
- Root/admin events visible in monitoring and alerting systems.

---

## Suggested delivery order
1. RA-001 → RA-003 (role/policy foundation)
2. RA-004 → RA-006 (root auth hardening)
3. RA-007 → RA-009 (admin lifecycle + audit)
4. RA-010 → RA-012 (impersonation)
5. RA-013 → RA-016 (billing/files privilege expansion)
6. RA-017 → RA-018 (UI)
7. RA-019 → RA-020 (test/security hardening)

## Definition of done (program-level)
- Single root login exists and is enforceably network-restricted.
- Root-managed admin role lifecycle is fully audited.
- Admin impersonation is safe, time-bounded, and transparent.
- Admin/root can operate across billing and file-management with traceability.
- All controls are covered by automated tests and operational monitoring.
