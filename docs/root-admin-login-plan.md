# Root and Admin Login / Authorization Plan

## Objectives
- Introduce a **single break-glass root account**.
- Restrict root login to **trusted network paths only** (allowlisted public IPs and/or local-only access).
- Allow root to grant and revoke **admin rights**.
- Allow admins to **impersonate normal users** (with full auditing and guardrails).
- Ensure admins can access **all billing** and **all file-management** areas for operational support.

## Role model
Define explicit roles and capabilities:

- `root` (exactly one principal)
  - Manage role assignments for `admin`.
  - Perform all admin actions.
  - Cannot be deleted through normal APIs.
- `admin`
  - Read/write all billing data.
  - Read/write all file-management data.
  - Start and stop user impersonation sessions.
- `user`
  - Standard least-privilege account.

Implementation notes:
- Store role membership as immutable audit events + current projection (for fast authorization checks).
- Enforce an invariant: **exactly one active root principal** at all times.

## Authentication and network controls for root

### 1) Dedicated root identity
- Provision root as a dedicated identity (`ROOT_USER_SUB` or equivalent immutable subject).
- Disallow self-registration and role-escalation to root in all user-facing endpoints.

### 2) Root-only login path
- Use a distinct endpoint for root auth (e.g. `/auth/root/login`) with additional checks.
- Require strong MFA (prefer WebAuthn passkey + backup TOTP).
- Optionally require step-up challenge on every root login, regardless of recent session age.

### 3) Source network restrictions
- Add middleware/guard that evaluates client source:
  - Allow only if request source IP is in configured allowlist (CIDR/IP list), **or**
  - Allow only from loopback/local network when running in local-only mode.
- Parse `X-Forwarded-For` only from trusted reverse proxies.
- Reject root login if source cannot be reliably determined.

Suggested config keys:
- `ROOT_USER_SUB`
- `ROOT_LOGIN_ALLOWED_IPS` (comma-separated CIDRs)
- `ROOT_LOGIN_LOCAL_ONLY` (`true|false`)
- `TRUSTED_PROXY_CIDRS`

### 4) Session hardening for root
- Root sessions use shorter TTL than normal user/admin sessions.
- Disable long-lived “remember me” behavior.
- Rotate session on privilege elevation and on MFA completion.
- Mark root tokens with `role=root` and a high-assurance `auth_level` claim.

## Root grants admin rights

### 1) Role assignment API
Add root-protected endpoints:
- `POST /admin/roles/grant` (`target_user_sub`, `role=admin`, `reason`)
- `POST /admin/roles/revoke` (`target_user_sub`, `role=admin`, `reason`)
- `GET /admin/roles/audit` for security review.

Rules:
- Only root can call grant/revoke.
- Root cannot revoke itself from `root`.
- Optional two-person workflow for revocation/grant in production (recommended).

### 2) Audit and notifications
- Every grant/revoke writes immutable audit records including:
  - actor, target, timestamp, source IP, request id, reason.
- Emit operational alerts for role changes.

## Admin impersonation design

### 1) Impersonation lifecycle
- Endpoint: `POST /admin/impersonation/start` (`target_user_sub`, `reason`, `ticket_id`).
- Endpoint: `POST /admin/impersonation/stop`.
- Produce a short-lived impersonation token/session containing:
  - `actor_sub` (real admin)
  - `effective_sub` (target user)
  - `impersonation=true`
  - `reason`, `ticket_id`, `started_at`

### 2) Guardrails
- Admin can impersonate only `user` accounts by default.
- Disallow impersonating `admin` or `root` unless root explicitly enables emergency mode.
- UI and API responses clearly indicate impersonation context.
- Force max impersonation duration (for example 30–60 minutes).

### 3) Audit requirements
- Log impersonation start/stop and sensitive actions performed while impersonating.
- Keep both actor and effective identities in all logs/events.

## Billing and file-management access model

### Billing
- Add authorization dependency checks so `admin` bypasses owner scoping for:
  - billing overview
  - ledger/transactions
  - subscriptions/payment methods
  - reconcile/dunning/admin billing tasks
- Preserve explicit “viewed-as-admin” audit metadata on reads and writes.

### File management
- Add admin override mode in file APIs:
  - list/search any user files
  - view metadata and content (if business policy allows)
  - move/share/delete with strict audit trails
- Consider policy split:
  - Tier 1 admin: metadata-only
  - Tier 2 admin: content access

## Data model and policy updates
- Add fields/structures for:
  - `role_assignments` (current state)
  - `role_assignment_events` (immutable history)
  - `impersonation_sessions`
  - `security_audit_events`
- Centralize authorization decisions in one policy module to avoid per-router drift.

## API and UI changes

### API
- New root/admin routers for role and impersonation management.
- Update existing billing/file routers to use shared role-aware dependencies.
- Add consistent error codes:
  - `403 role_required`
  - `403 root_network_restricted`
  - `403 impersonation_not_allowed`

### UI
- Add root-only admin console section:
  - grant/revoke admin
  - role audit timeline
- Add admin support panel:
  - start/stop impersonation
  - “acting as user” banner
  - link to billing and file-management tools in impersonated context.

## Security controls checklist
- Enforce strict rate limiting on root login endpoint.
- Require CSRF protection/cookie hardening if browser sessions are used.
- Encrypt/highly protect root recovery factors.
- Add SIEM hooks for root/admin events.
- Run periodic access reviews for all admin assignments.
- Add break-glass runbook and incident response playbook.

## Rollout plan (phased)
1. **Phase 0 – foundations**
   - Add role primitives and centralized policy checks.
   - Add audit event model and storage.
2. **Phase 1 – root controls**
   - Introduce dedicated root login endpoint + IP/local restrictions.
   - Enable short TTL root sessions and strong MFA.
3. **Phase 2 – admin management**
   - Implement root grant/revoke admin endpoints + audit UI.
4. **Phase 3 – impersonation**
   - Ship impersonation APIs, UI indicators, and immutable logs.
5. **Phase 4 – billing/files expansion**
   - Complete admin-wide access to billing and file-management endpoints.
6. **Phase 5 – hardening**
   - Pen test, threat modeling review, chaos drills for break-glass flow.

## Acceptance criteria
- Exactly one root principal exists and can authenticate only from approved network sources.
- Root can grant and revoke admin rights with complete audit history.
- Admins can impersonate normal users with clear indicators and automatic expiry.
- Admins can access all billing and file-management functions.
- All privileged actions are attributable, queryable, and alertable.
