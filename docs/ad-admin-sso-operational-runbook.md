# AD Admin SSO Operational Runbook (AD-015)

## Purpose
This runbook enables on-call responders to recover AD Admin SSO service without waiting for engineering escalation.

It covers:
1. OIDC/SAML key and certificate rollover.
2. IdP outage response and continuity actions.
3. Admin lockout recovery through local `root` break-glass controls.
4. Escalation and ownership rules.

## Ownership and escalation

### Primary ownership
- **Primary service owner:** Platform Auth team (`platform-auth-oncall`).
- **Secondary owner:** Platform Ops (`platform-ops-oncall`).
- **Security approver for emergency auth changes:** Security on-call (`security-oncall`).

### Escalation path (P1/P0)
1. Platform Auth on-call (0-10 minutes).
2. Platform Ops on-call (if active incident >10 minutes or multi-tenant impact).
3. Security on-call (any suspected compromise, token forgery, or key misuse).
4. Engineering Manager on-call (if SLA breach risk >30 minutes).

## Preconditions and access
- Root break-glass token available through approved path.
- Access to:
  - Root-only **Identity & SSO** UI page.
  - Root-only APIs under `/auth/admin/sso/*`.
  - Ops telemetry endpoints `/ops/metrics`, `/ops/alerts`, `/ops/dashboard-template`.
- Active provider IDs and tenant mapping inventory documented in tenant ops notes.

---

## A. Key rotation / certificate rollover (planned or emergency)

### A1. Prepare and stage
1. Store new secret/cert material in secret store (never plaintext in app DB).
2. If protocol metadata changes, update provider in draft state:
   - `PUT /auth/admin/sso/providers/{provider_id}`
3. Verify role mappings are still present and valid:
   - `GET /auth/admin/sso/providers/{provider_id}/role-mappings`

### A2. Non-destructive validation
1. Execute test-config:
   - `POST /auth/admin/sso/providers/{provider_id}/test-config`
2. Execute formal validation transition:
   - `POST /auth/admin/sso/providers/{provider_id}/validate`
3. Confirm status is `validated`:
   - `GET /auth/admin/sso/providers/{provider_id}`

### A3. Activate rollover
1. Activate the validated configuration:
   - `POST /auth/admin/sso/providers/{provider_id}/activate`
2. Confirm callback health in metrics:
   - `admin_sso_login_failure_total`
   - `admin_sso_callback_latency_avg_seconds`
3. Confirm alerts are clear or improving:
   - `GET /ops/alerts`

### A4. Post-activation checks
- Run a known-good admin login through `/auth/admin/sso/start` + `/auth/admin/sso/callback`.
- Confirm login success audit event in `admin_sso_auth_audit_events`.
- Confirm no spike of:
  - `admin_sso_denial_spike`
  - `admin_sso_callback_errors`

---

## B. IdP outage response (federation unavailable)

### B1. Detect and classify
Trigger criteria:
- Callback errors increase rapidly.
- Admin users report inability to complete callback.
- Alert `admin_sso_callback_errors` active.

Severity guidance:
- **P1:** single tenant or degraded login.
- **P0:** multi-tenant outage or full admin lockout risk.

### B2. Stabilize
1. Deactivate affected provider(s):
   - `POST /auth/admin/sso/providers/{provider_id}/deactivate`
2. If broad impact or uncertainty exists, execute global rollback:
   - `POST /auth/admin/sso/rollback`
3. Verify providers are in `draft` and disabled:
   - `GET /auth/admin/sso/providers`
4. Confirm local admin/root path is functional.

### B3. Recover
1. Wait for IdP health confirmation from customer/provider.
2. Re-run validation:
   - `POST /auth/admin/sso/providers/{provider_id}/test-config`
   - `POST /auth/admin/sso/providers/{provider_id}/validate`
3. Re-activate in controlled sequence:
   - `POST /auth/admin/sso/providers/{provider_id}/activate`
4. Watch metrics/alerts for 15 minutes before closing incident.

---

## C. Lockout recovery using root break-glass

### C1. When to invoke
Use this path when all non-root admins cannot authenticate through SSO or mapping policy.

### C2. Recovery steps
1. Authenticate as local `root` (break-glass path).
2. Confirm current provider state:
   - `GET /auth/admin/sso/providers`
3. Execute immediate rollback if access restoration is required:
   - `POST /auth/admin/sso/rollback`
4. If issue is mapping-related, run simulation before reactivation:
   - `GET /auth/admin/sso/simulate-role?provider_id={provider_id}&groups={group_list}`
5. Apply corrected mappings and re-validate.

### C3. Exit criteria
- At least one non-root admin can authenticate successfully.
- Root account remains usable regardless of SSO enforcement state.
- Incident audit notes include timeline and reason codes.

---

## D. Validation map (UI and API parity)

The following steps were validated against current root-only UI and API workflows:
- Save/update provider (`POST/PUT /auth/admin/sso/providers*`).
- Validate/test/activate/deactivate provider.
- Rollback to local-only mode.
- Role mapping CRUD and simulation.

Use either UI controls or API endpoints; both map to the same lifecycle transitions (`draft -> validated -> active` and rollback to `draft`).

## E. Audit and evidence requirements
For every incident/change:
- Confirm config audit events exist for create/update/validate/activate/deactivate/rollback.
- Confirm login success/failure events include provider context and failure reason when applicable.
- Capture `/ops/metrics` and `/ops/alerts` snapshots in incident ticket.

## Related docs
- `docs/ACTIVE_DIRECTORY_ADMIN_LOGIN_PLAN.md`
- `docs/ad-admin-sso-threat-model.md`
- `docs/ad-admin-sso-security-controls-checklist.md`
- `docs/ad-admin-sso-oncall-handbook.md`
