# AD Admin SSO Recovery Checklist (Staging Validation)

## Goal
Provide a copy/paste operational checklist for AD Admin SSO recovery and document the latest staged execution.

## Checklist

### 1) Confirm incident and gather signals
- [ ] Confirm `/ops/alerts` and identify active AD SSO alerts.
- [ ] Confirm current SSO metrics from `/ops/metrics`:
  - `admin_sso_login_failure_total`
  - `admin_sso_login_denied_total`
  - `admin_sso_callback_latency_avg_seconds`
  - `admin_sso_config_validation_failures_total`

### 2) Stabilize access
- [ ] Sign in as local `root` break-glass account.
- [ ] If active outage exists, execute rollback:
  - `POST /auth/admin/sso/rollback`
- [ ] Verify providers are disabled/draft:
  - `GET /auth/admin/sso/providers`

### 3) Repair configuration
- [ ] Update provider metadata/secret references if needed:
  - `PUT /auth/admin/sso/providers/{provider_id}`
- [ ] Validate role mappings:
  - `GET /auth/admin/sso/providers/{provider_id}/role-mappings`
- [ ] Run simulation for known groups:
  - `GET /auth/admin/sso/simulate-role?provider_id={provider_id}&groups={group_list}`

### 4) Re-enable in staged order
- [ ] Test config (non-destructive):
  - `POST /auth/admin/sso/providers/{provider_id}/test-config`
- [ ] Validate config lifecycle transition:
  - `POST /auth/admin/sso/providers/{provider_id}/validate`
- [ ] Activate provider:
  - `POST /auth/admin/sso/providers/{provider_id}/activate`

### 5) Verify end-to-end recovery
- [ ] Confirm admin login success via `/auth/admin/sso/start` + callback.
- [ ] Confirm auth audit event emitted with `outcome=success` and provider context.
- [ ] Confirm callback error/denial alerts cleared or trending down.

### 6) Closeout
- [ ] Record incident timeline and reason codes.
- [ ] Attach metrics + alerts snapshots.
- [ ] Confirm escalation path was followed and ownership assigned.

---

## Latest staging exercise record
- **Date:** 2026-03-06
- **Scenario:** Simulated callback denial spike and SAML config validation failure.
- **Executed by:** Platform Auth on-call, Platform Ops duty engineer.
- **Result:** Pass.
- **Observations:**
  1. Rollback endpoint disabled SSO immediately and restored local-only admin access.
  2. Re-validation blocked invalid metadata until corrected.
  3. Activation succeeded after validation; callback metrics stabilized.
- **Follow-up actions:** None required.
