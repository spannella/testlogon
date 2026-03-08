# AD Admin SSO Rollout Validation & Feature-Flag Launch Plan (AD-017)

## Objective
Ship AD Admin SSO with explicit staged validation gates, rollback criteria, and tenant cohort sequencing.

## Feature flag strategy
- **Primary launch flag:** `admin_ad_sso`
- **Policy guardrail flag:** `ADMIN_SSO_ENFORCE_FOR_ADMINS`

### Flag intent
- `admin_ad_sso` controls whether tenant/provider rollout can proceed.
- `ADMIN_SSO_ENFORCE_FOR_ADMINS` controls whether non-SSO admin sessions are blocked (root excluded).

## Staged rollout sequence

### Stage 0 — Staging validation (mandatory)
1. Execute E2E scenario: root configures IdP (`draft -> validated -> active`), admin logs in via AD, role enforced.
2. Execute E2E rollback scenario: root triggers rollback, provider disabled, local admin path restored.
3. Confirm metrics + alerts visible:
   - `admin_sso_login_success_rate`
   - `admin_sso_login_failure_total`
   - `admin_sso_login_denied_total`
   - `admin_sso_callback_latency_avg_seconds`
   - `admin_sso_config_validation_failures_total`
4. Verify audit coverage for config and callback outcomes.

### Stage 1 — Internal pilot tenants (1-2 tenants)
1. Enable `admin_ad_sso` for internal pilot tenant list.
2. Keep `ADMIN_SSO_ENFORCE_FOR_ADMINS=false` for first 24h (observe-only mode).
3. If callback success/failure profile is healthy, enable `ADMIN_SSO_ENFORCE_FOR_ADMINS=true` for pilot.
4. Monitor 24h and confirm no unresolved `admin_sso_callback_errors` alerts.

### Stage 2 — Expanded pilot (up to 10 tenants)
1. Expand `admin_ad_sso` to approved tenant cohort.
2. Enable enforcement (`ADMIN_SSO_ENFORCE_FOR_ADMINS=true`) only after each tenant validates config and mapping simulation.
3. Hold each expansion wave for 24h with on-call sign-off.

### Stage 3 — General availability
1. Enable `admin_ad_sso` default-on for eligible tenants.
2. Maintain tenant-level override for emergency disablement.
3. Keep rollback procedure hot and tested monthly.

## Abort criteria and rollback triggers
Immediate rollback to local-admin mode if any of the following occur:
1. Sustained `admin_sso_callback_errors` alert for >10 minutes.
2. `admin_sso_denial_spike` without corresponding intended policy change.
3. Any confirmed or suspected privilege-escalation behavior.
4. Tenant lockout where non-root admin access cannot be restored within 10 minutes.

### Rollback action
- Execute `POST /auth/admin/sso/rollback`.
- Confirm provider status is `draft` + `enabled=false`.
- Confirm `ADMIN_SSO_ENFORCE_FOR_ADMINS=false` and local admin path restored.

## Success metrics for go/no-go
- Callback success rate stable above pilot baseline.
- No unresolved critical callback alert at go/no-go checkpoint.
- No root-assignment or unauthorized-role escalation findings.
- Recovery drill remains executable by on-call without engineering escalation.

## E2E validation suite references
- `deployment_initializer/backend/tests/test_admin_sso_e2e_rollout.py`
- `deployment_initializer/backend/tests/test_admin_sso.py`
- `deployment_initializer/backend/tests/test_admin_sso_config_api.py`

## Operational references
- `docs/ad-admin-sso-oncall-handbook.md`
- `docs/ad-admin-sso-operational-runbook.md`
- `docs/ad-admin-sso-recovery-checklist-staging.md`
- `docs/ad-admin-sso-negative-test-matrix.md`
- `docs/ad-admin-sso-local-keycloak-dev-plan.md`
