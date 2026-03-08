# AD Admin SSO On-Call Handbook

## Scope
This handbook is the entry point for operational response to AD Admin SSO incidents.

## Primary runbooks
- **Operational runbook (rotation/outage/lockout):** `docs/ad-admin-sso-operational-runbook.md`
- **Security controls baseline:** `docs/ad-admin-sso-security-controls-checklist.md`
- **Threat scenarios and mitigations:** `docs/ad-admin-sso-threat-model.md`
- **Release rollout and pilot sequencing:** `docs/ad-admin-sso-rollout-launch-plan.md`

## Incident routing
- Page `platform-auth-oncall` first for all AD Admin SSO incidents.
- Add `platform-ops-oncall` for incidents lasting >10 minutes or impacting multiple tenants.
- Add `security-oncall` for token validation anomalies, signature/key concerns, or suspected compromise.

## Severity routing quick guide
- **P1:** single-tenant auth degradation, recovery path available.
- **P0:** broad outage or admin lockout requiring root break-glass intervention.

## Tabletop + staging validation record (AD-015)
- **Tabletop scenario:** IdP callback failures + mapping-deny spike.
- **Staging drill result:** pass (recovery executed using documented API/UI steps only).
- **Validation date:** 2026-03-06.
- **Validated by:** Platform Auth on-call + Platform Ops duty engineer.
- **Evidence source:** `docs/ad-admin-sso-recovery-checklist-staging.md`.


## Local/dev triage quick reference (Dev UI + AD activity)
Use this matrix for local/staging support issues before escalating to DB-level inspection.

| Observed issue | Where to confirm | Primary remediation |
|---|---|---|
| No events visible for expected login | Dev UI → AD Activity Explorer with `Since Minutes` widened | Re-apply filters, ensure root acting role, click **Load Directory Data**. |
| Repeated `denied` outcomes | Activity Explorer event details | Check user group membership and provider role mappings; add `group-admins` or `group-ops`. |
| Callback failures mentioning issuer/audience | Activity Explorer troubleshooting fields | Re-sync provider config from discovery (`local-ad-sso-provider-config.py`) and re-activate provider. |
| JWKS/signature failures during drill | Activity Explorer + AD-021 drill logs | Verify JWKS endpoint reachability, complete rotation recovery, retry callback. |
| User cannot login but appears in directory | Dev Directory user list | Confirm user is enabled; enable in UI and retest. |

Escalate to backend/log inspection only after the above UI-first checks fail.

## Recovery checklist reference
Use the tested checklist directly during incidents:
- `docs/ad-admin-sso-recovery-checklist-staging.md`
