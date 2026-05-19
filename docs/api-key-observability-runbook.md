# API Key Observability Runbook (AKI-050)

## Purpose
This runbook covers dashboards, alerts, triage, and rollback guidance for API key adoption and abuse monitoring.

## Dashboards
- Product/route/key operations dashboard: `docs/dashboards/api-key-product-usage-dashboard.json`
- Supporting metering dashboard: `docs/api-usage-observability-dashboards-alerts.md`

## Alert rules
- Rule pack: `docs/alerts/api-key-observability-alerts.yaml`
- Critical alerts:
  - `ApiKey401Spike`
  - `ApiKey403Spike`
  - `ApiKeySuspiciousActivity`
  - `ApiKeyRegistryCoverageDrift`

## Simulated alert verification checklist
1. **401 simulation**
   - Send API traffic with an invalid API key for 10+ minutes in staging.
   - Verify `ApiKey401Spike` fires and runbook link resolves.
2. **403 simulation**
   - Send API traffic with a valid key missing route scopes.
   - Verify `ApiKey403Spike` fires and include deny reasons in incident notes.
3. **Suspicious activity simulation**
   - Replay the same key from >10 distinct synthetic client IP labels in 30 minutes.
   - Verify `ApiKeySuspiciousActivity` pages security on-call.
4. **Registry coverage drift simulation**
   - Temporarily add a synthetic rollout-surface route in staging without a matching registry/exemption entry.
   - Verify `ApiKeyRegistryCoverageDrift` fires and includes the runbook link.

Record trigger time, alert firing time, and acknowledgment owner for each simulation.

## Triage: authentication spike (401)
1. Confirm surge source by `api_key_id`, `route_id`, and `client_ip` panels.
2. Check recent key lifecycle events:
   - `api_key_create`
   - `api_key_revoke`
   - expiration in API keys table
3. Validate parser/header failures (`x-api-key`, `Authorization: ApiKey`).
4. If broad impact:
   - roll back recent API key parser/dependency changes,
   - disable newly rolled scope enforcement toggles.

## Triage: authorization/entitlement spike (403)
1. Break down by deny reason (`missing_scope`, `unmapped_route`, `api_entitlement_denied`).
2. Confirm route registry entries for impacted endpoints.
3. Validate entitlement records and route allowlists for affected tenants.
4. Rollback options:
   - restore previous route scope registry mapping,
   - disable new entitlement gate behavior by feature flag,
   - temporarily exempt affected route while remediation is prepared.

## Triage: shadow vs enforce drift (AKI-052)
1. Filter audit stream for `api_key_policy_shadow_eval` and group by `product`, `route_id`, and `reason`.
2. Check `/v1/admin/api-keys/rollout-state` `registry_drift.status`:
   - `ok`: no immediate registry risk detected,
   - `warning`: stale registry entries exceeded threshold,
   - `critical`: unregistered rollout-surface live routes detected (treat as immediate remediation).
3. Verify shadow-deny reasons match expected policy behavior before moving from `shadow` to `canary`.
4. For canary cohorts, compare 401/403 and latency SLOs between canary and non-canary populations.
5. If regressions appear, set `API_KEY_<PRODUCT>=0` or revert phase to `shadow` for immediate rollback.

## Triage: suspicious key activity
1. Identify `api_key_id` and owner account.
2. Review key usage fan-out by route and client IP.
3. If compromise suspected:
   - revoke key immediately,
   - notify user/security on-call,
   - rotate integrations and issue replacement key with least privilege scopes.
4. Correlate with audit events and recent configuration changes.

## Rollback guidance
- **Scope mapping regressions:** revert `app/services/api_key_route_scope_registry.py` to last known good release.
- **Enforcement regressions:** remove/disable `maybe_enforce_api_key_route_policy` on affected routers.
- **Entitlement regressions:** disable pre-request entitlement checks for impacted product namespace.

## Escalation
- Primary: API platform on-call.
- Secondary: Security on-call (for suspicious activity / possible key compromise).
- Notify developer experience stakeholders for sustained integration impact.
