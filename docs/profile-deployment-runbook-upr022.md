# UPR-022 Deployment Runbook: Canonical Profile Lookup Rollout

## Purpose
This runbook defines the production deployment sequence for canonical profile lookup/navigation and the associated audience filtering/discoverability controls.

## Scope
- Backend API: `GET /ui/profiles/{identifier}`
- Frontend route/navigation: `/u/:identifier` and cross-module `UserProfileLink`
- Feature flags:
  - `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED`
  - `VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED`

## Pre-deployment prerequisites
1. Confirm privacy/security GA gate is green:
   - `python scripts/check_profile_privacy_release_gate.py --checklist docs/profile-privacy-security-release-gate-upr021.json`
2. Confirm backfill tooling readiness:
   - `scripts/backfill_profile_discoverability_state.py` dry-run reviewed.
3. Confirm observability assets are applied:
   - `docs/alerts/profile-lookup-alerts.yml`
   - `docs/dashboards/profile-lookup-observability-dashboard.json`

## Ordered deployment steps (required)

### Step 1 — Migration / backfill
1. Run discoverability backfill in **dry-run** mode and review counts.
2. Run discoverability backfill in **apply** mode.
3. Verify no unexpected malformed state count.

### Step 2 — Backend deploy
1. Deploy backend services with:
   - `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED=false`
2. Smoke-check existing `/ui/profile` and related module APIs.
3. Verify `profile_lookup_events_total` and `profile_lookup_latency_seconds` emit as expected.

### Step 3 — Frontend deploy
1. Deploy frontend bundle with:
   - `VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED=false`
2. Validate existing module flows (messaging/contacts/feed/calendar/tickets) remain unchanged.

### Step 4 — Feature-flag enablement (staged)
1. Enable `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED=true` for canary backend slice.
2. Run canary checks (below). If healthy, expand to full backend.
3. Enable `VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED=true` for canary frontend cohort.
4. Run canary checks again. If healthy, expand to full frontend.

## Canary checks
- Endpoint behavior:
  - unknown/suppressed identifiers return non-enumerating 404.
  - owner/member/public audiences receive expected field sets.
- Module navigation:
  - contacts, messaging, feed, calendar, and tickets link to canonical `/u/:identifier`.
- Rate limiting:
  - anonymous/authenticated lookup throttles return expected 429 payloads.

## Post-release verification (required)

### Metrics
- `profile_lookup_events_total`
  - monitor `result=error` and `result=denied` by `suppression_reason`
- `profile_lookup_latency_seconds`
  - confirm p95/p99 within SLO target

### Logs
- Verify structured `profile_lookup` log entries include:
  - `correlation_id`, `audience`, `result`, `suppression_reason`, `status_code`
- Confirm logs do **not** contain raw sensitive profile fields.

### Error budgets
- 5xx rate for profile lookup remains within service error budget threshold.
- sustained increase in 404/429 beyond expected rollout baseline triggers investigation.

## Rollback plan

### Fast rollback (frontend only)
1. Set `VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED=false`.
2. Redeploy/roll frontend.

### Behavioral rollback (backend filtering)
1. Set `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED=false`.
2. Roll/restart backend.

### Full rollback
1. Disable both flags.
2. Revert to previous stable backend/frontend revisions if incident persists.
3. Re-run baseline smoke checks.

## On-call owners and responsibilities
- **Backend on-call (Platform API):**
  - monitors API errors, suppression behavior, latency, and rate-limit anomalies.
  - executes backend flag rollback if canary fails.
- **Frontend on-call (Web Platform):**
  - monitors navigation regressions and client error spikes.
  - executes frontend flag rollback if route/link regressions occur.
- **SRE on-call:**
  - monitors global error budget impact and alert health.
  - coordinates incident command and cross-team rollback decisions.

## Exit criteria for GA
- Canary + full rollout complete with no unresolved Sev-1/Sev-2 incidents.
- Post-release checks pass for one full monitoring window.
- No open remediation items from privacy/security review.
