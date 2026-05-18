# UPR-020 rollout playbook: canonical profile route + audience filtering

This playbook defines staged rollout for canonical profile navigation and public-preview audience filtering, with independent kill switches for quick rollback.

## Feature flags

### Backend (API filtering behavior)
- `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED` (default: `false`)
  - `false`: backward-compatible payload behavior for `GET /ui/profiles/{identifier}` (no discoverability suppression and no audience field filtering).
  - `true`: enforce discoverability suppression + audience-based profile field filtering.

### Frontend (canonical navigation behavior)
- `VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED` (default: `false`)
  - `false`: canonical `/u/:identifier` route is not mounted; profile links remain non-navigable text fallback.
  - `true`: canonical route is mounted and shared profile links navigate to `/u/:identifier`.

## Stage gates

1. **Stage 0 — dark launch (all flags off)**
   - Backend flag: `false`
   - Frontend flag: `false`
   - Gate criteria:
     - Existing module flows (messaging/contacts/feed/calendar/tickets) remain unchanged.
     - No increase in `404`/`429` for legacy profile APIs.

2. **Stage 1 — API-only rollout**
   - Backend flag: `true`
   - Frontend flag: `false`
   - Purpose: validate audience filtering and suppression semantics without changing user navigation.
   - Gate criteria:
     - `profile_lookup_events_total{result="error"}` remains at baseline.
     - `profile_lookup_events_total{result="denied",suppression_reason="rate_limited"}` does not exceed alert thresholds.
     - Integration tests for owner/member/public audience continue passing.

3. **Stage 2 — frontend route + navigation enablement**
   - Backend flag: `true`
   - Frontend flag: `true`
   - Gate criteria:
     - Cross-module canonical profile navigation smoke tests pass.
     - No sustained elevation in client-side 404s for `/u/:identifier`.
     - Support/on-call confirms no regression in module entry points.

4. **Stage 3 — expand and steady-state**
   - Keep both flags on in production.
   - Continue monitoring suppression-rate, lookup-latency, and route-level 404/429 trends for at least one full release cycle.

## Rollback criteria

Rollback immediately if any of the following are observed:
- Material increase in profile lookup errors (`5xx`) or latency SLO breach.
- Unexpected suppression spike causing valid profiles to become inaccessible.
- Cross-module profile navigation regression (broken link surfaces or route failures).

## Rollback actions

1. **Fastest rollback (UI only):**
   - Set `VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED=false`.
   - Redeploy frontend.
   - Expected result: `/u/:identifier` route and canonical link navigation disabled.

2. **Behavior rollback (API filtering):**
   - Set `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED=false`.
   - Restart/redeploy backend.
   - Expected result: profile lookup endpoint returns legacy unfiltered payload behavior.

3. **Full rollback:**
   - Disable both flags.
   - Confirm via smoke checks that legacy module behavior is restored.

## Operational checks per stage

- Verify current flag values in deployment config before each promotion.
- Run targeted tests:
  - backend: `tests/test_profile_endpoint_audience_integration.py`
  - frontend: `frontend/src/components/shared/UserProfileLink.test.tsx`
- Confirm dashboards/alerts for profile lookup are green before promoting.
