# Profile User-Posts Feed — Post-release Validation Report (PUF-303)

Date: 2026-04-04
Release phase: Rollout readiness artifact

## Scope

Validation targets after enabling profile posts feed gate:

- user-visible behavior on profile page posts tab
- profile mode search/filter/pagination correctness
- security/visibility behavior (no private post leaks)
- observability health (metrics + structured logs)

## Verification summary

- ✅ Feature flag and kill switch documented and wired (`VITE_PROFILE_POSTS_FEED_ENABLED`, `VITE_PROFILE_POSTS_FEED_KILL_SWITCH`).
- ✅ Backend/Frontend automated regression tests exist for author scoping, ordering, visibility, and profile UI flow.
- ⚠️ Environment-limited local execution in this container (missing `fastapi` and `vitest` binaries), so production telemetry checks are documented but not executed here.

## Telemetry checks to run during production ramp

1. Throughput by mode:
   - `sum(rate(newsfeed_feed_requests_total{mode="profile"}[5m]))`
2. Error rate by mode:
   - `sum(rate(newsfeed_feed_errors_total{mode="profile"}[5m])) by (error_type)`
3. Latency p95:
   - `histogram_quantile(0.95, sum(rate(newsfeed_feed_latency_seconds_bucket{mode="profile",outcome="success"}[5m])) by (le))`
4. Filter usage adoption:
   - `sum(rate(newsfeed_feed_filter_usage_total{mode="profile"}[15m])) by (filter_name)`

## Launch decision gates

- Proceed from canary to full rollout only if:
  - no critical auth/privacy regressions,
  - no sustained error-rate or latency regressions,
  - support/incidents remain within normal baseline.
- If any gate fails, activate kill switch and investigate before re-enable.
