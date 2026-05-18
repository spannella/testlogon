# Profile User-Posts Feed Rollout Checklist (PUF-303)

Date: 2026-04-04
Owner: Feed Platform + Web App

## Runtime flag configuration (no redeploy)

Use frontend runtime config/env controls:

- `VITE_PROFILE_POSTS_FEED_ENABLED`
  - default: `true`
  - purpose: primary gate for profile posts tab/feed surface
- `VITE_PROFILE_POSTS_FEED_KILL_SWITCH`
  - default: `false`
  - purpose: emergency disable for rapid rollback

Effective state:

- feature **ON** when `enabled=true` and `kill_switch=false`
- feature **OFF** when `enabled=false` OR `kill_switch=true`

## Staged enablement plan

1. **Internal/dev**
   - Enable flag for internal environment only.
   - Validate profile tab visibility, search/filter behavior, and pagination.
2. **Staging**
   - Enable in staging.
   - Verify telemetry from `newsfeed_feed_requests_total` and `newsfeed_feed_errors_total` (mode=`profile`).
   - Run smoke checklist (see below).
3. **Production canary**
   - Enable for canary environment/slice.
   - Observe 30–60 minutes before broader rollout.
4. **Production full rollout**
   - Keep kill switch available during first 24h.
   - Review metrics/logs at 1h, 6h, and 24h marks.

## Halt / rollback criteria

Roll back immediately (set `VITE_PROFILE_POSTS_FEED_KILL_SWITCH=true`) if any occur:

- sustained profile feed error rate spike versus baseline
- p95 profile feed latency regression above agreed SLO
- authorization/visibility bug reports (private content exposure risk)
- severe UX regressions (tab unusable, broken pagination, repeated stale content)

## Smoke checklist

- [ ] Posts tab appears only when flag is enabled.
- [ ] Profile feed returns only selected author posts.
- [ ] Search + date + media filters return expected subsets.
- [ ] Infinite pagination loads additional pages without duplicates.
- [ ] Global feed remains unaffected when profile mode is disabled.
- [ ] Metrics/logs visible for mode=`profile` and mode=`global`.
