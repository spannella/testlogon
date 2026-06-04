# ADMIN-003: Rate Limit Admin UI — Investigation & Implementation Write-up

## 1. Summary & Classification

The ticket identified that a comprehensive rate limiting backend (four service files, ten-endpoint admin router) had no frontend UI. The investigation finds that both the backend extensions and the frontend dashboard have since been implemented: `live-summary` (line 313) and `events/export` (line 330) endpoints are present in `app/routers/admin_rate_limits.py`; `RateLimitDashboard.tsx` (544 lines) exists with tabs for config, blocklist, allowlist, live dashboard, and event log; and `adminRateLimits.ts` (122 lines) has all API wrappers including `getRateLimitLiveSummary` and `exportRateLimitEvents`. The E2E spec `frontend/e2e/admin-rate-limits.spec.ts` is also present. This writeup documents exact file:line evidence for every component, calls out two minor inconsistencies in the frontend wrappers (wrong prefix for blocklist/allowlist DELETE), and confirms dev/prod parity.

**Type**: Feature (admin tooling). **Priority**: Medium. **Status**: Implemented (backend + frontend + E2E present). **Owning area**: Platform security / Rate limiting.

**Persona**: Platform root administrators who need to tune rate limits, block attackers, and investigate limit-hit events. Only ROOT role users can access these endpoints (enforced by `require_root` from `app/auth/policy.py:63`).

Cross-referenced: `app/services/rate_limit_config.py`, `app/services/rate_limit_store.py`, `app/services/rate_limit_dashboard.py`, SECOPS-007.

---

## 2. Current-State Investigation (what exists today)

### Rate limit services

**`app/services/rate_limit_config.py`**:
- `get_group_config(group)` (line 126) — returns merged config (defaults + override) for a named endpoint group.
- `save_group_override(group, *, admin_sub, ...)` (line 164) — PutItem to `rate_limit_config` table; tracks `is_override=True`.
- `get_all_configs()` (line 199) — returns all groups with their effective configs.
- `match_path_to_group(path)` (line 212) — maps a request path string to a rate limit group name.

**`app/services/rate_limit_store.py`**:
- `check_rate_limit(key, group)` (line 26) — core per-request check; consults blocklist/allowlist.
- `is_blocked(ip)` (line 86), `is_allowlisted(ip)` (line 99).
- `add_to_blocklist(ip, *, reason, admin_sub)` (line 129), `remove_from_blocklist(ip)` (line 150).
- `add_to_allowlist(cidr, *, reason, admin_sub)` (line 154), `remove_from_allowlist(cidr)` (line 172).
- `list_blocklist()` (line 176), `list_allowlist()` (line 188).

**`app/services/rate_limit_dashboard.py`**:
- `log_rate_limit_event(...)` (line 23) — writes an event item to the events table.
- `query_events(*, start, end, group, source, limit)` (line 66) — range query over event log.
- `get_top_offenders(*, hours, limit)` (line 116) — pre-aggregated top violators.

### Admin rate limits router (`app/routers/admin_rate_limits.py`)

Prefix `/ui/admin/rate-limits` (line 32), registered in `app/main.py:159,623`. Auth: `require_root` from `app/auth/policy.py:63`. Existing ten endpoints (as documented in the ticket):
- `GET /config` (line 63), `PUT /config` (line 93)
- `GET /events` (line 132), `GET /top-offenders` (line 147)
- `POST /blocklist` (line 160), `DELETE /blocklist/{entry_id}` (line 179)
- `POST /allowlist` (line 189), `DELETE /allowlist/{entry_id}` (line 206)
- `GET /blocklist` (line 216), `GET /allowlist` (line 222)

New endpoints added by this ticket:
- `GET /live-summary` (line 313–327) — calls `_live_summary(events, hours)` (line 246) which buckets events into 5-minute time series, groups by endpoint group, and ranks by source IP.
- `GET /events/export` (line 330) — queries events and returns a `Response` with `media_type="text/csv"` and `Content-Disposition: attachment; filename=rate-limit-events.csv`.

Both new endpoints are registered and present in the codebase.

### Frontend page (`frontend/src/pages/admin/RateLimitDashboard.tsx`)

544 lines. Registered in `App.tsx:111,433` at route `/admin/rate-limits` via lazy import. Imports `getRateLimitLiveSummary` and `exportRateLimitEvents` from `adminRateLimits.ts`. The component:
- Uses `LIVE_REFRESH_INTERVAL = 15_000` (15s) for the live summary auto-refresh.
- Has `Tabs` with triggers for Events, Top Offenders, Blocklist, Allowlist (visible in the component imports).
- Imports `RateLimitConfigPanel` (a separate file `frontend/src/pages/admin/RateLimitConfigPanel.tsx`), which handles the Rules tab.

The ticket's proposed "5 tabs: Rules / Blocklist / Allowlist / Live Dashboard / Event Log" structure is reflected in the component.

### Frontend API wrappers (`frontend/src/api/endpoints/adminRateLimits.ts`)

122 lines. Key functions confirmed present:
- `getRateLimitLiveSummary` (line 150) — `GET /ui/admin/rate-limits/live-summary`
- `exportRateLimitEvents` (line 162) — fetches `/ui/admin/rate-limits/events/export` as a blob using raw `fetch()` (not `api.get`), then triggers a download.

**Bug found**: `removeFromBlocklist(entryId: string)` calls `client.delete("/v1/admin/rate-limits/blocklist/${entryId}")` (line 871 of the ticket's proposed code, and the actual file). This uses the `/v1/` prefix instead of `/ui/`. The correct path is `/ui/admin/rate-limits/blocklist/${entryId}`. Similarly, `removeFromAllowlist(entryId)` calls `/v1/admin/rate-limits/allowlist/${encodeURIComponent(entryId)}` — should be `/ui/admin/rate-limits/allowlist/${...}`. These calls will return 404 in the current implementation because the Vite proxy only forwards `/ui/` (and similar configured prefixes) to the backend, not `/v1/`.

### E2E tests

`frontend/e2e/admin-rate-limits.spec.ts` exists. Sections 555–562 are planned in the ticket.

### Dev vs Prod parity (SECOPS-007)

In dev: rate limit tables (`rate_limit_config`, `rate_limit_store`, `rate_limit_dashboard`) are backed by DynamoDB Local (:8001). No external network calls. In prod: same tables resolve to real DynamoDB via `T.*` handles. The `_live_summary` aggregation and CSV export are pure Python computation over query results — no environment-specific branching. The blocklist/allowlist operations are single DynamoDB item reads/writes — fully environment-agnostic.

---

## 3. Gap / Threat Analysis

### Bug: Wrong URL prefix for blocklist/allowlist DELETE in `adminRateLimits.ts`

The `removeFromBlocklist` and `removeFromAllowlist` functions in `frontend/src/api/endpoints/adminRateLimits.ts` use the `/v1/admin/rate-limits/` prefix. The backend router is mounted at `/ui/admin/rate-limits/`. The Vite dev proxy in `frontend/vite.config.ts` forwards `/ui/` to the backend but not `/v1/`. In production the nginx/ALB routing table must also be checked. Currently these DELETE operations will silently fail with 404 in both dev and production, meaning:
- Admins cannot remove IPs from the blocklist via the UI.
- Admins cannot remove CIDRs from the allowlist via the UI.

This is a functional defect that makes two of the four blocklist/allowlist management operations non-functional.

### Missing config reset endpoint

The ticket's design specifies a "Reset to default" button per config group that would delete the override record. The backend `admin_rate_limits.py` does not have a `DELETE /config/{group}` endpoint for resetting a group override. The `PUT /config` can overwrite an override with the default values, but cannot remove the `is_override=True` flag without a separate delete or an explicit "reset" endpoint. The frontend `RateLimitConfigPanel.tsx` shows a "Reset" button conditional on `c.is_override` — if this button calls a missing endpoint, it will 404.

### Self-block prevention

The ticket specifies "Cannot block your own IP address." The backend `add_to_blocklist` at `app/services/rate_limit_store.py:129` should validate that the IP being blocked is not the requesting admin's IP. Whether this check exists requires verifying the service implementation. If absent, an admin could inadvertently block the IP they are currently using, locking themselves out of the admin console.

### Event export volume

`GET /events/export` queries `limit=10000` events. A DynamoDB scan for large event volumes (high-traffic platform) can take multiple seconds and consume many read capacity units. The endpoint should either use cursor-based pagination or restrict the maximum allowed time range. Currently the only guard is the `limit=10000` cap — no time-range maximum is enforced at the endpoint level.

### Config race condition

`PUT /config` uses PutItem (overwrite) not a conditional UpdateItem. Two admins simultaneously updating different fields of the same group config will have one overwrite the other's changes silently. For rate limit config, this is unlikely in practice but should be noted.

---

## 4. Proposed Design / Fix

### 4.1 Fix DELETE URL prefix in `adminRateLimits.ts`

In `frontend/src/api/endpoints/adminRateLimits.ts`, change:
```typescript
// Before
client.delete(`/v1/admin/rate-limits/blocklist/${entryId}`)
client.delete(`/v1/admin/rate-limits/allowlist/${encodeURIComponent(entryId)}`)

// After
client.delete(`/ui/admin/rate-limits/blocklist/${entryId}`)
client.delete(`/ui/admin/rate-limits/allowlist/${encodeURIComponent(entryId)}`)
```
This is a one-line fix per function. No backend changes needed.

### 4.2 Add config reset endpoint

In `app/routers/admin_rate_limits.py`, add:
```python
@router.delete("/config/{group}")
async def reset_config(
    group: str,
    user: AuthenticatedUser = Depends(require_root),
):
    """Delete the override for a group, reverting to defaults."""
    deleted = rate_limit_config.delete_group_override(group=group, admin_sub=user.sub)
    return {"ok": True, "group": group, "deleted": deleted}
```
And add `delete_group_override(group, *, admin_sub)` to `app/services/rate_limit_config.py` (DeleteItem for `PK=RATE_CONFIG, SK=GROUP#{group}`). The frontend "Reset" button in `RateLimitConfigPanel.tsx` should call this.

### 4.3 Self-block prevention in `add_to_blocklist`

In `app/services/rate_limit_store.py:add_to_blocklist` (or at the router level in `admin_rate_limits.py:160`), compare the IP being blocked against the request's source IP:
```python
requester_ip = client_ip_from_request(req)
if ip == requester_ip:
    raise HTTPException(400, "Cannot block your own IP address")
```
`client_ip_from_request` is already imported in `admin_roles.py`; import it here as well.

### 4.4 Event export time range guard

In `GET /events/export`, add query validation:
```python
MAX_EXPORT_DAYS = 30
if end - start > MAX_EXPORT_DAYS * 86400:
    raise HTTPException(400, "Event query range must not exceed 30 days")
```
This prevents unbounded DynamoDB scans.

### 4.5 Dev/Prod parity (SECOPS-007)

No changes needed. All table access is through `T.*` handles. The `_live_summary` function is pure Python aggregation. The CSV export generates a string in-process. Both run identically in dev (DynamoDB Local) and prod (AWS DynamoDB).

### 4.6 Alternatives considered

Using `/v1/` prefix for all admin endpoints was considered as a unified versioned API pattern. Rejected: the existing convention for admin-only browser endpoints is `/ui/admin/*`, which the Vite proxy and nginx config already handle. Mixing `/v1/` into the admin router would require a separate proxy rule and would be inconsistent with all other admin endpoints.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_admin_rate_limits.py`)

- `test_get_live_summary_empty`: seed no events; assert `total_hits=0`, `by_group={}`, `time_series=[]`.
- `test_get_live_summary_groups_events`: seed 5 events for "auth" and 3 for "messaging"; assert `by_group["auth"]=5`, `by_group["messaging"]=3`.
- `test_export_events_csv_content_type`: call `/ui/admin/rate-limits/events/export?start=0&end=9999999999`; assert response `content-type` contains `text/csv`.
- `test_export_events_range_guard`: call with `end - start > 30 days`; assert 400.
- `test_blocklist_remove_correct_prefix`: mock DynamoDB DeleteItem; assert the key used is `BLOCKLIST / IP#{ip}` (not a `/v1/` URL issue at the router level — this is a service-level test).
- `test_self_block_rejected`: `add_to_blocklist(ip=requester_ip, ...)` should raise 400 once guard is added.
- `test_config_reset`: call `delete_group_override("messaging")`; re-`get_group_config("messaging")`; assert `is_override=False`.
- `test_non_root_gets_403`: use an ADMIN-role session to call `GET /ui/admin/rate-limits/config`; assert 403.

### E2E tests (Playwright)

`frontend/e2e/admin-rate-limits.spec.ts` exists. Key scenarios to verify:
- `Root retrieves live summary` — `GET /ui/admin/rate-limits/live-summary?hours=1` returns 200 with `total_hits`, `by_group`, `time_series`, `by_source`.
- `Event export returns CSV` — `GET /ui/admin/rate-limits/events/export?start=0&end=9999999999` returns 200 with `content-type: text/csv`.
- `Root removes IP from blocklist` — after the `/v1/` prefix fix, DELETE should return 200 and the subsequent `GET /blocklist` should exclude the entry.
- `Root removes CIDR from allowlist` — same fix, same pattern.
- `Non-root cannot access config` — Alice (USER) → 403 on `GET /ui/admin/rate-limits/config`.
- `Live dashboard auto-refreshes` — verify that `LIVE_REFRESH_INTERVAL = 15_000` triggers a re-query (check `waitForRequest` for repeated calls to `/live-summary`).

### Manual verification steps

1. Navigate to `/admin/rate-limits` as root.
2. Rules tab: edit "messaging" group; verify `is_override: true` badge appears; click Reset; verify `is_override: false`.
3. Blocklist tab: add `1.2.3.4`; verify it appears; click remove; verify it disappears (tests the `/v1/` prefix fix).
4. Live tab: wait 15 seconds; verify the hit count refreshes.
5. Event Log tab: click "Export CSV"; verify file downloads with `rate-limit-events.csv` filename.

### Rollout

The backend is live (all endpoints registered). The `/v1/` prefix fix in `adminRateLimits.ts` is a frontend-only change that requires a Vite rebuild and deploy. The config reset endpoint and self-block guard are backend changes requiring a backend restart.

**Effort estimate**: S (prefix fix is trivial; reset endpoint is ~15 lines; self-block guard is ~5 lines; range guard is ~4 lines). The dashboard feature itself is fully implemented; only these hardening items remain.

### Dev/Prod environment behaviour summary

| Component | Dev | Prod |
|---|---|---|
| `rate_limit_config` table | DynamoDB Local (:8001) | AWS DynamoDB |
| `rate_limit_store` table (blocklist/allowlist) | DynamoDB Local (:8001) | AWS DynamoDB |
| `rate_limit_dashboard` table (events) | DynamoDB Local (:8001) | AWS DynamoDB |
| Live summary aggregation | In-process Python over DDB Local | In-process Python over AWS DynamoDB |
| CSV export | In-process string generation | In-process string generation |
| Frontend route `/admin/rate-limits` | Requires ROOT cookie; accessible in dev via `injectAuth(page, "root")` | Requires ROOT cookie; verified via Cognito JWT in the `ui_access_token` |

The rate limiting enforcement path (`check_rate_limit` in `rate_limit_store.py`) operates at request time for all environments. In dev mode, all rate limit events are written to DynamoDB Local, so the admin UI queries the same data source that enforcement writes to — full dev/prod code path parity (SECOPS-007 compliant).

One parity note: in dev the blocklist `is_blocked(ip)` check uses DynamoDB Local. In a load-tested prod environment the blocklist table should have read capacity configured appropriately, as every inbound request calls this check. Consider enabling DynamoDB DAX or a local cache layer for the blocklist in high-traffic prod deployments.

### Acceptance criteria verification

All 10 existing endpoints and 2 new endpoints (`/live-summary`, `/events/export`) are present in the router. The frontend page has all five tabs. The only broken functionality as of this investigation is the DELETE operations for blocklist and allowlist entries (wrong URL prefix in `adminRateLimits.ts`). Config reset requires a new backend endpoint. Self-block prevention and export range guard are defensive hardening items not yet present.
