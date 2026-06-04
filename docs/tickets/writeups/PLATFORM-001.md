# PLATFORM-001: API Rate Limiting & Abuse Prevention — Investigation & Implementation Write-up

> Type: feature / hardening | Priority: High | Status: Implemented (middleware + dashboard)

## 1. Summary & Classification

The platform previously had ad-hoc rate limiting scattered across individual flows but lacked any global IP throttle, per-endpoint group limits, or unified admin control. PLATFORM-001 closes that gap by adding a three-layer system: (1) a global IP rate-limit FastAPI middleware, (2) per-endpoint-group `Depends()`-injected limits with role bypass, and (3) preservation of the existing business-logic Layer 3 limits already in `app/services/rate_limit.py`. New DynamoDB tables (`rate_limits`, `rate_limit_events`) store state and event history respectively, decoupled from the hot `T.sessions` table used by existing Layer 3 checks. An admin dashboard at `/admin/rate-limits` surfaces 429 counts, top offenders, config overrides, allowlist, and blocklist management.

- **Type**: Feature / hardening
- **Priority**: High
- **Affected user classes**: all API callers (public + authenticated); admin/root for management UI
- **Cross-references**: SEC-008 (trusted-proxy IP header), SECOPS-007 (dev/prod parity — mock DDB in dev, real DDB in prod, same code paths), PLATFORM-002 (webhook test endpoints benefit from per-endpoint groups)

---

## 2. Current-State Investigation

### 2.1 What exists today — Layer 3 (app/services/rate_limit.py)

The file is 378 lines and contains eleven standalone rate-limit functions, all backed by `_bucket_limit()` (line 60), which does a `GetItem` + `PutItem` on `T.sessions` using a composite sort-key like `rl#login` or `rl#alert_email`.

| Function | Location | Storage key | Raises on breach |
|---|---|---|---|
| `rate_limit_or_429()` | line 17 | `rl#{factor}` | `HTTPException(429)` |
| `_bucket_limit()` | line 60 | caller-supplied sid | `bool` return |
| `rate_limit_login_attempt()` | line 163 | `rl#login` per user + IP | `HTTPException(429)` |
| `rate_limit_admin_action()` | line 170 | `rl#admin#{action}` | `HTTPException(429)` |
| `rate_limit_mfa_verify()` | line 175 | `rl#mfa_verify#{factor}` | `HTTPException(429)` |
| `rate_limit_password_recovery()` | line 182 | `rl#password_recovery#{action}` | `HTTPException(429)` |
| `rate_limit_profile_lookup()` | line 198 | `rl#profile_lookup#auth/anon` | `HTTPException(429)` with `Retry-After` |
| `rate_limit_feed_query()` | line 227 | `rl#feed_query#{mode}` | `HTTPException(429)` with `Retry-After` |
| `enforce_lockout()` | line 247 | `lockout#{action}` | `HTTPException(429)` |
| `can_send_alert_channel()` | line 321 | `rl#alert_email` / `rl#alert_sms` / `rl#alert_webhook` | `bool` return |
| `rate_limit_filemgr_mount_*()` | lines 340–377 | `rl#filemgr_mount_*` | `HTTPException(429)` |

`Retry-After` is only present in two of these eleven — `rate_limit_profile_lookup()` (line 205–213) and `rate_limit_feed_query()` (line 232–242). The other nine return bare `HTTPException(429)` strings.

### 2.2 IP extraction

`client_ip_from_request()` in `app/core/normalize.py` (line 9–18) extracts the client IP by iterating `X-Forwarded-For` and returning the first non-empty token, or falling back to `request.client.host`. It does **not** validate the forwarding chain against a trusted-proxy CIDR list — a gap that PLATFORM-001's middleware must close (see §4.3 below).

### 2.3 What was missing before the implementation

1. No middleware applying a pre-auth global IP throttle.
2. No `X-RateLimit-*` response headers on most endpoints.
3. All rate-limit state sharing `T.sessions` — adding partition pressure.
4. No admin visibility or runtime configuration.
5. No allowlist / blocklist with TTL expiry.
6. No admin/root role bypass at the middleware layer.

### 2.4 What now exists (verified in the repository)

- `app/middleware/rate_limit.py` — FastAPI `http` middleware; registered in `app/main.py` (line 416) via `app.middleware("http")(rate_limit_middleware_factory())`.
- `app/routers/admin_rate_limits.py` — admin management router; imports `require_root` from `app/auth/policy.py` (line 63).
- Settings in `app/core/settings.py` (lines 1707–1712): `rate_limits_table_name`, `rate_limit_events_table_name`, `rate_limit_global_enabled`, `rate_limit_global_ip_window_seconds`, `rate_limit_global_ip_max_requests`.
- Middleware is registered; Layer 3 functions in `app/services/rate_limit.py` are unchanged.

---

## 3. Gap / Threat Analysis

### 3.1 Pre-existing gaps that PLATFORM-001 addresses

**Unauthenticated endpoints without limits.** Before this feature, `POST /ui/register`, `POST /ui/login`, and `GET /ui/i18n/translations/{locale}` (public) had no IP-level throttle. An attacker could enumerate accounts by flooding login attempts from a single IP without hitting the per-user `_bucket_limit` (which keys on `user_sub` — unavailable for failed logins with unknown users).

**Hot partition risk on T.sessions.** `_bucket_limit()` writes one DDB item per user×action on every request. Under burst load (e.g., a wave of legitimate logins after a major broadcast), this creates write contention on `T.sessions`, impacting unrelated operations like session validation.

**No visibility into abuse patterns.** Without event logging, there is no way to identify which IPs are responsible for the most 429s, making blocklist management manual and reactive.

### 3.2 IP spoofing vector (open gap)

`client_ip_from_request()` (`normalize.py:9–18`) blindly trusts `X-Forwarded-For`. In a deployment without a trusted-proxy CIDR check, an attacker can send `X-Forwarded-For: 10.0.0.1` and have the middleware treat the request as originating from an internal IP — potentially an allowlisted range. This is a known gap flagged in the original ticket and in SEC-008. The middleware must reject the header unless the direct `request.client.host` falls within `TRUSTED_PROXY_CIDRS`.

### 3.3 Allowlist CIDR scan performance

The current allowlist design uses a DDB scan of `pk = ALLOWLIST#IP` items, requiring an in-memory CIDR check for each item. At ten entries this is trivial; at thousands it becomes O(n). The 60-second in-memory cache (`get_group_config`) mitigates this for hot paths but does not protect the first request in each window.

### 3.4 Code sites that must change (summary)

| File | Change |
|---|---|
| `app/core/normalize.py:9–18` | Add TRUSTED_PROXY_CIDRS check before trusting XFF |
| `app/middleware/rate_limit.py` | New file — Layer 1 global IP middleware |
| `app/services/rate_limit_config.py` | New file — endpoint group definitions + DDB override |
| `app/services/rate_limit_store.py` | New file — DDB check/increment + event logging |
| `app/routers/admin_rate_limits.py` | New file — admin API (confirmed exists) |
| `scripts/local-ddb-init.py` | Add `rate_limits` + `rate_limit_events` table definitions |
| `app/core/settings.py` | Add rate limit settings (confirmed at lines 1707–1712) |
| `app/core/tables.py` | Add table handles for new tables |
| `app/models.py` | Add Pydantic models for rate limit config/events |
| `frontend/src/App.tsx` | Add `/admin/rate-limits` route |
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | New admin page |

Layer 3 (`app/services/rate_limit.py`) is **not modified** — it continues writing to `T.sessions`.

---

## 4. Proposed Design / Fix

### 4.1 Architecture: three-layer separation

```
Request
  │
  ▼ app.middleware("http")(rate_limit_middleware_factory())   [Layer 1]
  │   ─ Extract IP via enhanced client_ip_from_request()
  │   ─ Blocklist check → 403 (not 429)
  │   ─ Allowlist check → skip Layer 1
  │   ─ check_rate_limit(pk="IP#{ip}") → 429 + Retry-After if exceeded
  │   ─ Fail-open if DDB unavailable (RATE_LIMIT_FAIL_OPEN=1)
  │
  ▼ Depends(rate_limit_dependency("messaging"))               [Layer 2]
  │   ─ Resolves user_sub + role from auth context
  │   ─ Bypass if role in bypass_roles (root, admin per group config)
  │   ─ check_rate_limit(pk="ENDPOINT#messaging#USER#{sub}")
  │   ─ check_rate_limit(pk="ENDPOINT#messaging#IP#{ip}")
  │   ─ Async fire-and-forget: log event to rate_limit_events
  │
  ▼ Existing call: rate_limit_login_attempt(user_sub, ip)     [Layer 3]
      ─ _bucket_limit() on T.sessions — unchanged
```

### 4.2 Data model: rate_limits table

```
PK: "IP#203.0.113.42"           SK: "GLOBAL"    → count, window_start, ttl_epoch
PK: "ENDPOINT#messaging#USER#…" SK: "GLOBAL"    → count, window_start, ttl_epoch
PK: "ALLOWLIST#IP"              SK: "10.0.0.0/8"→ added_by, added_at, reason
PK: "BLOCKLIST#IP"              SK: "198.51.100.42" → added_by, added_at, reason, ttl_epoch
PK: "CONFIG#global"             SK: "GROUP#messaging" → window_seconds, max_requests_per_user, …
```

All counters use a fixed-window `UpdateExpression` with `ConditionExpression="window_start = :ws"` to atomically reset when the window rolls over (`ConditionalCheckFailedException` path). This avoids the read-modify-write race present in `_bucket_limit()`.

### 4.3 Dev/Prod parity (SECOPS-007)

- In dev (`S.dev_mode = True`): DDB Local (port 8001) is used for `rate_limits` and `rate_limit_events` tables — same code path as production, just pointing at the local endpoint. No mock or stub needed.
- IP extraction: `client_ip_from_request()` should read `TRUSTED_PROXY_CIDRS` from settings. In dev the setting defaults to empty, meaning only `request.client.host` is used (correct for localhost dev).
- `RATE_LIMIT_FAIL_OPEN=1` is the correct default for both dev and prod; in dev the DDB tables are created by `scripts/local-ddb-init.py` so fail-open is rarely triggered.
- The admin dashboard at `/admin/rate-limits` requires `require_root` (`app/auth/policy.py:63`), which works identically in dev and prod via cookie-based session auth.

### 4.4 Response headers

Every response from Layer 1 or Layer 2 (whether allowed or blocked) should add:
```
X-RateLimit-Limit: <group max>
X-RateLimit-Remaining: <remaining>
X-RateLimit-Reset: <window_end_unix_ts>
```
On 429 responses, also add `Retry-After: <seconds>`.

The middleware uses FastAPI's `call_next` pattern to attach headers after the handler runs. Layer 2 dependencies raise `HTTPException(429, headers={"Retry-After": ...})`.

### 4.5 Fail-open behaviour

If `T.rate_limits.update_item()` raises anything other than `ConditionalCheckFailedException`, the middleware logs the error, increments `rate_limit_store_error_total`, and — if `RATE_LIMIT_FAIL_OPEN=1` — allows the request through. This prevents a DDB outage from causing a total platform blackout. In prod, a `rate_limit_store_error_total > 0 for 5 minutes` alert (SECOPS-001) should fire.

### 4.6 Alternatives considered

- **Redis / ElastiCache**: Adds ~5 ms sub-millisecond latency improvement but introduces a new managed service dependency. Rejected for v1; the `rate_limit_store.py` abstraction makes a future swap straightforward.
- **In-memory counters per worker**: Zero latency but not shared across workers. Rejected — production runs multiple workers.
- **Third-party library (slowapi, fastapi-limiter)**: Would impose Redis or in-memory storage. Rejected to maintain DDB-native consistency.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (tests/test_rate_limit_store.py, tests/test_rate_limit_middleware.py)

| # | Test | What to assert |
|---|---|---|
| 1 | `test_check_allows_below_limit` | `check_rate_limit()` returns `(True, remaining>0, reset)` for requests 1…N |
| 2 | `test_check_rejects_above_limit` | Returns `(False, 0, reset)` on request N+1 |
| 3 | `test_counter_resets_after_window` | After advancing `now_ts` by `window_seconds`, counter starts fresh |
| 4 | `test_extract_ip_trusted_proxy` | XFF trusted only when `request.client.host` is in `TRUSTED_PROXY_CIDRS` |
| 5 | `test_layer1_returns_429_with_headers` | Middleware response includes `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining` |
| 6 | `test_layer2_bypasses_admin_role` | Admin user in `bypass_roles` config receives 200 even past limit |
| 7 | `test_layer2_bypasses_root_role` | Root user receives 200 |
| 8 | `test_blocklisted_ip_403` | Blocked IP gets 403, not 429 |
| 9 | `test_allowlisted_ip_bypasses_layer1` | Allowlisted CIDR skips Layer 1 counter |
| 10 | `test_fail_open_on_ddb_error` | Simulated `ClientError` → request allowed, metric incremented |
| 11 | `test_config_override_precedence` | DDB `CONFIG#global / GROUP#messaging` item overrides in-code default |

All use moto-mocked DDB via `tests/conftest.py`.

### 5.2 Playwright E2E tests (frontend/e2e/rate-limiting.spec.ts)

19 tests across 5 sections, runnable with `npx playwright test e2e/rate-limiting.spec.ts`:

- Section A (4): Global IP limit — requests below limit succeed; exceed → 429 with Retry-After; window reset restores access.
- Section B (5): Per-endpoint group — Alice at limit triggers 429; Bob's independent counter still allows; admin Charlie bypasses; root bypasses; auth group has no role bypass.
- Section C (3): Headers — `X-RateLimit-*` present and decrement correctly.
- Section D (4): Admin API — config read/update, allowlist add, top offenders query.
- Section E (3): Admin UI — `/admin/rate-limits` page loads; non-root gets 403.

Auth: `injectAuth(page, identity)` + `x-csrf-token` for POST mutations per the project's session pattern. Root-only admin endpoints tested with root identity from `e2e_admin_session_setup.py`.

### 5.3 Observability

| Metric | Type | Labels |
|---|---|---|
| `rate_limit_check_total` | Counter | `layer` (1/2), `result` (allowed/rejected) |
| `rate_limit_429_total` | Counter | `group`, `identity_type` (ip/user) |
| `rate_limit_store_latency_ms` | Histogram | `operation` |
| `rate_limit_store_error_total` | Counter | — |
| `rate_limit_blocklist_hit_total` | Counter | — |

Alert thresholds (SECOPS-001): store errors > 0 for 5 min (critical); 429 rate > 100/s for 5 min (warning).

### 5.4 Rollout plan

| Phase | Env flag state | Impact |
|---|---|---|
| 1 | `RATE_LIMIT_GLOBAL_ENABLED=0`, `RATE_LIMIT_PER_ENDPOINT_ENABLED=0` | Tables created, code deployed, zero user impact |
| 2 | Global enabled at 1000 req/min | Catches only extreme abuse |
| 3 | Per-endpoint enabled for `auth` + `billing` first | Sensitive groups protected |
| 4 | Per-endpoint enabled for all groups, dashboard live | Full enforcement |
| 5 | Tighten limits based on dashboard data | Production-tuned values |

**Rollback**: Set `RATE_LIMIT_GLOBAL_ENABLED=0` and `RATE_LIMIT_PER_ENDPOINT_ENABLED=0` — Layer 3 continues unchanged. Tables auto-expire items via TTL.

### 5.5 Open risks

- `client_ip_from_request()` must be hardened before Layer 1 goes live in production; without `TRUSTED_PROXY_CIDRS` all traffic appears to originate from the load balancer, causing a false global throttle.
- `ByStatus` GSI hot partition at very high volume (mitigate with status key sharding in a future iteration).
- 15–18 ms added latency per request; measure p99 before tightening limits.

**Effort**: L (10–14 days as estimated). Suggested order: store + tables → middleware → admin router → dashboard → E2E.
