# Security Tooling & Honeypots — Implementation Tickets

This backlog adds defensive security tooling — honeytokens, decoy/honeypot endpoints, intrusion-detection signals, security alerting, and a unified Security dashboard — layered on top of the existing fraud/rate-limit/risk infrastructure (`app/services/fraud_detection.py`, `app/services/rate_limit.py`, `app/services/rate_limit_dashboard.py`, `app/routers/fraud_detection.py`). All work here is strictly DEFENSIVE: detect, alert, and (optionally) slow down hostile callers; it never attacks back.

## Milestone 1 — Foundations (config, storage, signal bus)

### HNY-001: Security tooling settings + feature flags
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add a cohesive block of `Settings` fields next to the existing fraud flags (`app/core/settings.py:2541-2552`, `fraud_detection_enabled` / `fraud_block_enabled` / `fraud_score_threshold`) using the same `os.environ.get(...).lower() not in (...)` idiom and `int(os.environ.get(...))` for numerics.
- New flags (all default OFF except where noted, SECOPS-007 dev/prod parity — no `dev_mode` branch): `honeytoken_enabled`, `honeypot_endpoints_enabled`, `honeypot_tarpit_enabled` (default false), `honeypot_tarpit_max_seconds` (default 5), `ids_enabled`, `ids_impossible_travel_enabled`, `ids_credential_stuffing_enabled`, `ids_scanning_detection_enabled`, `security_dashboard_enabled`, `security_webhooks_enabled`, and numeric thresholds `ids_credential_stuffing_max_failures` (default 10), `ids_credential_stuffing_window_seconds` (default 300), `ids_scanning_max_404_per_min` (default 30), `ids_impossible_travel_min_kmh` (default 900).
- Add matching entries to `.env.local.example` documented as defensive-only.

**Acceptance Criteria**
- All flags resolve from env via the singleton `S` and default to OFF (except thresholds).
- With every flag at default, no behavior changes vs current `main` (all new code paths short-circuit when disabled).
- `tests/` unit test asserts each flag's default and env override.

**Dependencies**
- None.

---

### HNY-002: DynamoDB tables for security events, honeytokens, and decoy hits
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `TableDef` entries to `scripts/local-ddb-init.py` following the existing single-table conventions (see the `fraud_detection` table used by `T.fraud_cases` in `app/services/fraud_detection.py:26`).
- New table `security_events` (PK `pk`, SK `sk`) for unified IDS/honeypot/honeytoken signal rows, with a GSI keyed on `event_date` (S) + `ts` (N) for the dashboard time-window queries — declare `attr_types={"ts": "N"}` per the numeric-GSI gotcha in `CLAUDE.md` and the `schedules-due-index` precedent.
- New table `honeytokens` (PK `token_id`) holding decoy API keys / fake credential records / canary-row pointers, plus a GSI to look up a decoy by its `lookup_hash` (so a honeytoken key reuses the same `key_id`/`secret_hash` shape as real keys in `app/services/api_keys.py:141-177`).
- Wire table handles into `app/core/tables.py` as `T.security_events` and `T.honeytokens`.

**Acceptance Criteria**
- `just restart` recreates both tables; `T.security_events` / `T.honeytokens` are importable.
- Numeric GSI sort keys carry `attr_types` and accept integer `now_ts()` queries without `ValidationException`.
- A throwaway pytest writes + queries one row through each handle (moto).

**Dependencies**
- HNY-001.

---

### HNY-003: Security event recorder + severity-aware alert bridge
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Create `app/services/security_events.py` with `record_security_event(*, kind, severity, source_ip, user_sub=None, request=None, **details)` writing to `T.security_events` (HNY-002) and returning an `event_id`.
- Emit a high-severity alert through the existing audit/alert mechanism: call `app.services.alerts.audit_event(event="security_signal", user_sub=..., request=..., outcome="suspicious", severity=..., **details)` (signature at `app/services/alerts.py:644`) so IP/user-agent/impersonation enrichment (`alerts.py:652-667`) and `write_alert` persistence (`alerts.py:711`) are reused — do NOT reimplement alerting.
- Provide a `_safe_record(...)` fire-and-forget wrapper (local import, swallow all exceptions) mirroring `host_inventory._audit`, so a recorder failure NEVER breaks the request path.
- Capture `source_ip` via the existing `client_ip_from_request` used in `audit_event` (`alerts.py:653`).

**Acceptance Criteria**
- `record_security_event` persists a row and triggers exactly one `audit_event` call.
- Recorder raising internally does not propagate (caller sees `None`/no-op).
- Severity is a constrained enum (`info|low|medium|high|critical`); high/critical map to an alert outcome that surfaces in the alerts list.
- Offline pytest with patched `audit_event` + moto `T.security_events`.

**Dependencies**
- HNY-001, HNY-002.

---

## Milestone 2 — Honeytokens (decoy credentials & canary data)

### HNY-004: Honeytoken issuance service (decoy API keys / fake creds / canary rows)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `app/services/honeytokens.py` with `mint_honeytoken(*, kind, label, admin_sub, placement=None)` where `kind ∈ {api_key, credential_record, canary_row}`.
- For `api_key` honeytokens, generate a key with the exact public shape of a real one (`ak_<kid>.<secret>` via `new_api_key_secret`/`parse_api_key`, `app/services/api_keys.py:18-29`) and store its `key_id` + `api_key_hash(secret)` (`api_keys.py:31-34`) in `T.honeytokens` — NOT in `T.api_keys` — so it is indistinguishable to an attacker but isolated from the real key store.
- For `credential_record` / `canary_row`, store a decoy username/password or a marked data-row id (the "canary") that, when read, can be matched back to a honeytoken.
- Emit `audit_event("honeytoken.mint", admin_sub, ...)` on creation.

**Acceptance Criteria**
- Minting returns the plaintext token once (never again), persisting only the hash for `api_key` kind.
- Honeytoken keys never appear in `list_api_keys` / `T.api_keys` queries (isolation verified).
- Each kind is retrievable by `token_id` and matchable by `lookup_hash`.
- Offline pytest (moto `T.honeytokens`, stubbed pepper).

**Dependencies**
- HNY-002, HNY-003.

---

### HNY-005: Honeytoken trip-wire on API-key authentication
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- In the API-key validation path `check_api_key_allowed` (`app/services/api_keys.py:386-412`) — the single chokepoint reached via `require_api_key_principal` (`app/services/api_key_auth_dependency.py:55-82`) — before the normal "Invalid API key" raise (`api_keys.py:388-389`), check whether the presented `key_id`+secret matches a honeytoken via `honeytokens.match_api_key(...)`.
- On a honeytoken match: call `security_events.record_security_event(kind="honeytoken_api_key_used", severity="critical", source_ip=client_ip, request=...)` then raise the SAME `HTTPException(401, "Invalid API key")` so the response is byte-for-byte identical to a normal failure (no oracle for the attacker).
- Gate the whole check on `S.honeytoken_enabled`; when off, behavior is unchanged.

**Acceptance Criteria**
- Using a honeytoken API key returns the identical 401 a bogus key returns (status, body, headers).
- A `critical` security event + alert is recorded with the caller IP and user-agent.
- A genuine key is unaffected and never recorded as a honeytoken hit.
- Offline pytest drives `check_api_key_allowed` with a planted honeytoken and asserts the event + identical 401.

**Dependencies**
- HNY-004.

---

### HNY-006: Canary data-row access detection
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Provide `honeytokens.note_canary_access(canary_id, *, user_sub, request)` that records a `high`-severity security event when a marked canary row (HNY-004 `canary_row` kind) is read or exported.
- Wire it into one or two high-value read paths as a reference integration (e.g., an admin user-lookup / export read) — keep the hook a single best-effort line, no behavioral change to the legitimate response.
- Document the pattern in code comments so future read endpoints can opt in.

**Acceptance Criteria**
- Reading a canary row fires exactly one `high` security event tied to the canary's `token_id`.
- Reading a non-canary row fires nothing (no per-read overhead beyond a cheap membership check, gated by `S.honeytoken_enabled`).
- Offline pytest validates the hook fires on canary read and not otherwise.

**Dependencies**
- HNY-004.

---

### HNY-007: Honeytoken admin CRUD endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add `app/routers/security_honeytokens.py` (prefix `/v1/admin/security/honeytokens`, `Depends(require_root_session)` per `app/auth/deps.py:308`) mirroring the fraud router style (`app/routers/fraud_detection.py:34`).
- Endpoints: `POST /` (mint, returns plaintext once), `GET /` (list metadata, never secrets), `DELETE /{token_id}` (retire), `GET /{token_id}/hits` (security events for that token).
- Register the router in `app/main.py` alongside the other admin routers (`app/main.py:538+`).

**Acceptance Criteria**
- Non-root callers receive 403; root can mint/list/retire/inspect hits.
- List/get responses never echo a stored secret or hash.
- Offline pytest exercises all four routes with stubbed deps.

**Dependencies**
- HNY-004, HNY-005.

---

## Milestone 3 — Honeypot / decoy endpoints

### HNY-008: Decoy endpoint router (fake admin/login paths)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `app/routers/security_honeypot.py` registering plausible-but-fake paths that don't exist today (e.g. `/wp-login.php`, `/admin.php`, `/.env`, `/api/v1/admin/login`, `/phpmyadmin`) — chosen to mimic common scanner targets, NOT to shadow any real route (verify none collide with existing routes registered in `app/main.py:538+`).
- Each handler records `security_events.record_security_event(kind="honeypot_hit", severity="medium", source_ip, request)` then returns a generic, realistic-looking failure (e.g. a fake login form or 401) — never reveal it is a trap.
- Gate registration on `S.honeypot_endpoints_enabled`; when off, the routes are not mounted (so probing them 404s like any other unknown path).

**Acceptance Criteria**
- Hitting any decoy path records a `honeypot_hit` event with the caller IP/UA and returns a benign response.
- With the flag off, decoy paths are absent (normal 404).
- No decoy path shadows or intercepts a real application route.
- Offline pytest hits each decoy and asserts the event + response shape.

**Dependencies**
- HNY-003.

---

### HNY-009: Tarpit middleware for flagged callers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add an `app.middleware("http")` factory (registered in `create_app` after the existing middleware chain, `app/main.py:529-532`) that, when `S.honeypot_tarpit_enabled`, applies a bounded `asyncio.sleep` (≤ `S.honeypot_tarpit_max_seconds`) to requests from source IPs recently flagged by honeypot/IDS signals.
- Maintain the "flagged IP" set via the DDB-backed bucket primitives already used for rate limits (`app/services/rate_limit.py:_bucket_limit`, `rate_limit.py:60`) or a short-TTL `security_events` lookup — do NOT add a new in-memory-only store (multi-worker safety).
- Tarpit must be async (never block the event loop with `time.sleep`) and must NEVER apply to authenticated admin/root sessions.

**Acceptance Criteria**
- A flagged IP experiences an added delay ≤ the configured max; an unflagged IP is unaffected.
- Disabling the flag removes all delay.
- Tarpit cannot exceed the cap and cannot delay root/admin traffic.
- Offline pytest patches the flagged-IP check + `asyncio.sleep` and asserts delay application/skip.

**Dependencies**
- HNY-008.

---

## Milestone 4 — Intrusion detection signals

### HNY-010: Credential-stuffing / brute-force detector
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `app/services/intrusion_detection.py` with `note_auth_failure(*, user_sub, ip, request)` that counts failures per-IP and per-account within `S.ids_credential_stuffing_window_seconds` using the existing DDB bucket counters (`app/services/rate_limit.py:163` `rate_limit_login_attempt` / `_bucket_limit`).
- When failures exceed `S.ids_credential_stuffing_max_failures`, record a `high` security event (`kind="credential_stuffing"`) and feed it into risk via the fraud service's existing user-risk path (`app/services/fraud_detection.py:196` `compute_risk_score` / flag mechanism) rather than a parallel scorer.
- Hook `note_auth_failure` into the login/MFA failure paths that already emit `audit_event` (e.g. the flows behind `rate_limit_login_attempt`/`rate_limit_mfa_verify`, `rate_limit.py:163,175`).

**Acceptance Criteria**
- N+1 failures from one IP across many accounts within the window fires one `credential_stuffing` event and raises that signal into the risk/flag pipeline.
- Below threshold or with `S.ids_credential_stuffing_enabled` off → nothing.
- Successful logins do not increment the failure counter.
- Offline pytest with patched `now_ts` + moto bucket table.

**Dependencies**
- HNY-003.

---

### HNY-011: Impossible-travel detector
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- In `app/services/intrusion_detection.py`, add `check_impossible_travel(*, user_sub, ip, request)` that compares the current login's geo against the user's last recorded login geo/timestamp and flags when implied speed exceeds `S.ids_impossible_travel_min_kmh`.
- Reuse any existing geo/device-trust signal already captured for `device_location_mismatch` (referenced in the alert pretty-map, `app/services/alerts.py:704`) and store last-seen geo on the user/security-event row; do not add a new third-party geo dependency in dev (mock-resolvable, SECOPS-007 parity).
- On trip, record a `high` `kind="impossible_travel"` security event and raise the user's risk signal.

**Acceptance Criteria**
- Two logins from distant geos within an impossibly short interval fire the event; plausible travel does not.
- Disabling `S.ids_impossible_travel_enabled` short-circuits.
- First-ever login for a user (no prior geo) never trips.
- Offline pytest with synthetic geo/timestamp pairs.

**Dependencies**
- HNY-010.

---

### HNY-012: Scanning / enumeration detector
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Detect scanning by tracking per-IP 404/401 burst rates in middleware: extend the existing middleware chain (after `rate_limit_middleware_factory`, `app/main.py:530`) to increment a per-IP bucket on 4xx responses and, above `S.ids_scanning_max_404_per_min`, record a `medium` `kind="scanning"` security event.
- Treat repeated honeypot hits (HNY-008) as a strong scanning corroborator (escalate severity to `high` when both signals present for an IP).
- Must be cheap: only count on 4xx, gate on `S.ids_scanning_detection_enabled`, never on the hot 2xx path.

**Acceptance Criteria**
- A burst of 404s from one IP within a minute fires one `scanning` event; normal browsing does not.
- A scanning IP that also tripped a honeypot is escalated to `high`.
- Flag off → no counting overhead.
- Offline pytest drives the middleware with synthetic 404 bursts.

**Dependencies**
- HNY-003, HNY-008.

---

## Milestone 5 — Unified Security dashboard

### HNY-013: Security dashboard aggregation service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `app/services/security_dashboard.py` that aggregates, for a time window, counts/series from: fraud (`app/routers/fraud_detection.py:185` `get_stats` / `app/services/fraud_detection.py`), rate-limit offenders (`app/services/rate_limit_dashboard.py:116` `get_top_offenders` + `query_events`, `rate_limit_dashboard.py:66`), risk scores (`compute_risk_score`, `fraud_detection.py:196`), and the new `T.security_events` (honeypot hits, honeytoken trips, IDS signals).
- Provide `get_security_overview(window)` returning blended sections: `active_threats` (open fraud freezes + recent critical/high security events), `honeypot_hits`, `honeytoken_trips`, `ids_signals`, `rate_limit_offenders`, `risk_distribution`.
- Query `T.security_events` via the `event_date`+`ts` GSI (HNY-002) — do NOT scan.

**Acceptance Criteria**
- `get_security_overview` returns a single typed payload combining all five sources for a given window.
- `T.security_events` access uses the GSI (no table scan).
- Empty environment returns zeroed sections, not errors.
- Offline pytest with seeded rows across sources.

**Dependencies**
- HNY-003, HNY-013 sources (existing fraud/rate-limit services).

---

### HNY-014: Security dashboard API endpoints
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `app/routers/security_dashboard.py` (prefix `/v1/admin/security`, `Depends(require_admin_session)` for read, `require_root_session` for honeytoken/decoy mutation per `app/auth/deps.py:308`).
- Endpoints: `GET /overview`, `GET /events` (paginated via `app/core/cursor.py`, filterable by `kind`/`severity`/`ip`), `GET /events/{event_id}`, `GET /threats/active`.
- Gate on `S.security_dashboard_enabled` and register in `app/main.py` near the fraud/risk routers.

**Acceptance Criteria**
- Admin can read overview/events; non-admin → 403.
- Event list paginates with encoded cursors and honors `kind`/`severity`/`ip` filters.
- With the flag off the router returns 404 for its paths.
- Offline pytest covers auth gating, filtering, and pagination.

**Dependencies**
- HNY-013.

---

### HNY-015: Unified Security dashboard frontend page
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `frontend/src/pages/admin/SecurityDashboardPage.tsx` aggregating the new API, modeled on the existing `RiskDashboardPage.tsx` / `RateLimitDashboard.tsx` / `fraud/FraudReviewQueuePage.tsx` pages (`frontend/src/pages/admin/`) and their React Query patterns.
- Sections: Active Threats banner, Honeypot Hits, Honeytoken Trips, IDS Signals timeline, Rate-Limit Offenders, Risk Distribution; drill-down to a security-event detail.
- Add endpoint wrappers in `frontend/src/api/endpoints/` and types in `frontend/src/api/types.ts`; add the route + lazy import in `frontend/src/App.tsx` next to the existing `admin/risk` / `admin/rate-limits` / `admin/fraud` routes (`App.tsx:439,444,462`).

**Acceptance Criteria**
- Route `admin/security` renders all sections from live API data behind the admin shell.
- Event drill-down shows IP/UA/severity/kind/details.
- Page is hidden/empty-stated cleanly when `S.security_dashboard_enabled` is off (API 404).
- Playwright E2E spec (`frontend/e2e/security-dashboard.spec.ts`) covers admin access + section rendering, following the admin-session cookie pattern (`e2e_admin_session_setup.py`).

**Dependencies**
- HNY-014.

---

## Milestone 6 — Alerting, webhooks, and hardening

### HNY-016: Security webhook event types + dispatch
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Register security event types in `WEBHOOK_EVENT_TYPES_V2` (`app/services/webhook_service.py:60`) — e.g. `security.honeytoken.tripped`, `security.honeypot.hit`, `security.ids.signal`, `security.threat.detected` — mirroring how KYC/ad events are registered (`webhook_service.py:182,189`).
- From `security_events.record_security_event` (HNY-003), best-effort dispatch high/critical events to subscribed endpoints (reuse the existing webhook dispatcher and `app.services.alerts.send_alert_webhook_fanout`, `app/services/alerts.py:636`), gated on `S.security_webhooks_enabled`.
- Dispatch must be fire-and-forget and never block the request or the recorder.

**Acceptance Criteria**
- New event types validate on webhook subscription creation.
- A high/critical security event triggers one dispatch per subscribed endpoint; low/info do not.
- Dispatch failure is swallowed (recorder still succeeds).
- Offline pytest with a stubbed dispatcher asserts type filtering + best-effort behavior.

**Dependencies**
- HNY-003.

---

### HNY-017: Active-threat correlation + auto-escalation into risk/freeze
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add a correlation step in `app/services/intrusion_detection.py` that, when multiple distinct high/critical signals concentrate on one user/IP (e.g. honeytoken trip + credential-stuffing within a window), raises the fraud risk signal and — only when `S.fraud_freeze_enabled` (`app/core/settings.py:2547`) — invokes the existing `freeze_user(...)` path (`app/services/fraud_detection.py:435`); otherwise it only flags.
- Reuse the fraud review queue / flag mechanism so escalations land in `FraudReviewQueuePage` — do NOT build a parallel queue.
- Record an `audit_event("security.auto_escalate", "system_security", ...)` on every escalation.

**Acceptance Criteria**
- Correlated multi-signal pressure on one subject raises risk and (with freeze enabled) freezes; with freeze disabled it only flags.
- Escalations appear in the existing fraud review queue and emit an audit event.
- Single isolated signals do not auto-escalate.
- Offline pytest with patched `freeze_user` asserts both flag-only and freeze branches.

**Dependencies**
- HNY-005, HNY-010, HNY-012.

---

### HNY-018: Security tooling test suite + threat-model pass
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Consolidate offline regression tests under `tests/` for every HNY service following the repo's hermetic style (moto tables bound to frozen `T.*`/`S` via `object.__setattr__`, patched collaborators, no real AWS/network — per the GAP-test patterns in `CLAUDE.md`).
- Add an E2E spec exercising the admin Security dashboard, honeytoken CRUD, and a simulated honeypot hit.
- Run a defensive threat-model review: confirm honeytoken auth failures are byte-identical to real failures (no oracle), tarpit cannot DoS legitimate users, IDS counters can't be poisoned to flag innocents, and no decoy path shadows a real route.

**Acceptance Criteria**
- `just test` passes with the new unit tests; `just e2e` passes the new security spec.
- Threat-model checklist documented and each item verified by a test where feasible.
- All feature flags default OFF → suite confirms zero behavioral change from current `main` when disabled.

**Dependencies**
- HNY-005, HNY-008, HNY-010, HNY-014, HNY-016, HNY-017.

---
