# SECOPS-001: Unified Security-Event Telemetry Pipeline — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

SECOPS-001 establishes a single structured sink for every suspicious or attack-relevant event the backend detects. Today the platform has three orthogonal recording paths — the `alerts` system (user-visible notification rows in `app/services/alerts.py`), the Prometheus `metrics.py` counters (process-local, no history), and domain-specific DynamoDB audit rows (business audit, not security) — but no unified, enriched, queryable attack-telemetry stream. A login-brute-force burst, a CSRF failure, and a price-tamper rejection each land in different tables with different schemas, different retention, and no cross-correlation possible from a single read path.

The goal is `app/services/security_events.py`, a thin emitter that any backend code calls with `record_security_event(event_type, severity, ...)`. The emitter auto-enriches the event with trusted client IP (requiring the SEC-008 prereq), ASN + organization, country, user-agent, request path/method, actor sub/role, and a monotone request ID, then writes to a `security_events` DynamoDB table, appends a JSON line to the app logger (for SIEM shipping), and increments a `security_events_total` Prometheus counter.

- **Type**: infra / security hardening (foundation for SECOPS-002/003/004)
- **Priority**: High — auto-ban (SECOPS-002), honeypot detection (SECOPS-003), and the monitoring dashboard (SECOPS-004) all depend on this stream
- **Status**: Open
- **Attacker class**: 🌐 any-user / ⚙️ config — affects every traffic source
- **Dependencies**: SEC-008 (trusted client IP) is a hard prerequisite; without it, XFF spoofing makes IP attribution meaningless. SECOPS-007 governs dev/prod parity for the entire pipeline.

---

## 2. Current-State Investigation (what exists today)

### 2.1 Existing recording paths

**Prometheus metrics** (`app/metrics.py`): In-process `Counter`/`Gauge`/`Histogram` objects. `LOGIN_SUCCESSES`, `LOGIN_FAILURES`, `MFA_SUCCESSES`, `MFA_FAILURES` are already defined at `app/metrics.py:62–77`. `record_auth_event(alert_type)` at `app/metrics.py:1076` dispatches to these counters. They are ephemeral (lost on restart), unlabeled by IP or actor, and non-queryable from DynamoDB. In dev mode (`APP_ENV != "prod"`) all counter objects are no-op stubs (`_NoopMetric` at `app/metrics.py:26–55`) — the `metrics_middleware` still fires but the counters do nothing.

**User-alert system** (`app/services/alerts.py`): The `ALERT_CATEGORIES["security"]` set (`alerts.py:36–38`) contains events like `login_failure`, `rate_limited`, `access_denied`, and the catch-all `security_event`. `ALERT_EVENT_TYPES` at `alerts.py:133–147` is the full enumeration. Alert rows are written to the `alerts` DynamoDB table (wired at `app/core/tables.py:314`) and delivered to users via SSE, email, SMS, webhook, and push. These are **user-facing notifications**, not an internal attack stream — they are throttled, deduplicated, and visible to the affected user, not security operators.

**Domain audit rows**: Scattered per-domain `put_item` calls write audit events to individual tables with no common schema. None carry enriched IP context.

**Rate-limit events** (`app/services/rate_limit_dashboard.py`): `log_rate_limit_event()` at `rate_limit_dashboard.py:23` writes to `T.rate_limit_events` with a date-bucket PK `DATE#{date_str}` and a timestamp sort key. This is the closest existing pattern to what SECOPS-001 needs, but it is scoped only to rate-limit exceedances.

### 2.2 IP extraction — the SEC-008 gap

Two independent IP extraction functions currently exist:

- `client_ip_from_request(req)` at `app/core/normalize.py:9` — takes the first comma-segment of `X-Forwarded-For`, falling back to `req.client.host`. **No trusted-proxy filtering.** An attacker can inject `X-Forwarded-For: 1.2.3.4` and any event recorded via this function will carry `1.2.3.4` as the attributed IP.
- `_get_client_ip(request)` at `app/services/geo_check.py:109` — identical logic; also trusts the full XFF chain without validating the proxying source.

`app/core/settings.py:32` has `trusted_proxy_cidrs: str = os.environ.get("TRUSTED_PROXY_CIDRS", "")` — the setting exists but no code currently uses it to validate the proxy chain. SEC-008 must implement a `trusted_client_ip_from_request(req)` that only trusts XFF hops forwarded by known proxy CIDRs.

### 2.3 GeoIP service — country only, no ASN

`app/services/geoip.py` implements `lookup_country(ip)` with a TTL-backed in-memory cache (cache TTL from `S.geo_cache_ttl_seconds`, default 3600; max size from `S.geo_cache_max_size`, default 50000 — `geoip.py:41–42`). In production it reads from a MaxMind GeoLite2 Country database via `geoip2.database.Reader` (`geoip.py:72–79`). In dev with no `S.geo_maxmind_db_path` it returns `None` (fail-open, `geoip.py:67–68`). Dev override: `set_mock_country(ip, code)` at `geoip.py:96`. **No ASN reader exists.** The `security_events` enricher needs both country and ASN — ASN is critical for identifying datacenter/hosting abuse (e.g., all traffic from AS14061 DigitalOcean) and triggering SECOPS-002 ASN-level blocks.

### 2.4 Middleware chain

`app/main.py:412–420` registers middleware in this order (last-registered runs first in FastAPI's LIFO stack):

```
CORSMiddleware  ← outermost
TenantMiddleware  ← if multi_tenancy_enabled
rate_limit_middleware_factory()
_api_usage_metering_middleware()
_playback_entitlement_middleware()
metrics_middleware  ← if METRICS_ENABLED (prod only)
```

`_security_headers_middleware` is **defined** at `main.py:348` but **never registered** — a known gap from SEC-016. A new `security_block_middleware` (SECOPS-002) will need to be inserted after trusted-IP resolution and before routers; the security event emitter itself does not require middleware placement since it is called inline from endpoint code.

### 2.5 `alerts.py` send_alert pattern

`app/services/alerts.py:17` imports `client_ip_from_request` from `app/core/normalize` and `record_auth_event` from `app/metrics`. The `send_alert` function already writes structured DDB rows with a `security` category. The new `record_security_event` must not call `send_alert` — that's user-visible and throttled. It writes independently to `T.security_events`.

---

## 3. Gap / Threat Analysis

### 3.1 No correlated attack stream

Today an operator cannot answer "how many failed logins came from IP 1.2.3.4 in the last hour?" without stitching together the sessions table, the Prometheus `/metrics` endpoint (only if prod mode), and the application logs. There is no single index keyed by `(IP, event_type, time_window)`.

### 3.2 XFF spoofing makes all IP-keyed data unreliable

`client_ip_from_request` (`normalize.py:9–18`) and `_get_client_ip` (`geo_check.py:109–114`) both trust the first XFF segment without validating the forwarding chain. A client behind no reverse proxy can set `X-Forwarded-For: 10.0.0.1` and be attributed as an internal IP. This enables:
- False trust: the auto-ban engine sees an RFC-1918 address that hits honeypots, never matches a block rule.
- False blame: a legitimate user's IP gets attributed to attacks originating from a different source.

### 3.3 GeoIP returns None for private IPs — silently drops enrichment

Even after SEC-008, the GeoIP lookup returns `None` for private-range IPs (`geoip.py:32–39`). The emitter must handle `None` gracefully — store `null` for country/ASN, never drop the event.

### 3.4 Missing event taxonomy at call sites

The taxonomy in the ticket maps 13+ event types to their source files. None of these sites currently call anything resembling `record_security_event`. The emitter is useless without comprehensive instrumentation. Every site listed in the taxonomy table is a code change.

### 3.5 PII / retention

IP addresses are PII in most EU jurisdictions under GDPR. The `security_events` table must have a TTL (default 90 days) on each item. The admin API (SECOPS-004) must be restricted to root/security-scoped admins only. Event records must never contain plaintext secrets, tokens, or passwords — the enricher must be called after authentication logic, not passed credential material.

### 3.6 Counter label cardinality

A `security_events_total` Prometheus counter with labels `{type, severity}` is safe cardinality (13 types × 5 severities = 65 series). Do not add `ip` as a label — unbounded cardinality would kill Prometheus.

---

## 4. Proposed Design / Fix

### 4.1 `app/services/security_events.py` — new file

```python
def record_security_event(
    event_type: str,           # taxonomy string, e.g. "auth.login_failed"
    severity: str,             # info | low | medium | high | critical
    request: Optional[Request] = None,
    actor_sub: Optional[str] = None,
    target: Optional[str] = None,   # target resource id if applicable
    detail: Optional[dict] = None,  # free-form enrichment; must not contain secrets
) -> None:
```

Internally:
1. **Trusted IP** — call `trusted_client_ip_from_request(request)` (SEC-008 implementation; falls back to `client_ip_from_request` until SEC-008 lands, gated by `S.trusted_proxy_cidrs`).
2. **Country enrichment** — `lookup_country(ip)` from `geoip.py`. Returns `None` in dev without a DB; stored as `null`.
3. **ASN enrichment** — `lookup_asn(ip)` from extended `geoip.py` (new function). Returns `(asn_number, org_name)` or `(None, None)`.
4. **Build item** — event_id `ev_<uuid4().hex>`, `pk = f"IP#{ip}"`, `sk = f"{now_ts()}#{event_id}"`, plus a `date_bucket` attribute `YYYY-MM-DD` for GSI-based daily scans, plus all enrichment fields.
5. **Write to `T.security_events`** (fire-and-forget; exceptions logged, never raised).
6. **Append JSON line** to `logger.info(json.dumps(event_item))` — structured logging for SIEM.
7. **Increment** `SECURITY_EVENTS_TOTAL.labels(type=event_type, severity=severity).inc()`.

The function is intentionally synchronous and does not `await` anything — it can be called from both sync and async handlers without ceremony.

### 4.2 DynamoDB table: `security_events`

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    name="security_events",
    pk="pk",            # "IP#{ip}" for per-source scans; "EV#{date}" for day-bucket
    sk="sk",            # "{ts}#{event_id}"
    ttl_attribute="ttl_epoch",
    gsis=[
        GSIDef("event_type-index", pk="event_type", sk="sk"),
        GSIDef("actor_sub-index",  pk="actor_sub",  sk="sk"),
        GSIDef("asn-index",        pk="asn",         sk="sk"),
        GSIDef("country-index",    pk="country",     sk="sk"),
        GSIDef("date-index",       pk="date_bucket", sk="sk"),
    ],
    attr_types={
        "pk": "S", "sk": "S",
        "event_type": "S", "actor_sub": "S",
        "asn": "S", "country": "S", "date_bucket": "S",
    },
)
```

Note: `sk` contains a numeric timestamp prefix for chronological sorting within each GSI partition. Since `sk` is a `String` type (contains the `#event_id` suffix), the numeric prefix sorts lexicographically — use zero-padded 10-digit epoch (`f"{now_ts():010d}#{event_id}"`).

Add to `app/core/tables.py` `Tables` dataclass:

```python
security_events: Any
```

And wire in `T = Tables(...)`:

```python
security_events=_safe_table(S.security_events_table_name),
```

Add to `app/core/settings.py`:

```python
security_events_table_name: str = os.environ.get("SECURITY_EVENTS_TABLE_NAME", "security_events")
security_events_ttl_days: int = int(os.environ.get("SECURITY_EVENTS_TTL_DAYS", "90"))
```

### 4.3 Extend `app/services/geoip.py` — add ASN reader

Add a parallel `_asn_cache` dict and `lookup_asn(ip)` function mirroring `lookup_country` but using `geoip2.database.Reader` with a GeoLite2-ASN database. Add `S.geo_asn_db_path` setting. In dev without the DB path, return `(None, None)`. Add `set_mock_asn(ip, asn, org)` / `clear_mock_asns()` for E2E overrides — same pattern as `set_mock_country` at `geoip.py:95–109`.

### 4.4 Prometheus metrics additions to `app/metrics.py`

```python
SECURITY_EVENTS_TOTAL = Counter(
    "security_events_total",
    "Security telemetry events recorded",
    ["type", "severity"],
)
```

Add a `record_security_event_metric(event_type, severity)` helper following the `record_auth_event` pattern at `metrics.py:1076`.

### 4.5 Instrumentation map — call sites

Each call site below adds one line (or a small wrapper) calling `record_security_event(...)`. No router logic changes required beyond adding the call:

| Site | Event type | Severity |
|------|-----------|---------|
| `app/routers/ui_mfa.py` login failure handler | `auth.login_failed` | medium |
| `app/services/rate_limit.py` `rate_limit_or_429` HTTPException raise (`rate_limit.py:58`) | `ratelimit.exceeded` | low |
| `app/auth/deps.py` CSRF validation failure | `auth.csrf_failed` | medium |
| `app/auth/deps.py` 403 on IDOR-protected paths | `authz.forbidden` | medium |
| CCBill/Stripe webhook signature verifiers | `webhook.signature_invalid` | high |
| `app/services/shoppingcart.py` price-tamper rejection | `commerce.price_tamper_rejected` | high |
| SSRF policy rejection sites | `ssrf.blocked` | high |
| Ban-check on session load | `ban.access_after_ban` | critical |
| Moderation flood detection | `moderation.report_flood` | medium |
| MFA device add / WebAuthn register | `mfa.factor_added` | info |

### 4.6 Dev/Prod parity (SECOPS-007)

| Layer | Dev (no AWS) | Prod (AWS) |
|-------|-------------|-----------|
| DynamoDB sink | DDB Local `:8001` via `T.security_events` — same boto3 path | DynamoDB |
| GeoIP country | `set_mock_country` override or `None` (fail-open) | GeoLite2 Country DB at `S.geo_maxmind_db_path` |
| ASN enrichment | `set_mock_asn` override or `(None, None)` | GeoLite2 ASN DB at `S.geo_asn_db_path` |
| Log sink | `logging.getLogger` → stdout | CloudWatch Logs handler (SIEM ship) |
| Prometheus counter | `_NoopMetric` (dev mode noop) | real `prometheus_client.Counter` |

The `record_security_event` function itself has zero conditionals on `S.dev_mode` — all variation is in the called helpers (`lookup_country`, `lookup_asn`) that already handle dev gracefully.

### 4.7 Backward compatibility

The emitter is additive. It does not change any existing function signatures, DDB schemas for existing tables, or middleware behavior. The only schema addition is the new `security_events` table. The only settings additions are three new `SECURITY_EVENTS_*` and `GEO_ASN_DB_PATH` variables, all with safe defaults.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_security_events.py`)

- **Enrichment fields present**: mock `lookup_country` → `"US"`, `lookup_asn` → `(14061, "DIGITALOCEAN-ASN")`, call `record_security_event("auth.login_failed", "medium", request=mock_request, actor_sub="usr_abc")`, assert the written DDB item contains `country="US"`, `asn="AS14061"`, `org="DIGITALOCEAN-ASN"`, `actor_sub="usr_abc"`, `ip=...`, `event_type="auth.login_failed"`.
- **TTL set correctly**: assert `item["ttl_epoch"] > now_ts() + 86400 * 89`.
- **No secrets in item**: pass a `detail={"password": "hunter2", "token": "tok_abc"}`, assert the written item does not contain either value (the emitter should redact well-known secret keys or simply document that callers must not pass them).
- **Counter increments**: in prod mode, assert `SECURITY_EVENTS_TOTAL.labels(type="auth.login_failed", severity="medium")` count is 1 after call.
- **None enrichment handled**: mock `lookup_country` → `None`, `lookup_asn` → `(None, None)`, assert item is still written without error with `country=None`, `asn=None`.
- **GeoIP fail-open**: simulate `lookup_country` raising an exception, assert `record_security_event` does not raise.

### 5.2 Playwright E2E (`frontend/e2e/security-events.spec.ts`)

- Trigger a failed login for Alice via `page.request.post("/ui/session/login", ...)` with wrong credentials.
- Query `GET /internal/security-events?event_type=auth.login_failed` (dev-only endpoint added in SECOPS-004 dev panel).
- Assert one event exists with correct `event_type`, `severity`, and non-null `ip`.
- Rate-limit exceedance: send 6 rapid identical requests to a rate-limited endpoint; assert `ratelimit.exceeded` event appears.
- Verify no event emitted for a clean, successful login.

### 5.3 Manual QA steps

1. `just restart` to wipe DDB Local.
2. Trigger a login failure in the browser; open Dev Tools (port 3001) → Security Events panel (SECOPS-004); assert event row visible.
3. Check structured log output in `.logs/uvicorn.log`; assert JSON line with `event_type`, `severity`, `ip`.
4. In prod deployment: verify `security_events_total` counter appears in Prometheus scrape at `/metrics`; verify CloudWatch log group contains the JSON events.

### 5.4 Rollback plan

The emitter is fire-and-forget — any DDB write failure is logged and swallowed. Disabling instrumentation at any call site requires only deleting the `record_security_event(...)` call. The table and settings can be left in place with no functional impact if the emitter is commented out. The Prometheus counter addition (`_NoopMetric` in dev) is safe to revert by removing the counter definition and its increment call.

### 5.5 Risks & open questions

- **SEC-008 not yet implemented**: Until `trusted_client_ip_from_request` exists, the emitter uses `client_ip_from_request` — all IP data is spoofable. Tag every row `ip_trusted: False` until SEC-008 lands, then flip to `ip_trusted: True`.
- **GeoLite2 ASN DB licensing**: MaxMind GeoLite2 ASN is free but requires a MaxMind account and CI/CD pipeline fetch step. Must not be checked into the repo.
- **Single-process moto S3 note**: The emitter writes to DynamoDB, not S3, so the `--workers 1` moto constraint does not apply. The DDB local session is safe for multiple test workers.
- **High write volume**: On a busy prod instance with many `ratelimit.exceeded` events, this could generate thousands of DDB writes per minute. Mitigation: the auto-ban engine (SECOPS-002) consumes these events and suppresses repeat-offender traffic quickly; also consider sampling `info`-severity events at 10% in prod.

### 5.6 Effort estimate

**Medium** (~5 days): 1 day for `security_events.py` + table + settings; 1 day for ASN extension to `geoip.py`; 1.5 days for instrumentation across all call sites; 1 day for tests; 0.5 day for metrics additions. Sequentially after SEC-008 (adds ~2 more days for trusted IP).
