# SECOPS-004: Detection, Correlation, Alerting & Monitoring Dashboard — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

SECOPS-004 converts the raw security-event stream from SECOPS-001 into operator situational awareness and timely actionable notifications. It has three interdependent components:

1. **Threat scoring** (`app/services/threat_scoring.py`): a sliding-window aggregation engine that computes a numerical risk score per IP, ASN, country, and actor sub from the mix of recent events. Feeds SECOPS-002's auto-ban threshold logic with a pre-computed score rather than per-event threshold polling.
2. **Alerting integration** (`app/services/alerts.py` extension): reuses the existing alert delivery infrastructure to notify security admins on high-severity events, honeypot hits, score spikes, and auto-ban escalations — with deduplication/throttle so a single burst doesn't flood the on-call channel.
3. **Security Monitoring Dashboard** (`frontend/src/pages/admin/SecurityMonitoringPage.tsx`): a root/security-scoped admin page showing a live event timeline, top-offender breakdowns by IP/ASN/country, current block/allow lists with one-click management, per-source drill-down, and a honeypot/honeytoken feed. Backed by new read endpoints in `app/routers/security_monitoring.py`.

- **Type**: feature / operational tooling
- **Priority**: Medium (detection infrastructure must ship first; this surfaces it)
- **Status**: Open
- **Attacker class**: N/A — this ticket is operator-facing, not directly attacker-facing
- **Persona**: security operator / root admin
- **Consumes**: SECOPS-001 events, SECOPS-002 block lists, SECOPS-003 honeypot events
- **Reuses**: `app/services/alerts.py`, `app/services/alert_priority.py`, `app/metrics.py`, `RiskDashboardPage.tsx` UI patterns, `RateLimitDashboard.tsx` table/badge/dialog components
- **Cross-references**: SECOPS-007 (dev/prod parity), SECOPS-001/002/003 (all must ship first)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Existing alert delivery infrastructure

`app/services/alerts.py` is a mature, multi-channel delivery system. The `ALERT_CATEGORIES["security"]` set at `alerts.py:36–38` already includes `"security_event"` — a catch-all event type wired to the `URGENT` priority in `app/services/alert_priority.py:28`. `send_alert` writes rows to `T.alerts`, delivers via SSE, email, SMS, webhook, and push. Rate-limiting per channel is enforced by `can_send_alert_channel` in `app/services/rate_limit.py:321–337` (hourly caps for email/SMS/push/webhook).

`app/services/alert_email_templates.py:140` maps `"security_event"` to `_template_security_alert`, so security event alerts already have an email template path. The security events SECOPS-004 wants to alert on (`honeypot.hit`, `critical` severity events, score spikes) can be delivered by calling `send_alert(user_sub=security_admin_sub, event="security_event", details={...})` — no new delivery plumbing is required.

### 2.2 `RiskDashboardPage.tsx` — existing admin risk dashboard

`frontend/src/pages/admin/RiskDashboardPage.tsx` (lines 1–80 read) uses `useQuery`, `useMutation`, `Badge`, `Table`, `Dialog`, and score visualizations (`TierBadge`, `ScoreGauge`). The design pattern — a risk score out of 100, tier badges (low/medium/high/critical), and a user drill-down dialog — maps directly to the threat-score visualization needed in the new security monitoring page. The `RiskDashboardPage` and the new `SecurityMonitoringPage` are **different concerns** (user-risk scoring vs. network-attack telemetry), but share UI primitives and layout.

### 2.3 `RateLimitDashboard.tsx` — block/allowlist management UI

`frontend/src/pages/admin/RateLimitDashboard.tsx` (lines 1–80 read) imports `getBlocklist`, `addToBlocklist`, `removeFromBlocklist`, `addToAllowlist`, `removeFromAllowlist` from `@/api/endpoints/adminRateLimits`. It uses `Tabs`, `Table`, `Badge`, `Dialog`, `Input`, and mutation-based add/remove flows with toast notifications. The block/allowlist management section of `SecurityMonitoringPage` reuses this same component structure — the difference is it queries `T.security_blocklist` (SECOPS-002) rather than the rate-limit blocklist.

### 2.4 `app/metrics.py` — existing counters, noop in dev

`app/metrics.py:13–15` gates all Prometheus metrics on `APP_ENV in {"prod", "production"}`. In dev, all metric objects are `_NoopMetric` stubs (`metrics.py:26–55`). The new security counters (`SECURITY_EVENTS_TOTAL`, `NETBLOCKS_ACTIVE`, `AUTOBAN_ACTIONS_TOTAL`, `HONEYPOT_HITS_TOTAL`) follow the same pattern — defined as `Counter`/`Gauge` at module level, functional in prod, no-ops in dev.

The existing `metrics_middleware` at `metrics.py:1111` tracks per-request HTTP metrics. Security-specific metrics are logically separate counters, not extensions of the HTTP middleware.

### 2.5 Admin authorization pattern

`app/auth/deps.py` provides `require_admin_session` (role ≥ ADMIN) and `require_root_session` (role == ROOT). Security monitoring endpoints expose sensitive attack intelligence and block-list management — these must use `require_root_session` or a dedicated `require_security_scope_session` check (a scoped admin with `admin_profile.scopes` containing `"security"`).

The existing `ADMIN_SCOPE_DENIED` counter at `metrics.py:719` tracks scope authorization failures. An attempt by a non-security-scoped admin to reach the security monitoring endpoints should both return 403 and increment this counter.

### 2.6 `app/services/rate_limit_dashboard.py` — query pattern for event log

`rate_limit_dashboard.py:23` writes events to `T.rate_limit_events` with `pk = f"DATE#{date_str}"` and `sk = f"{ts}#{event_id}"`. Query pattern: `T.rate_limit_events.query(KeyConditionExpression=Key("pk").eq(f"DATE#{today}"))`. The `security_events` table (SECOPS-001) uses the same date-bucket pattern (`date_bucket` GSI). The security monitoring API's "recent events" query reuses this GSI-based daily-bucket pattern.

### 2.7 No existing `threat_scoring.py` or `security_monitoring.py`

A codebase search confirms neither `app/services/threat_scoring.py` nor `app/routers/security_monitoring.py` exists. This is greenfield.

---

## 3. Gap / Threat Analysis

### 3.1 Raw events without aggregation create alert storms

If the alerting system fires a notification for every individual `auth.login_failed` event during a credential-stuffing attack (potentially thousands per minute), on-call channels are flooded and the real signal is buried. The threat-scoring layer aggregates events into a single "IP X has risk score 87, breached critical threshold" alert — one notification, not thousands.

### 3.2 No operator visibility into the live attack surface

Without the dashboard, a security operator must manually query DynamoDB, grep logs, or write custom scripts to answer basic questions: "What IP is hammering us right now?", "Which country has the most blocked requests today?", "Are any honeytokens in use?" The monitoring page makes this a one-click operation.

### 3.3 Block/allowlist management requires root CLI access today

After SECOPS-002 ships, adding/removing blocks requires a DynamoDB console or custom script. The security monitoring dashboard's one-click block/unblock UI makes incident response dramatically faster.

### 3.4 Threat score drift — stale scores

A sliding-window aggregation over the SECOPS-001 table is computed on-demand per request. At high event volume (> 10,000 events/hour), a naive per-request query for the latest score could be slow. The scoring engine must cache recent scores in memory or in a lightweight DDB `threat_scores` table updated asynchronously.

### 3.5 Alert deduplication — existing `alerts.py` per-user rate limits

`can_send_alert_channel` (`rate_limit.py:321–337`) enforces per-user-per-channel hourly caps (e.g., `S.alerts_email_max_per_window` emails/hour to a given admin). An attack generating 1,000 honeypot hits/minute would exhaust the hourly email cap in seconds. The security alerting wrapper must implement **event-level deduplication** — one alert per (event_type, source_ip, 5-minute window) regardless of the channel caps — so the operator gets one notification about "IP X is hitting honeypots" rather than being silently throttled after the first.

---

## 4. Proposed Design / Fix

### 4.1 `app/services/threat_scoring.py` — new file

```python
def compute_threat_score(ip: str, window_seconds: int = 3600) -> dict:
    """
    Aggregate security events for the given IP in the past window_seconds.
    Returns a dict with score (0-100), tier, event_counts, and contributing_events.
    """
    # Query security_events GSI "pk = IP#{ip}", sk >= (now - window)
    # Weight each event_type: honeypot.hit=50, ssrf.blocked=30, auth.login_failed=2,
    #   ratelimit.exceeded=1, authz.forbidden=5, commerce.price_tamper_rejected=20, ...
    # score = min(100, sum(weights))
    # tier = "critical" if score >= 80 else "high" if >= 60 else "medium" if >= 30 else "low"
    ...

def compute_top_offenders(
    dimension: str,   # "ip" | "asn" | "country" | "actor_sub"
    window_seconds: int = 3600,
    limit: int = 20,
) -> List[dict]:
    """
    Aggregate events across the dimension within the window.
    Returns top-N sorted by total weighted score.
    """
    ...

def get_cached_score(ip: str) -> Optional[dict]:
    """Check in-process cache (TTL 60s) before computing."""
    ...
```

Score weights (calibrated to the event taxonomy from SECOPS-001):

| event_type | weight |
|-----------|-------|
| `honeypot.hit` | 50 |
| `honeytoken.used` | 100 (instant critical) |
| `ssrf.blocked` | 30 |
| `commerce.price_tamper_rejected` | 25 |
| `webhook.signature_invalid` | 20 |
| `authz.forbidden` | 10 |
| `ban.access_after_ban` | 15 |
| `auth.csrf_failed` | 8 |
| `auth.login_failed` | 3 |
| `ratelimit.exceeded` | 1 |
| `netblock.denied` | 0 (blocked source, already controlled) |

Score capped at 100. Cache results in a module-level dict `_score_cache: Dict[str, Tuple[dict, float]]` with 60s TTL.

### 4.2 Alert integration (`app/services/security_alert_dispatch.py` — new file)

A thin layer that deduplicates security alerts before calling into `alerts.py`:

```python
_alert_dedup_cache: Dict[str, float] = {}  # key → last_sent_ts

def dispatch_security_alert(
    event_type: str,
    severity: str,
    ip: str,
    detail: dict,
    dedup_window: int = 300,  # 5 minutes
) -> None:
    dedup_key = f"{event_type}:{ip}"
    now = time.time()
    if now - _alert_dedup_cache.get(dedup_key, 0) < dedup_window:
        return  # deduplicated
    _alert_dedup_cache[dedup_key] = now

    # Find all security admins (users with security scope or root role)
    # Call send_alert(user_sub=admin_sub, event="security_event", details={...})
    for admin_sub in get_security_admin_subs():
        send_alert(admin_sub, "security_event", details={
            "event_type": event_type,
            "severity": severity,
            "ip": ip,
            **detail,
        })
```

Trigger conditions (called from `record_security_event` in SECOPS-001 after writing the event):
- Any `honeypot.hit` or `honeytoken.used` event (immediate)
- Any `severity == "critical"` event
- When a computed threat score crosses 80 (critical threshold) for the first time in the dedup window
- When auto-ban escalates from IP to CIDR or from CIDR to ASN

### 4.3 `app/routers/security_monitoring.py` — new router

All endpoints require `Depends(require_root_session)` or a `require_security_scope` dependency:

```
GET /internal/security/events
    ?event_type=&severity=&ip=&asn=&country=&actor_sub=
    &from_ts=&to_ts=&limit=100&cursor=
    → paginated list of security_events rows (SECOPS-001 table)

GET /internal/security/top-offenders
    ?dimension=ip|asn|country|actor_sub&window_hours=1&limit=20
    → List[{value, score, tier, event_counts}]

GET /internal/security/threat-score/{ip}
    → {ip, score, tier, event_counts, window_seconds, cached}

GET /internal/security/honeypot-feed
    ?limit=50&cursor=
    → recent honeypot.hit + honeytoken.used events

# Block/allowlist management (delegates to SECOPS-002 service)
GET  /internal/security/blocklist?kind=&cursor=
POST /internal/security/blocklist         # {kind, value, action, reason, ttl_seconds?}
DELETE /internal/security/blocklist/{kind}/{value}
GET  /internal/security/allowlist
POST /internal/security/allowlist         # {cidr, reason}
DELETE /internal/security/allowlist/{cidr}

# Metrics snapshot
GET /internal/security/metrics-snapshot
    → {security_events_24h, blocked_sources, honeypot_hits_24h, autoban_actions_24h, top_event_types}
```

Register in `app/main.py` near the other internal/admin routers.

### 4.4 `frontend/src/pages/admin/SecurityMonitoringPage.tsx` — new page

**Layout** (using existing shadcn/ui primitives and `Tabs`, `Table`, `Badge`, `Dialog`):

```
SecurityMonitoringPage
├── Header: "Security Monitoring" + refresh button + last-refresh timestamp
├── KPI row: 4 stat cards
│   ├── Events (24h) [with trend]
│   ├── Blocked Sources [active blocklist count]
│   ├── Honeypot Hits (24h)
│   └── Auto-Ban Actions (24h)
├── Tabs: [Live Events] [Top Offenders] [Block/Allowlist] [Honeypot Feed]
│
│ [Live Events tab]
│   Filter bar: event_type dropdown, severity filter, IP search, time range
│   Table: timestamp | event_type | severity | IP | country | ASN | actor | path
│   Rows clickable → drill-down Dialog with full event JSON
│
│ [Top Offenders tab]
│   Dimension selector: IP / ASN / Country / Actor
│   Table: value | score | tier badge | event breakdown (sparkbar) | last_seen | [Block] button
│   [Block] opens "Add Block" Dialog (kind/value pre-filled)
│
│ [Block/Allowlist tab]
│   Sub-tabs: Blocklist | Allowlist
│   Blocklist table: kind | value | action | reason | source | created_by | expires | hit_count | [Remove]
│   Add form: kind select + value input + action select + reason + TTL optional
│   Allowlist table: CIDR | reason | created_by | [Remove]
│
│ [Honeypot Feed tab]
│   Table: timestamp | event_type | IP | country | trap name | path | [Ban IP now]
│   [Ban IP now] calls POST /internal/security/blocklist with kind=ip
```

**React Query hooks**:
```ts
useQuery(["security", "events", filters], () => getSecurityEvents(filters), { refetchInterval: 15000 })
useQuery(["security", "top-offenders", dimension, windowHours], ...)
useQuery(["security", "blocklist", kind], ...)
useMutation(() => addBlock(...), { onSuccess: () => queryClient.invalidateQueries(["security", "blocklist"]) })
```

**Route**: add `"/admin/security"` to `frontend/src/App.tsx` lazy-loading `SecurityMonitoringPage`. Add to the admin sidebar under a "Security" section (alongside `RiskDashboardPage`, `RateLimitDashboard`).

**Access control**: the page itself should check `user.role === "ROOT" || user.admin_profile?.scopes?.includes("security")` and show a 403 page otherwise. The backend endpoints enforce this independently.

### 4.5 `app/metrics.py` additions

```python
SECURITY_EVENTS_TOTAL = Counter(
    "security_events_total",
    "Security telemetry events",
    ["type", "severity"],
)
NETBLOCKS_ACTIVE = Gauge(
    "netblocks_active",
    "Currently active network block entries",
    ["kind"],  # ip | cidr | asn | country
)
AUTOBAN_ACTIONS_TOTAL = Counter(
    "autoban_actions_total",
    "Auto-ban block insertions by trigger event type",
    ["trigger_event_type", "kind"],
)
HONEYPOT_HITS_TOTAL = Counter(
    "honeypot_hits_total",
    "Honeypot and honeytoken hits",
    ["trap_name"],
)
```

`NETBLOCKS_ACTIVE` is a `Gauge` that is updated after each add/remove blocklist operation. Add helper functions following the pattern of `record_auth_event` at `metrics.py:1076`.

### 4.6 Dev panel (`devtools.html` — port 3001)

Add a "Security Events" section to the Dev Tools app at port 3001 (the standalone dev panel, not gated by auth). It displays:

- Last 20 security events in a simple table (polling `GET /internal/security/events?limit=20` with a dev-only `X-User-Id` override header).
- A "Seed Honeytokens" button calling `POST /internal/dev/honeytokens/seed`.
- A "Clear Security Events" button calling `DELETE /internal/dev/security-events` (wipes DDB Local `security_events` table for test isolation).

These dev-only endpoints are gated by `if not S.dev_mode: raise HTTPException(404)`.

### 4.7 Dev/Prod parity (SECOPS-007)

| Layer | Dev | Prod |
|-------|-----|------|
| `security_events` queries | DDB Local `:8001` | DynamoDB |
| `threat_scoring.py` | Identical code — uses DDB Local query | Same, DynamoDB |
| Alert delivery | Mock/log channel — `send_alert` writes to DDB Local `alerts` table; captured by tests | SES (email) / Slack webhook |
| Prometheus counters | `_NoopMetric` stubs | Real `prometheus_client.Counter/Gauge` |
| Dashboard auth | Cookie-based sessions with root/security scope (same as prod) | Same |
| Dev panel (port 3001) | Active; `S.dev_mode=True` | Not deployed in prod |

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_security_monitoring.py`)

- **Threat score computation**: seed 10 `auth.login_failed` events and 1 `honeypot.hit` for IP `1.2.3.4` within the window; assert `compute_threat_score("1.2.3.4")["score"] >= 55`, `tier == "high"`.
- **Instant critical for honeytoken**: seed one `honeytoken.used`; assert score == 100, tier == "critical".
- **Top offenders**: seed events across 5 IPs; assert `compute_top_offenders("ip", ...)` returns the highest-scoring IP first.
- **Alert dispatch deduplication**: call `dispatch_security_alert("honeypot.hit", "high", "1.2.3.4", {})` twice within dedup window; assert `T.alerts` received only one row.
- **Alert dispatch fires on critical**: seed a `critical` severity event; assert alert row created in `T.alerts`.
- **Monitoring endpoints — 403 for non-root**: send request to `/internal/security/events` with an ADMIN session (non-root, no security scope); assert 403.
- **Monitoring endpoints — 200 for root**: send request with root session; assert paginated response with correct fields.
- **Metrics snapshot endpoint**: assert response contains numeric values for `security_events_24h`, `blocked_sources`, etc.

### 5.2 Playwright E2E (`frontend/e2e/security-monitoring.spec.ts`)

- Log in as root; navigate to `/admin/security`.
- Assert "Security Monitoring" heading visible.
- From another tab, hit `/.env` (honeypot route) as Alice.
- Refresh the security monitoring page; assert at least one `honeypot.hit` event in the Live Events tab with Alice's IP.
- Navigate to Top Offenders tab; assert Alice's IP appears with a non-zero score.
- Click "Block" on Alice's IP; assert block dialog appears; fill in reason; confirm → assert blocklist entry appears in Block/Allowlist tab.
- Navigate to Block/Allowlist tab; remove the block; assert entry disappears.
- Assert that a non-root admin (Charlie) navigating to `/admin/security` sees a 403 or "Access denied" message.

### 5.3 Metrics/observability verification

1. In prod, after deploying: verify `security_events_total` counter appears in Prometheus scrape at `/metrics`.
2. Trigger a honeypot hit; assert `honeypot_hits_total{trap_name="aws_env"}` increments by 1.
3. Add a block entry; assert `netblocks_active{kind="ip"}` gauge increments.
4. Trigger an auto-ban; assert `autoban_actions_total{trigger_event_type="auth.login_failed", kind="ip"}` increments.

### 5.4 Rollout plan

1. Deploy `security_monitoring.py` router and `threat_scoring.py` behind a `SECURITY_MONITORING_ENABLED` flag (default `True`, no-op if no security events yet).
2. Deploy the frontend page behind the root/security scope — it renders an empty state gracefully if no events exist.
3. After SECOPS-001/002/003 are live and generating events, the dashboard populates naturally.
4. Enable alert dispatch only after confirming deduplication is working correctly (validate in staging first).
5. Set Prometheus/Grafana alert thresholds for `security_events_total` spikes.

### 5.5 Risks & open questions

- **DDB query cost for threat scoring**: `compute_threat_score` queries two GSIs (`IP#{ip}` partition on the events table + a time-range filter). At 1,000 IPs/min each needing a score, that's 1,000 GSI queries/min. The 60s in-process cache significantly reduces this, but a large attack from many IPs (distributed botnet) can bypass the cache. Consider a background task that pre-computes scores for the top-50 active IPs every 30s.
- **`get_security_admin_subs()`**: `dispatch_security_alert` needs to find all security admins. This requires a query against the `T.users` or `T.role_audit` table for users with root role or security scope — a relatively expensive scan. Cache the result for 5 minutes.
- **SECOPS-001/002/003 must ship first**: the dashboard is a consumer; if the event stream or blocklist tables don't exist, it renders an empty state. Ship in order: 001 → 002 → 003 → 004.
- **`_alert_dedup_cache` is in-process only**: with multiple uvicorn workers (e.g., in prod non-dev mode), each worker has its own dedup cache. A single IP hitting honeypots rapidly could generate N separate alert emails (one per worker). For a single-worker dev setup this is fine; in prod, replace the in-process cache with a DDB-backed dedup record with a 5-minute TTL.

### 5.6 Effort estimate

**Large** (~12 days, including SECOPS-001/002/003 as sequential prerequisites): 2 days for `threat_scoring.py`; 1 day for `security_alert_dispatch.py`; 1.5 days for `security_monitoring.py` router (all endpoints); 3 days for `SecurityMonitoringPage.tsx` (all tabs, queries, mutations); 1 day for metrics additions; 0.5 day for dev panel; 2 days for tests; 1 day for QA. Parallelizable with SECOPS-003 after SECOPS-001 is done.
