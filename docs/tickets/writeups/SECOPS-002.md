# SECOPS-002: Network Blocklist & Auto-Ban Engine — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

SECOPS-002 builds an active enforcement layer that stops malicious traffic at the network edge before it reaches any router. It complements SECOPS-001 (detection) with SECOPS-002 (prevention): a DynamoDB-backed blocklist covering individual IPs, CIDR ranges, Autonomous Systems (ASNs), and GeoLocation countries; a corresponding allowlist that always overrides the blocklist; a FastAPI middleware registered early in the `app/main.py` chain to enforce blocks on every request; and an auto-ban engine that consumes SECOPS-001 events and automatically inserts TTL-limited block entries when threshold rules fire (e.g., more than N `auth.login_failed` events from one IP in a rolling window).

- **Type**: security hardening / infra
- **Priority**: High
- **Status**: Open
- **Attacker class**: 🌐 any-user — applies to all traffic, including unauthenticated
- **Hard prerequisite**: SEC-008 (trusted client IP). Without it, XFF spoofing lets attackers both evade blocks (claim an allowlisted IP) and get legitimate users falsely blocked (forge another user's IP). This is non-negotiable.
- **Consumes**: SECOPS-001 event stream.
- **Reuses**: `app/services/geoip.py` country lookup + new ASN lookup (added for SECOPS-001), `app/services/geo_check.py` pattern, `app/core/normalize.py` `ip_in_any_cidr()` and `normalize_cidr()`.
- **Cross-references**: SECOPS-004 (admin UI for manage/view blocks), SECOPS-007 (dev/prod parity).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Existing geo-blocking infrastructure

The platform already has a per-content geo-access enforcement path:

- `app/services/geoip.py:24` — `lookup_country(ip)` with a TTL cache (`geo_cache_ttl_seconds`, max `geo_cache_max_size` — `geoip.py:41–42`), falling back to `None` in dev without a MaxMind DB path.
- `app/services/geo_check.py:23` — `check_geo_access(request, geo_mode, geo_countries)` applies a platform-level block list from `S.geo_platform_block_countries` (a comma-separated env var, `geo_check.py:53`) then per-content rules. **This is content-scoped and called explicitly by video/broadcast/catalog routers** — it is not a global middleware.
- `app/routers/geo_rules.py:33` — CRUD endpoints for per-content geo restrictions (`/ui/geo/videos/{id}`, `/ui/geo/broadcasts/{id}`, `/ui/geo/catalog/{id}`), plus `GET /ui/geo/my-country` and `GET /ui/geo/check` dry-run.
- `app/core/normalize.py:43–64` — `normalize_cidr(s)` (validates/normalizes CIDR notation) and `ip_in_any_cidr(ip_str, cidrs)` (membership check). Both are already production-quality and can be reused directly.

### 2.2 Rate-limit store — closest existing pattern for blocklist enforcement

`app/services/rate_limit_store.py:26` — `check_rate_limit(pk, window_seconds, max_requests)` returns `(allowed, remaining, reset_timestamp)`. It uses DDB conditional updates with atomic increment. The blocklist check is simpler (a DDB `get_item` against a known PK), but the event-log pattern from `app/services/rate_limit_dashboard.py:23` (`log_rate_limit_event`) is the right model for how to record `netblock.denied` events.

### 2.3 Middleware chain (current registration order in `app/main.py`)

`app/main.py:412–420`:

```
CORSMiddleware               # outermost
TenantMiddleware             # if multi_tenancy_enabled
rate_limit_middleware_factory()
_api_usage_metering_middleware()
_playback_entitlement_middleware()
metrics_middleware           # if METRICS_ENABLED
```

`_security_headers_middleware` is defined at `main.py:348` but **never registered** (SEC-016). The new `security_block_middleware` must be registered before `rate_limit_middleware_factory()` — it needs to run early so blocked sources never reach rate-limit accounting or router logic. However, it must run **after** trusted-IP resolution (SEC-008). The correct insertion point is immediately after CORS and Tenant middleware, before the rate-limit middleware.

### 2.4 Admin blocklist — `RateLimitDashboard.tsx`

`frontend/src/pages/admin/RateLimitDashboard.tsx:1–14` already imports `getBlocklist`, `addToBlocklist`, `removeFromBlocklist`, `addToAllowlist`, `removeFromAllowlist` from `@/api/endpoints/adminRateLimits`. These are currently wired to the **rate-limit** blocklist (IP-only, for rate-limit enforcement). SECOPS-002 needs a broader security blocklist (IP + CIDR + ASN + country) accessible from a security monitoring page (SECOPS-004). The existing UI components (`Table`, `Badge`, `Dialog`, `Tabs`) can be directly reused.

### 2.5 `S.trusted_proxy_cidrs` — defined but unused

`app/core/settings.py:32` defines `trusted_proxy_cidrs: str = os.environ.get("TRUSTED_PROXY_CIDRS", "")`. This field exists precisely for SEC-008-style trusted IP resolution but is not yet consumed by any code path. The `security_block_middleware` must use the SEC-008 implementation — do not read `trusted_proxy_cidrs` directly in the new middleware; rely on the `trusted_client_ip_from_request(request)` function that SEC-008 will deliver.

### 2.6 GeoIP — no ASN lookup today

`geoip.py` has no `lookup_asn`. SECOPS-001 adds it (GeoLite2-ASN reader). SECOPS-002 depends on it being in place for ASN-level blocks. If SECOPS-001 ships first, SECOPS-002 can call `lookup_asn` from `geoip.py`. If they ship together, the ASN extension belongs in the SECOPS-001 batch.

### 2.7 Dev/test geo overrides

`geoip.py:95–109` provides `set_mock_country(ip, country_code)` and `get_mock_country(ip)` for E2E tests. The same pattern (`set_mock_asn(ip, asn, org)`) must be added for ASN override. The `X-Geo-Country` header override in `geo_check.py:41–44` works in `S.dev_mode` for UI-level testing.

---

## 3. Gap / Threat Analysis

### 3.1 No global network-level enforcement today

`geo_check.py`'s `check_geo_access` is called **only where authors remember to call it** — video endpoints, broadcast, catalog. A brute-force attacker hammering `/ui/session/login`, `/ui/mfa`, or any API endpoint from a sanctioned country is never geo-blocked globally. A known-bad IP (e.g., from a previous incident) has no persistent block.

### 3.2 Manual IP blocks have no persistence

Today an operator wanting to block an IP must either (a) configure a network-level ACL outside the application (e.g., AWS WAF, Security Group) — manual, no audit trail in the app — or (b) edit `TRUSTED_PROXY_CIDRS` env var as a workaround. Neither approach is manageable at scale or auditable within the platform.

### 3.3 XFF spoofing enables block evasion and false-blocking

Without SEC-008's trusted-proxy chain validation, the middleware's IP resolution is trivially evaded:
- **Evasion**: attacker sends `X-Forwarded-For: <allowlisted-office-IP>` → allowlist check matches → block skipped.
- **False block**: attacker sends `X-Forwarded-For: <victim-user-IP>` → block check fires → victim's real IP gets blocked.

### 3.4 ASN-level attacks from datacenter ranges

Many credential-stuffing and scraping campaigns originate from cloud/hosting ASNs (AWS EC2 public IPs, DigitalOcean droplets, OVH servers). A "block all datacenter traffic" toggle — matching against a curated ASN seed list — dramatically reduces the attack surface for credential stuffing with zero false-positives for real users (who are on residential/mobile ISPs). This capability does not exist today.

### 3.5 Auto-ban threshold rules need to be stateful

Threshold-based auto-ban ("block IP after 20 failed logins in 5 min") requires a sliding-window aggregation over the SECOPS-001 event stream. Today `rate_limit.py`'s `record_login_anomaly` (`rate_limit.py:100`) tracks per-user and per-IP-prefix login spreads using the `sessions` table, but it does not write to a blocklist and cannot escalate from IP to /24 CIDR to ASN.

### 3.6 Compliance: country blocks require explicit audit

Country-level blocking has legal implications (sanctions compliance requires blocking specific countries; arbitrary country bans may violate anti-discrimination laws in some jurisdictions). Every country block must carry `reason`, `created_by` (operator sub), and `created_at` and be retrievable via an audit endpoint. Permanent country blocks should require root-level authorization.

---

## 4. Proposed Design / Fix

### 4.1 `app/services/security_blocklist.py` — new file

Implements the blocklist/allowlist CRUD and lookup logic.

```python
BlocklistEntry = TypedDict("BlocklistEntry", {
    "pk": str,           # "BLOCK#ip", "BLOCK#cidr", "BLOCK#asn", "BLOCK#country"
    "sk": str,           # "ENTRY" (single record per value)
    "kind": str,         # "ip" | "cidr" | "asn" | "country"
    "value": str,        # normalized: IP address, "1.2.3.0/24", "AS14061", "CN"
    "action": str,       # "block" | "tarpit" | "challenge"
    "reason": str,
    "source": str,       # "manual" | "auto_ban" | "abuseipdb"
    "created_by": str,   # actor_sub or "system"
    "created_at": int,
    "expires_at": int,   # 0 = permanent
    "ttl_epoch": int,    # DDB TTL; = expires_at if temp, else 0 (no TTL)
    "hit_count": int,
})

def check_blocked(ip: str, asn: Optional[str], country: Optional[str]) -> Optional[BlocklistEntry]:
    """Return the matching block entry, or None if not blocked.
    Check order: allowlist first, then ip → cidr → asn → country.
    """

def is_allowlisted(ip: str) -> bool:
    """Check if IP is in the allowlist (never block)."""

def add_block(kind, value, action, reason, source, created_by, ttl_seconds=None) -> BlocklistEntry:
def remove_block(kind, value) -> bool:
def increment_hit_count(pk, sk) -> None:  # fire-and-forget
def list_blocks(kind=None, limit=100, cursor=None) -> (List[BlocklistEntry], Optional[str]):
def add_allowlist(cidr, reason, created_by) -> None:
def list_allowlist() -> List[dict]:
def remove_allowlist(cidr) -> bool:
```

The `check_blocked` function must execute in a minimal number of DDB calls. Optimal path: one `get_item` for the specific IP (PK = `BLOCK#ip#{ip}`), one for each CIDR in a local CIDR-set cache (refreshed every 60s), one `get_item` for the ASN, one `get_item` for the country. The CIDR membership test uses `ip_in_any_cidr` from `normalize.py:53`. A local in-process cache of active CIDR blocks (refreshed on miss or TTL) keeps hot-path latency under 1ms.

### 4.2 DynamoDB table: `security_blocklist`

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    name="security_blocklist",
    pk="pk",   # "BLOCK#{kind}#{value}" or "ALLOW#{cidr}"
    sk="sk",   # "ENTRY"
    ttl_attribute="ttl_epoch",
    gsis=[
        GSIDef("kind-index",       pk="kind",       sk="created_at"),
        GSIDef("source-index",     pk="source",     sk="created_at"),
        GSIDef("created_by-index", pk="created_by", sk="created_at"),
    ],
    attr_types={
        "pk": "S", "sk": "S",
        "kind": "S", "source": "S", "created_by": "S",
        "created_at": "N",
    },
)
```

Add `security_blocklist: Any` to `app/core/tables.py:Tables` dataclass and `security_blocklist_table_name: str` to `app/core/settings.py`.

### 4.3 `security_block_middleware` — new middleware

```python
async def security_block_middleware(request: Request, call_next):
    ip = trusted_client_ip_from_request(request)  # SEC-008
    if is_allowlisted(ip):
        return await call_next(request)

    asn, _ = lookup_asn(ip)      # from geoip.py (SECOPS-001 addition)
    country = lookup_country(ip) # from geoip.py

    entry = check_blocked(ip, asn, country)
    if entry:
        increment_hit_count(entry["pk"], entry["sk"])
        record_security_event("netblock.denied", "medium",
            request=request, detail={"kind": entry["kind"], "value": entry["value"], "action": entry["action"]})
        if entry["action"] == "tarpit":
            await asyncio.sleep(5)  # slow-roll
        return JSONResponse(status_code=403, content={"detail": {"code": "blocked", "message": "Access denied."}})

    return await call_next(request)
```

Register in `app/main.py` after CORS/Tenant, before rate_limit:

```python
app.middleware("http")(security_block_middleware)
app.middleware("http")(rate_limit_middleware_factory())
```

Because FastAPI middleware is LIFO, adding `security_block_middleware` **after** `rate_limit_middleware_factory()` in code means it runs **before** rate-limit in the actual request path. Verify ordering with a test that asserts a blocked IP receives 403 and no rate-limit event is recorded.

### 4.4 Auto-ban engine: `app/services/auto_ban.py`

A consumer function called from `record_security_event` (or from a periodic background task):

```python
def evaluate_auto_ban(event: dict) -> None:
    """
    Called after each security event write. Checks threshold rules.
    If threshold exceeded, calls add_block(..., source="auto_ban", ttl_seconds=...).
    """
    rules = [
        ("auth.login_failed",        "ip",  20, 300,  3600),   # 20 failures/5min → 1hr block
        ("honeypot.hit",             "ip",   1,   0,  86400),  # any hit → 24hr block
        ("ssrf.blocked",             "ip",   3, 300,  7200),
        ("auth.csrf_failed",         "ip",  10, 300,  3600),
        ("commerce.price_tamper_rejected", "ip", 5, 600, 14400),
    ]
```

Uses a sliding-window counter stored in `T.security_events` itself — query `GSI event_type-index` with a `KeyConditionExpression` on `event_type` and `sk BETWEEN now-window AND now`, filter by `ip = <target>`, count results. If count ≥ threshold, call `add_block(...)`.

Escalation: if auto-ban for the same `/24` CIDR fires three times, add a CIDR block for the prefix. If the same ASN triggers five IP-level auto-bans within 24 hours, add an ASN block.

Decay: all auto-ban entries are TTL-limited (never permanent). A "graduated block" pattern: first offense → 1hr; second offense (within 7 days) → 24hr; third → 7 days. Store `offense_count` in the blocklist entry.

### 4.5 Curated datacenter/hosting ASN seed list

A static file `app/services/datacenter_asns.py` containing a `DATACENTER_ASNS: frozenset[str]` with major hosting provider ASNs (AWS = AS16509/14618, GCP = AS15169, Azure = AS8075, DigitalOcean = AS14061, Hetzner = AS24940/213230, OVH = AS16276, Linode/Akamai = AS63949, Vultr = AS20473, etc.). A settings flag `S.block_datacenter_asns: bool` (default `False`) triggers auto-insertion of these ASNs into the blocklist as `kind="asn"`, `source="datacenter_seed"`, `action="block"`, permanent. When the flag is toggled on, a startup task inserts missing entries; toggle off removes `source="datacenter_seed"` entries.

### 4.6 Admin API endpoints (`app/routers/security_blocklist.py`)

Requires `Depends(require_root_session)` for all write endpoints:

```
GET  /internal/security/blocklist?kind=&cursor=&limit=
POST /internal/security/blocklist          # add_block
DELETE /internal/security/blocklist/{kind}/{value}  # remove_block
GET  /internal/security/allowlist
POST /internal/security/allowlist
DELETE /internal/security/allowlist/{cidr}
POST /internal/security/auto-ban/evaluate  # manual trigger
```

For SECOPS-004 dashboard integration.

### 4.7 Dev/Prod parity (SECOPS-007)

| Layer | Dev | Prod |
|-------|-----|------|
| Blocklist store | DDB Local `:8001` via `T.security_blocklist` | DynamoDB |
| ASN lookup | `set_mock_asn` / return `(None, None)` | GeoLite2 ASN DB |
| Country lookup | `set_mock_country` / `None` | GeoLite2 Country DB |
| Middleware execution | Identical — runs for every request in dev and prod | Same |
| Auto-ban | Same code, fires immediately in test | Same |
| `S.block_datacenter_asns` | Default `False` (dev should not block datacenter ranges) | Operator choice |

A `SECURITY_BLOCKLIST_ENABLED: bool` setting (default `True`) allows the middleware to be compiled in but disabled globally for an emergency rollback without a code deploy.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_security_blocklist.py`)

- **IP block**: seed a `BLOCK#ip#1.2.3.4` entry, send a request with `X-Forwarded-For: 1.2.3.4` (after SEC-008), assert middleware returns 403 and emits `netblock.denied`.
- **CIDR block**: seed `BLOCK#cidr#1.2.3.0/24`, test `1.2.3.200` → blocked, `1.2.4.1` → not blocked.
- **ASN block**: seed `BLOCK#asn#AS14061`, mock `lookup_asn("5.6.7.8") = (14061, "DIGITALOCEAN")`, assert 403.
- **Country block**: seed `BLOCK#country#CN`, mock `lookup_country("...") = "CN"`, assert 403.
- **Allowlist overrides block**: add allowlist CIDR that contains the blocked IP → assert 200.
- **XFF cannot evade with spoofed IP** (after SEC-008): request without a trusted proxy cannot inject XFF → uses `req.client.host`.
- **Auto-ban fires**: call `evaluate_auto_ban` 20 times with `auth.login_failed` from the same IP within a 5-min window; assert `check_blocked(ip)` returns a block entry.
- **Auto-ban escalation**: simulate 3 auto-ban triggers for IPs in the same /24; assert CIDR block added.
- **TTL decay**: assert auto-ban entry has `ttl_epoch` set; simulate time advancing past TTL; assert `check_blocked` returns None.
- **Datacenter ASN seed**: set `S.block_datacenter_asns = True`, call startup seeder; assert `BLOCK#asn#AS14061` exists.

### 5.2 Playwright E2E (`frontend/e2e/security-blocklist.spec.ts`)

- Use root session to `POST /internal/security/blocklist` adding Alice's IP as a block.
- Attempt Alice login → assert 403 with `code: "blocked"`.
- Remove block → assert Alice can log in again.
- Add country block for `XX` (nonexistent ISO code); confirm it does not affect test users.

### 5.3 Rollout plan

1. Deploy with `SECURITY_BLOCKLIST_ENABLED=false` — middleware loaded but immediately passes all requests through.
2. Enable: `SECURITY_BLOCKLIST_ENABLED=true` + `TRUSTED_PROXY_CIDRS=<load-balancer-CIDRs>` (SEC-008).
3. Seed allowlist with office CIDRs, health-check probe IPs, partner CIDRs.
4. Enable auto-ban rules one at a time, monitoring for false-positive blocks.
5. Enable `block_datacenter_asns` only after validating all legitimate API partners are on the allowlist.

### 5.4 Risks & open questions

- **CIDR scan DDB cost**: checking hundreds of active CIDR blocks per request is O(N) DDB reads without caching. The local in-process CIDR-set cache is critical; refresh interval (60s) must be tunable (`BLOCKLIST_CIDR_CACHE_TTL_SECONDS`).
- **Cold-start CIDR cache**: first request after deploy reads all CIDR blocks from DDB. Add a warm-up step in `app/main.py`'s startup event.
- **SEC-008 is a hard prerequisite**: shipping SECOPS-002 without SEC-008 is dangerous — it provides false confidence in the block enforcement. Ship them together or gate SECOPS-002 on SEC-008 completion.
- **Tarpit async sleep in middleware**: `asyncio.sleep(5)` holds the uvicorn worker's event loop slot for 5 seconds per tarpitted request. Under a high-volume attack this starves legitimate requests. Consider returning a 429 with a `Retry-After: 5` header instead, or off-loading tarpit logic to a queue.
- **Country block legal review**: require legal sign-off before enabling any country block in production. The code should enforce that country blocks are logged with a `legal_basis` field.

### 5.5 Effort estimate

**Large** (~10 days): 2 days for `security_blocklist.py` + table + settings; 1.5 days for middleware + `main.py` registration; 2 days for auto-ban engine with escalation/decay; 1 day for datacenter ASN seed list; 1 day for admin API router; 1.5 days for tests; 1 day for frontend wiring (SECOPS-004). Sequential on: SEC-008 (~3 days), SECOPS-001 ASN extension (~1 day).
