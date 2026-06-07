# SECOPS-006: AbuseIPDB Reporting & Threat-Intel Enrichment — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

SECOPS-006 adds two-way integration with [AbuseIPDB](https://www.abuseipdb.com/), the public IP-abuse reporting service. Outbound: when the platform has verified a source IP as malicious (via honeypot hits, brute-force patterns, or LLM analyst recommendation from SECOPS-005), it reports that IP to AbuseIPDB using the v2 API with mapped category codes and a sanitised comment. Inbound: the service fetches AbuseIPDB's `check` and `blacklist` data to enrich threat-scoring and populate SECOPS-002's blocklist with externally confirmed bad actors. The integration is wrapped as the first concrete implementation of a `ThreatIntelProvider` framework, leaving room for future feeds (Shodan, GreyNoise, etc.). A hard prerequisite is SEC-008 (trusted client IP resolution): reporting a spoofed or NAT-translated private IP to a public database is harmful and irreversible, so the integration must never fire without confirmed real-IP attribution.

- **Type**: feature (new service + provider framework)
- **Priority/Severity**: Medium
- **Status**: Open — no implementation exists
- **Owning area**: Security Operations / Threat Intelligence
- **Affected party**: platform operator (inbound enrichment); third-party IPs and AbuseIPDB community (outbound reports — requires extreme care)
- **Cross-references**: [[SEC-008]] (trusted IP — **hard prereq**), [[SECOPS-001]] (security_events source), [[SECOPS-002]] (blocklist sink), [[SECOPS-004]] (dashboard / human-approval gate), [[SECOPS-005]] (LLM analyst recommendation trigger), [[SECOPS-007]] (dev/prod parity)

---

## 2. Current-State Investigation (what exists today)

### 2.1 GeoIP as a direct analogue

`app/services/geoip.py` is the closest existing example of an external enrichment provider with a dev/prod split. The pattern:

- `lookup_country` (line 24): checks an in-process cache, then delegates to `_lookup_country_uncached`.
- `_lookup_country_uncached` (line 60–68): if `S.geo_maxmind_db_path` is empty (dev), returns `None` (fail-open). In prod, calls `_lookup_maxmind`.
- `set_mock_country` / `get_mock_country` (lines 95–109): test hook that bypasses the lookup entirely for seeded IP/country pairs.
- Settings at `app/core/settings.py:1760–1766`: `geo_blocking_enabled`, `geo_maxmind_db_path`, `geo_cache_ttl_seconds`, `geo_fail_open_dev`.

AbuseIPDB must follow the same structure: a provider interface with a dev mock and a prod real-HTTP implementation, selected by `S.dev_mode` or `S.abuseipdb_mock_enabled`. The GeoIP cache pattern (TTL + max-size LRU eviction, lines 44–57) can be reused verbatim for AbuseIPDB `check` responses.

### 2.2 KMS secret storage — already in place

`ABUSEIPDB_API_KEY` must be stored encrypted at rest. The path is identical to LLM provider keys: `kms_encrypt(api_key)` (`app/core/crypto.py:16`), persisted in DynamoDB, decrypted at call time with `kms_decrypt` (`app/core/crypto.py:22`). In dev, the mock KMS at port 7999 (pointed to by `S.kms_endpoint_url`, read in `app/core/aws_clients.py:90–91`) handles encrypt/decrypt transparently.

### 2.3 Billing mock as rate-limiting / quota analogue

`S.ccbill_mock_enabled` (`app/core/settings.py:310`) defaults to `True` when `DEV_MODE=1`, preventing any real CCBill calls in dev. The AbuseIPDB `abuseipdb_mock_enabled` flag should follow the same default: `os.environ.get("ABUSEIPDB_MOCK_ENABLED", os.environ.get("DEV_MODE", "1"))`.

### 2.4 Alert infrastructure

`app/services/alerts.py:31–43` defines `ALERT_CATEGORIES` including a `"security"` bucket with the `"security_event"` event type. Report confirmations and quota warnings from the AbuseIPDB reporter can feed through `create_alert` with `event="security_event"` and `details={reporter: "abuseipdb", ...}`.

### 2.5 What does NOT exist yet

- No `app/services/threat_intel/` package (will be created by SECOPS-005; SECOPS-006 adds to it)
- No `AbuseIPDBClient` (real or mock)
- No reporting policy engine (allowlist, private-range guard, dedup window, quota tracker)
- No category-code mapper (`our_event_type → abuseipdb_category_code[]`)
- No `abuseipdb_reports` audit DynamoDB table
- No inbound enrichment pipeline feeding SECOPS-002
- No settings fields for the AbuseIPDB integration
- SEC-008 itself (trusted IP resolution) is a separate open ticket

### 2.6 Dev vs. prod today

In dev mode, there are no outbound calls to third-party services for any security function. The existing patterns (geoip `None`-return, ccbill mock, stripe pointing at localhost:12111) all confirm the repo's discipline: the dev stack must run with `--network none` equivalent.

---

## 3. Gap / Threat Analysis

### 3.1 Reporting a spoofed or innocent IP — the primary catastrophic risk

Without SEC-008's verified real-IP logic, `request.client.host` may return an RFC-1918 proxy address, or `X-Forwarded-For` may be attacker-forged. If the system reports `10.0.0.1` or a victim's spoofed IP, AbuseIPDB receives a false report. Because AbuseIPDB reports are **public and semi-permanent**, a false report can:

- Damage the reputation of an innocent IP owner (ISP, CDN, business, home user).
- Trigger AbuseIPDB-based auto-blocks at other organisations using the feed.
- Expose the platform to legal liability in some jurisdictions.
- Cause AbuseIPDB to revoke the platform's reporter API key for abuse of the reporting system.

This is why SEC-008 is a hard prerequisite — the outbound reporter must refuse to fire without a confirmed trusted-IP attribute on the source event.

### 3.2 Comment hygiene failure — PII and internal details leak

AbuseIPDB `comment` fields are **public** by default (visible to any API consumer). A naïve implementation that includes `user_sub`, internal hostname, database IDs, session tokens, or victim email addresses in the comment would expose PII and internal topology to the entire internet.

### 3.3 Re-reporting the same IP — quota exhaustion and spam

The free AbuseIPDB tier allows ~1,000 reports per day. Without a dedup window, a sustained low-and-slow brute-force campaign from a single IP could generate 10,000 events and exhaust the daily quota in minutes, then prevent legitimate high-confidence reports from being filed.

### 3.4 Premature auto-reporting (insufficient confidence)

The human-in-the-loop gate can be bypassed if the `auto_report_honeypot` flag is set too broadly. The only class of events that qualifies for auto-report is a direct canary token access (SECOPS-003) — the equivalent of honeypot-grade certainty with zero false positive rate. All other event types (brute-force login attempts, web crawlers) require human approval because they are probabilistic, not deterministic.

### 3.5 Inbound blacklist poisoning

If the platform ingests AbuseIPDB's bulk blacklist without validation and populates SECOPS-002's blocklist directly, an adversary who has compromised AbuseIPDB's database (or who files mass false reports against a target IP) can cause the platform to block legitimate users. Inbound data must be treated as a **hint** that feeds a scoring signal, not an authoritative block.

### 3.6 Code sites that must change or be created

| File | Change |
|---|---|
| `app/services/threat_intel/abuseipdb.py` | **New** — real AbuseIPDB client |
| `app/services/threat_intel/mock_abuseipdb.py` | **New** — mock client for dev/tests |
| `app/services/threat_intel/base.py` | **New** (shared with SECOPS-005) — abstract `ThreatIntelProvider` |
| `app/services/abuseipdb_reporter.py` | **New** — reporting policy, dedup, quota, audit |
| `app/services/abuseipdb_enricher.py` | **New** — inbound check/blacklist ingestion |
| `app/core/settings.py` | Add 8+ new settings fields |
| `scripts/local-ddb-init.py` | Add `abuseipdb_reports` audit table + `threat_intel_cache` table |
| `app/core/tables.py` | Expose new table handles |

---

## 4. Proposed Design / Fix

### 4.1 Provider interface + factory (SECOPS-007 compliance)

```python
# app/services/threat_intel/base.py (shared with SECOPS-005)
from abc import ABC, abstractmethod
from typing import Any

class ThreatIntelProvider(ABC):
    @abstractmethod
    def report_ip(self, *, ip: str, categories: list[int], comment: str, timestamp: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def check_ip(self, *, ip: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def get_blacklist(self, *, confidence_minimum: int) -> list[dict[str, Any]]:
        ...
```

Factory in `app/services/abuseipdb_reporter.py`:

```python
def _get_abuseipdb_provider() -> ThreatIntelProvider:
    if S.dev_mode or S.abuseipdb_mock_enabled:
        from app.services.threat_intel.mock_abuseipdb import MockAbuseIPDBProvider
        return MockAbuseIPDBProvider()
    from app.services.threat_intel.abuseipdb import AbuseIPDBProvider
    return AbuseIPDBProvider(api_key=_load_api_key())
```

`_load_api_key()` decrypts via `kms_decrypt` following the pattern in `llm_provider_keys.py:159–170`. The key is stored encrypted in DynamoDB under a known `pk/sk` pair; it is **never** logged or returned in any API response.

### 4.2 Reporting policy engine

The `report_ip` entry point in `abuseipdb_reporter.py` enforces, in order:

1. **SEC-008 guard**: the event must have `trusted_ip: True` on its source record. If absent, raise `UntrustedIPError` and log `abuseipdb_report_blocked:reason=untrusted_ip`.
2. **Private/reserved range guard**: parse via `ipaddress` (same approach as `geoip.py:32–38`). RFC-1918, loopback, link-local, documentation, and multicast ranges → hard reject.
3. **Allowlist guard**: `S.abuseipdb_never_report_cidrs` (comma-separated CIDRs) — own infra, CDN egress, partner ranges.
4. **Dedup window**: query `abuseipdb_reports` table with `pk=REPORT#{ip}`, scan for records within `S.abuseipdb_dedup_window_seconds` (default 86400). If found → skip, log `abuseipdb_report_blocked:reason=dedup`.
5. **Quota guard**: atomic counter `abuseipdb_reports#DAILY#{date}` with conditional `ADD 1` and check against `S.abuseipdb_daily_quota` (default 950 — 5% headroom below 1000). If exhausted → enqueue for next day, log `abuseipdb_report_blocked:reason=quota`.
6. **Human-in-the-loop gate** (unless `S.abuseipdb_auto_report_enabled` and event class is `honeypot_canary`): write to `abuseipdb_reports` with `status=pending_approval`. Return early.
7. **Comment sanitisation**: `comment = f"Automated web-application attack detected at {utc_iso}. Category: {category_labels}."` — no IP owner PII, no victim data, no internal hostnames, no tokens. Max 1024 chars.
8. **Category code mapping**: map `our_event_type → [abuseipdb_code]`. E.g. `brute_force_login → [18]`, `web_app_attack → [21]`, `honeypot_hit → [21, 19]`, `port_scan → [14]`, `ssh_brute_force → [22, 18]`. Stored as a config dict, not hardcoded.
9. **Fire and audit**: call provider `report_ip`; write to `abuseipdb_reports` with `status=reported`, `response_id`, `decided_by=auto|manual`, `categories`, `confidence_score` from response.

### 4.3 Comment hygiene enforcement

```python
_SAFE_COMMENT_PATTERN = re.compile(r"^[A-Za-z0-9 .,:()\[\]\-_@/]{0,1024}$")

def _sanitise_comment(raw: str) -> str:
    # Strip anything that is not printable ASCII in the safe class
    safe = re.sub(r"[^\x20-\x7E]", "", raw)
    # Remove anything matching email/token/path patterns
    safe = re.sub(r"\S+@\S+\.\S+", "[EMAIL]", safe)
    safe = re.sub(r"[A-Za-z0-9_\-]{32,}", "[TOKEN]", safe)
    return safe[:1024]
```

A separate unit test asserts that no generated comment ever contains patterns matching `@`, `://`, `/api/`, DynamoDB table names, or 32+ character hex strings.

### 4.4 Inbound enrichment pipeline

`app/services/abuseipdb_enricher.py` implements two inbound paths:

- **`enrich_ip(ip)`**: calls `provider.check_ip(ip=ip)`. Returns `{abuse_confidence_score, country_code, isp, usage_type, is_tor, is_vpn}`. Caches in `threat_intel_cache` DynamoDB table (TTL = `S.abuseipdb_cache_ttl_seconds`, default 3600). The SECOPS-002 blocklist service can call `enrich_ip` during a scoring pass to incorporate external confidence.
- **`sync_blacklist(confidence_minimum=90)`**: calls `provider.get_blacklist(confidence_minimum=90)` (bulk endpoint, max 10,000 entries). Writes IPs with external score ≥ 90 to the SECOPS-002 blocklist table with `source=abuseipdb`, `auto_expires_at = now() + S.abuseipdb_blacklist_ttl_seconds`. Tagged as **hints** (lower weight than directly observed events); does not override a human-approved allowlist entry.

### 4.5 Mock client for dev/tests

`MockAbuseIPDBProvider`:

```python
class MockAbuseIPDBProvider(ThreatIntelProvider):
    def __init__(self, capture: list | None = None, canned_check: dict | None = None):
        self._capture = capture if capture is not None else []
        self._canned_check = canned_check or {"abuseConfidenceScore": 90, "countryCode": "CN", "isp": "Mock ISP"}

    def report_ip(self, *, ip, categories, comment, timestamp):
        self._capture.append({"op": "report", "ip": ip, "categories": categories, "comment": comment})
        return {"data": {"reportId": 99999, "ipAddress": ip, "abuseConfidenceScore": 100}}

    def check_ip(self, *, ip):
        self._capture.append({"op": "check", "ip": ip})
        return {"data": self._canned_check}

    def get_blacklist(self, *, confidence_minimum):
        return {"data": []}
```

In dev mode, no HTTP call to `api.abuseipdb.com` is ever made. `self._capture` allows tests to assert that the correct IP, categories, and sanitised comment were assembled without requiring a network-capable environment.

### 4.6 New settings fields

```python
abuseipdb_enabled: bool = os.environ.get("ABUSEIPDB_ENABLED", "0") not in ("0", "false", "False")
abuseipdb_mock_enabled: bool = os.environ.get("ABUSEIPDB_MOCK_ENABLED", os.environ.get("DEV_MODE", "1")) ...
abuseipdb_api_key_ddb_pk: str = os.environ.get("ABUSEIPDB_API_KEY_DDB_PK", "SYSTEM#abuseipdb_api_key")
abuseipdb_auto_report_enabled: bool = os.environ.get("ABUSEIPDB_AUTO_REPORT", "0") ...
abuseipdb_daily_quota: int = int(os.environ.get("ABUSEIPDB_DAILY_QUOTA", "950"))
abuseipdb_dedup_window_seconds: int = int(os.environ.get("ABUSEIPDB_DEDUP_WINDOW_SECONDS", "86400"))
abuseipdb_cache_ttl_seconds: int = int(os.environ.get("ABUSEIPDB_CACHE_TTL_SECONDS", "3600"))
abuseipdb_blacklist_ttl_seconds: int = int(os.environ.get("ABUSEIPDB_BLACKLIST_TTL_SECONDS", "86400"))
abuseipdb_never_report_cidrs: str = os.environ.get("ABUSEIPDB_NEVER_REPORT_CIDRS", "")
abuseipdb_reports_table_name: str = os.environ.get("ABUSEIPDB_REPORTS_TABLE_NAME", "abuseipdb_reports")
threat_intel_cache_table_name: str = os.environ.get("THREAT_INTEL_CACHE_TABLE_NAME", "threat_intel_cache")
```

### 4.7 DynamoDB tables

`abuseipdb_reports`:

- PK: `REPORT#{ip}`, SK: `TS#{iso_timestamp}`
- GSIs: `status-created_at-index` (for pending approval queue), `date-index` (for daily quota count)
- `attr_types={"created_at": "N"}` required per the CLAUDE.md gotcha on numeric GSI sort keys

`threat_intel_cache`:

- PK: `IP#{ip}`, SK: `SOURCE#abuseipdb`
- TTL attribute: `ttl_epoch` (native DDB TTL expiry)

### 4.8 Alternatives considered

- **Greylisting instead of reporting**: insufficient community benefit and does not protect other AbuseIPDB consumers from known-bad IPs.
- **Always auto-report on any security event**: rejected — false positive rate is too high; single login failures from residential ISPs are normal background noise and should never be reported.
- **Skip the human-approval gate entirely**: rejected — outbound reports to a public third party are irreversible. The human gate exists as a policy control, not a technical limitation.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_abuseipdb_reporter.py`)

All run fully offline with no real AbuseIPDB calls, using `MockAbuseIPDBProvider(capture=[])` and moto for DynamoDB.

| Test case | Expected result |
|---|---|
| `test_verified_malicious_ip_reported` | High-confidence event with `trusted_ip=True`, non-RFC1918, passes dedup → mock `report_ip` called once with correct category codes and sanitised comment |
| `test_private_ip_never_reported` | Source `10.0.0.1` → `UntrustedIPError`; zero mock calls |
| `test_allowlisted_ip_never_reported` | IP in `ABUSEIPDB_NEVER_REPORT_CIDRS` → blocked; zero mock calls |
| `test_untrusted_ip_never_reported` | Source event with `trusted_ip=False` (SEC-008 not yet resolved) → blocked |
| `test_dedup_suppresses_rereport` | First report succeeds; second report same IP within 24 h → blocked with `reason=dedup`; mock called once total |
| `test_quota_exhaustion_queues` | Counter at 950 → no `report_ip` call; record written with `status=queued_next_day` |
| `test_comment_contains_no_pii` | Comment generated for a real event → regex confirms no email, no 32+ hex token, no internal hostname pattern |
| `test_comment_contains_no_secrets` | Mock API key injected into a test event details dict → comment does not contain the key substring |
| `test_auto_report_honeypot_fires_without_approval` | `S.abuseipdb_auto_report_enabled=True`, event class `honeypot_canary` → direct `report_ip` call, no pending-approval record |
| `test_non_honeypot_queued_for_approval` | `abuseipdb_auto_report_enabled=True` but event class `brute_force_login` → pending_approval record, no direct call |
| `test_mock_provider_in_dev_mode` | `S.dev_mode=True` → factory returns `MockAbuseIPDBProvider`; no `httpx`/`requests` call |
| `test_check_ip_enriches_scoring` | `enrich_ip("1.2.3.4")` → returns `{abuse_confidence_score: 90, ...}` from mock; result cached in `threat_intel_cache` table |
| `test_blacklist_sync_populates_blocklist` | `sync_blacklist(90)` → mock returns 3 IPs; all three appear in SECOPS-002 blocklist table with `source=abuseipdb` |
| `test_inbound_hint_does_not_override_allowlist` | IP on allowlist + inbound blacklist entry → allowlist wins |

### 5.2 Playwright E2E (`frontend/e2e/secops-abuseipdb.spec.ts`)

Uses `S.dev_mode=True` with mock provider and `capture` list inspected via an internal inspection endpoint.

- Seed a verified-malicious event; call batch reporter trigger; assert `abuseipdb_reports` shows one `status=pending_approval` record in the SECOPS-004 dashboard.
- Operator approves → assert `status=reported` in audit table; mock capture list shows exactly one `report_ip` call with the expected IP.
- Seed a private-IP event; assert no record created, warning log emitted.
- Trigger blacklist sync; assert three IPs appear in the blocklist admin API with `source=abuseipdb`.

### 5.3 Manual / QA steps

1. `ABUSEIPDB_ENABLED=1 ABUSEIPDB_MOCK_ENABLED=1 just restart`
2. Seed a honeypot-hit event via the dev event seeder.
3. Confirm event appears in SECOPS-004 dashboard queue with `decided_by=pending`.
4. Approve via dashboard; confirm `abuseipdb_reports` record shows `status=reported`.
5. Check backend log for `abuseipdb_report_submitted ip=... categories=...` (mock mode — no real call).
6. Toggle `ABUSEIPDB_MOCK_ENABLED=0` in a staging environment with a real test API key; repeat step 2–4 with a throwaway test IP known to AbuseIPDB (their docs provide test IPs); confirm real `reportId` in response.

### 5.4 Observability

Structured log lines: `abuseipdb_report_submitted`, `abuseipdb_report_blocked` (with `reason`), `abuseipdb_quota_warning`, `abuseipdb_check_enriched`, `abuseipdb_blacklist_synced`. Counter metrics: `abuseipdb_reports_total{status}`, `abuseipdb_checks_total`, `abuseipdb_blacklist_ips_synced`. Alert when daily quota > 80% consumed.

### 5.5 Rollback plan

`ABUSEIPDB_ENABLED=0` disables all outbound and inbound operations instantly. The `abuseipdb_reports` and `threat_intel_cache` tables persist; no data is lost. Existing SECOPS-002 blocklist entries written with `source=abuseipdb` continue to be enforced until their TTL expires (they can be mass-deleted via a one-time scan if needed).

### 5.6 Prod readiness checklist

- SEC-008 trusted IP logic deployed and verified.
- `ABUSEIPDB_API_KEY` stored as KMS-encrypted DDB record (not in `.env`).
- `ABUSEIPDB_ENABLED=1`, `ABUSEIPDB_MOCK_ENABLED=0` in prod `.env`.
- `ABUSEIPDB_NEVER_REPORT_CIDRS` populated with own egress IPs, CDN ranges, partner ranges.
- `ABUSEIPDB_AUTO_REPORT=0` initially — enable only after one sprint of observation in approval-queue mode.
- MaxMind GeoIP/ASN DB present at `GEO_MAXMIND_DB_PATH` (for country/ISP enrichment to cross-validate inbound data).

### 5.7 Effort estimate and implementation order

**Total: M (medium)**

1. (S) Shared `ThreatIntelProvider` base class in `app/services/threat_intel/base.py` (may be done with SECOPS-005).
2. (S) Add settings fields; add `abuseipdb_reports` + `threat_intel_cache` DDB tables.
3. (M) `MockAbuseIPDBProvider` + `AbuseIPDBProvider` (real HTTP client using `httpx`, timeout=10s, retry=2).
4. (M) `abuseipdb_reporter.py` — full policy engine (SEC-008 guard, private-range check, allowlist, dedup, quota, sanitiser, category mapper, audit).
5. (S) `abuseipdb_enricher.py` — `check_ip` + `sync_blacklist` with SECOPS-002 write-through.
6. (M) pytest unit tests (all offline).
7. (S) Playwright E2E spec (requires SECOPS-004 dashboard queue UI).

---

## Second-pass verification (2026-06-05)

- [Confirmed] `geoip.py:lookup_country` at line 24 — `app/services/geoip.py:24`
- [Confirmed] `_lookup_country_uncached` at lines 60–68 — `app/services/geoip.py:60–68`
- [Corrected] Cache pattern cited as "lines 44–57": cache TTL/max setup actually begins at line 41 (`cache_ttl = getattr(...)`); cache write is at line 56. Correct range is lines 41–56. — `app/services/geoip.py:41–56`
- [Confirmed] `set_mock_country` / `get_mock_country` at lines 95–109 — `app/services/geoip.py:95`, `app/services/geoip.py:107`
- [Corrected] Settings cited as "lines 1760–1766": line 1760 is the comment `# Geo-blocking (GEO-001)`, not a setting field. The four geo settings (`geo_blocking_enabled`, `geo_maxmind_db_path`, `geo_cache_ttl_seconds`, `geo_cache_max_size`) begin at line 1761. Correct range is lines 1761–1766. — `app/core/settings.py:1761–1766`
- [Confirmed] `kms_encrypt` at `app/core/crypto.py:16`, `kms_decrypt` at `app/core/crypto.py:22`
- [Confirmed] `S.kms_endpoint_url` read in `app/core/aws_clients.py:90–91` (`_kms_endpoint_url` function)
- [Confirmed] `alerts.py:31–43` defines `ALERT_CATEGORIES` including `"security"` bucket with `"security_event"` — `app/services/alerts.py:31–43`
- [Confirmed] `write_alert` at `app/services/alerts.py:355`
- [Confirmed] `ccbill_mock_enabled` at `app/core/settings.py:310`
- [Confirmed] `llm_provider_keys.py:159–170` for `get_decrypted_api_key` with `kms_decrypt` — `app/services/llm_provider_keys.py:159–170`
- [Confirmed] No `app/services/threat_intel/` package, no `AbuseIPDBClient`, no `abuseipdb_reports` table, no `threat_intel_cache` table, no AbuseIPDB settings fields — all "does not exist yet" claims hold
