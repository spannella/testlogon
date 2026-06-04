# SECOPS-006: AbuseIPDB Reporting & Threat-Intel Enrichment

**Ticket**: SECOPS-006 · **Status**: Open · **Priority**: Medium · **Date**: 2026-06-04
**Theme**: Security Detection & Response.
**Hard prereq**: SEC-008 (trusted client IP) — reporting a spoofed/innocent IP to
AbuseIPDB is harmful and hard to undo. **Consumes**: SECOPS-001/005; **feeds**: SECOPS-002.

## Goal
Two-way AbuseIPDB integration: **report** confirmed-malicious IPs outbound, and
**enrich/ingest** their intelligence to strengthen our own blocking — built as a small
threat-intel provider framework so other feeds can plug in later.

## Design
- **Client** (`app/services/threat_intel/abuseipdb.py`):
  - **Report**: `POST /api/v2/report` with `ip`, AbuseIPDB **category codes**
    (e.g. 18 brute-force, 21 web app attack, 14 port scan, 19 bad web bot, 16 SSH),
    `comment`, `timestamp`. Map our event taxonomy → categories.
  - **Enrich**: `GET /api/v2/check` (abuse confidence score, country, ISP, usage type
    incl. **datacenter/hosting**) and `GET /api/v2/blacklist` (bulk high-confidence
    list) to feed SECOPS-002's ASN/IP blocklists and SECOPS-005's scoring.
- **Reporting policy** (critical, to protect innocents and our reporter standing):
  - Only report **high-confidence, verified-malicious, trusted-IP** sources — never on
    a single ambiguous event; honeypot hits and repeated verified attacks qualify.
  - **Allowlist + private/reserved-range guard**: never report RFC-1918/loopback,
    our own infra, partners, or allowlisted IPs.
  - **Dedup/throttle**: don't re-report the same IP within a window; respect the daily
    API quota (free tier ~1000/day) with a queue + backoff.
  - **Comment hygiene**: no victim PII, no secrets/tokens, no internal hostnames — a
    generic factual description ("automated web-app attack / honeypot hit at <utc>").
  - Default **human-in-the-loop approval** (from the SECOPS-004 dashboard) for outbound
    reports; an "auto-report honeypot hits" toggle for the highest-certainty class.
- **Config/secrets**: `ABUSEIPDB_API_KEY` via settings (KMS/secret, never logged);
  `ABUSEIPDB_ENABLED`, `ABUSEIPDB_AUTO_REPORT` flags; dev-mode uses a mock client
  (no real outbound calls in tests/E2E).
- **Audit**: every report logged (ip, categories, decided_by manual|llm, response id);
  store AbuseIPDB's returned confidence for the IP.

## Testing
pytest (mock AbuseIPDB): a verified-malicious trusted IP is reported with correct
categories + sanitized comment; a private/allowlisted/spoofed-XFF IP is **never**
reported; dedup suppresses re-reports; quota exhaustion queues+backs off; `check`/
`blacklist` results enrich the blocklist; no secret/PII appears in any payload; outbound
disabled in dev unless explicitly enabled.
