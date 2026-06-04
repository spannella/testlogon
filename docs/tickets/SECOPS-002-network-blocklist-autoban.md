# SECOPS-002: Network Blocklist & Auto-Ban Engine (IP / CIDR / ASN / Geo)

**Ticket**: SECOPS-002 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Theme**: Security Detection & Response. **Hard prereq**: SEC-008 (trusted client IP) —
without it, attackers spoof `X-Forwarded-For` to evade blocks or get *others* blocked.
**Consumes**: SECOPS-001 events. **Reuses**: `app/services/geoip.py`.

## Goal
Enforce blocking of malicious sources by **individual IP, CIDR range, ASN
(datacenter/hosting providers), and GeoLocation (country)**, both manual and automatic.

## Design
- **Store**: `app/services/security_blocklist.py` + DynamoDB `security_blocklist`
  table. Entry kinds: `ip`, `cidr`, `asn`, `country`; fields: value, action
  (block | tarpit | challenge), reason, source (manual/auto), created_by, **TTL**
  (temp bans) or permanent, hit_count. Plus an **allowlist** (never-block: office IPs,
  partners, health-check probes) checked first.
- **ASN support**: extend `geoip.py` with a **GeoLite2-ASN** reader → `lookup_asn(ip)`
  returning `(asn, org)`; seed a curated **datacenter/hosting ASN list** (AWS/GCP/Azure/
  OVH/Hetzner/DigitalOcean/etc.) so "block datacenters" is one toggle while real users
  on residential ISPs pass.
- **Enforcement middleware**: register a `security_block_middleware` **early** in the
  `app/main.py` chain (after trusted-IP resolution, before routers — note the
  security-headers middleware is currently unregistered per SEC-016, fix alongside).
  Resolve client IP → check allowlist → check ip/cidr/asn/country blocklists →
  on match: emit `netblock.denied` (SECOPS-001), return **403** (or tarpit slow-roll /
  challenge), increment hit_count. Re-resolve hostname→IP to be DNS-rebinding-safe.
  Reuse the existing country path (`geo_check`/`geo_platform_block_countries`) but
  generalize from per-content geofencing to a global managed deny/allow list.
- **Auto-ban engine**: a consumer of SECOPS-001 events with threshold rules
  (e.g. `>N auth.login_failed/IP/10min`, any `honeypot.hit`, `>M ssrf.blocked`) →
  insert a TTL block with escalation: IP → /24 CIDR → ASN if abuse continues; decay/
  expire automatically; cooldown before permanent.
- **Admin API + UI**: list/add/remove/expire blocks + allowlist, see hit counts,
  manual ban with reason+TTL (UI in SECOPS-004).
- **Compliance**: geoblocking has legal implications (sanctions vs. arbitrary
  country bans) — make country rules explicit/audited; fail-open in dev
  (`geo_fail_open_dev` already exists).

## Testing
pytest: a blocked IP/CIDR/ASN/country → 403 + `netblock.denied`; allowlisted source is
never blocked even if it matches; spoofed XFF cannot evade (uses trusted IP); auto-ban
fires after threshold and expires via TTL; escalation IP→/24→ASN.

---
**Dev/Prod parity**: must satisfy [SECOPS-007](SECOPS-007-dev-prod-parity-aws-abstraction.md) — runs in dev with no AWS/offline (mock backend) and in prod on AWS, same code path, backend chosen by flag.
