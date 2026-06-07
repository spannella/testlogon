# SECOPS-001: Unified Security-Event Telemetry Pipeline

**Ticket**: SECOPS-001 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Theme**: Security Detection & Response. Foundation for SECOPS-002/003/004.
**Prereq**: SEC-008 (trusted client IP) — accurate attribution depends on a
non-spoofable client IP.

## Goal
One choke-point emitter that records every *suspicious* event identified in the audit
(and future detections) as a structured, enriched, queryable record we can monitor,
alert on, and feed to the auto-ban engine. Distinct from the existing per-domain
`audit_event` (business audit) and `metrics.py` (counters) — this is an attack-telemetry
stream.

## Design
- **Emitter**: `app/services/security_events.py` →
  `record_security_event(event_type, severity, request=None, actor_sub=None, target=None,
  detail=None)`. Severity = info/low/medium/high/critical.
- **Enrichment** (auto): trusted client IP (`client_ip_from_request` post-SEC-008),
  **ASN + org** and **country** (extend `app/services/geoip.py` — add a GeoLite2-ASN
  reader alongside the existing country reader; both cached), user-agent, path/method,
  session id, actor_sub/role, request id, timestamp.
- **Sink**: DynamoDB `security_events` table (PK by day-bucket or `IP#{ip}` for fast
  per-source scans; GSIs by `event_type`, `actor_sub`, `asn`, `country`; **TTL** ~90d) +
  structured JSON to the app logger (for SIEM shipping) + a `security_events_total`
  Prometheus counter (labels: type, severity) in `metrics.py`.
- **PII/compliance**: IP+geo are PII — document retention (TTL), access control
  (root/security-scope only), and that logs must not contain secrets/tokens.

## Event taxonomy (instrumentation map — emit at each site)
| event_type | where (file) | from finding |
|---|---|---|
| `auth.login_failed` / `auth.mfa_failed` | `routers/ui_mfa.py`, login | SEC-008/009 |
| `auth.csrf_failed` | `auth/policy.py` / `sessions.py` CSRF check | — |
| `authz.forbidden` (403 on IDOR-ish paths) | `auth/deps.py` + IDOR sites | SEC-005 |
| `ban.access_after_ban` | `sessions.py` ban/API-key path | SEC-018 |
| `ratelimit.exceeded` | `services/rate_limit.py` | — |
| `ssrf.blocked` | link-preview, browser-ssh/sftp policy | SEC-001/020 |
| `webhook.signature_invalid` | ccbill/stripe/kyc webhooks | SEC-002 |
| `commerce.price_tamper_rejected` | `services/shoppingcart.py` | SEC-024 |
| `moderation.report_flood` | `routers/moderation.py` | SEC-025 |
| `notify.sms_email_abuse` | `routers/mfa_devices.py` send paths | SEC-014 |
| `mfa.factor_added` / `webauthn.registered` | webauthn/mfa | SEC-017 |
| `honeypot.hit` / `honeytoken.used` | SECOPS-003 | — |
| `netblock.denied` (ip/cidr/asn/geo) | SECOPS-002 middleware | — |

## Testing
pytest: each emit site writes a `security_events` row with enriched ip/asn/country;
TTL set; severity correct; no secret/token fields present; counter increments.

---
**Dev/Prod parity**: must satisfy [SECOPS-007](SECOPS-007-dev-prod-parity-aws-abstraction.md) — runs in dev with no AWS/offline (mock backend) and in prod on AWS, same code path, backend chosen by flag.
