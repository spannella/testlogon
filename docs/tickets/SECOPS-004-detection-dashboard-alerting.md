# SECOPS-004: Detection, Correlation, Alerting & Monitoring Dashboard

**Ticket**: SECOPS-004 · **Status**: Open · **Priority**: Medium · **Date**: 2026-06-04
**Theme**: Security Detection & Response. **Consumes**: SECOPS-001/002/003.
**Reuses**: `app/services/alerts.py`, `app/metrics.py`, admin dashboard patterns
(`RiskDashboardPage.tsx`, `RateLimitDashboard.tsx`).

## Goal
Turn the security-event stream into situational awareness + timely notifications, and
give operators one place to watch attacks and act (block/unblock).

## Design
- **Correlation/scoring**: `app/services/threat_scoring.py` — sliding-window
  aggregation per IP / ASN / country / actor_sub; a risk score from event mix
  (honeypot hit = instant high; bursts of auth fails / ssrf / 403s ramp the score).
  Feeds SECOPS-002 auto-ban thresholds.
- **Alerting**: reuse `alerts.py` + `alert_priority.py` to notify security admins
  (email/webhook/Slack) on: any honeypot/honeytoken hit, critical events, score
  spikes, a new top-offender ASN, auto-ban escalations. Dedup/throttle to avoid storms.
- **Admin dashboard** (`frontend/src/pages/admin/SecurityMonitoringPage.tsx`, route +
  sidebar under admin): live event timeline, top offender IPs/CIDRs/ASNs/countries,
  geo/ASN breakdown, honeypot feed, current block/allow lists with one-click
  add/remove/expire + reason, per-source drill-down. Backed by a
  `app/routers/security_monitoring.py` (root/security-scope only).
- **Dev panel**: a section in `devtools.html` (3001) to view recent security events +
  toggle/seed honeypots locally (cross-ref DEVTOOLS-001).
- **Metrics export**: `security_events_total`, `netblocks_active`,
  `autoban_actions_total`, `honeypot_hits_total` via `metrics.py` for Prometheus/Grafana.

## Testing
E2E: dashboard lists recent events and offenders; clicking "block" adds a
`security_blocklist` entry that then 403s the source; a honeypot hit raises an alert
record; access restricted to root/security scope (regular admin → 403).

---
**Dev/Prod parity**: must satisfy [SECOPS-007](SECOPS-007-dev-prod-parity-aws-abstraction.md) — runs in dev with no AWS/offline (mock backend) and in prod on AWS, same code path, backend chosen by flag.
