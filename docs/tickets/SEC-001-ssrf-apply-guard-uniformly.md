# SEC-001: Apply SSRF Guard Uniformly (link preview, UPS emit, webhook v1)

**Ticket**: SEC-001 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (item 1)

## Problem
An SSRF guard exists (`app/services/webhook_ssrf.py validate_webhook_url`, blocks
loopback/link-local/private CIDRs + cloud metadata) and is used for webhook
registration + CalDAV — but is **not applied to every server-side fetch of a
user-influenced URL**:
- 🌐 **Critical** — `app/routers/messaging.py:~4844` `_fetch_link_preview()` does
  `requests.get(url)` on a URL pulled from message text, no guard → any user posts
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/` or
  `http://localhost:8001` → cloud-credential / internal-service exfiltration.
- `app/routers/ups.py:207` `/emit/ups-tracking-webhook` POSTs to an arbitrary
  `target_url` with no validation (dev-gated, but still SSRF + secret exfil).
- `app/services/webhook_service.py:225` SSRF validation only runs when
  `webhooks_v2_enabled` and **swallows** errors in dev.

## Fix
- Call `validate_webhook_url(url, skip_dns=S.dev_mode)` (raise on failure) before
  EVERY outbound fetch/post of a user-influenced URL: link preview, UPS emit, any
  link-unfurl/import/avatar-by-URL path.
- Make webhook-registration SSRF validation unconditional (not gated on v2) and
  never swallow the error in prod.
- Audit grep: `requests.(get|post)|httpx|urllib|fetch(` in app/ for other unguarded
  user-URL fetches.

## Testing
pytest: link preview / UPS emit / webhook register all reject `169.254.169.254`,
`127.0.0.1`, `10.x`, `localhost`, DNS-rebind to private; allow normal public URLs.
