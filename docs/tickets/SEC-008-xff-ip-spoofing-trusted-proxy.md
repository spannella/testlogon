# SEC-008: X-Forwarded-For Spoofing → Rate-Limit/Blocklist/Audit Bypass

**Ticket**: SEC-008 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 2)

## Problem
`app/core/normalize.py:client_ip_from_request` returns the **first
`X-Forwarded-For` value with NO trusted-proxy validation**. Any client can set
`X-Forwarded-For: <anything>`. This resolved IP drives security decisions:
- **Rate limit** (`app/middleware/rate_limit.py:100,232`, `rate_limit_store.py`):
  rotate XFF per request → fresh per-IP bucket → **bypass per-IP limits / brute-force
  login, MFA, registration, password-reset**; spoof an allowlisted IP → skip limits;
  spoof a different IP → **evade the IP blocklist** (`is_blocked`).
- **Audit / login-anomaly / device-trust** (`alerts.py:17`, `rate_limit.py:100`,
  `device_trust.py:31`) → forge source IP, poison forensics, bypass anomaly detection.
- **Magic link IP check** (`magic_links.py:89`) → spoof victim IP to use their link.
(Note: the ROOT network gate `root_network.py` is OK — it validates a trusted-proxy
CIDR before honoring XFF. The generic helper does not — that inconsistency is the bug.)

## Fix
- Single trusted-proxy-aware IP resolver: honor `X-Forwarded-For` **only** when the
  direct peer (`request.client.host`) is in `TRUSTED_PROXY_CIDRS`; otherwise use the
  socket peer. Take the right-most untrusted hop, not the first. Make
  `client_ip_from_request` use it everywhere (or replace call sites with the
  `root_network` resolver).
- Per-account lockout for auth endpoints so IP rotation alone can't brute-force
  (see SEC-009).

## Testing
pytest: with no trusted proxy configured, a spoofed `X-Forwarded-For` is ignored
(uses peer IP); rate-limit/blocklist key off the real peer; behind a configured
trusted proxy, the real client IP is taken from XFF correctly.
