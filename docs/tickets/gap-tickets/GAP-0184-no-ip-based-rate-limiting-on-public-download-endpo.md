# GAP-0184: no IP-based rate limiting on public download endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FILES-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FILES-001.md`); see also `docs/tickets/writeups/FILES-001.md`

## Location
`app/routers/file_share_links.py:96`

## Problem / Impact
the ticket design specifies 10 req/min per IP and 5 password attempts per link+IP per minute; neither limit is enforced; the public endpoint has no rate-limiter dependency and no `X-Forwarded-For` inspection

## Fix
add rate-limit middleware or a per-request in-memory / DDB counter keyed on `(link_id, client_ip)` for password attempts; apply general IP rate limit via existing rate-limit infrastructure or a new decorator

## Notes
This gap was identified by the second-pass as-built review of FILES-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
