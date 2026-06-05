# GAP-0183: sticker_url accepts arbitrary external URLs with no platform-only enforcement

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FEED-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FEED-004.md`); see also `docs/tickets/writeups/FEED-004.md`

## Location
`app/routers/newsfeed.py:1591`

## Problem / Impact
the ticket spec requires sticker URLs to reference platform CDN only; any external URL is currently accepted and stored, enabling hotlinking of off-platform resources or SSRF-adjacent abuse

## Fix
validate sticker_url matches platform S3/CDN origin (e.g. begins with /mock/s3/ in dev, or configured CDN_BASE_URL)

## Notes
This gap was identified by the second-pass as-built review of FEED-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
