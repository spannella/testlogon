# GAP-0182: gif_url accepts arbitrary URL schemes with no domain allowlist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FEED-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FEED-004.md`); see also `docs/tickets/writeups/FEED-004.md`

## Location
`app/routers/newsfeed.py:1585`

## Problem / Impact
any URL including data: or javascript: URIs can be stored and rendered as img src; malicious data: URIs can embed arbitrary content, and future CSP relaxations or renderer bugs could enable XSS

## Fix
validate gif_url is http/https and restrict to an allowlist of known GIF CDN domains (e.g. media.giphy.com, media.tenor.com)

## Notes
This gap was identified by the second-pass as-built review of FEED-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
