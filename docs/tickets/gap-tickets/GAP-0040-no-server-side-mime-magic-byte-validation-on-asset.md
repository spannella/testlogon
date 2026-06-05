# GAP-0040: no server-side MIME magic-byte validation on asset upload

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-002.md`); see also `docs/tickets/writeups/ADS-002.md`

## Location
`app/routers/ads.py:_validate_asset`

## Problem / Impact
attacker uploads executable disguised as JPEG; content_type header is browser-controlled

## Fix
add imghdr/magic-bytes check on raw file data before S3 upload

## Notes
This gap was identified by the second-pass as-built review of ADS-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
