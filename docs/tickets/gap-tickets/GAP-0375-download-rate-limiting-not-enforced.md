# GAP-0375: download rate limiting not enforced

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-012 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-012.md`); see also `docs/tickets/writeups/VOD-012.md`

## Location
`app/routers/video_listing.py:772-824`

## Problem / Impact
settings.py defines video_download_rate_limit_per_10m=5 but the download endpoint never reads this setting or checks a rate-limit counter; spec §1.4 requires 5 requests per 10 minutes per user per video to prevent URL farming

## Fix
add a Redis/DynamoDB rate-limit check keyed by user_sub+video_id before minting the presigned URL; return 429 if limit exceeded

## Notes
This gap was identified by the second-pass as-built review of VOD-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
