# GAP-0056: no per-API-key rate limiting

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-011.md`); see also `docs/tickets/writeups/ADS-011.md`

## Location
`app/routers/advertiser_api.py`

## Problem / Impact
any API key can make unlimited requests; risk of DDB hot partitions from bulk analytics queries

## Fix
add check_rate_limit middleware on advertiser_api_router at 1000 req/min per key

## Notes
This gap was identified by the second-pass as-built review of ADS-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
