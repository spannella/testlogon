# GAP-0055: webhook system entirely absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-011 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ADS-011.md`); see also `docs/tickets/writeups/ADS-011.md`

## Location
`app/services/`

## Problem / Impact
no ad_webhooks.py, no DDB table, no CRUD endpoints, no delivery mechanism; advertisers cannot receive real-time campaign event notifications

## Fix
implement app/services/ad_webhooks.py + ad_webhooks DDB table + POST/GET/DELETE/test endpoints in advertiser_api_router

## Notes
This gap was identified by the second-pass as-built review of ADS-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
