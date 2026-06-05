# GAP-0043: list_campaigns_by_status does not use ByStatusCreatedAt GSI

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-004.md`); see also `docs/tickets/writeups/ADS-004.md`

## Location
`app/services/ad_campaigns.py:list_campaigns_by_status`

## Problem / Impact
implicit table scan at scale; slow and expensive for every serve request

## Fix
use Query(IndexName="ByStatusCreatedAt", KeyConditionExpression=Key("status").eq(status))

## Notes
This gap was identified by the second-pass as-built review of ADS-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
