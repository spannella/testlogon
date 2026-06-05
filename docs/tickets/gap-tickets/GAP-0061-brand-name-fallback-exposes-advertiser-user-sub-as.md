# GAP-0061: brand name fallback exposes advertiser user sub as PII

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-013 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-013.md`); see also `docs/tickets/writeups/ADS-013.md`

## Location
`app/services/sponsorship_deals.py:submit_content:521`

## Problem / Impact
when account lookup fails, ftc_disclosure contains "Paid partnership with alice@company.com"

## Fix
fall back to "a verified brand partner" rather than the user sub string

## Notes
This gap was identified by the second-pass as-built review of ADS-013. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
