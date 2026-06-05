# GAP-0006: legacy record_ad_impression() in ad_placement.py has no fraud check

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: ADS-014 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-014.md`); see also `docs/tickets/writeups/ADS-014.md`

## Location
`app/services/ad_placement.py:233`

## Problem / Impact
VOD ad-impression path (POST /ui/videos/{id}/ad-impression) bypasses all fraud detection; any user can fire unlimited complete events to generate unbounded creator revenue

## Fix
add check_fraud() call at start of record_ad_impression(); pass ip_address, user_agent, view_time_ms, campaign_id

## Notes
This gap was identified by the second-pass as-built review of ADS-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
