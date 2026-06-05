# GAP-0068: global ad kill switch absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-018 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-018.md`); see also `docs/tickets/writeups/ADS-018.md`

## Location
`app/services/admin_ad_platform.py`

## Problem / Impact
no emergency path to stop all ad serving platform-wide; admins must reject campaigns one by one

## Fix
implement toggle_kill_switch service + POST /ui/admin/ad-platform/kill-switch endpoint + serve_ad check at startup

## Notes
This gap was identified by the second-pass as-built review of ADS-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
