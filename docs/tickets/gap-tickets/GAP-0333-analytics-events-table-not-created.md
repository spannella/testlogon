# GAP-0333: Analytics events table not created

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-019 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-019.md`); see also `docs/tickets/writeups/PLATFORM-019.md`

## Location
`scripts/local-ddb-init.py`

## Problem / Impact
Runtime `ResourceNotFoundException` the moment any event-recording call is made; rollup job can never run

## Fix
add `TableDef("analytics_events", "pk", "sk", gsis=[{"name":"GSI1","pk":"GSI1PK","sk":"GSI1SK"}], ttl_field="ttl_epoch")` in local-ddb-init.py

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
