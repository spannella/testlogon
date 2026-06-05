# GAP-0306: `enforcement_id` absent from warning and ban alert details

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MOD-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MOD-003.md`); see also `docs/tickets/writeups/MOD-003.md`

## Location
`enforcement_id`

## Problem / Impact
`enforcement_id` absent from warning and ban alert details

## Fix
pass `enforcement_id` kwarg through `_persist_enforcement_if_needed()` in `admin_moderation.py:482` to both notification functions per section 3.3

## Notes
This gap was identified by the second-pass as-built review of MOD-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
