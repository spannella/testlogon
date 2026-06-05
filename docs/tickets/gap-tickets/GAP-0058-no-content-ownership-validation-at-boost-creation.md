# GAP-0058: no content ownership validation at boost creation

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-012.md`); see also `docs/tickets/writeups/ADS-012.md`

## Location
`app/services/content_boost.py:create_boost`

## Problem / Impact
any user can pay to boost content they don't own, skewing feed ranking for others' content

## Fix
call _verify_content_ownership(owner_sub, content_type, content_id) before wallet charge

## Notes
This gap was identified by the second-pass as-built review of ADS-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
