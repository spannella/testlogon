# GAP-0321: `locale` field absent from user profile model

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-003.md`); see also `docs/tickets/writeups/PLATFORM-003.md`

## Location
`locale`

## Problem / Impact
`locale` field absent from user profile model

## Fix
add `locale: Optional[str]` to profile, validated against `I18N_SUPPORTED_LOCALES` before storage

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
