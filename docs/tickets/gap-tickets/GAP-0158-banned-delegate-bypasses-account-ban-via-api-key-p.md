# GAP-0158: banned delegate bypasses account ban via API key path

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: DELEGATE-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/DELEGATE-005.md`); see also `docs/tickets/writeups/DELEGATE-005.md`

## Location
`app/services/delegation_api.py:239`

## Problem / Impact
authenticate_key checks delegation status but not delegate account ban; a banned user retains full delegation API key access

## Fix
add is_user_currently_banned(item["owner_sub"]) check after delegation relationship check at line 241

## Notes
This gap was identified by the second-pass as-built review of DELEGATE-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
