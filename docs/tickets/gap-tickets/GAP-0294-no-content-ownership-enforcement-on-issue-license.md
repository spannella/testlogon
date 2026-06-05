# GAP-0294: No content ownership enforcement on issue_license

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LICENSE-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/LICENSE-002.md`); see also `docs/tickets/writeups/LICENSE-002.md`

## Location
`app/services/issued_licenses.py:25`

## Problem / Impact
Any authenticated user can issue a license claiming to be the licensor of any content_id without verifying ownership; a malicious user can grant blanket licenses on content they don't own, polluting the Licensed Content Library and triggering fraudulent revenue splits

## Fix
add `_validate_content_ownership(licensor_sub, content_id, content_type)` against the relevant content table before writing any license record

## Notes
This gap was identified by the second-pass as-built review of LICENSE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
