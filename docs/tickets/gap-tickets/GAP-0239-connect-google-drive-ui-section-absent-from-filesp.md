# GAP-0239: "Connect Google Drive" UI section absent from `FilesPage.tsx`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INTEG-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INTEG-001.md`); see also `docs/tickets/writeups/INTEG-001.md`

## Location
`FilesPage.tsx`

## Problem / Impact
"Connect Google Drive" UI section absent from `FilesPage.tsx`

## Fix
add the Google Drive integration section (connection badge, Connect/Disconnect/Browse buttons) to `FilesPage.tsx` as described in ticket section 4.6 and render `<GoogleDrivePickerDialog>`

## Notes
This gap was identified by the second-pass as-built review of INTEG-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
