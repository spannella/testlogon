# GAP-0240: `GoogleDrivePickerDialog` not used anywhere in the frontend

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INTEG-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INTEG-001.md`); see also `docs/tickets/writeups/INTEG-001.md`

## Location
`GoogleDrivePickerDialog`

## Problem / Impact
the component is defined and renders correctly but is never imported by any page; the E2E test at `frontend/e2e/drive-picker.spec.ts:201` confirms this with a conditional `if (visible)` guard and notes "may not be wired into the Files page toolbar yet"

## Fix
import and render the dialog from `FilesPage.tsx` with `drivePickerOpen` state controlled by the Browse button

## Notes
This gap was identified by the second-pass as-built review of INTEG-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
