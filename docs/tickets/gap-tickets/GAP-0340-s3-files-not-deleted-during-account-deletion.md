# GAP-0340: S3 files not deleted during account deletion

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PRIVACY-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PRIVACY-001.md`); see also `docs/tickets/writeups/PRIVACY-001.md`

## Location
`app/services/gdpr_service.py:672-827`

## Problem / Impact
Files the user uploaded persist in the `filemgr_bucket` S3 bucket; file manager DDB records are also not deleted

## Fix
add S3 `delete_objects` batch call and file-manager DDB cleanup step to `process_deletion()`

## Notes
This gap was identified by the second-pass as-built review of PRIVACY-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
