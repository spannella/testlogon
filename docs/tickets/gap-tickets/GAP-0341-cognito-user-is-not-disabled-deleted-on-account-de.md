# GAP-0341: Cognito user is not disabled/deleted on account deletion

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PRIVACY-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PRIVACY-001.md`); see also `docs/tickets/writeups/PRIVACY-001.md`

## Location
`app/services/gdpr_service.py:672-827`

## Problem / Impact
Deleted users can still authenticate via their Cognito credentials; SEC-018 cross-ref: token revocation does not propagate

## Fix
call `cognito_client.admin_disable_user` then `admin_delete_user` guarded by `_cognito_available()` check, matching the pattern in `app/core/aws.py`

## Notes
This gap was identified by the second-pass as-built review of PRIVACY-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
