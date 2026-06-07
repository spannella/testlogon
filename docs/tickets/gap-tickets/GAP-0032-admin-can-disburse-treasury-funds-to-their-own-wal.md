# GAP-0032: Admin can disburse treasury funds to their own wallet, violating the core no-admin-withdrawal constraint

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: SYND-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SYND-004.md`); see also `docs/tickets/writeups/SYND-004.md`

## Location
`app/services/syndicate_treasury.py:240-339`

## Problem / Impact
the `disburse` endpoint validates that `recipient_user_id` is a syndicate member but does not block `admin_sub == recipient_user_id`; a malicious admin can unilaterally withdraw all contributed funds to themselves, which is exactly the attack the no-withdrawal rule was designed to prevent

## Fix
add `if admin_sub == recipient_user_id: raise HTTPException(400, "Admin cannot disburse to themselves")` at the start of `disburse()`

## Notes
This gap was identified by the second-pass as-built review of SYND-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
