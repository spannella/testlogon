# GAP-0199: No admin-global dispute arbitration endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FIN-011.md`); see also `docs/tickets/writeups/FIN-011.md`

## Location
`GET /ui/admin/collaboration-disputes`

## Problem / Impact
the ticket spec requires `GET /ui/admin/collaboration-disputes` and `POST /ui/admin/collaboration-disputes/{dispute_id}/arbitrate` for admins to view all open disputes cross-collaboration, but `app/routers/collaborations.py` only exposes `GET /{collab_id}/disputes` (scoped to participants); admins cannot discover disputes without knowing the `collab_id`

## Fix
add `require_admin_session`-gated list-all-disputes and arbitrate endpoints using `cr.list_disputes(collaboration_id=None)` from `app/services/collaboration_revenue.py:553`

## Notes
This gap was identified by the second-pass as-built review of FIN-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
