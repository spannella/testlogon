# GAP-0178: Background async export worker not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-004 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-004.md`); see also `docs/tickets/writeups/ENTERPRISE-004.md`

## Location
`app/services/`

## Problem / Impact
The ticket's section 3.4 describes `audit_export_worker.py` with `run_audit_export_worker_loop()`; the file does not exist and no startup hook in `app/main.py` references it. Export jobs created via `POST /ui/admin/audit-exports` are only processed synchronously in dev mode (capped at 500 events); in production the job stays in `pending` status indefinitely.

## Fix
Create `app/services/audit_export_worker.py`, register its startup coroutine in `app/main.py`, and wire S3 upload in `process_export_job`.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
