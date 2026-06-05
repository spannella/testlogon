# GAP-0179: S3 upload path dead in current pipeline

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-004 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-004.md`); see also `docs/tickets/writeups/ENTERPRISE-004.md`

## Location
`app/services/audit_export_pipeline.py:110-116`

## Problem / Impact
S3 upload path dead in current pipeline

## Fix
Implement `process_export_job()` in the pipeline file (or the worker) with real S3 upload via `boto3`.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
