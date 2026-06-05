# GAP-0379: Concat job exception never calls fail_job

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-016 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-016.md`); see also `docs/tickets/writeups/VOD-016.md`

## Location
`app/services/video_concatenator.py:308`

## Problem / Impact
on any exception the job stays in `running` state forever; worker cannot retry or surface the error

## Fix
catch exception, call `fail_job(job_id, str(e), attempt)` before re-raise

## Notes
This gap was identified by the second-pass as-built review of VOD-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
