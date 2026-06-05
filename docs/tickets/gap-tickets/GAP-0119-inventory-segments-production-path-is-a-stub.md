# GAP-0119: `inventory_segments` production path is a stub

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-006 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BCAST-006.md`); see also `docs/tickets/writeups/BCAST-006.md`

## Location
`inventory_segments`

## Problem / Impact
returns `[]` in both mock and non-mock paths; no S3 `ListObjectsV2` pagination wired; production recordings have no segments

## Fix
implement paginated `s3.get_paginator("list_objects_v2")` with moto endpoint in dev

## Notes
This gap was identified by the second-pass as-built review of BCAST-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
