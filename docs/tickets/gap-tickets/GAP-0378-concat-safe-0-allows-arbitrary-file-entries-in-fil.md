# GAP-0378: `concat -safe 0` allows arbitrary file:// entries in filelist.txt

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-016 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-016.md`); see also `docs/tickets/writeups/VOD-016.md`

## Location
`concat -safe 0`

## Problem / Impact
if the filelist path is writable or the scratch_dir is attacker-influenced, ffmpeg will read any local file via the concat demuxer; SEC-012 explicitly flags this pattern

## Fix
use `-safe 1` and validate every entry is inside the owned scratch_dir before writing it to filelist.txt (i.e., assert `p.is_relative_to(scratch_dir)` per SEC-012 recommendation)

## Notes
This gap was identified by the second-pass as-built review of VOD-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
