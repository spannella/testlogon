# GAP-0154: conversion attribution chain broken

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CREATOR-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CREATOR-004.md`); see also `docs/tickets/writeups/CREATOR-004.md`

## Location
`app/services/commerce_order_service.py:39`

## Problem / Impact
no conversions are ever attributed regardless of clicks; affiliate commission is never earned

## Fix
extract afl_ref cookie in checkout endpoint and call record_conversion on order completion

## Notes
This gap was identified by the second-pass as-built review of CREATOR-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
