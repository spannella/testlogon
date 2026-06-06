# GAP-0263: `notary_stamp` field type not valid

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-007.md`); see also `docs/tickets/writeups/KYC-007.md`

## Location
`notary_stamp`

## Problem / Impact
only `text`, `signature`, and `date` field types are accepted; `notary_stamp` with `stamp_image_ref`, `stamp_number`, `stamp_expiry` is needed for high-risk cases

## Fix
extend valid field-type set in `signature_packet_store.py` to include `notary_stamp`; add S3-backed stamp image ref (moto in dev)

## Notes
This gap was identified by the second-pass as-built review of KYC-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
