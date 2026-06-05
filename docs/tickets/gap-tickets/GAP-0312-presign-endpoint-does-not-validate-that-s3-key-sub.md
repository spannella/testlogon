# GAP-0312: presign endpoint does not validate that `s3_key` submitted to create endpoint matches the presigned key

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MSG-002.md`); see also `docs/tickets/writeups/MSG-002.md`

## Location
`s3_key`

## Problem / Impact
a user could presign for one `s3_key` then submit `create_voice_message` with an arbitrary `s3_key` pointing to another user's file or a non-existent object; no ownership check prevents this

## Fix
store the presigned `(message_id → s3_key)` mapping in DDB or a short-TTL cache and verify it matches in `create_voice_message`

## Notes
This gap was identified by the second-pass as-built review of MSG-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
