# GAP-0315: sticker upload in `sticker_collections.py` validates MIME only from declared `content_type` header, not magic bytes

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MSG-007.md`); see also `docs/tickets/writeups/MSG-007.md`

## Location
`sticker_collections.py`

## Problem / Impact
sticker upload in `sticker_collections.py` validates MIME only from declared `content_type` header, not magic bytes

## Fix
add a `_detect_content_type(data)` helper to `sticker_collections.py` (mirrors `custom_emojis.py:72`) and reject if sniffed MIME doesn't match declared or allowed list

## Notes
This gap was identified by the second-pass as-built review of MSG-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
