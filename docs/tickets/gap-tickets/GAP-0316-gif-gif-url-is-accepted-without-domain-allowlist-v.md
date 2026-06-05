# GAP-0316: GIF `gif_url` is accepted without domain allowlist validation

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MSG-008.md`); see also `docs/tickets/writeups/MSG-008.md`

## Location
`gif_url`

## Problem / Impact
GIF `gif_url` is accepted without domain allowlist validation

## Fix
add `gif_allowed_domains: list[str]` setting (default `[""]` to allow `/mock/*` in dev); validate `urllib.parse.urlparse(inp.gif_url).netloc` against the list in `send_gif_message()`; raise `HTTPException(400, "gif_url_not_allowed")` on mismatch

## Notes
This gap was identified by the second-pass as-built review of MSG-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
