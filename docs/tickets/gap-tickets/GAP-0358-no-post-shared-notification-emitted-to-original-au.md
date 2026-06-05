# GAP-0358: No `post_shared` notification emitted to original author on repost

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOCIAL-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SOCIAL-002.md`); see also `docs/tickets/writeups/SOCIAL-002.md`

## Location
`post_shared`

## Problem / Impact
the repost handler writes the repost entity, increments `repost_count`, fans out to followers, but never calls `put_notification()` or `emit_social_alert()` to notify the original post author that their content was reposted; the `post_shared` alert type is registered in `ALERT_EVENT_TYPES` (alerts.py:143) but never triggered

## Fix
add `put_notification(recipient_user_id=author_id, notif_type="post_shared", payload={"post_id": post_id, "repost_id": repost_id, "from_user_id": user_id})` after the repost entity is written

## Notes
This gap was identified by the second-pass as-built review of SOCIAL-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
