# GAP-0355: `emit_social_alert()` never called from social event triggers

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOC-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/SOC-004.md`); see also `docs/tickets/writeups/SOC-004.md`

## Location
`emit_social_alert()`

## Problem / Impact
the `social_alerts.py` module and `emit_social_alert()` are fully implemented but zero callers exist outside the module itself; reactions, comments, tips, reposts, and follows only use `put_notification()` (newsfeed-internal GSI3 system), so no social alerts ever land in the `alerts` table and the bell badge stays silent for all social events

## Fix
add `emit_social_alert()` calls after each event: reaction handler (post_reaction/post_liked), comment handler (post_comment/comment_reply), tip_post handler (post_tip), message tip handler (message_tip), `social.follow_user()` (new_follower), subscription create (subscription_started)

## Notes
This gap was identified by the second-pass as-built review of SOC-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
