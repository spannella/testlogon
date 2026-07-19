# Reporting a video comment 500s (get_comment duplicate-def keyword-only shadow)

## Symptom
POST /moderation/reports with content_type=video_comment 500s:
`TypeError: get_comment() takes 0 positional arguments but 2 were given`
(also affects any moderation/DMCA/hide path that validates a video comment).

## Root cause
app/services/video_comments.py defines get_comment TWICE:
- line 108: def get_comment(video_id, comment_id)            # positional (original)
- line 372: def get_comment(*, video_id, comment_id)         # keyword-only (later)

Python keeps the LAST definition, so the keyword-only one wins and every
POSITIONAL caller breaks:
- app/routers/moderation.py:106 _video_comment_exists(get_comment(video_id, comment_id))
- app/routers/moderation.py:199, app/services/dmca_content_operations.py:314,
  app/services/moderation_hide.py:174 / :406

## Fix
Remove the keyword-only marker (`*,`) from the surviving get_comment so it accepts
BOTH positional and keyword args (params are identical), restoring every caller
with a one-line change. See video_comment_get_comment_signature.patch.
Verified: POST /moderation/reports (video_comment) 500 -> 404 for a missing
comment (200 for a real one).

## Prod-mirror status: PROD: APPLIED 2026-07-19
> PROD: APPLIED 2026-07-19 (SSM). Pre-fix prod had the duplicate keyword-only `def get_comment(*, ...)`
> at line 368, NOT divergent. Dropped the `*,`. bak: `app/services/video_comments.py.bak_fs_video_comment_get_comment_signature_20260719045927`.
> Verify: positional `get_comment(v,c)` returns None (was TypeError 500); moderation/dmca/hide modules
> import cleanly. dev==prod.

This 500s on the live server for any user reporting a video comment. Apply the
.patch on prod (/home/ubuntu/testlogon) via SSM, restart uvicorn, re-verify.
