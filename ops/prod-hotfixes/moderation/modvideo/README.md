# MOD-C2 hotfix (modvideo) — enable WHOLE-VIDEO + VIDEO-COMMENT reports

The consumer app (MOD-C2) wires Report actions onto a video detail
(content_type="video", content_id=video_id) and onto video comments
(content_type="video_comment", content_id=comment_id, video_id=parent).
Three gaps blocked those surfaces on the LIVE backend:

1. **content_type Literal** on `CreateModerationReportIn` omitted "video"
   (prod had only "video_comment"; the dev clone had neither) -> whole-video
   reports **422'd** at input validation.
2. **moderation_hide.resolve_owner** handled neither "video" nor
   "video_comment", so the moderation CASE recorded `owner_user_id=None` for
   video content -> it never appeared in the poster's
   `GET /moderation/cases/mine` ("My content under review") and owner-notify
   fell back to the hide_content return.
3. (**prod only**) `_video_comment_exists` called the keyword-only
   `get_comment()` **positionally** -> `TypeError` -> video_comment reports
   **500'd** at validation.

The non-destructive hide primitive (`_apply`/`_hide_video`/`_hide_video_comment`)
already supported both types; only the input gate + owner resolver were missing.

## Files patched
- `app/routers/moderation.py` — canonical 8-type Literal (adds video +
  video_comment); `video_id` model field (if absent); self-contained
  `_validate_content_exists` branches for video + video_comment; `_video_comment_exists`
  keyword-call fix.
- `app/services/moderation_hide.py` — `resolve_owner` video + video_comment
  owner lookups (video_metadata owner_sub/user_id/creator_id; video_comment
  get_comment().user_id).

## Apply (idempotent, presence-guarded, anchor-tolerant; py_compile-validated)
    ROOT=/home/ubuntu/testlogon .venv/bin/python apply_video_report.py

Safe to re-run; skips anything already present.

## Deployed
- Prod EC2 i-08f937fc705ebea75 via SSM: apply -> import-test (runtime env) ->
  restart uvicorn (preserved /proc env) -> openapi 200, live enum shows all 8.
  Backups: moderation.py.bak_modvideo*_<epoch>, moderation_hide.py.bak_modvideo*_<epoch>.
- Dev clone: applied in place (same script).

## Verified (in-process on real prod DynamoDB-Local, via SSM)
- Consolidated state-machine regression: **75/75 PASS** (report->guarded auto-hide->
  owner-view non-destructive->confirm->30d hold->respond->reinstate/close->sweep->
  final-call delete+ban->licensing/DMCA->guards).
- Video-surface supplement: **18/18 PASS** (video + video_comment accepted (not 422),
  severe auto-hide -> under_review, case owner==poster => appears in /cases/mine,
  owner-view hidden-for-stranger/visible-to-owner, non-destructive, spam x1 stays
  visible, video_comment 500 fixed).
