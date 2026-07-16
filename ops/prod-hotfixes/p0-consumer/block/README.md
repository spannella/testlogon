# P0 Consumer — USER BLOCK backend enforcement hotfix

Applied live to PROD (EC2 `i-08f937fc705ebea75`, us-east-2) via AWS SSM `AWS-RunShellScript`
on 2026-07-14, and mirrored byte-for-byte into the `android-impl` dev clone.

## Context
The block subsystem (`app/services/blocking.py`, routes `/ui/social/block|unblock|blocked|block-status`)
was already present and enforced on: feed listing, repost, DM find-or-create, DM send, follow.
Two enforcement GAPS remained — closed here so a block reliably hides content and stops contact.

## Changes
1. `app_routers_newsfeed.py.patch` — `create_comment` (POST /posts/{post_id}/comments):
   add `is_any_block(user_id, post_author)` -> 403 `{code:blocked}`. Previously a blocked
   user could comment on the blocker's public post (only subscription/lock gates were checked).
2. `app_routers_messaging.py.patch` — `create_call_invite` (POST /messages/calls/invite):
   add `is_any_block(user_id, body.callee_user_id)` -> 403 `{code:blocked}`. This is the
   direct 1:1 call-ring path; it did not inherit DM block enforcement.
   (Group calls in `group_call_service.create_group_call` require 3+ members and are conversation-
   scoped, so they are not a 1:1 bypass — left unchanged.)

## Anchoring
Both patches are string-anchored (unique) and idempotent (skip if the guard text is already present).
Prod backups: `app/routers/{newsfeed,messaging}.py.bak_p0_block_20260714164126`.

## Verify
- `python3 -m py_compile` clean on both files (prod + dev).
- Prod restarted via `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; `GET /openapi.json` -> 200.
- `GET /ui/social/blocked` -> 401 (session-gated, router loads).
