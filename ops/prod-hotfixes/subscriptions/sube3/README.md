# SUB-E3-1 — subscriber-only content-gating enforcement (LIVE PROD HOTFIX)

Prod: EC2 i-08f937fc705ebea75 (SSM). Applied 2026-07-11.
Backups: `<file>.bak_sube3_1783748136` for all 7 files (prod /home/ubuntu/testlogon).
Restart: restart_backend.sh; openapi 200. In-process VERIFY on prod DDB = ALL 6 surfaces PASS (+ re-lock on expiry).

## Single source of truth
`app/services/subscription_access.py`
- `is_platform_admin(user_id)` — best-effort users-table role in {admin,root} (owner+ADMIN bypass).
- `content_locked_for_viewer(viewer, creator, subscriber_only=True)` — True=LOCKED. Bypass for owner/admin/active-sub(lifecycle-aware E1)/syndicate-bundle. Re-locks on expiry automatically (has_active_subscription bounded by grace-extended current_period_end).
- `can_access_creator` — added admin bypass.

## Surfaces enforced (all via content_locked_for_viewer, binary any-active-sub)
1. FEED POST (main/group/syndicate) — `newsfeed._post_to_dict`: per-post `subscriber_only` flag -> non-destructive `locked_body` marker; output adds `subscriber_only`/`subscriber_locked`/`creator_id`. `CreatePostRequest.subscriber_only` + persisted on create. `_subscriber_locked_post` helper.
2. POST COMMENTS — `newsfeed.list_comments` + `create_comment`: 403 SUBSCRIBER_ONLY when `_subscriber_locked_post`.
3. VIDEO — `vod_purchase.check_vod_access`: pre-existing subscriber_only via has_active_subscription; ADDED admin bypass (reason="admin").
4. MESSAGES/DM — `require_subscription_access` (creator-wide pay-to-DM) already routes through can_access_creator (now admin-bypassed + lifecycle-aware). Verified.
5. CREATOR FEED — `newsfeed.can_view_post` -> can_access_creator (creator-wide require_subscription). Verified.
6. BROADCAST viewer — `broadcast_privacy.check_viewer_access`: NEW subscriber_only gate (reads raw session flag) -> 403 BROADCAST_SUBSCRIBER_ONLY. `subscriber_only` added to model/serialization/create (models_broadcast, broadcast_store, broadcast router).

Attachment endpoints (`get_post_file`, `download_post_attachment`) also gated.

## Prod divergence (anchors differ dev vs prod — audio-room + lock_type aliases)
Prod patch = `ops/prod-hotfixes/subscriptions/patch_sube3_prod.py` (4 anchors retuned: CreatePostRequest visibility-only anchor; broadcast_store create_session stage_max_slots signature/construct; broadcast router create_session_route mode/stage_max_slots). All 22 edits applied clean, py_compile OK.

## Verify (in-process, prod DDB)
Per surface: non-subscriber LOCKED (no body/403) / active subscriber FULL / owner sees / admin bypass / after current_period_end elapses -> RE-LOCK (has_active_subscription now False). See verify_sube3.py.
