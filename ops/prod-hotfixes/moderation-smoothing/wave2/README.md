# Moderation Smoothing — WAVE 2 (coverage: close the silent-enforcement-failure surfaces)

Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM) + folded here for re-apply,
plus the Android report call-sites. **The moderation core (state machine / byte-for-byte
hide-unhide / 30d sweep / fail-closed ban / DMCA) is unchanged and still verifies (this wave:
54/54, incl. the feed_post core-regression row).**

Plan: `ops/plans/moderation-rough-edges-plan.md` (Wave 2 = MODX-10..12).

## The problem
Whole live surfaces *claimed* moderation but silently no-op'd. Reporting them opened a case and
told the user "reported", but nothing was ever hidden:
- **syndicate posts** were filed by the app as `feed_post` -> hide looked up `POST#{id}` in the
  feed table, missed, and no-op'd (the real `syndicate_post` backend branch was dead).
- **profile photos** — `moderation_hide._apply` had a literal `return content_id` no-op.
- **accounts** (photoless), **commerce** (products/reviews), **live chat**, **stories/clips** had
  no report/hide path at all.

## Tickets

### MODX-10 — syndicate + profile-photo enforcement
- App: `SyndicateOverviewScreen` now files `ReportTarget.Content(postId, "syndicate_post",
  syndicateId=viewModel.syndicateId)` (was `feed_post`) so the real `T.syndicate_posts` branch hides it.
- Backend: `moderation_hide._hide_profile_photo` is REAL now — non-destructive url-swap (stash the
  original photo url under `moderation_saved_photo_url`, null `profile_photo_url` so non-owners stop
  seeing it, restore byte-for-byte on unhide). Photo-scoped flags kept separate from account flags.
- Fixed `moderation.py::_profile_photo_exists` (was keyed on `user_id` + read a top-level url that
  never exists — T.profile is keyed by `user_sub` with the photo NESTED under `profile`; the check
  always 404'd, so profile-photo reports never worked end-to-end).

### MODX-11 — account-level report
- New `content_type` `user`/`account`, keyed on the user (NOT a photo) — a photoless account is
  reportable. `_hide_user_account` writes a non-destructive account-hidden flag over the profile row;
  `profile.py::get_public_profile` 404s the profile for non-owners while held (owner keeps access to
  respond/appeal); NEVER deletes the account (ban is the account remedy). App: `ReportTarget.Account`.

### MODX-12 — commerce + live-chat + ephemeral coverage
- New `content_type`s wired through report validation + hide + delete dispatch + resolve_owner +
  read-path enforcement:
  - `catalog_item` (T.catalog `CAT#/ITEM#`, owner=creator_id) — read hidden in `catalog.list_items`.
  - `catalog_review` (T.catalog `ITEM#/REVIEW#`, owner=reviewer) — read hidden in `catalog.list_reviews`.
  - `broadcast_message` (T.broadcast_chat_messages via MessageIdIndex, owner=sender_id) — read hidden in
    `broadcast_chat_store.get_chat_history` / `fetch_chat_messages_after` (viewer -> the real state
    machine, not just the parallel host mute).
  - `story` (APP_TABLE `STORY#/META`, owner=author_id) — read hidden in `stories.get_user_stories` /
    `get_story_bar`.
  - `clip` (T.broadcast_clips, owner=creator_user_id) — read hidden in `broadcast_clip.get_public_clip`
    (404) + list queries.
- App report call-sites: live-chat message long-press -> Report (`broadcast_message`); products shelf
  card -> Report (`catalog_item`). Backend covers `catalog_review`/`story`/`clip` end-to-end; those app
  surfaces are scoped follow-ons.

## Files
Backend (in-place, prod == dev HEAD byte-for-byte pre-edit — `apply_wave2.py` patches both):
- `app/services/moderation_hide.py`  — 8 real hide primitives + `_apply` dispatch + resolve_owner
- `app/services/moderation_delete.py` — terminal delete primitives + dispatch (user = safe no-op)
- `app/routers/moderation.py`         — content_type Literal + fields + validation + metadata + photo-exists fix
- `app/services/moderation_flags.py`  — default-ON reporting-surface gates for the new surfaces
- `app/routers/profile.py`            — account-hold 404 for non-owners
- `app/services/broadcast_chat_store.py`, `app/services/broadcast_clip.py`, `app/services/stories.py`,
  `app/routers/catalog.py` — read-path filters honor `moderation_hidden`

App (`app_apply_wave2.py`):
- `data/report/ReportFlow.kt`, `data/report/ModerationReportApi.kt`, `data/report/ReportFlowRepository.kt`
- `feature/syndicates/ui/SyndicateOverviewScreen.kt`  (the B1 bug)
- `feature/broadcast/chat/LiveChatPanel.kt`, `feature/broadcast/shelf/ProductsShelf.kt`

## Deploy
`python3 apply_wave2.py` from the repo root (idempotent, anchor+guard based). `py_compile`,
`chown ubuntu:ubuntu`, `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`, `openapi.json` -> 200.

## Verify
`PYTHONPATH=. .venv/bin/python ops/prod-hotfixes/moderation-smoothing/wave2/verify_wave2.py`
(in-process on prod DDB, self-cleaning). **54/54 PASS** — every new surface: reportable ->
auto-hides (flag on the real row + the surface read hides it for a non-owner) -> admin-visible
under_review case -> reinstated byte-for-byte; plus the feed_post core-regression row.

## Coverage matrix (verified 2026-07-14, prod LocalStack DDB)
| content_type      | report | auto-hide (flag) | read-path hides | admin case | reinstate byte-for-byte |
|-------------------|:------:|:----------------:|:---------------:|:----------:|:-----------------------:|
| profile_photo     | PASS   | PASS             | PASS            | PASS       | PASS                    |
| user/account      | PASS   | PASS             | PASS            | PASS       | PASS                    |
| syndicate_post    | PASS   | PASS             | PASS            | PASS       | PASS                    |
| catalog_item      | PASS   | PASS             | PASS            | PASS       | PASS                    |
| catalog_review    | PASS   | PASS             | PASS            | PASS       | PASS                    |
| broadcast_message | PASS   | PASS             | PASS            | PASS       | PASS                    |
| story             | PASS   | PASS             | PASS            | PASS       | PASS                    |
| clip              | PASS   | PASS             | PASS            | PASS       | PASS                    |
| feed_post (core)  | PASS   | PASS             | PASS            | PASS       | PASS                    |

No silent no-op remains on any wired surface.
