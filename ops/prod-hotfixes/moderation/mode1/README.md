# MOD-E1/E2 backend additive hotfix — admin detail case-state + syndicate snapshot

Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM), folded here.
Additive-only edit to `app/routers/admin_moderation.py` so the Android admin
moderation board (MOD-E1/E2) can render the NEW state machine.

## What it adds (all additive; no behavior change to existing responses)
1. `GET /v1/admin/moderation/tickets/{id}` detail (`ModerationTicketDetailOut`) now returns:
   - `case_state`  — live `moderation_case.state` (visible/under_review/hold/awaiting_final/
     dismissed/reinstated/deleted); falls back to the ticket `moderation_case_state`.
   - `hold_until`  — epoch secs when the 30-day hold ends (drives the app hold countdown).
   - `owner_user_id` — resolved poster.
2. `_content_snapshot` gains a `syndicate_post` branch (reads `T.syndicate_posts` via
   `syndicate_feed._get_post`); the `syndicate_id` comes from the report metadata OR,
   when absent, from the moderation_case `content_metadata` (report rows do not persist
   `syndicate_id`).

Anchors are byte-identical dev==prod (admin_moderation.py was folded at aba724d2).
apply_mode1_detail_fields.py then apply_mode1_syndicate_snapshot.py are idempotent
(print ALREADY on re-run).

## Prod .bak
- `admin_moderation.py.bak_e1_1783621226`  (fully original — rollback target)
- `admin_moderation.py.bak_e1b_1783622867` (after step 1, before step 2)
Live sha256 = f3193c198b5661dbf2a4412fb2e2e94e4a7ef29ad348697e318f02f90ee5638b ; openapi 200.

## Verify — 25/25 ALL PASS (verify_mode1_e2e.py, in-process prod DDB, real HTTP routes)
report->auto-hide (feed + syndicate in own store) ; admin detail case_state/hold/snapshot/
offender ; confirm->30d hold ; final-call delete+ban(7d) [content hard-deleted + poster
BANNED-enforced] ; dismiss->un-hide ; syndicate confirm->reinstate (byte-for-byte, reappears
for non-owner) ; permanent-ban 403 for a non-senior admin + allowed for senior.
