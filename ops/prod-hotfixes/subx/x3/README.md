# SUBX EPIC X3 — PER-TIER GATING (SUBX-30..33)

Un-defers the LOCKED binary-gating decision (USER-APPROVED): a viewer now unlocks
subscriber-only content only at/BELOW their subscribed tier, instead of any active
sub unlocking everything. Reconciles the abandoned `fan_club` `TIER#` primitives
with the subscription `PLAN#` model; migration-safe (no existing subscriber loses
paid access).

Dev clone `~/dev/testlogon` @ `android-impl`. Prod EC2 `i-08f937fc705ebea75` via SSM
(mock backend bound to DDB-Local :8001). Prod base was byte-identical to the dev
pre-X3 clone for all 6 touched backend files (md5-verified) EXCEPT `newsfeed.py` and
`vod_purchase.py`, which differ elsewhere but share the exact anchors these patches
target — so the anchor-based patches apply cleanly on both.

## Ticket matrix

| Ticket | What | Where |
|--------|------|-------|
| SUBX-30 | Ordered tier-LEVEL model. `get_plan_level(creator,plan)` resolves a level: explicit `PLAN#.level` -> `fan_club TIER#` bridge (by `plan_id`) -> DENSE price-rank (cheapest active plan = L1, ties share a level). `viewer_max_tier_level` / `get_subscriber_tier_level` return the highest lifecycle-active level a viewer holds. | `app/services/subscription_access.py` |
| SUBX-31 | Thread the tier through the gate. `content_locked_for_viewer(..., required_level)` + `has_active_subscription(..., required_level)`: level 0 = the pre-tier BINARY gate (unchanged for every existing caller); level>=1 unlocks only a viewer at/above it. Wired into the POST gate (`newsfeed._post_to_dict` + `_subscriber_locked_post`), BROADCAST (`broadcast_privacy`), VIDEO (`vod_purchase.check_vod_access`). Items carry `required_tier_level`. | `subscription_access.py`, `newsfeed.py`, `broadcast_privacy.py`, `vod_purchase.py` |
| SUBX-32 | Migration that strands no one. RULE: an existing sub maps to its plan's resolved level (grandfather to L1 when a plan can't be resolved); pre-tier content has no `required_tier_level` (=0 binary) so ALL existing content stays open to ANY active sub — access can never be removed. Read-side FALLBACK (`viewer_max_tier_level` falls back to live `get_plan_level` when a sub lacks `tier_level`) makes the backfill optional. `tier_level` is persisted going forward at subscribe/gift/upgrade and at downgrade-apply. `backfill_tier_level.py` (idempotent, `--apply`) hardens existing rows. Prod had 0 existing subs at ship time -> no-op. | `subscription_server.py` (subscribe/gift/change), `subscription_renewal.py` (`_apply_pending_change`), `backfill_tier_level.py` |
| SUBX-33 | Correctness: expiry re-locks per tier (lifecycle bound already excludes lapsed periods -> level 0); UPGRADE re-resolves+persists the new tier_level immediately (unlocks higher tier now); DOWNGRADE keeps the current higher tier_level until `_apply_pending_change` re-resolves at period end (no early loss); bundle/syndicate holders bypass the tier cap entirely (never over-locked); multi-sub holders resolve to the MAX tier. | `subscription_access.py`, `subscription_server.py`, `subscription_renewal.py` |

Authoring foundation (for X4): `PlanCreate/Update/Out` gain an optional `level`
(>=1); when omitted the level is derived by price rank.

App content-requirement surface: `SubscriberLockCard` now names the REQUIRED tier
and upsells to it ("<Tier> tier required" / "Subscribe to <Tier>"). Wire fields
`required_tier_level` + `required_tier_name` flow `_post_to_dict` -> `FeedDtos` ->
`FeedDomain.Paywall.SubscriberLocked` -> `PostItem` -> the card.

## Apply order (prod, via SSM; cwd = /home/ubuntu/testlogon)

1. Back up the 6 files (`.bak_subx30_<ts>`), overwrite `app/services/subscription_access.py`
   with `subscription_access.final.py` (prod base identical to dev pre-X3).
2. `python3 patch_server.py` (subscription_server.py)
3. `python3 patch_rest.py` (subscription_renewal, newsfeed, broadcast_privacy, vod_purchase)
4. `python3 patch_label_newsfeed.py` (newsfeed create/emit + tier label helper; access-append is guarded/idempotent)
5. `chown ubuntu:ubuntu` the 6 files, AST-check, `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`, openapi 200.
App: `patch_app.py` on the dev clone -> `./gradlew :app:assembleDebug`.

## Verify (live-DDB-direct, self-cleaning, 0 residue)

- `verify_subx3.py` (== `subx30_verify.py`): tier model + gate matrix — 32/32 PASS.
  Isolated probe creator for explicit-level/bridge so ranks aren't polluted.
- `verify_subx3_wire.py` (== `subx31_wire.py`): `_post_to_dict` app-contract — 8/8 PASS
  (tier-1 viewer of a tier-2 post -> locked + required tier named; tier-2 -> shown).
- Regression (no core break): SUB-E3 gating (all 6 surfaces + expiry re-lock) ALL PASS;
  SUBX-2 money core 19/19 PASS.

Run env: `set -a; source .env.local; export DDB_ENDPOINT_URL=http://localhost:8001
AWS_ENDPOINT_URL=http://localhost:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
AWS_REGION=us-east-1 PYTHONPATH=/home/ubuntu/testlogon; set +a` then `.venv/bin/python3 <script>`.
