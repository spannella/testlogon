# Broadcast live ads + no-tip-on-sponsored + group/syndicate feed ads

LIVE PROD HOTFIX (SSM). Prod backups: `*.bak_bcastads_1783541000` on the 7 files
below. Restart: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`; openapi 200.

## Files
- NEW `app/services/sponsored_feed.py` — shared standalone sponsored-unit injector
  (group + syndicate feeds); `serve_ad` with no content_owner -> platform-100%.
- `apply_bcast_feed.py` — idempotent anchored patch (runs on dev clone AND prod):
  1. `app/services/broadcast_ads.py` — FEATURE 1: `serve_broadcast_ad` now passes
     `content_owner_id=creator_id` (broadcaster) + `build_pre_roll` uses
     surface=`broadcast_preroll` and carries `ad_click_id`; `record_ad_event`
     gains `ad_click_id` + charges via new `_charge_broadcast_preroll_completion`
     (reads AdClicks row, `ad_billing._process_charge`, funds-guarded, idempotent
     per `broadcast_preroll:{ad_click_id}`, credits broadcaster 70/30).
  2. `app/routers/broadcast_ads.py` — `PreRollOut.ad_click_id` + `ad_click_id`
     query param on `/broadcast/sessions/{id}/ads/{cr}/track` -> `record_ad_event`.
  3. `app/routers/newsfeed.py` — FEATURE 2: `tip_post` + `tip_react_to_post` reject
     `is_sponsored` posts with 400 `tip_not_allowed_on_ad`.
  4. `app/services/group_feed.py` — FEATURE 3: `list_group_feed` injects
     `inject_sponsored(surface=group_feed)`.
  5. `app/services/syndicate_feed.py` — FEATURE 3: `list_syndicate_posts` injects
     `inject_sponsored_syndicate(surface=syndicate_feed)`.
  6. `app/models.py` — `SyndicatePostOut` gains optional sponsored fields so an
     injected unit serializes through the strict response model.
  7. `app/core/settings.py` — `broadcast_ads_billing_enabled` default `0`->`1`
     (enable the dark broadcast-ads billing path).

## Verify
`verify_bcast_feed.py` — in-process on prod DDB via SSM. 31/31 ALL_PASS:
F1 serve+ad_click_id (owner=broadcaster, surface=broadcast_preroll) / advertiser
debit 25001 / broadcaster credit 70% 17500 type=credit / platform 30% 7501 /
idempotent repeat=0 / self-exclusion. F2 tip + tip-react -> 400. F3 group +
syndicate inject is_sponsored, standalone content_owner="" , advertiser charged
25 platform-100% creator=0, syndicate serializes through SyndicatePostOut.
