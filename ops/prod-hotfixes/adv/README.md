# ADV — Advertising epic prod-hotfix folds

Prod source (`/home/ubuntu/testlogon`) diverges from the `android-impl` dev clone.
Every advertising backend change lands as an `android-impl` commit **and** a re-apply
artifact here. This folder is the fold seam for the whole advertising program
(ADV-B0 … ADV-B5; plan: `ops/plans/advertising-implementation-plan.md`).

## Re-apply order (for a fresh prod / after a prod redeploy)

Apply ad-platform patches in dependency order so imports resolve:

1. **settings** — `app/core/settings.py` (new `*_table_name` + feature flags)
2. **tables**   — `app/core/tables.py` (register `T.<name>`) + run the DDB table create
3. **billing**  — `app/services/ad_billing.py` (deposit charge, funds-guard, split)
4. **serving**  — `app/services/ad_serving.py`, `app/services/vod_ad_supported.py`
5. **routers**  — `app/routers/ads.py`, `newsfeed.py`, `subscription_server.py`, etc.
6. restart backend: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`

Each prod file edit is preceded by a `.bak_adv_<ts>` copy.

---

## ADV-001 — prod ad feature-flag values (read via SSM, DEV_MODE box)

Prod `.env.local` sets **only** `DEV_MODE=1` for the ad surface; every ad flag below
falls to its code default. Values are the live computed `app.core.settings` values on
prod (2026-07-07):

| Flag | Prod value | dev default | Meaning for serving |
|---|---|---|---|
| `dev_mode` | **True** | True | **Gate on live pre-roll.** `vod_ad_supported.py:109` ORs `dev_mode` into the deterministic decision → while `dev_mode=True` the VOD path uses the deterministic **placeholder** creative regardless of `vod_ad_supported_deterministic`. B2 live pre-roll needs `dev_mode` OFF (or the ADV-201 gate must stop OR-ing dev_mode). |
| `sponsored_posts_enabled` | True | True | Newsfeed ad-injection gate is ON (`_inject_sponsored_posts` every 5, max 3). Live today but returns **empty** — no paid campaigns + house ads dropped. B1 makes it serve real paid units. |
| `sponsored_post_interval` | 5 | 5 | Inject one sponsored slot every 5 organic posts. |
| `sponsored_post_max_per_page` | 3 | 3 | Max 3 sponsored slots per feed page. |
| `broadcast_ads_billing_enabled` | **False** | False | Broadcast pre-roll billing path is DARK. Out of scope for B1/B2 (a 4th surface, deferred). |
| `vod_ad_supported_enabled` | True | True | VOD ad-supported playback is on. |
| `vod_ad_supported_deterministic` | **True** | True | VOD pre-roll uses the deterministic placeholder; live `serve_ad` is bypassed. B2/ADV-201 flips this to False — **but see `dev_mode` above: the flip alone is insufficient while dev_mode=True.** |
| `ad_fraud_detection_enabled` | True | True | Fraud gate active on `track_ad_event`. |
| `vod_ad_cpm_cents` | 500 | 500 | Placeholder/house CPM ($5.00). |

**Net for serving today:** newsfeed injection ON-but-empty; VOD pre-roll = deterministic
placeholder (dev_mode + deterministic both force it); broadcast billing off. No real paid
ad reaches a viewer and no real money moves — exactly the simulation the epic converts.

---

## ADV-002 — ad_clicks CPA attribution table

New DDB-Local table `AdClicks` (setting `ad_clicks_table_name`, env `DDB_AD_CLICKS`,
default `AdClicks`). Backs the last-click 7-day CPA window (B4): serve mints a click row,
track updates status, a purchase looks up an unexpired click for the viewer.

- **hash key** `ad_click_id` (S)
- **attributes** (written by the app, not declared at create): `viewer_sub`,
  `campaign_id`, `creative_id`, `content_owner_sub`, `surface`, `created_at`, `status`, …
- **TTL** on `expires_at` (Unix epoch secs) = `created_at + 604800` → 7d auto-expiry
- **GSI `ByViewer`** — `viewer_sub` (S) HASH + `created_at` (N) RANGE, Projection ALL —
  so a purchase can look up an unexpired click for that viewer at conversion time.

### How it is created
- **Dev clone / future re-seeds:** registered in `scripts/local-ddb-init.py`
  (`TableDef` + `_enable_ttl_if_needed`-style `update_time_to_live` on `expires_at`) and
  in `app/core/tables.py` (`T.ad_clicks`) + `app/core/settings.py`
  (`ad_clicks_table_name`). Any `local-ddb-init.py` run now creates it with TTL enabled.
- **Prod (existing DDB-Local @ localhost:8001, no full re-seed):** run the one-shot
  `create_ad_clicks.py` in this folder with the app venv:
  `/home/ubuntu/testlogon/.venv/bin/python ops/prod-hotfixes/adv/create_ad_clicks.py`
  (idempotent; creates the table + GSI if absent, enables TTL on `expires_at`).

### Verified on prod (2026-07-07)
Table created (was absent); `describe_time_to_live` → `ENABLED` on `expires_at`;
put/get round-trip (expires_at ≈ now+7d); GSI `ByViewer` query returns the seeded click;
test row deleted after. Convention matched: `BillingMode=PAY_PER_REQUEST`, GSI Projection
`ALL`, numeric `created_at` (N) — same as the other ad tables in `local-ddb-init.py`.

---

## Fold log

| Ticket | Change | Artifact | Prod applied |
|---|---|---|---|
| ADV-001 | Read prod ad flags via SSM | (this README, flag table) | read-only |
| ADV-002 | Create `ad_clicks` (AdClicks) table + TTL + GSI | `create_ad_clicks.py`; dev-clone reg in settings/tables/local-ddb-init | **yes** — table live on prod DDB-Local |
| ADV-003 | Establish this fold folder + convention | `ops/prod-hotfixes/adv/` | n/a (doc) |
