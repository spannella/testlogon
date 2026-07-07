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

---

## ADV-B1 — real funding + serving + newsfeed sponsored fields (ADV-101..104)

Live prod hotfix applied 2026-07-07 via SSM against `/home/ubuntu/testlogon`.
Re-apply artifact: **`apply_advb1.py`** (idempotent, marker-skip, makes a
`.bak_advb1_<ts>` per file). Seed + money-path verifier: **`seed_verify_advb1.py`**.

Re-apply:  `/home/ubuntu/testlogon/.venv/bin/python apply_advb1.py /home/ubuntu/testlogon`
then restart the backend. Verify: load env + `PYTHONPATH=<root>` then run
`seed_verify_advb1.py` → `OVERALL ALL_PASS`.

### Changes
- **ADV-101** `ad_billing.deposit_funds` now CHARGES `payment_method_id` via a
  stripe-mock PaymentIntent (`_charge_deposit`, mirrors `tips._charge_tip`:
  `off_session=True, confirm=True, idempotency_key="addep:{acct}:{amt}:{pm}"`)
  BEFORE any ledger/balance write. Decline/processor-error → `HTTPException(402)`,
  no ledger row, no balance credit. The `budget_deposit` ledger meta now records
  `stripe_payment_intent_id`. stripe-mock nuance handled exactly like TIP-101
  (accept the created intent unless canceled/payment_failed when `stripe_api_base`
  is overridden; real Stripe still requires `succeeded`; real CardError declines).
- **ADV-102** `ad_billing._process_charge` debits the balance FIRST under
  `ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt"`;
  on `ConditionalCheckFailedException` it returns
  `{"ok": False, "reason": "insufficient_funds"}` and writes NOTHING (no ledger,
  no campaign-spend bump, no revenue split). Balance can never go negative.
- **ADV-103** `ad_serving.serve_ad` mints a per-serve `ad_click_id` (uuid) and
  writes an `AdClicks` row (`viewer_sub`, `campaign_id`, `account_id`,
  `creative_id`, `content_owner_sub`, `surface`, `slot_type`, `content_id`,
  `status="served"`, `effective_price_cents`=winning bid placeholder, `created_at`,
  `expires_at`=now+7d TTL). New kwarg `content_owner_id` (default "") carries the
  content owner; response + tracking URLs now include `ad_click_id`, and the
  response also carries `account_id` + `content_owner_id`. House-ad path mints
  nothing. `AdServeRequestIn` gains `content_owner_id`; `ads.py` /serve passes it.
- **ADV-104** `newsfeed._fetch_sponsored_post` surfaces `account_id`,
  `ad_click_id`, `content_owner_id` into the injected sponsored dict (already had
  is_sponsored/creative/campaign/cta/impression+click urls). Feed returns raw
  dicts (no response_model), so the fields reach the app.
- **B0 prod-registration gap closed:** B0 created the physical `AdClicks` table on
  prod but only registered `T.ad_clicks` / `ad_clicks_table_name` on the dev clone.
  This hotfix folds that registration into prod `app/core/tables.py` +
  `app/core/settings.py` (dev clone already had it → marker-skip).

### Verified on prod (2026-07-07, seed_verify_advb1.py → ALL_PASS)
- ADV-101: deposit $5000 → PaymentIntent created + balance 0→500000 + ledger meta
  carries the PI id; declined charge (CardError→402) → balance unchanged.
- ADV-102: over-balance charge → `insufficient_funds`, balance unchanged (>=0);
  a legitimate small charge still debits atomically.
- ADV-103: two serves mint distinct ad_click_ids; `AdClicks` row present with
  `status=served`, `expires_at≈now+7d`; `content_owner_id` carry verified.
- ADV-104: injected sponsored dict carries is_sponsored/campaign/account_id/
  ad_click_id/content_owner_id/cta/impression+click urls.
- Seeded funded+approved campaign left live for the app tickets:
  account `adacct_6ad6af06389d`, campaign `camp_e976f3150eb6`, creative `cr_756bf247c1f7`.

### Prod .bak files
`ad_billing.py`/`ad_serving.py`/`newsfeed.py`/`models.py`/`ads.py` →
`*.bak_advb1_20260707_225618`;  `settings.py`/`tables.py` →
`*.bak_advb1_20260707_230210`.

## Fold log (B1)

| Ticket | Change | Artifact | Prod applied |
|---|---|---|---|
| ADV-101 | deposit_funds charges PM (stripe-mock PI) before credit | `apply_advb1.py` (ad_billing.py) | **yes** |
| ADV-102 | funds-guard ConditionExpression on _process_charge | `apply_advb1.py` (ad_billing.py) | **yes** |
| ADV-103 | serve_ad mints ad_click_id + AdClicks row + content_owner | `apply_advb1.py` (ad_serving.py, models.py, ads.py) | **yes** |
| ADV-104 | newsfeed injection surfaces ad_click_id/account_id/content_owner | `apply_advb1.py` (newsfeed.py) | **yes** |
| ADV-002-fix | register T.ad_clicks on prod (B0 gap) | `apply_advb1.py` (settings.py, tables.py) | **yes** |
