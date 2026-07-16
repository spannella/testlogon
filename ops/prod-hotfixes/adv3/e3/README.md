# ADV3 EPIC E3 — serving coverage (ADV3-6 / ADV3-7)

Backend live prod hotfix + prod flag/inventory confirmation. Turns the biggest
dark placement on (VOD pre-roll) and makes multi-slot serving a real, diverse,
paced business instead of a single-advertiser monopoly.

Repo: `~/dev/testlogon` @ `android-impl`. Prod EC2 `i-08f937fc705ebea75` (SSM,
DynamoDB Local :8001, stripe-mock :12111, DEV_MODE=1).

---

## ADV3-6 — real serving ON + prove live inventory (C1 / C2 / C3)

**No code change — ops confirmation.** All three facts were verified live on prod:

- **C1 VOD pre-roll flag is OFF.** `VOD_AD_SUPPORTED_DETERMINISTIC=0` is persisted
  in prod `/home/ubuntu/testlogon/.env.local` and present in the live uvicorn
  process env, so `S.vod_ad_supported_deterministic is False`. The decoupled live
  `serve_ad(preroll)` path (`vod_ad_supported.py:_resolve_ad_schedule`) runs; the
  static placeholder is retained ONLY as a no-fill fallback. **Reversible:** set
  `VOD_AD_SUPPORTED_DETERMINISTIC=1` in `.env.local` and restart to revert.
- **C2 broadcast billing is ON.** `S.broadcast_ads_billing_enabled is True`;
  `broadcast_ads.py:449` calls `_charge_broadcast_completion` gated on that flag
  (`:443`) — live breaks charge the advertiser + credit the broadcaster.
- **C3 live inventory exists.** Prod has **48 active campaigns, 24 with an approved
  creative (22 paid-servable + 2 self-promo)** — NOT an empty delivery layer. No
  onboarding follow-up needed.

Proven end-to-end on prod DDB (`adv3_e3_prod_live.py`, zero residue):
`serve_ad(surface="preroll")` returns a REAL paid fill (real active campaign, minted
`ad_click_id`, not the placeholder); a completed pre-roll runs the shipped
`_charge_preroll_completion` → advertiser DEBITED 500c, poster CREDITED 350c (70%
split), idempotent on replay (no double-charge).

## ADV3-7 — fill diversity, pacing, ranked-feed inventory, platform guard (C4/C5/C6/C7)

Four source files patched (idempotent, anchor-checked patchers in this folder):

### `app/services/ad_serving.py`
- **C4 exclusion + deferred mint.** `serve_ad` gains `exclude_campaign_ids` /
  `exclude_account_ids` (per-fetch candidate exclusion) and `defer_ad_click`. When
  deferred it builds the AdClicks item but does NOT write it — the row is stashed
  on `_pending_ad_click` and persisted by the new `commit_ad_click(ad)` only for a
  unit the caller actually keeps. Non-deferred (single-serve) callers persist
  immediately, unchanged.
- **C5 pacing.** New `_passes_pacing(campaign)`: for a DAILY-budget campaign,
  compares fraction-of-UTC-day-elapsed vs fraction-of-daily-budget-spent; at/under
  pace (plus `ad_pacing_slack`, default 0.15) it serves, ahead of pace it serves
  with probability `expected/actual` — spreading spend across the day instead of
  front-loading. Lifetime budgets + pacing-disabled always pass. Fails open.
- **C7 platform guard.** `RESERVED_AD_CREATOR_IDS = {"platform"}`; when the
  standalone `creator_id` is reserved, `serve_ad` uses force-permissive settings
  (`allow_ads=True`) instead of `get_creator_ad_settings("platform")`, so a stray
  admin write to the reserved pseudo-creator can never darken all standalone fill.

### `app/routers/newsfeed.py`
- **C4** `_inject_sponsored_posts` threads already-won campaign ids so each slot
  draws a DISTINCT advertiser; `_fetch_sponsored_post` serves with
  `defer_ad_click=True` and commits only on keep (a hidden/no-fill spin leaves no
  orphan).
- **C6** the ranked `GET /feed/for-you` branch now calls `_inject_sponsored_posts`
  (previously only chronological `GET /feed` monetized). `GET /feed/interesting`
  is documented as intentionally unmonetized (it returns a bare post_id list, not a
  rendered feed).

### `app/services/shop_ads.py` and `app/services/sponsored_feed.py`
- **C4** the shop `serve_shop_sponsored` loop and the `sponsored_feed` group /
  syndicate inject loops thread won-campaign exclusion + `defer_ad_click` and
  commit only on keep. A 3-unit shop fetch that previously spun `range(limit*3)`
  and minted up to 9 `served` rows now mints exactly the rows returned.

### Orphan cleanup
`orphan_sweep.py` deletes expired `served` AdClicks rows (belt-and-suspenders vs
the enabled `expires_at` TTL). Prod run: 232 rows / 127 served / **0 expired
orphans** (TTL keeps up; deferred mint prevents new ones).

---

## Apply (idempotent, anchor-checked, atomic per file)

Each `patch_*.py` does exact-string replacements, asserts every anchor is unique
(count==1) and aborts BEFORE writing otherwise. `ad_serving.py`, `shop_ads.py`,
`sponsored_feed.py` were byte-identical dev↔prod; `newsfeed.py` DIVERGES on prod
(line offsets) but all four anchor blocks matched, so the same patcher applied.

```
cd /home/ubuntu/testlogon
TS=$(date +%s)
for p in app/services/ad_serving.py app/routers/newsfeed.py \
         app/services/shop_ads.py app/services/sponsored_feed.py; do
  sudo cp $p $p.bak_adv3e3_$TS
done
sudo -u ubuntu python3 patch_ad_serving.py
sudo -u ubuntu python3 patch_newsfeed.py
sudo -u ubuntu python3 patch_shop_ads.py
sudo -u ubuntu python3 patch_sponsored_feed.py
for p in .../ad_serving.py .../newsfeed.py .../shop_ads.py .../sponsored_feed.py; do
  sudo chown ubuntu:ubuntu $p; sudo -u ubuntu python3 -m py_compile $p; done
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh
curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/openapi.json   # 200
```

Prod backups: `*.bak_adv3e3_1784133796` (4 files).
Dev backups:  `ad_serving 1784132805 · newsfeed 1784132879 · shop_ads 1784132928 · sponsored_feed 1784133012`.

## Verify

- `adv3_e3_verify.py` — moto in-process, controlled inventory, ZERO prod-DDB
  residue. **15/15 PASS** on dev (T1 diversity/exclusion, T2 deferred mint+commit,
  T3 non-defer regression, T4 reserved-platform fill guard + disable control,
  T5 daily-budget pacing).
- `adv3_e3_prod_live.py` — LIVE prod DDB, real inventory, explicit cleanup.
  **21/21 PASS**, cross-table residue audit = 0.

### Placement serve matrix (live prod)

| Placement / surface | Before | After (this epic) |
|---|---|---|
| VOD pre-roll | static placeholder, bills nobody | REAL paid `serve_ad` fill; completion charges CPM + credits poster (350/500 = 70%) |
| Broadcast live break | — | billing flag ON; `_charge_broadcast_completion` fires |
| Newsfeed `GET /feed` (chronological) | injected, top bidder monopoly, orphan rows | injected, DISTINCT advertisers, rows==units |
| Ranked `GET /feed/for-you` | never injected | injects sponsored (distinct advertisers) |
| `GET /feed/interesting` | never injected | documented unmonetized (id-list, not a feed) |
| Shop search/browse | up to 9 `served` rows per 3 units, monopoly | ≤3 rows == units, distinct advertisers |
| Group / syndicate feeds | monopoly, orphan rows | distinct advertisers, rows==units |
| Standalone `creator_id="platform"` | a stray config could dark ALL fill | reserved id force-permissive (cannot be darkened) |
