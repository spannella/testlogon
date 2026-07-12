# ADV-B2 (ADV-201 + ADV-203) prod hotfix — VOD pre-roll live serve + completion billing

LIVE PROD HOTFIX applied to EC2 i-08f937fc705ebea75 via SSM on 2026-07-08.

## What changed
- **ADV-201 (gate decouple + live pre-roll serve)** `app/services/vod_ad_supported.py`
  - `_resolve_ad_schedule`: `deterministic = flag OR dev_mode` -> `deterministic = flag` ONLY
    (platform runs DEV_MODE=1 everywhere; ORing dev_mode forced the placeholder forever).
  - live `serve_ad(surface="preroll", content_owner_id=video.id-owner)` mints an AdClicks row
    (surface=preroll, content_owner_sub = the VIDEO poster); schedule break carries `ad_click_id`.
  - fixed a latent bug surfaced by first-ever live run: `video.video_id` -> `video.id`.
  - flag flip: `.env.local` `VOD_AD_SUPPORTED_DETERMINISTIC=0` (DEV_MODE stays 1).
- **ADV-203 (completion charge + poster credit, idempotent)**
  - `vod_ad_supported.report_break`: on a completed PAID pre-roll (ad_click_id present, on the
    completion transition only) -> `_charge_preroll_completion` reads the AdClicks row and runs the
    funds-guarded `ad_billing._process_charge` (CPM = effective_price_cents; entry_type
    impression_charge) which debits the advertiser and `_split_revenue` credits the video POSTER
    (~70%) + platform (~30%). Idempotent per ad_click_id.
  - `ad_billing._process_charge` / `charge_impression`: new optional `idempotency_key` -> a marker
    conditional-put (sk=IDEMP#{key}) claimed BEFORE the debit; duplicate -> {ok, reason:duplicate};
    released on insufficient_funds so a funded retry still charges once.
  - Reconciliation (no double-credit): `ad_placement.record_ad_impression` new `credit_revenue`
    flag; `report_break` passes `credit_revenue=not ad_click_id` so the legacy phantom-CPM credit
    is suppressed for paid pre-rolls (poster credited from real ad spend instead).

## Apply order (idempotent patchers, run under prod repo root /home/ubuntu/testlogon)
1. `python3 apply_advb2.py <root>`   (vod_ad_supported.py gate/serve/completion + ad_billing.py idempotency)
2. `sed -i "s/video\.video_id/video.id/g" app/services/vod_ad_supported.py`
3. `python3 apply_advb2_2.py <root>` (ad_placement credit_revenue flag + report_break wiring)
4. set `VOD_AD_SUPPORTED_DETERMINISTIC=0` in `.env.local`; keep `DEV_MODE=1`
5. `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`; verify openapi.json == 200

## Backups on prod
- `app/services/vod_ad_supported.py.bak_advb2_1783477605`, `.bak_advb2b_1783477955`, `.bak_advb2c_1783478116`
- `app/services/ad_billing.py.bak_advb2_1783477605`
- `app/services/ad_placement.py.bak_advb2c_1783478116`
- `.env.local.bak_advb2_1783477631`

## Prod E2E evidence (video v_advb2_6a4db795, poster advb2_poster_6a4db795, campaign camp_bb03c5bf728f / account adacct_fe7cd67dd715, bid_cpm=800)
- serve: pre-roll break creative cr_7d4935af1073 (image), ad_click_id c460c93d26ed40cca92515e1397baa03,
  AdClicks surface=preroll content_owner_sub=poster eff_price=800.
- complete #1: advertiser 499100 -> 498300 (debited 800, funds-guarded); poster credit type=credit
  amount=560 reason "Ad revenue share" model=cpm surface=preroll ad_click_id match; platform 240.
- idempotent: dup report_break extra_debit=0; direct dup -> reason=duplicate, extra_debit=0.
- no double-credit: legacy 1c phantom credit suppressed (poster has exactly one 560 credit).

## Pre-existing dev<->prod divergence NOT touched by this hotfix
- `ad_billing._split_revenue` creator credit entry_type: prod writes `"credit"`, dev clone writes
  `"ad_revenue_credit"` (both -> ledger field `type`). Left as-is (outside ADV-B2 scope).
