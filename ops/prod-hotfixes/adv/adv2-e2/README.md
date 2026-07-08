# ADV2-E2 (F2) — In-video / live click-through CTAs (BACKEND, ADV2-201..206)

LIVE PROD HOTFIX (EC2 `i-08f937fc705ebea75` via SSM) + mirrored to the dev clone.
Money-path. Adds structured click-through CTA targets to the ad creative/serve,
a CTA-click endpoint that charges CPC (except tip), and threads the existing
last-click CPA attribution for a resulting purchase/subscribe.

## Contracts

### CTA target model (ADV2-201)
`CtaActionIn { cta_type, target_id, label }` where
`cta_type ∈ {buy_product, view_product, tip, subscribe, subscribe_other}`.
Added `ctas: List[CtaActionIn]` (max 8) to `CreativeCreateIn` / `CreativeUpdateIn`;
`create_creative` persists `ctas` (list of dicts) onto the creative row;
`update_creative` carries it via `model_dump`.

### Serve carry (ADV2-202/203/204)
`serve_ad` output now includes `"ctas": creative.get("ctas") or []`, carried into:
- VOD pre-roll — `vod_ad_supported._resolve_ad_schedule` persists `ctas` on each
  schedule entry + `_session_to_dict` surfaces `ad_click_id` + `ctas`; DTO
  `VodAdBreak` gained `ad_click_id` + `ctas`.
- Broadcast pre-roll + mid-roll — `broadcast_ads.build_pre_roll` /
  `build_mid_roll` payloads + router `PreRollOut` / `MidRollOut` gained `ctas`.
- Newsfeed / group / syndicate sponsored units — `sponsored_feed.build_sponsored_unit`,
  `_to_syndicate_shape`, `newsfeed` main injection + `SyndicatePostOut` +
  `AdServeResponseOut` gained `ctas`.

### CTA click endpoint (ADV2-201) — the new money path
`POST /ui/ads/cta-click` body `CtaClickIn { ad_click_id, cta_type, target_id? }`
→ `ad_serving.record_cta_click`:
- Records the tap on the AdClicks row (`last_cta_type` / `last_cta_target` /
  `cta_clicked_at`) for last-click attribution / analytics.
- **Charges CPC** via `ad_billing.charge_click` (funds-guarded), idempotency key
  `{ad_click_id}#cta#{cta_type}` — repeat = 0 extra charge. Placement split
  unchanged (`creator_id = content_owner_sub`: in front of a creator → creator
  share; standalone → platform).
- **tip → NO advertiser charge** (`CTA_NO_ADVERTISER_CHARGE = {"tip"}`), returns
  `reason="tip_no_advertiser_charge"`. A tip CTA deep-links to the creator tip
  flow; the viewer tips the creator as normal creator earnings.

### Conversion / CPA (ADV2-205/206)
No new money code: `buy_product` / `subscribe` / `subscribe_other` carry the
`ad_click_id` into the ALREADY-SHIPPED conversion path (cart `CartPurchaseIn` /
subscribe `SubscribeIn` / unlock → `ad_attribution.attribute_conversion`, CPA
`bid_cpa_cents`, idempotent `{ad_click_id}#conversion`). `view_product` is
nav-only (CPC on tap, no CPA). Tip fires NO advertiser conversion.

## Files (9)
app/models.py, app/services/ad_creatives.py, app/services/ad_serving.py,
app/routers/ads.py, app/services/broadcast_ads.py, app/routers/broadcast_ads.py,
app/services/vod_ad_supported.py, app/services/sponsored_feed.py,
app/routers/newsfeed.py

## Apply / prod
`ROOT=/home/ubuntu/testlogon python3 apply_adv2e2.py` — idempotent, anchor-matched
(runs on the divergent dev clone AND prod; models.py / broadcast_ads.py /
vod_ad_supported.py / newsfeed.py all diverge on prod — every anchor confirmed
verbatim). Prod backups: `*.bak_adv2e2_1783550466`. Restarted, openapi 200,
`/ui/ads/cta-click` registered in openapi.

## Verify — in-process on PROD DDB via SSM (`verify_adv2e2.py`): OVERALL ALL_PASS (10/10)
- ADV2-201 creative persists 5 ctas (buy_product/view_product/tip/subscribe/subscribe_other).
- ADV2-202 a served ad carries the 5 CTA targets (own campaign won the auction).
- CTA tap (buy_product) → advertiser CPC debit 1234¢ (funds-guarded); repeat →
  0¢ (idempotent, reason=duplicate).
- Placement split: creator credited 863¢ (70% of the 1234¢ CPC) — split unchanged.
- buy_product purchase carries ad_click_id → CPA 5678¢ fires + attributed.
- subscribe tap → CPC 1234¢, then subscription → CPA 5678¢ attributed.
- tip CTA → advertiser delta 0 (reason=tip_no_advertiser_charge); the click is
  NOT marked converted (no CPA on tip).
