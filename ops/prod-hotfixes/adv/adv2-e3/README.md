# ADV2-E3 (F3) self-advertising = free "promote my content" — LIVE PROD HOTFIX

Backend tickets ADV2-301..305. Self-advertising is a PER-CAMPAIGN toggle (D2):
a creator runs a FREE `is_self_promo` campaign to promote their OWN content.
Cost 0 — NO charge, NO balance debit, NO revenue split/credit. Bypasses the
self-ad-exclusion ONLY for the creator's own content (slot content_owner ==
the campaign's ad-account owner); never serves on another creator's content nor
as a standalone unit. Mode: `always_win` (self-promo always wins the own slot,
may displace a paid ad) vs `fill_only` (serve only when no paying ad is eligible).

## Contracts
- `CampaignCreateIn`/`CampaignUpdateIn`/`CampaignOut`: `is_self_promo: bool`,
  `self_promo_mode: fill_only|always_win`. Self-promo forces bids=0 and relaxes
  the `budget_cents >= 100` floor (no funding).
- `create_campaign`: persists the flavor; a self-promo AUTO-ACTIVATES (skips
  pending_review) and zeroes bids; paid campaigns unchanged (draft).
- `POST /ui/ads/accounts/{id}/campaigns`: a self-promo needs no active/funded
  ad account; paid still requires an active account.
- `serve_ad`: self-promo eligible ONLY when `content_owner_id == account.owner_sub`;
  bypasses self-exclusion / min-CPM / budget / category for that case (keeps
  fraud + frequency cap). Precedence: always_win self-promo > paid auction >
  fill_only self-promo > house. A self-promo win clears price 0 and mints
  AdClicks `self_promo=True, effective_price_cents=0`.
- CHARGE SHORT-CIRCUIT on the minted `self_promo` flag across every entry point:
  `ad_serving.track_ad_event` (newsfeed/group/syndicate impression+click),
  `ad_serving.record_cta_click` (CPC), `broadcast_ads._charge_broadcast_completion`
  (pre/mid-roll, BEFORE the 500c floor), `vod_ad_supported._charge_preroll_completion`
  (BEFORE the 500c floor), `ad_attribution.attribute_conversion` (CPA). No ledger
  row, debit nobody, credit nobody.

## Files patched (dev clone + prod /home/ubuntu/testlogon)
app/models.py, app/services/ad_campaigns.py, app/routers/ads.py,
app/services/ad_serving.py, app/services/broadcast_ads.py,
app/services/vod_ad_supported.py, app/services/ad_attribution.py

## PROD apply
- `apply_adv2e3.py <ROOT>` — idempotent, anchored, verbatim (anchors verified on
  prod == dev before apply). PROD backups: `*.bak_adv2e3_1783555104`.
- Restart: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`; openapi 200.

## VERIFY (in-process on PROD DDB) — 25/25 PASS
`verify_adv2e3.py` (isolated via a unique category whitelist). Proved: self-promo
(no funding) serves in front of the creator's OWN content; serve+impression+click+CTA
= ZERO ad_billing ledger rows, advertiser balance 0 (no debit), creator credited
nothing; always_win beats a funded paid advertiser (advertiser NOT charged);
fill_only yields to paid (paid wins @ second-price 50c); self-promo never serves
on a different creator's content nor standalone; a creator PAID campaign is
self-excluded from their own view but serves to other viewers.
