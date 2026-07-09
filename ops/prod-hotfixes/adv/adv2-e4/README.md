# ADV2-E4 (F4) — Sponsored-as-creator posts (advertiser-drafted, creator-approved)

LIVE PROD HOTFIX via SSM. Backend ADV2-401..406. Rail B (engagement ad-money-path).

## What ships
- NEW `app/services/sponsored_creator_posts.py` — proposal model + store (reuses the
  `sponsorship_deals` DDB table with a DISTINCT key space `SPCP#{id}` + isolated GSI
  partitions `SPCP_CREATOR#` (review queue) / `SPCP_ADV#` (outbox) so it never mixes
  with ADS-013 brand deals). create_proposal / list_pending_for_creator /
  list_for_advertiser / approve_and_publish / reject_proposal / mint_post_ad_click +
  the reusable `_persist_post(author_id != caller)` publish tail (ADV2-402).
- `app/routers/ads.py` — 6 endpoints under /ui/ads/sponsored-posts/*:
  POST proposals (advertiser draft), GET proposals/inbox (creator queue),
  GET proposals/outbox, POST proposals/{id}/approve, POST proposals/{id}/reject,
  GET {post_id}/placement (per-viewer ad-click mint -> track handles).
- `app/routers/newsfeed.py` — `_post_to_dict` additive paid_partnership fields (ADV2-403).

## DISTINCT flag (NOT is_sponsored)
An approved post is authored_by the CREATOR (user_id=creator) and carries
`paid_partnership`/`promoted_by_advertiser` + `sponsor_account_id` + `content_owner_id`.
It deliberately does NOT set `is_sponsored`, so it stays a NORMAL creator post:
tippable/likeable/commentable, normal engagement bar, NO forced "Sponsored" label (D3).
The flag drives advertiser BILLING + attribution + analytics only.

## Billing (Rail B, funds-guarded, idempotent)
On feed-read a per-(viewer,post) AdClicks row is lazy-minted (surface=
`sponsored_creator_post`, content_owner_sub=creator). An impression/click through
/ui/ads/track charges the advertiser via ad_billing (CPM/CPC) and credits the creator
the placement share (~70/30) as type:"credit". A viewer TIP still credits the creator
(distinct flag — not blocked). Only the targeted creator can approve; reject/pending
never publish.

## Apply / verify
- apply_adv2e4.py  — idempotent anchored patch (ROOT env/argv). Runs on dev clone + prod.
- verify_adv2e4.py — in-process money-path verify (self-seeds funded advertiser + creator
  + viewer). Prod DDB via SSM: OVERALL ALL_PASS 33/33.
- Prod .bak: app/routers/ads.py.bak_adv2e4_1783558291,
  app/routers/newsfeed.py.bak_adv2e4_1783558291. Restart openapi 200.

## Residual
- App slice ADV2-407..409 (advertiser draft composer / creator approval queue / render)
  + ADV2-410 2-device — separate task (backend-only here; no app change).
- create_post itself keeps its rich inline build; the reusable publish-as-creator tail
  is `sponsored_creator_posts._persist_post` (used by approve_and_publish).
- Pre-existing/orthogonal: charge_tip with a NULL payment method raises a DDB
  TransactWriteItems type edge (real viewers have a funded PM). Verify 8b proves the
  paid_partnership tip is NOT ad-blocked (got past the guard); 8c proves is_sponsored IS
  blocked (400). charged_cents=0 cosmetic on ad_clicks row carries over from prior slices.
