# TestLogon Advertising v2 — Implementation Plan & Ticket Breakdown

Status: PLAN (for review). Author: grounded in a read-only re-read of the ad code on dev host `192.168.0.249` (`~/dev/testlogon`, `android-impl` @ `f2e2ede6`), 2026-07-08.

Scope: **7 new advertiser/creator monetization features built ON TOP of the now-live core ad system** (v1 turned the simulation into a real ad business: real funding, second-price auction, real charging via `_process_charge`, attribution via `AdClicks`/`ad_attribution`, creator revenue split via `_split_revenue`, prod-verified 31/31). v2 does NOT rebuild any money engine — every feature reuses `serve_ad` + `AdClicks` + `_process_charge` + `_split_revenue` + the shipped attribution.

> Prod (EC2 `i-08f937fc705ebea75`) diverges from this dev clone. Every backend change lands as an `android-impl` commit AND (for anything already live) an anchor-matched, idempotent re-apply artifact under `ops/prod-hotfixes/adv/`. Verify prod feature flags via the SSM PROD-ACCESS pattern before/after. Two-device on-device verification per user-facing ticket (Galaxy A15 = record device; Pixel 7a `screenrecord` is broken; admin acct `crash1782189692@`).

The 7 features:
- **F1** live-stream ad breaks (host-triggered mid-roll)
- **F2** in-video / live click-through CTAs (buy/tip/subscribe/product)
- **F3** self-advertising (free own-content promo, per-campaign toggle)
- **F4** sponsored-as-creator posts (advertiser-drafted, creator-approved)
- **F5** sponsored mass-messaging (creator on behalf of advertiser)
- **F6** advertiser direct mass-DM
- **F7** syndicate advertising (syndicate-level advertiser + cross-member serving + split)

Ticket id scheme: `ADV2-1xx`=F1, `2xx`=F2, `3xx`=F3, `4xx`=F4, `5xx`=F5, `6xx`=F6, `7xx`=F7. Effort: S≈≤1d, M≈2-4d, L≈1wk+.

---

## LOCKED USER DECISIONS (build to these — do not re-litigate)

- **D1 — advertiser direct mass-DM audience** = ONLY an existing relationship (the user follows/subscribes to the advertiser, or has explicitly opted into ad messages) + honor a per-user AD OPT-OUT. Never broad cold-DM. (Governs F6, and F5's audience.)
- **D2 — self-advertising inventory** = a PER-CAMPAIGN TOGGLE: `fill_only` (serve the free self-promo in the creator's own slots ONLY when no paying advertiser is eligible) vs `always_win` (self-promo always wins the creator's own-content slots). Free = cost 0, no balance debit, bypasses self-ad-exclusion for the creator's own content. (Governs F3, reused by F7-B6.)
- **D3 — sponsored-as-creator posts + sponsored mass-messaging** = the creator MUST APPROVE before it goes out; NO forced sponsorship label (creator/advertiser choose the wording). (Governs F4, F5.)
- **D4 — ad-messaging billing** = HYBRID: charge the advertiser a base amount per message DELIVERED, PLUS an additional charge on OPEN/CLICK (so something is charged just for sending, more if engaged). For sponsored-via-creator the creator earns a placement share. (Governs F5, F6.)

D1-D4 do NOT cover F1, F2, or F7's split/funding — those carry their own open decisions (see the per-feature "Decisions needed" and the consolidated 2nd-pass list).

---

## Existing ad infra to REUSE (the money engine — do not rebuild)

- `app/services/ad_serving.py` — `serve_ad` (`:61`): 2nd-price auction, mints `ad_click_id` into `AdClicks` (`:214-243`, `content_owner_sub` at `:227`), self-ad-exclusion `account.owner_sub == user_id` (`:107-116`), `allow_ads` gate (`:92-95`), targeting `creator_ids`/`exclude_creator_ids` via `ad_targeting.evaluate_targeting` (`:154-161`); `track_ad_event` billable block (`:378-441`, reads `content_owner_sub` `:403`).
- `app/services/ad_billing.py` — `_process_charge` (`:211`, funds-guarded conditional debit + `IDEMP#{key}` marker + budget bump, idempotent); `charge_impression`/`charge_click`/`charge_conversion` (`:157/:173/:188`); `_split_revenue` (`:325`, content_owner present → creator ~70% (`get_creator_revenue_share_bps`) + platform 30%, absent → platform 100%).
- `app/services/broadcast_ads.py` — `serve_broadcast_ad` (`:56`), `build_pre_roll` (`:114`), `start_ad_break`/`end_ad_break`/`schedule_ad_break_end` (`:160/:188/:197`), `_charge_broadcast_preroll_completion` (`:218`, broadcaster 70/30, idempotent `broadcast_preroll:{ad_click_id}`); `broadcast_ads_billing_enabled=1`.
- `app/services/ad_attribution.py` — `attribute_conversion` (last-click 7d over `AdClicks`, placement-aware); already attached to subscribe / cart / post-unlock (ADV-405).
- `app/services/sponsored_feed.py` — group/syndicate standalone injector.
- `creator_earnings` (`type:"credit"` shows in earnings; `state != reversed` excluded), `creator_payouts`.
- `app/services/sponsorship_deals.py` (605 lines, ADS-013) — full brand-deal lifecycle + escrow + FTC label + deal DM (F4 extends this).
- Mass-message engine: `app/routers/messaging.py` (`create_mass_message_campaign:805`, worker `run_mass_message_immediate_worker:594`, `_process_mass_message_destination:493`, `_send_mass_message_destination:5100`, `find_or_create_dm:6316`, receipts `:4964/:5008/:5022`, `_get/_put_message_privacy:6200/6214`) + `mass_message_campaigns.py` + `mass_message_campaign_destinations.py` + `models_mass_message.py` (`kind: Literal["text"]` — confirmed text-only).
- `app/services/syndicate_revenue_split.py` — `execute_split` (`:161`, per-member `type:"credit"` + `apply_wallet_delta` `:288`, invariant-checked), `get_split_config` (`:61`), `get_member_earnings` (`:347`); `syndicate_treasury.spend_on_advertising` (`:355`).
- App: `DetailAdAwarePlayer`/`AdSupportedPlayerViewModel`/`AdOverlay` (VOD pre-roll), `BroadcastPreRollPlayer`, `SponsoredFeedCard` (no-tip), `AdClickAttributionStore`, `AdTrackRepository`, ads create screens, `feature/messaging/mass/*`, `feature/sponsorship/*`, `feature/syndicates/campaign/*`.

---

# F1 — Live-stream ad breaks (host-triggered mid-roll)

## Design
The mid-roll **control plane already ships end-to-end** (web-parity B2/AND-316): host trigger button, `POST .../ad-break` + `.../ad-break/end`, session state machine (`ad_break_active`/`ad_break_started_at`/`total_ad_breaks`), SSE `ad_break:start` fan-out, kill-switch `broadcast_midroll_enabled`, auto-end scheduler. **But the break serves no creative, bills nobody, and no viewer surface reacts.** F1 wires the proven pre-roll monetization path (`serve_broadcast_ad` → mint `ad_click_id` → `record_ad_event` → `_charge_broadcast_preroll_completion`) into the shipped trigger, and builds the viewer-side interrupt/resume. Two hard constraints from the codebase: (a) a single host trigger fanning to all viewers cannot carry a per-viewer `ad_click_id` → a **new per-viewer serve endpoint** is required; (b) SSE is unreliable on-device (app viewer already uses a chat POLL fallback) → detection must be **poll-based** off the persisted break state. Live media keeps running server-side; mid-roll is a **client-side overlay** convention (ad viewers miss that segment; ad-free viewers keep watching).

## Tickets
- **ADV2-101 (M, BE)** — New `POST /broadcast/sessions/{id}/ad-break/serve` (viewer). Add `build_mid_roll(session, viewer_id)` mirroring `build_pre_roll` (`broadcast_ads.py:114`) but `surface="broadcast_midroll"`, `slot_type="broadcast_midroll"`; returns creative + `ad_click_id` + `skip_after_seconds` (`mid_roll_skip_after_seconds`) + break `remaining_seconds`. Honor `is_ad_free` (`broadcast_ads.py:37`), `broadcast_midroll_enabled`, require `ad_break_active`. Register on the existing `broadcast_ads` router. Deps: none.
- **ADV2-102 (S, BE)** — Correct billing surface labeling: parametrize `_charge_broadcast_preroll_completion(surface=...)` (`broadcast_ads.py:218`) → idempotency `broadcast_midroll:{ad_click_id}` + meta `surface=broadcast_midroll`. NOTE: the `record_ad_event` billing block already charges on any `impression|complete` + `ad_click_id` regardless of slot, so once ADV2-101 mints the row this **largely works already** — this is correctness/labeling. Broadcaster 70/30 falls out of `_split_revenue` (content_owner present). Deps: ADV2-101.
- **ADV2-103 (S, BE)** — Poll-detectable break state: GET `.../ad-config` already returns `ad_break_active`/`ad_break_started_at`/`total_ad_breaks`; add `remaining_seconds` (or a lighter `GET .../ad-break/state`) so the viewer poll is cheap. Deps: none.
- **ADV2-104 (S, BE)** — Anti-abuse guardrails in `trigger_ad_break_route` (`broadcast_ads.py:194`): min interval between breaks + max breaks/session (config-driven, see DEC D-F1-d). Deps: none.
- **ADV2-105 (M, APP)** — Viewer mid-roll interrupt/resume in `ViewerViewModel.kt`: bounded poll while `Ready` (reuse ~2s chat-poll cadence) reading ad-config/state; on `ad_break_active` → new `ViewerUiState.MidRoll` → call `/ad-break/serve` → pause live `VideoPlayerController` → render `AdOverlay` (reuse `BroadcastPreRollPlayer`) → fire `impression`; on complete/skip/break-end → resume live (seek to live edge, re-mint if URL expired). Extend `BroadcastViewerAdApi` with `serve` + mid-roll DTO + `slot_type="mid_roll"` track. Mirror `enterPreRoll`/`onPreRollCompleted`. Deps: ADV2-101, ADV2-103.
- **ADV2-106 (S, APP)** — Surface "Start ad break" (+ active countdown / End early) on the primary live `HostControlScreen.kt`, not only the sub AdControl screen; reuse `AdControlViewModel.triggerAdBreak` (`:142`). Deps: none.
- **ADV2-107 (S, APP)** — Confirm broadcaster's own host preview + ad-free subscribers are never interrupted (falls out of BE `is_ad_free`/no-fill); add client guard. Deps: ADV2-105.
- **ADV2-108 (M, VERIFY)** — 2-device prod verify (reuse `seed_ad_demo.py` Acme/Bella/demo-viewer): host triggers break on the watched live → viewer interrupted with Acme creative → advertiser debited CPM + broadcaster credited 70/30 with `surface=broadcast_midroll`, idempotent per `ad_click_id`; ad-free subscriber NOT interrupted; broadcaster self-excluded; live resumes on end. Record on A15. Deps: all F1 BE+APP.

## Acceptance criteria (money-path)
- Each ad-viewer of a break gets exactly one served creative and one minted `ad_click_id`.
- Advertiser debited CPM once per served completion; **idempotent** on `broadcast_midroll:{ad_click_id}` (retry = no double charge).
- Broadcaster credited 70% (`type:"credit"`, appears in earnings), platform 30%, via `_split_revenue` (content_owner=broadcaster).
- Self-promo/self-exclusion: broadcaster never billed/credited for their own preview; ad-free subscribers never interrupted, never billed.
- No-fill or unfunded advertiser → per DEC D-F1-b (house creative vs stay-live) — no negative balance (funds-guard in `_process_charge`).

## Decisions needed (F1-specific, beyond D1-D4)
- **D-F1-a** post-skip: resume live immediately vs hold a "back shortly" slate until host ends. (Rec: resume-immediately.)
- **D-F1-b** no-fill/unfunded during break: free house creative vs keep viewer live. (Rec: keep live.)
- **D-F1-c** break duration source: fixed `mid_roll_ad_break_duration_seconds` vs served-creative length driving auto-resume.
- **D-F1-d** guardrail values for ADV2-104 (min seconds between breaks, max breaks/session).
- **D-F1-e** confirm overlay-only semantics (live encode keeps running underneath; not a true server-side splice) acceptable for launch.

---

# F2 — In-video / live click-through CTAs

## Design
Today a creative carries exactly one `cta_text`+`cta_url`, http(s)-only (`app/models.py:4834-4906`, validator `:4850-4862`) — no CTA type, no in-app deep-link, no multi-CTA. `serve_ad` already emits `cta_text`/`cta_url`/`click_url`/`ad_click_id` (`ad_serving.py:257-280`) and the **newsfeed sponsored CTA is fully wired** (reference pattern: `FeedViewModel.onSponsoredClick:398-403` → `record` + `track(CLICK)`, `FeedScreen.kt:221-223` opens URL). Conversion attribution is COMPLETE (subscribe/cart/unlock all attach `ad_click_id`, ADV-405). Gaps: VOD pre-roll DROPS the CTA (`vod_ad_supported.py:159-172`), `AdOverlay` renders no tappable CTA, no CLICK path for pre-roll (`report_ad_break` accepts only impression|complete|skip, and `/ui/ads/track` click is surface-gated to skip pre/mid-roll to avoid double-charge), broadcast pre-roll carries CTA but reuses the CTA-less overlay, single external-URL only, tip is not a conversion type.

**Approach:** author CTAs on the creative as a typed ordered list (`CtaAction = {type, label, target}`, `type ∈ {buy, add_to_cart, view_product, subscribe, tip, profile, external}`); keep legacy single CTA as a back-compat `external`. On tap in any player: `record(ad_click_id)` → CLICK track → deep-link nav; conversion charges ride the already-shipped subscribe/cart/unlock attribution. All destination routes already exist (product/cart/subscribe/profile/tip).

## Tickets
- **ADV2-201 (M, BE)** — Structured CTA model: add `ctas: List[CtaActionIn]` to `CreativeCreateIn`/`UpdateIn`/`Out` (`models.py:4834+`); persist, validate targets by type; relax the http/https-only `cta_url` validator (`:4850`) for deep-link types; map legacy single CTA → one `external` CTA. Deps: none.
- **ADV2-202 (S, BE)** — Carry `ctas` through `serve_ad` output (`ad_serving.py:257-280`) alongside legacy fields. Deps: ADV2-201.
- **ADV2-203 (M, BE)** — VOD pre-roll CTA + click billing: add cta fields to schedule dict (`vod_ad_supported.py:159-172`), persist on session `ad_schedule`, expose in VOD DTOs; add `click` to `VALID_EVENTS` (`:63`) and charge CPC idempotently `{ad_click_id}#click` via `charge_click` reading the AdClicks row (independent of CPM completion) — **gated by DEC ND3**. Deps: ADV2-202.
- **ADV2-204 (S, BE)** — Broadcast pre-roll/live CTA: add `ctas` to `build_pre_roll`/`PreRollOut` (`broadcast_ads.py:145-152`) and, if F1 ships, to the mid-roll payload. Deps: ADV2-202 (+F1 ADV2-101).
- **ADV2-205 (S, BE)** — Product buy/cart conversion: no new endpoint — cart purchase already accepts `ad_click_id`; confirm `view_product` is nav-only no-charge, `buy` routes to add-to-cart/checkout so existing cart attribution fires. Deps: ADV2-201.
- **ADV2-206 (S/M, BE, gated ND2)** — Tip-as-conversion: thread `ad_click_id` into tip surfaces + `attribute_conversion(conversion_type="tip")` after `charge_tip`; decide advertiser CPA-on-tip (DEC ND2). Deps: ADV2-202.
- **ADV2-207 (M, APP)** — CTA model app-side: `CtaAction{type,label,target}` domain + parse into `SponsoredInfo` (`FeedDomain.kt:65`), `AdBreak` (`AdSupportedDomain.kt`), `BroadcastPreRollDto`. Deps: ADV2-201.
- **ADV2-208 (M, APP)** — Reusable `AdCtaBar` composable + `AdCtaRouter` mapping a `CtaAction` → `ProductDetailDest`/`CartDest`/`SubscriptionTiersDest`/`SubscribeDest`/`VideoTipViewModel.open`/profile/external; on tap → `AdClickAttributionStore.record` + `AdTrackRepository.track(CLICK)` + navigate. Central reuse point. Deps: ADV2-207.
- **ADV2-209 (S, APP)** — Newsfeed: swap single external-URL CTA (`FeedScreen.kt:221-223`) for the CTA bar + router; keep back-compat. Deps: ADV2-208.
- **ADV2-210 (M, APP)** — VOD/normal detail player: render CTA bar in `AdOverlay`/`DetailAdPlayer` over the pre-roll, fire new pre-roll click path (ADV2-203), optional non-blocking in-content overlay CTA (DEC ND5). Deps: ADV2-208, ADV2-203.
- **ADV2-211 (S, APP)** — Broadcast viewer: CTA bar on `BroadcastPreRollPlayer` (`ViewerScreen.kt`) + live mid-stream CTA chip (rides F1). Deps: ADV2-208, ADV2-204.
- **ADV2-212 (S, APP)** — Advertiser authoring UI: multi-CTA editor (type + target + label) in the ads creative create/edit screens. Deps: ADV2-201.
- **ADV2-213 (S, VERIFY)** — 2-device money-path verify + build-gate + presigned APK. Deps: all F2.

## Acceptance criteria (money-path)
- CTA tap always records last-click (`AdClickAttributionStore`) + fires a CLICK track (idempotent per `{ad_click_id}#click` if CPC charged, ND3).
- `buy`/cart/subscribe/unlock conversions charge CPA via the already-shipped `attribute_conversion` (last-click 7d) — no new money code; `view_product` charges nothing.
- Tip CTA: per ND2 — track-only (no advertiser charge, recommended) OR CPA-on-tip.
- Legacy single-CTA creatives keep working (mapped to `external`).
- Deep-link CTA targets resolve to in-app routes; `external` http still supported; misdirection restricted per ND4.

## Decisions needed (F2-specific)
- **ND1** CTA authoring locus (per-creative typed list, recommended) + max CTAs per creative.
- **ND2** tip-as-conversion: advertiser CPA on tip, or track-only? (Rec: track-only.)
- **ND3** pre-roll/live CTA click billing: charge CPC on click in addition to CPM? (Rec: one idempotent CPC per `{ad_click_id}#click`.)
- **ND4** "subscribe/tip to ANOTHER account": restrict CTA target to content-owner / advertiser-owned accounts? (Rec: yes, restrict.)
- **ND5** ship persistent lower-third in-content overlay CTA (the unused `overlay` slot_type) or limit F2 to pre-roll/break card CTAs?

---

# F3 — Self-Advertising (free own-content promo, per-campaign toggle D2)

## Design
The "is this the creator's own slot?" test is a **one-line join**: `serve_ad` already receives `content_owner_id` from every caller (VOD `vod_ad_supported.py:133-142` = `video.owner_user_id`; broadcast `broadcast_ads.py:76-83` = `creator_id`; standalone feed passes `""`). A self-promo campaign's owner is `get_ad_account(account_id).owner_sub`. **Serve a self-promo campaign only when `content_owner_id != "" and account.owner_sub == content_owner_id`** — and in that case BYPASS the self-ad-exclusion (`ad_serving.py:107-116`), min-CPM floor, budget, and category filters. A persisted `self_promo` flag on the AdClicks row is **mandatory** because two paths charge on a 0 price: broadcast completion floors 0→500¢ (`broadcast_ads.py:236-241`) and impression billing does `max(1, ...)`→1¢ (`ad_billing.py:157-169`). D2 auction precedence: `always_win` self-promo > paid > `fill_only` self-promo > house ad.

## Tickets
- **ADV2-301 (S, BE)** — Campaign self-promo flavor: add `is_self_promo: bool=False` + `self_promo_fill_mode` (`^(fill_only|always_win)$`, default `fill_only`) to `CampaignCreateIn` (`models.py:4451`)/`UpdateIn` (`:4806`)/`Out` (`:4487`); persist in `create_campaign` (`ad_campaigns.py:40-59`); force bids=0 + relax `budget_cents ge=100` floor for self-promo. Deps: none.
- **ADV2-302 (M, BE)** — serve_ad self-promo eligibility + auction (D2): in the campaign loop require `content_owner_id and account.owner_sub == content_owner_id` for `is_self_promo`, bypass self-ad-exclusion/min-CPM/budget/category, collect into a `self_promo` bucket with `fill_mode`; implement precedence in winner-selection (`:189-205`); set `self_promo: True`, `effective_price_cents: 0` in the AdClicks mint (`:214-243`). Frequency cap still applied (assumption). Deps: ADV2-301.
- **ADV2-303 (S, BE)** — Billing guards (no charge on self-promo): gate `track_ad_event` `_billable` (`ad_serving.py:385-392`) on `not click_row.get("self_promo")`; early-return in `_charge_broadcast_preroll_completion` (`broadcast_ads.py:225-241`) before the 500¢ floor when the row is `self_promo`. No `_split_revenue` runs → zero money movement. Deps: ADV2-302.
- **ADV2-304 (S, BE)** — Lifecycle/approval for free own-content campaigns: decide auto-activate (skip `pending_review` at `ad_campaigns.py:177-186` + `ads.py:248`) and creative auto-approve (bypass `list_approved_creatives` gate `ad_serving.py:167`). Rec: auto-approve but still run creative moderation + fraud. Needs DEC F3-1. Also carve-out for `allow_ads=False` (DEC F3-2). Deps: ADV2-302.
- **ADV2-305 (S, VERIFY)** — In-process money-path proof via SSM: `always_win` self-promo wins own pre-roll over a funded paid campaign with 0 debit / 0 ledger / 0 credit; `fill_only` serves only when no paid candidate; never appears on a different creator's content or as a standalone feed unit; idempotency. Fold `ops/prod-hotfixes/adv/f3-self-promo/`. Deps: ADV2-302, ADV2-303.
- **ADV2-306 (M, APP)** — Create-campaign UI: "Promote my content" toggle + `fill_only`/`always_win` segmented control in `AdsCreateDtos.kt:42-48` + `CreateCampaignViewModel`/`Screen` + mappers; when self-promo on, hide/zero CPM/CPC/CPA (`CreateCampaignScreen.kt:231-248`) and the "Add funds" prerequisite. testTags `create_campaign_self_promo_toggle`/`create_campaign_fill_mode`. Deps: ADV2-301.
- **ADV2-307 (S, VERIFY)** — `:app:assembleDebug` gate + A15 drive: creator makes a self-promo `always_win` for own content, a second-account viewer sees the promo pre-roll with no advertiser debit, ROAS/earnings unchanged. Presigned APK. Deps: ADV2-306, ADV2-305.

## Acceptance criteria (money-path)
- Self-promo: `effective_price_cents=0`, `self_promo=True` on the AdClicks row; **NO** advertiser debit, **NO** ledger row, **NO** creator credit, on impression/click/completion (both the 500¢ and 1¢ default paths early-return).
- `always_win` self-promo displaces paid demand on own-content slots (DEC F3-3 confirms revenue-negative is intended); `fill_only` only replaces the house-ad fallback.
- Self-promo never serves on a different creator's content, nor as a standalone feed unit (feed injectors pass `content_owner_id=""`).
- Self-ad-exclusion bypass is scoped ONLY to self-promo-on-own-content.

## Decisions needed (F3-specific)
- **DEC F3-1** auto-activate self-promo campaign/creative (skip admin review) vs queue like paid. (Rec: auto-approve + retain fraud/moderation.)
- **DEC F3-2** if creator has `allow_ads=False`, may their own self-promo still serve? (Rec: yes — it's their content; needs carve-out in ADV2-302/304.)
- **DEC F3-3** confirm `always_win` self-promo should displace a real paying advertiser on own slots (revenue-negative). D2 implies yes.

---

# F4 — Sponsored-as-creator posts (advertiser-drafted, creator-approved)

## Design
~70% exists as ADS-013 "sponsorship deals" (`sponsorship_deals.py`, 605 lines): lifecycle proposed→…→completed, escrow (advertiser wallet debit at propose `:139`, release 85/15 creator/platform on complete `_release_escrow:177`, refund/dispute), FTC label `_add_ftc_label:265`, deal DM, notifications. **The authorship direction is REVERSED**: in ADS-013 the CREATOR links their OWN post (`_verify_content_ownership:295` requires `post.user_id == creator_sub`); F4 needs the ADVERTISER to draft, the creator to APPROVE, then publish authored-by-creator. And F4 forbids a forced label (D3), whereas `_add_ftc_label` hardcodes "Paid partnership with {brand}". Non-tip is already enforced: `tip_post`/`tip_react_to_post` raise `tip_not_allowed_on_ad` when `post.is_sponsored` (`newsfeed.py:4759/4977`). Publish path = `create_post` (`newsfeed.py:3424`, `post_item` build `:3667`, then `fan_out_post_to_followers`).

**Billing rail (DEC F4-1):** Rail A = flat fee via existing 85/15 escrow (one-time, off the ad money-path). Rail B = engagement CPM/CPC via the ad money-path with creator 70% placement share (funds-guard + ROAS + reversal for free). Rec: B or C (hybrid) to keep F4 inside ad reporting. This drives whether ADV2-404 is in scope.

## Tickets
- **ADV2-401 (M, BE)** — Advertiser draft + creator-approval store: extend `sponsorship_deals.py` with an advertiser-authored flavor (META `draft_body`/`draft_body_format`/`draft_image_urls`/`draft_video_id`/`proposed_sponsor_label?`/`proposed_disclosure?`) + status path `draft_proposed → approved(published)/rejected/changes_requested`; reuse GSIs (GSI2 CREATOR#=review queue, GSI1/3=advertiser view), `_record_event`, `_notify`; new `create_sponsored_draft`/`approve_and_publish`/`reject_draft`; escrow hold at draft time. Deps: none.
- **ADV2-402 (M, BE)** — Publish-as-creator on approve: refactor `create_post`'s `post_item` build (`newsfeed.py:3667`) into a reusable `_persist_post(author_id=creator, ...)`; `approve_and_publish` calls it with `user_id=creator`, `is_sponsored=True`, ad linkage (`campaign_id/account_id/creative_id/ad_click_id-seed`, `sponsor_label`, `disclosure`), then `fan_out_post_to_followers`. Do NOT call `_add_ftc_label`; write chosen wording verbatim (D3). Release escrow (Rail A) and/or seed content_owner (Rail B). Deps: ADV2-401.
- **ADV2-403 (S, BE)** — Serialize sponsored fields on persisted posts: add `is_sponsored`/`sponsor_label`/`impression_url`/`click_url`/`ad_click_id`/`campaign_id`/`account_id`/`creative_id`/`content_owner_id` to `_post_to_dict` (`newsfeed.py:2191`) when present (mirror `_fetch_sponsored_post:155`); additive/defaulted so organic posts unchanged. Deps: ADV2-402.
- **ADV2-404 (M, BE, ONLY if Rail B/C)** — Per-viewer ad-click minting for a persistent post: lazy-mint an AdClicks row per (viewer, post) at feed-read with `content_owner_sub=creator`, `surface="sponsored_creator_post"` (add to un-gated billable set in `track_ad_event:390`); idempotent per (viewer, post); reuse the `serve_ad` mint block (`ad_serving.py:216`). Deps: ADV2-403, DEC F4-1.
- **ADV2-405 (S, BE)** — Creator eligibility/opt-out gate: only allow a draft proposal to a creator who accepts them (reuse `creator_ad_prefs` `allow_ads` + `is_advertiser_blocked`); 403 otherwise. Deps: ADV2-401.
- **ADV2-406 (S, BE)** — Money-path tests + prod hotfix fold: draft→approve→published carries `is_sponsored`+non-tippable (assert 400 on tip/tip-react), advertiser debited, creator credited placement share (per rail), reject→escrow refund. Fold `ops/prod-hotfixes/adv/f4-sponsored-creator/`. Deps: ADV2-402 (+404 if Rail B).
- **ADV2-407 (M, APP)** — Advertiser "draft a post for a creator" composer: new screen (body/media + target creator + optional label/disclosure + fee) posting the draft endpoint; reuse `SponsorshipRepository` + composer widgets. Deps: ADV2-401.
- **ADV2-408 (M, APP)** — Creator review queue + approve/edit-wording/reject: extend `SponsorshipInboxScreen`/`SponsorshipDealScreen` for the drafted flavor — preview the exact post, edit disclosure wording (D3), Approve→publish / Request-changes / Reject. Deps: ADV2-401.
- **ADV2-409 (S, APP)** — Render authored-by-creator sponsored post: feed already parses `is_sponsored`/`sponsor_label`/`ad_click_id` (`FeedDtos.kt:73-87`, `FeedDomain.kt:55/178`); add a variant so a creator-authored sponsored post shows the creator's own identity + optional disclosure line (not the generic brand card), still non-tippable, impression/click via `AdTrackRepository`+`AdClickAttributionStore`. Deps: ADV2-403.
- **ADV2-410 (S, VERIFY)** — Build-gate + 2-device verify + presigned APK (record A15). Deps: all F4.

## Acceptance criteria (money-path)
- Approval is the ONLY path that publishes (creator must approve; no forced label — chosen wording written verbatim; D3).
- Published post persists `is_sponsored=True` → non-tippable (400 `tip_not_allowed_on_ad` on tip + tip-react).
- Rail A: advertiser wallet debited at draft, 85/15 released on publish, refunded on reject. Rail B: advertiser ad-account debited per impression/click (funds-guarded, idempotent), creator credited placement share (70%, `type:"credit"`, in earnings), reversible + in ROAS.
- Creator opt-out (`allow_ads`/advertiser-block) gates receiving proposals (403).

## Decisions needed (F4-specific)
- **DEC F4-1** billing model: A flat escrow / B engagement CPM-CPC / C hybrid. (Rec: B or C.) Drives ADV2-404.
- **DEC F4-2** creator revenue share: reuse default 70% bps (Rail B) or ADS-013 85/15 (Rail A) or align. (Rec: reuse existing per-creator bps.)
- **DEC F4-3** label wording: allow free wording but require a non-empty disclosure field, or allow truly blank? (Rec: require the field present, creator-authored.)

---

# F5 — Sponsored mass-messaging (creator on behalf of advertiser)

## Design
The full mass-message campaign engine ships (idempotent, funds-guarded counters, retry/backoff, rate limits, worker pool, scheduled dispatch, delivery/read receipts). Gaps: (1) no advertiser→creator sponsorship/approval object (D3, net-new); (2) content is text-only (`MassMessageContentPayload.kind=Literal["text"]`); (3) zero billing in the send path; (4) no per-recipient `ad_click_id`/attribution; (5) create requires pre-existing `conversation_ids` + 100-destination cap (audience must resolve followers/subscribers → DMs and handle >100); (6) recipient ad opt-out not enforced. Reuse the ad money-path verbatim: creator earns a placement share by passing the creator's sub as `creator_id` to `_split_revenue`. Recipients are the creator's own audience → D1's cold-DM restriction is inherently satisfied.

## Tickets
- **ADV2-501 (M, BE)** — Sponsorship offer + approval object (D3): new `app/services/sponsored_message_offers.py` + table; advertiser drafts (`ad_account_id`/`campaign_id`/`creative_id`/target creator_sub/terms) → draft/pending_creator/approved/rejected/expired; endpoints advertiser `POST /ui/ads/sponsored-messages`, creator `GET /messaging/sponsored-offers` + `.../{id}/approve|reject`. Approve = ONLY path that can create a sponsored mass-message campaign; creator sets wording (no forced label, D3). Deps: none.
- **ADV2-502 (M, BE)** — Sponsored campaign variant on the existing engine: extend/ add `MassMessageSponsoredPayload` (`sponsor_ad_account_id`/`campaign_id`/`creative_id`/`cta_url`/`image_url?`); extend create (`messaging.py:805`) to accept a `sponsorship_id` (settable ONLY via the ADV2-501 approve path, guarded); stamp `sponsor_ad_account_id`/`ad_click_id` onto each message item in `_process_mass_message_destination` (`:493`). Deps: ADV2-501.
- **ADV2-503 (M, BE)** — Delivered billing (D4 base): after a successful send, when sponsored, mint a per-recipient `ad_click_id` (reuse `serve_ad` AdClicks write, `content_owner_sub=creator_sub`) + new `ad_billing.charge_message_delivery` (thin `_process_charge` wrapper, `entry_type="message_delivery_charge"`, funds-guarded, idempotency `{campaign_id}:{conversation_id}:delivery`) → `_split_revenue(creator_id=creator_sub)` pays creator placement share; insufficient funds → mark `failed`/`skipped`, do NOT send. Add delivered/opened/clicked counters. Deps: ADV2-502.
- **ADV2-504 (M, BE)** — Open + click billing (D4 additional): open = first time a sponsored message's `read_at ≥ created_at` (hook `_message_receipt_summary:4964`/`mark_read`) → `charge_message_open` (idempotency `...:open`, gated on `_message_receipts_enabled:3003`); click = `POST /messaging/mass-messages/{id}/messages/{mid}/click` (or `/ui/ads/track` with the minted id) → `charge_click` idempotent `{ad_click_id}#click`. Both split creator share. Deps: ADV2-503.
- **ADV2-505 (S, BE)** — Audience resolution + opt-out: `resolve_creator_audience(creator_sub, segment)` via `social.get_followers:162`/`creator_analytics.get_subscribers:333`, filtered by a per-recipient ad-message opt-out (extend `creator_ad_prefs`), expanded via `find_or_create_dm:6316`; raise/relax `MAX_DESTINATIONS_PER_CAMPAIGN` (auto-chunk or async fanout). Deps: ADV2-502.
- **ADV2-506 (S, BE)** — Reversal/ROAS parity: ensure `message_delivery_charge`/open/click flow through `reverse_ad_charge` + `/ui/ads/roas`; add entry types to `creator_earnings.classify_entry` so the creator's placement share shows in earnings. Deps: ADV2-503, ADV2-504.
- **ADV2-507 (M, APP)** — Creator review-queue + approve/edit screen: list pending offers, preview creative + terms, edit wording, approve→send / reject. Deps: ADV2-501.
- **ADV2-508 (S, APP)** — Advertiser "sponsor a creator" draft screen: pick creator + creative + terms, submit, see status; reuse ads create screens. Deps: ADV2-501.
- **ADV2-509 (S, APP)** — Sponsored campaign progress UI: extend mass-message detail with delivered/opened/clicked + spend + creator earnings. Deps: ADV2-503, ADV2-504.
- **ADV2-510 (S, APP)** — Recipient render + click: render inbound sponsored message with CTA button; tap fires the click endpoint (ADV2-504); reuse `SponsoredFeedCard`/`AdTrackRepository`; no forced label (D3). Deps: ADV2-504.
- **ADV2-511 (S, APP)** — Per-user ad-message opt-out toggle in Message-Privacy settings (reuse TIP-404 surface). Deps: ADV2-505 (+shared F6 ADV2-601).

## Acceptance criteria (money-path)
- Only a creator-approved offer can create a sponsored campaign (D3); creator wording used verbatim (no forced label).
- Delivered: advertiser debited base-per-delivery once per destination, idempotent `{campaign}:{conversation}:delivery`; funds-fail → not sent.
- Open + click: additional charge each fires at most once (idempotent `...:open` / `{ad_click_id}#click`); stacking per DEC F5-1.
- Creator credited placement share (~70%, `type:"credit"`, in earnings) via `_split_revenue(creator_id=creator_sub)`; reversible + in ROAS.
- Recipients limited to the creator's existing audience (D1 satisfied); per-recipient ad opt-out honored.

## Decisions needed (F5-specific)
- **DEC F5-1** billing schema: `base_per_delivery_cents` + is the open/click surcharge fixed `open_bonus`+`click_bonus` (stacking) or open-OR-click (first)? Who prices — advertiser bid or platform-fixed?
- **DEC F5-2** which audience segments (all followers / paid subscribers only / saved segment); does per-recipient opt-out apply even to the creator's own audience?
- **DEC F5-3** audience-size cap: raise `MAX_DESTINATIONS_PER_CAMPAIGN`, auto-chunk, or async large-audience fanout (required — audiences exceed 100).
- **DEC F5-4** disclosure/compliance: accept D3 no-forced-label risk; recommend at least an optional creator-chosen disclosure default.

---

# F6 — Advertiser Direct Mass-DM (D1 + D4)

## Design
~70% is reusable infra: the mass-message engine + the funds-guarded ad-billing rail. F6 adds (a) an advertiser-scoped audience-resolution + eligibility layer, (b) D4 hybrid billing in the send worker, (c) a per-user ad opt-out. Two genuine new-build pieces: audience resolution from the relationship graph (with a **subscriber-enumeration gap** — `subscriptions` has no `ByCreator` GSI; `get_subscribers:333` is a time-series rollup, not an ID list; followers are enumerable via GSI5 `social.get_followers:162`) and delivery/open/click billing+tracking. Opt-out home = the `message_privacy` record (`_get/_put_message_privacy:6200/6214`). Distinct from `creator_ad_prefs.allow_ads` (content-ad serving). Because F6 is platform-100% (no content owner), `_split_revenue` with empty `creator_id` books it entirely to platform.

## Tickets
- **ADV2-601 (S, BE)** — Per-user ad opt-out: add `allow_ad_messages: bool=True` to `message_privacy` (`_get/_put:6200/6214`, `MessagePrivacyOut/UpdateIn:1748`); helper `_user_accepts_ad_messages(sub)`; reuse TIP-401 settings endpoints. (SHARED with F5 opt-out.) Deps: none.
- **ADV2-602 (L, BE)** — Audience resolution + D1 eligibility: new `app/services/ad_dm_audience.py` — eligible = followers ∪ active-subscribers ∪ explicit ad-opt-in, each filtered by `allow_ad_messages` AND not-blocked AND relationship RE-VERIFIED (`is_following`/`has_active_subscription`, never cold); includes the subscriber-enumeration solution (DEC-2); paginated, capped. Deps: ADV2-601.
- **ADV2-603 (L, BE)** — Advertiser mass-DM campaign flavor: advertiser-scoped campaign tied to `ad_account_id` + ad `campaign_id`, destinations resolved from ADV2-602 (not client conversation_ids), per-destination `find_or_create_dm(advertiser→recipient)`, re-check eligibility, send an ad message (new content kind: advertiser identity + CTA + minted `ad_click_id`); reuse `upsert_destination` + counters + worker + retry; new endpoints under an advertiser prefix (create/list/detail/cancel). Deps: ADV2-602.
- **ADV2-604 (M, BE)** — D4 delivery billing: `ad_billing.charge_ad_message_delivery` (`_process_charge`, base cents/delivery, idempotency `dm_deliver:{campaign}:{conversation}`, `creator_id=""` → platform-100%); called in the worker on each SENT destination; funds-fail → mark `failed`, respect budget auto-complete. Deps: ADV2-603.
- **ADV2-605 (M, BE)** — D4 open/click billing + tracking: mint an AdClicks row per delivered ad-DM (advertiser-owned, no content owner); extend `/ui/ads/track` (or a scoped route) for `open` (message-read) + `click` (CTA tap); charge surcharge idempotent `{ad_click_id}#open` / `#click`; reuse `ad_attribution.py` last-click. Deps: ADV2-604.
- **ADV2-606 (S, BE)** — Send-time re-gate + audit/metrics: re-verify eligibility + opt-out at send moment (opt-out between create and dispatch drops the destination); audit `ad_mass_dm_*`; extend metrics (delivered/opened/clicked/spend). Deps: ADV2-603.
- **ADV2-607 (M, APP)** — Advertiser mass-DM create screen: compose text + CTA target + audience picker (followers/subscribers/opted-in) + budget/account; reuse `MassMessagesViewModel`/`MassMessageRepository` + ads create/account screens. Deps: ADV2-603.
- **ADV2-608 (S, APP)** — Campaign list/detail: delivered/opened/clicked/spend counters; reuse `MassMessagesScreen` + ROAS card. Deps: ADV2-604, ADV2-605.
- **ADV2-609 (M, APP)** — Recipient render + open/click tracking: render ad DM with advertiser identity + tappable CTA; fire `open` on read + `click` on CTA via `AdTrackRepository`/`AdClickAttributionStore`; deep-link CTA (reuse ADV-405 attribution + F2 `AdCtaRouter`). Deps: ADV2-605 (+F2 ADV2-208).
- **ADV2-610 (S, APP)** — Ad opt-out toggle "Allow promotional messages" in Message-Privacy settings (reuse TIP-404), bound to ADV2-601. Deps: ADV2-601.

## Acceptance criteria (money-path)
- Audience is ONLY existing relationships (follower/subscriber) or explicit opt-in; relationship re-verified at resolve AND at send; a user who opts out between create and dispatch is dropped (D1).
- Delivered: advertiser debited base-per-delivery once per destination, idempotent `dm_deliver:{campaign}:{conversation}`; funds-fail → not sent, campaign paused/completed (no negative balance).
- Open + click surcharge each fires at most once (idempotent `{ad_click_id}#open`/`#click`).
- No content owner → `_split_revenue` books platform-100% (no creator credit).
- Frequency cap enforced per DEC-3.

## Decisions needed (F6-specific)
- **DEC-1** opt-in granularity: global (`allow_ad_messages`) vs per-advertiser opt-in? (Changes ADV2-601/602 data model.)
- **DEC-2** subscriber-audience enablement: add a `ByCreator` GSI to `subscriptions` (clean, backfill) vs advertiser-maintained opt-in snapshot (staler). Followers already work.
- **DEC-3** frequency cap: max ad-DMs per user per advertiser per day/week.
- **A1 amounts** (needs sign-off): delivery ≈ 2-5¢, open ≈ 3¢, click = campaign `bid_cpc_cents`.
- **A3 pay-to-message interaction**: confirm ad-DMs to an existing relationship bypass the `require_tip_to_message` gate; a tip-gated non-follower who merely opted-in still hits the gate.

---

# F7 — Syndicate Advertising

## Design
**Two parallel ad systems that don't touch.** System A = the REAL engine (`ad_accounts`→`ad_campaigns`→`ad_creatives`→`serve_ad`→`track_ad_event`→`_process_charge`→`_split_revenue`). System B = a self-contained SIMULATION already named "syndicate advertising" (`syndicate_advertising.py`, SYND-006): own table `syndicate_ad_campaigns` (serve_ad never sees it), deterministic `COST_PER_IMPRESSION_CENTS=1`, treasury-funded, client-driven fictional `record_campaign_impression:237`, pays members nothing. **F7 = make the simulation real by bridging it into System A + adding the cross-member split.** Two keystones already exist: (1) cross-member targeting needs NO new engine — `evaluate_targeting` supports `creator_ids`/`exclude_creator_ids` (`ad_targeting.py:154-161`) and `serve_ad` puts the content creator in context; a syndicate campaign is just a targeting set of member subs. (2) Member distribution needs NO new money code — `syndicate_revenue_split.execute_split(source_type=...)` (`:161`) already writes per-member credits + wallet deltas (`apply_wallet_delta:288`) with an invariant check. Gaps: syndicate-owned ad account (`ad_accounts` knows only `owner_sub`), treasury→ad-account funding rail, 3-way placement split (`_split_revenue` is 2-way), syndicate-feed member attribution (`sponsored_feed` hardcodes platform-100%).

## Tickets
- **ADV2-701 (M, BE)** — Syndicate-owned ad account: add `owner_type` (`user`|`syndicate`) + `owner_syndicate_id` to `ad_accounts` META (`ad_accounts.py:45-57`) + `AdAccountCreateIn` (`models.py:4430`); new `create_syndicate_ad_account` gated by `syndicates._require_admin` (`:594`); update `serve_ad` self-ad-exclusion (`ad_serving.py:107-116`) + `deposit_funds` owner resolution (`ad_billing.py:44-52`) for a syndicate owner; reuse approve path. Deps: none.
- **ADV2-702 (S, BE)** — Treasury→balance funding rail: `fund_ad_account_from_treasury(syndicate_id, account_id, amount)` = debit via `treasury.spend_on_advertising:355` + credit `ad_accounts.balance_cents` (mirror `deposit_funds` credit half), one treasury ledger row, admin-gated, no card; cancel/refund mirrors the simulation's treasury refund. Deps: ADV2-701.
- **ADV2-703 (S, BE)** — Syndicate-member targeting: add a `syndicate_id` targeting key resolving to `list_members` subs at eval time (churn-safe), evaluated through the existing `creator_ids` branch (`ad_targeting.py:155`); default a syndicate campaign to member-restricted (DEC 5). Deps: ADV2-701.
- **ADV2-704 (L, BE, money-path)** — 3-way placement split: extend `_split_revenue` (`ad_billing.py:325`) — when the content owner (`creator_id`) resolves to a syndicate member, route the creator-share through `execute_split(source_type="ad_placement")` (member+syndicate per `get_split_config`) instead of a single creator credit; stay idempotent (existing marker) + reversible (mirror ADV-502 backing out `creator_credit_sk`/`platform_entry_sk`); denormalize split pointers onto the charge row. Deps: ADV2-701.
- **ADV2-705 (M, BE)** — Cross-member serving wiring: feed the adjacent member author as `content_owner` in `sponsored_feed.build_sponsored_unit`/`inject_sponsored_syndicate` (`:28,168`, today platform-100%); verify member pre-roll/broadcast (`vod_ad_supported.py:133`, `broadcast_ads.py:83`) trigger ADV2-704 when the poster is a member. Deps: ADV2-704.
- **ADV2-706 (S, BE)** — Free syndicate self-promo across members: per-campaign `fill_only`/`always_win` + cost-0 path bypassing self-ad-exclusion for the syndicate's own member content (D2 pattern applied to a syndicate); hook `ad_serving.py:107-116`. Deps: ADV2-701, F3 ADV2-302. (Governed by DEC 3.)
- **ADV2-707 (M, BE)** — Rewire/retire the simulation: turn `syndicate_advertising.create_campaign:70` into a facade over the real account+campaign+creative (ADV2-701/702), or deprecate the module + router (`app/routers/syndicate_advertising.py:27,145`); serve analytics from real `ad_impressions`/`ad_billing`/ROAS; retire the fictional `record_impression`. (Governed by DEC 4.) Deps: ADV2-701, ADV2-702.
- **ADV2-708 (S, VERIFY)** — Full lifecycle: fund-from-treasury → serve across a member → charge → platform/syndicate/member 3-way split (assert member wallet + treasury/member ledger via `execute_split`) → reversal clawback. Fold `ops/prod-hotfixes/adv/f7-syndicate/`; verify on prod DDB via SSM. Deps: all F7 BE.
- **ADV2-709 (M, APP)** — Rewire the existing syndicate campaign UI to System A: point `feature/syndicates/campaign/CampaignRepository` + `SyndicateCampaignApi.kt` at the real account/campaign/creative + fund-from-treasury endpoints; add creative upload (reuse ADV-B1 screens) + real ROAS (reuse ADV-B5 card). Deps: ADV2-701, ADV2-702, ADV2-707.
- **ADV2-710 (S, APP)** — Member placement-earnings surface: reuse `get_member_earnings:347` — show a member their ad-placement share alongside existing split earnings. Deps: ADV2-704.
- **ADV2-711 (S, APP)** — Syndicate-feed sponsored card attribution: card already renders via `SponsoredFeedCard` (no-tip); verify the member-attributed unit tracks impression/click through `AdTrackRepository`. Largely verification. Deps: ADV2-705.

## Acceptance criteria (money-path)
- Syndicate ad account funds ONLY from the treasury (no card); funding writes one treasury debit + one balance credit; refund on cancel.
- External advertiser in front of a member's content: creator-share (70%) is split member/syndicate per `get_split_config`; platform 30% unchanged (subject to DEC 1/2). 3-way split is idempotent AND fully reversible (clawback backs out every member credit + wallet delta + platform entry).
- `execute_split` invariant holds: `platform_fee + Σ member_distributions == gross`.
- Syndicate self-promo (ADV2-706): cost 0, no debit, bypasses self-ad-exclusion for member content only (DEC 3).
- Member serving restricted to member content by default (DEC 5).

## Decisions needed (F7-specific)
- **DEC 1** third-party-ad tax: does an external advertiser's 70% creator-share get split member/syndicate, or does the member keep 100% and the syndicate earns only when IT advertises?
- **DEC 2** member/syndicate ratio: fixed bps vs entirely via `split_config`; does platform's 30% stay unchanged?
- **DEC 3** syndicate-as-advertiser in front of its own members: free (D2-style, treasury spends 0) or treasury pays so members earn from cross-promotion?
- **DEC 4** keep vs rebuild: facade over the real engine (cheaper, ADV2-707) vs deprecate + build fresh.
- **DEC 5** default targeting scope: member-content-only vs platform-wide with member content boosted.
- **DEC 6** who can run syndicate ads: admin-only (current `_require_admin`) vs a new per-member advertiser role.

---

# DEPENDENCY-ORDERED EPIC PLAN

Sequenced so each epic reuses code stabilized by the prior one and shares components forward. F5+F6 are merged into one ad-messaging epic because they share the mass-message engine, the D4 billing wrappers, the per-user ad opt-out (ADV2-601 == ADV2-511's dependency), and the recipient CTA render.

- **E1 — Live-stream ad breaks (F1)** — ADV2-101..108. First: pure extension of an already-shipped control plane onto the proven broadcast pre-roll billing; lowest new-surface risk; validates the "reuse the money engine" thesis on-device. No dependency on other epics.
- **E2 — Click-through CTAs (F2)** — ADV2-201..213. Second: builds the reusable `AdCtaBar`/`AdCtaRouter` + structured CTA model that E5 (ad-DM recipient render) and E1's live CTA chip consume. Depends on nothing structural but should precede messaging so the CTA render is shared, not duplicated. (E1's ADV2-211 live CTA chip can land after E2.)
- **E3 — Self-advertising (F3)** — ADV2-301..307. Third: introduces the `is_self_promo`/`fill_mode` campaign fields + auction precedence + zero-charge guards that E6 (F7-B6 syndicate self-promo, ADV2-706) reuses directly.
- **E4 — Sponsored-as-creator posts (F4)** — ADV2-401..410. Fourth: exercises the approval-gated (D3) publish-as-creator flow + `sponsored_creator_post` billing surface that de-risks the same approval + placement-share pattern used in E5.
- **E5 — Ad-messaging (F5 + F6 shared)** — ADV2-501..511 + ADV2-601..610. Fifth: the largest epic. Reuses D3 approval (from E4), the ad money-path, the D4 delivery/open/click `_process_charge` wrappers (built once, shared F5↔F6), the shared per-user ad opt-out (ADV2-601/511), and E2's `AdCtaRouter` for recipient CTAs. Build order within: ADV2-601 (opt-out) → ADV2-602/603 (audience + campaign) → ADV2-503/504/604/605 (billing) → F5 approval layer → app.
- **E6 — Syndicate advertising (F7)** — ADV2-701..711. Last: the deepest money-path change (3-way split) and the widest reuse — depends on the self-promo toggle from E3 (ADV2-706), the ad money-path proven across E1-E5, and `execute_split`. Rewiring the existing simulation is safest once every real-engine surface it bridges into is stable.

Rationale for order E1→E2→E3→E4→E5→E6: risk-ascending and reuse-forward — each epic hardens a primitive (broadcast billing → CTA components → self-promo/auction → approval+placement-share → shared D4 billing → 3-way split) that a later epic consumes, so nothing is built twice and the deepest split change lands on the most-exercised code.

---

# SECOND-PASS ASSUMPTION CHECK (adversarial re-read)

Re-verified load-bearing premises against `android-impl @ f2e2ede6` on dev host `.249` (read-only). Prod (SSM) deliberately not read — that is each VERIFY ticket's job. **Verdict: every load-bearing premise CONFIRMED; 0 tickets invalidated. Below: confirmations of the biggest premises + the premises I could NOT fully confirm + open product decisions.**

### Premises CONFIRMED this pass
| Premise (ticket relies on it) | Result | Citation |
|---|---|---|
| F1 mid-roll control plane ships (trigger/serve/charge templates) | CONFIRMED | `broadcast_ads.py` router `trigger_ad_break_route:194`; svc `serve_broadcast_ad:56`, `build_pre_roll:114`, `start_ad_break:160`, `_charge_broadcast_preroll_completion:218` |
| F3 `content_owner_id` flows to `serve_ad` + is minted onto AdClicks | CONFIRMED | `ad_serving.py:70` kwarg, `:227` `content_owner_sub`, `:276` output |
| F3 self-ad-exclusion is `account.owner_sub == user_id` | CONFIRMED | `ad_serving.py:107-116` (`:113` compares `owner_sub` to `user_id`) |
| F4 sponsorship_deals lifecycle + escrow + FTC label + ownership check exist | CONFIRMED | `sponsorship_deals.py` `_release_escrow:177`, `_add_ftc_label:265`, `_verify_content_ownership:295` (`:518` requires creator owns the post) |
| F4 `is_sponsored` already blocks tipping | CONFIRMED | `newsfeed.py:4759/4977` raise `tip_not_allowed_on_ad`; injected units set `is_sponsored:True` `:157` |
| F5/F6 mass-message engine (create/worker/dm) exists | CONFIRMED | `messaging.py` `create_mass_message_campaign:805`, `_process_mass_message_destination:493`, `find_or_create_dm:6316`; privacy `_get/_put:6200/6214` |
| F5 content payload is text-only | CONFIRMED | `models_mass_message.py:16` `kind: Literal["text"] = "text"` |
| F5/F6 ad money-path (`charge_*`/`_process_charge`/`_split_revenue`) exists | CONFIRMED | `ad_billing.py:157/173/211/325` |
| F6 followers enumerable | CONFIRMED | `social.py:162` `get_followers` |
| F7 syndicate simulation is separate + 1¢ flat + client-driven | CONFIRMED | `syndicate_advertising.py:46` const, `:70` create, `:237` `record_campaign_impression` |
| F7 `execute_split` distributes per-member (credit + wallet) | CONFIRMED | `syndicate_revenue_split.py:161` def, `apply_wallet_delta` used `:288`, `get_member_earnings:347` |
| F7 targeting supports member `creator_ids` | CONFIRMED | `ad_targeting.py:154-161` |
| F7 `ad_accounts` knows only `owner_sub` (no syndicate owner) | CONFIRMED | `ad_accounts.py:28/49/67` all `owner_sub` |

### Premises I could NOT fully confirm this pass (verify before/at build)
- **F1 SSE-unreliable-on-device / app viewer uses chat POLL fallback** — sourced from the `android-web-parity` memory, not re-read in the app tree this pass. The poll-based detection design (ADV2-103/105) depends on it. If SSE actually reaches the app, a simpler SSE path is possible. VERIFY in `feature/broadcast/viewer/*` before ADV2-105.
- **F1 exact line numbers `broadcast_ads.py:225-241 / 236-241` for the 500¢ floor** — the function `_charge_broadcast_preroll_completion` exists at `:218`; the specific 500¢-fallback lines were not individually re-read this pass. The `self_promo` early-return (ADV2-303) and mid-roll labeling (ADV2-102) depend on that block's exact shape.
- **F3 the two 0-price charge traps (broadcast 500¢ floor; impression `max(1,...)` 1¢)** — cited from the F3 scope; `_charge_broadcast_preroll_completion:218` and `charge_impression:157` exist, but the exact fallback arithmetic lines were not re-opened. The `self_promo` flag is mandatory ONLY if these traps are real — confirm at ADV2-303 (if absent, `effective_price_cents=0` alone suffices).
- **F4 `create_post` refactor into `_persist_post(author_id=...)` (ADV2-402)** — `create_post:3424` and the `post_item` build region exist; that the build is cleanly extractable (no hard `user_id == caller` coupling in fan-out) is an assumption. Confirm the fan-out path accepts an author != caller before ADV2-402.
- **F5/F6 `creator_earnings.classify_entry` (ADV2-506)** — referenced by analogy to ADV-406; not re-read this pass. Confirm the classifier exists + is the right hook for the new entry types.
- **F6 subscriber enumeration gap** — CONFIRMED absent by design (no `ByCreator` GSI); this is flagged as DEC-2 (a real schema decision, not a bug), so ADV2-602's subscriber path is BLOCKED on DEC-2.
- **F7 3-way reversal (ADV2-704) mirroring "ADV-502"** — the reversal that backs out `creator_credit_sk`/`platform_entry_sk` is referenced from the v1 program; not re-read. Confirm the existing reversal's shape before extending it to N member credits.

### Open product decisions the user should weigh in on BEFORE building (beyond the 4 locked)
Ordered by blocking impact:
1. **F5-1 / F6-A1 ad-messaging prices** — D4 fixes the shape, not the numbers. Need `base_per_delivery`, open surcharge, click surcharge, and the stacking rule (open+click stack vs first-only), and who prices (advertiser bid vs platform-fixed). **Blocks E5 billing (ADV2-503/504/604/605).**
2. **F6 DEC-2 subscriber enumeration** — add a `ByCreator` GSI to `subscriptions` (clean, backfill) vs advertiser-maintained snapshot. **Blocks the subscriber audience path in ADV2-602.** (Followers work today with no change.)
3. **F4-1 billing rail** — flat escrow (A) vs engagement ad-money-path (B) vs hybrid (C). **Determines whether ADV2-404 is in scope.** (Rec: B or C.)
4. **F7 DEC-1/DEC-2 split economics** — does joining a syndicate skim a member's normal (external-advertiser) 70% share, and what member/syndicate ratio? **Blocks the core F7 money-path (ADV2-704).**
5. **F3 DEC-3 / F7 DEC-3** — confirm free `always_win` self-promo may displace real paying demand on own/member slots (revenue-negative by design).
6. **F2 ND2/ND3** — tip-as-conversion (advertiser CPA on tip? rec no) and pre-roll CTA CPC-on-click in addition to CPM (rec yes, idempotent).
7. **F6 DEC-1 opt-in granularity** (global vs per-advertiser) and **DEC-3 frequency cap** value.
8. **F1 D-F1-a..e** — skip-resume behavior, no-fill fallback, break-duration source, guardrail values, and confirm overlay-only (not server-side splice) is acceptable for launch.
9. **F7 DEC-4** — rewire the simulation into a facade vs deprecate + rebuild; **DEC-5** default targeting scope; **DEC-6** who may run syndicate ads.

### Ticket count per feature
- F1: 8 (ADV2-101..108) — 4 BE, 3 APP, 1 VERIFY
- F2: 13 (ADV2-201..213) — 6 BE, 6 APP, 1 VERIFY
- F3: 7 (ADV2-301..307) — 4 BE, 1 VERIFY(BE), 1 APP, 1 VERIFY(APP)
- F4: 10 (ADV2-401..410) — 6 BE, 3 APP, 1 VERIFY
- F5: 11 (ADV2-501..511) — 6 BE, 5 APP
- F6: 10 (ADV2-601..610) — 6 BE, 4 APP
- F7: 11 (ADV2-701..711) — 8 BE, 3 APP
- **TOTAL: 70 tickets** across 6 epics.
