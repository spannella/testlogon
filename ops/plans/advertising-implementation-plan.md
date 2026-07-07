# TestLogon Advertising — Implementation Plan & Ticket Breakdown

Status: PLAN (uncommitted, for review). Author: grounded in a live re-read of the ad code on dev host `192.168.0.249` (`~/dev/testlogon`), 2026-07-07.
Scope: turn the existing ad **simulation** into a **live ad business** — real funding, real serving to viewers, real charging, real revenue attribution — across backend + Android app.

> Prod diverges from this dev clone. Every backend change lands as an `android-impl` commit AND (for anything already live) a re-apply artifact in `ops/prod-hotfixes/`. Verify prod feature flags via SSM before/after (see B0). Two-device on-device verification per user-facing ticket (Galaxy A15 `R5CX821TA9R` / Pixel 7a `32281JEHN13840`; admin acct `crash1782189692@testlogon.example`).

---

## 1. Overview & Current End-to-End Truth

The ad **control plane** is real and well-built: account/campaign/creative CRUD + admin review (`ad_accounts.py`, `ad_campaigns.py`, `ad_creatives.py`, `app/routers/ads.py`), a real targeting/decision engine (`ad_serving.serve_ad`), a genuinely-wired fraud system (`ad_fraud_prevention.py`), dayparting/flights, optimization, analytics, and a revenue-split (`ad_billing._split_revenue` → creator `ad_revenue_credit` + `platform_revenue_credit`). But the three wires that make it a *business* are absent. The lifecycle breaks in four places:

### 1a. CREATE — app cannot author the ad objects
- Backend has the full chain: `POST /ui/ads/accounts` → admin approve → `POST /ui/ads/accounts/{id}/deposit` → `POST /ui/ads/accounts/{id}/campaigns` → `POST /ui/ads/campaigns/{cid}/creatives` (+ `/upload`) → submit → review (`app/routers/ads.py:144-345`).
- The **app** exposes only read + deposit + studio-editors: `AdsAccountsApi.kt` has `GET accounts`, `GET accounts/{id}`, `GET .../campaigns`, `GET .../billing`, `POST .../deposit` — **no `POST ui/ads/accounts`, no `POST .../campaigns`, no `POST campaigns/{cid}/creatives`, no `/upload`** (`android/core-network/.../ads/AdsAccountsApi.kt:28-101`). The studio editors self-heal onto the *first* campaign of the *first* account via `AdsStudioCampaignResolver.resolveFirstCampaign()` (`.../feature/ads/studio/data/AdsStudioCampaignResolver.kt`) — there is nothing to create that account/campaign/creative from the phone.

### 1b. SERVE — nothing renders to a viewer
- Newsfeed injection is built and enabled: `_inject_sponsored_posts` runs every `sponsored_post_interval` (5) up to `sponsored_post_max_per_page` (3), gated on `S.sponsored_posts_enabled` (`app/routers/newsfeed.py:86-118`, flag default `true` at `settings.py:1126`). It calls `serve_ad(surface="newsfeed", creator_id="platform", slot_type="sponsored_post")` (`newsfeed.py:127-193`).
- But `serve_ad` returns the **house ad** whenever there are no eligible paid campaigns (`ad_serving.py:82-83 no_active_campaigns`, `:161-162 no_eligible_campaigns`), and `_fetch_sponsored_post` **drops house ads** (`newsfeed.py:143-144`) → in practice, empty.
- The app `PostDto` has **no sponsored fields** — no `is_sponsored`, `creative_id`, `campaign_id`, `impression_url`, `click_url`, `sponsor_label`, `cta_*` (`android/.../data/feed/FeedDtos.kt:31-68`). A sponsored dict from the backend deserializes as a blank normal post. The app **never calls `/ui/ads/serve` or `/ui/ads/track`** (confirmed: no such route reference anywhere in `android/app/src/main` or `core-network`).
- VOD pre-roll: `vod_ad_supported._resolve_ad_schedule` bypasses the live `serve_ad` because `vod_ad_supported_deterministic` defaults **true** (`settings.py:1774`; branch at `vod_ad_supported.py:109-143` only calls `serve_ad` when deterministic is false). App has `AdSupportedPlayerViewModel.kt` + `AdOverlay.kt` under `feature/vod/adsupported/` but they are **not wired into the real player** (dead unreferenced code).

### 1c. BILL — no real money moves
- `deposit_funds` stores `payment_method_id` in `meta` but **never charges it** — it only writes a `budget_deposit` ledger row and increments `balance_cents` (`ad_billing.py:30-64`). "The one lie in the system."
- `track_ad_event` (the app-facing `/ui/ads/track` path) does **fraud + impression-logging only — no charge** (`ad_serving.py:208-303`; writes to `ad_impressions`, increments freq cap, returns).
- The real charges (`charge_impression`/`charge_click`/`charge_conversion` → `_process_charge`, `ad_billing.py:67-157`) are wired **only** to admin `/ui/admin/ads/internal/charge-*` (`app/routers/ads.py:487-532`) and the dark broadcast pre-roll path (`broadcast_ads_billing_enabled` default **0**, `settings.py:566`).
- `_process_charge` debits with `SET balance_cents = balance_cents - :amt` and **no ConditionExpression** → balance can go **negative** (`ad_billing.py:133-138`). No idempotency key on charges.
- Serving ranks by `bid_cpm * 1.0` and picks the single highest (`ad_serving.py:152-166`) — **no auction, no second-price, no CPC/CPA bid fields** on the campaign (`CampaignCreateIn` has only `bid_cpm_cents`, `models.py:4441-4485`).

### 1d. ATTRIBUTE (CPA) — no click→conversion link
- There is **no `ad_click` store** (tables list has `ad_impressions`, `ad_accounts`, `ad_campaigns`, `ad_creatives`, `ad_frequency_caps`, `ad_billing`, `vod_ad_sessions` — no click/conversion table; `app/core/tables.py:160-483`). `ad_click_id` exists nowhere except a log line in `ad_creative_affiliate.py:342`.
- No `ad_click_id` threads into `POST /ui/shoppingcart/carts/{id}/purchase` (`shoppingcart.py:176`), `POST /api/plans/{plan_id}/subscribe` (`subscription_server.py:934`), or post-unlock (`newsfeed.unlock_post:5968`). Affiliate `redeem` is report-only.
- **What already works** and we build on: VOD ad-break `complete` **does** credit the creator once/slot/day (`ad_placement.record_ad_impression:346-355` → `_credit_ad_revenue:426-468`, dedup via `_claim_complete_slot`). That is the model for "creator share on a real content-owner placement."

**Verdict:** a sophisticated simulation. Wire (1) real funding, (2) a real bid+auction+charge, (3) placement-aware attribution, and the same objects become a live ad business.

---

## 2. Decisions

### 2.1 The 3 LOCKED decisions (reflected throughout)

1. **REAL BILLING RAIL.** `deposit_funds` must actually charge the payment method through the stripe-mock `PaymentIntent` (mirroring `app/routers/billing.py:1095-1175`: `ensure_stripe_configured()`, `get_or_create_customer(user_id)`, `stripe.PaymentIntent.create(amount, currency, customer, payment_method, off_session=True, confirm=True, idempotency_key=...)`), then credit `ad_accounts.balance_cents` only on `succeeded`. Every impression/click/conversion **debits** balance behind a **funds-guard** (`ConditionExpression="balance_cents >= :amt"`, no negative balance).
2. **BID MODEL.** Advertiser-set CPM/CPC/CPA bids + a **real auction** (second-price among eligible ads). Add `bid_cpc_cents` + `bid_cpa_cents` to the campaign model and to serve scoring.
3. **REVENUE ATTRIBUTION BY PLACEMENT.** Video pre-roll splits with the video's **ORIGINAL POSTER** (creator `ad_revenue_credit` ~70% + `platform_revenue_credit` ~30%). A **STANDALONE newsfeed sponsored unit** = **platform 100%, no creator credit**. The serve/charge path carries the in-front-of **content-owner sub**; `_split_revenue` fires the creator credit **only when a content-owner is present**. An ad against a newsfeed **VIDEO** post counts as video → the poster shares; a pure sponsored feed unit (`creator_id="platform"`) → platform only.

### 2.2 Still-open defaults (assumed as documented; confirm in §7)
- Min deposit `$50` (`MIN_DEPOSIT_CENTS=5000`), min campaign budget `$1` (`budget_cents ge=100`), CPM floor `$5`/`500` + bounds `$0.50–$200` (`models.py:4451-4453`). Propose CPC default `$0.50`/`50`, CPA default `$5`/`500`, with bounds.
- Creator split for video pre-roll: default `7000` bps (70%) = `DEFAULT_CREATOR_REVENUE_SHARE_BPS`, overridable per-creator via `content_ad_controls.get_creator_revenue_share_bps`.
- Frequency: newsfeed every 5, max 3/page; per-campaign caps `{1h:3, 24h:10, 7d:30}`.
- Subscriber ad opt-out: creator `allow_ads` + `ads_free_for_subscribers` (already honored in `serve_ad:76-78` and `vod_ad_supported._is_ads_free`).
- CPA window: **last-click 7 days** (`ad_click` TTL 7d). Conversions counted: subscription purchase, post-unlock, cart checkout.
- Placement selection: derived from creative `format` + surface `slot_type` (no explicit per-campaign placement picker in v1).

---

## 3. Target Architecture

### 3.1 Data flow (serve → track → charge → attribute → credit)

```
                          ┌────────────────────── VIEWER (Android app) ──────────────────────┐
                          │                                                                    │
  FEED LOAD               │  PLAYER OPEN (ad_supported video)                                  │
  GET /ui/newsfeed  ──────┤  POST /ui/vod/ad-supported/{vid}/start                             │
   backend injects        │   backend _resolve_ad_schedule (deterministic=false → serve_ad)    │
   _inject_sponsored_posts│                                                                    │
        │                 │            │                                                       │
        ▼                 │            ▼                                                       │
  serve_ad(surface=newsfeed,     serve_ad(surface=vod, creator_id=<POSTER>, content_id=<vid>) │
    creator_id="platform")          │  AUCTION: eligible campaigns → 2nd-price by effective bid│
        │  AUCTION (same)            │  mint ad_click_id  (store: ad_clicks pk=CLICK#{id} TTL7d)│
        │  mint ad_click_id          │                                                         │
        ▼                            ▼                                                         │
  PostDto{is_sponsored, creative_id, campaign_id, account_id,                                  │
          impression_url, click_url, ad_click_id, content_owner_id=""}    (feed card)          │
                          │                                                                    │
   ── IMPRESSION ──►  POST /ui/ads/track {event=impression, ad_click_id, content_owner_id}     │
                          │  track_ad_event → fraud gate → (NEW) charge_impression w/ auction  │
                          │      price → funds-guard debit → _split_revenue(content_owner)      │
   ── CLICK ──────►  POST /ui/ads/track {event=click, ad_click_id}                             │
                          │  → charge_click (CPC 2nd-price) + funds-guard + idempotent(ad_click)│
                          │  → mark ad_click "clicked"                                          │
                          └───────────────────────────┬────────────────────────────────────────┘
                                                       │  (later, within 7d)
                                                       ▼
             CONVERSION: subscribe / unlock / cart checkout carries ad_click_id
             POST /api/plans/{id}/subscribe | /ui/newsfeed unlock | /ui/shoppingcart/.../purchase
                                                       │
                                                       ▼
             attribute_conversion(ad_click_id): last-click ≤7d, not-yet-converted
                                                       │
                                                       ▼
             charge_conversion (CPA 2nd-price) → funds-guard debit → _split_revenue
                                                       │
             ┌─────────────────────────────────────────┴───────────────────────────────┐
             ▼ content_owner present (VOD poster / video post)      ▼ standalone unit (platform)
   creator ad_revenue_credit (~70%) + platform_revenue_credit (~30%)   platform_revenue_credit (100%)
             │                                                        (NO creator credit)
             ▼
   ad_roas.record(conversion, spend, revenue)  → ROAS reporting
```

### 3.2 `ad_click_id` lifecycle
- **Minted at serve** (`serve_ad`) for every filled *paid* ad (not house). Written to a new **`ad_clicks`** DDB item: `pk=CLICK#{ad_click_id}`, `sk=META`, `{campaign_id, account_id, creative_id, creator_id/content_owner_id, surface, slot_type, content_id, effective_price_cents (auction), bid model prices, user_id, status=served, created_at, ttl=created_at+604800}`.
- Returned in the serve response + carried into the feed `PostDto` / VOD schedule.
- **Threaded into `/ui/ads/track`** — impression sets `status=impressed`; click sets `status=clicked, clicked_at`.
- **Threaded into conversion endpoints** — `subscribe`, `unlock`, `cart purchase` accept an optional `ad_click_id`. On success, `attribute_conversion(ad_click_id)` claims it (conditional `status IN (clicked, impressed) AND attribute_not_exists(converted_at)`), fires `charge_conversion`, sets `status=converted`.
- **TTL 7d** — DynamoDB TTL on `ttl` attribute auto-expires the click store (last-click 7-day window).

### 3.3 Auction (second-price)
- In `serve_ad`, build candidates with an **effective bid** per objective: `awareness→CPM`, `traffic→CPC`, `conversions→CPA`, normalized to a common eCPM-comparable rank score (v1: rank by the campaign's primary bid for its objective; store the runner-up's bid).
- Winner pays **`min(own_bid, second_bid + 1 cent)`** for its model (classic 2nd-price); if only one eligible candidate, pays its own bid (or a reserve/floor = creator `min_cpm_cents` or platform floor). Store `effective_price_cents` on the `ad_clicks` item so track/charge uses the auction-cleared price, not the raw bid.

### 3.4 Revenue attribution by placement
- `serve_ad`/track/charge carry `content_owner_id`:
  - VOD pre-roll → `content_owner_id = video.owner_user_id` (the poster).
  - Newsfeed sponsored unit (`creator_id="platform"`) → `content_owner_id = ""` (none).
  - Ad against a newsfeed **video** post → `content_owner_id = <video poster>`.
- `_split_revenue` already resolves per-creator bps and writes both a creator credit and a platform credit; **change**: when `content_owner_id` is empty, **skip the creator credit** and write `platform_revenue_credit` for the **full** charge (100%). When present, keep the ~70/30 split. (Today `_split_revenue` uses `creator_id`; we make "no owner" mean platform-only rather than defaulting a creator.)

### 3.5 Funding / funds-guard
- `deposit_funds`: charge via stripe-mock PaymentIntent; only on `succeeded` write the `budget_deposit` ledger row (state settled) + increment balance. On non-succeeded, write `pending`/`failed` and do not credit. Idempotency key `addep:{account_id}:{amount}:{pm}`.
- `_process_charge`: debit with `ConditionExpression="balance_cents >= :amt"`; on `ConditionalCheckFailedException` → do **not** write the charge, return `{"ok": false, "reason": "insufficient_funds"}` and (optionally) auto-pause the campaign (`out_of_funds`). Idempotency: charge keyed on `ad_click_id + event` (conditional put on `ad_billing` sk so a retried track never double-charges).

### 3.6 New / changed endpoints, models, DDB items (summary)

| Kind | Item | Change |
|---|---|---|
| Endpoint | `POST /ui/ads/accounts` | already exists; **expose in app** (B1) |
| Endpoint | `POST /ui/ads/accounts/{id}/campaigns` | already exists; expose in app + add CPC/CPA (B1/B3) |
| Endpoint | `POST /ui/ads/campaigns/{cid}/creatives` (+`/upload`,`/submit`) | already exists; expose in app (B1) |
| Endpoint | `POST /ui/ads/serve` / `POST /ui/ads/track` | already exist; app calls them, add `ad_click_id`, `content_owner_id`, real charge (B1/B3) |
| Endpoint | `POST /api/plans/{id}/subscribe`, cart `/purchase`, unlock | add optional `ad_click_id` (B4) |
| Model | `CampaignCreateIn`/`CampaignUpdateIn` | add `bid_cpc_cents`, `bid_cpa_cents` (B3) |
| Model | `AdServeResponseOut`, `AdTrackEventIn` | add `ad_click_id`, `content_owner_id`, `effective_price_cents` (B1/B3) |
| Model | `PostDto` (app) | add sponsored fields (B1) |
| DDB | `ad_clicks` table | NEW — `pk=CLICK#{id}`, TTL 7d (B4, seam laid in B1) |
| DDB | `ad_campaigns` items | add `bid_cpc_cents`, `bid_cpa_cents` (B3) |
| DDB | `ad_billing` items | idempotent charge sk keyed on `ad_click_id#event` (B3) |
| Infra | stripe-mock customer/PM for advertiser | reuse `get_or_create_customer` (B1) |

---

## 4. Epics

- **B0 — Foundations / prod-parity.** Verify prod flags via SSM (`sponsored_posts_enabled`, `BROADCAST_ADS_BILLING_ENABLED`, `vod_ad_supported_deterministic`, `ad_fraud_detection_enabled`), reconcile dev↔prod divergence, create the `ad_clicks` table + settings, set the `ops/prod-hotfixes/` fold convention for the ad platform.
- **B1 — Real funding + serving-decision + newsfeed sponsored card + app create-screens.** Charge on deposit; make `serve_ad` mint `ad_click_id` and return real paid ads; add sponsored fields to `PostDto` + render a Sponsored card + fire impression/click to `/ui/ads/track`; build app create screens (account/campaign/creative+upload) replacing the auto-resolver.
- **B2 — Video pre-roll.** Flip `vod_ad_supported_deterministic=false`, wire the live `serve_ad` creative, and wire `AdSupportedPlayerScreen` + `AdOverlay` into the real player.
- **B3 — Impression/click real charge + budget depletion + auction.** Make `track_ad_event` actually charge (CPM/CPC/CPA per objective), add CPC/CPA bids, 2nd-price auction, funds-guard, idempotency; budget-alert/auto-complete already real.
- **B4 — CPA attribution + revenue credit.** `ad_clicks` store (TTL 7d); thread `ad_click_id` through subscribe/unlock/cart; on conversion call `charge_conversion` + `_split_revenue` (placement-aware) + `ad_roas`.
- **B5 — Hardening.** Idempotency everywhere, refund/reversal on ad charges, ROAS reporting surface, backend + app tests, prod fold + 2-device sign-off.

---

## 5. Tickets

> Convention: `ADV-<epic><nn>`. EFFORT S≈≤0.5d, M≈1–2d, L≈3–5d. All backend tickets also produce an `ops/prod-hotfixes/` re-apply artifact when the touched code is already live in prod.

### EPIC B0 — Foundations / prod-parity

**ADV-001 — Verify prod ad feature flags via SSM & document divergence** · infra · S
- DESC: Read the live prod env for `SPONSORED_POSTS_ENABLED`, `SPONSORED_POST_INTERVAL/MAX_PER_PAGE`, `BROADCAST_ADS_BILLING_ENABLED`, `VOD_AD_SUPPORTED_DETERMINISTIC`, `VOD_AD_SUPPORTED_ENABLED`, `AD_FRAUD_DETECTION_ENABLED`, `VOD_AD_CPM_CENTS`; compare to dev defaults; record the gap so later flips are intentional.
- AC: a table of {flag, dev default, prod value, target}; confirmed which surfaces are live in prod today (expect sponsored posts *enabled but empty*, broadcast billing *off*, vod deterministic *on*).
- FILES: `app/core/settings.py:566,1126-1129,1692,1737,1771-1774`; prod `.env.local` via SSM.
- DEPS: none. VERIFY: `aws ssm send-command` reads prod env; document in `ops/prod-hotfixes/ads/README.md`.

**ADV-002 — Create `ad_clicks` DDB table + settings + TTL** · infra · S
- DESC: Add `ad_clicks_table_name` setting + `T.ad_clicks` wiring; create table dev (moto/DDB-Local) and prod with `pk`/`sk` and a DynamoDB TTL on `ttl`. This is the seam B1 mints into and B4 reads.
- AC: `T.ad_clicks` resolves in dev + prod; TTL enabled on `ttl`; put/get round-trips; hidden-table gotcha avoided (exact-name access).
- FILES: `app/core/settings.py`, `app/core/tables.py:160-483` (add `ad_clicks: Any` + `_safe_table`), infra table-create script.
- DEPS: none. VERIFY: boto3 put/get against `http://localhost:8001`; prod `describe-table` shows TTL enabled.

**ADV-003 — Ad-platform prod-hotfix fold convention** · infra · S
- DESC: Establish `ops/prod-hotfixes/ads/` with a README describing the re-apply order (settings → tables → billing → serving → routers) since prod source diverges from `android-impl`.
- AC: README lists each ad backend patch + apply order + SSM/restart steps; referenced by every B1–B5 backend ticket.
- FILES: `ops/prod-hotfixes/ads/`. DEPS: ADV-001. VERIFY: doc review.

### EPIC B1 — Real funding + serving decision + sponsored card + app create-screens

**ADV-101 — `deposit_funds` charges the payment method (real billing rail)** · backend · M
- DESC: Replace the "store PM but never charge" behavior with a real stripe-mock charge. Mirror `billing.py:1095-1175`: `ensure_stripe_configured()`, `get_or_create_customer(owner_sub)`, `stripe.PaymentIntent.create(amount=amount_cents, currency="usd", customer, payment_method=payment_method_id, off_session=True, confirm=True, idempotency_key="addep:{account}:{amt}:{pm}")`. Only on `status=="succeeded"` write the `budget_deposit` ledger (settled) + increment `balance_cents`; else write `pending/failed` and do not credit. Keep `MIN_DEPOSIT_CENTS` guard.
- AC: deposit with a good PM → PaymentIntent succeeded, balance rises by amount, ledger row has `stripe_payment_intent_id`; declined PM → 402/failed, balance unchanged; no PM → 400; duplicate idempotency key → single charge; `< $50` → 400.
- FILES: `app/services/ad_billing.py:30-64`; `app/routers/ads.py:445-452`; reuse `app/routers/billing.py:636-704`.
- DEPS: ADV-003. EFFORT M. VERIFY: `POST /ui/ads/accounts/{id}/deposit` contract (success/decline/dup); ledger + `ad_accounts.balance_cents` inspected.

**ADV-102 — Funds-guard on `_process_charge` (no negative balance)** · backend · S
- DESC: Add `ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt"` to the balance debit; on `ConditionalCheckFailedException` skip the ledger write + revenue split and return `{"ok": false, "reason": "insufficient_funds"}`. Optionally flip campaign to a paused `out_of_funds` state.
- AC: charge with sufficient balance debits atomically; charge that would go negative is rejected, writes nothing, balance unchanged; concurrent charges never oversell (conditional write).
- FILES: `app/services/ad_billing.py:107-157`. DEPS: ADV-101. EFFORT S. VERIFY: unit test drives balance to 0 then charges → rejected; internal `/charge-*` contract.

**ADV-103 — `serve_ad` mints `ad_click_id` + carries `content_owner_id` + returns paid ads** · backend · M
- DESC: When a paid winner is selected, mint `ad_click_id`, persist an `ad_clicks` item (`status=served`, TTL 7d, `content_owner_id`, `effective_price_cents` placeholder = winning bid until B3 auction), and add `ad_click_id`/`content_owner_id` to the serve response and tracking URLs. Set `content_owner_id` from the caller: VOD → poster, standalone newsfeed → "".
- AC: `POST /ui/ads/serve` for an eligible paid campaign returns `filled=true, is_house_ad=false, ad_click_id, content_owner_id, impression_url/click_url` carrying `ad_click_id`; an `ad_clicks` row exists with TTL≈now+7d; house-ad path mints nothing.
- FILES: `app/services/ad_serving.py:45-205`; `app/models.py:4944-5010` (`AdServeRequestIn` add `content_owner_id`, `AdServeResponseOut` add `ad_click_id`/`content_owner_id`); `T.ad_clicks`.
- DEPS: ADV-002. EFFORT M. VERIFY: serve contract returns a click id + row present; two serves mint distinct ids.

**ADV-104 — Newsfeed sponsored injection returns real paid units end-to-end** · backend · S
- DESC: `_fetch_sponsored_post` already drops house ads; ensure it surfaces the new serve fields (`ad_click_id`, `account_id`, `content_owner_id=""`) into the sponsored dict, and that `_post_to_dict`/read projection passes them through so the app receives them. Keep `allow_ads_near` + hidden-ad filtering.
- AC: with an eligible paid campaign, a feed load injects a sponsored dict carrying `is_sponsored, creative_id, campaign_id, account_id, ad_click_id, impression_url, click_url, cta_*`; with no paid campaigns, no sponsored item appears (house ad still suppressed).
- FILES: `app/routers/newsfeed.py:86-193, 2176-2342`. DEPS: ADV-103. EFFORT S. VERIFY: seed a paid campaign+approved creative, `GET /ui/newsfeed`, assert sponsored fields present.

**ADV-105 — App `PostDto` sponsored fields + Sponsored feed card** · app · M
- DESC: Add sponsored fields to `PostDto` (`is_sponsored`, `sponsor_label`, `headline`, `cta_text`, `cta_url`, `creative_id`, `campaign_id`, `account_id`, `impression_url`, `click_url`, `ad_click_id`, `content_owner_id`). Render a distinct **Sponsored** card in the feed (label + CTA button + "Why this ad?"/hide via existing `/ui/ads/feedback`). Map DTO→domain in feed mappers.
- AC: a sponsored post renders with a Sponsored chip + CTA; a normal post is unchanged; hide sends feedback and removes the unit; both phones render without crash.
- FILES: `android/.../data/feed/FeedDtos.kt:31-68`; feed mappers + `feature/feed/*` card composables.
- DEPS: ADV-104. EFFORT M. VERIFY: 2-device — sponsored card visible in feed; hide works.

**ADV-106 — App fires impression + click to `/ui/ads/track`** · app · M
- DESC: Add an `AdsTrackApi` (`POST ui/ads/track`) + `AdServeApi` (`POST ui/ads/serve` for surfaces the app drives directly). On sponsored-card first-view fire `event=impression` (with `ad_click_id`, `content_owner_id`, `creative_id/campaign_id/account_id/surface/slot_type/content_id/creator_id`); on CTA tap fire `event=click` then open `cta_url`. Debounce impression once per card instance.
- AC: scrolling a sponsored card into view fires exactly one impression; CTA tap fires one click then navigates; payload matches `AdTrackEventIn`; verified server-side (impression row / click).
- FILES: NEW `android/.../data/ads/AdsTrackApi.kt` + repo; feed card view-tracking hook; `AdTrackEventIn` (`models.py:5340`).
- DEPS: ADV-105, ADV-103. EFFORT M. VERIFY: 2-device + server log/`ad_impressions` shows impression then click.

**ADV-107 — App create-screen: advertiser account** · app · M
- DESC: Add `POST ui/ads/accounts` to `AdsAccountsApi` + a "Create ad account" screen (company_name, billing_email) and a deposit-with-real-PM flow (reuse existing payment-method selection). Show pending_review state until admin approval.
- AC: from the phone a user creates an account (201), sees it pending, and after admin approve can deposit real funds; validation errors surfaced (422/400).
- FILES: `android/core-network/.../ads/AdsAccountsApi.kt:28-101` (add create); NEW `feature/ads/accounts/create/*`; backend `app/routers/ads.py:144-149` (exists).
- DEPS: ADV-101. EFFORT M. VERIFY: 2-device create → admin approve (admin acct) → deposit succeeds.

**ADV-108 — App create-screen: campaign** · app · M
- DESC: Add `POST ui/ads/accounts/{id}/campaigns` + `POST .../submit` to the app; a campaign create screen (name, objective, budget + type, bid_cpm; CPC/CPA once B3 lands, start/end, category). Replace the `AdsStudioCampaignResolver` auto-resolve with a real campaign picker feeding the studio editors.
- AC: create a draft campaign (201), edit, submit for review; the targeting/scheduling/optimization editors open against the *selected* campaign, not "first-of-first"; admin can approve it.
- FILES: NEW `feature/ads/campaigns/create/*` + campaign picker; retire/att `AdsStudioCampaignResolver.kt`; backend `ads.py:167-219` (exists).
- DEPS: ADV-107. EFFORT M. VERIFY: 2-device create→submit→admin approve→active.

**ADV-109 — App create-screen: creative + asset upload** · app · L
- DESC: Add `POST ui/ads/campaigns/{cid}/creatives`, `POST .../{crid}/upload` (multipart via the OS picker seam), `POST .../submit` to the app; a creative editor (format, title, headline, body, cta_text/url, rotation_weight) + image/video upload (respect backend magic-byte + size limits: image ≤5MB JPEG/PNG/WebP, video ≤50MB MP4).
- AC: create a creative, upload a valid image/video (invalid type/size rejected with the backend's 400), submit; admin approves; the creative then becomes eligible to serve.
- FILES: NEW `feature/ads/creatives/*` + upload; reuse picker seam (`ops/testing/pick_real.sh`); backend `ads.py:265-345` + `ad_creatives.py:125-166`.
- DEPS: ADV-108. EFFORT L. VERIFY: 2-device create+upload (picker seam) → admin approve → appears in serve.

**ADV-110 — End-to-end seed + serve smoke (newsfeed)** · test · S
- DESC: A scripted contract test that walks create→approve→deposit→campaign→creative→approve→serve→feed-injection using the dev-bearer/admin accounts, proving a paid sponsored unit reaches `GET /ui/newsfeed`.
- AC: repeatable script yields a sponsored card in the feed; asserts serve fields + `ad_clicks` row.
- FILES: `ops/testing/ads_e2e_newsfeed.sh` (new). DEPS: ADV-104..106. EFFORT S. VERIFY: script green.

### EPIC B2 — Video pre-roll

**ADV-201 — Flip VOD to live ad selection (`deterministic=false`) safely** · backend · M
- DESC: Gate the live path so `_resolve_ad_schedule` uses `serve_ad` (surface=`vod`, `creator_id=video.owner_user_id`, `content_owner_id=poster`) when a new flag is on, falling back to the deterministic placeholder when serve is unfilled — so E2E stays reproducible and a no-fill never blocks playback.
- AC: with the flag on + an eligible campaign, the pre-roll schedule carries a real `creative_id`/`creative_url` + `ad_click_id`; with no fill, the placeholder plays and playback still works; subscriber ad-free still bypasses.
- FILES: `app/services/vod_ad_supported.py:90-158`; `app/core/settings.py:1774`.
- DEPS: ADV-103. EFFORT M. VERIFY: `POST /ui/vod/ad-supported/{vid}/start` returns a real creative; fallback path verified.

**ADV-202 — Wire `AdSupportedPlayerScreen` + `AdOverlay` into the real player** · app · L
- DESC: Connect the currently-dead `AdSupportedPlayerViewModel`/`AdOverlay` (`feature/vod/adsupported/`) into the actual VOD player: call `/start`, render the pre-roll (skip after N s), gate continued playback on `/break` complete, mid-roll overlays. Fire `/break` events (impression/complete/skip).
- AC: opening an `ad_supported` video plays the pre-roll, skip appears after `skip_after_seconds`, completing the break unlocks the video, mid-rolls fire at position; subscriber ad-free skips ads; both phones.
- FILES: `android/.../feature/vod/adsupported/AdSupportedPlayerViewModel.kt`, `AdOverlay.kt`, `data/vod/adsupported/VodAdSupportedRepository.kt`; player entry.
- DEPS: ADV-201. EFFORT L. VERIFY: 2-device pre-roll→complete→unlock; skip; ad-free subscriber.

**ADV-203 — Pre-roll completion charges + credits the poster** · backend · M
- DESC: On VOD pre-roll `complete`, charge the advertiser (CPM/auction) and split with the **poster** (`content_owner_id`). Reconcile the two revenue paths: the legacy `ad_placement._credit_ad_revenue` (video metadata CPM) vs the new advertiser-funded `_split_revenue` — ensure a completed paid pre-roll credits the poster from advertiser spend, not a phantom CPM, and does not double-credit.
- AC: a completed paid pre-roll debits the advertiser (funds-guard), credits the poster ~70% + platform ~30%, once per slot/user/day (existing dedup); an unfilled/placeholder pre-roll credits nobody from advertiser funds.
- FILES: `app/services/vod_ad_supported.py:336-412`, `app/services/ad_placement.py:346-468`, `app/services/ad_billing.py:_split_revenue`.
- DEPS: ADV-201, ADV-301, ADV-302. EFFORT M. VERIFY: ledger shows advertiser debit + poster credit + platform credit; dedup holds.

### EPIC B3 — Impression/click real charge + budget depletion + auction

**ADV-301 — Add CPC/CPA bids to the campaign model** · backend · S
- DESC: Add `bid_cpc_cents` + `bid_cpa_cents` to `CampaignCreateIn`/`CampaignUpdateIn` (bounded), persist in `create_campaign`, and surface in `update_campaign`. Defaults: CPC `50`, CPA `500`.
- AC: create/update accept + persist CPC/CPA; bounds enforced; existing CPM-only clients still work (defaults applied).
- FILES: `app/models.py:4441-4485,4786-4796`; `app/services/ad_campaigns.py:35-63`.
- DEPS: none. EFFORT S. VERIFY: campaign create/get contract shows new fields.

**ADV-302 — Second-price auction in `serve_ad` + cleared price on `ad_clicks`** · backend · M
- DESC: Rank eligible candidates by the campaign's objective bid; compute the second-price cleared amount `min(own_bid, runner_up_bid + 1)` (or floor when singleton) for the relevant model; store `effective_price_cents` (+ per-model prices) on the `ad_clicks` item so track/charge bills the cleared price.
- AC: with two eligible campaigns, the higher bid wins and is charged the runner-up+1; with one, charged its bid or the floor; `ad_clicks.effective_price_cents` reflects the clearing.
- FILES: `app/services/ad_serving.py:85-205`. DEPS: ADV-103, ADV-301. EFFORT M. VERIFY: unit test with 2 campaigns asserts winner + cleared price.

**ADV-303 — `track_ad_event` performs the real charge (impression/click)** · backend · M
- DESC: After the fraud gate passes, charge based on event+objective using the cleared price from the `ad_clicks` item: impression→`charge_impression` (awareness/CPM), click→`charge_click` (traffic/CPC). Pass `content_owner_id` through so `_split_revenue` attributes correctly. Update `ad_clicks` status.
- AC: an impression on a paid unit debits the advertiser at the cleared CPM and (VOD) credits the poster; a click debits at cleared CPC; a fraud-flagged event charges nothing; standalone newsfeed unit → platform 100%, no creator credit.
- FILES: `app/services/ad_serving.py:208-303`; `app/services/ad_billing.py:67-104`.
- DEPS: ADV-102, ADV-302. EFFORT M. VERIFY: `/ui/ads/track` contract → `ad_billing` + balance move; fraud path no-charge.

**ADV-304 — Charge idempotency on `ad_click_id + event`** · backend · S
- DESC: Make each charge idempotent: conditional put on an `ad_billing` sk derived from `{ad_click_id}#{event}` (`attribute_not_exists`), so a retried/duplicate track never double-charges. Return the prior result on conflict.
- AC: two identical track calls (same `ad_click_id`+event) → exactly one charge; distinct events on the same click each charge once.
- FILES: `app/services/ad_billing.py:107-157`. DEPS: ADV-303. EFFORT S. VERIFY: replay the same track twice → one ledger row.

**ADV-305 — Budget depletion → auto-complete + serve exclusion (verify)** · test · S
- DESC: Confirm the existing `_check_budget_and_alert` (50/80/100% alerts + auto-complete at 100%) fires under real charges and that `_has_budget`/status excludes depleted campaigns from `serve_ad`. Add the `out_of_funds` pause from ADV-102.
- AC: charging a campaign to 100% emits alerts, transitions it to `completed`, and it stops being served; an out-of-funds account is excluded.
- FILES: `app/services/ad_billing.py:265-365`, `app/services/ad_serving.py:119-120,347-357`. DEPS: ADV-303. EFFORT S. VERIFY: drive spend to budget, assert completed + no serve.

**ADV-306 — App: CPC/CPA bid inputs in campaign create/edit** · app · S
- DESC: Extend the ADV-108 campaign screen with CPC/CPA bid fields (shown per objective) mapped to the new model fields.
- AC: create/edit sends CPC/CPA; objective drives which bid is primary; both phones.
- FILES: `feature/ads/campaigns/create/*`, campaign DTO. DEPS: ADV-301, ADV-108. EFFORT S. VERIFY: 2-device create with CPC/CPA → persisted.

### EPIC B4 — CPA attribution + revenue credit

**ADV-401 — `ad_clicks` attribution service (claim + last-click 7d)** · backend · M
- DESC: `attribute_conversion(ad_click_id, conversion_type, conversion_value_cents)` that loads the click, checks `created_at ≥ now-7d` and `status in (clicked, impressed)` and not yet converted, atomically claims it (conditional `attribute_not_exists(converted_at)`), then calls `charge_conversion` (CPA cleared price) with `content_owner_id` and records for ROAS. Idempotent + safe on missing/expired clicks (no-op).
- AC: a valid click within 7d converts once (charge_conversion fires, status=converted); a second attempt is a no-op; an expired/unknown click is a no-op; standalone unit → platform 100%.
- FILES: NEW `app/services/ad_attribution.py`; `app/services/ad_billing.py:94-104`; `T.ad_clicks`.
- DEPS: ADV-002, ADV-102, ADV-302. EFFORT M. VERIFY: unit test valid/dup/expired.

**ADV-402 — Thread `ad_click_id` into subscribe** · backend · S
- DESC: Accept optional `ad_click_id` on `POST /api/plans/{plan_id}/subscribe`; on a successful charge, call `attribute_conversion(..., "subscription", plan_price)`.
- AC: subscribing with a valid `ad_click_id` fires one conversion charge + credit; without it, unchanged; failed subscription → no conversion.
- FILES: `app/routers/subscription_server.py:934-1112`. DEPS: ADV-401. EFFORT S. VERIFY: subscribe-with-click contract → conversion ledger.

**ADV-403 — Thread `ad_click_id` into cart checkout** · backend · S
- DESC: Accept `ad_click_id` on `CartPurchaseIn` / `POST /ui/shoppingcart/carts/{id}/purchase`; on success attribute `"purchase"` with the order total.
- AC: purchase-with-click → one conversion; idempotent with the existing `X-Idempotency-Key`; no double attribution on retried purchase.
- FILES: `app/routers/shoppingcart.py:176-200`; `app/models.py:897-899 (CartPurchaseIn)`. DEPS: ADV-401. EFFORT S. VERIFY: purchase-with-click contract.

**ADV-404 — Thread `ad_click_id` into post-unlock** · backend · S
- DESC: Accept `ad_click_id` on the unlock request; on a successful paid unlock attribute `"unlock"` with the unlock price.
- AC: unlock-with-click → one conversion; the existing unlock idempotency/throttle unaffected.
- FILES: `app/routers/newsfeed.py:5968 (unlock_post)` + `UnlockPostRequest`. DEPS: ADV-401. EFFORT S. VERIFY: unlock-with-click contract.

**ADV-405 — App carries `ad_click_id` from ad click → conversion** · app · M
- DESC: Persist the `ad_click_id` from the last ad click (feed CTA / pre-roll CTA) in a short-lived store; when the user then subscribes / unlocks / checks out within the session, attach it to the request. Clear after use / after 7d.
- AC: tapping an ad CTA then subscribing attaches the `ad_click_id`; the conversion is attributed server-side; unrelated conversions carry none; both phones.
- FILES: NEW `android/.../data/ads/AdClickAttributionStore.kt`; subscribe/cart/unlock repos. DEPS: ADV-402..404, ADV-106. EFFORT M. VERIFY: 2-device click→subscribe → conversion ledger + attribution.

**ADV-406 — `_split_revenue` placement-aware (platform-only when no owner)** · backend · S
- DESC: Make `_split_revenue` treat an empty `content_owner_id` as **platform-100%** (skip the creator credit; write the full amount as `platform_revenue_credit`), and keep the ~70/30 split when an owner is present. Replace any implicit creator default.
- AC: a standalone newsfeed conversion credits platform 100%, no creator row; a VOD conversion credits poster ~70% + platform ~30%; transparency log only written when an owner exists.
- FILES: `app/services/ad_billing.py:160-262`. DEPS: ADV-303/ADV-401. EFFORT S. VERIFY: two charges (owner vs no-owner) → correct ledger rows.

### EPIC B5 — Hardening

**ADV-501 — ROAS reporting surface (`ad_roas`)** · backend · M
- DESC: Ensure conversions feed `ad_roas` (spend vs attributed conversion value) and expose a per-campaign ROAS endpoint + include in analytics summary.
- AC: `GET /ui/ads/analytics/summary` (or a new ROAS endpoint) returns spend, conversions, conversion value, ROAS for a campaign; matches ledger.
- FILES: `app/services/ad_roas.py`, `app/routers/ads.py:541-580`, `app/services/ad_analytics.py`. DEPS: ADV-401. EFFORT M. VERIFY: endpoint contract vs seeded conversions.

**ADV-502 — Ad-charge refund / reversal** · backend · M
- DESC: A reversal path for a charge (fraud clawback, disputed conversion): re-credit the advertiser balance, reverse creator/platform credits, mark the `ad_billing` entry reversed — mirroring the ecom refund `entry_id=txn_id` convention and Bug#3 `entry_type` bucketing so earnings/payouts stay consistent.
- AC: reversing a charge restores advertiser balance, backs out creator+platform credits, is idempotent, and shows in billing history; does not corrupt creator earnings query.
- FILES: `app/services/ad_billing.py`; admin endpoint under `/ui/admin/ads/`. DEPS: ADV-303, ADV-401. EFFORT M. VERIFY: charge→reverse contract; balances net zero.

**ADV-503 — App ROAS / campaign performance surface** · app · S
- DESC: Show spend/conversions/ROAS on the campaign detail + AdsBilling screens.
- AC: campaign detail shows spend, conversions, ROAS from the endpoint; both phones.
- FILES: `feature/adsbilling/*`, `feature/ads/analytics/*`. DEPS: ADV-501. EFFORT S. VERIFY: 2-device render.

**ADV-504 — Backend test suite for the money paths** · test · M
- DESC: Unit/contract tests for deposit-charge, funds-guard, auction clearing, charge idempotency, attribution (valid/dup/expired), placement split (owner vs none), reversal.
- AC: tests cover each AC above; green in dev; documents the seed fixtures.
- FILES: `app/tests/ads/*` (or repo test dir). DEPS: B1–B4. EFFORT M. VERIFY: test run green.

**ADV-505 — Prod fold + 2-device sign-off + flag flips** · infra · M
- DESC: Fold all backend patches into `ops/prod-hotfixes/ads/`, apply to prod via SSM, flip the go-live flags (`VOD_AD_SUPPORTED_DETERMINISTIC=0`, confirm `SPONSORED_POSTS_ENABLED=true`, decide `BROADCAST_ADS_BILLING_ENABLED`), and run the full 2-device suite (create→approve→deposit→serve→impression/click charge→convert→credit) on both phones + web parity check.
- AC: prod serves real paid ads, charges real deposits, attributes conversions; 2-device suite passes; APK shipped (presigned S3 URL); commits on `android-impl` + prod-hotfixes folded.
- FILES: `ops/prod-hotfixes/ads/*`. DEPS: all. EFFORT M. VERIFY: 2-device end-to-end + prod ledger inspection.

---

## 6. Execution Sequence & Summary

### Dependency-ordered sequence
1. **B0**: ADV-001 → ADV-002 → ADV-003.
2. **B1 backend**: ADV-101 → ADV-102 → ADV-103 → ADV-104.
3. **B1 app**: ADV-105 → ADV-106; ADV-107 → ADV-108 → ADV-109; ADV-110 smoke.
4. **B3** (before charging goes live): ADV-301 → ADV-302 → ADV-303 → ADV-304 → ADV-305 → ADV-306.
5. **B2**: ADV-201 → ADV-202 → ADV-203.
6. **B4**: ADV-401 → (ADV-402, ADV-403, ADV-404) → ADV-405 → ADV-406.
7. **B5**: ADV-501 → ADV-502 → ADV-503 → ADV-504 → ADV-505.

> Note: B3 is sequenced right after B1 so the app never fires tracks that silently no-charge for long; B2 can proceed in parallel with B3 once ADV-103 lands.

### Summary table

| Ticket | Epic | Title | Type | Effort | Deps |
|---|---|---|---|---|---|
| ADV-001 | B0 | Verify prod ad flags via SSM | infra | S | — |
| ADV-002 | B0 | Create `ad_clicks` table + TTL | infra | S | — |
| ADV-003 | B0 | Ad-platform prod-hotfix fold convention | infra | S | 001 |
| ADV-101 | B1 | `deposit_funds` charges the PM | backend | M | 003 |
| ADV-102 | B1 | Funds-guard on `_process_charge` | backend | S | 101 |
| ADV-103 | B1 | `serve_ad` mints `ad_click_id` + owner | backend | M | 002 |
| ADV-104 | B1 | Newsfeed injection returns paid units | backend | S | 103 |
| ADV-105 | B1 | App `PostDto` sponsored fields + card | app | M | 104 |
| ADV-106 | B1 | App fires impression/click track | app | M | 105,103 |
| ADV-107 | B1 | App create account screen | app | M | 101 |
| ADV-108 | B1 | App create campaign screen | app | M | 107 |
| ADV-109 | B1 | App create creative + upload | app | L | 108 |
| ADV-110 | B1 | E2E seed+serve smoke | test | S | 104-106 |
| ADV-201 | B2 | Flip VOD to live ad selection | backend | M | 103 |
| ADV-202 | B2 | Wire pre-roll player + overlay | app | L | 201 |
| ADV-203 | B2 | Pre-roll completion charges+credits poster | backend | M | 201,301,302 |
| ADV-301 | B3 | Add CPC/CPA bids to campaign | backend | S | — |
| ADV-302 | B3 | Second-price auction + cleared price | backend | M | 103,301 |
| ADV-303 | B3 | `track_ad_event` real charge | backend | M | 102,302 |
| ADV-304 | B3 | Charge idempotency on click+event | backend | S | 303 |
| ADV-305 | B3 | Budget depletion/auto-complete verify | test | S | 303 |
| ADV-306 | B3 | App CPC/CPA bid inputs | app | S | 301,108 |
| ADV-401 | B4 | Attribution service (last-click 7d) | backend | M | 002,102,302 |
| ADV-402 | B4 | Thread click into subscribe | backend | S | 401 |
| ADV-403 | B4 | Thread click into cart checkout | backend | S | 401 |
| ADV-404 | B4 | Thread click into post-unlock | backend | S | 401 |
| ADV-405 | B4 | App carries click → conversion | app | M | 402-404,106 |
| ADV-406 | B4 | `_split_revenue` placement-aware | backend | S | 303,401 |
| ADV-501 | B5 | ROAS reporting surface | backend | M | 401 |
| ADV-502 | B5 | Ad-charge refund/reversal | backend | M | 303,401 |
| ADV-503 | B5 | App ROAS surface | app | S | 501 |
| ADV-504 | B5 | Backend money-path tests | test | M | B1-B4 |
| ADV-505 | B5 | Prod fold + 2-device sign-off | infra | M | all |

### Effort roll-up
- Total tickets: **33** (B0:3, B1:10, B2:3, B3:6, B4:6, B5:5).
- By size: **S ×15**, **M ×15**, **L ×3**.
- Rough person-days (S≈0.4, M≈1.5, L≈4): 15×0.4 + 15×1.5 + 3×4 = **≈40.5 dev-days** (~8 focused weeks solo; less with backend/app parallelism). By type: backend ~17, app ~12 (incl. the L player/creative screens), infra ~5, test ~3 tickets.

---

## 7. Open Questions (resolve before/at build)

1. **Auction normalization across objectives** — how to make CPM vs CPC vs CPA bids comparable in one ranking (predicted CTR/CVR needed for a true eCPM)? v1 ranks within objective / by primary bid; is a cross-objective eCPM required for launch?
2. **CPA conversion value** — attribute the full order/plan price, or a fixed CPA bid amount? (Plan assumes charge = CPA bid; ROAS uses order value.)
3. **Reserve / floor price** for singleton auctions — creator `min_cpm_cents`, a platform floor, or the bid itself?
4. **Broadcast pre-roll** — bring `BROADCAST_ADS_BILLING_ENABLED` into scope now (it's a fourth surface) or defer? Plan defers to a follow-on.
5. **Deposit payment method** — do advertisers reuse their consumer stripe-mock customer/PM (`get_or_create_customer(owner_sub)`) or a separate advertiser billing profile?
6. **Attribution model** — last-click only, or last-click with view-through fallback (impression→conversion) for awareness campaigns?
7. **Insufficient-funds behavior** — hard-pause the campaign (`out_of_funds`) vs skip-and-continue-serving; and how quickly the account can top up + auto-resume.
8. **Double-credit reconciliation (ADV-203)** — the legacy `ad_placement._credit_ad_revenue` CPM credit vs the new advertiser-funded split: retire the legacy phantom-CPM credit for paid pre-rolls, or keep it for house/unfilled only?
9. **Fraud vs billing ordering** — confirm a fraud-flagged event charges nothing (current plan) and whether flagged clicks should still burn the `ad_click` (they should not convert).
10. **Prod flag flips** — timing/blast-radius of `VOD_AD_SUPPORTED_DETERMINISTIC=0` on prod given E2E depends on determinism; stage behind a canary?
