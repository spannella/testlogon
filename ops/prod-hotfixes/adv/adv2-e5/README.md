# ADV2-E5 (F5) — Shared ad-messaging billing engine + sponsored mass-messaging

LIVE PROD HOTFIX via SSM (prod `i-08f937fc705ebea75`). Backend-only.

## What shipped
- **NEW `app/services/ad_messaging.py`** — the SHARED ad-messaging engine + F5.
  - **Hybrid billing engine** (`charge_event`): per (message, recipient) event,
    config cents `AD_MSG_DELIVERED_CENTS=2` / `AD_MSG_OPEN_CENTS=5` /
    `AD_MSG_CLICK_CENTS=10`, funnel-STACKING (a clicked message = 2+5+10 = 17c),
    idempotent per `{ad_click_id}#{event}`, funds-guarded + split via
    `ad_billing._process_charge`/`_split_revenue`. `creator_sub` present ->
    creator 70% / platform 30% (F5); `""` -> platform 100% (F6 reuse).
  - **Per-recipient delivery state** on the minted AdClicks row (surface
    `ad_message`): delivered_at/opened_at/clicked_at.
  - **Send record + counters** on `sponsorship_deals` (distinct key space
    `AMSG#`); offers on `AMSGOFFER#` with isolated GSI partitions
    `AMSG_ADV#`/`AMSG_CREATOR#` (never mix with SPCP/brand deals).
  - **F5** (reuses the E4 proposal/approve pattern): `create_offer` (advertiser
    draft) -> `list_pending_for_creator` -> `approve_and_send` (ONLY the targeted
    creator; atomic-claim; D3 no forced label; sends to the creator audience AS
    the creator with delivered billing + creator 70% share). `record_open` /
    `record_click` charge the surcharges once.
  - **Audience** (`resolve_creator_audience`): creator followers (GSI5,
    enumerable) minus per-user ad opt-outs; subscriber-only enumeration is the
    known DEC-2 gap (deferred, logged; `subscriber_enumeration=deferred_dec2_followers_only`).
  - **Per-user ad opt-out** (`user_accepts_ad_messages`/`set_ad_messages_optout`)
    on the shared `message_privacy.allow_ad_messages` (default True).
- **APPEND to `app/routers/ads.py`** — 9 endpoints under `/ui/ads`
  (`ads_endpoints_block.py`), idempotent-guarded on the marker
  `Ad-messaging: shared engine + F5 sponsored mass-messaging (ADV2-E5)`.

## Endpoints
```
POST /ui/ads/sponsored-messages/offers                       advertiser draft
GET  /ui/ads/sponsored-messages/offers/inbox                 creator queue
GET  /ui/ads/sponsored-messages/offers/outbox                advertiser outbox
POST /ui/ads/sponsored-messages/offers/{offer_id}/approve    creator -> SEND
POST /ui/ads/sponsored-messages/offers/{offer_id}/reject     creator
GET  /ui/ads/sponsored-messages/sends/{send_id}              progress
POST /ui/ads/messages/{ad_click_id}/open                     recipient +5c
POST /ui/ads/messages/{ad_click_id}/click                    recipient +10c
GET/PUT /ui/ads/messages/ad-preferences                      per-user opt-out
```

## Apply (idempotent)
```
python ops/prod-hotfixes/adv/adv2-e5/apply_adv2e5.py            # ROOT=. (dev clone)
ROOT=/home/ubuntu/testlogon python .../apply_adv2e5.py         # prod
```
`ad_messaging.py` is a committed repo file (no patch). The apply only appends the
`ads.py` endpoints block when the marker is absent.

## Verify (in-process on prod DDB via SSM)
`python ops/prod-hotfixes/adv/adv2-e5/verify_adv2e5.py` — self-seeds funded
advertiser+campaign, creator, 3 following recipients, an opted-out follower, a
non-follower, a non-target. **OVERALL ALL_PASS 28/28** on prod:
delivered 3x2c debit + creator 3x1c credit(type:credit); open +5c/creator +3c;
click +10c/creator +7c; re-open/re-click 0 (idempotent); clicked funnel-stack
17c; creator total 13c; non-target approve 403; double-approve 409; opt-out +
non-relationship EXCLUDED; insufficient balance -> 0 delivered /
paused_insufficient_funds / balance never negative.

## Prod deploy record
- `.bak_adv2e5_1783567298` on `app/routers/ads.py` (ad_messaging.py net-new).
- Restart openapi 200; 9 routes live.

## ADV2-E5 ad-message HYDRATION follow-up (apply_adv2e5_hydrate.py)
The delivered sponsored DM row stores ad_message/ad_click_id/cta_url/sponsor_label/
content_owner_sub/ad_image_url, but the message READ-path serializer
(`_message_out_from_item` -> `MessageOut`, which also feeds the realtime event via
`_serialize_message_event_payload`) dropped them, so a real recipient device never
saw the sponsor footer and could not fire the open(+5c)/click(+10c) money beacons.
`apply_adv2e5_hydrate.py` (idempotent, marker `# ADV2-E5 ad-message hydration`) adds
the six fields to MessageOut + the serializer. Mirrors the TIP-B2 tip_reactions
hydration. LIVE prod hotfix (`.bak_adv2e5hydrate_*` on messaging.py), restart
openapi 200. The APP side needed the twin fix: the thread renders from Room (which
drops these fields), so ThreadViewModel now overlays the ad fields from loadHistory
(mirroring the tip_reactions overlay) — without it `isAdMessage` stayed false and
neither the footer nor the beacons fired. 2-device verified: open/click POST 200,
funnel-stack 17c, F5 creator 70% / F6 platform 100%.
