# ADS-020: Broadcast Ad Serving + Billing Integration (wire ADS-006 to the real ad platform)

**Ticket**: ADS-020
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: High
**Estimated effort**: 6-9 days
**Dependencies**: ADS-006 (broadcast ad breaks), ADS-004 (ad serving engine), ADS-007 (ad billing/financial engine), ADS-003 (subscriptions), ad fraud prevention, ad analytics

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The Broadcast Ad Breaks feature (ADS-006) delivers the full **viewer experience**
end to end — pre-roll on join, broadcaster-triggered mid-roll, SSE
`ad_break:start/end`, the `AdOverlay` (countdown/skip/CTA), and correct
subscriber/broadcaster ad-free handling. **But broadcast ads are completely
siloed from the real ad platform**, so they generate no revenue and have no real
ad selection:

1. **Stub ad serving** — `serve_broadcast_ad()`
   (`app/services/broadcast_ads.py:55-84`) returns a **hardcoded "house"
   creative** with a mock video URL. No campaign eligibility, targeting,
   frequency capping, or budget enforcement. (Comment at lines 5-6 notes this was
   intentional until ADS-004 landed; ADS-004 now exists.)
2. **No billing / revenue** — `record_ad_event()`
   (`app/services/broadcast_ads.py:185-217`) writes only to the separate
   `broadcast_ad_events` table. Impressions/clicks **never** flow to
   `ad_impressions` or `ad_billing`: advertisers are **not charged**, creators
   earn **zero revenue/rev-share**, and campaign spend counters are not updated.
3. **No fraud detection** — broadcast impressions bypass
   `ad_fraud_prevention` (used by `ad_serving.track_ad_event()`).
4. **No analytics** — nothing written to `ad_analytics_rollups`; broadcast ad
   performance is invisible in campaign analytics.
5. **2 failing E2E UI tests** — `frontend/e2e/ads-broadcast.spec.ts:500` (369.1
   pre-roll overlay appears) and `:509` (369.2 skip button appears). The backend
   returns correct data but the overlay doesn't render on the viewer page —
   likely an `adJoin()` timing / `pre_roll_enabled` persistence / state issue in
   `frontend/src/pages/broadcast/LivePlayer.tsx:115-142,232-253`.
6. **No unit tests** — there is no `tests/test_broadcast_ads.py` (the ADS-006
   spec planned 10+).

Net: broadcast ads "work" as a demo but are not monetized, not targeted, not
auditable, and not fully tested.

### 1.2 How It Works (proposed)

Wire the broadcast ad path into the existing ad engine instead of stubbing it:

1. **Real serving**: `serve_broadcast_ad()` delegates to the ADS-004 ad-serving
   engine (`ad_serving.serve_ad()`) with a broadcast slot context (slot_type
   pre/mid-roll, format=video, viewer + creator context, session id). Falls back
   to a house creative only when no eligible paid ad fills the slot.
2. **Billing + revenue**: `record_ad_event()` routes impressions/clicks through
   the same path as `ad_serving.track_ad_event()` → writes `ad_impressions`,
   calls `ad_billing` to charge the advertiser and credit the creator's
   revenue-split, and updates campaign `spent_today_cents`/`lifetime_spent_cents`.
   Keep the `broadcast_ad_events` table as the broadcast-specific event log, but
   make it a parallel write, not the only one.
3. **Fraud + frequency cap**: run broadcast impressions through
   `ad_fraud_prevention` and the frequency-cap increment, same as video ads.
4. **Analytics**: emit broadcast impressions into `ad_analytics_rollups` with a
   `surface=broadcast_preroll|broadcast_midroll` dimension.
5. **Fix the player overlay tests** (369.1/369.2) and add the missing pytest
   coverage.

### 1.3 Design Principles

- **Reuse the real engine**: no parallel billing/serving logic — broadcast becomes
  another *surface* of ADS-004/007/fraud/analytics, distinguished by a slot/surface
  tag.
- **Graceful fallback**: if no paid ad is eligible, serve the house creative (free,
  not billed) so the viewer flow never breaks.
- **Ad-free respected**: the existing subscriber/broadcaster ad-free check stays;
  ad-free viewers never trigger serving or billing.
- **Backwards-compatible events**: keep `broadcast_ad_events` for broadcast-specific
  reporting; add the canonical `ad_impressions`/billing writes alongside.

---

## 2. Implementation

### 2.1 Backend
- `app/services/broadcast_ads.py`:
  - `serve_broadcast_ad()` → call `ad_serving.serve_ad(slot_context)`; house-creative fallback when unfilled.
  - `record_ad_event()` → in addition to `broadcast_ad_events`, invoke the canonical impression/click path (`ad_impressions` write + `ad_billing` charge/rev-split + fraud check + frequency cap + analytics rollup), tagged `surface=broadcast_{slot}`.
- Reuse ADS-004/007 service functions; do not duplicate billing math.
- Ensure `paid` vs `house` (unfilled fallback) is recorded so house impressions are not billed.

### 2.2 Frontend
- `frontend/src/pages/broadcast/LivePlayer.tsx`: fix the pre-roll render path so the overlay reliably appears once `adJoin()` returns a `pre_roll` (resolve the `adJoin` timing/`preRollDone` race); confirm `pre_roll_enabled` persists create→fetch.

### 2.3 Settings / flags
- Reuse existing ad-platform flags; add `BROADCAST_ADS_BILLING_ENABLED` (default true once wired) so the integration can be toggled.

---

## 3. Testing

- **pytest** (`tests/test_broadcast_ads.py`, new): `is_ad_free()`; `serve_broadcast_ad()` real-fill vs house fallback; `record_ad_event()` writes `ad_impressions` + charges `ad_billing` + credits creator + increments campaign spend + fraud/freq-cap invoked; ad-free viewer is never billed; ad-break state transitions + idempotent end.
- **E2E** (`frontend/e2e/ads-broadcast.spec.ts`): fix 369.1/369.2 (overlay + skip render); add an assertion that a non-subscriber pre-roll impression produces an `ad_impressions`/billing record (seed a funded campaign), and that a subscriber sees no ad and no charge.

## 4. Out of Scope

- The viewer overlay UX itself (already built).
- New creative/targeting features beyond what ADS-002/003/004 already provide.

---

## 5. Current-State Summary

| Aspect | Status |
|--------|--------|
| Viewer flow (pre/mid-roll overlay, skip, SSE) | ✅ works (2 UI tests flaky/failing) |
| Subscriber/broadcaster ad-free | ✅ wired to real subscriptions |
| Real ad selection (targeting/budget/freq-cap) | ❌ hardcoded house creative |
| Advertiser billing / creator revenue | ❌ none — impressions never reach ad_billing |
| Fraud detection | ❌ bypassed |
| Analytics rollups | ❌ none |
| Unit tests | ❌ missing |
| E2E | ⚠️ 17/19 pass; 369.1/369.2 fail |
