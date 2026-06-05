# M6 — Creator Tools — Tickets

Decomposition of milestone **M6** (epics **E34–E38**). Format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**.

**Milestone exit criteria:** earnings/payout views; calendar/scheduler; watch a live broadcast with chat.

---

## Epic E34 — Earnings dashboard

### AND-251 — Earnings API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `earnings.ts` endpoints/DTOs (summary, series).
**Acceptance:** Earnings payloads map (tested).

### AND-252 — Earnings dashboard + charts
**Type:** Feature · **Priority:** P0 · **Deps:** AND-251, AND-255
**Scope:** Totals, time-series charts, breakdowns.
**Acceptance:** Dashboard renders real earnings.

### AND-253 — Per-content revenue
**Type:** Feature · **Priority:** P1 · **Deps:** AND-251
**Scope:** `perContentRevenue.ts` table/sort.
**Acceptance:** Per-content revenue renders.

### AND-254 — Engagement rate
**Type:** Feature · **Priority:** P2 · **Deps:** AND-251
**Scope:** `engagementRate.ts` metrics.
**Acceptance:** Engagement metrics render.

### AND-255 — Reusable charts component
**Type:** Feature · **Priority:** P0 · **Deps:** AND-019
**Scope:** Line/bar charts composable (Vico or custom) for finance screens.
**Acceptance:** Chart renders sample series; reused by payouts/ads.

### AND-256 — Earnings ViewModel
**Type:** Feature · **Priority:** P1 · **Deps:** AND-251
**Scope:** Range selection, state.
**Acceptance:** Unit-tested.

### AND-257 — Earnings tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-256
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E35 — Payouts

### AND-258 — Payouts API
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `payouts.ts` endpoints/DTOs.
**Acceptance:** Payout data maps (tested).

### AND-259 — Payout setup (+ KYC gate)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-258, AND-320
**Scope:** Configure payout method; block/guide if KYC tier insufficient.
**Acceptance:** Setup works; KYC gate routes to verification when required.

### AND-260 — Payout history + status
**Type:** Feature · **Priority:** P1 · **Deps:** AND-258
**Scope:** History list, statuses, detail.
**Acceptance:** History renders with statuses.

### AND-261 — Bulk payout tools (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-258
**Scope:** `bulkPayoutTools.ts` read-only views.
**Acceptance:** Bulk views render.

### AND-262 — Payouts ViewModel
**Type:** Feature · **Priority:** P1 · **Deps:** AND-258
**Scope:** State + gating logic.
**Acceptance:** Unit-tested.

### AND-263 — Payouts tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-262
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E36 — Referrals, affiliates, promo

### AND-264 — Referrals
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `referrals.ts`; referral link/stats, share.
**Acceptance:** Referral link + stats render.

### AND-265 — Affiliates dashboard
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `affiliates.ts`; links + earnings.
**Acceptance:** Affiliate dashboard renders.

### AND-266 — Promo codes
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `promoCodes.ts`; create/list/redeem.
**Acceptance:** Promo create/list works.

### AND-267 — Affiliate discounts
**Type:** Feature · **Priority:** P2 · **Deps:** AND-265
**Scope:** `adCreativeAffiliate`/ad-affiliate discounts surface.
**Acceptance:** Discounts render.

### AND-268 — Referrals/affiliates ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-264
**Scope:** State.
**Acceptance:** Unit-tested.

### AND-269 — Referrals/affiliates tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-268
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E37 — Calendar & scheduling

### AND-270 — Calendar API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `calendar.ts` endpoints/DTOs (events, recurrence).
**Acceptance:** Calendar payloads map (tested).

### AND-271 — Calendar views
**Type:** Feature · **Priority:** P1 · **Deps:** AND-270
**Scope:** Month/week/agenda views, timezone handling.
**Acceptance:** Events render in correct slots/timezones.

### AND-272 — Event detail (+ public event)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-271, AND-022
**Scope:** Event detail; public `/event/:calendarId/:eventId` App Link.
**Acceptance:** Event detail + public link work.

### AND-273 — Google Calendar integration
**Type:** Feature · **Priority:** P2 · **Deps:** AND-270
**Scope:** OAuth (dev `/mock/google-calendar`), sync calendars.
**Acceptance:** Connect + list external calendars.

### AND-274 — Content calendar
**Type:** Feature · **Priority:** P1 · **Deps:** AND-270
**Scope:** `content-calendar.ts`; scheduled content view.
**Acceptance:** Content calendar renders.

### AND-275 — Scheduler
**Type:** Feature · **Priority:** P1 · **Deps:** AND-270
**Scope:** `scheduler.ts`; schedule/reschedule items.
**Acceptance:** Schedule create/edit works.

### AND-276 — ICS export / reminders
**Type:** Feature · **Priority:** P2 · **Deps:** AND-272
**Scope:** ICS export, local reminders/notifications.
**Acceptance:** Reminder fires; ICS exports.

### AND-277 — Calendar tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-271
**Scope:** Repo + UI tests (timezone/recurrence).
**Acceptance:** Pass.

---

## Epic E38 — Broadcast viewer

### AND-278 — Broadcast API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `/broadcast/sessions`, scheduled/upcoming, session detail DTOs.
**Acceptance:** Broadcast payloads map (tested).

### AND-279 — Browse / scheduled broadcasts
**Type:** Feature · **Priority:** P0 · **Deps:** AND-278
**Scope:** Live/scheduled/upcoming lists; remind-me.
**Acceptance:** Lists render; remind-me toggles.

### AND-280 — Viewer playback (HLS)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-278, AND-167
**Scope:** `playback-url` + `playback/verify`; HLS viewer.
**Acceptance:** Live stream plays for an authorized viewer.

### AND-281 — Live chat
**Type:** Feature · **Priority:** P0 · **Deps:** AND-280, AND-143
**Scope:** `chat/stream` (SSE) + send; reactions.
**Acceptance:** Chat updates live; send works.

### AND-282 — Tips & goals
**Type:** Feature · **Priority:** P1 · **Deps:** AND-281, AND-031
**Scope:** `chat/tip`, tips summary, goals display.
**Acceptance:** Tip submits; goal progress shows.

### AND-283 — Products shelf
**Type:** Feature · **Priority:** P2 · **Deps:** AND-280, AND-206
**Scope:** `chat/product`, products list; buy from stream.
**Acceptance:** Shelf renders; buy routes to checkout.

### AND-284 — Q&A
**Type:** Feature · **Priority:** P2 · **Deps:** AND-280
**Scope:** `qa/questions` (+ upvote) and `/ui/live-qa/*`.
**Acceptance:** Ask/upvote questions; featured render.

### AND-285 — Viewer join/leave/heartbeat
**Type:** Feature · **Priority:** P1 · **Deps:** AND-280
**Scope:** viewers join/leave/heartbeat + count.
**Acceptance:** Presence/count update; heartbeat runs.

### AND-286 — Broadcast viewer ViewModel
**Type:** Feature · **Priority:** P0 · **Deps:** AND-278
**Scope:** Session state machine, chat merge.
**Acceptance:** Unit-tested.

### AND-287 — Broadcast viewer tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-286
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

### M6 ticket count: 37 (E34:7, E35:6, E36:6, E37:8, E38:10)
**Running total through M6:** 287 tickets (AND-001…AND-287).
