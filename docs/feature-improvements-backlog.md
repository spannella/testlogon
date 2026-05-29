# Feature Improvements Backlog

Living document of identified gaps and improvement opportunities.
Last updated: 2026-05-29

---

## P0 — Core Experience Gaps

| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 1 | Post Bookmarks/Save Collections | MISSING | No DDB entity, API, or UI. High-frequency user feature. |
| 2 | Global Search (unified) | MISSING | Only per-module searches; no unified endpoint or Ctrl+K UI. |
| 3 | Web Push Delivery | MISSING | Service worker + VAPID infrastructure absent; placeholder token gen only. |
| 4 | User Blocking UI | PARTIAL | Backend `_is_blocked` exists; no block/unblock endpoints or UI buttons. |
| 5 | Public Reposting | PARTIAL | Share-to-DM exists; public repost/reblog missing. |

## P1 — Creator & Admin Features

| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 6 | Payout Dashboard UI | MISSING UI | Full backend in `creator_payouts.py`; no route/page/nav link. |
| 7 | Subscription Tier Manager UI | MISSING UI | Backend CRUD exists; no creation/edit UI for creators. |
| 8 | Tip Leaderboards | MISSING | Ledger writes exist; no aggregation query or visualization. |
| 9 | Creator Storefront | PARTIAL | Profile page exists; no tabbed content/subscription view. |
| 10 | Admin Email/SMS Dashboards | MISSING UI | Stats/delivery/bounce endpoints exist; no admin dashboard UI. |

## P2 — Polish & Stubs

| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 11 | Privacy account deletion | STUB | Password verification is a placeholder in prod code. |
| 12 | Analytics refresh | STUB | Returns success immediately without processing. |
| 13 | Affiliate link tracking UI | PARTIAL | UI exists but tracking stats incomplete. |
| 14 | Rate limit admin UI | PARTIAL | Dynamic blocklist/allowlist management panel minimal. |

## Accounting & Financial Gaps (Deep Dive — 2026-05-29)

### Consumer (Basic User)

| # | Feature | Severity | Status | Notes |
|---|---------|----------|--------|-------|
| 15 | Invoice/receipt PDF download | P0 | MISSING | No generation endpoint, no historical invoice list |
| 16 | Promo codes in checkout UI | P1 | MISSING WIRING | Promo system exists but not integrated into Checkout.tsx |
| 17 | Cart abandonment reminders | P1 | MISSING | No TTL/expiration on carts, no scheduled reminders |
| 18 | Consumer tax documents | P2 | MISSING | No tax form viewing for consumers |
| 19 | Multi-currency display | P2 | MISSING | All prices USD; no user currency preference or conversion |

### Content Provider (Creator)

| # | Feature | Severity | Status | Notes |
|---|---------|----------|--------|-------|
| 20 | Per-content revenue breakdown | P0 | MISSING | Can't see earnings per video/post/broadcast |
| 21 | Platform commission visibility | P0 | MISSING | No "your cut vs platform fee" display anywhere |
| 22 | Tax form generation (1099/W-9) | P0 | MISSING | No TIN collection, no 1099-NEC generation or distribution |
| 23 | Payout Dashboard frontend | P1 | STUB | Full backend in `creator_payouts.py`; frontend is minimal stub |
| 24 | Affiliate earnings dashboard | P1 | MISSING UI | DDB tables exist (`AffiliateLinks`, `AffiliateClicks`); no tracking UI |
| 25 | Collaboration revenue splitting | P1 | MISSING | Collab agreements table exists; no revenue split calculation |
| 26 | Engagement rate calculation | P2 | STUB | Hardcoded to 0.0 in `creator_analytics.py:391` |

### Admin (Platform Operator)

| # | Feature | Severity | Status | Notes |
|---|---------|----------|--------|-------|
| 27 | Platform financial dashboard | P0 | MISSING | No GMV, net revenue, take rate, or payment provider breakdown |
| 28 | Payment provider health monitoring | P1 | MISSING UI | Webhooks handled but no status/health dashboard |
| 29 | Fraud detection dashboard | P1 | MISSING | No velocity checks, risk scoring, or anomaly detection |
| 30 | Financial audit log export | P1 | MISSING | Ledger exists but no CSV/PDF export endpoint |
| 31 | Bulk payout/refund tools | P2 | MISSING | One-at-a-time processing only |
| 32 | Billing configuration UI | P2 | MISSING | Fees/minimums/pricing only configurable via env vars |

### Existing Financial Infrastructure (Reference)

**Strong areas (already implemented):**
- Wallet balance viewing + deposits (Stripe, CCBill)
- Payment method CRUD (cards, ACH, CCBill tokens)
- Purchase/transaction history with search
- Tip sending (messages, posts, broadcasts)
- Content unlock (locked messages + posts)
- Subscription management (subscribe, cancel, upgrade)
- Shopping cart + checkout + order history
- Refund request workflow (submit → admin review → approve/reject)
- Creator payout workflow (request → admin approve → complete)
- Dispute/chargeback management (multi-provider, evidence upload, state machine)
- Call billing ledger
- 12 dedicated DDB tables, 25+ financial services, 3 payment providers

---

## Investigation Queue

- [x] Accounting deep dive: basic user, content provider, admin perspectives
- [ ] Additional gaps from `docs/gap-analysis.md` (30 verified gaps)
- [ ] Messaging/social feature gaps
- [ ] Media/streaming feature gaps
- [ ] Admin tooling gaps
