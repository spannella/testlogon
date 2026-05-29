# Feature Improvements Backlog

Living document of identified gaps and improvement opportunities.
Last updated: 2026-05-29 (153 tickets across 13 feature areas)

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

## KYC / Compliance (Deep Dive — 2026-05-29)

24 detailed ticket specs generated in `docs/tickets/KYC-*.md`. ~422 planned E2E tests total.

### Existing KYC Infrastructure (Reference)

**Already implemented:**
- Full case lifecycle (draft→submitted→under_review→needs_more_info→approved/rejected/expired)
- Document uploads (selfie, id_front, id_back, proof_of_address) with verification_state tracking
- Questionnaire integration with PDF generation
- Signature packet integration (multi-signer, legal notice, audit trail)
- Admin queue with metrics, assignment, and ticket-based communication
- Optimistic locking, idempotency hashing, evidence snapshots
- Retention purge automation (30/90 day windows)
- Comprehensive audit logging (15+ KYC-specific event types)

### Core KYC Infrastructure Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 33 | KYC-001 | Admin KYC Review Dashboard | P0 | 25 | 150-155 |
| 34 | KYC-002 | Identity Document Verification / OCR | P0 | 20 | 156-159 |
| 35 | KYC-003 | Liveness Video Verification Call | P0 | 18 | 160-163 |
| 36 | KYC-004 | Proof of Residency Verification | P0 | 15 | 164-166 |
| 37 | KYC-005 | Proof of Funds / Source of Funds | P0 | 15 | 167-169 |
| 38 | KYC-006 | Sanctions & PEP Screening | P0 | 20 | 170-173 |
| 39 | KYC-007 | Enhanced Document Signing for KYC | P1 | 18 | 174-177 |
| 40 | KYC-008 | KYC Risk Scoring Engine | P0 | 18 | 178-181 |

### Tiering, Scanning & Monitoring Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 41 | KYC-009 | Tiered Verification Levels | P0 | 22 | 182-186 |
| 42 | KYC-010 | Passport & National ID Scanner (MRZ) | P0 | 20 | 187-190 |
| 43 | KYC-011 | KYC Webhooks & Notifications | P1 | 15 | 191-193 |
| 44 | KYC-012 | Compliance Reporting & Export | P1 | 15 | 194-196 |
| 45 | KYC-013 | User Self-Service Portal (Wizard) | P0 | 25 | 197-202 |
| 46 | KYC-014 | Facial Comparison (Selfie vs ID) | P1 | 15 | 203-205 |
| 47 | KYC-015 | Business / Corporate KYC (KYB) | P1 | 20 | 206-209 |
| 48 | KYC-016 | Ongoing Monitoring & Periodic Review | P1 | 18 | 210-213 |

### Templates, Privacy & Analytics Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 49 | KYC-017 | Document Signing Template Library | P1 | 18 | 214-217 |
| 50 | KYC-018 | Address Verification Service | P1 | 15 | 218-220 |
| 51 | KYC-019 | Case Assignment & Workload Management | P1 | 18 | 221-224 |
| 52 | KYC-020 | Multi-Language KYC Support | P2 | 12 | 225-227 |
| 53 | KYC-021 | KYC API for Third-Party Integration | P2 | 15 | 228-230 |
| 54 | KYC-022 | Electronic Identity Verification (eID) | P2 | 15 | 231-233 |
| 55 | KYC-023 | KYC Data Encryption & Privacy | P1 | 15 | 234-236 |
| 56 | KYC-024 | KYC Analytics & Funnel Dashboard | P2 | 15 | 237-239 |

---

## Cloud Infrastructure & Remote Compute (Deep Dive — 2026-05-29)

12 detailed ticket specs generated in `docs/tickets/INFRA-*.md`. ~206 planned E2E tests total.

### Existing Remote Access Infrastructure (Reference)

**Already implemented:**
- VNC remote desktop (noVNC, JWT sessions, capability negotiation, timeout policies, audit)
- SSH terminal (Paramiko WebSocket bridge, destination policy, rate limiting, role-based access)
- Targets hardcoded in env vars (no DDB table, no dynamic host inventory)
- Credentials supplied per-session (not stored server-side)
- Prometheus metrics for session lifecycle, duration, errors

### Foundation Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 57 | INFRA-001 | Host Inventory Management | P0 | 20 | 240-243 |
| 58 | INFRA-002 | SSH Key Manager | P0 | 18 | 244-247 |
| 59 | INFRA-006 | Connection Profiles & Quick Connect | P1 | 15 | 261-263 |

### Cloud Compute Provisioning Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 60 | INFRA-003 | EC2 Instance Launcher | P0 | 22 | 248-252 |
| 61 | INFRA-004 | Kubernetes Container Launcher | P0 | 20 | 253-256 |
| 62 | INFRA-005 | Compute Cost Tracking | P0 | 18 | 257-260 |
| 63 | INFRA-007 | Instance Templates & Presets | P1 | 15 | 264-266 |

### Monitoring, Security & Admin Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 64 | INFRA-008 | Instance Monitoring & Health | P1 | 15 | 267-269 |
| 65 | INFRA-009 | Security Groups & Network Rules | P1 | 15 | 270-272 |
| 66 | INFRA-010 | SSH Session Recording & Playback | P1 | 18 | 273-276 |
| 67 | INFRA-011 | Multi-Hop SSH (Bastion/Jump Host) | P2 | 12 | 277-279 |
| 68 | INFRA-012 | Admin Compute Dashboard | P1 | 18 | 280-283 |

### Dependency Chain

```
INFRA-001 (hosts) + INFRA-002 (keys) ← foundation
    ↓
INFRA-003 (EC2) + INFRA-004 (K8s) ← launchers auto-register hosts + inject keys
    ↓
INFRA-005 (billing) ← tracks launcher costs via per-minute metering
    ↓
INFRA-006-012 ← advanced features on top
```

---

## Messaging & Social Features (Deep Dive — 2026-05-29)

16 detailed ticket specs generated in `docs/tickets/MSG-*.md`, `FEED-0*.md`, `FILES-*.md`, `SOCIAL-007*.md`. ~196 planned E2E tests total.

### Messaging Enhancements

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 69 | MSG-006 | Emoji Messages | P1 | 15 | 284-286 |
| 70 | MSG-007 | Custom Emojis | P1 | 18 | 287-290 |
| 71 | MSG-008 | GIF & Sticker Messages | P1 | 22 | 291-295 |
| 72 | MSG-009 | Find-a-DateTime Message | P1 | 20 | 296-299 |
| 73 | MSG-010 | Countdown Messages | P2 | 12 | 306-308 |
| 74 | MSG-011 | Emoji Reactions Enhancement | P1 | 10 | 326-328 |
| 75 | MSG-012 | Message Formatting & Rich Text | P1 | 15 | 329-332 |

### Newsfeed Enhancements

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 76 | FEED-003 | Find-a-DateTime Newsfeed Post | P1 | 12 | 300-302 |
| 77 | FEED-004 | Emoji/GIF/Sticker Comments | P1 | 12 | 303-305 |
| 78 | FEED-005 | Countdown Newsfeed Posts | P2 | 10 | 309-311 |
| 79 | FEED-006 | Hide Post | P1 | 10 | 317-319 |
| 80 | FEED-007 | Mark Post Interesting / Not Interesting | P1 | 10 | 320-322 |
| 81 | FEED-008 | Enhanced Post Composer | P1 | 12 | 333-335 |
| 82 | FEED-009 | Post Bookmarks / Save Collections | P0 | 18 | 336-339 |

### File Sharing & Social

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 83 | FILES-001 | Encrypted One-Time Share Links | P1 | 20 | 312-316 |
| 84 | SOCIAL-007 | Snooze Following | P1 | 12 | 323-325 |

---

## Advertising Platform (Deep Dive — 2026-05-29)

19 detailed ticket specs generated in `docs/tickets/ADS-*.md`. ~325 planned E2E tests total.

### Core Ad Infrastructure

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 85 | ADS-001 | Advertiser Accounts & Campaign Manager | P0 | 22 | 340-344 |
| 86 | ADS-002 | Ad Creative Management | P0 | 20 | 345-349 |
| 87 | ADS-003 | Ad Targeting Engine | P0 | 18 | 350-353 |
| 88 | ADS-004 | Ad Serving Engine | P0 | 20 | 354-358 |
| 89 | ADS-007 | Ad Billing & Financial Engine | P0 | 20 | 369-373 |

### Ad Placements & Formats

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 90 | ADS-005 | Newsfeed Sponsored Posts | P0 | 18 | 359-363 |
| 91 | ADS-006 | Broadcast Ad Breaks | P1 | 18 | 364-368 |

### User & Provider Controls

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 92 | ADS-009 | User Ad Preferences & Ad-Free Tiers | P1 | 15 | 379-382 |
| 93 | ADS-010 | Content Provider Ad Controls | P1 | 18 | 383-387 |
| 94 | ADS-019 | Content Provider Self-Placed Ads | P1 | 18 | 419-422 |

### Analytics, API & Optimization

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 95 | ADS-008 | Ad Analytics Dashboard | P1 | 18 | 374-378 |
| 96 | ADS-011 | Advertiser API | P1 | 18 | 388-391 |
| 97 | ADS-017 | Ad Performance Optimization | P2 | 12 | 411-413 |
| 98 | ADS-016 | Ad Scheduling & Dayparting | P1 | 12 | 408-410 |

### Partnerships, Promotions & Fraud

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 99 | ADS-012 | Self-Promotion & Content Boosting | P1 | 15 | 392-395 |
| 100 | ADS-013 | Sponsored Content & Creator Partnerships | P1 | 18 | 396-400 |
| 101 | ADS-014 | Ad Fraud Prevention | P1 | 15 | 401-404 |
| 102 | ADS-015 | Ad Creative with Affiliate Links & Discounts | P2 | 12 | 405-407 |
| 103 | ADS-018 | Admin Ad Platform Management | P1 | 18 | 414-418 |

### Dependency Chain

```
ADS-001 (accounts) + ADS-002 (creatives) + ADS-003 (targeting) ← foundation
    ↓
ADS-004 (serving) ← resolves ads from campaigns
    ↓
ADS-005 (newsfeed) + ADS-006 (broadcast) ← placement surfaces
    ↓
ADS-007 (billing) ← charges advertisers per impression/click
    ↓
ADS-008-019 ← analytics, API, controls, optimization, fraud, self-promo
```

---

## Content Provider Syndicates (Deep Dive — 2026-05-29)

6 detailed ticket specs generated in `docs/tickets/SYND-*.md`. ~101 planned E2E tests total.

### Syndicate Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 104 | SYND-001 | Syndicate Creation & Membership Management | P0 | 18 | 423-426 |
| 105 | SYND-002 | Bundled Subscription Plans | P0 | 17 | 427-430 |
| 106 | SYND-003 | Revenue Splitting Engine | P0 | 16 | 431-434 |
| 107 | SYND-004 | Treasury & Fund Management | P0 | 16 | 435-438 |
| 108 | SYND-005 | Syndicate Page & Newsfeed | P1 | 18 | 439-442 |
| 109 | SYND-006 | Syndicate Advertising | P1 | 16 | 443-446 |

### Dependency Chain

```
SYND-001 (membership) ← foundation
    ↓
SYND-002 (bundled subs) + SYND-004 (treasury) ← financial primitives
    ↓
SYND-003 (revenue splitting) ← depends on subs + treasury
    ↓
SYND-005 (page/feed) + SYND-006 (advertising) ← consumer-facing features
```

---

## User Groups (Deep Dive — 2026-05-29)

4 detailed ticket specs generated in `docs/tickets/GROUP-*.md`. ~64 planned E2E tests total.

### Group Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 110 | GROUP-001 | User Group Creation & Membership | P1 | 16 | 447-450 |
| 111 | GROUP-002 | Group Page & Newsfeed | P1 | 16 | 451-454 |
| 112 | GROUP-003 | Group Advertising & External Fundraising | P2 | 16 | 455-458 |
| 113 | GROUP-004 | Group Treasury Management | P2 | 16 | 459-462 |

---

## Content Licensing (Deep Dive — 2026-05-29)

6 detailed ticket specs generated in `docs/tickets/LICENSE-*.md`. ~95 planned E2E tests total.

### Licensing Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 114 | LICENSE-001 | License Agreement Upload & Management | P1 | 16 | 463-466 |
| 115 | LICENSE-002 | Content License Issuance | P0 | 16 | 467-470 |
| 116 | LICENSE-003 | License Terms & Revenue Sharing | P0 | 15 | 471-474 |
| 117 | LICENSE-004 | License Request & Approval Workflow | P1 | 16 | 475-478 |
| 118 | LICENSE-005 | Syndicate Open Licensing | P1 | 16 | 479-482 |
| 119 | LICENSE-006 | License Compliance & Verification | P1 | 16 | 483-486 |

### Dependency Chain

```
LICENSE-001 (upload agreements) ← standalone
LICENSE-002 (issue licenses) ← standalone
    ↓
LICENSE-003 (revenue sharing) ← depends on LICENSE-002 terms
LICENSE-004 (request workflow) ← depends on LICENSE-002 issuance
    ↓
LICENSE-005 (syndicate licensing) ← depends on LICENSE-002 + SYND-001
LICENSE-006 (compliance) ← depends on LICENSE-001 + LICENSE-002
```

---

## Provider Delegation & External Control (Deep Dive — 2026-05-29)

5 detailed ticket specs generated in `docs/tickets/DELEGATE-*.md`. ~79 planned E2E tests total.

### Delegation Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 120 | DELEGATE-001 | Delegate Management & Permissions | P0 | 16 | 487-490 |
| 121 | DELEGATE-002 | Chat Delegation | P0 | 15 | 491-494 |
| 122 | DELEGATE-003 | Newsfeed Delegation | P1 | 16 | 495-498 |
| 123 | DELEGATE-004 | Broadcast Chat Delegation | P1 | 16 | 499-502 |
| 124 | DELEGATE-005 | Delegation API | P1 | 16 | 503-506 |

### Dependency Chain

```
DELEGATE-001 (permissions) ← foundation for all delegation
    ↓
DELEGATE-002 (chat) + DELEGATE-003 (feed) + DELEGATE-004 (broadcast) ← domain surfaces
    ↓
DELEGATE-005 (API) ← wraps all delegation services for external tools
```

---

## Chat Bots (Deep Dive — 2026-05-29)

4 detailed ticket specs generated in `docs/tickets/BOT-*.md`. ~64 planned E2E tests total.

### Bot Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 125 | BOT-001 | Bot Framework & Lifecycle | P0 | 16 | 507-510 |
| 126 | BOT-002 | Template & Scheduled Messages | P1 | 16 | 511-514 |
| 127 | BOT-003 | Content & Event Promotion Bot | P1 | 16 | 515-518 |
| 128 | BOT-004 | AI Chat Bot (LLM Integration) | P1 | 16 | 519-522 |

### Dependency Chain

```
BOT-001 (framework) ← foundation
    ↓
BOT-002 (templates) + BOT-003 (promotion) ← rule-based bots
    ↓
BOT-004 (AI/LLM) ← most advanced, depends on framework
```

---

## Core Platform Gaps (Deep Dive — 2026-05-29)

4 detailed ticket specs generated in `docs/tickets/PLATFORM-01{6-9}*.md`. ~63 planned E2E tests total.

### Platform Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 129 | PLATFORM-016 | Web Push Delivery | P0 | 15 | 523-526 |
| 130 | PLATFORM-017 | Creator Storefront | P1 | 16 | 527-530 |
| 131 | PLATFORM-018 | Privacy Account Deletion | P0 | 16 | 531-534 |
| 132 | PLATFORM-019 | Analytics Engine | P0 | 16 | 535-538 |

---

## Financial Features (Deep Dive — 2026-05-29)

18 detailed ticket specs generated in `docs/tickets/FIN-*.md`. ~278 planned E2E tests total.

### Consumer Financial

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 133 | FIN-001 | Invoice / Receipt PDF Download | P0 | 16 | 539-542 |
| 134 | FIN-002 | Promo Codes in Checkout UI | P1 | 18 | 543-546 |
| 135 | FIN-003 | Cart Abandonment Reminders | P1 | 15 | 547-550 |
| 136 | FIN-004 | Consumer Tax Documents | P2 | 16 | 551-554 |
| 137 | FIN-005 | Multi-Currency Display | P2 | 15 | 555-558 |

### Creator Financial

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 138 | FIN-006 | Per-Content Revenue Breakdown | P0 | 16 | 559-562 |
| 139 | FIN-007 | Platform Commission Visibility | P0 | 16 | 563-566 |
| 140 | FIN-008 | Tax Form Generation (1099/W-9) | P0 | 18 | 567-570 |
| 141 | FIN-009 | Payout Dashboard Frontend | P1 | 18 | 571-574 |
| 142 | FIN-010 | Affiliate Earnings Dashboard | P1 | 16 | 575-578 |
| 143 | FIN-011 | Collaboration Revenue Splitting | P1 | 16 | 579-582 |
| 144 | FIN-012 | Engagement Rate Calculation | P2 | 16 | 583-586 |

### Admin Financial

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 145 | FIN-013 | Platform Financial Dashboard | P0 | 15 | 587-590 |
| 146 | FIN-014 | Payment Provider Health Monitoring | P1 | 14 | 591-594 |
| 147 | FIN-015 | Fraud Detection Dashboard | P1 | 16 | 595-598 |
| 148 | FIN-016 | Financial Audit Log Export | P1 | 14 | 599-602 |
| 149 | FIN-017 | Bulk Payout/Refund Tools | P2 | 15 | 603-606 |
| 150 | FIN-018 | Billing Configuration UI | P2 | 13 | 607-610 |

---

## Admin Tools (Deep Dive — 2026-05-29)

3 detailed ticket specs generated in `docs/tickets/ADMIN-*.md`. ~47 planned E2E tests total.

### Admin Tickets

| # | Ticket | Feature | Priority | Tests | Sections |
|---|--------|---------|----------|-------|----------|
| 151 | ADMIN-001 | Subscription Tier Manager UI | P1 | 16 | 611-614 |
| 152 | ADMIN-002 | Admin Email/SMS Dashboards | P1 | 16 | 615-618 |
| 153 | ADMIN-003 | Rate Limit Admin UI | P2 | 15 | 619-622 |

---

## Investigation Queue

- [x] Accounting deep dive: basic user, content provider, admin perspectives
- [x] KYC deep dive: existing infrastructure, verification, compliance, signing, video calls
- [x] Cloud infrastructure deep dive: SSH/VNC, host management, compute provisioning, billing
- [x] Messaging/social feature gaps: emoji, GIF/stickers, find-a-datetime, countdown, bookmarks, etc.
- [x] Advertising platform: full ad system from accounts to fraud prevention
- [x] Content provider syndicates: bundled subs, revenue splitting, treasury
- [x] User groups: membership, newsfeeds, fundraising, treasury
- [x] Content licensing: agreements, issuance, revenue sharing, syndicate licensing, compliance
- [x] Provider delegation & external control: chat, feed, broadcast delegation + API
- [x] Chat bots: framework, templates, content promotion, AI/LLM integration
- [x] Core platform gaps: web push, creator storefront, privacy deletion, analytics engine
- [x] Financial gaps: consumer (invoices, promo, cart, tax, currency), creator (revenue, commission, tax, payouts, affiliate, collab, engagement), admin (dashboard, health, fraud, audit, bulk ops, config)
- [x] Admin tooling: subscription tier UI, email/SMS dashboards, rate limit admin UI
- [ ] Additional gaps from `docs/gap-analysis.md` (30 verified gaps)
- [ ] Media/streaming feature gaps
