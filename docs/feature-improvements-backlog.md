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

## Investigation Queue

- [x] Accounting deep dive: basic user, content provider, admin perspectives
- [x] KYC deep dive: existing infrastructure, verification, compliance, signing, video calls
- [x] Cloud infrastructure deep dive: SSH/VNC, host management, compute provisioning, billing
- [ ] Additional gaps from `docs/gap-analysis.md` (30 verified gaps)
- [ ] Messaging/social feature gaps
- [ ] Media/streaming feature gaps
- [ ] Admin tooling gaps
