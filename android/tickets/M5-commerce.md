# M5 — Commerce — Tickets

Decomposition of milestone **M5** (epics **E28–E33**). Format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**.

**Milestone exit criteria:** end-to-end purchase (incl. one payment provider) and subscription manage;
invoices/refunds/disputes/tax visible.

---

## Epic E28 — Catalog & product

### AND-204 — Catalog API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** Catalog/shop endpoints + DTOs (categories, items, search).
**Acceptance:** Catalog + item payloads map (tested).

### AND-205 — Catalog / category browse
**Type:** Feature · **Priority:** P0 · **Deps:** AND-204, AND-103
**Scope:** Category list, item grid, paging.
**Acceptance:** Browse renders + paginates.

### AND-206 — Product detail
**Type:** Feature · **Priority:** P0 · **Deps:** AND-205
**Scope:** `shop/:categoryId/:itemId` detail, media, price, add-to-cart.
**Acceptance:** Detail renders; add-to-cart works.

### AND-207 — Catalog search
**Type:** Feature · **Priority:** P1 · **Deps:** AND-204
**Scope:** Full-text catalog search (name/desc/SKU).
**Acceptance:** Search returns items.

### AND-208 — Catalog ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-204
**Scope:** Browse/detail/search state.
**Acceptance:** Unit-tested.

### AND-209 — Catalog tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-208
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E29 — Cart & checkout

### AND-210 — Cart API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `cart.ts` endpoints/DTOs.
**Acceptance:** Cart payload maps (tested).

### AND-211 — Cart screen
**Type:** Feature · **Priority:** P0 · **Deps:** AND-210
**Scope:** Add/update qty/remove, totals, empty state.
**Acceptance:** Cart edits persist + totals update.

### AND-212 — Cart search/items
**Type:** Feature · **Priority:** P2 · **Deps:** AND-210
**Scope:** Item/SKU search within cart.
**Acceptance:** Search filters cart.

### AND-213 — Checkout session
**Type:** Feature · **Priority:** P0 · **Deps:** AND-211, AND-227
**Scope:** `/ui/checkout/session` (+ file-bundle); order review.
**Acceptance:** Checkout creates a session and proceeds to payment.

### AND-214 — Address / shipping
**Type:** Feature · **Priority:** P1 · **Deps:** AND-213
**Scope:** Address entry/select, shipping options.
**Acceptance:** Address applies to order.

### AND-215 — Carrier tracking
**Type:** Feature · **Priority:** P2 · **Deps:** AND-218
**Scope:** `carrierTracking.ts`; tracking status display.
**Acceptance:** Tracking shows for an order.

### AND-216 — Cart abandonment hooks
**Type:** Feature · **Priority:** P2 · **Deps:** AND-210
**Scope:** `cartAbandonment.ts` events.
**Acceptance:** Abandonment event emitted.

### AND-217 — Cart/checkout tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-213
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E30 — Purchases & order history

### AND-218 — Purchases API
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `purchases.ts` list/detail/search.
**Acceptance:** Purchases map (tested).

### AND-219 — Purchase history + search
**Type:** Feature · **Priority:** P1 · **Deps:** AND-218
**Scope:** History list, full-text search.
**Acceptance:** History renders + searchable.

### AND-220 — Order detail + tracking
**Type:** Feature · **Priority:** P1 · **Deps:** AND-219, AND-215
**Scope:** Order detail, items, tracking link.
**Acceptance:** Detail renders with tracking.

### AND-221 — Purchases ViewModel
**Type:** Feature · **Priority:** P1 · **Deps:** AND-218
**Scope:** State + paging.
**Acceptance:** Unit-tested.

### AND-222 — Purchases tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-221
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E31 — Billing & payment methods

### AND-223 — Billing API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `billing.ts` + `/ui/billing/*`, `/api/billing/*` DTOs.
**Acceptance:** Billing payloads map (tested).

### AND-224 — Payment methods management
**Type:** Feature · **Priority:** P0 · **Deps:** AND-223
**Scope:** List/add/remove/default payment methods.
**Acceptance:** Methods render + manage.

### AND-225 — Stripe Android SDK integration
**Type:** Feature · **Priority:** P0 · **Deps:** AND-223
**Scope:** Add Stripe SDK; PaymentSheet/PaymentIntent wiring.
**Acceptance:** Stripe initialized; test PaymentIntent confirms in test mode.

### AND-226 — Add card (Stripe)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-225
**Scope:** Add/confirm card via Stripe; attach to account.
**Acceptance:** Card adds + appears in methods (test mode).

### AND-227 — Checkout session billing
**Type:** Feature · **Priority:** P0 · **Deps:** AND-225
**Scope:** `/ui/billing/checkout_session`; complete payment.
**Acceptance:** A purchase completes via Stripe (test).

### AND-228 — PayPal (Custom Tabs)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-231
**Scope:** PayPal redirect via Custom Tabs; `/mock/paypal` in dev.
**Acceptance:** PayPal flow returns to app authenticated/paid.

### AND-229 — CCBill flow
**Type:** Feature · **Priority:** P1 · **Deps:** AND-231
**Scope:** `/api/billing/ccbill/frontend-oauth` via Custom Tabs; dev mock.
**Acceptance:** CCBill flow completes + returns.

### AND-230 — US bank + microdeposits
**Type:** Feature · **Priority:** P2 · **Deps:** AND-223
**Scope:** `/ui/billing/us-bank/verify-microdeposits`.
**Acceptance:** Microdeposit verification works (test).

### AND-231 — Payment redirect/return handler
**Type:** Feature · **Priority:** P0 · **Deps:** AND-022
**Scope:** Deep-link return URLs for redirect providers; success/cancel/failure routing.
**Acceptance:** Returns route to correct state (tested).

### AND-232 — Billing ViewModels + error mapping
**Type:** Feature · **Priority:** P0 · **Deps:** AND-223, AND-015
**Scope:** Payment state machine, provider error mapping.
**Acceptance:** Unit-tested.

### AND-233 — Billing tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-227, AND-231
**Scope:** Repo + redirect-return tests.
**Acceptance:** Pass.

---

## Epic E32 — Subscriptions & fan-club

### AND-234 — Subscriptions API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `subscriptions.ts` endpoints/DTOs.
**Acceptance:** Tiers/subs map (tested).

### AND-235 — Subscription tiers browse
**Type:** Feature · **Priority:** P0 · **Deps:** AND-234
**Scope:** Creator subscription tiers display.
**Acceptance:** Tiers render with pricing.

### AND-236 — Subscribe flow
**Type:** Feature · **Priority:** P0 · **Deps:** AND-235, AND-227
**Scope:** Subscribe + payment + entitlement.
**Acceptance:** Subscription activates (test).

### AND-237 — Manage / cancel subscription
**Type:** Feature · **Priority:** P1 · **Deps:** AND-236
**Scope:** View/manage/cancel/renew.
**Acceptance:** Cancel/renew reflected.

### AND-238 — Fan-club channels list
**Type:** Feature · **Priority:** P1 · **Deps:** AND-234
**Scope:** Fan-club channels overview.
**Acceptance:** Channels render by tier.

### AND-239 — Fan-club channel messages
**Type:** Feature · **Priority:** P1 · **Deps:** AND-238, AND-126
**Scope:** `/ui/fan-club/channels/{id}/messages` (+ react/delete); reuse message UI.
**Acceptance:** Messages render/post/react.

### AND-240 — Fan-club tiers / members
**Type:** Feature · **Priority:** P2 · **Deps:** AND-238
**Scope:** `/ui/fan-club/tiers/{id}/members`.
**Acceptance:** Members list renders.

### AND-241 — Subscriptions/fan-club ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-234
**Scope:** State + entitlement.
**Acceptance:** Unit-tested.

### AND-242 — Subscriptions/fan-club tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-241
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E33 — Invoices, refunds, disputes, tax

### AND-243 — Invoices
**Type:** Feature · **Priority:** P1 · **Deps:** AND-223
**Scope:** `invoices.ts` list/detail; `/ui/invoices/{n}/email`.
**Acceptance:** Invoices render; email works.

### AND-244 — Refund requests
**Type:** Feature · **Priority:** P1 · **Deps:** AND-223
**Scope:** `refundRequests.ts` submit/list/status.
**Acceptance:** Refund request submits + tracks.

### AND-245 — Disputes
**Type:** Feature · **Priority:** P2 · **Deps:** AND-223
**Scope:** `billingDisputes.ts` list/detail.
**Acceptance:** Disputes render.

### AND-246 — Tax documents
**Type:** Feature · **Priority:** P2 · **Deps:** AND-223
**Scope:** `taxDocuments.ts` list/download.
**Acceptance:** Tax docs list + download.

### AND-247 — 1099 tax forms
**Type:** Feature · **Priority:** P2 · **Deps:** AND-246
**Scope:** `taxForm1099.ts`.
**Acceptance:** 1099 renders/downloads.

### AND-248 — Billing config (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-223
**Scope:** `billingConfig.ts` display.
**Acceptance:** Config renders read-only.

### AND-249 — Invoices/tax ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-243
**Scope:** State + paging.
**Acceptance:** Unit-tested.

### AND-250 — Invoices/tax tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-249
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

### M5 ticket count: 47 (E28:6, E29:8, E30:5, E31:11, E32:9, E33:8)
**Running total through M5:** 250 tickets (AND-001…AND-250).
