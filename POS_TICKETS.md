# POS — Point of Sale — Implementation Tickets

This backlog adds an in-person **Point of Sale** channel — register/terminal sessions, scan/add items, in-person tender (cash/card), and a printable receipt — as a thin front-end over the **existing** cart→order→inventory→billing paths. POS is a sales *channel*, not a new commerce engine: it reuses `app/services/shoppingcart.py` (`purchase_cart`), `commerce_order_service.create_order_from_line_items`, the SHOP-001 reservation/stock path, and `billing_shared.new_ledger_entry` / `refund_payment` — never forking billing or inventory. The whole module ships behind a default-off `POS_ENABLED` flag, is additive (existing shop/cart/orders/billing/inventory byte-for-byte unchanged with the flag off), uses single-table DynamoDB modeling, deterministic-id idempotency, SECOPS-007 dev/prod parity, and hermetic offline tests.

## Milestone 1 — Scoping & Scaffolding

### POS-001: POS channel mapping spike & reuse contract
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map the OFBiz POS application (register/terminal session, line-item scan, in-person tender, receipt, X/Z reports) onto the existing commerce stack so POS adds **no new commerce engine**: every sale resolves to a cart purchase via `app/services/shoppingcart.py:474` `purchase_cart` and an order via `commerce_order_service.create_order_from_line_items` (`app/services/commerce_order_service.py:132`); stock comes from the SHOP-001 decrement path (`app/services/shoppingcart.py:498`-`:538`); money flows through `app/services/billing_shared.py:224` `new_ledger_entry` and refunds through `refund_payment`/`settle_or_reverse_ledger` (`app/routers/billing.py:1179`+).
- Decide the POS-specific entities that genuinely don't exist yet (register/terminal config, an open *register session*/till with opening + closing cash float, a *POS transaction* wrapper that ties a cart+order+tender, and tender records for cash/card/wallet split) vs. what is reused verbatim (cart, order, line items, inventory reservation, ledger, receipts).
- Define the new DynamoDB table(s) + GSIs (with `attr_types` for numeric keys), the `app/models.py` shapes, settings keys, and the `POS_ENABLED` flag group. Record the cash-tender ledger reason (e.g. `pos_cash_sale`) and `extra={"provider": "pos_cash"}` attribution so platform financial dashboard buckets in-person cash correctly (FIN-013).

**Acceptance Criteria**
- A short design note (section in `docs/ofbiz-full-buildout-plan.md` or `docs/pos-plan.md`) enumerates each POS concept and whether it is NEW or REUSED, citing the file:line it reuses.
- Data-model delta lists each new table with PK/SK/GSIs (numeric keys flagged for `attr_types`), the new Pydantic models, and the new settings/flags — all defaulting off.
- The reuse contract explicitly states POS never writes orders/ledger/inventory directly except via the cited existing services.

**Dependencies**
- None.

---

### POS-002: POS data model (models.py)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add Pydantic shapes to `app/models.py` (alongside the existing cart/order/catalog models, e.g. near `CreateImageMessageIn`/catalog models ~`:546`): `RegisterConfig` (register_id, label, location_id, default_currency), `RegisterSessionOut` (session_id, register_id, cashier_sub, status `open|closed`, opening_float_cents, closing_float_cents, expected_cash_cents, counted_cash_cents, over_short_cents, opened_at, closed_at), `PosTransactionOut` (txn_id, session_id, cart_id, order_id, status `tendered|voided|refunded`, subtotal_cents, discount_cents, tax_cents, total_cents, tenders, receipt_id), `TenderIn`/`TenderOut` (kind `cash|card|wallet`, amount_cents, change_due_cents, payment_method_id?, card_ref?).
- Request models: `OpenSessionIn`, `CloseSessionIn` (counted_cash_cents), `AddLineItemIn` (sku/category_id/item_id, quantity), `TenderRequestIn` (list of `TenderIn`, idempotency_key), `RefundTxnIn` (txn_id, line refs/qty, reason).
- Reuse existing money/quantity conventions (integer cents, `now_ts()`); do not introduce a parallel currency type.

**Acceptance Criteria**
- All models import cleanly and validate (quantity ≥ 1, amount_cents ≥ 0, tender kind enum enforced).
- `tenders` sum validation helper exists so a tender request can be checked against transaction total.
- A smoke pytest constructs each model from a representative dict.

**Dependencies**
- POS-001.

---

### POS-003: POS DynamoDB tables, settings & feature flag
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `TableDef` entries to `scripts/local-ddb-init.py` (following the `_resolve_table_name(S.<name>, "<default>")` pattern used at `:103`/`:288`) for a single-table `pos` store: PK `pos_pk` / SK `pos_sk` with rows `REGISTER#{register_id}` / `META`, `SESSION#{session_id}` / `META`, `SESSION#{session_id}` / `TENDER#{txn_id}`, `TXN#{txn_id}` / `META`. GSIs: `GSI_REGISTER_OPEN` (register_id → opened_at, **numeric** sort, `attr_types={"opened_at":"N"}`) to find the open session per register; `GSI_SESSION_TXN` (session_id → created_at numeric) to list a session's transactions; `GSI_CASHIER` (cashier_sub → opened_at numeric) for a cashier's sessions. Declare every numeric GSI sort key in `attr_types` (per the CLAUDE.md gotcha).
- Add settings keys to `app/core/settings.py` next to `shopping_cart_table_name` (`:811`) / `orders_table_name` (`:1124`): `pos_table_name`, plus the flag `pos_enabled` (`POS_ENABLED`, default off) and `pos_cash_drawer_required` (default off). Mirror the `not in ("0","false","False")` idiom.
- Wire the handle in `app/core/tables.py` as `T.pos`.

**Acceptance Criteria**
- `just restart` recreates the `pos` table with all GSIs and no `ValidationException` (numeric sort keys queryable with integer values).
- `S.pos_enabled` reads through the singleton and defaults to `False`; with the flag off no POS router/route is reachable.
- A smoke pytest imports `T.pos` and asserts the handle resolves.

**Dependencies**
- POS-001.

---

## Milestone 2 — Register Session (Till) Service

### POS-004: Register & session service — open/close with cash float
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/pos_register.py`: `create_register(...)`, `open_session(cashier_sub, register_id, opening_float_cents)` (only one OPEN session per register — enforced via a conditional put keyed off `GSI_REGISTER_OPEN`), `get_open_session(register_id)`, `close_session(session_id, counted_cash_cents)` (computes `expected_cash_cents = opening_float + Σ cash tenders − Σ cash change/refunds`, `over_short_cents = counted − expected`, sets status `closed`).
- Emit audit events via `app/services/alerts.audit_event` (mirroring `commerce_order_service.py:106`) for `pos_session_opened` / `pos_session_closed` with over/short.
- Use `now_ts()` for all timestamps; all writes are conditional/atomic so a double-open or double-close is rejected.

**Acceptance Criteria**
- Opening a session when one is already open for that register → 409.
- Closing computes expected cash from recorded cash tenders + opening float; over/short is exact in a unit test with mixed tenders.
- Closing an already-closed session → 409; audit events written on both transitions.
- pytest covers open→close happy path, double-open rejection, and over/short math.

**Dependencies**
- POS-002, POS-003.

---

### POS-005: POS cart binding — scan/add line items reusing shoppingcart
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- In `app/services/pos_register.py` (or a thin `pos_cart.py`), a POS transaction draft binds to a real cart owned by the cashier's session subject so line-item add/remove reuses the existing cart primitives in `app/services/shoppingcart.py` (`add_item`/`list_items`, the `_item_sk`/`_catalog_item_key` helpers at `:34`-`:43`) — POS does NOT reimplement cart math; `line_total_cents` comes from `_item_from_item` (`:79`).
- `add_line_item(session_id, sku|category_id+item_id, qty)` resolves the catalog item, adds it to the bound cart, and returns the running cart total (same `sum(line_total_cents)` as `purchase_cart` at `:496`). Support quantity edits and remove. A "scan" is just an add by SKU/barcode lookup against the catalog.
- Keep the draft idempotent: re-binding returns the same cart for the same session+txn draft.

**Acceptance Criteria**
- Adding/removing items mutates the bound cart and the returned total matches the cart subtotal computed by the existing cart code (no parallel math).
- Unknown SKU/barcode → 404; the cart is never left partially mutated.
- pytest binds a session, adds two items, edits qty, removes one, and asserts the total equals the shoppingcart-computed subtotal.

**Dependencies**
- POS-004.

---

## Milestone 3 — Tender & Order Settlement

### POS-006: Cash tender, change calc & cash ledger entry
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Add `app/services/pos_tender.py`: `tender_cash(session_id, txn_draft, amount_tendered_cents)` validates `amount_tendered ≥ total`, computes `change_due_cents`, and records a CASH tender row on the session. Cash settlement writes a ledger entry via `billing_shared.new_ledger_entry` with `entry_type` reflecting a settled in-person sale, `reason="pos_cash_sale"`, `extra={"provider":"pos_cash"}` (FIN-013 attribution), state `settled` — POS never mints its own money record.
- The actual order is created by reusing the cart purchase path: call `purchase_cart` (`app/services/shoppingcart.py:474`) so stock decrement (`:498`-`:538`), order creation (`commerce_order_service.create_order_from_line_items` `:580`), and idempotency (`cart_purchase:` trigger `:597`) all run unchanged; POS supplies the `idempotency_key`.

**Acceptance Criteria**
- A cash sale decrements stock exactly once (via the existing SHOP-001 path), creates one order, writes one `pos_cash_sale` ledger entry, and returns the correct change.
- Tender below total → 422 with no order/ledger written.
- Replaying the same tender idempotency key returns the same order_id/txn_id (no duplicate ledger/stock change).
- pytest covers exact-cash, change-due, under-tender rejection, and replay idempotency.

**Dependencies**
- POS-005.

---

### POS-007: Card / wallet tender via existing billing
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Extend `pos_tender.py` with `tender_card(...)` and `tender_wallet(...)` that route the charge through the **existing** billing paths — card via the `charge_once` flow (`app/routers/billing.py:1179`) / its underlying service, wallet via `apply_wallet_delta` (`app/services/billing_shared.py`, used at `app/routers/billing.py:2536`) — so payment-provider attribution, fraud gating (GAP-0206/0207), and provider-toggle 503s all apply to POS card sales unchanged. POS passes `provider` through to the ledger.
- Support **split tender** (e.g. partial cash + partial card) by recording multiple tender rows whose sum equals the transaction total; only on full settlement is the cart purchased (single `purchase_cart` call, single order).

**Acceptance Criteria**
- A card sale goes through `charge_once`'s provider path (verified by asserting the provider-gate/fraud-gate is invoked) and produces provider-attributed ledger entries.
- A split cash+card tender settles only when tenders sum to total; an under-sum tender leaves the transaction open and creates no order.
- Wallet tender debits the wallet via `apply_wallet_delta` (insufficient balance → existing 4xx, no order).
- pytest covers card-only, wallet-only, and a cash+card split, each producing exactly one order.

**Dependencies**
- POS-006.

---

### POS-008: Void & in-person refund reusing refund_payment
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `void_transaction(txn_id)` (pre-settlement: releases the bound cart/reservation, marks txn `voided`, no money moved) and `refund_transaction(txn_id, line refs/qty, reason)` (post-settlement) to `pos_tender.py`. Refund money-out reuses the single refund mechanism — `refund_payment` / `settle_or_reverse_ledger` (`app/routers/billing.py:1179`+, `billing_shared.settle_or_reverse_ledger` `:262`) with `reason="refund"` and the original provider attribution — never a parallel refund. Cash refunds record a negative cash tender (affects the till's expected cash at close) and reverse the cash ledger entry.
- Restock returned qty via the inventory adjust path (gated on the inventory flag, mirroring OFB-009's `inventory.adjust(..., reason="pos_refund_restock")`).

**Acceptance Criteria**
- Voiding a pre-settlement txn releases stock/cart and writes no ledger entry; voiding a settled txn → 409 (must refund instead).
- A refund produces exactly one refund ledger entry tied to the original payment+provider; partial-qty refunds prorate; double-refund is prevented (idempotent).
- Cash refunds reduce the session's expected cash at close; restock increments on-hand once when inventory is enabled.
- pytest covers void, full refund, partial refund, refund idempotency, and cash-refund-affects-till.

**Dependencies**
- POS-006, POS-007.

---

## Milestone 4 — Receipt, Reports & Router

### POS-009: Receipt generation reusing the receipts pipeline
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Generate a printable in-person receipt for a settled POS transaction reusing the dependency-free receipt writer pattern (`app/services/receipts.py`, the same pure-Python approach cited in CLAUDE.md for audit PDFs) — line items, subtotal/discount/tax/total, tender breakdown (cash + change, card last-4), register/cashier/session, timestamp. Store the receipt id on the `PosTransactionOut`.
- Expose receipt retrieval (HTML/PDF) for reprint; binary-safe response for PDF (per the GAP-0209 `Response(media_type="application/pdf")` gotcha — not `PlainTextResponse`).

**Acceptance Criteria**
- A settled txn yields a receipt with correct totals and tender breakdown; reprint returns the same receipt deterministically.
- PDF bytes are served binary-safe (no UTF-8 corruption).
- pytest renders a receipt for a mixed-tender sale and asserts totals + tender lines.

**Dependencies**
- POS-007.

---

### POS-010: X/Z session reports (till summary)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `session_report(session_id, kind="x"|"z")` to `pos_register.py`: an **X report** (mid-shift, non-resetting) and **Z report** (end-of-shift, produced at close) summarizing gross sales, by-tender totals (cash/card/wallet), refunds, voids, discount/tax totals, opening float, expected vs counted cash, and over/short — aggregated from the session's tender rows + transactions via `GSI_SESSION_TXN`.
- Reuse the same per-day/per-session aggregation discipline as the platform financial dashboard (don't scan; query the GSI), and reconcile by-tender totals to the ledger entries written in POS-006/007.

**Acceptance Criteria**
- X and Z reports total correctly for a session with cash, card, a split tender, a refund, and a void; by-tender sums tie out to the recorded tenders and ledger entries.
- A Z report is only producible for a closed session; X for an open one.
- pytest covers a representative multi-tender session and asserts each summary line.

**Dependencies**
- POS-006, POS-007, POS-008.

---

### POS-011: POS router (registered in app/main.py)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/pos.py` and register it in `app/main.py` (per the CLAUDE.md router convention). Endpoints under `require_ui_session` with an admin/cashier role gate (`require_admin_session` for register config; cashier session subject for tendering): `POST /ui/pos/registers`, `GET /ui/pos/registers`; `POST /ui/pos/sessions/open`, `POST /ui/pos/sessions/{id}/close`, `GET /ui/pos/sessions/{id}`, `GET /ui/pos/sessions/{id}/report`; `POST /ui/pos/sessions/{id}/lines` (add/scan), `DELETE /ui/pos/sessions/{id}/lines/{sku}`; `POST /ui/pos/sessions/{id}/tender`; `POST /ui/pos/txns/{id}/void`, `POST /ui/pos/txns/{id}/refund`; `GET /ui/pos/txns/{id}/receipt`.
- Every handler short-circuits to **404/disabled** when `S.pos_enabled` is off (so the surface is byte-for-byte absent with the flag off). CSRF applies to non-GET cookie-auth requests (standard). Tender endpoints accept and forward an `idempotency_key`.

**Acceptance Criteria**
- With `POS_ENABLED=0` every POS route returns 404/disabled and no existing route changes behavior.
- With the flag on, the full open→scan→tender→receipt→close flow works end-to-end against the dev stack.
- Role gating: non-admin cannot create registers; foreign cashier cannot tender on another's session → 403.

**Dependencies**
- POS-004, POS-005, POS-006, POS-007, POS-008, POS-009, POS-010.

---

## Milestone 5 — Frontend (Register Terminal UI)

### POS-012: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TS interfaces to `frontend/src/api/types.ts` mirroring the POS Pydantic models (RegisterConfig, RegisterSession, PosTransaction, Tender, reports) and an endpoint wrapper module `frontend/src/api/endpoints/pos.ts` using the shared axios instance (`frontend/src/api/client.ts`, CSRF-aware) for every POS-011 route.
- Use React Query hooks conventions (`useQuery`/`useMutation`) consistent with existing shop endpoints (`frontend/src/api/endpoints/`).

**Acceptance Criteria**
- Types compile and mirror the backend response shapes exactly (integer cents).
- Endpoint wrappers cover open/close/lines/tender/void/refund/receipt/report.

**Dependencies**
- POS-011.

---

### POS-013: Register terminal page + route + nav
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add `frontend/src/pages/pos/` with a register terminal page: open/close-session panel (opening float, closing count + over/short), a scan/add line panel (SKU/barcode input + product search reusing existing catalog search), a running cart with running total/tax/discount, a tender modal (cash with change calc, card via the selected payment method, wallet, split tender), receipt preview/print, and an X/Z report view.
- Add a lazy-loaded route in `frontend/src/App.tsx` and a sidebar/nav entry (`components/layout/`), both **flag-gated** on POS_ENABLED (hide nav + guard route when off) and role-gated (admin/cashier). Forms use React Hook Form + Zod; UI uses shadcn/ui primitives.

**Acceptance Criteria**
- A cashier can open a session, scan/add items, take a cash sale with correct change, print a receipt, and close with over/short — all from the page.
- The nav entry and route are absent when `POS_ENABLED` is off; non-authorized roles are denied.
- Split tender (cash+card) settles a single order from the UI.

**Dependencies**
- POS-012.

---

## Milestone 6 — Tests

### POS-014: POS hermetic pytest + E2E suite
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest (`tests/test_pos_*.py`) following the repo's frozen-`T`/moto pattern (moto in-memory `pos`/`orders`/`order_items`/`shopping_cart`/`billing`/`catalog` tables bound to the exact frozen handles via `object.__setattr__`, billing/charge collaborators patched, frozen `S.pos_enabled` toggled): cover session open/close + over/short (POS-004), cart binding total parity with shoppingcart (POS-005), cash tender + change + idempotency + single-order/stock-decrement (POS-006), card/wallet/split tender via the existing billing paths (POS-007), void + refund-via-refund_payment + restock (POS-008), receipt totals (POS-009), and X/Z report tie-out to ledger/tenders (POS-010).
- Add `frontend/e2e/pos.spec.ts` (seeded admin/cashier session + CSRF per CLAUDE.md/MEMORY.md): open session → scan items → cash sale with change → receipt → close with over/short; a split-tender sale; a refund; and the flag-off assertion (POS routes 404 / nav hidden). Assert dev/prod parity (no `dev_mode` branch in the money path).

**Acceptance Criteria**
- Pytest suite passes offline with no real AWS/network and asserts: single order + single ledger entry per sale, refund-once idempotency, over/short math, and total parity with the shoppingcart subtotal.
- E2E covers open→sale→receipt→close, split tender, refund, and the flag-off (POS absent) case under the standard 1-worker Playwright config.
- With `POS_ENABLED=0`, a regression test confirms existing shop/cart/order/billing tests are unaffected.

**Dependencies**
- POS-011, POS-013.

---
