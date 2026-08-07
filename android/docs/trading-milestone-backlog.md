# Milestone 2 — Trading (TRD)

Order entry + management + positions/wallet/margin for the exchange client, behind the
`me_trade_enabled` gate. Follow-on to the market-data client (charting + book + trades already
shipped). Android first; web mirror later. **Prefix `TRD`.** ☐ todo · ◐ in progress · ☑ done · ⊘ deferred.

## Backend contract (scoped live 2026-08-07 — do not re-derive)
- **Place** `POST /me/orders {symbolid, side:"buy"|"sell", price, qty, clordid}` → `{status:ack|nak,
  type:new_order_ack, clordid, orderid, symbolid, mpid, client_connection_id, fills:[]}`. clordid ≤20, unique.
- **Amend** `PATCH /me/orders/{clordid} {new_qty, new_price?}` — field is **`new_qty`** (not qty). In-place;
  reduce-qty keeps queue priority. → ack.
- **Cancel** `DELETE /me/orders/{clordid}` → `{status:ack, type:cancel_ack, cancelled_qty, ...}`.
- **Bulk cancel** `POST /me/bulk_cancel` (contract TBD).
- **Account/positions/wallet/margin READ** `GET /me/margin_account` → `{available_balance, balance,
  reserved_margin, num_positions, pos_symbol_idx, pos_qty, pos_entry_price, pos_liquidation_price,
  pos_unrealized_pnl, distress_level, is_liquidating, margin_mode, mpid}`. Single net position.
- **Advanced (exist, write-only, contract TBD per type)**: `POST /me/algo` (stop/TWAP/VWAP), `/me/oco`,
  `/me/oto`, `/me/quote`, `/me/funding_order`.
- **⚠ Gaps**: NO server list of working orders (`GET /me/orders*` → 405) and NO fills-history read (404).
  Client must TRACK its own working orders + session fills from acks/fills[]. A private exec-report
  stream may exist (unverified — probe as TRD-2 stretch).
- **⊘ Spot**: no spot account/balance read exists (all 404). Cash wallet = `margin_account.balance`.
  A real spot-account view is backend-blocked (needs a new endpoint). Building margin/perp only.
- Auth `Authorization: Bearer <ui_access_token>` (or cookie). Gate `me_trade_enabled` on tlc_users.

## Wave 1 — Foundation + order ticket
- ☑ **TRD-1 · Trading data layer** — `L` · **done** (2026-08-07) — `TradingApi` (place/amend/cancel +
  `getMarginAccount`) + `TradingDtos` (Moshi codegen; `new_qty` amend field) + `TradingModels`
  (OrderSide/OrderAck/CancelAck/Fill/MarginAccount/PositionSnapshot + `marginUsedFraction`) + mappers
  + `TradingRepository` (apiCall/ApiResult). Wired in ExchangeDataModule reusing the HTTP/1.1 pin +
  cookie session. Build-green. (bulkCancel/advanced endpoints deferred to their waves.)
- ◐ **TRD-2 · Order + fills store** — `M` — session working-orders tracked in the VM (added on ack,
  removed on cancel; filled qty subtracted). Persisted store + fills-log still to add.
- ◐ **TRD-3 · Trade gate** — `S` — rejection path done: the engine's "trading not enabled for this
  account" nak is surfaced as the (red) ticket message. Proactive gate/disable + enablement still to add.
- ☑ **TRD-4 · Order ticket UI** — `L` · **done** (2026-08-07) — "Order" tab on the symbol screen:
  Buy/Sell, price (prefilled from last), quantity, order value, Available + margin-used meter (from
  margin_account), place → `POST /me/orders`, result/error line, and this-session open-orders list
  with Cancel. Limit orders (market/advanced later). Build-green; on-device A15 verified: ticket
  renders, place hits the engine, gate nak "trading not enabled" surfaced. (Successful place pending
  an `me_trade_enabled` account — TRD-16.)

## Wave 2 — Click-to-trade + order management
- ☑ **TRD-5 · Click-to-trade from book** — `M` · **done** (2026-08-07) — tapping an order-book row
  (Ladder or Columns) prefills the ticket and jumps to the Order tab: ask row → Buy @ that ask, bid
  row → Sell @ that bid. `OrderBookL2.onPriceClick(price, side)` → shared `TradingViewModel.prefillPrice`
  (both book + ticket resolve the same nav-scoped VM) → `tab = Order`.
- ☐ **TRD-6 · Click-to-trade from chart** — `M` — tap/long-press a chart price → prefill ticket price.
- ☐ **TRD-7 · Open orders panel** — `M` — list working orders (from store) with cancel + amend.
- ☐ **TRD-8 · Amend vs replace** — `M` — reduce-qty → PATCH `new_qty` (amend, keep priority);
  price change / qty-up → replace (cancel+new) or PATCH `new_price`; explicit Replace + Cancel actions.

## Wave 3 — Positions, wallet, margin
- ☐ **TRD-9 · Positions panel** — `M` — from margin_account: qty/side, entry, liq price, unrealized
  PnL (colored), position value.
- ☐ **TRD-10 · Close position / close all** — `M` — market/opposing order for pos_qty; one-tap close +
  close-all (single net position today, but built to scale).
- ☐ **TRD-11 · Wallet (cash)** — `S` — balance + available_balance.
- ☐ **TRD-12 · Margin usage meter** — `M` — reserved_margin vs balance → used %, free margin;
  distress_level / is_liquidating warning banner.

## Wave 4 — Fills, advanced types, polish
- ☐ **TRD-13 · Fills viewer** — `M` — session fills (from acks) with price/qty/side/time; honest
  "session only" note (no history endpoint).
- ☐ **TRD-14 · Advanced order types** — `L` — Stop (via /me/algo), OCO, OTO, TWAP/VWAP; scope each
  contract then build its ticket. (Only after Limit/Market loop is solid.)
- ☐ **TRD-15 · Live account refresh + notifications** — `M` — poll margin_account; ack/nak/fill toasts;
  push on fills (FCM already wired).
- ☐ **TRD-16 · On-device E2E** — `M` — place/amend/cancel/close on an enabled account (A15); verify
  wallet/margin/position update. Enable the test account (`me_trade_enabled` on tlc_users) or use mmA/mmB.

## Deferred / backend-blocked
- ⊘ Spot account view (no backend read). ⊘ Fills history (no read). ⊘ Working-orders server list
  (405 — client-tracked instead). Web-parity mirror. Liquidations viewer (no feed).
