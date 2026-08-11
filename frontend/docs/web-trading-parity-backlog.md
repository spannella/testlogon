# Web trading + prediction-market parity backlog

Goal: bring the **mobile-web** client to parity with the Android trading + market-data feature
set. The web app already has **market-data view-only** (`src/pages/markets/*`, `src/hooks/useMarketData*`);
everything below the market-data line is currently **Android-only**.

## Audit (2026-08-11)

**Stack:** React + TypeScript + Vite + React Query v5 (`@tanstack/react-query`). API client
`src/api/client.ts` already sends **cookie (`credentials: include`) + `Authorization: Bearer` +
`X-CSRF-Token`** → authed `/me/*` POSTs work with no extra plumbing. Web builds green (Node 20).

**Present:** `api/endpoints/marketData.ts` (symbols/book/candles/trades), `useMarketData`
(RQ 2s) + `useMarketDataStream` (SSE live book+candles), `MarketsPage`, `SymbolDetailPage`
(book + trades + chart + live), `CandleChart` (**basic SVG candles — no indicators/drawing**).
Routes `/markets`, `/markets/:symbolId`.

**Missing vs Android (the parity gap):** all order entry; advanced order types (quote/algo/OTO,
+OCO/funding/spot staged); account/positions/margin/close; fills + exec-events; working orders +
amend/cancel-all; click-to-trade; chart indicators + drawing + dual-style book + search/watchlist;
prediction markets; web-native feedback (Notification API + `navigator.vibrate`); mobile-first layout.

## Contract (same endpoints Android uses; see also the exchange-client memory)

- Order entry `POST /me/orders` `{symbolid, side, price, qty, clordid, market?, tif?(GTC/IOC/FOK/GTD),
  post_only?, hidden?, aon?, display_qty?, min_qty?, expiry_ns?}`; `PATCH /me/orders/{clordid}`
  `{new_qty, new_price?, symbolid?}`; `DELETE /me/orders/{clordid}?symbolid=N`.
- `POST /me/bulk_cancel`; `POST /me/quote {symbolid,bid_price,ask_price,bid_qty,ask_qty}`;
  `POST /me/algo {algo_type(stop|stop_limit|stop_market|take_profit),symbolid,side,qty,stop_price?,limit_price?}`;
  `POST /me/oto {symbolid,parent_*,child_*}`.
- `GET /me/margin_account`; `POST /me/margin_deposit {amount}`; `GET /me/algo/events`.
- Prediction market: `GET /me/pm_state?symbolid=N` → `{is_binary,state,outcome,face_value,resolve_ts,resolver_id}`.
  A PM is a symbol; price ∈ [0, face] = implied YES prob × face; YES=buy, NO=sell.
- Staged (edge/config-blocked today): `POST /me/oco`, `POST /me/funding_order`, `GET /me/spot_balance`, `POST /me/spot_deposit`.

## Waves

- **WEB-A — Trading data layer ✅ (this change).** `api/endpoints/trading.ts` (all calls + types +
  helpers `isAck`/`ackMessage`/`impliedYes`/`marginUsedFraction`) + `hooks/useTrading.ts` (RQ
  queries `useMarginAccount`/`usePmState`/`useExecEvents` + mutations place/amend/cancel/bulk-cancel/
  deposit/quote/algo/oto). Reuses `client.ts`. Type-checks clean; no UI yet.
- **WEB-B — Order ticket.** Order-type selector (Limit/Market/Stop/Stop-Limit/TP/Quote/OTO; OCO/Funding
  gated), Buy/Sell, price/qty **steppers + 25/50/75/Max chips**, TIF+GTD, advanced flags
  (post-only/hidden/AON/iceberg/min-qty), order value + avail, submit with **confirm step** for
  market/close, entry hints, sectioned **Trade / Positions / Orders / Fills**, **mobile-first**.
- **WEB-C — Account + positions + fills.** Wallet/margin strip + meter + distress, position card +
  **market-order close (STP guard)**, session fills + exec-events feed, cancel-all, amend/replace,
  funding deposit.
- **WEB-D — Click-to-trade + chart/book enrichment.** Prefill from book/chart; dual-style book;
  chart indicators (MA/EMA/RSI/MACD/BB/VWAP/volume) + chart types + drawing tools; symbol search + watchlist.
- **WEB-E — Prediction markets.** `pm_state` banner (implied-YES bar, payout, resolved YES/NO) + YES/NO relabel.
- **WEB-F — Web-native polish.** Web Notification API + `navigator.vibrate` (haptics/notifications
  equivalent); OCO/funding/spot behind flags; responsive/touch pass.

## Notes / caveats
- **Prediction markets are merged to backend `origin/main` but NOT yet on the running prod binary**
  (`pm_state` 404s live today) → the PM UI stays inert until prod redeploys + an admin configures a
  market. Same graceful-degrade approach as Android.
- No server-side working-orders / fills list → the client tracks its own from acks + `/me/algo/events` (like Android).
- OCO returns `no_response` through the prod edge; `funding_order` rejects `reason 30`; spot needs an
  asset-id map — all staged/flagged, not wired into the primary flow.
