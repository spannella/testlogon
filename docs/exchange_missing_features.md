# Exchange Frontend: Coverage & Missing Features

Status of the trading/exchange frontend (web + Android) against the edge `/me/*` route surface, as of 2026-08-21. Companion to `custody_missing_features.md` (custody-specific). "Real" = moves real state through the engine/gateway; "Stub" = documented no-op / empty feed that shapes I/O without a backing read.

## Status legend
| Status | Meaning |
|---|---|
| **Full** | Frontend wired to a real, working backend route. |
| **Real (undeployed)** | Route + UI are real, but the edge route isn't deployed to prod yet (UI 404-degrades). |
| **Stub** | Route returns an empty/simulated feed (`stub:true`) because the backend has no read for it. |
| **Missing** | No route and no UI. |

---

## Covered this session (Full / Real-undeployed)
All wired web + Android, gated + tested; edge routes not all prod-deployed → 404-degrade gracefully.

- **Custody**: balance, deposit address+QR, withdraw, deposits history, sub-accounts (list/create), vault↔vault transfer, custody↔trading bridge (fund/settle spot+margin).
- **Margin**: account, position (entry/liq/uPnL), config (admin), liquidation-risk display, funding orders.
- **Feeds**: per-fill fees (`/me/fills/fees`), liquidations (`/me/liquidations`), funding payments (`/me/funding/payments`).
- **Live market data**: SSE `/md/stream/{symbol}` → live book + price/chart with reconnect (this one IS core md and should work on prod).
- **Money-safety UX**: confirm dialogs, balance-aware Max/over-spend blocking, receipts on all money moves.
- **Admin engine config**: matching_algo, spread_config, trading_params, risk_config, spot_index, spot_config.
- **Prediction Markets** (admin): create binary/categorical, resolve, resolution audit log; trader PM banner (implied YES %).
- **Staking (peer) + Auctions** (trader): stake_request/stake_offer, auction_request/auction_bid — act-by-id.

---

## Stubbed / Missing (what we still need)

### 1. Peer-staking & auction DISCOVERY — **Stub** (edge stub added; needs an engine read)
- **Now stubbed at the edge** (this session, `testlogon-cpp` clone commit `469cb3f`, code-only/undeployed):
  - `GET /me/stake_requests` → `{stake_requests:[], count:0, stub:true, note}`
  - `GET /me/auctions` → `{auctions:[], count:0, stub:true, note}`
- **Why stub:** the matching engine exposes only the *write* actions (`stake_request`/`stake_offer`, `auction_request`/`auction_bid`) — there is **no read** to list open stake requests or open auctions, so a user can act by id but cannot browse.
- **Backend work to make real:** engine adds `me_stake_requests(engine)` and `me_auctions(engine)` (open items with id/symbol/qty/price/reserve/expiry/status); then repoint the two edge handlers to proxy them and drop `stub:true`.

### 2. Custody yield-staking — **Real (undeployed)** (edge proxy added)
- **Added this session** (`469cb3f`, real proxy of the gateway `/v1/staking/*`):
  - `GET /me/staking/providers` (real proxy)
  - `GET /me/staking/positions` (real proxy, filtered to the caller's vault + sub-accounts)
  - `POST /me/staking/stake {provider, amount}` (real proxy, idempotency-keyed, base custody vault)
- **Backend work:** deploy the edge routes; the gateway `/v1/staking` already backs them. (Distinct from the engine peer `/me/stake_*` market above.)
- **Optional:** `POST /v1/staking/positions/{id}/{action}` (unstake/claim) exists gateway-side but has no edge route yet.

### 3. Deployment — **Real, undeployed**
- The custody, feed, admin-config, PM, staking, and discovery edge routes are on `testlogon-cpp` main (or the local clone for the newest stubs) but **not deployed to the prod edge**. The prod custody-host gateway also needs the `c62dfa8` rebuild for deposits/staking. Until deployed, all these surfaces 404-degrade.

### 4. Live end-to-end — **Unverified**
- The `/me/custody/*` surface is account-gated (demo 404s). Nothing custody/staking has been driven end-to-end. `/md/stream` (live market data) is the one piece expected to work on prod today.

---

## Frontend built since (was the candidate list) — now BUILT, waiting on backend
All shipped to `main` (web + Android), degrade-on-404 until the backend/deploy lands:
- ✅ **Portfolio / account overview** — consolidated custody+spot+margin+staking + open positions/uPnL. USD total via `/me/prices` (stub) → labeled "indicative" until a real oracle.
- ✅ **Order management + trade history** — working-orders view (amend/cancel/cancel-all) + fills trade-history. **Blocked on a real `/me/orders/live`** (see below) — shows only session orders otherwise.
- ✅ **Staking dashboard** — providers/positions/stake (real gateway proxy, undeployed).
- ✅ **Discovery browse** — open stake-requests/auctions (edge stubs return empty; needs the engine listing read).
- ✅ **Trading alerts** — client-derived from the feeds (bell/toasts/system-notif). A server push would replace polling (see below).
- ✅ **Watchlists + market browser** — searchable list (last price / % change / sparkline) + client-side watchlist (star + All/Watchlist). NOTE: % change is a ~1h candle window (no 24h ticker stat exists) — see backend list.
- ✅ **Charting upgrades** — timeframe switcher, EMA overlays, RSI/Volume sub-panes, crosshair, live SSE bars. Indicators computed **client-side** (`/md/indicators` 404s on this edge) — see backend list.
- ✅ **Settings & preferences** — theme, default market (auto-opens on the markets landing), per-kind alert toggles, notification permission, reset. Prefs are **client-only** (localStorage / SharedPrefs), no server sync — see backend list.
- ✅ **Class-filtered unified symbol picker** (PR #226, 2026-08-20) — the Markets list + `Cmd+K` palette group the flat `/md/symbols` catalog by instrument class: **Spot**/**Perp** (`is_perpetual`), **Funding book** (perps + latest funding-rate bps from `/me/funding/payments`), **Prediction** (per-symbol PM-state probe → implied-YES %). Prediction/Funding lean on inference/probing until the backend adds a class discriminator (see the P2 picker asks).
- ✅ **Paper trading** (PRs #222 / #223 / #225) — dedicated Paper page + paper-mode toggle on the full trade ticket + the paper account surfaced across the blotter / PnL / portfolio views (all client-side; see Future-tooling section).
- ✅ **Historical market-data analysis workbench** (PR #227, 2026-08-21) — web `/analysis` + Android "Analysis" hub: class-filtered symbol picker, long-range chart, stats panel (returns / annualized-vol / max-drawdown / hi-lo / volume), multi-symbol compare + correlation matrix, MA-cross backtest with equity curve. **Backend blocker:** `GET /md/history/{symbol}` (degrades to the recent candle window until then). *Backend spec written.*
- ✅ **Creator revenue-share tokens** (PR #228, 2026-08-21) — web `/tokens` + Android "Creator Tokens" hub: mint (+$100 fee), market/browse, token detail (cap table / revenue distributions + claim / upkeep $100-gauge + holder pro-rata shortfall + FROZEN / issuer IPO launcher + single-clearing auction). Real revenue-share claim; degrade-on-404. **Backend-blocked** (mint engine symbol + seed book, cap table, revenue routing, upkeep billing job, IPO clearing). *Full backend spec written.*
- ✅ **Pre-emptive margin distress / bailout auctions** (PR #229, 2026-08-21) — web `/bailouts` + Portfolio distress banner + Android `feature/bailout`: a position approaching a margin call (volatility-scaled distress band, still-solvent only) can open a **position-share** rescue auction (sealed single-clearing) to avoid forced liquidation; 3-zone health meter, rescuer discovery board, opt-in auto-open setting, auto-cancel→liquidation on maintenance breach. Server-authoritative distress; degrade-on-404. **Backend-blocked** (distress read, position co-ownership, auction clearing). *Full backend spec written.*
- ✅ **Multi-protocol trading/custody credentials** (PR #230, 2026-08-21) — extends the API-key manager (web `security/ApiKeys.tsx` + Android `feature/apikeys`): Trading/Custody/Market-Data scopes + a REST/WS/FIX/Binary protocol selector + per-key Connection Credentials (WS token + subscribe payloads / FIX session `.cfg` + rotate password / binary `me_wire` endpoint + HMAC + rotate secret), secrets shown once, degrade-on-404. **Backend-blocked** (key model spanning 4 channels + FIX/binary provisioning + `GET /me/gateway/endpoints`). *Full backend spec written.*

---

## Backend support needed (consolidated — what the frontend is waiting on)

Every frontend surface below is BUILT and merged; it 404-degrades until the backend piece lands. Grouped by priority.

### P0 — makes a shipped surface actually functional (currently stub/absent)
- [ ] **Real `GET /me/orders/live`** — the working-orders read is **not wired in this repo** (the exchange edge-forwards `/me/*` to a remote engine; grep found no `/me/orders/live` handler). The order-management UI calls it and degrades to session-only orders. Need the remote engine's open-orders read exposed through the edge (`{orders:[{clordid,symbolid,side,price,qty,leaves_qty,tif,ts}]}`) so orders survive restart + reflect server truth.
- [ ] **Real `GET /me/prices`** — currently an edge **stub** with hardcoded indicative prices (`aa08415`, clone-only). Need a real engine mark/oracle read (e.g. `me_marks(engine)` → asset→USD, or per-symbol mark from the book) so the Portfolio total equity is a settled USD value, not "indicative".
- [ ] **Engine open-listing reads** `me_stake_requests(engine)` + `me_auctions(engine)` → repoint the `/me/stake_requests` + `/me/auctions` edge stubs so Discovery Browse shows real open items (today they return empty).

### P0 — deploy (nothing custody/exchange-new is live)
- [ ] **Deploy all new edge routes to prod** (custody bridge/subaccounts/deposits, fees, fills-fees/liquidations/funding, admin engine-config, prediction-markets, staking proxy, discovery/prices stubs, orders/live) — they're on `main`/clone but not on the prod edge.
- [ ] **Rebuild the custody-host gateway** (`c62dfa8`) so `/me/custody/deposits` + `/me/staking/*` return real data (it runs the pre-`c62dfa8` binary today).
- [ ] **Provide a custody/trade-enabled account** — the whole `/me/custody/*` surface is `CUSTODY_ALLOWLIST`-gated (demo 404s); nothing has been driven end-to-end.

### P1 — completeness of shipped surfaces
- [ ] **Per-sub-account balance read** — `GET /me/custody/subaccounts` returns only `{label,vault}` (no balances). Without a per-vault balance read, the UI can't show sub-account balances or a Max on transfers *from* a named sub-account.
- [ ] **`POST /me/staking/positions/{id}/{action}`** (unstake / claim) — the gateway supports it (`/v1/staking/positions/{id}/{action}`); add the edge proxy so the Staking dashboard can unstake/claim, not just stake.
- [ ] **Paginated trade/order history** — the fills feed (`/me/fills/fees`) is a recent window; a cursor/paginated historical feed (`me_fills(sub, since?)`) would back a full trade-history view.
- [ ] **Margin-config READ** (`GET /me/margin_config/{symbolid}`) — the per-symbol initial/maintenance margin bps are **write-only** today (only `POST /me/margin_config` exists). Without a read, the order-entry **margin-impact + est. liquidation-price** previews use assumed defaults (labeled "(est.)"). A read (initial/maintenance/liq-fee/borrow bps per symbol) would make those previews exact.

### P2 — quality / real-time
- [ ] **Server push for trading events** — alerts are client-**polled** off the feeds today. A user event stream (WS/SSE) for fills/liquidation/margin-distress/funding would replace polling and enable background/push notifications. (The WS server exists but is scoped to call-signaling; it'd need a trading user-event channel.)
- [ ] **Real-time balance/position push** — same idea for the Portfolio/margin surfaces (currently 5s polling).

### P2 — surfaced by the charting / watchlists / settings work (2026-08-19)
- [ ] **`GET /md/indicators/{symbol}`** — the route exists in the edge (`md_consumer.cpp`) but **404s on this deployment**, so the chart computes MA/EMA/RSI/MACD/VWAP **client-side**. Deploy/enable it (with a known response shape) to serve engine-computed indicators consistently and offload heavier ones.
- [ ] **24h ticker stats** (`GET /md/ticker/{symbol}` or a `/md/stats`) — 24h change / high / low / volume per symbol. The market browser's "% change" is currently derived from a ~1h candle window (there's no ticker-stats read); a real 24h stat would make the change column accurate and cheap (one call vs per-symbol candle fetches).
- [ ] **Server-side user preferences** (optional) — watchlist, default market, and per-kind alert prefs are persisted **client-side only** (localStorage / SharedPrefs), so they don't sync across devices/sessions-cleared. A `/me/prefs` get/put would enable cross-device sync. Low priority (client persistence works fine for a single device).

### P2 — surfaced by the class-filtered symbol picker (2026-08-20)
The picker groups the symbol catalog by instrument class (Spot / Perp / Prediction / Funding book). Spot & Perp are free from `/md/symbols` (`is_perpetual`); the other two lean on reads that don't exist cleanly yet:
- [ ] **PM-enabled symbol list** — there is **no list of prediction-market symbols**; the frontend detects a PM only by probing the per-symbol PM-state read (a non-PM symbol 404s, `retry:false`). The picker's **Prediction** group therefore probes listed symbols and caches — fine for a handful of symbols, wasteful at scale. Add a cheap `GET /md/symbols?class=prediction` (or a `pm: true` / `instrument_class` field on the `/md/symbols` rows, or a `GET /pm/markets` listing) so the group is one read, not N probes.
- [ ] **Per-symbol current funding rate** — the **Funding book** shows perpetual contracts + funding interval (from the symbol) but the **current funding rate (bps)** is only available as a side-effect of the `/me/funding/payments` feed (recent payments) or an admin index-set ack. A read like `GET /md/funding/{symbol}` (or `funding_rate_bps` + `next_funding_ts` on the `/md/symbols` rows) would give the funding book an accurate live rate + countdown without mining the payments feed.
- [ ] **`instrument_class` discriminator on `/md/symbols`** (umbrella) — today the only class field is `is_perpetual`; Prediction & Funding are inferred. A single `instrument_class` enum (`spot|perp|prediction|funding`) on each symbol row would let the picker group by truth instead of inference and drop the PM probing entirely.

---

## Future tooling (roadmap — requested 2026-08-20, not started)

### Historical market data analysis — ✅ FRONTEND BUILT (PR #227, 2026-08-20)
A research/analysis workbench over historical data (long-range charts, volatility/return stats, correlations, indicator backtesting, session replays). **Shipped** web (`/analysis`) + Android ("Analysis" in the More/GROWTH hub): class-filtered symbol picker, long-range chart (degrades to the recent candle window with a banner until `/md/history` lands), stats panel (returns/annualized-vol/max-drawdown/hi-lo/volume/cumulative), multi-symbol normalized compare + correlation matrix, and an MA-cross backtest with equity curve. Pure stats libs (`marketStats.ts` +24 vitest / `MarketStats.kt` +20 JVM). **Backend blocker (only):** the `GET /md/history/{symbol}?interval=&from=&to=&cursor=` paginated OHLCV read below — until then it analyzes the recent window only.
- **Backend needed (blocker):** a **historical bars/trades store + query endpoint** — `/md/candles` today is a recent window only. Need e.g. `GET /md/history/{symbol}?interval=&from=&to=&cursor=` (paginated long-range OHLCV) and/or a historical trades feed. Without it the frontend can only analyze the recent window it can pull.
- **Frontend (buildable on top):** long-range/zoomable charts, a stats panel (returns, volatility, drawdown, hi/lo), multi-symbol compare/correlation, and a simple indicator/strategy backtest runner (reuse the client-side indicator math already written for the chart).

### Paper trading — ✅ BUILT (web + Android, client-side)
A simulated-trading mode: virtual balance, simulated fills against live/last prices, virtual positions + PnL — no real orders.
- ✅ **Dedicated Paper surface** (PR #222) — a client-side paper account (persisted: web `paper.account.v1` localStorage, Android `paper.account` DataStore) + a pure fill engine (`paperEngine.ts` / `PaperEngine.kt`, int64 tick space, avg-cost positions incl. shorts, market fills at market + resting-limit fills on tick, realized/unrealized PnL, equity) matching virtual orders against the live market-data feed.
- ✅ **Paper-mode toggle on the full trade ticket** (PR #223, 2026-08-20) — the real `TradeTicket` (web + Android) now has a **Paper** switch. ON = PAPER badge/amber banner, order types restricted to Market/Limit, submits route to the SAME shared paper account (no `/me/orders`), confirm relabeled "Confirm paper order", account strip shows paper cash/buying-power. OFF = ticket behaves exactly as before (real orders). Ticket and Paper page share one virtual account.
- **Optional backend (NOT built — for realism/persistence/leaderboards):** a server-side sandbox/paper account + a paper order path (e.g. a `paper=true` flag or a separate `/me/paper/*` surface) so fills go through the real matching engine's logic and persist/sync across devices. Nice-to-have; the client-side version ships without it.
- ✅ **Paper account in the read-only views** (PR #225, 2026-08-20) — the **Blotter** (Orders/Fills/Positions), **PnL**, and **Portfolio** views (web + Android) now source from the shared paper account with live-mark MTM when paper-mode is ON (PAPER badge on each; OFF = real data unchanged). The `AnalyticsPage` is creator/content analytics (not trading) and is intentionally out of scope.

### Tokenized creator revenue-share contracts — ✅ FRONTEND BUILT (PR #228, 2026-08-20) · backend-blocked
A new primitive: a content-selling creator can **tokenize their revenue share** into a tradeable coin. **Frontend shipped** web (`/tokens`) + Android (`feature/tokens`, "Creator Tokens" hub): Mint (+$100 creation-fee confirm), Market/browse, and Token detail (cap table / revenue distributions + claim / upkeep $100-gauge + holder pro-rata share + FROZEN state / issuer IPO launcher + single-clearing-price auction panel). All reads degrade-on-404 to honest "pending backend" states; all mutations error clearly (never silent success). Pure math libs `tokens.ts` (+14 vitest) / `TokenMath.kt` (+16 JVM). **Locked decisions:** (1) real revenue-share claim; (2) $100/mo upkeep on holders pro-rata as a shortfall top-up (`max(0, $100 − fees)`), non-payment → freeze (assumption labelled in-UI); (3) single-clearing-price IPO auction; (4) frontend-first. **Nothing moves real value until the backend blockers below land.**
**Flow:** creator signs up → **mint** a new token (creator holds **100%**, **$100 creation fee**) → optionally **list** it by selling **N%** in an **auction** → post-auction the token trades on a **continuous order book** → **book-upkeep billing**: **$100/month** to keep the book tradeable, **waived** in any month where trading fees generated ≥ $100 (only charged when the book underperforms its own upkeep).
- **Reuses (design):** the matching engine's continuous book + `auction_request`/`auction_bid` (or a new IPO batch auction); the **subscriptions dunning/billing** engine (monthly upkeep charge); the **one-true-ledger** + **payouts** rails (creation fee, auction proceeds, revenue-share distributions); the **prediction-market create** flow as precedent for spinning up a new tradeable symbol; and the **class-filtered picker** (a new "creator-token" instrument class).
- **Hard backend blockers (frontend cannot do these):**
  - **Mint a new engine symbol + seed its book** on the remote matching engine (the edge only forwards `/me/*`; there is no "create instrument" write today). Needs an engine `create_token` / `list_symbol` primitive.
  - **Per-token cap table / holdings ledger** (who holds what %, transfer on fills) — the revenue-share claim settles against it.
  - **Revenue routing** — if the token is a real revenue-share claim, a seam that streams a % of the creator's content earnings (ecom/subs/tips already in the ledger) to current holders pro-rata.
  - **Book-upkeep billing job** — a monthly runner summing each token's trading fees vs. $100 and charging the shortfall/flat fee (reuse subscriptions dunning), with a non-payment → book-freeze/delist state.
  - **Auction clearing** — a single-clearing-price batch auction for the initial N% sale (the existing peer auction is per-item, not an IPO).
- **Product decisions — 🔒 LOCKED 2026-08-21** (build to these; §D–H already reflect them):
  1. **Real revenue-share claim** — the token is a genuine claim on `revenue_share_bps` of the creator's ongoing content revenue (§E), not a branded speculative scoreboard.
  2. **Holders bear upkeep, pro-rata, shortfall-to-$100** — monthly `amount_due = max(0, 10000 − fees_generated)`, split `round(amount_due * holder_qty / total_supply)` per holder (§F). Not issuer-only, not flat-$100.
  3. **New single-clearing-price IPO batch auction** — sealed-bid, one uniform clearing price (§G); the existing per-item peer `auction_request`/`auction_bid` is not reused for listings.
  4. **Freeze, not delist** — non-payment → `status:frozen` + halt book; reversible once shares are paid (§F). Positions preserved.
- **Frontend (buildable now, degrade-on-404):** a "Tokenize" creator flow (mint + $100-fee confirm), a token/cap-table dashboard (holdings, % held, upkeep status + fee-vs-$100 gauge), a "List token" auction launcher (set N% + reserve), and revenue-distribution history. The trade surfaces already exist — the continuous book plugs into the current book/ticket/blotter once the symbol is mintable, surfaced as a new instrument class in the picker.

> See `custody_missing_features.md` for the custody-specific items the team has since largely closed (atomic vault↔vault transfer, custody↔trading fund/settle bridge, real per-fill fee, deposits) — those moved from stub to real; the remaining custody item is deploy + the enabled account.

---

## Added 2026-08-20 — this session's deltas + newly-surfaced backlog

### Status flips (moved to DONE / deployed this session)
- ✅ **Server push for trading events** (was P2) — `ws_user_events_loop` pushes `fill`/`liquidation`/`funding` on the authenticated user WS (`{"sub":"events"}`, `ws_token`/`WS_TOKEN_SECRET`). **Merged + deployed to prod** (`ea74d70`). Replaces the client polling for those feeds. *Still gated on prod:* WS is inert until `WS_TOKEN_SECRET` + WS port/edge-tunnel are set on the live `:443` box (currently unset).
- ✅ **Custody over more than REST (unified gateway)** — the exchange is now ONE gateway fronting BOTH the matching engine AND custody across **WS** (custody events on the user WS via `{"sub":"custody"}`), **FIX** (CU-series MsgTypes on `me-fix-gateway`), and **binary** (`CU_OP_*` on the `me_wire` listener). Merged to `main`, deployed in the exchange binary. *Gated on prod:* binary custody needs `TLC_ME_OE_LISTEN`; the FIX gateway is a separate process not yet running on prod.
- [ ] **📋 BACKLOG — multi-protocol trading/custody credential management in the API-key UI** (requested 2026-08-21) — the client-side counterpart to the unified gateway above. Extend the existing **API-key management** surface (see the API-key-parity program, PR #118 — keys are already scoped/fail-closed) so a user can provision + manage credentials for **every access channel**, not just REST:
  - **REST + WS** creds for **trading** and **custody** — issue a key/secret scoped to `trading` and/or `custody` (reuse the existing scope model), plus the **WS token** (`ws_token`/`WS_TOKEN_SECRET`) needed to subscribe to the user event channels (`{"sub":"events"|"custody"}`). Surface the WS URL + how to auth the socket.
  - **FIX** session creds — SenderCompID / TargetCompID, FIX username/password (logon `553/554`), the `me-fix-gateway` host:port, supported MsgTypes (order-entry + the CU-series custody msgs), and a downloadable session config. Show the gateway's running/not-running status (it's a separate process, not yet on prod).
  - **Binary** creds — the `me_wire` binary listener endpoint (`TLC_ME_OE_LISTEN`), the API-key/secret + HMAC scheme for the binary session, and the `CU_OP_*`/order-entry op catalog.
  - **Cross-cutting:** per-credential **scopes** (trading / custody / market-data / read-only), **per-protocol enable toggles**, IP allowlist, expiry/rotation, last-used, and **revoke** — one key that can be entitled across REST/WS/FIX/binary or issued per-protocol. Secrets shown **once** on create (never re-fetchable), HMAC/FIX passwords never round-tripped to the client after issue.
  - **Backend needed:** an API-key issuance/scope model that spans the 4 channels (extend the existing key store with `protocols[]` + FIX/binary identity fields), a FIX credential provisioning path on `me-fix-gateway`, and a binary-session credential path on the `me_wire` listener. **Frontend buildable now, degrade-on-404** (mirror the token/bailout pattern) — the management UI + typed clients ship first; each protocol's cred section lights up as its issuance endpoint lands. *Not started — backlog only.*
- ✅ **Custody↔trading bridge + USD/USDC spot** — `/me/wallet/{fund,settle}-{spot,margin}` deployed to prod; `pay_with` supports USD (fiat wallet) and USDC (spot). **Enabled end-to-end**: the remote ME was rebuilt from proto-v2 → **v7** (`.141`/exchange-beta), so the exchange's spot forwarding now works (verified: `GET /me/spot_balance` = 200, net-zero USD/USDC round-trip on the ME).
- ◐ **Real-time balance/position push** (P2) — partially addressed by the user WS events channel; a dedicated balance/position delta stream is still open.

### ✅ 2026-08-20 (pm) — BACKEND BACKLOG CLEARED + DEPLOYED
All P0/P1/P2 backend items below are now **built, tested, merged to `testlogon-cpp` main, and deployed to the prod exchange** (`i-08f937fc705ebea75`, us-east-2) — verified end-to-end. Remaining open work is the newest items (picker class-discriminator/PM-list/funding-rate, `/md/history` OHLCV, `/me/tokens/*` epic), server-side prefs (needs a new table), and the frontend UI wiring.
- ✅ **Real `GET /me/orders/live`** — order-recovery, mapped to `{side,leaves_qty,count}` (MR !39).
- ✅ **Real `GET /me/prices`** — live mark oracle (book-mid → per-coin reference fallback); shares one rate source with the FX quote (MR !38).
- ✅ **Discovery reads** `GET /me/stake_requests` + `/me/auctions` — new engine `open_stake_requests()`/`open_auctions()` + additive wire ops 25/26 (no proto bump), vault-safe (MR !40). **Remote ME `.141` rebuilt to serve the new ops.**
- ✅ **Per-sub-account balances** — `/me/custody/subaccounts` entries now carry `balances` (MR !41).
- ✅ **`POST /me/staking/positions/{id}/{action}`** (unstake) + the whole `/me/staking/*` proxy base ported into main, with vault-filter + ownership + action-whitelist guards (MR !44).
- ✅ **Paginated trade history** `GET /me/fills/history` — durable DDB archive (`tlc_fills`, on-demand create) + cursor pagination; archiver loop + archive-on-read (MR !45).
- ✅ **Margin-config READ** `GET /me/margin_config/{symbolid}` — additive wire op 27 (MR !41).
- ✅ **Server push for trading events + real-time balance/position push** — `ws_user_events_loop` (`{sub:events}`) + `ws_portfolio_loop` (`{sub:portfolio}`) on the user WS; custody events on `{sub:custody}`. **WS ACTIVATED + SECURED on prod** (`WS_TOKEN_SECRET` rotated off the dev default; `wss://tl-api.bitbazaar.cc/ws` h1 tunnel already worked — earlier "404" was curl h2; mint via `GET /ui/ws_token`).
- ✅ **`GET /md/indicators/{symbol}`** — was already registered in main; deployed/live.
- ✅ **24h ticker** `GET /md/ticker/{symbol}` — 24h OHLCV+change aggregated from the durable candle store (MR !43).
- ✅ **Pay any fee with any coin (on-the-fly FX)** — quote (`POST /me/fees/quote`) with per-coin liquidity/variance conversion fee + 60s HMAC rate-lock; generalized `pay_with` on tips+checkout (MR !37). Deployed + FEE_QUOTE_SECRET set. USDC exact; volatile coins use the reference fallback until real books seed.
- ✅ **Remote-ME v7 rebuild + USD/USDC spot bridge enabled** (the `.141` proto-v2→v7 fix that unblocked all remote `/me/*`).
- ⏸️ **Deferred:** server-side prefs (new DDB table), P1d deep-history-beyond-window edge case (API-only traders archive when they next hold a WS conn), `/md/history` OHLCV + `/me/tokens/*` (see the contract spec below), the P2 picker class/PM-list/funding-rate reads, and the fees/payments follow-ons (tiering, fiat on-ramp, FX revenue accounting).

### Fees & Payments (NEW epic — the biggest new area)
- [x] **Pay any fee with any coin (on-the-fly FX)** *(✅ DONE + deployed this session — MR !37)* — a user pays any platform fee/price with any coin they hold; it's converted to the fee currency (USD cents) at the current rate plus a conversion fee, **with the rate shown before they confirm**. Two parts: (a) a **quote** endpoint returning `{rate, coin_amount, conversion_fee_bps, conversion_fee_coin, total_coin, expires_at}`; (b) a **generalized pay path** extending the current `pay_with` (USD/USDC-only) branch to any spot asset (debit the coin's spot balance by converted amount + conversion fee, settle the fee). **Rate is locked for 60s** via a signed quote token the pay path validates.
- [ ] **Per-coin conversion-fee model** — the conversion fee `X%` is set **per coin from its liquidity + variance vs USD** (USDC ≈ floor; volatile/thin coins higher). Needs two live signals: **realized volatility** (rolling window of engine marks, stddev of returns) and **liquidity** (order-book depth near mid and/or bid–ask spread). `fee_bps = clamp(base + k_var·vol + k_liq·illiquidity, min, max)`, env-configurable + admin override per coin.
- [ ] **Real price/mark oracle (`me_marks`)** — **PROMOTED from "nice-to-have" to a hard dependency.** Pay-any-coin needs asset→USD marks; this also makes `GET /me/prices` real (drop the indicative stub, `aa08415`) and gives Portfolio a settled-USD equity. Read current per-symbol/per-asset marks from the (remote) engine.
- [ ] **FX / conversion-fee revenue accounting** — where the conversion-fee spread accrues (a platform-revenue vault/account), plus a report/feed of conversions (coin, rate, fee, USD-equivalent) for reconciliation.
- [ ] **Trading fee model** — maker/taker split, VIP/volume-tier fee schedule, liquidation fees, and small-deposit + network-withdrawal fees. (The engine already charges a real per-fill fee; this is the schedule/tiering layer on top.)
- [ ] **Fiat USD on-ramp** — Stripe / CCBill / PayPal → credit the custody/trading USD balance (usable for trading, margin, and fees). Complements the coin-pay path above with a fiat entry point.

### Prediction markets — wire/REST/boot layer
- [ ] **Expose prediction markets to clients** — the engine core is built + tested (`instrument_type_e::binary`, categorical groups; `ME_OP_PM_*` wire ops exist). Still need the REST/edge + client surface for market **create/resolve/state** and a trader **PM order path** (beyond the admin banner already shipped).

### Infra note (resolved this session)
- ✅ **Remote-ME version drift** — the prod exchange forwards `/me/*` to a remote ME (`TLC_ME_ENDPOINT`) that had drifted to proto-v2 and was being refused at handshake (all forwarded ops returned "unreachable"). Rebuilt to proto-v7. Worth a **standing check that the remote ME and the exchange are built from the same commit** on every exchange deploy (a version/ABI mismatch silently disables all remote `/me/*`).

---

# Backend contract spec — `/md/history` + `/me/tokens/*` (written 2026-08-20)

Implementation spec for the two frontend programs shipped this session (PR #227 historical analysis, PR #228 creator tokens). **This defines exactly what the shipped web + Android clients already call** — implement to these shapes and the UIs light up with zero client changes. Until then every read 404-degrades to an honest empty state and every mutation surfaces a clear error (the clients never fake success).

## Conventions (apply to every route below)
- **Auth:** same as the rest of `/me/*` — bearer JWT → `sub`. Token-issuer-only actions are enforced server-side (do **not** trust a client `creator_sub`). Gateway calls remain server-to-server HMAC; the HMAC secret never reaches the client.
- **Units:** all money amounts are **integer USD cents** (`100` = $1.00). `*_bps` = **basis points** (`10000` = 100%). Token quantities are integer base units. Timestamps `*_ts` are epoch ms unless suffixed `_ns`.
- **Idempotency:** every mutation accepts an `Idempotency-Key` header (mint, list, bid, clear, claim, pay). Re-use returns the original result, never double-charges. Reuse the payouts/ledger idempotency pattern.
- **Error envelope:** non-2xx returns `{error:{code,message}}`. Use `404` only for "not implemented / no such token" (the client's degrade trigger); use `409`/`422` for real conflicts (e.g. bid below reserve, insufficient balance) so the client shows the message instead of an empty state.
- **Money-safety:** the $100 creation fee and every upkeep/claim charge go through the **one-true-ledger** with a receipt; reuse the dispute/reversal rails so any charge is reversible.

---

## A. `GET /md/history/{symbolId}` — paginated long-range OHLCV (historical analysis)
The analysis workbench's only blocker. `/md/candles` is a recent window; this is the durable store.
- **Query:** `interval` (e.g. `1m,5m,1h,1d`), `from` (epoch ms, inclusive), `to` (epoch ms, exclusive), `cursor` (opaque, from a prior page). `from/to` optional (default: earliest→now, server-capped page).
- **Response:** `{ symbol_id:int, interval:str, bars:[{ ts:int_ms, o:num, h:num, l:num, c:num, v:num }], next_cursor:str|null, stub?:bool }`. Bars ascending by `ts`. Prices in the symbol's price scale (the client already handles `price_scaler`). Omit or `false` the `stub` flag when real; the client shows the "recent window only" banner whenever the payload is missing/`stub:true`.
- **Backend work:** a bars store (roll up engine trades into OHLCV per interval, or persist the candle feed). Cursor = last-`ts`+interval, opaque. A historical **trades** feed (`GET /md/trades/history/{symbolId}?...`) is a nice follow-on for tick-level replay but is **not** required for the shipped UI.

---

## B. Token data model (storage)
Three new stores (DDB tables or engine-side, your call). All keyed by an opaque `token_id`.
- **`token`** — `{ token_id (PK), symbol_id (null until listed), creator_sub, name, ticker, total_supply, revenue_share_bps, status ∈ {draft,minted,listed,frozen,delisted}, created_ts, offered_pct_bps?, clearing_price?, listed_ts? }`. `ticker` unique (reject dup on mint).
- **`token_holding`** — cap table: `{ token_id (PK), sub (SK), qty }`. `pct_bps` is derived (`qty*10000/total_supply`). On mint, one row `{creator_sub, total_supply}`. Every auction fill / secondary-book fill mutates these rows atomically with the trade.
- **`token_ledger`** — per-token event log for revenue distributions + upkeep: `{ token_id (PK), event_ts (SK), kind ∈ {distribution,upkeep_charge,upkeep_payment,creation_fee,auction_proceeds}, amount_cents, per_token_cents?, source?, sub? }`. Drives the Revenue + Upkeep reads.

---

## C. Engine primitives (the hard part — no edge-only workaround)
The edge only forwards `/me/*`; these need the **remote matching engine**:
1. **`create_token` / `list_symbol(token_id, symbol_meta) → symbol_id`** — mint a new tradeable symbol and stand up its continuous book (mirror the prediction-market `instrument_type` create path). Returns the `symbol_id` written back onto the `token` row. Until this exists nothing lists.
2. **Cap-table settlement on fills** — when the token's book (auction or continuous) fills, the engine must move `token_holding.qty` between buyer/seller atomically with cash settlement (buyer's USD/USDC → seller/issuer). This is what makes the token a real holding, not a scoreboard.
3. **Single-clearing-price batch auction** (see §G) — the existing peer `auction_request`/`auction_bid` is per-item; the IPO needs a sealed-bid batch that computes one clearing price and fills all winners at it.

---

## D. REST surface — `/me/tokens/*` (edge handlers → engine/stores)
Exact I/O the clients call. `Token` and `TokenAuction` shapes are reused throughout:
```
Token        = { token_id, symbol_id?, creator_sub, name, ticker, total_supply,
                 revenue_share_bps, status, created_ts, offered_pct_bps?, clearing_price? }
TokenAuction = { auction_id, token_id, offered_pct_bps, reserve_price, status ∈ {open,cleared,cancelled},
                 clearing_price?, filled_qty?, close_ts, bids?: [{ sub, qty, limit_price }] }
```

| Method & path | Body | Returns | Notes / validation |
|---|---|---|---|
| `POST /me/tokens` | `{name,ticker,total_supply,revenue_share_bps}` | `Token` | **Charge the $100 creation fee** (10000¢) through the ledger BEFORE mint; reject `402` on insufficient funds. `revenue_share_bps ≤ 10000`. Unique `ticker`. Creates `token` (`status:minted`) + one `token_holding` (creator = `total_supply`). Idempotent. |
| `GET /me/tokens` | — | `{tokens:[Token]}` | Tokens where `creator_sub == caller` (issuer view). |
| `GET /me/tokens/market` | — | `{tokens:[Token]}` | All `status ∈ {listed,frozen}` tokens (browse). Include `clearing_price`/last for display. |
| `GET /me/tokens/{id}` | — | `Token` | `404` if unknown. |
| `GET /me/tokens/{id}/captable` | — | `{token_id, creator_pct_bps, holders:[{sub,qty,pct_bps}]}` | Derived from `token_holding`. `creator_pct_bps` = creator's current holding. |
| `POST /me/tokens/{id}/list` | `{offered_pct_bps,reserve_price,close_ts}` | `TokenAuction` | **Issuer-only.** `offered_pct_bps ≤` creator holding. Opens a batch auction (`status:open`); sets `token.offered_pct_bps`. `409` if already listed/auction open. |
| `GET /me/tokens/{id}/auction` | — | `TokenAuction` | Current/most-recent auction. `bids` visible per your disclosure policy (at minimum the caller's own + aggregate depth). |
| `POST /me/tokens/{id}/auction/bid` | `{qty,limit_price}` | `{ok:true,...}` ack | **Not** the issuer. Escrow `qty*limit_price` from the bidder's USD/USDC (reserve, don't settle). `422` below `reserve_price`; `402` on insufficient funds. Idempotent per key. |
| `POST /me/tokens/{id}/auction/clear` | — | `TokenAuction` (`status:cleared`) | **Issuer-or-admin**, or auto at `close_ts`. Runs §G clearing: sets `clearing_price`+`filled_qty`, settles fills (cap-table moves + cash), refunds losing/over-escrow, `token.status→listed`, stands up the continuous book. |
| `GET /me/tokens/{id}/revenue` | — | `{token_id,my_qty,my_pct_bps,my_claimable,distributions:[{ts,total_amount,per_token_amount,source}]}` | `my_claimable` = caller's unclaimed accrued distributions (§E). `distributions` = token-level history. |
| `POST /me/tokens/{id}/revenue/claim` | — | `{ok:true,claimed_cents}` ack | Pay caller's `my_claimable` from the token's distribution escrow to their wallet; zero the accrual. Idempotent. |
| `GET /me/tokens/{id}/upkeep` | — | `{token_id,month,fees_generated,threshold,amount_due,my_share,status}` | `threshold=10000`. `amount_due = max(0, threshold − fees_generated)` (**shortfall model** — see §F; flip to flat by returning `threshold` when `fees<threshold`). `my_share` = caller's pro-rata slice by holding. `status ∈ {covered,due,paid,delinquent,frozen}`. |
| `POST /me/tokens/{id}/upkeep/pay` | — | `{ok:true,paid_cents}` ack | Charge caller's `my_share` via the ledger; mark their portion paid. When all holders' shares are paid → clear any freeze. Idempotent. |

---

## E. Revenue routing seam (real revenue-share claim)
The token entitles holders to a % of the creator's ongoing content revenue.
- **Trigger:** wherever the creator's content revenue already lands in the one-true-ledger (ecommerce sale, subscription cycle, tip), if that creator has a minted token, **skim `revenue_share_bps`** of the net into that token's **distribution escrow** and append a `token_ledger{kind:distribution, amount_cents, per_token_cents = amount/total_supply, source}` row.
- **Accrual:** holders accrue **pro-rata by holding at distribution time** (snapshot `token_holding`, or a dividend-per-share accumulator so late buyers don't claim past distributions). `my_claimable` = Σ over distributions of `per_token_cents * caller_qty_at_that_time` − already-claimed.
- **Claim** pays out of the escrow (§D claim). This is the biggest new accounting seam; reuse payouts for the wallet credit.

## F. Book-upkeep billing job (monthly)
- **Runner** (reuse the subscriptions **dunning** scheduler): for each `listed` token, at month close compute `fees_generated` = sum of this token's book **trading fees** for the month. `amount_due = max(0, 10000 − fees_generated)` (**shortfall top-up** — the locked decision; a one-value change makes it flat-$100).
- **Charge holders pro-rata:** each holder owes `round(amount_due * holder_qty / total_supply)`. Post `token_ledger{kind:upkeep_charge}`; dun per holder.
- **Non-payment → freeze:** if the collective shortfall isn't covered by the grace deadline, set `token.status:frozen` and **halt the book** (reject new orders, keep positions). Freeze is **reversible**: once `upkeep/pay` covers the shares, `status→listed` and the book reopens. (Delist is a heavier alternative we deliberately did not pick.)

## G. Single-clearing-price IPO auction (clearing algorithm)
Sealed-bid, one price:
1. Collect open bids `{sub,qty,limit_price}`; total offered `Q = total_supply * offered_pct_bps / 10000`.
2. Sort bids by `limit_price` desc. Walk down accumulating `qty`; the **clearing price** `P` = the price at which cumulative demand first ≥ `Q` (uniform-price). If total demand < `Q`, clear at `reserve_price` for the demanded qty (partial listing) — or cancel if below reserve, your policy.
3. **All winning bids fill at `P`** (not their bid). Pro-rate the marginal price level if it straddles `Q`. Refund `qty*(limit_price − P)` over-escrow to winners; refund losers fully.
4. Settle: move `Q` (or demanded) from creator's holding to winners in `token_holding`; credit proceeds `filled_qty*P` to the creator (minus any platform listing fee); set `clearing_price=P`, `filled_qty`, `status:cleared`; open the continuous book seeded around `P`.

## H. Money/ledger integration points (summary)
- **Creation fee** $100 → platform-revenue account, on mint (§D `POST /me/tokens`).
- **Auction proceeds** → creator, on clear (§G4), reversible.
- **Distributions** → token distribution escrow → holders on claim (§E).
- **Upkeep** → platform (book-maintenance account), charged to holders (§F).
- All through the one-true-ledger with receipts + the existing reversal/dispute rails.

## I. Suggested implementation order
1. `GET /md/history` — unblocks the whole analysis workbench cheaply (no engine changes if you persist candles).
2. `POST /me/tokens` + `GET /me/tokens[/market|/{id}|/captable]` + the $100 fee — mint & cap table become real (no book yet).
3. Engine `create_token`/`list_symbol` + §G batch auction + `list`/`auction/*` — listing goes live.
4. §E revenue routing + revenue read/claim — the actual revenue-share claim.
5. §F monthly upkeep job + upkeep read/pay + freeze — the sustainability loop.

Once symbols mint with an `instrument_class`, they also drop into the **class-filtered picker** (add a `creator_token` class) and trade through the existing ticket/book/blotter with no new client work.

---

# Backend contract spec — margin distress / pre-emptive bailout auctions (written 2026-08-21)

Implementation spec for the pre-emptive **bailout auction** frontend (PR #229, shipped 2026-08-21). A leveraged margin position **approaching** a margin call can raise rescue capital and avoid forced liquidation. **Pre-emptive by design:** the auction exists ONLY while the position is in a distress band AND still solvent (`equity > maintenance`); once `equity ≤ maintenance` it is impossible and normal liquidation takes over. Same conventions as the token spec (integer cents, `_bps`, `Idempotency-Key`, `404`=not-implemented degrade trigger, ledger money-safety, server enforces owner/eligibility).

## Locked decisions (frontend built to these)
1. **Distress trigger = volatility-scaled distance-to-liquidation.** `buffer_bps = |mark − liq_price|/mark`; `danger_bps = clamp(k × volatility_bps, floor, ceil)` where `volatility_bps` is the symbol's realized vol (reuse the rolling-stddev-of-marks signal specced for the per-coin conversion-fee model). **In band** when `buffer_bps ≤ danger_bps`. More volatile → wider band → enters distress sooner. `k`, `floor`, `ceil` env-configurable + admin-overridable per symbol.
2. **Rescue instrument = position-share.** Rescuers inject capital and receive a pro-rata **share of the position** (co-own its future uPnL + margin obligation), sized by capital injected vs the position's equity. It's an equity raise on the position.
3. **Sealed single-clearing-price auction.** Bidders submit `{capital, share_bps}`; clear at the **least total share given up** that raises enough capital to lift margin back above a safe threshold. Reuse the token §G uniform-clearing algorithm (target = `capital_needed` instead of a fixed offered qty).
4. **Auto-open is opt-in per account.** If the trader enabled `auto_bailout`, band-entry auto-opens an auction with their `default_max_share_bps`; otherwise they get a strong distress prompt + a manual "Open bailout auction" button.
5. **Breach → liquidation.** If `equity` hits `maintenance` mid-auction, auto-cancel (release rescuer escrow) and hand off to the normal liquidation path. A bailout can never rescue an already-underwater position.

## Engine / risk primitives needed
- **Distress read** — per open margin position, compute `mark, liq_price, equity, maintenance, buffer_bps, volatility_bps, danger_bps, in_band, eligible`. `eligible = in_band && equity > maintenance`. This is the one genuinely new risk-engine read.
- **Position co-ownership** — the position ledger must support **multiple owners with fractional shares** (share_bps summing to 10000), splitting uPnL and margin-call responsibility pro-rata. Rescue = mint new shares to rescuers, diluting the original owner; their capital is added to the position's margin.
- **Auction clearing tied to margin restoration** — clearing must raise ≥ `capital_needed` (the capital that lifts the margin ratio above the safe threshold at current mark) at the least dilution; settle by crediting the position margin + writing rescuer shares.
- **Auto-trigger hook** — on the risk engine's band-entry event, if `auto_bailout` is set, open the auction; on maintenance breach, cancel + liquidate.

## REST surface — edge handlers (degrade-on-404)
```
DistressPosition = { symbol_id, symbol, side, qty, entry_price, mark_price, liq_price,
                     equity_cents, maintenance_cents, buffer_bps, volatility_bps, danger_bps,
                     in_band, eligible, auction_id? }
BailoutAuction   = { auction_id, symbol_id, owner_sub, side, qty, capital_needed_cents,
                     max_share_bps, status ∈ {open,cleared,cancelled,liquidated},
                     clearing_share_bps?, raised_cents?, rescuers?:[{sub,capital_cents,share_bps}],
                     liq_price, mark_price, close_ts }
```
| Method & path | Body | Returns | Notes |
|---|---|---|---|
| `GET /me/margin/distress` | — | `{positions:[DistressPosition]}` | Caller's positions with band/eligibility computed server-side. The client renders only this — it never fabricates a distress signal. |
| `GET /me/bailouts` | — | `{auctions:[BailoutAuction]}` | Open bailout auctions = the rescuer opportunity board (sibling to `/me/liquidations`). |
| `GET /me/positions/{symbolId}/bailout` | — | `BailoutAuction` | Current auction for the caller's position; `404` when none. |
| `POST /me/positions/{symbolId}/bailout` | `{max_share_bps,close_ts?}` | `BailoutAuction` | **Owner-only.** `422` if the position isn't `eligible` (not in band, or already underwater). Sets `capital_needed_cents` from the current margin gap. Idempotent. |
| `POST /me/bailouts/{auctionId}/bid` | `{capital_cents,share_bps}` | ack | Rescuer (not the owner). **Escrow** `capital_cents`. `422` on absurd share; `402` on insufficient funds. Idempotent. |
| `POST /me/bailouts/{auctionId}/clear` | — | `BailoutAuction` (`cleared`) | Owner/admin, or auto at `close_ts`/threshold-restored. Runs the clearing: set `clearing_share_bps`+`raised_cents`, credit position margin, write rescuer shares (dilute owner), refund over-escrow + losers. |
| `GET /me/prefs/bailout` | — | `{auto_enabled, default_max_share_bps}` | Account setting. |
| `PUT /me/prefs/bailout` | `{auto_enabled, default_max_share_bps}` | ack | Persist the opt-in + default terms (fold into `/me/prefs` if that lands). |

## Money/ledger + lifecycle
- **Bid** escrows capital (reserve, not settled). **Clear** moves escrow → position margin, mints rescuer shares, refunds the rest — all through the ledger with receipts, reversible.
- **Auto-cancel on breach** releases all escrow and emits a liquidation as usual.
- **Post-rescue**, the position has multiple owners; PnL close/settle distributes by `share_bps`. Surface the co-ownership + the original owner's dilution (the client already renders the cap-table-style diff).
- **Suggested order:** (1) `GET /me/margin/distress` read (unblocks the whole health-meter + banner UI); (2) position co-ownership in the position ledger; (3) auction open/bid/clear + the §G clearing; (4) auto-trigger hook + `/me/prefs/bailout`.

---

# Backend contract spec — multi-protocol trading/custody credentials in the API-key UI (written 2026-08-21)

Implementation spec for the credential-management frontend (PR #230, shipped 2026-08-21). **Extends** the existing `/ui/api_keys` surface (API-key-parity program, PR #118) so one key can be entitled across **REST / WS / FIX / binary** channels of the unified gateway. Same conventions (auth→`sub`, `Idempotency-Key` on rotate/create, `404`=not-implemented degrade trigger, server-enforced ownership). **Secrets are shown exactly once** (at create or rotate) and never re-fetchable — persist only a hash server-side.

## New capability scopes (add to `app/services/api_key_capabilities.py`)
- **Trading:** `trading:read, trading:orders, trading:cancel, trading:positions, trading:funding`
- **Custody:** `custody:read, custody:deposit, custody:withdraw, custody:transfer`
- **Market Data:** `marketdata:read, marketdata:stream`
The existing fail-closed scope enforcement applies unchanged; the trading/custody routes must gate on these scopes (a content-only key must NOT reach `/me/orders` etc.).

## Key model extension
`api_key` rows gain: `protocols text[]` (subset of `rest|ws|fix|binary` the key is entitled to) + per-protocol identity/secret-hash fields:
- **ws:** `ws_token_hash` (the token used to auth the user WS `{"sub":"events"|"custody"}` subscription).
- **fix:** `fix_sender_comp_id`, `fix_target_comp_id`, `fix_username`, `fix_password_hash`.
- **binary:** `binary_key_id`, `binary_secret_hash`, `binary_hmac_scheme` (e.g. `HMAC-SHA256`).

## REST surface (edge/app handlers — all degrade-on-404)
| Method & path | Body | Returns | Notes |
|---|---|---|---|
| `POST /ui/api_keys` **(extended)** | existing + `protocols?:[rest\|ws\|fix\|binary]` | `ApiKeyCreated` + optional `protocol_credentials:{ ws?:{ws_token}, fix?:{username,password}, binary?:{api_key,secret} }` | On create, provision each requested protocol's identity and return its one-time secret(s) in `protocol_credentials`. Reject `422` if a protocol is requested without the scope it requires (FIX/binary need ≥1 trading/custody scope; WS needs ≥1 trading/custody/marketdata). |
| `GET /me/gateway/endpoints` | — | `{ ws:{url,enabled}, fix:{host,port,running}, binary:{endpoint,enabled} }` | Connection info + live availability, so the UI can hint "FIX gateway not running" and render connect instructions before a key exists. |
| `GET /ui/api_keys/{id}/protocols` | — | `{ rest?:{base_url,scopes[]}, ws?:{url,subs[],token_set:bool}, fix?:{sender_comp_id,target_comp_id,host,port,username,msg_types[],status}, binary?:{endpoint,hmac_scheme,ops[],key_set:bool} }` | Per-protocol **metadata only — never secrets**. `token_set`/`key_set` say whether a secret has been issued. `status` = the FIX session/gateway state. |
| `POST /ui/api_keys/{id}/protocols/{protocol}/rotate` | — | `{ protocol, secret }` | Owner-only. Re-issue that protocol's secret (WS token / FIX password / binary secret), invalidate the prior one, return the new value **once**. Idempotent per key. |

## Provisioning paths (the real backend work)
- **WS token** — issue a signed token (`WS_TOKEN_SECRET`) bound to `sub`+scopes so the user WS accepts the `{"sub":"events"|"custody"}` subscription; rotate invalidates the old token.
- **FIX** — register the SenderCompID/TargetCompID + logon password on `me-fix-gateway` (the separate process — reflect its running/not-running in `/me/gateway/endpoints.fix.running`); logon (35=A, 553/554) validates against the stored hash; scope-gate the CU-series custody MsgTypes.
- **Binary** — register the `binary_key_id`/secret for the `me_wire` listener (`TLC_ME_OE_LISTEN`); the session HMAC-signs with the scheme in `binary_hmac_scheme`; scope-gate `CU_OP_*` + order-entry ops.
- **Suggested order:** (1) scopes + `protocols[]` on the key model + `GET /me/gateway/endpoints` (unblocks the whole create UI); (2) WS token issue/rotate (reuses `WS_TOKEN_SECRET`, already in the codebase); (3) FIX credential provisioning; (4) binary-session credential provisioning.
