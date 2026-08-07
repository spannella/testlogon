# Market-Data Experience — TradingView-parity backlog (MDX)

**Scope:** bring the native Android market-data charting (feature/markets) to TradingView-class
UX, plus the parallel web surface. This is the follow-on to the exchange market-data client
(SSE live feed + candlestick chart + L2 book + HyperLiquid dark theme) already shipped on
`android-impl` (`6817160a` retint, `8391eb17` windowing, `2b046a3e` candle-publish,
`dff56531` REST→HTTP/1.1).

**Prefix:** `MDX` (Market-Data Experience), distinct from the `AND-4xx` port tickets.
**Effort:** S ≈ ½ day · M ≈ 1–2 days · L ≈ 3–5 days.
**Status legend:** ☐ todo · ◐ in progress · ☑ done.

> **Baseline already shipped** (verified in code 2026-08-07): candlestick render, volume sub-pane,
> horizontal pan, pinch-zoom, draggable crosshair + O/H/L/C tooltip card, dashed last-price line +
> tag, right price axis, bottom time axis, L2 order book + depth curve, HyperLiquid dark theme.
> Several backlog tickets below were found already-built and are marked ☑.

> Standing constraint (learned the hard way): the cpp HTTP/2 edge refuses concurrent streams
> (REFUSED_STREAM) and resets long-lived SSE. The entire exchange data plane (REST + SSE) must
> stay pinned to HTTP/1.1 on its own ConnectionPool. Any new market-data endpoint call inherits
> the `ExchangeApi` h1.1 client. Do NOT run the aggressive market-maker against prod cpp.

---

## Epic A — Timeframes & chart controls

- ☑ **MDX-101 · Timeframe switcher** — `M` · **already built** (Timeframe enum M1/M5/M15/H1/D1,
  `TimeframeBar` in SymbolDetailScreen, `setInterval()`/`refetchCandles()` in the VM re-fetch
  `/md/candles/{id}?interval=N` and restart the SSE stream at the new interval). Uses the h1.1 client.

- ☑ **MDX-102 · Chart-type toggle** — `M` · **done**
  Candles / Line / Area toggle (`ChartType` enum) in a `ChartTypeToggle` control beside the timeframe
  bar; line/area drawn over closes in the mint `Accent` (area = filled to baseline). State in the
  screen via `remember` (per-session). No refetch.

- ☑ **MDX-103 · Interval-aware axis labels** — `S` · dep MDX-101 · **this wave**
  Chart time-axis format now adapts to the selected timeframe (HH:mm intraday, `dd HH:mm` for ≥1h,
  `MMM d` for ≥1D); the `Timeframe` is threaded into `CandlestickCanvas`.

## Epic B — Indicators / studies

- ☑ **MDX-111 · MA overlay** — `M` · **this wave**
  Binance-style MA7 / MA25 / MA99 (simple, on close) computed over the full series (so the visible
  window's left edge uses prior bars) and drawn as line overlays; a top-left legend with tappable
  chips toggles each MA on/off. `sma()`/`ema()` helpers included (EMA available for future specs).
  AC met: lines align to candle centers; nulls skipped until enough samples; per-MA toggle.

- ☑ **MDX-112 · Volume MA line** — `S` · **done** — gold SMA(20) line over the volume histogram.

- ☑ **MDX-113 · Oscillator sub-pane** — `L` · **done** — the chart now reallocates vertical space
  (price 56% / volume 14% / oscillator 24%) and grows its canvas 260→340dp when an oscillator is
  active; shares the same window/X-scale as price. A mutually-exclusive `Oscillator` enum (None/RSI/
  MACD) is selected via an `OscillatorToggle` control (left of the chart-type toggle).

- ☑ **MDX-114 · RSI** — `M` · **done** — Wilder RSI(14) in the sub-pane with 30/70 dashed guides +
  live value label.
- ☑ **MDX-115 · MACD** — `M` · **done** — MACD(12,26,9): blue MACD line + orange signal + up/down
  histogram, symmetric zero-centered scale, zero line + label.
- ☑ **MDX-116 · Bollinger Bands** — `M` · **done** (price overlay: SMA20 ± 2σ upper/lower solid +
  mid dashed + faint fill; `stdDev()` helper; legend `BB` chip toggle, off by default).
- ☑ **MDX-117 · VWAP** — `M` · **done** (session-cumulative Σ(typical·vol)/Σvol; orange line; legend
  `VWAP` chip toggle, off by default).
  Note: RSI/MACD (sub-pane) remain — see MDX-113/114/115. Params fixed for now (20/2σ), not yet editable.

## Epic C — Interaction polish

- ☑ **MDX-121 · Double-tap reset / auto-fit** — `S` · **this wave**
  Double-tap resets `visibleCount` to default and `scrollOffset` to 0 (re-fits Y to latest N candles,
  since Y auto-scales to the visible window). Added as its own `detectTapGestures` pointerInput.

- ⊘ **MDX-122 · Independent Y-axis drag scale** — `M` · **DEFERRED** — on a phone the price-axis
  gutter is ~58px and overlaps the crosshair drag detector; implementing it means reworking the
  gesture arbitration between the verified pan/pinch/crosshair detectors for marginal value. Revisit
  only if users ask. Y auto-fits the visible window today (usually what's wanted).

- ⊘ **MDX-123 · Fling / momentum pan** — `S` · **DEFERRED** — needs a VelocityTracker + decay
  animation layered onto detectTransformGestures without disturbing pan/pinch/crosshair; nice-to-have,
  not worth the regression risk right now.

- ◐ **MDX-124 · On-device pan/zoom verification** — `S` · dep current chart
  `input swipe` + before/after screenshots (+ optional screen-cap) to confirm the window shifts and
  pinch changes visibleCount. AC: documented evidence pan + zoom work; no crash.

## Epic D — Drawing tools

- ☑ **MDX-131 · Drawing layer + persistence** — `L` · **done** — `Anchor(tsNs, price)` /
  `ChartDrawing(tool, a, b?)` model anchored to bar-timestamp + price (not pixels), so drawings stay
  put across pan/zoom. A `DrawingTool` enum + `DrawingToolbar` control; when a tool is active the
  chart swaps pan/zoom/crosshair for tap-to-place (1st tap buffers, 2nd commits), rendered by mapping
  ts→x / price→y each frame. Persisted per symbol in SharedPreferences (`chart_drawings/sym_<id>`,
  serialized) via the detail VM (`@ApplicationContext`); survives nav away/back + app restart. Clear-all
  button. (Individual-drawing delete + drag-to-edit deferred; clear-all covers the MVP.)

- ☑ **MDX-132 · Horizontal line** — `M` · **done** — 1-tap price line across the pane (cyan).
- ☑ **MDX-133 · Trendline** — `M` · **done** — 2-tap segment between (ts,price) anchors.
- ☑ **MDX-134 · Fibonacci retracement** — `M` · **done** — 2-tap; gold levels 0/.236/.382/.5/.618/.786/1
  with labels.
- ☑ **MDX-135 · Rectangle / zone** — `M` · **done** — 2-tap rect with faint fill + border. (Text-note
  annotation deferred.)

## Epic E — Depth & trades tape

- ☑ **MDX-141 · Recent-trades tape** — `M` · **already built** (SymbolDetailScreen "Recent Trades"
  section: `TradeRow` with aggressor up/down color + ^/v arrow, size, HH:mm:ss time; VM `pollTrades()`
  at 4s; take(40)). Refinement left: dedicated tab/split layout — see MDX-142.

- ☐ **MDX-142 · Book/tape/chart layout modes** — `M` · dep MDX-141
  Tab or split layout to switch chart ↔ order book ↔ trades on mobile; state preserved.

- ☐ **MDX-143 · Depth-chart crosshair readout** — `S` · dep existing depth curve
  Hover shows cumulative size + price at level.

## Epic F — Symbols, watchlists, alerts

- ☑ **MDX-151 · Symbol search** — `M` · **done** — themed search field on the Markets list
  (`MarketSearchField`, BasicTextField + search/clear icons) filters rows by symbol substring.
  (In-detail quick-switcher deferred — with 3 seeded symbols a one-tap back-to-list suffices.)

- ☑ **MDX-152 · Watchlist / favorites** — `M` · **done** — star per row (`Icons.Star/StarBorder`),
  persisted in SharedPreferences (`markets_prefs/favorites`), starred instruments float to the top of
  the list; live last-price/%chg already on each row via the existing quote poll.

- ⊘ **MDX-153 · Price alerts** — `L` · **DEFERRED (needs backend)** — requires a backend alert-eval
  seam (no `/md` alert endpoint today) + push wiring. App-side FCM exists; blocked on the exchange
  backend adding a threshold-cross evaluator. Revisit when the backend seam lands.

## Epic G — Nice-to-haves / lower priority

- ☐ **MDX-161 · Pre/post shading & session markers** — `S` — low value (crypto 24/7).
- ☐ **MDX-162 · Bid/ask axis markers** — `S`.
- ☐ **MDX-163 · Multi-chart / split layout** — `L` — likely out of scope for phone.

---

## Web parity (mirror)

The web market-data surface (`frontend/src/pages/markets/*`, `useMarketDataStream.ts`, hand-rolled
SVG `CandleChart`, commit `9e2db064`) mirrors the same gaps. Each Android MDX ticket has a web twin;
tracked here as `MDX-W<nnn>` and built in the same batch where cheap to share logic (indicator math,
interval params). Web-specific note: consider a mature charting lib (lightweight-charts) for the web
side rather than hand-rolling indicators/drawings.

---

## Sequencing (build batches) — committed scope: ALL (Batches 1–4)

**Batch 1 — "Feels like a real trading app"** — MOSTLY DONE.
MDX-101 ☑ (pre-existing) · MDX-141 ☑ (pre-existing) · MDX-121 ☑ · MDX-111 ☑ · MDX-103 ☑ ·
MDX-124 ◐ (on-device verify) · **MDX-102 ☐ (line/area chart type — next)**.

**Batch 2 — Indicators depth**
MDX-113 → MDX-114 / MDX-115 / MDX-116 / MDX-117 → MDX-112 → MDX-122 → MDX-123 → MDX-103.

**Batch 3 — Symbols & alerts**
MDX-151 → MDX-152 → MDX-153 (backend work) → MDX-142 → MDX-143.

**Batch 4 — Drawing tools** (largest)
MDX-131 → MDX-132 → MDX-133 → MDX-134 → MDX-135.

**Backlog / defer:** Epic G.

---

## Milestone 2 (out of this backlog): TRADING
Order entry/cancel via `/me/orders`, positions, balances — behind the `me_trade_enabled` gate.
Tracked separately once market-data UX lands.
