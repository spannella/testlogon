# Market-Data Experience — TradingView-parity backlog (MDX)

**Scope:** bring the native Android market-data charting (feature/markets) to TradingView-class
UX, plus the parallel web surface. This is the follow-on to the exchange market-data client
(SSE live feed + candlestick chart + L2 book + HyperLiquid dark theme) already shipped on
`android-impl` (`6817160a` retint, `8391eb17` windowing, `2b046a3e` candle-publish,
`dff56531` REST→HTTP/1.1).

**Prefix:** `MDX` (Market-Data Experience), distinct from the `AND-4xx` port tickets.
**Effort:** S ≈ ½ day · M ≈ 1–2 days · L ≈ 3–5 days.
**Status legend:** ☐ todo · ◐ in progress · ☑ done.

> Standing constraint (learned the hard way): the cpp HTTP/2 edge refuses concurrent streams
> (REFUSED_STREAM) and resets long-lived SSE. The entire exchange data plane (REST + SSE) must
> stay pinned to HTTP/1.1 on its own ConnectionPool. Any new market-data endpoint call inherits
> the `ExchangeApi` h1.1 client. Do NOT run the aggressive market-maker against prod cpp.

---

## Epic A — Timeframes & chart controls

- ☐ **MDX-101 · Timeframe switcher** — `M` · no deps
  Chip row (1m/5m/15m/1h/4h/1D) above the chart; selecting refetches
  `/md/candles?intervalSec=N` and re-aligns the SSE `marketData(symbolId, intervalSec)` stream.
  AC: switching interval reloads candle history for that interval; live SSE bar merges at the
  correct bucket; selection persists per-symbol in VM state; uses the h1.1 client (no REFUSED_STREAM).

- ☐ **MDX-102 · Chart-type toggle** — `M` · no deps
  Toggle candles / line / area (Heikin-Ashi stretch). Line/area derive from candle closes.
  AC: toggle re-renders without refetch; line/area use the mint `Accent`; state persists per session.

- ☐ **MDX-103 · Interval-aware axis labels** — `S` · dep MDX-101
  Time-axis tick format adapts to interval (HH:mm intraday, dd MMM for ≥1D); local tz/DST correct;
  no label overlap.

## Epic B — Indicators / studies

- ☐ **MDX-111 · SMA/EMA overlay** — `M` · no deps (highest value)
  Client-computed SMA & EMA (configurable periods, default 7/25/99) drawn as line overlays with a
  legend + per-MA toggle. AC: lines align to candle centers; recompute on pan/zoom window; correct
  at series edges (partial windows).

- ☐ **MDX-112 · Volume MA line** — `S` · dep MDX-111
  MA line over the volume histogram sub-pane.

- ☐ **MDX-113 · Oscillator sub-pane framework** — `L` · refactor of volume pane
  Generalize the volume sub-pane into a reusable stacked-pane host sharing the X-axis + crosshair,
  so oscillators stack below price. AC: N sub-panes stack with shared X scale + crosshair; volume
  migrated onto it.

- ☐ **MDX-114 · RSI** — `M` · dep MDX-113
- ☐ **MDX-115 · MACD** — `M` · dep MDX-113
- ☐ **MDX-116 · Bollinger Bands** — `M` · dep MDX-111 (price overlay, not sub-pane)
- ☐ **MDX-117 · VWAP** — `M` · dep MDX-111
  Each: standard formula, configurable params, crosshair legend readout.
  AC (each): matches TradingView within rounding on a spot-check symbol; toggle on/off; params editable.

## Epic C — Interaction polish

- ◐ **MDX-121 · Double-tap reset / auto-fit** — `S` · no deps (easy win)
  Double-tap resets `visibleCount` to default and re-fits Y to latest N candles.

- ☐ **MDX-122 · Independent Y-axis drag scale** — `M` · no deps
  Vertical drag on the price axis rescales Y; lock/auto toggle; auto re-engages on reset.

- ☐ **MDX-123 · Fling / momentum pan** — `S` · no deps
  Velocity-based inertial scroll on pan release; decelerates smoothly; clamps at data edges.

- ◐ **MDX-124 · On-device pan/zoom verification** — `S` · dep current chart
  `input swipe` + before/after screenshots (+ optional screen-cap) to confirm the window shifts and
  pinch changes visibleCount. AC: documented evidence pan + zoom work; no crash.

## Epic D — Drawing tools

- ☐ **MDX-131 · Drawing layer + persistence store** — `L` · foundation
  Overlay canvas + per-symbol persisted drawing model (local first). AC: drawings survive nav
  away/back and interval change (anchored to time/price, not pixels).

- ☐ **MDX-132 · Horizontal line / ray** — `M` · dep MDX-131
- ☐ **MDX-133 · Trendline** — `M` · dep MDX-131
- ☐ **MDX-134 · Fibonacci retracement** — `M` · dep MDX-131
- ☐ **MDX-135 · Rectangle / zone + text note** — `M` · dep MDX-131
  AC (each): drag to place/edit, long-press to delete, re-anchors correctly on zoom.

## Epic E — Depth & trades tape

- ☐ **MDX-141 · Recent-trades tape** — `M` · partial (pollTrades exists)
  Surface polled trades as a scrolling list: price (up/down color by aggressor side), size, time;
  capped ring buffer; updates live.

- ☐ **MDX-142 · Book/tape/chart layout modes** — `M` · dep MDX-141
  Tab or split layout to switch chart ↔ order book ↔ trades on mobile; state preserved.

- ☐ **MDX-143 · Depth-chart crosshair readout** — `S` · dep existing depth curve
  Hover shows cumulative size + price at level.

## Epic F — Symbols, watchlists, alerts

- ☐ **MDX-151 · Symbol search / switcher** — `M` · partial (list from /md/symbols)
  Searchable symbol picker; quick-switch without leaving the chart; recent symbols; deep-link retained.

- ☐ **MDX-152 · Watchlist / favorites** — `M` · dep MDX-151
  Star symbols; persisted watchlist row with live last-price + %chg via SSE or poll.

- ☐ **MDX-153 · Price alerts** — `L` · needs backend seam
  Set a price threshold → notification on cross. Needs a backend alert-eval seam + push
  (FCM already wired app-side). AC: create/list/delete alert; fires once on cross; delivered via push.

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

**Batch 1 — "Feels like a real trading app"** (quick, high-signal; backend already supports)
MDX-124 → MDX-121 → MDX-101 → MDX-111 → MDX-141 → MDX-102. ~1 week.

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
