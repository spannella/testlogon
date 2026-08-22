/**
 * Activity Center — pure, framework-free normalization + aggregation of the
 * account-level `/me/*` trader feeds into a single durable, day-grouped
 * timeline. This is the history-view counterpart to the transient
 * `useTradingAlerts` bell (same source feeds; different lifetime).
 *
 * Everything here is deterministic and side-effect free so it is trivially
 * unit-testable. Monetary values are carried as INTEGER CENTS (`amountCents`)
 * — never floats — matching the ledger convention elsewhere in the app.
 *
 * Timestamps (`ts`) are normalized to epoch MILLISECONDS. Feed rows may carry
 * seconds OR ms; `toMs` detects and normalizes (parity with useTradingAlerts).
 */

export type ActivityCategory =
  | "trade"
  | "funding"
  | "liquidation"
  | "risk"
  | "money"
  | "system";

export type ActivitySeverity = "info" | "success" | "warning" | "critical";

/** A normalized, source-agnostic account event. */
export interface ActivityEvent {
  /** Stable de-dupe id (source + event key). */
  id: string;
  /** Epoch MILLISECONDS. */
  ts: number;
  /** Fine-grained event kind (e.g. "fill", "funding", "liquidation"). */
  kind: string;
  category: ActivityCategory;
  title: string;
  subtitle?: string;
  /** Signed integer cents when the event carries a monetary amount. */
  amountCents?: number;
  /** In-app deep link to the most relevant surface. */
  href?: string;
  severity: ActivitySeverity;
}

// -- Time helpers -----------------------------------------------------

/** Feed timestamps may be seconds OR ms — normalize to ms. */
export function toMs(ts: number | undefined): number {
  if (ts == null || !Number.isFinite(ts)) return 0;
  return ts < 1e12 ? Math.floor(ts * 1000) : Math.floor(ts);
}

// -- Minimal structural feed shapes -----------------------------------
// Structural (not imported) so this lib stays framework/endpoint free and
// unit-testable in isolation. Fields mirror the `/me/*` feed rows.

export interface FillRow {
  symbolid?: number;
  price?: number;
  qty?: number;
  side?: string;
  fee?: number;
  ts?: number;
}

export interface FundingRow {
  symbolid?: number;
  funding_rate_bps?: number;
  payment?: number;
  received?: boolean;
  ts?: number;
}

export interface LiquidationRow {
  symbolid?: number;
  qty?: number;
  mark_price?: number;
  realized_pnl?: number;
  fee?: number;
  ts?: number;
}

/** Optional per-symbol context (display name + tick-to-cents scaler). */
export interface NormalizeContext {
  /** Map a symbol id to a display name. Defaults to `#<id>`. */
  symbolName?: (id: number | undefined) => string;
  /**
   * Divisor turning an int64 engine tick into whole currency units.
   * `amountCents` is then `Math.round(tick / scaler * 100)`. Defaults to 1
   * (i.e. one tick == one cent) which keeps values integer + stable.
   */
  scalerFor?: (id: number | undefined) => number;
}

function nameOf(ctx: NormalizeContext | undefined, id: number | undefined): string {
  if (ctx?.symbolName) return ctx.symbolName(id);
  return id != null ? `#${id}` : "?";
}

/** Convert an int64 engine tick to signed integer cents. */
export function tickToCents(
  tick: number | undefined,
  ctx: NormalizeContext | undefined,
  id: number | undefined,
): number | undefined {
  if (tick == null || !Number.isFinite(tick)) return undefined;
  const scaler = (ctx?.scalerFor && ctx.scalerFor(id)) || 1;
  return Math.round((tick / scaler) * 100);
}

// -- Normalizers ------------------------------------------------------

export function normalizeFills(
  rows: FillRow[] | undefined,
  ctx?: NormalizeContext,
): ActivityEvent[] {
  if (!rows) return [];
  return rows.map((r) => {
    const sym = nameOf(ctx, r.symbolid);
    const side = (r.side ?? "").toString().toUpperCase();
    const feeCents = tickToCents(r.fee, ctx, r.symbolid);
    return {
      id: `fill:${r.symbolid}:${r.ts}:${r.price}:${r.qty}:${r.side}`,
      ts: toMs(r.ts),
      kind: "fill",
      category: "trade",
      title: `Filled ${sym}`,
      subtitle:
        `${side} ${r.qty ?? "?"} @ ${r.price ?? "?"}` +
        (feeCents != null ? ` · fee ${(feeCents / 100).toFixed(2)}` : ""),
      href: r.symbolid != null ? `/markets/${r.symbolid}` : "/blotter",
      severity: "success",
    };
  });
}

export function normalizeFunding(
  rows: FundingRow[] | undefined,
  ctx?: NormalizeContext,
): ActivityEvent[] {
  if (!rows) return [];
  return rows.map((r) => {
    const sym = nameOf(ctx, r.symbolid);
    const received = !!r.received;
    const amountCents = tickToCents(r.payment, ctx, r.symbolid);
    const dir = received ? "received" : "paid";
    return {
      id: `funding:${r.symbolid}:${r.ts}:${r.payment}`,
      ts: toMs(r.ts),
      kind: "funding",
      category: "funding",
      title: `Funding ${dir}`,
      subtitle: `${sym} · ${r.funding_rate_bps ?? 0} bps`,
      amountCents,
      href: r.symbolid != null ? `/markets/${r.symbolid}` : "/portfolio",
      severity: received ? "success" : "info",
    };
  });
}

export function normalizeLiquidations(
  rows: LiquidationRow[] | undefined,
  ctx?: NormalizeContext,
): ActivityEvent[] {
  if (!rows) return [];
  return rows.map((r) => {
    const sym = nameOf(ctx, r.symbolid);
    const pnlCents = tickToCents(r.realized_pnl, ctx, r.symbolid);
    return {
      id: `liq:${r.symbolid}:${r.ts}:${r.qty}`,
      ts: toMs(r.ts),
      kind: "liquidation",
      category: "liquidation",
      title: `Liquidated ${sym}`,
      subtitle:
        `${r.qty ?? "?"} closed @ ${r.mark_price ?? "?"}` +
        (pnlCents != null ? ` · PnL ${(pnlCents / 100).toFixed(2)}` : ""),
      amountCents: pnlCents,
      href: "/portfolio/analytics",
      severity: "critical",
    };
  });
}

// -- Aggregation ------------------------------------------------------

/**
 * Merge any number of event lists into ONE list sorted newest-first, with a
 * stable de-dupe by `id` (delta-dedupe: the first occurrence of an id wins so
 * re-polled feeds never double-count). Ties on `ts` keep insertion order.
 */
export function mergeEvents(...lists: ActivityEvent[][]): ActivityEvent[] {
  const seen = new Set<string>();
  const out: ActivityEvent[] = [];
  for (const list of lists) {
    for (const ev of list) {
      if (!ev || seen.has(ev.id)) continue;
      seen.add(ev.id);
      out.push(ev);
    }
  }
  // Stable descending sort by ts (later ts first; equal ts keeps order).
  return out
    .map((ev, i) => ({ ev, i }))
    .sort((a, b) => (b.ev.ts - a.ev.ts) || (a.i - b.i))
    .map((x) => x.ev);
}

export interface ActivityDayGroup {
  /** ISO date key `YYYY-MM-DD` (local time). */
  day: string;
  events: ActivityEvent[];
}

/** Local `YYYY-MM-DD` for an epoch-ms timestamp. */
export function dayKey(ts: number): string {
  const d = new Date(ts);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

/**
 * Group an already-sorted (desc) event list into day buckets, preserving the
 * incoming order both across and within groups. Does NOT re-sort — pass the
 * output of `mergeEvents`.
 */
export function groupByDay(events: ActivityEvent[]): ActivityDayGroup[] {
  const groups: ActivityDayGroup[] = [];
  let current: ActivityDayGroup | null = null;
  for (const ev of events) {
    const key = dayKey(ev.ts);
    if (!current || current.day !== key) {
      current = { day: key, events: [] };
      groups.push(current);
    }
    current.events.push(ev);
  }
  return groups;
}

/** Filter by category; `"all"` (or undefined) is a pass-through. */
export function filterByCategory(
  events: ActivityEvent[],
  category: ActivityCategory | "all" | undefined,
): ActivityEvent[] {
  if (!category || category === "all") return events;
  return events.filter((e) => e.category === category);
}

/** True when the event is newer than the last-seen marker. */
export function isUnread(ev: ActivityEvent, lastSeenTs: number | undefined): boolean {
  if (lastSeenTs == null) return true;
  return ev.ts > lastSeenTs;
}

/** Count events newer than the last-seen marker. */
export function unreadCount(
  events: ActivityEvent[],
  lastSeenTs: number | undefined,
): number {
  let n = 0;
  for (const ev of events) if (isUnread(ev, lastSeenTs)) n++;
  return n;
}
