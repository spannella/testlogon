/**
 * Pure, framework-free helpers for the unified DISCOVER / INVEST HUB.
 *
 * The hub is a single front door over the several investable/tradeable product
 * surfaces that each already live in their own route (Markets, Creator Tokens,
 * Strategy Funds, Staking, and the peer/bailout/IPO "Opportunities"). This
 * module holds the cross-surface logic that must NOT touch React, the network,
 * or the DOM so it can be exhaustively unit-tested:
 *
 *   - a NORMALIZED {@link DiscoverItem} shape so every heterogeneous product
 *     row renders through one card component (kind / id / title / subtitle /
 *     metric / href);
 *   - a heterogeneous SEARCH match (a single query filters across market
 *     symbols, creator tokens, and strategy funds by name / ticker);
 *   - RANKING helpers (top movers by |change|, strategies by inception return
 *     or AUM, tokens, capacity-remaining fraction).
 *
 * CONVENTIONS (shared with the reused surfaces): monetary amounts are INTEGER
 * CENTS; `_bps` fields are BASIS POINTS (100% = 10_000). Nothing here fetches --
 * callers pass already-read data and render the result, degrading per-section
 * on a 404 upstream.
 */

import type { MarketSymbol } from "@/api/endpoints/marketData";
import type { Token } from "@/api/endpoints/tokens";
import type { Strategy } from "@/api/endpoints/strategies";

// -- Normalized item shape --------------------------------------------

/** Which product surface a {@link DiscoverItem} came from. */
export type DiscoverKind =
  | "market"
  | "token"
  | "strategy"
  | "staking"
  | "opportunity";

/**
 * A single, surface-agnostic row for the hub. Every section maps its native
 * records to this shape so one card component renders them all uniformly.
 */
export interface DiscoverItem {
  kind: DiscoverKind;
  /** Stable id within the kind (symbol id, token id, strategy id, ...). */
  id: string;
  title: string;
  subtitle?: string;
  /** Pre-formatted headline metric (price, NAV, APY, return, ...). */
  metric?: string;
  /** Signed change in bps when the metric trends (drives up/down colour). */
  changeBps?: number;
  /** Deep link into the existing route for this item. */
  href: string;
}

// -- Text search (heterogeneous) --------------------------------------

/** Lower-case + trim a query/term for case-insensitive substring matching. */
export function normalizeQuery(q: string | null | undefined): string {
  return (q ?? "").trim().toLowerCase();
}

/** True when every whitespace-separated token of `q` is a substring of some field. */
export function matchesText(q: string, ...fields: Array<string | null | undefined>): boolean {
  const query = normalizeQuery(q);
  if (!query) return true;
  const hay = fields
    .filter((f): f is string => typeof f === "string" && f.length > 0)
    .join(" ")
    .toLowerCase();
  if (!hay) return false;
  return query.split(/\s+/).every((tok) => hay.includes(tok));
}

/** Filter market symbols by symbol/ticker text. Empty query -> all. */
export function searchSymbols(symbols: MarketSymbol[], q: string): MarketSymbol[] {
  const query = normalizeQuery(q);
  if (!query) return symbols ?? [];
  return (symbols ?? []).filter((s) => matchesText(query, s.symbol));
}

/** Filter creator tokens by name/ticker text. Empty query -> all. */
export function searchTokens(tokens: Token[], q: string): Token[] {
  const query = normalizeQuery(q);
  if (!query) return tokens ?? [];
  return (tokens ?? []).filter((t) => matchesText(query, t.name, t.ticker));
}

/** Filter strategy funds by name/description text. Empty query -> all. */
export function searchStrategies(strategies: Strategy[], q: string): Strategy[] {
  const query = normalizeQuery(q);
  if (!query) return strategies ?? [];
  return (strategies ?? []).filter((s) => matchesText(query, s.name, s.description));
}

// -- Ranking helpers --------------------------------------------------

/** A symbol paired with its (client-computed) recent change, in bps. */
export interface SymbolChange {
  symbol: MarketSymbol;
  /** Signed change over the sampled window, in bps (10_000 = +100%). */
  changeBps: number;
}

/**
 * Top movers: sort by ABSOLUTE change (biggest movers first, either direction),
 * breaking ties by symbol name for a stable order. Non-finite changes sink to
 * the bottom. Returns a new array (does not mutate the input).
 */
export function topMovers(items: SymbolChange[], limit = Infinity): SymbolChange[] {
  const scored = (items ?? []).filter((i) => i && i.symbol);
  const sorted = scored.slice().sort((a, b) => {
    const aa = Number.isFinite(a.changeBps) ? Math.abs(a.changeBps) : -1;
    const bb = Number.isFinite(b.changeBps) ? Math.abs(b.changeBps) : -1;
    if (bb !== aa) return bb - aa;
    return a.symbol.symbol.localeCompare(b.symbol.symbol);
  });
  return Number.isFinite(limit) ? sorted.slice(0, Math.max(0, limit)) : sorted;
}

/** Change in bps between a first and last price (10_000 = +100%). NaN if undefined/zero base. */
export function changeBpsFromPrices(
  first: number | undefined | null,
  last: number | undefined | null,
): number {
  if (first == null || last == null || !Number.isFinite(first) || !Number.isFinite(last)) {
    return NaN;
  }
  if (first === 0) return NaN;
  return ((last - first) / first) * 10_000;
}

/**
 * Sort strategies by a chosen metric, descending (best first). Missing values
 * sink to the bottom. Returns a new array.
 */
export function sortStrategies(
  strategies: Strategy[],
  by: "inception" | "aum",
  limit = Infinity,
): Strategy[] {
  const key = (s: Strategy): number => {
    const v = by === "inception" ? s.inception_return_bps : s.aum_cents;
    return v != null && Number.isFinite(v) ? v : Number.NEGATIVE_INFINITY;
  };
  const sorted = (strategies ?? []).slice().sort((a, b) => {
    const d = key(b) - key(a);
    if (d !== 0) return d;
    return (a.name ?? "").localeCompare(b.name ?? "");
  });
  return Number.isFinite(limit) ? sorted.slice(0, Math.max(0, limit)) : sorted;
}

/**
 * Sort creator tokens (listed first, then by most recently created). Returns a
 * new array.
 */
export function sortTokens(tokens: Token[], limit = Infinity): Token[] {
  const rank = (t: Token): number => (t.status === "listed" ? 1 : 0);
  const sorted = (tokens ?? []).slice().sort((a, b) => {
    const r = rank(b) - rank(a);
    if (r !== 0) return r;
    const d = (b.created_ts ?? 0) - (a.created_ts ?? 0);
    if (d !== 0) return d;
    return (a.name ?? "").localeCompare(b.name ?? "");
  });
  return Number.isFinite(limit) ? sorted.slice(0, Math.max(0, limit)) : sorted;
}

/**
 * Fraction (0..1) of a strategy's AUM CAPACITY still AVAILABLE. Uncapped
 * (max <= 0) returns 1 (fully open). Clamped to [0, 1].
 */
export function capacityRemainingFraction(
  aumCents: number | undefined | null,
  maxAumCents: number | undefined | null,
): number {
  if (maxAumCents == null || !(maxAumCents > 0)) return 1;
  const aum = aumCents != null && aumCents > 0 ? aumCents : 0;
  const frac = 1 - aum / maxAumCents;
  if (!Number.isFinite(frac)) return 0;
  return Math.min(1, Math.max(0, frac));
}

// -- Mappers to the normalized DiscoverItem ---------------------------

/** Basis points -> a compact signed percent string, e.g. 250 -> "+2.5%". */
export function bpsToSignedPct(bps: number, maxFrac = 2): string {
  const pct = bps / 100;
  const sign = pct >= 0 ? "+" : "";
  return `${sign}${pct.toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: maxFrac,
  })}%`;
}

/** Integer cents -> "$1,234.56"; non-finite -> undefined. */
export function centsToUsd(cents: number | undefined | null): string | undefined {
  if (cents == null || !Number.isFinite(cents)) return undefined;
  return `$${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

/** Map a symbol + its recent change to a normalized market item. */
export function marketItem(sym: MarketSymbol, changeBps: number): DiscoverItem {
  const hasChange = Number.isFinite(changeBps);
  return {
    kind: "market",
    id: String(sym.symbol_id),
    title: sym.symbol,
    subtitle: sym.is_perpetual ? "Perpetual" : "Spot",
    metric: hasChange ? bpsToSignedPct(changeBps) : undefined,
    changeBps: hasChange ? changeBps : undefined,
    href: `/markets/${sym.symbol_id}`,
  };
}

/** Map a creator token to a normalized item. */
export function tokenItem(t: Token): DiscoverItem {
  return {
    kind: "token",
    id: t.token_id,
    title: t.ticker || t.name,
    subtitle: t.name,
    metric: t.clearing_price != null ? centsToUsd(t.clearing_price) : t.status,
    href: `/tokens/${encodeURIComponent(t.token_id)}`,
  };
}

/** Map a strategy fund to a normalized item (metric = since-inception return). */
export function strategyItem(s: Strategy): DiscoverItem {
  const hasReturn = s.inception_return_bps != null && Number.isFinite(s.inception_return_bps);
  const aumUsd = centsToUsd(s.aum_cents);
  return {
    kind: "strategy",
    id: s.strategy_id,
    title: s.name,
    subtitle: aumUsd ? `AUM ${aumUsd}` : s.kind === "rule" ? "Rule-based" : "Basket",
    metric: hasReturn ? bpsToSignedPct(s.inception_return_bps!) : centsToUsd(s.nav_per_unit),
    changeBps: hasReturn ? s.inception_return_bps! : undefined,
    href: `/strategies/${encodeURIComponent(s.strategy_id)}`,
  };
}
