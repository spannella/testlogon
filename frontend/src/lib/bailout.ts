// Pure, dependency-free math for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT
// AUCTION surface. Framework-free so it is unit-testable in isolation (see
// bailout.test.ts). None of these functions perform I/O — they only compute the
// numbers the screens render off a SERVER-AUTHORITATIVE distress read.
//
// CONCEPT: a leveraged margin position approaching a margin call can raise
// rescue capital via a sealed single-clearing-price auction — rescuers inject
// capital for a position-SHARE (co-owning a slice of the position + its future
// uPnL). This is PRE-EMPTIVE: it only exists while the position is in a
// volatility-scaled DISTRESS band but STILL SOLVENT (equity > maintenance).
// Once equity <= maintenance the auction is impossible — that is a liquidation.
//
// CONVENTIONS (locked, mirrors tokens.ts): all monetary amounts are INTEGER
// CENTS; every `_bps` value is BASIS POINTS (1% = 100 bps, 100% = 10_000 bps).

/** Full basis-points denominator (100%). */
export const BPS_DENOM = 10_000;

/** Clamp a number into [lo, hi]; non-finite -> lo. */
export function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}

/** Basis points -> fraction (0..1). 10_000 bps -> 1. Non-finite -> 0. */
export function bpsToFraction(bps: number | undefined | null): number {
  if (bps == null || !Number.isFinite(bps)) return 0;
  return bps / BPS_DENOM;
}

/** Basis points -> a human percent number (e.g. 250 -> 2.5). */
export function bpsToPct(bps: number | undefined | null): number {
  return bpsToFraction(bps) * 100;
}

/** A human percent number -> basis points, floored to an int (2.5 -> 250). */
export function pctToBps(pct: number | undefined | null): number {
  if (pct == null || !Number.isFinite(pct)) return 0;
  return Math.round(clamp(pct, 0, 100) * 100);
}

/** Format basis points as a percent string, e.g. 250 -> "2.5%". */
export function formatBps(bps: number | undefined | null, maxFrac = 2): string {
  const pct = bpsToPct(bps);
  return `${pct.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: maxFrac })}%`;
}

/** Integer cents -> "$1,234.56". Non-finite -> "—". */
export function formatCents(cents: number | undefined | null): string {
  if (cents == null || !Number.isFinite(cents)) return "—";
  return `$${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

// -- Distress health zone ----------------------------------------------

/** The three-zone position health classification. */
export type HealthZone = "healthy" | "distress" | "liquidation";

/**
 * Classify a position into one of three zones from its SERVER-COMPUTED buffer
 * and danger line (both in bps) plus its solvency flag:
 *   - `liquidation` when NOT solvent (equity <= maintenance) — the bailout
 *     window is closed; this is a liquidation, not a rescue opportunity.
 *   - `distress`    when solvent AND buffer_bps <= danger_bps (in-band).
 *   - `healthy`     otherwise (solvent and comfortably away from the liq line).
 * The client NEVER fabricates distress — it renders the server read. A
 * non-finite buffer/danger is treated as the safe (`healthy`) side while solvent.
 */
export function healthZone(
  bufferBps: number | undefined | null,
  dangerBps: number | undefined | null,
  solvent: boolean,
): HealthZone {
  if (!solvent) return "liquidation";
  const buffer = Number.isFinite(bufferBps as number) ? (bufferBps as number) : Infinity;
  const danger = Number.isFinite(dangerBps as number) ? (dangerBps as number) : 0;
  return buffer <= danger ? "distress" : "healthy";
}

/**
 * The volatility-scaled danger line in bps:
 *   danger_bps = clamp(k * volatility_bps, floor, ceil)
 * A convenience mirror of the server rule so the UI can show the same number if
 * the read only carries volatility. The server value (`danger_bps`) is
 * authoritative when present.
 */
export function dangerBps(
  volatilityBps: number,
  k: number,
  floorBps: number,
  ceilBps: number,
): number {
  const vol = Number.isFinite(volatilityBps) ? Math.max(0, volatilityBps) : 0;
  const kk = Number.isFinite(k) ? Math.max(0, k) : 0;
  const lo = Number.isFinite(floorBps) ? floorBps : 0;
  const hi = Number.isFinite(ceilBps) ? ceilBps : lo;
  return clamp(kk * vol, lo, Math.max(lo, hi));
}

/**
 * Buffer bps = |mark - liq| / mark * 10_000 — distance-to-liquidation as bps of
 * the mark. Mirrors the server rule so the UI can render distance-to-liq when a
 * read carries only marks. Returns 0 for a non-positive mark (already at/over
 * the line). The server `buffer_bps` is authoritative when present.
 */
export function bufferBps(markCents: number, liqCents: number): number {
  if (!(markCents > 0) || !Number.isFinite(liqCents)) return 0;
  return Math.round((Math.abs(markCents - liqCents) / markCents) * BPS_DENOM);
}

/**
 * Fraction (0..1) of the way the buffer has been consumed toward the danger
 * line, for a 3-zone health meter fill. 0 = full buffer (healthy edge), 1 = at
 * the danger line (distress). Values <= danger clamp to 1 (fully in-band).
 */
export function distressFraction(
  bufferBps: number | undefined | null,
  dangerBps: number | undefined | null,
): number {
  const buffer = Number.isFinite(bufferBps as number) ? Math.max(0, bufferBps as number) : 0;
  const danger = Number.isFinite(dangerBps as number) ? Math.max(0, dangerBps as number) : 0;
  if (!(buffer > 0)) return 1; // at/over the line
  if (!(danger > 0)) return 0; // no danger band -> render as healthy
  // The meter spans [danger .. 2*danger] of buffer -> [1 .. 0] consumed. Beyond
  // 2*danger of buffer the meter reads 0 (fully healthy).
  const span = danger; // width of the "approaching" ramp
  const consumed = clamp((2 * danger - buffer) / span, 0, 1);
  return consumed;
}

// -- Bailout clearing summary ------------------------------------------

/**
 * One sealed rescue bid: `capital` cents offered in exchange for `share_bps` of
 * the position (the price the rescuer is willing to pay is capital per bps).
 */
export interface RescueBid {
  capital: number; // integer cents escrowed
  share_bps: number; // position-share demanded for that capital
}

/** One filled rescuer in the cleared outcome. */
export interface FilledRescuer {
  /** Index of the bid in the input array (stable identity for the caller). */
  index: number;
  /** Capital actually taken from this rescuer, in cents. */
  capital: number;
  /** Position-share actually granted to this rescuer, in bps. */
  share_bps: number;
}

/** The computed outcome of clearing a bailout auction at a single share price. */
export interface BailoutClearing {
  /**
   * The single uniform clearing rate = share_bps granted per capital cent for
   * the marginal (last-filled) bid. `null` when nothing clears.
   */
  clearingRateBpsPerCent: number | null;
  /** Total capital raised, in cents (meets need when cleared). */
  raised: number;
  /** Total position-share given up, in bps (the dilution the owner accepts). */
  clearingShareBps: number;
  /** The filled rescuers (pro-rated at the marginal level). */
  filled: FilledRescuer[];
  /** True when the raised capital meets `capitalNeeded`. */
  cleared: boolean;
}

/**
 * Clear a sealed bailout auction at a SINGLE clearing price, choosing the
 * outcome that raises `capitalNeeded` while giving up the LEAST total
 * position-share (least-dilutive to the owner) — the mirror of the token IPO
 * uniform-price clearing, but here we minimise share GIVEN UP rather than
 * maximise proceeds.
 *
 * Each bid asks for `share_bps` in exchange for `capital` cents; its implied
 * "cheapness" for the owner is capital/share_bps (cents raised per bps of
 * dilution) — HIGHER is better for the owner. We greedily accept bids from the
 * cheapest-dilution (highest capital-per-bps) down until the capital need is
 * met, pro-rating the marginal bid so we take exactly the capital still needed
 * (and a pro-rated slice of its share).
 *
 * Returns a not-cleared summary (best partial) when total offered capital
 * cannot cover the need.
 */
export function bailoutClearing(
  bids: RescueBid[],
  capitalNeeded: number,
): BailoutClearing {
  const empty: BailoutClearing = {
    clearingRateBpsPerCent: null,
    raised: 0,
    clearingShareBps: 0,
    filled: [],
    cleared: false,
  };
  if (!(capitalNeeded > 0)) return empty;

  const valid = (bids ?? [])
    .map((b, index) => ({ index, capital: b?.capital ?? 0, share_bps: b?.share_bps ?? 0 }))
    .filter((b) => b.capital > 0 && b.share_bps > 0);
  if (valid.length === 0) return empty;

  // Owner-cheapest first: MOST capital per bps of dilution given up.
  valid.sort((a, b) => b.capital / b.share_bps - a.capital / a.share_bps);

  let raised = 0;
  let shareBps = 0;
  const filled: FilledRescuer[] = [];

  for (const b of valid) {
    if (raised >= capitalNeeded) break;
    const remaining = capitalNeeded - raised;
    if (b.capital <= remaining) {
      // Take the whole bid.
      raised += b.capital;
      shareBps += b.share_bps;
      filled.push({ index: b.index, capital: b.capital, share_bps: b.share_bps });
    } else {
      // Pro-rate the marginal bid: take exactly `remaining` capital and a
      // pro-rated slice of its share.
      const frac = remaining / b.capital;
      const takenShare = Math.round(b.share_bps * frac);
      raised += remaining;
      shareBps += takenShare;
      filled.push({ index: b.index, capital: remaining, share_bps: takenShare });
    }
  }

  const cleared = raised >= capitalNeeded;
  // Marginal implied rate = share/capital of the last filled bid (bps per cent).
  const last = filled.length > 0 ? filled[filled.length - 1]! : undefined;
  const clearingRateBpsPerCent =
    last && last.capital > 0 ? last.share_bps / last.capital : null;

  return {
    clearingRateBpsPerCent,
    raised,
    clearingShareBps: shareBps,
    filled,
    cleared,
  };
}

/**
 * Indicative position-share (bps) a rescuer would receive for injecting
 * `capitalCents` into an auction needing `capitalNeeded` cents at a target total
 * dilution of `maxShareBps` — a simple pro-rata preview for the bid form
 * (server clearing is authoritative). Guards non-positive need by returning 0.
 */
export function indicativeShareBps(
  capitalCents: number,
  capitalNeeded: number,
  maxShareBps: number,
): number {
  if (!(capitalNeeded > 0) || !(capitalCents > 0) || !(maxShareBps > 0)) return 0;
  const frac = clamp(capitalCents / capitalNeeded, 0, 1);
  return Math.round(maxShareBps * frac);
}
