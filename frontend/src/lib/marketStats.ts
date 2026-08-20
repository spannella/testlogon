/**
 * Pure, framework-free statistics over a market bar series.
 *
 * A "bar" is the normalized OHLCV shape used by the history endpoint
 * ({@link Bar}); the Analysis workbench maps the exchange `Candle`
 * (integer prices scaled by `price_scaler`, nanosecond timestamps) into this
 * shape before calling in, so everything here is plain floating-point math.
 *
 * Nothing here touches React, the network, or the DOM: it is deterministic and
 * unit-tested in `marketStats.test.ts`.
 */

/** One OHLCV bar. `ts` is epoch-ms; prices/volume are already de-scaled. */
export interface Bar {
  ts: number;
  o: number;
  h: number;
  l: number;
  c: number;
  v: number;
}

/** The number of bars of a given interval that make up one calendar year. */
export function barsPerYear(intervalSec: number): number {
  if (!Number.isFinite(intervalSec) || intervalSec <= 0) return 0;
  const SECONDS_PER_YEAR = 365 * 24 * 60 * 60;
  return SECONDS_PER_YEAR / intervalSec;
}

/** Natural-log returns between consecutive closes (length = bars.length - 1). */
export function logReturns(bars: Bar[]): number[] {
  const out: number[] = [];
  for (let i = 1; i < bars.length; i++) {
    const prev = bars[i - 1]!.c;
    const cur = bars[i]!.c;
    if (prev > 0 && cur > 0) out.push(Math.log(cur / prev));
    else out.push(0);
  }
  return out;
}

/** Simple (arithmetic) returns between consecutive closes. */
export function simpleReturns(bars: Bar[]): number[] {
  const out: number[] = [];
  for (let i = 1; i < bars.length; i++) {
    const prev = bars[i - 1]!.c;
    const cur = bars[i]!.c;
    out.push(prev !== 0 ? cur / prev - 1 : 0);
  }
  return out;
}

/** Arithmetic mean of a numeric array (0 for empty). */
export function mean(xs: number[]): number {
  if (xs.length === 0) return 0;
  let s = 0;
  for (const x of xs) s += x;
  return s / xs.length;
}

/**
 * Sample standard deviation (n-1 denominator). Returns 0 for series with
 * fewer than two observations.
 */
export function stdev(xs: number[]): number {
  const n = xs.length;
  if (n < 2) return 0;
  const m = mean(xs);
  let acc = 0;
  for (const x of xs) {
    const d = x - m;
    acc += d * d;
  }
  return Math.sqrt(acc / (n - 1));
}

/** Simple moving average; entries before `period-1` are null. */
export function sma(vals: number[], period: number): (number | null)[] {
  const out: (number | null)[] = [];
  if (period <= 0) return vals.map(() => null);
  let sum = 0;
  for (let i = 0; i < vals.length; i++) {
    sum += vals[i]!;
    if (i >= period) sum -= vals[i - period]!;
    out.push(i >= period - 1 ? sum / period : null);
  }
  return out;
}

export interface DrawdownResult {
  /** Max drawdown as a negative fraction (e.g. -0.25 = a 25% peak-to-trough fall). */
  maxDrawdown: number;
  /** Index of the peak that precedes the worst trough (-1 if not defined). */
  peakIndex: number;
  /** Index of the worst trough (-1 if not defined). */
  troughIndex: number;
}

/**
 * Maximum drawdown of the close series: the deepest peak-to-trough decline as a
 * negative fraction of the peak. Zero for a non-decreasing series or <2 bars.
 */
export function maxDrawdown(bars: Bar[]): DrawdownResult {
  if (bars.length < 2) return { maxDrawdown: 0, peakIndex: -1, troughIndex: -1 };
  let peak = bars[0]!.c;
  let peakIdx = 0;
  let worst = 0;
  let worstPeakIdx = -1;
  let worstTroughIdx = -1;
  for (let i = 1; i < bars.length; i++) {
    const c = bars[i]!.c;
    if (c > peak) {
      peak = c;
      peakIdx = i;
    } else if (peak > 0) {
      const dd = c / peak - 1; // <= 0
      if (dd < worst) {
        worst = dd;
        worstPeakIdx = peakIdx;
        worstTroughIdx = i;
      }
    }
  }
  return { maxDrawdown: worst, peakIndex: worstPeakIdx, troughIndex: worstTroughIdx };
}

export interface SeriesStats {
  bars: number;
  first: number | null;
  last: number | null;
  hi: number | null;
  lo: number | null;
  /** Total (cumulative) return over the window: last/first - 1. */
  cumulativeReturn: number;
  /** Mean of per-bar simple returns. */
  avgReturn: number;
  /** Sample stdev of per-bar log returns (per-bar, not annualized). */
  volatility: number;
  /** {@link volatility} annualized by sqrt(barsPerYear(interval)). */
  annualizedVolatility: number;
  maxDrawdown: number;
  avgVolume: number;
  totalVolume: number;
}

/** Full stat pack for a bar series at a given interval (seconds). */
export function computeStats(bars: Bar[], intervalSec: number): SeriesStats {
  const n = bars.length;
  if (n === 0) {
    return {
      bars: 0, first: null, last: null, hi: null, lo: null,
      cumulativeReturn: 0, avgReturn: 0, volatility: 0, annualizedVolatility: 0,
      maxDrawdown: 0, avgVolume: 0, totalVolume: 0,
    };
  }
  const first = bars[0]!.c;
  const last = bars[n - 1]!.c;
  let hi = bars[0]!.h;
  let lo = bars[0]!.l;
  let volSum = 0;
  for (const b of bars) {
    if (b.h > hi) hi = b.h;
    if (b.l < lo) lo = b.l;
    volSum += b.v || 0;
  }
  const logRets = logReturns(bars);
  const simpleRets = simpleReturns(bars);
  const perBarVol = stdev(logRets);
  const annFactor = Math.sqrt(barsPerYear(intervalSec));
  return {
    bars: n,
    first,
    last,
    hi,
    lo,
    cumulativeReturn: first !== 0 ? last / first - 1 : 0,
    avgReturn: mean(simpleRets),
    volatility: perBarVol,
    annualizedVolatility: perBarVol * annFactor,
    maxDrawdown: maxDrawdown(bars).maxDrawdown,
    avgVolume: volSum / n,
    totalVolume: volSum,
  };
}

/**
 * Pearson correlation of two equal-length numeric series. Returns 0 when the
 * series differ in length, are shorter than 2, or either has zero variance.
 */
export function correlation(a: number[], b: number[]): number {
  const n = Math.min(a.length, b.length);
  if (n < 2) return 0;
  const ma = mean(a.slice(0, n));
  const mb = mean(b.slice(0, n));
  let cov = 0;
  let va = 0;
  let vb = 0;
  for (let i = 0; i < n; i++) {
    const da = a[i]! - ma;
    const db = b[i]! - mb;
    cov += da * db;
    va += da * da;
    vb += db * db;
  }
  if (va === 0 || vb === 0) return 0;
  return cov / Math.sqrt(va * vb);
}

/**
 * Align two bar series on their shared timestamps and return the paired
 * log-return vectors (one entry per shared consecutive-timestamp pair). Used to
 * correlate two instruments that may not share every bar.
 */
export function alignedLogReturns(a: Bar[], b: Bar[]): { a: number[]; b: number[] } {
  const mapB = new Map<number, number>();
  for (const bar of b) mapB.set(bar.ts, bar.c);
  // Common timestamps in a's order.
  const common: { ts: number; ca: number; cb: number }[] = [];
  for (const bar of a) {
    const cb = mapB.get(bar.ts);
    if (cb != null) common.push({ ts: bar.ts, ca: bar.c, cb });
  }
  const ra: number[] = [];
  const rb: number[] = [];
  for (let i = 1; i < common.length; i++) {
    const p = common[i - 1]!;
    const q = common[i]!;
    ra.push(p.ca > 0 && q.ca > 0 ? Math.log(q.ca / p.ca) : 0);
    rb.push(p.cb > 0 && q.cb > 0 ? Math.log(q.cb / p.cb) : 0);
  }
  return { a: ra, b: rb };
}

/** Correlation of two bar series over their aligned log-returns. */
export function seriesCorrelation(a: Bar[], b: Bar[]): number {
  const { a: ra, b: rb } = alignedLogReturns(a, b);
  return correlation(ra, rb);
}

/**
 * Normalize a close series to a base of 100 at the first bar, for overlay
 * compare charts. Empty in -> empty out; a zero first close yields all-100.
 */
export function normalizeTo100(bars: Bar[]): { ts: number; v: number }[] {
  if (bars.length === 0) return [];
  const base = bars[0]!.c;
  return bars.map((b) => ({ ts: b.ts, v: base !== 0 ? (b.c / base) * 100 : 100 }));
}

export interface BacktestTrade {
  entryIndex: number;
  exitIndex: number;
  entryPrice: number;
  exitPrice: number;
  ret: number;
}

export interface BacktestResult {
  /** Equity curve (starts at 1.0), one entry per bar. */
  equity: number[];
  totalReturn: number;
  trades: BacktestTrade[];
  numTrades: number;
  wins: number;
  /** Fraction of closed trades that were profitable (0 when no trades). */
  winRate: number;
  fast: number;
  slow: number;
}

/**
 * Long/flat SMA-crossover backtest. Go LONG on the bar after fast SMA crosses
 * above slow SMA; go FLAT on the bar after it crosses back below. The position
 * held into a bar is applied to that bar's simple return (no look-ahead).
 * Frictionless.
 */
export function backtestMaCross(bars: Bar[], fast: number, slow: number): BacktestResult {
  const empty: BacktestResult = {
    equity: bars.length ? [1] : [],
    totalReturn: 0,
    trades: [],
    numTrades: 0,
    wins: 0,
    winRate: 0,
    fast,
    slow,
  };
  if (fast <= 0 || slow <= 0 || fast >= slow || bars.length < slow + 1) return empty;

  const closes = bars.map((b) => b.c);
  const fastMa = sma(closes, fast);
  const slowMa = sma(closes, slow);

  const equity: number[] = new Array(bars.length).fill(1);
  const trades: BacktestTrade[] = [];
  let eq = 1;
  let position = 0; // 0 flat, 1 long
  let entryIndex = -1;
  let entryPrice = 0;

  for (let i = 0; i < bars.length; i++) {
    // Apply the position held coming into bar i to this bar's return.
    if (i > 0 && position === 1) {
      const prev = closes[i - 1]!;
      const cur = closes[i]!;
      if (prev !== 0) eq *= cur / prev;
    }
    equity[i] = eq;

    // Decide the signal from THIS bar's completed MAs; it takes effect next bar.
    const f = fastMa[i];
    const s = slowMa[i];
    if (f != null && s != null) {
      const wantLong = f > s;
      if (wantLong && position === 0) {
        position = 1;
        entryIndex = i;
        entryPrice = closes[i]!;
      } else if (!wantLong && position === 1) {
        const exitPrice = closes[i]!;
        trades.push({
          entryIndex,
          exitIndex: i,
          entryPrice,
          exitPrice,
          ret: entryPrice !== 0 ? exitPrice / entryPrice - 1 : 0,
        });
        position = 0;
      }
    }
  }
  // Close any open position at the final bar for accounting.
  if (position === 1 && entryIndex >= 0) {
    const exitPrice = closes[bars.length - 1]!;
    trades.push({
      entryIndex,
      exitIndex: bars.length - 1,
      entryPrice,
      exitPrice,
      ret: entryPrice !== 0 ? exitPrice / entryPrice - 1 : 0,
    });
  }

  const wins = trades.filter((t) => t.ret > 0).length;
  return {
    equity,
    totalReturn: eq - 1,
    trades,
    numTrades: trades.length,
    wins,
    winRate: trades.length ? wins / trades.length : 0,
    fast,
    slow,
  };
}
