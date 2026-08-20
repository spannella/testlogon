import { describe, expect, it } from "vitest";

import {
  type Bar,
  backtestMaCross,
  barsPerYear,
  computeStats,
  correlation,
  logReturns,
  maxDrawdown,
  mean,
  normalizeTo100,
  seriesCorrelation,
  simpleReturns,
  sma,
  stdev,
} from "./marketStats";

/** Build a bar series from a close array; ts is index-based hourly spacing. */
function barsFromCloses(closes: number[], volumes?: number[]): Bar[] {
  return closes.map((c, i) => ({
    ts: i * 3_600_000,
    o: i === 0 ? c : closes[i - 1]!,
    h: c,
    l: c,
    c,
    v: volumes ? volumes[i]! : 1,
  }));
}

describe("mean / stdev", () => {
  it("mean of empty is 0; stdev needs >=2 samples", () => {
    expect(mean([])).toBe(0);
    expect(stdev([])).toBe(0);
    expect(stdev([5])).toBe(0);
  });

  it("computes a known sample stdev", () => {
    // [2,4,4,4,5,5,7,9] has sample stdev ~2.1381 (n-1).
    const s = stdev([2, 4, 4, 4, 5, 5, 7, 9]);
    expect(s).toBeCloseTo(2.1381, 3);
  });
});

describe("logReturns / simpleReturns", () => {
  it("empty and single-bar series yield no returns", () => {
    expect(logReturns([])).toEqual([]);
    expect(simpleReturns(barsFromCloses([100]))).toEqual([]);
  });

  it("simple return of a doubling is 1.0", () => {
    const r = simpleReturns(barsFromCloses([100, 200]));
    expect(r).toHaveLength(1);
    expect(r[0]).toBeCloseTo(1, 10);
  });

  it("log return of a doubling is ln(2)", () => {
    const r = logReturns(barsFromCloses([100, 200]));
    expect(r[0]).toBeCloseTo(Math.log(2), 10);
  });
});

describe("sma", () => {
  it("nulls the warmup then averages", () => {
    expect(sma([1, 2, 3, 4], 2)).toEqual([null, 1.5, 2.5, 3.5]);
  });

  it("period <= 0 yields all nulls", () => {
    expect(sma([1, 2, 3], 0)).toEqual([null, null, null]);
  });
});

describe("maxDrawdown", () => {
  it("is 0 for a monotonically rising series", () => {
    expect(maxDrawdown(barsFromCloses([1, 2, 3, 4])).maxDrawdown).toBe(0);
  });

  it("is 0 for <2 bars", () => {
    expect(maxDrawdown([]).maxDrawdown).toBe(0);
    expect(maxDrawdown(barsFromCloses([10])).maxDrawdown).toBe(0);
  });

  it("captures the deepest peak-to-trough decline", () => {
    // peak 100 -> trough 50 = -0.5.
    const dd = maxDrawdown(barsFromCloses([80, 100, 70, 50, 90]));
    expect(dd.maxDrawdown).toBeCloseTo(-0.5, 10);
    expect(dd.peakIndex).toBe(1);
    expect(dd.troughIndex).toBe(3);
  });
});

describe("barsPerYear", () => {
  it("hourly bars ~ 8760/yr, daily ~365", () => {
    expect(barsPerYear(3600)).toBeCloseTo(8760, 6);
    expect(barsPerYear(86400)).toBeCloseTo(365, 6);
  });

  it("guards non-positive intervals", () => {
    expect(barsPerYear(0)).toBe(0);
    expect(barsPerYear(-1)).toBe(0);
  });
});

describe("computeStats", () => {
  it("returns a zeroed pack for an empty series", () => {
    const s = computeStats([], 3600);
    expect(s.bars).toBe(0);
    expect(s.first).toBeNull();
    expect(s.cumulativeReturn).toBe(0);
    expect(s.annualizedVolatility).toBe(0);
  });

  it("handles a single bar (no returns, hi/lo defined)", () => {
    const s = computeStats(barsFromCloses([100]), 3600);
    expect(s.bars).toBe(1);
    expect(s.first).toBe(100);
    expect(s.last).toBe(100);
    expect(s.volatility).toBe(0);
    expect(s.cumulativeReturn).toBe(0);
  });

  it("computes cumulative return, hi/lo and volume aggregates", () => {
    const s = computeStats(barsFromCloses([100, 110, 105, 120], [2, 4, 6, 8]), 3600);
    expect(s.cumulativeReturn).toBeCloseTo(0.2, 10);
    expect(s.hi).toBe(120);
    expect(s.lo).toBe(100);
    expect(s.totalVolume).toBe(20);
    expect(s.avgVolume).toBe(5);
    expect(s.annualizedVolatility).toBeGreaterThan(s.volatility);
  });
});

describe("correlation", () => {
  it("is +1 for a perfectly linear relationship", () => {
    expect(correlation([1, 2, 3, 4], [2, 4, 6, 8])).toBeCloseTo(1, 10);
  });

  it("is -1 for a perfectly inverse relationship", () => {
    expect(correlation([1, 2, 3, 4], [4, 3, 2, 1])).toBeCloseTo(-1, 10);
  });

  it("is 0 when a series has zero variance or is too short", () => {
    expect(correlation([1, 1, 1], [1, 2, 3])).toBe(0);
    expect(correlation([1], [1])).toBe(0);
  });

  it("seriesCorrelation aligns on shared timestamps", () => {
    const closesA = [100, 110, 105, 120, 118];
    const a = barsFromCloses(closesA);
    // b is a exactly scaled by 2 -> identical log-returns -> correlation +1.
    const b = barsFromCloses(closesA.map((c) => c * 2));
    expect(seriesCorrelation(a, b)).toBeCloseTo(1, 10);
  });
});

describe("normalizeTo100", () => {
  it("rebases the first bar to 100", () => {
    const n = normalizeTo100(barsFromCloses([50, 75, 25]));
    expect(n.map((p) => p.v)).toEqual([100, 150, 50]);
  });

  it("empty in -> empty out", () => {
    expect(normalizeTo100([])).toEqual([]);
  });
});

describe("backtestMaCross", () => {
  it("degrades safely on bad params / short series", () => {
    const r = backtestMaCross(barsFromCloses([1, 2, 3]), 5, 2); // fast >= slow
    expect(r.numTrades).toBe(0);
    expect(r.totalReturn).toBe(0);
    const short = backtestMaCross(barsFromCloses([1, 2]), 2, 3);
    expect(short.numTrades).toBe(0);
  });

  it("produces an equity curve of the right length and takes trades on a trend", () => {
    // A rise then fall should trigger at least one long entry and exit.
    const closes = [10, 10, 10, 11, 12, 13, 14, 15, 14, 12, 10, 9, 8, 9, 11, 13];
    const r = backtestMaCross(barsFromCloses(closes), 2, 4);
    expect(r.equity).toHaveLength(closes.length);
    expect(r.equity[0]).toBe(1);
    expect(r.numTrades).toBeGreaterThan(0);
    expect(r.winRate).toBeGreaterThanOrEqual(0);
    expect(r.winRate).toBeLessThanOrEqual(1);
  });

  it("a flat market takes no profitable trades and keeps equity ~1", () => {
    const r = backtestMaCross(barsFromCloses(new Array(20).fill(100)), 3, 6);
    expect(r.totalReturn).toBeCloseTo(0, 10);
  });
});
