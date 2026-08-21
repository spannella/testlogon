import { describe, expect, it } from "vitest";

import type { Bar } from "./marketStats";
import {
  bpsToFraction,
  bpsToPct,
  pctToBps,
  formatBps,
  formatCents,
  unitsForInvestment,
  proceedsForUnits,
  mgmtFeeAccrual,
  perfFee,
  totalWeightBps,
  validateWeights,
  canInvest,
  capacityFilledFraction,
  basketBacktest,
  BPS_DENOM,
  type StrategyLeg,
  type LegSeries,
} from "./strategies";

describe("bps <-> pct/fraction", () => {
  it("converts and formats bps", () => {
    expect(bpsToFraction(10_000)).toBe(1);
    expect(bpsToFraction(250)).toBe(0.025);
    expect(bpsToFraction(undefined)).toBe(0);
    expect(bpsToPct(250)).toBeCloseTo(2.5, 6);
    expect(pctToBps(2.5)).toBe(250);
    expect(pctToBps(150)).toBe(10_000); // clamp default 100
    expect(pctToBps(150, 5000)).toBe(15_000); // custom max raises the clamp ceiling
    expect(formatBps(250)).toBe("2.5%");
    expect(formatCents(123456)).toBe("$1,234.56");
    expect(formatCents(undefined)).toBe("—");
  });
});

describe("NAV / units math", () => {
  it("mints units for an investment at NAV", () => {
    // $100.00 at a $12.34 NAV -> 8.103... units
    expect(unitsForInvestment(10000, 1234)).toBeCloseTo(8.1037, 3);
    expect(unitsForInvestment(0, 1234)).toBe(0);
    expect(unitsForInvestment(10000, 0)).toBe(0);
  });
  it("redeems proceeds for units at NAV, rounded to cents", () => {
    expect(proceedsForUnits(8.1037, 1234)).toBe(10000); // round-trips ~$100
    expect(proceedsForUnits(10, 1500)).toBe(15000);
    expect(proceedsForUnits(0, 1500)).toBe(0);
  });
  it("round-trips invest -> redeem at a flat NAV", () => {
    const nav = 2000;
    const units = unitsForInvestment(50000, nav);
    expect(proceedsForUnits(units, nav)).toBe(50000);
  });
});

describe("fee accrual", () => {
  it("accrues a management fee by day-count on AUM", () => {
    // 2% (200 bps) annual on $1,000,000 for a full year = $20,000
    expect(mgmtFeeAccrual(100_000_00, 200, 365)).toBe(2_000_00 * 100 / 100); // = 2_000_000 cents
    // half a year -> half the fee
    expect(mgmtFeeAccrual(100_000_00, 200, 182.5)).toBe(100_000);
    expect(mgmtFeeAccrual(0, 200, 365)).toBe(0);
    expect(mgmtFeeAccrual(100_000_00, 0, 365)).toBe(0);
    expect(mgmtFeeAccrual(100_000_00, 200, 0)).toBe(0);
  });
  it("charges a performance fee only on gains above the high-water mark", () => {
    // 20% (2000 bps) of a $10,000 gain above HWM = $2,000
    expect(perfFee(110_000_00, 100_000_00, 2000)).toBe(2_000_00);
    // at/below the mark -> no fee
    expect(perfFee(100_000_00, 100_000_00, 2000)).toBe(0);
    expect(perfFee(90_000_00, 100_000_00, 2000)).toBe(0);
    expect(perfFee(110_000_00, 100_000_00, 0)).toBe(0);
  });
});

describe("weight validation", () => {
  const legs = (arr: [number, number][]): StrategyLeg[] =>
    arr.map(([symbol_id, weight_bps]) => ({ symbol_id, weight_bps }));

  it("sums leg weights ignoring junk", () => {
    expect(totalWeightBps(legs([[1, 5000], [2, 5000]]))).toBe(10_000);
    expect(totalWeightBps(legs([[1, 5000], [2, -100]]))).toBe(5000);
  });
  it("passes only when legs sum to exactly 100% with unique symbols", () => {
    const ok = validateWeights(legs([[1, 6000], [2, 4000]]));
    expect(ok.valid).toBe(true);
    expect(ok.driftBps).toBe(0);
    expect(ok.hasDuplicateSymbol).toBe(false);
  });
  it("fails when under/over 100%", () => {
    expect(validateWeights(legs([[1, 6000], [2, 3000]])).valid).toBe(false);
    expect(validateWeights(legs([[1, 6000], [2, 3000]])).driftBps).toBe(-1000);
    expect(validateWeights(legs([[1, 6000], [2, 5000]])).driftBps).toBe(1000);
  });
  it("flags duplicate symbols and empty baskets", () => {
    expect(validateWeights(legs([[1, 5000], [1, 5000]])).hasDuplicateSymbol).toBe(true);
    expect(validateWeights(legs([[1, 5000], [1, 5000]])).valid).toBe(false);
    expect(validateWeights([]).hasLegs).toBe(false);
    expect(validateWeights([]).valid).toBe(false);
  });
  it("honors a rounding tolerance", () => {
    expect(validateWeights(legs([[1, 3333], [2, 3333], [3, 3333]]), 5).valid).toBe(true);
    expect(validateWeights(legs([[1, 3333], [2, 3333], [3, 3333]]), 0).valid).toBe(false);
  });
});

describe("min-size + capacity checks", () => {
  it("blocks non-positive amounts", () => {
    expect(canInvest(0, 10000, 0, 0).ok).toBe(false);
    expect(canInvest(0, 10000, 0, 0).reason).toBe("amount_non_positive");
  });
  it("blocks below the minimum investment", () => {
    const r = canInvest(5000, 10000, 0, 0);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("below_min");
  });
  it("blocks over the AUM capacity cap", () => {
    // cap $100k, already $95k in -> only $5k room
    const r = canInvest(10_000_00, 0, 95_000_00, 100_000_00);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("over_capacity");
    expect(r.capacityRemainingCents).toBe(5_000_00);
  });
  it("allows a valid investment and reports uncapped remaining as Infinity", () => {
    const r = canInvest(50_000_00, 10000, 0, 0);
    expect(r.ok).toBe(true);
    expect(r.capacityRemainingCents).toBe(Number.POSITIVE_INFINITY);
  });
  it("computes capacity-filled fraction", () => {
    expect(capacityFilledFraction(50_000_00, 100_000_00)).toBeCloseTo(0.5, 6);
    expect(capacityFilledFraction(50_000_00, 0)).toBe(0); // uncapped
    expect(capacityFilledFraction(200_000_00, 100_000_00)).toBe(1); // clamped
  });
});

describe("basket backtest", () => {
  const bars = (closes: number[], startTs = 1_000): Bar[] =>
    closes.map((c, i) => ({ ts: startTs + i * 60, o: c, h: c, l: c, c, v: 0 }));

  it("returns an empty result for no legs", () => {
    const r = basketBacktest([], 60);
    expect(r.steps).toBe(0);
    expect(r.equity).toEqual([]);
    expect(r.aligned).toBe(false);
  });

  it("tracks a single leg's return exactly", () => {
    const legs: LegSeries[] = [
      { symbol_id: 1, weight_bps: 10_000, bars: bars([100, 110, 121]) },
    ];
    const r = basketBacktest(legs, 60);
    expect(r.steps).toBe(3);
    expect(r.equity[0]).toBeCloseTo(1, 9);
    expect(r.equity[2]).toBeCloseTo(1.21, 9); // +10% then +10%
    expect(r.stats.cumulativeReturn).toBeCloseTo(0.21, 6);
  });

  it("blends two legs by weight over shared timestamps", () => {
    // Leg A doubles (100->200, +100%); leg B flat. 50/50 -> +50% total.
    const legs: LegSeries[] = [
      { symbol_id: 1, weight_bps: 5000, bars: bars([100, 200]) },
      { symbol_id: 2, weight_bps: 5000, bars: bars([100, 100]) },
    ];
    const r = basketBacktest(legs, 60);
    expect(r.aligned).toBe(true);
    expect(r.equity[1]).toBeCloseTo(1.5, 9);
  });

  it("aligns on shared timestamps only", () => {
    const legs: LegSeries[] = [
      { symbol_id: 1, weight_bps: 5000, bars: bars([100, 110, 120], 1000) },
      { symbol_id: 2, weight_bps: 5000, bars: bars([100, 105], 1060) }, // ts 1060,1120
    ];
    const r = basketBacktest(legs, 60);
    // Shared ts = 1060, 1120 -> 2 aligned steps.
    expect(r.steps).toBe(2);
  });

  it("normalizes weights that do not total 100%", () => {
    // Both legs weight 2500 bps (sum 5000). A +10%, B flat -> normalized 50/50 -> +5%.
    const legs: LegSeries[] = [
      { symbol_id: 1, weight_bps: 2500, bars: bars([100, 110]) },
      { symbol_id: 2, weight_bps: 2500, bars: bars([100, 100]) },
    ];
    const r = basketBacktest(legs, 60);
    expect(r.equity[1]).toBeCloseTo(1.05, 9);
  });
});

describe("constants", () => {
  it("uses 10_000 bps as the 100% denominator", () => {
    expect(BPS_DENOM).toBe(10_000);
  });
});
