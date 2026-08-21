import { describe, expect, it } from "vitest";

import {
  bpsToFraction,
  bpsToPct,
  pctToBps,
  formatBps,
  formatCents,
  healthZone,
  dangerBps,
  bufferBps,
  distressFraction,
  bailoutClearing,
  indicativeShareBps,
  BPS_DENOM,
} from "./bailout";

describe("bps <-> pct/fraction + formatters", () => {
  it("converts bps to fraction/pct and pct to bps", () => {
    expect(bpsToFraction(10_000)).toBe(1);
    expect(bpsToFraction(250)).toBe(0.025);
    expect(bpsToPct(250)).toBeCloseTo(2.5, 6);
    expect(bpsToFraction(undefined)).toBe(0);
    expect(bpsToFraction(NaN)).toBe(0);
    expect(pctToBps(2.5)).toBe(250);
    expect(pctToBps(150)).toBe(10_000); // clamp
    expect(pctToBps(-5)).toBe(0);
    expect(BPS_DENOM).toBe(10_000);
  });

  it("formats bps and cents", () => {
    expect(formatBps(250)).toBe("2.5%");
    expect(formatBps(10_000)).toBe("100%");
    expect(formatCents(123_456)).toBe("$1,234.56");
    expect(formatCents(undefined)).toBe("—");
    expect(formatCents(NaN)).toBe("—");
  });
});

describe("healthZone", () => {
  it("insolvent is always liquidation, regardless of buffer", () => {
    expect(healthZone(9999, 100, false)).toBe("liquidation");
    expect(healthZone(0, 0, false)).toBe("liquidation");
  });

  it("solvent + buffer <= danger is distress (in-band)", () => {
    expect(healthZone(100, 200, true)).toBe("distress");
    expect(healthZone(200, 200, true)).toBe("distress"); // boundary is in-band
  });

  it("solvent + buffer > danger is healthy", () => {
    expect(healthZone(500, 200, true)).toBe("healthy");
  });

  it("non-finite buffer while solvent reads healthy (never fabricate distress)", () => {
    expect(healthZone(undefined, 200, true)).toBe("healthy");
    expect(healthZone(NaN, 200, true)).toBe("healthy");
  });
});

describe("dangerBps + bufferBps", () => {
  it("scales danger by volatility and clamps to [floor, ceil]", () => {
    // k*vol below floor -> floor
    expect(dangerBps(100, 1, 300, 1000)).toBe(300);
    // in range
    expect(dangerBps(500, 1, 300, 1000)).toBe(500);
    // above ceil -> ceil
    expect(dangerBps(5000, 1, 300, 1000)).toBe(1000);
    // k multiplier
    expect(dangerBps(200, 2, 0, 10000)).toBe(400);
    // guards
    expect(dangerBps(NaN, 1, 300, 1000)).toBe(300);
  });

  it("computes buffer bps from mark and liq distance", () => {
    // mark 100.00 ($10000c), liq 95.00 ($9500c) -> 5% -> 500 bps
    expect(bufferBps(10000, 9500)).toBe(500);
    // symmetric (short: liq above mark)
    expect(bufferBps(10000, 10500)).toBe(500);
    // non-positive mark -> 0
    expect(bufferBps(0, 9500)).toBe(0);
  });
});

describe("distressFraction", () => {
  it("is 1 at/over the liq line (no buffer)", () => {
    expect(distressFraction(0, 200)).toBe(1);
  });
  it("is 1 at the danger line and 0 at 2x danger of buffer", () => {
    expect(distressFraction(200, 200)).toBe(1); // at danger line
    expect(distressFraction(400, 200)).toBe(0); // 2x danger -> healthy
    expect(distressFraction(300, 200)).toBeCloseTo(0.5, 6); // midway
  });
  it("clamps beyond 2x danger to 0 (fully healthy)", () => {
    expect(distressFraction(5000, 200)).toBe(0);
  });
  it("no danger band -> reads 0 (healthy)", () => {
    expect(distressFraction(500, 0)).toBe(0);
  });
});

describe("bailoutClearing", () => {
  it("guards non-positive need / empty bids", () => {
    expect(bailoutClearing([], 100_00).cleared).toBe(false);
    expect(bailoutClearing([{ capital: 100_00, share_bps: 100 }], 0).clearingShareBps).toBe(0);
    expect(bailoutClearing([{ capital: 100_00, share_bps: 100 }], 0).clearingRateBpsPerCent).toBeNull();
  });

  it("fills fully at least dilution when capital covers the need", () => {
    // need $200. Two bids: A gives $200 for 100bps (cheap), B gives $200 for 400bps (dear).
    // A alone covers -> take only A, give up 100bps.
    const s = bailoutClearing(
      [
        { capital: 200_00, share_bps: 400 }, // dear
        { capital: 200_00, share_bps: 100 }, // cheap
      ],
      200_00,
    );
    expect(s.cleared).toBe(true);
    expect(s.raised).toBe(200_00);
    expect(s.clearingShareBps).toBe(100); // only the cheap bid was needed
    expect(s.filled).toHaveLength(1);
    expect(s.filled[0]!.share_bps).toBe(100);
  });

  it("accepts cheapest-dilution first, then the next, until the need is met", () => {
    // need $300. cheap A $200/100bps, dearer B $200/300bps.
    // Take A fully ($200,100bps), then $100 of B (pro-rated share = 150bps).
    const s = bailoutClearing(
      [
        { capital: 200_00, share_bps: 300 }, // B
        { capital: 200_00, share_bps: 100 }, // A cheaper
      ],
      300_00,
    );
    expect(s.cleared).toBe(true);
    expect(s.raised).toBe(300_00);
    // A full 100bps + half of B's 300 = 150 -> 250 total
    expect(s.clearingShareBps).toBe(250);
    expect(s.filled).toHaveLength(2);
  });

  it("pro-rates the marginal bid to take exactly the remaining capital", () => {
    // need $150, single bid $300 for 200bps -> take half: $150 for 100bps.
    const s = bailoutClearing([{ capital: 300_00, share_bps: 200 }], 150_00);
    expect(s.cleared).toBe(true);
    expect(s.raised).toBe(150_00);
    expect(s.clearingShareBps).toBe(100);
    expect(s.filled[0]!.capital).toBe(150_00);
  });

  it("reports a not-cleared partial when total capital is short", () => {
    const s = bailoutClearing([{ capital: 50_00, share_bps: 100 }], 200_00);
    expect(s.cleared).toBe(false);
    expect(s.raised).toBe(50_00);
    expect(s.clearingShareBps).toBe(100);
  });

  it("ignores zero/negative capital or share bids", () => {
    const s = bailoutClearing(
      [
        { capital: 0, share_bps: 100 },
        { capital: 100_00, share_bps: 0 },
        { capital: 100_00, share_bps: 100 },
      ],
      100_00,
    );
    expect(s.cleared).toBe(true);
    expect(s.filled).toHaveLength(1);
    expect(s.clearingShareBps).toBe(100);
  });
});

describe("indicativeShareBps", () => {
  it("pro-rates share by capital fraction of the need", () => {
    // inject $50 of a $100 need at 400bps max dilution -> 200bps.
    expect(indicativeShareBps(50_00, 100_00, 400)).toBe(200);
    // full need -> full max share
    expect(indicativeShareBps(100_00, 100_00, 400)).toBe(400);
    // over-funding clamps to full
    expect(indicativeShareBps(500_00, 100_00, 400)).toBe(400);
  });
  it("guards non-positive inputs", () => {
    expect(indicativeShareBps(0, 100_00, 400)).toBe(0);
    expect(indicativeShareBps(50_00, 0, 400)).toBe(0);
    expect(indicativeShareBps(50_00, 100_00, 0)).toBe(0);
  });
});
