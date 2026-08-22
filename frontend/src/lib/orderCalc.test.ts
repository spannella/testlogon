import { describe, expect, it } from "vitest";

import {
  positionSizeQty,
  riskReward,
  liquidationPreview,
  breakevenPrice,
  twapSchedule,
  icebergClips,
} from "./orderCalc";

describe("positionSizeQty", () => {
  it("sizes qty from a risk budget and stop distance", () => {
    // risk budget = 100000 * 1% = 1000; distance = 50 -> 20 lots
    expect(
      positionSizeQty({ equityCents: 100000, riskPct: 1, entryPrice: 1000, stopPrice: 950 }),
    ).toBe(20);
  });
  it("floors to a whole lot", () => {
    // budget = 100000 * 2% = 2000; distance = 300 -> 6.66 -> 6
    expect(
      positionSizeQty({ equityCents: 100000, riskPct: 2, entryPrice: 1000, stopPrice: 700 }),
    ).toBe(6);
  });
  it("clamps riskPct above 100", () => {
    expect(
      positionSizeQty({ equityCents: 1000, riskPct: 999, entryPrice: 100, stopPrice: 90 }),
    ).toBe(100); // budget 1000, dist 10
  });
  it("returns 0 for equal entry and stop (no distance)", () => {
    expect(
      positionSizeQty({ equityCents: 100000, riskPct: 1, entryPrice: 1000, stopPrice: 1000 }),
    ).toBe(0);
  });
  it("returns 0 for non-positive equity or riskPct", () => {
    expect(positionSizeQty({ equityCents: 0, riskPct: 1, entryPrice: 1000, stopPrice: 900 })).toBe(0);
    expect(positionSizeQty({ equityCents: 100000, riskPct: 0, entryPrice: 1000, stopPrice: 900 })).toBe(0);
    expect(positionSizeQty({ equityCents: -5, riskPct: 1, entryPrice: 1000, stopPrice: 900 })).toBe(0);
  });
});

describe("riskReward", () => {
  it("computes risk/reward for a long", () => {
    const r = riskReward({ side: "buy", entry: 1000, stop: 900, target: 1300, qty: 5 });
    expect(r.riskCents).toBe(500); // (1000-900)*5
    expect(r.rewardCents).toBe(1500); // (1300-1000)*5
    expect(r.rr).toBe(3);
  });
  it("computes risk/reward for a short (inverted)", () => {
    const r = riskReward({ side: "sell", entry: 1000, stop: 1100, target: 800, qty: 2 });
    expect(r.riskCents).toBe(200); // (1100-1000)*2
    expect(r.rewardCents).toBe(400); // (1000-800)*2
    expect(r.rr).toBe(2);
  });
  it("zeroes reward when target is on the wrong side", () => {
    const r = riskReward({ side: "buy", entry: 1000, stop: 900, target: 950, qty: 1 });
    expect(r.rewardCents).toBe(0);
    expect(r.rr).toBe(0);
  });
  it("returns zeros for non-positive entry or qty", () => {
    expect(riskReward({ side: "buy", entry: 0, stop: 1, target: 2, qty: 1 })).toEqual({
      riskCents: 0,
      rewardCents: 0,
      rr: 0,
    });
    expect(riskReward({ side: "buy", entry: 100, stop: 90, target: 120, qty: 0 })).toEqual({
      riskCents: 0,
      rewardCents: 0,
      rr: 0,
    });
  });
  it("treats missing (zero) stop/target as no leg", () => {
    const r = riskReward({ side: "buy", entry: 1000, stop: 0, target: 1200, qty: 3 });
    expect(r.riskCents).toBe(0);
    expect(r.rewardCents).toBe(600);
    expect(r.rr).toBe(0); // no risk leg -> rr undefined -> 0
  });
});

describe("liquidationPreview", () => {
  it("computes margin from leverage", () => {
    const r = liquidationPreview({
      side: "buy",
      entry: 1000,
      qty: 10,
      leverage: 5,
      maintenanceMarginBps: 500,
    });
    expect(r.marginRequiredCents).toBe(2000); // 1000*10/5
  });
  it("long liq sits below entry, short liq above", () => {
    const long = liquidationPreview({ side: "buy", entry: 1000, qty: 1, leverage: 10, maintenanceMarginBps: 0 });
    const short = liquidationPreview({ side: "sell", entry: 1000, qty: 1, leverage: 10, maintenanceMarginBps: 0 });
    expect(long.liqPrice).toBeCloseTo(900); // 1000*(1-0.1)
    expect(short.liqPrice).toBeCloseTo(1100); // 1000*(1+0.1)
  });
  it("maintenance margin pulls the long liq up", () => {
    const r = liquidationPreview({ side: "buy", entry: 1000, qty: 1, leverage: 10, maintenanceMarginBps: 200 });
    expect(r.liqPrice).toBeCloseTo(920); // 1000*(1-0.1+0.02)
  });
  it("returns null liq / 0 margin for unusable inputs", () => {
    expect(liquidationPreview({ side: "buy", entry: 0, qty: 1, leverage: 5, maintenanceMarginBps: 100 })).toEqual({
      liqPrice: null,
      marginRequiredCents: 0,
    });
    expect(liquidationPreview({ side: "buy", entry: 1000, qty: 1, leverage: 0, maintenanceMarginBps: 100 })).toEqual({
      liqPrice: null,
      marginRequiredCents: 0,
    });
  });
});

describe("breakevenPrice", () => {
  it("buy breakeven sits above entry by round-trip fees", () => {
    expect(breakevenPrice({ side: "buy", entry: 10000, feeBps: 10 })).toBe(10020); // 2*0.001
  });
  it("sell breakeven sits below entry", () => {
    expect(breakevenPrice({ side: "sell", entry: 10000, feeBps: 10 })).toBe(9980);
  });
  it("zero fee returns entry", () => {
    expect(breakevenPrice({ side: "buy", entry: 5000, feeBps: 0 })).toBe(5000);
  });
  it("returns 0 for non-positive entry", () => {
    expect(breakevenPrice({ side: "buy", entry: 0, feeBps: 10 })).toBe(0);
  });
});

describe("twapSchedule", () => {
  it("splits evenly and puts the remainder on the last slice", () => {
    const s = twapSchedule({ totalQty: 10, slices: 4, durationMs: 3000, startMs: 0 });
    expect(s.map((x) => x.qty)).toEqual([2, 2, 2, 4]);
    expect(s.reduce((a, b) => a + b.qty, 0)).toBe(10);
  });
  it("evenly spaces the fire times from the start", () => {
    const s = twapSchedule({ totalQty: 4, slices: 4, durationMs: 4000, startMs: 1000 });
    expect(s.map((x) => x.atMs)).toEqual([1000, 2000, 3000, 4000]);
  });
  it("guards <1 slice to a single slice", () => {
    const s = twapSchedule({ totalQty: 7, slices: 0, durationMs: 1000, startMs: 0 });
    expect(s).toHaveLength(1);
    expect(s[0]!.qty).toBe(7);
  });
  it("caps slices at total qty so no slice is empty", () => {
    const s = twapSchedule({ totalQty: 3, slices: 10, durationMs: 1000, startMs: 0 });
    expect(s).toHaveLength(3);
    expect(s.every((x) => x.qty >= 1)).toBe(true);
  });
  it("returns [] for non-positive total or duration", () => {
    expect(twapSchedule({ totalQty: 0, slices: 3, durationMs: 1000, startMs: 0 })).toEqual([]);
    expect(twapSchedule({ totalQty: 10, slices: 3, durationMs: 0, startMs: 0 })).toEqual([]);
  });
});

describe("icebergClips", () => {
  it("breaks total into visible clips with a smaller last clip", () => {
    const r = icebergClips({ totalQty: 10, visibleQty: 3 });
    expect(r).toEqual({ clips: 4, clipQty: 3, lastClipQty: 1 });
  });
  it("even division gives a full last clip", () => {
    const r = icebergClips({ totalQty: 9, visibleQty: 3 });
    expect(r).toEqual({ clips: 3, clipQty: 3, lastClipQty: 3 });
  });
  it("visible >= total is one whole clip", () => {
    expect(icebergClips({ totalQty: 5, visibleQty: 5 })).toEqual({ clips: 1, clipQty: 5, lastClipQty: 5 });
    expect(icebergClips({ totalQty: 5, visibleQty: 20 })).toEqual({ clips: 1, clipQty: 5, lastClipQty: 5 });
  });
  it("returns zero-clip for non-positive inputs", () => {
    expect(icebergClips({ totalQty: 0, visibleQty: 3 })).toEqual({ clips: 0, clipQty: 0, lastClipQty: 0 });
    expect(icebergClips({ totalQty: 10, visibleQty: 0 })).toEqual({ clips: 0, clipQty: 0, lastClipQty: 0 });
  });
  it("clip quantities sum back to the total", () => {
    const r = icebergClips({ totalQty: 17, visibleQty: 5 });
    const sum = r.clipQty * (r.clips - 1) + r.lastClipQty;
    expect(sum).toBe(17);
  });
});
