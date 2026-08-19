import { describe, expect, it } from "vitest";

import {
  notional,
  maxQtyForBalance,
  riskSizedQty,
  pctOfBuyingPowerQty,
  estLiquidationPrice,
} from "./orderMath";

describe("notional", () => {
  it("multiplies price * qty exactly", () => {
    expect(notional(100, 3)).toBe(300);
    expect(notional(12345, 7)).toBe(86415);
  });
  it("returns 0 for non-positive inputs", () => {
    expect(notional(0, 5)).toBe(0);
    expect(notional(100, 0)).toBe(0);
    expect(notional(-1, 5)).toBe(0);
  });
});

describe("maxQtyForBalance", () => {
  it("floors balance / price to a whole lot", () => {
    expect(maxQtyForBalance(1000, 100)).toBe(10);
    expect(maxQtyForBalance(1050, 100)).toBe(10);
    expect(maxQtyForBalance(99, 100)).toBe(0);
  });
  it("returns 0 on non-positive price or balance", () => {
    expect(maxQtyForBalance(1000, 0)).toBe(0);
    expect(maxQtyForBalance(0, 100)).toBe(0);
    expect(maxQtyForBalance(-5, 100)).toBe(0);
  });
});

describe("riskSizedQty", () => {
  it("sizes qty from risk / stop-distance", () => {
    // risk 500, entry 100, stop 90 -> dist 10 -> 50
    expect(riskSizedQty(500, 100, 90)).toBe(50);
    // short: entry 100 stop 110 -> dist 10 -> 50
    expect(riskSizedQty(500, 100, 110)).toBe(50);
  });
  it("floors partial lots", () => {
    // 505 / 10 = 50.5 -> 50
    expect(riskSizedQty(505, 100, 90)).toBe(50);
  });
  it("guards divide-by-zero when entry == stop", () => {
    expect(riskSizedQty(500, 100, 100)).toBe(0);
  });
  it("returns 0 for non-positive risk", () => {
    expect(riskSizedQty(0, 100, 90)).toBe(0);
    expect(riskSizedQty(-10, 100, 90)).toBe(0);
  });
});

describe("pctOfBuyingPowerQty", () => {
  it("takes a percentage of the affordable max", () => {
    // max = 10; 25% -> 2 (floor of 2.5), 50% -> 5, 100% -> 10
    expect(pctOfBuyingPowerQty(1000, 100, 25)).toBe(2);
    expect(pctOfBuyingPowerQty(1000, 100, 50)).toBe(5);
    expect(pctOfBuyingPowerQty(1000, 100, 100)).toBe(10);
  });
  it("clamps pct to [0,100]", () => {
    expect(pctOfBuyingPowerQty(1000, 100, 150)).toBe(10);
    expect(pctOfBuyingPowerQty(1000, 100, -50)).toBe(0);
  });
  it("returns 0 when nothing is affordable", () => {
    expect(pctOfBuyingPowerQty(50, 100, 100)).toBe(0);
  });
});

describe("estLiquidationPrice (rough, assumed-bps only)", () => {
  it("puts the long liq below entry and short liq above entry", () => {
    const longLiq = estLiquidationPrice(100, "buy", 1000, 500);
    const shortLiq = estLiquidationPrice(100, "sell", 1000, 500);
    // long = 100 * (1 - 0.10 + 0.05) = 95
    expect(longLiq).toBeCloseTo(95, 6);
    // short = 100 * (1 + 0.10 - 0.05) = 105
    expect(shortLiq).toBeCloseTo(105, 6);
  });
  it("returns null on unusable inputs", () => {
    expect(estLiquidationPrice(0, "buy", 1000, 500)).toBeNull();
    expect(estLiquidationPrice(100, "buy", 0, 500)).toBeNull();
  });
});
