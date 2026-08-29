import { describe, expect, it } from "vitest";
import {
  buildMarketCardPayload,
  buildPositionCardPayload,
  changePctFromCloses,
  type PositionSource,
} from "./tradingCards";

const src: PositionSource = {
  symbol_id: 1,
  symbol: "BTCUSDC",
  side: "Long",
  roi_pct: 12.5,
  entry: 100000,
  mark: 112500,
  size: 3,
  price_scaler: 1,
};

describe("buildPositionCardPayload disclosure gating", () => {
  it("full disclosure carries entry, mark and (absolute) size", () => {
    const p = buildPositionCardPayload(src, "full");
    expect(p.disclosure).toBe("full");
    expect(p.symbol).toBe("BTCUSDC");
    expect(p.side).toBe("Long");
    expect(p.roi_pct).toBe(12.5);
    expect(p.entry).toBe(100000);
    expect(p.mark).toBe(112500);
    expect(p.size).toBe(3);
  });

  it("size is normalised to its absolute value at full disclosure", () => {
    const short = buildPositionCardPayload({ ...src, side: "Short", size: -4 }, "full");
    expect(short.size).toBe(4);
  });

  it("pnl_pct disclosure reveals ONLY symbol/side/roi -- never notionals", () => {
    const p = buildPositionCardPayload(src, "pnl_pct");
    expect(p.disclosure).toBe("pnl_pct");
    expect(p.symbol).toBe("BTCUSDC");
    expect(p.side).toBe("Long");
    expect(p.roi_pct).toBe(12.5);
    expect(p.entry).toBeUndefined();
    expect(p.mark).toBeUndefined();
    expect(p.size).toBeUndefined();
  });

  it("roi disclosure reveals ONLY symbol/side/roi -- never notionals", () => {
    const p = buildPositionCardPayload(src, "roi");
    expect(p.entry).toBeUndefined();
    expect(p.mark).toBeUndefined();
    expect(p.size).toBeUndefined();
    expect(p.roi_pct).toBe(12.5);
  });
});

describe("buildMarketCardPayload", () => {
  it("carries just symbol_id + symbol", () => {
    expect(buildMarketCardPayload(2, "ETHUSDC")).toEqual({ symbol_id: 2, symbol: "ETHUSDC" });
  });
});

describe("changePctFromCloses", () => {
  it("computes first->last percent change", () => {
    expect(changePctFromCloses([100, 110])).toBeCloseTo(10);
  });
  it("returns undefined for an empty window or zero base", () => {
    expect(changePctFromCloses([])).toBeUndefined();
    expect(changePctFromCloses([0, 5])).toBeUndefined();
  });
});
