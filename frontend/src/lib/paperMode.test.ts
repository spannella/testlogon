import { describe, expect, it } from "vitest";

import { isPaperOrderType, selectMarketPrice } from "./paperMode";

describe("isPaperOrderType", () => {
  it("accepts market and limit only", () => {
    expect(isPaperOrderType("market")).toBe(true);
    expect(isPaperOrderType("limit")).toBe(true);
  });
  it("rejects every other order type", () => {
    for (const t of ["stop", "stop_limit", "take_profit", "quote", "oto", "oco", "funding"]) {
      expect(isPaperOrderType(t)).toBe(false);
    }
  });
});

describe("selectMarketPrice", () => {
  const full = { bestBid: 100, bestAsk: 102, lastPrice: 101, refPrice: 99 };

  it("buy lifts the ask, sell hits the bid", () => {
    expect(selectMarketPrice("buy", full)).toBe(102);
    expect(selectMarketPrice("sell", full)).toBe(100);
  });

  it("falls back to last trade when the near-side quote is missing", () => {
    expect(selectMarketPrice("buy", { bestBid: 100, lastPrice: 101, refPrice: 99 })).toBe(101);
    expect(selectMarketPrice("sell", { bestAsk: 102, lastPrice: 101, refPrice: 99 })).toBe(101);
  });

  it("uses the far-side quote when near-side and last trade are absent (one-sided book)", () => {
    // buy with no ask but a bid present -> uses the bid
    expect(selectMarketPrice("buy", { bestBid: 100, refPrice: 99 })).toBe(100);
    // sell with no bid but an ask present -> uses the ask
    expect(selectMarketPrice("sell", { bestAsk: 104, refPrice: 99 })).toBe(104);
  });

  it("prefers the near-side quote over the mid when both sides exist", () => {
    expect(selectMarketPrice("buy", { bestBid: 100, bestAsk: 104 })).toBe(104);
    expect(selectMarketPrice("sell", { bestBid: 100, bestAsk: 104 })).toBe(100);
  });

  it("uses refPrice as the last resort", () => {
    expect(selectMarketPrice("buy", { refPrice: 99 })).toBe(99);
    expect(selectMarketPrice("sell", { refPrice: 99 })).toBe(99);
  });

  it("ignores non-positive / non-finite quotes and returns undefined when nothing is usable", () => {
    expect(selectMarketPrice("buy", { bestAsk: 0, bestBid: -5, lastPrice: 0, refPrice: 0 })).toBeUndefined();
    expect(selectMarketPrice("buy", {})).toBeUndefined();
    expect(selectMarketPrice("buy", { bestAsk: NaN, lastPrice: NaN })).toBeUndefined();
  });
});
