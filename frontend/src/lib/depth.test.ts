import { describe, expect, it } from "vitest";

import { computeDepth, cumulativeSide, type Level } from "./depth";

describe("cumulativeSide", () => {
  it("cumulates bids from the highest price outward", () => {
    const bids: Level[] = [
      [100, 5],
      [98, 3],
      [99, 2],
    ];
    const pts = cumulativeSide(bids, true);
    expect(pts.map((p) => p.price)).toEqual([100, 99, 98]);
    expect(pts.map((p) => p.cum)).toEqual([5, 7, 10]);
  });

  it("cumulates asks from the lowest price outward", () => {
    const asks: Level[] = [
      [103, 4],
      [101, 1],
      [102, 2],
    ];
    const pts = cumulativeSide(asks, false);
    expect(pts.map((p) => p.price)).toEqual([101, 102, 103]);
    expect(pts.map((p) => p.cum)).toEqual([1, 3, 7]);
  });

  it("returns [] for empty/undefined input", () => {
    expect(cumulativeSide(undefined, true)).toEqual([]);
    expect(cumulativeSide([], false)).toEqual([]);
  });

  it("drops non-positive / non-finite levels", () => {
    const dirty: Level[] = [
      [100, 5],
      [0, 3],
      [99, 0],
      [98, -2],
      [Number.NaN, 4],
      [97, Number.POSITIVE_INFINITY],
      [96, 1],
    ];
    const pts = cumulativeSide(dirty, true);
    expect(pts.map((p) => p.price)).toEqual([100, 96]);
    expect(pts.map((p) => p.cum)).toEqual([5, 6]);
  });

  it("coalesces duplicate price levels by summing qty", () => {
    const bids: Level[] = [
      [100, 5],
      [100, 3],
      [99, 2],
    ];
    const pts = cumulativeSide(bids, true);
    expect(pts).toHaveLength(2);
    expect(pts[0]).toEqual({ price: 100, qty: 8, cum: 8 });
    expect(pts[1]).toEqual({ price: 99, qty: 2, cum: 10 });
  });
});

describe("computeDepth", () => {
  it("computes best bid/ask, mid, spread and axis bounds", () => {
    const bids: Level[] = [
      [100, 5],
      [99, 2],
    ];
    const asks: Level[] = [
      [102, 3],
      [104, 1],
    ];
    const d = computeDepth(bids, asks);
    expect(d.bestBid).toBe(100);
    expect(d.bestAsk).toBe(102);
    expect(d.mid).toBe(101);
    expect(d.spread).toBe(2);
    expect(d.maxCum).toBe(7); // bids cum 7 > asks cum 4
    expect(d.minPrice).toBe(99);
    expect(d.maxPrice).toBe(104);
    expect(d.bids.map((p) => p.cum)).toEqual([5, 7]);
    expect(d.asks.map((p) => p.cum)).toEqual([3, 4]);
  });

  it("leaves mid/spread undefined when a side is empty", () => {
    const onlyBids = computeDepth([[100, 5]], []);
    expect(onlyBids.bestBid).toBe(100);
    expect(onlyBids.bestAsk).toBeUndefined();
    expect(onlyBids.mid).toBeUndefined();
    expect(onlyBids.spread).toBeUndefined();
    expect(onlyBids.maxCum).toBe(5);
  });

  it("handles a fully empty book", () => {
    const d = computeDepth([], []);
    expect(d.bids).toEqual([]);
    expect(d.asks).toEqual([]);
    expect(d.maxCum).toBe(0);
    expect(d.mid).toBeUndefined();
    expect(d.minPrice).toBeUndefined();
    expect(d.maxPrice).toBeUndefined();
  });
});
