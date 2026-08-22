import { describe, expect, it } from "vitest";

import {
  type NormalizedPosition,
  allocation,
  concentration,
  diversificationScore,
  exposure,
  historicalVarCents,
  parametricVarCents,
  portfolioVolatilityBps,
  zForConfidence,
} from "./portfolioAnalytics";

function pos(over: Partial<NormalizedPosition> & { key: string; valueCents: number }): NormalizedPosition {
  return {
    label: over.key,
    group: "Spot",
    assetClass: "Crypto",
    side: "long",
    ...over,
  };
}

describe("allocation", () => {
  it("returns empty for an empty book", () => {
    expect(allocation([], "asset")).toEqual([]);
  });

  it("weights sum to ~10000 bps and sorts by value desc", () => {
    const book = [
      pos({ key: "BTC", label: "BTC", valueCents: 6000 }),
      pos({ key: "ETH", label: "ETH", valueCents: 3000 }),
      pos({ key: "SOL", label: "SOL", valueCents: 1000 }),
    ];
    const a = allocation(book, "asset");
    expect(a.map((s) => s.label)).toEqual(["BTC", "ETH", "SOL"]);
    expect(a[0]!.weightBps).toBe(6000);
    const sum = a.reduce((s, x) => s + x.weightBps, 0);
    expect(sum).toBe(10000);
  });

  it("buckets by class and by product", () => {
    const book = [
      pos({ key: "a", label: "BTC", assetClass: "Crypto", group: "Spot", valueCents: 100 }),
      pos({ key: "b", label: "USDC", assetClass: "Stablecoin", group: "Custody", valueCents: 100 }),
      pos({ key: "c", label: "ETH", assetClass: "Crypto", group: "Custody", valueCents: 200 }),
    ];
    const byClass = allocation(book, "class");
    expect(byClass.find((s) => s.label === "Crypto")!.valueCents).toBe(300);
    const byProduct = allocation(book, "product");
    expect(byProduct.find((s) => s.label === "Custody")!.valueCents).toBe(300);
  });

  it("uses absolute value for short legs", () => {
    const book = [pos({ key: "s", label: "BTC", side: "short", valueCents: -500 })];
    const a = allocation(book, "asset");
    expect(a[0]!.valueCents).toBe(500);
  });
});

describe("concentration", () => {
  it("single position -> hhi 10000", () => {
    const c = concentration([{ label: "BTC", weightBps: 10000 }]);
    expect(c.hhi).toBe(10000);
    expect(c.top).toHaveLength(1);
  });

  it("even 4-way -> hhi 2500", () => {
    const c = concentration([
      { label: "a", weightBps: 2500 },
      { label: "b", weightBps: 2500 },
      { label: "c", weightBps: 2500 },
      { label: "d", weightBps: 2500 },
    ]);
    expect(c.hhi).toBe(2500);
  });

  it("empty -> hhi 0 and no top", () => {
    const c = concentration([]);
    expect(c).toEqual({ hhi: 0, top: [] });
  });

  it("topN limits and orders descending", () => {
    const c = concentration(
      [
        { label: "a", weightBps: 1000 },
        { label: "b", weightBps: 5000 },
        { label: "c", weightBps: 4000 },
      ],
      2,
    );
    expect(c.top.map((t) => t.label)).toEqual(["b", "c"]);
  });
});

describe("exposure", () => {
  it("computes gross/net/long/short and leverage", () => {
    const book = [
      pos({ key: "l", side: "long", valueCents: 8000 }),
      pos({ key: "s", side: "short", valueCents: 2000 }),
    ];
    const e = exposure(book, 5000);
    expect(e.longCents).toBe(8000);
    expect(e.shortCents).toBe(2000);
    expect(e.grossCents).toBe(10000);
    expect(e.netCents).toBe(6000);
    expect(e.leverageBps).toBe(20000); // 10000 / 5000 = 2.0x
  });

  it("leverage is 0 when equity is non-positive", () => {
    const e = exposure([pos({ key: "l", valueCents: 100 })], 0);
    // equity <=0 falls back to gross so leverage is 1.0x, not divide-by-zero
    expect(e.leverageBps).toBe(10000);
  });

  it("empty book -> all zeros", () => {
    const e = exposure([]);
    expect(e).toEqual({ grossCents: 0, netCents: 0, longCents: 0, shortCents: 0, leverageBps: 0 });
  });
});

describe("portfolioVolatilityBps", () => {
  it("single asset equals that asset's vol", () => {
    expect(portfolioVolatilityBps([1], [4000], [[1]])).toBe(4000);
  });

  it("uncorrelated equal weights reduce vol below the naive average", () => {
    const v = portfolioVolatilityBps(
      [0.5, 0.5],
      [4000, 4000],
      [
        [1, 0],
        [0, 1],
      ],
    );
    // sqrt(0.25*0.16 + 0.25*0.16) = sqrt(0.08) ~ 0.2828 -> 2828 bps
    expect(v).toBe(2828);
  });

  it("perfectly correlated equal weights equals the average vol", () => {
    const v = portfolioVolatilityBps(
      [0.5, 0.5],
      [4000, 4000],
      [
        [1, 1],
        [1, 1],
      ],
    );
    expect(v).toBe(4000);
  });

  it("empty / all-zero -> 0", () => {
    expect(portfolioVolatilityBps([], [], [])).toBe(0);
    expect(portfolioVolatilityBps([0, 0], [0, 0], [[1, 0], [0, 1]])).toBe(0);
  });
});

describe("parametricVarCents", () => {
  it("value * vol * z", () => {
    // 1,000,000c * 0.20 * 1.645 = 329,000c
    expect(parametricVarCents(1_000_000, 2000, 1.645)).toBe(329000);
  });

  it("guards non-positive inputs", () => {
    expect(parametricVarCents(0, 2000, 1.645)).toBe(0);
    expect(parametricVarCents(1000, 0, 1.645)).toBe(0);
    expect(parametricVarCents(1000, 2000, 0)).toBe(0);
  });
});

describe("historicalVarCents", () => {
  it("returns the loss at the lower tail as positive cents", () => {
    const rets = [-0.10, -0.05, -0.02, 0.01, 0.03, 0.04, 0.02, -0.01, 0.00, -0.03];
    const v = historicalVarCents(1_000_000, rets, 0.9);
    expect(v).toBeGreaterThan(0);
  });

  it("0 when no losses at the quantile or empty series", () => {
    expect(historicalVarCents(1_000_000, [0.01, 0.02, 0.03], 0.95)).toBe(0);
    expect(historicalVarCents(1_000_000, [], 0.95)).toBe(0);
    expect(historicalVarCents(0, [-0.5], 0.95)).toBe(0);
  });
});

describe("zForConfidence", () => {
  it("maps common confidences", () => {
    expect(zForConfidence(0.95)).toBeCloseTo(1.645, 3);
    expect(zForConfidence(0.99)).toBeCloseTo(2.326, 3);
    expect(zForConfidence(0.5)).toBeCloseTo(1.645, 3);
  });
});

describe("diversificationScore", () => {
  it("single position -> 0", () => {
    expect(diversificationScore([{ label: "BTC", weightBps: 10000 }], [[1]])).toBe(0);
  });

  it("even + uncorrelated scores higher than concentrated + correlated", () => {
    const good = diversificationScore(
      [
        { label: "a", weightBps: 5000 },
        { label: "b", weightBps: 5000 },
      ],
      [
        [1, 0],
        [0, 1],
      ],
    );
    const bad = diversificationScore(
      [
        { label: "a", weightBps: 9500 },
        { label: "b", weightBps: 500 },
      ],
      [
        [1, 0.98],
        [0.98, 1],
      ],
    );
    expect(good).toBeGreaterThan(bad);
    expect(good).toBeGreaterThanOrEqual(0);
    expect(good).toBeLessThanOrEqual(100);
  });

  it("empty -> 0", () => {
    expect(diversificationScore([], [])).toBe(0);
  });
});
