import { describe, it, expect } from "vitest";
import {
  computeLots,
  realizedSummary,
  unrealized,
  lotsToCsv,
  holdingDaysBetween,
  type TaxFill,
} from "./taxLots";

// Timestamps as unix SECONDS. day(n) = n days after a fixed epoch.
const T0 = 1_600_000_000; // 2020-09-13
const DAY = 86_400;
const day = (n: number): number => T0 + n * DAY;

const buy = (symbol: string, qty: number, priceCents: number, ts: number, feeCents = 0): TaxFill => ({
  ts,
  symbol,
  side: "buy",
  qty,
  priceCents,
  feeCents,
});
const sell = (symbol: string, qty: number, priceCents: number, ts: number, feeCents = 0): TaxFill => ({
  ts,
  symbol,
  side: "sell",
  qty,
  priceCents,
  feeCents,
});

describe("holdingDaysBetween", () => {
  it("counts whole days and clamps negatives to 0", () => {
    expect(holdingDaysBetween(day(0), day(10))).toBe(10);
    expect(holdingDaysBetween(day(10), day(0))).toBe(0);
    expect(holdingDaysBetween(day(0), day(0))).toBe(0);
  });
  it("handles ms timestamps too", () => {
    expect(holdingDaysBetween(day(0) * 1000, day(5) * 1000)).toBe(5);
  });
});

describe("computeLots — empty / edge", () => {
  it("empty fills → empty result", () => {
    const r = computeLots([], "fifo");
    expect(r.openLots).toEqual([]);
    expect(r.realized).toEqual([]);
    expect(r.warnings).toEqual([]);
  });

  it("zero-qty fill is skipped + flagged", () => {
    const r = computeLots([buy("BTC", 0, 100, day(0))], "fifo");
    expect(r.openLots).toEqual([]);
    expect(r.warnings.length).toBe(1);
  });

  it("sell before any buy is skipped + flagged (no negative lot)", () => {
    const r = computeLots([sell("BTC", 5, 100, day(1))], "fifo");
    expect(r.realized).toEqual([]);
    expect(r.openLots).toEqual([]);
    expect(r.warnings.some((w) => /no open position/.test(w))).toBe(true);
  });

  it("oversell closes what it can + flags the excess", () => {
    const r = computeLots([buy("BTC", 3, 100, day(0)), sell("BTC", 5, 120, day(1))], "fifo");
    expect(r.realized.length).toBe(1);
    expect(r.realized[0]!.qty).toBe(3);
    expect(r.openLots).toEqual([]);
    expect(r.warnings.some((w) => /Oversell/.test(w))).toBe(true);
  });
});

describe("computeLots — FIFO", () => {
  it("matches oldest lot first and computes gain net of fees", () => {
    const fills = [
      buy("BTC", 10, 100, day(0), 10), // basis 1000 + 10 fee = 1010
      buy("BTC", 10, 200, day(30), 10), // basis 2000 + 10 = 2010
      sell("BTC", 10, 300, day(400), 20), // proceeds 3000 - 20 fee = 2980
    ];
    const r = computeLots(fills, "fifo");
    expect(r.realized.length).toBe(1);
    const lot = r.realized[0]!;
    // FIFO closes the first (day0) lot: cost 1010, proceeds 2980.
    expect(lot.costBasisCents).toBe(1010);
    expect(lot.proceedsCents).toBe(2980);
    expect(lot.gainCents).toBe(1970);
    // held 400 days > 365 → long
    expect(lot.term).toBe("long");
    // remaining open = the day30 lot
    expect(r.openLots.length).toBe(1);
    expect(r.openLots[0]!.qty).toBe(10);
    expect(r.openLots[0]!.costBasisCents).toBe(2010);
  });

  it("short-term when held <= 365 days", () => {
    const r = computeLots([buy("ETH", 1, 100, day(0)), sell("ETH", 1, 150, day(100))], "fifo");
    expect(r.realized[0]!.term).toBe("short");
    expect(r.realized[0]!.holdingDays).toBe(100);
  });

  it("partial close splits a lot", () => {
    const r = computeLots([buy("BTC", 10, 100, day(0)), sell("BTC", 4, 150, day(10))], "fifo");
    expect(r.realized[0]!.qty).toBe(4);
    // 4/10 of basis 1000 = 400
    expect(r.realized[0]!.costBasisCents).toBe(400);
    expect(r.openLots[0]!.qty).toBe(6);
    expect(r.openLots[0]!.costBasisCents).toBe(600);
  });
});

describe("computeLots — LIFO", () => {
  it("matches the newest lot first", () => {
    const fills = [
      buy("BTC", 10, 100, day(0)), // basis 1000
      buy("BTC", 10, 200, day(30)), // basis 2000
      sell("BTC", 10, 300, day(40)),
    ];
    const r = computeLots(fills, "lifo");
    // LIFO closes the day30 (200) lot: cost 2000
    expect(r.realized[0]!.costBasisCents).toBe(2000);
    expect(r.openLots[0]!.costBasisCents).toBe(1000);
    expect(r.openLots[0]!.openTs).toBe(day(0));
  });
});

describe("computeLots — average cost", () => {
  it("pools basis across buys and closes at the average", () => {
    const fills = [
      buy("BTC", 10, 100, day(0)), // basis 1000
      buy("BTC", 10, 200, day(30)), // basis 2000 → pool 20 @ avg 150
      sell("BTC", 10, 300, day(40)), // proceeds 3000
    ];
    const r = computeLots(fills, "avg");
    // avg unit basis = 3000/20 = 150 → matched 10*150 = 1500
    expect(r.realized[0]!.costBasisCents).toBe(1500);
    expect(r.realized[0]!.gainCents).toBe(1500);
    // remaining 10 @ avg → basis 1500
    expect(r.openLots.length).toBe(1);
    expect(r.openLots[0]!.qty).toBe(10);
    expect(r.openLots[0]!.costBasisCents).toBe(1500);
  });
});

describe("realizedSummary", () => {
  it("splits short vs long and totals by symbol", () => {
    const fills = [
      buy("BTC", 1, 100, day(0)),
      sell("BTC", 1, 200, day(400)), // long, +100
      buy("ETH", 1, 100, day(0)),
      sell("ETH", 1, 50, day(10)), // short, -50
    ];
    const r = computeLots(fills, "fifo");
    const s = realizedSummary(r.realized);
    expect(s.totalGainCents).toBe(50);
    expect(s.byTerm.longCents).toBe(100);
    expect(s.byTerm.shortCents).toBe(-50);
    const btc = s.bySymbol.find((x) => x.symbol === "BTC")!;
    expect(btc.gainCents).toBe(100);
    expect(btc.proceedsCents).toBe(200);
  });

  it("empty realized → zeros", () => {
    const s = realizedSummary([]);
    expect(s.totalGainCents).toBe(0);
    expect(s.byTerm).toEqual({ shortCents: 0, longCents: 0 });
    expect(s.bySymbol).toEqual([]);
  });
});

describe("unrealized", () => {
  it("values open lots at the mark", () => {
    const openLots = [
      { symbol: "BTC", openTs: day(0), qty: 10, costBasisCents: 1000 },
      { symbol: "ETH", openTs: day(0), qty: 5, costBasisCents: 500 },
    ];
    const rows = unrealized(openLots, { BTC: 150, ETH: 80 });
    const btc = rows.find((r) => r.symbol === "BTC")!;
    expect(btc.marketValueCents).toBe(1500);
    expect(btc.unrealizedCents).toBe(500);
    const eth = rows.find((r) => r.symbol === "ETH")!;
    expect(eth.marketValueCents).toBe(400);
    expect(eth.unrealizedCents).toBe(-100);
  });

  it("flags symbols with no mark and reports zero value", () => {
    const rows = unrealized([{ symbol: "SOL", openTs: day(0), qty: 3, costBasisCents: 300 }], {});
    expect(rows[0]!.noMark).toBe(true);
    expect(rows[0]!.marketValueCents).toBe(0);
    expect(rows[0]!.unrealizedCents).toBe(0);
  });

  it("aggregates multiple open lots of the same symbol", () => {
    const rows = unrealized(
      [
        { symbol: "BTC", openTs: day(0), qty: 5, costBasisCents: 500 },
        { symbol: "BTC", openTs: day(30), qty: 5, costBasisCents: 1000 },
      ],
      { BTC: 200 },
    );
    expect(rows.length).toBe(1);
    expect(rows[0]!.qty).toBe(10);
    expect(rows[0]!.costBasisCents).toBe(1500);
    expect(rows[0]!.marketValueCents).toBe(2000);
    expect(rows[0]!.unrealizedCents).toBe(500);
  });
});

describe("lotsToCsv", () => {
  it("emits a header + one row per realized lot with ISO times", () => {
    const r = computeLots([buy("BTC", 1, 10000, day(0)), sell("BTC", 1, 20000, day(400), 100)], "fifo");
    const csv = lotsToCsv(r.realized);
    const lines = csv.split("\n");
    expect(lines[0]!).toContain("Symbol");
    expect(lines[0]!).toContain("Term");
    expect(lines.length).toBe(2);
    expect(lines[1]!).toContain("BTC");
    expect(lines[1]!).toContain("long");
    // gain = (20000-100) - 10000 = 9900 cents = 99.00
    expect(lines[1]!).toContain("99.00");
  });

  it("empty realized → header only", () => {
    expect(lotsToCsv([]).split("\n").length).toBe(1);
  });
});
