import { describe, expect, it } from "vitest";

import { newAccount, placeOrder, type PaperAccount } from "./paperEngine";
import {
  paperOrdersToBlotter,
  paperFillsToBlotter,
  paperPositionsToBlotter,
  buildPnlSummaryFromPaper,
} from "./paperBlotter";

const BTC = 1;
const ETH = 2;
const symName = (id: number) => (id === BTC ? "BTCUSDC" : id === ETH ? "ETHUSDC" : `#${id}`);

/** A small account: long 10 BTC @ 100 (market), plus one resting limit BUY. */
function seedAccount(): PaperAccount {
  let a = newAccount(100_000);
  a = placeOrder(a, { symbolId: BTC, side: "buy", type: "market", qty: 10 }, 100).account;
  // Resting limit BUY far below the market — stays working.
  a = placeOrder(a, { symbolId: ETH, side: "buy", type: "limit", price: 50, qty: 4 }, 100).account;
  return a;
}

describe("paperOrdersToBlotter", () => {
  it("emits only working orders as live blotter rows", () => {
    const a = seedAccount();
    const rows = paperOrdersToBlotter(a, symName);
    expect(rows).toHaveLength(1); // the market order filled; only the limit rests
    const r = rows[0]!;
    expect(r.sym).toBe("ETHUSDC");
    expect(r.side).toBe("B");
    expect(r.status).toBe("live");
    expect(r.px).toBe(50);
    expect(r.qty).toBe(4);
    expect(r.leaves).toBe(4);
    expect(r.cumQty).toBe(0);
    expect(r.source).toBe("PAPR");
  });

  it("returns no rows for a fresh account", () => {
    expect(paperOrdersToBlotter(newAccount(100_000), symName)).toHaveLength(0);
  });
});

describe("paperFillsToBlotter", () => {
  it("emits one filled row per fill, newest first", () => {
    let a = newAccount(100_000);
    a = placeOrder(a, { symbolId: BTC, side: "buy", type: "market", qty: 3 }, 100).account;
    a = placeOrder(a, { symbolId: BTC, side: "sell", type: "market", qty: 1 }, 110).account;
    const rows = paperFillsToBlotter(a, symName);
    expect(rows).toHaveLength(2);
    // newest (the sell) first
    expect(rows[0]!.side).toBe("S");
    expect(rows[0]!.px).toBe(110);
    expect(rows[0]!.cumQty).toBe(1);
    expect(rows[0]!.status).toBe("filled");
    expect(rows[1]!.side).toBe("B");
    expect(rows[1]!.px).toBe(100);
    expect(rows[0]!.sym).toBe("BTCUSDC");
  });
});

describe("paperPositionsToBlotter", () => {
  it("marks the position to a live price with correct uPnL + side", () => {
    const a = seedAccount(); // long 10 BTC @ 100
    const rows = paperPositionsToBlotter(a, { [BTC]: 120 }, symName);
    expect(rows).toHaveLength(1);
    const r = rows[0]!;
    expect(r.sym).toBe("BTCUSDC");
    expect(r.side).toBe("Long");
    expect(r.netQty).toBe(10);
    expect(r.avgCost).toBe(100);
    expect(r.markPx).toBe(120);
    expect(r.unrealized).toBe((120 - 100) * 10); // 200
  });

  it("contributes 0 uPnL and undefined mark when no mark is provided", () => {
    const a = seedAccount();
    const rows = paperPositionsToBlotter(a, {}, symName);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.markPx).toBeUndefined();
    expect(rows[0]!.unrealized).toBe(0);
  });

  it("sorts largest absolute exposure first", () => {
    let a = newAccount(100_000);
    a = placeOrder(a, { symbolId: BTC, side: "buy", type: "market", qty: 2 }, 100).account;
    a = placeOrder(a, { symbolId: ETH, side: "sell", type: "market", qty: 9 }, 50).account;
    const rows = paperPositionsToBlotter(a, { [BTC]: 100, [ETH]: 50 }, symName);
    expect(rows.map((r) => r.symbolId)).toEqual([ETH, BTC]);
    expect(rows[0]!.side).toBe("Short");
  });
});

describe("buildPnlSummaryFromPaper", () => {
  it("computes realized, unrealized, equity, and return%", () => {
    let a = newAccount(100_000);
    // Buy 10 @ 100 (cash 99,000), then sell 4 @ 110 -> realized (110-100)*4 = 40.
    a = placeOrder(a, { symbolId: BTC, side: "buy", type: "market", qty: 10 }, 100).account;
    a = placeOrder(a, { symbolId: BTC, side: "sell", type: "market", qty: 4 }, 110).account;
    const s = buildPnlSummaryFromPaper(a, { [BTC]: 120 }, symName);
    expect(s.realized).toBe(40);
    // remaining long 6 @ 100, mark 120 -> unreal (120-100)*6 = 120
    expect(s.unrealized).toBe(120);
    // cash = 100000 - 1000 (buy) + 440 (sell) = 99,440; equity = cash + 6*120 = 100,160
    expect(s.cash).toBe(99_440);
    expect(s.equity).toBe(99_440 + 6 * 120);
    expect(s.startingCash).toBe(100_000);
    expect(s.returnPct).toBeCloseTo(((s.equity - 100_000) / 100_000) * 100, 10);
    expect(s.perSymbol).toHaveLength(1);
    expect(s.perSymbol[0]!.netQty).toBe(6);
  });
});
