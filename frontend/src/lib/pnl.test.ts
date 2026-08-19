import { describe, expect, it } from "vitest";

import {
  computePnl,
  walkSymbolFills,
  buildEquityCurve,
  type PnlFill,
} from "./pnl";

/** Build a fill with sane defaults. */
function fill(p: Partial<PnlFill> & Pick<PnlFill, "price" | "qty" | "side" | "ts">): PnlFill {
  return { symbolid: 1, fee: 0, ...p };
}

describe("walkSymbolFills — average-cost realized PnL", () => {
  it("realizes a simple long round-trip (buy low, sell high)", () => {
    const fills: PnlFill[] = [
      fill({ price: 100, qty: 10, side: "buy", ts: 1 }),
      fill({ price: 120, qty: 10, side: "sell", ts: 2 }),
    ];
    const { realized, realizedPerClose, volume } = walkSymbolFills(fills);
    // (120 - 100) * 10 = 200
    expect(realized).toBe(200);
    expect(realizedPerClose).toEqual([200]);
    // |100*10| + |120*10| = 2200
    expect(volume).toBe(2200);
  });

  it("realizes a short round-trip (sell high, buy back low)", () => {
    const fills: PnlFill[] = [
      fill({ price: 120, qty: 5, side: "sell", ts: 1 }),
      fill({ price: 100, qty: 5, side: "buy", ts: 2 }),
    ];
    const { realized, realizedPerClose } = walkSymbolFills(fills);
    // short: (100 - 120) * 5 * (-1) = 100
    expect(realized).toBe(100);
    expect(realizedPerClose).toEqual([100]);
  });

  it("weighted-averages the entry when adding to a position", () => {
    const fills: PnlFill[] = [
      fill({ price: 100, qty: 10, side: "buy", ts: 1 }),
      fill({ price: 200, qty: 10, side: "buy", ts: 2 }), // avg entry -> 150
      fill({ price: 180, qty: 20, side: "sell", ts: 3 }), // (180-150)*20 = 600
    ];
    const { realized } = walkSymbolFills(fills);
    expect(realized).toBe(600);
  });

  it("handles a partial close then a flip", () => {
    const fills: PnlFill[] = [
      fill({ price: 100, qty: 10, side: "buy", ts: 1 }), // long 10 @ 100
      fill({ price: 130, qty: 15, side: "sell", ts: 2 }), // close 10 -> +300, then short 5 @ 130
      fill({ price: 110, qty: 5, side: "buy", ts: 3 }), // cover short 5: (110-130)*5*-1 = +100
    ];
    const { realized, realizedPerClose } = walkSymbolFills(fills);
    expect(realizedPerClose).toEqual([300, 100]);
    expect(realized).toBe(400);
  });

  it("sorts fills oldest->newest by ts regardless of input order", () => {
    const fills: PnlFill[] = [
      fill({ price: 120, qty: 10, side: "sell", ts: 2 }),
      fill({ price: 100, qty: 10, side: "buy", ts: 1 }),
    ];
    const { realized } = walkSymbolFills(fills);
    expect(realized).toBe(200);
  });
});

describe("computePnl — net realized, win rate, fees, funding, liquidations", () => {
  it("nets fees, funding and liquidation pnl/fees into net realized", () => {
    const fills: PnlFill[] = [
      fill({ symbolid: 1, price: 100, qty: 10, side: "buy", ts: 1, fee: 5 }),
      fill({ symbolid: 1, price: 120, qty: 10, side: "sell", ts: 2, fee: 6 }),
    ];
    const funding = [{ symbolid: 1, payment: -8, ts: 3 }]; // paid 8
    const liquidations = [{ symbolid: 1, realized_pnl: 50, fee: 4, ts: 4 }];

    const s = computePnl(fills, funding, liquidations);

    expect(s.totalRealized).toBe(200);
    expect(s.totalFees).toBe(11);
    expect(s.totalFunding).toBe(-8);
    expect(s.totalLiquidationPnl).toBe(50);
    expect(s.totalLiquidationFees).toBe(4);
    // 200 - 11 + (-8) + 50 - 4 = 227
    expect(s.netRealized).toBe(227);
    expect(s.tradeCount).toBe(2);
    expect(s.totalVolume).toBe(2200);
  });

  it("computes win rate over position-closing trades", () => {
    // Symbol 1: one winning close. Symbol 2: one losing close.
    const fills: PnlFill[] = [
      fill({ symbolid: 1, price: 100, qty: 10, side: "buy", ts: 1 }),
      fill({ symbolid: 1, price: 120, qty: 10, side: "sell", ts: 2 }), // +200 win
      fill({ symbolid: 2, price: 100, qty: 10, side: "buy", ts: 3 }),
      fill({ symbolid: 2, price: 90, qty: 10, side: "sell", ts: 4 }), // -100 loss
    ];
    const s = computePnl(fills);
    expect(s.closeCount).toBe(2);
    expect(s.winCount).toBe(1);
    expect(s.winRate).toBe(0.5);
    expect(s.perSymbol).toHaveLength(2);
  });

  it("returns a zero-ish summary and 0 win rate for empty feeds", () => {
    const s = computePnl();
    expect(s.perSymbol).toEqual([]);
    expect(s.netRealized).toBe(0);
    expect(s.winRate).toBe(0);
    expect(s.closeCount).toBe(0);
    expect(s.equityCurve).toEqual([]);
  });
});

describe("buildEquityCurve — cumulative, time-ordered", () => {
  it("accumulates realized-minus-fees across events in ts order", () => {
    const fills: PnlFill[] = [
      fill({ symbolid: 1, price: 100, qty: 10, side: "buy", ts: 1, fee: 2 }),
      fill({ symbolid: 1, price: 120, qty: 10, side: "sell", ts: 3, fee: 3 }),
    ];
    const funding = [{ symbolid: 1, payment: 5, ts: 2 }];
    const curve = buildEquityCurve(fills, funding);

    // ts=1 open: realized 0 - fee 2 = -2
    // ts=2 funding: +5 -> 3
    // ts=3 close: +200 - fee 3 -> 200 => 3 + 197 = 200
    expect(curve.map((p) => p.ts)).toEqual([1, 2, 3]);
    expect(curve.map((p) => p.value)).toEqual([-2, 3, 200]);
  });
});
