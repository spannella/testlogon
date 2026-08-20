import { describe, expect, it } from "vitest";

import {
  newAccount,
  placeOrder,
  onTick,
  cancelOrder,
  resetAccount,
  unrealized,
  equity,
  positionMtm,
  DEFAULT_STARTING_CASH,
  type PaperAccount,
} from "./paperEngine";

const SYM = 1;

describe("newAccount", () => {
  it("seeds cash + startingCash and is empty", () => {
    const a = newAccount(100_000);
    expect(a.cash).toBe(100_000);
    expect(a.startingCash).toBe(100_000);
    expect(a.realizedPnl).toBe(0);
    expect(a.orders).toHaveLength(0);
    expect(a.fills).toHaveLength(0);
    expect(Object.keys(a.positions)).toHaveLength(0);
  });
  it("defaults + guards bad input", () => {
    expect(newAccount().cash).toBe(DEFAULT_STARTING_CASH);
    expect(newAccount(-5).cash).toBe(DEFAULT_STARTING_CASH);
    expect(newAccount(0).cash).toBe(DEFAULT_STARTING_CASH);
    expect(newAccount(NaN).cash).toBe(DEFAULT_STARTING_CASH);
  });
});

describe("market orders", () => {
  it("buy market fills immediately, moves cash + opens long", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order, fill } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "market", qty: 10 },
      100,
    );
    expect(order.status).toBe("filled");
    expect(fill).toBeDefined();
    expect(fill!.price).toBe(100);
    expect(fill!.qty).toBe(10);
    expect(a1.cash).toBe(100_000 - 100 * 10);
    expect(a1.positions[SYM]).toEqual({ qty: 10, avgEntry: 100 });
    expect(a1.realizedPnl).toBe(0);
    // Immutability: original untouched.
    expect(a0.cash).toBe(100_000);
    expect(a0.positions[SYM]).toBeUndefined();
  });

  it("sell market with no position opens a short and adds cash", () => {
    const a0 = newAccount(100_000);
    const { account: a1 } = placeOrder(
      a0,
      { symbolId: SYM, side: "sell", type: "market", qty: 5 },
      200,
    );
    expect(a1.cash).toBe(100_000 + 200 * 5);
    expect(a1.positions[SYM]).toEqual({ qty: -5, avgEntry: 200 });
  });

  it("market order with no market price is cancelled, no state change", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "market", qty: 5 },
      undefined,
    );
    expect(order.status).toBe("cancelled");
    expect(a1.cash).toBe(100_000);
    expect(a1.positions[SYM]).toBeUndefined();
  });

  it("non-positive qty is rejected", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "market", qty: 0 },
      100,
    );
    expect(order.status).toBe("cancelled");
    expect(a1.cash).toBe(100_000);
  });
});

describe("limit orders", () => {
  it("buy limit BELOW market rests as working", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order, fill } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "limit", price: 90, qty: 3 },
      100,
    );
    expect(order.status).toBe("working");
    expect(fill).toBeUndefined();
    expect(a1.cash).toBe(100_000);
    expect(a1.positions[SYM]).toBeUndefined();
  });

  it("buy limit AT/ABOVE market crosses and fills at the limit price", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order, fill } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "limit", price: 110, qty: 2 },
      100,
    );
    expect(order.status).toBe("filled");
    expect(fill!.price).toBe(110);
    expect(a1.cash).toBe(100_000 - 110 * 2);
    expect(a1.positions[SYM]).toEqual({ qty: 2, avgEntry: 110 });
  });

  it("sell limit ABOVE market rests as working", () => {
    const a0 = newAccount(100_000);
    const { order } = placeOrder(
      a0,
      { symbolId: SYM, side: "sell", type: "limit", price: 120, qty: 2 },
      100,
    );
    expect(order.status).toBe("working");
  });

  it("sell limit AT/BELOW market crosses and fills", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order, fill } = placeOrder(
      a0,
      { symbolId: SYM, side: "sell", type: "limit", price: 90, qty: 2 },
      100,
    );
    expect(order.status).toBe("filled");
    expect(fill!.price).toBe(90);
    expect(a1.positions[SYM]).toEqual({ qty: -2, avgEntry: 90 });
  });
});

describe("onTick — fills working orders as the market moves", () => {
  it("buy limit does NOT fill until price drops to/below the limit", () => {
    const a0 = newAccount(100_000);
    const { account: a1 } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "limit", price: 90, qty: 4 },
      100,
    );
    // Still above -> no fill.
    const a2 = onTick(a1, SYM, 95);
    expect(a2.positions[SYM]).toBeUndefined();
    expect(a2.orders[0]?.status).toBe("working");
    // Price crosses down -> fills at the limit (90), not the tick (89).
    const a3 = onTick(a2, SYM, 89);
    expect(a3.positions[SYM]).toEqual({ qty: 4, avgEntry: 90 });
    expect(a3.cash).toBe(100_000 - 90 * 4);
    expect(a3.orders[0]?.status).toBe("filled");
  });

  it("sell limit fills when price rises to/above the limit", () => {
    const a0 = newAccount(100_000);
    const { account: a1 } = placeOrder(
      a0,
      { symbolId: SYM, side: "sell", type: "limit", price: 120, qty: 3 },
      100,
    );
    const a2 = onTick(a1, SYM, 119);
    expect(a2.positions[SYM]).toBeUndefined();
    const a3 = onTick(a2, SYM, 125);
    expect(a3.positions[SYM]).toEqual({ qty: -3, avgEntry: 120 });
    expect(a3.orders[0]?.status).toBe("filled");
  });

  it("only ticks the matching symbol and ignores non-working orders", () => {
    const a0 = newAccount(100_000);
    const { account: a1 } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "limit", price: 90, qty: 4 },
      100,
    );
    const untouched = onTick(a1, 999, 50);
    expect(untouched).toBe(a1); // no working order for that symbol -> same ref
  });
});

describe("average-cost + realized PnL", () => {
  it("weighted-averages entry when adding to a long", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: SYM, side: "buy", type: "market", qty: 10 }, 100).account;
    a = placeOrder(a, { symbolId: SYM, side: "buy", type: "market", qty: 10 }, 200).account;
    // (100*10 + 200*10)/20 = 150
    expect(a.positions[SYM]).toEqual({ qty: 20, avgEntry: 150 });
  });

  it("realizes PnL on a partial close, keeps avgEntry", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: SYM, side: "buy", type: "market", qty: 10 }, 100).account;
    a = placeOrder(a, { symbolId: SYM, side: "sell", type: "market", qty: 4 }, 150).account;
    // realized = (150-100)*4 = 200
    expect(a.realizedPnl).toBe(200);
    expect(a.positions[SYM]).toEqual({ qty: 6, avgEntry: 100 });
    const lastFill = a.fills[a.fills.length - 1];
    expect(lastFill?.realized).toBe(200);
  });

  it("realizes on a full close and goes flat", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: SYM, side: "buy", type: "market", qty: 10 }, 100).account;
    a = placeOrder(a, { symbolId: SYM, side: "sell", type: "market", qty: 10 }, 130).account;
    expect(a.realizedPnl).toBe((130 - 100) * 10);
    expect(a.positions[SYM]).toBeUndefined();
  });

  it("flips long -> short cleanly, realizing only the closed leg", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: SYM, side: "buy", type: "market", qty: 10 }, 100).account;
    // Sell 15 at 120: close 10 (realize (120-100)*10=200) + open short 5 @ 120.
    a = placeOrder(a, { symbolId: SYM, side: "sell", type: "market", qty: 15 }, 120).account;
    expect(a.realizedPnl).toBe(200);
    expect(a.positions[SYM]).toEqual({ qty: -5, avgEntry: 120 });
  });

  it("realizes profit on covering a short", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: SYM, side: "sell", type: "market", qty: 10 }, 200).account;
    // Buy back 10 at 150: short profit (200-150)*10 = 500.
    a = placeOrder(a, { symbolId: SYM, side: "buy", type: "market", qty: 10 }, 150).account;
    expect(a.realizedPnl).toBe(500);
    expect(a.positions[SYM]).toBeUndefined();
  });
});

describe("unrealized / equity / positionMtm", () => {
  it("unrealized reflects mark vs avg entry (long & short)", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: 1, side: "buy", type: "market", qty: 10 }, 100).account;
    a = placeOrder(a, { symbolId: 2, side: "sell", type: "market", qty: 5 }, 200).account;
    // long: (150-100)*10 = 500 ; short: (180-200)*-5 = 100
    const marks = { 1: 150, 2: 180 };
    expect(unrealized(a, marks)).toBe(600);
  });

  it("equity = cash + Σ position MTM", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: 1, side: "buy", type: "market", qty: 10 }, 100).account;
    // cash = 1,000,000 - 1000 = 999,000 ; MTM at 150 = 1500 ; equity = 1,000,500
    expect(equity(a, { 1: 150 })).toBe(1_000_500);
  });

  it("positions without a mark contribute 0", () => {
    let a: PaperAccount = newAccount(1_000_000);
    a = placeOrder(a, { symbolId: 1, side: "buy", type: "market", qty: 10 }, 100).account;
    expect(unrealized(a, {})).toBe(0);
    expect(equity(a, {})).toBe(a.cash);
  });

  it("positionMtm handles flat / missing mark", () => {
    expect(positionMtm({ qty: 0, avgEntry: 0 }, 100)).toBe(0);
    expect(positionMtm({ qty: 5, avgEntry: 10 }, undefined)).toBe(0);
    expect(positionMtm({ qty: 5, avgEntry: 10 }, 20)).toBe(100);
  });
});

describe("cancelOrder", () => {
  it("cancels a working order and stops it filling on tick", () => {
    const a0 = newAccount(100_000);
    const { account: a1, order } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "limit", price: 90, qty: 4 },
      100,
    );
    const a2 = cancelOrder(a1, order.id);
    expect(a2.orders[0]?.status).toBe("cancelled");
    const a3 = onTick(a2, SYM, 80);
    expect(a3.positions[SYM]).toBeUndefined();
  });

  it("no-op for unknown / already-terminal orders", () => {
    const a0 = newAccount(100_000);
    expect(cancelOrder(a0, "nope")).toBe(a0);
    const { account: a1, order } = placeOrder(
      a0,
      { symbolId: SYM, side: "buy", type: "market", qty: 1 },
      100,
    );
    expect(cancelOrder(a1, order.id)).toBe(a1); // filled -> unchanged
  });
});

describe("resetAccount", () => {
  it("returns a fresh empty account with the given starting cash", () => {
    const a = resetAccount(50_000);
    expect(a.cash).toBe(50_000);
    expect(a.startingCash).toBe(50_000);
    expect(a.orders).toHaveLength(0);
    expect(a.fills).toHaveLength(0);
  });
  it("defaults when no cash passed", () => {
    expect(resetAccount().cash).toBe(DEFAULT_STARTING_CASH);
  });
});
