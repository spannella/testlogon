import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  addPriceAlert,
  alertCrossed,
  alertLabel,
  evaluate,
  loadPriceAlerts,
  parseCentsToInt,
  parsePriceToTicks,
  PRICE_ALERTS_KEY,
  subjectFallbackName,
  subjectKindLabel,
  type PriceAlert,
} from "@/lib/priceAlerts";

function makeAlert(over: Partial<PriceAlert>): PriceAlert {
  return {
    id: "a1",
    subjectKind: "symbol",
    subjectId: "1",
    field: "price",
    symbolId: 1,
    direction: "above",
    price: 65000,
    createdTs: 0,
    triggeredTs: null,
    armed: true,
    ...over,
  };
}

describe("evaluate (pure price-alert level trigger)", () => {
  it("above: does NOT fire while price is below the threshold", () => {
    const a = makeAlert({ direction: "above", price: 65000 });
    expect(evaluate(a, 64999)).toBe(false);
  });

  it("above: fires when price reaches / crosses the threshold", () => {
    const a = makeAlert({ direction: "above", price: 65000 });
    expect(evaluate(a, 65000)).toBe(true); // exactly at
    expect(evaluate(a, 65001)).toBe(true); // above
  });

  it("below: does NOT fire while price is above the threshold", () => {
    const a = makeAlert({ direction: "below", price: 3000 });
    expect(evaluate(a, 3001)).toBe(false);
  });

  it("below: fires when price reaches / crosses down through the threshold", () => {
    const a = makeAlert({ direction: "below", price: 3000 });
    expect(evaluate(a, 3000)).toBe(true); // exactly at
    expect(evaluate(a, 2999)).toBe(true); // below
  });

  it("one-shot: a disarmed (already-fired) alert never fires again", () => {
    const fired = makeAlert({ direction: "above", price: 65000, armed: false, triggeredTs: 123 });
    expect(evaluate(fired, 66000)).toBe(false);
    expect(evaluate(fired, 70000)).toBe(false);
  });

  it("re-arm: re-arming lets the alert fire again", () => {
    const rearmed = makeAlert({ direction: "above", price: 65000, armed: true, triggeredTs: null });
    expect(evaluate(rearmed, 65000)).toBe(true);
  });

  it("ignores non-finite prices", () => {
    const a = makeAlert({ direction: "above", price: 65000 });
    expect(evaluate(a, Number.NaN)).toBe(false);
    expect(evaluate(a, Number.POSITIVE_INFINITY)).toBe(false);
  });

  it("full lifecycle: armed->fires->disarm(one-shot)->re-arm->fires", () => {
    let a = makeAlert({ direction: "above", price: 65000, armed: true });
    expect(evaluate(a, 64000)).toBe(false);
    expect(evaluate(a, 65500)).toBe(true);
    a = { ...a, armed: false, triggeredTs: Date.now() };
    expect(evaluate(a, 66000)).toBe(false);
    a = { ...a, armed: true, triggeredTs: null };
    expect(evaluate(a, 66000)).toBe(true);
  });

  it("evaluates token (cents) and strategy (nav-cents) subjects the same way", () => {
    const tok = makeAlert({ subjectKind: "token", field: "price", direction: "above", price: 12_50 });
    expect(evaluate(tok, 12_49)).toBe(false);
    expect(evaluate(tok, 12_50)).toBe(true);
    const strat = makeAlert({ subjectKind: "strategy", field: "nav", direction: "below", price: 10_00 });
    expect(evaluate(strat, 10_01)).toBe(false);
    expect(evaluate(strat, 9_99)).toBe(true);
  });
});

describe("alertCrossed (pure edge trigger)", () => {
  it("above: fires only on the transition across the threshold", () => {
    expect(alertCrossed(64999, 65001, "above", 65000)).toBe(true); // crossed up
    expect(alertCrossed(65001, 65002, "above", 65000)).toBe(false); // already above
    expect(alertCrossed(64000, 64999, "above", 65000)).toBe(false); // still below
  });

  it("above: exact-touch of the threshold counts as a cross", () => {
    expect(alertCrossed(64999, 65000, "above", 65000)).toBe(true);
    expect(alertCrossed(65000, 65001, "above", 65000)).toBe(false); // prev already met
  });

  it("below: fires only on the transition down across the threshold", () => {
    expect(alertCrossed(3001, 2999, "below", 3000)).toBe(true); // crossed down
    expect(alertCrossed(2999, 2998, "below", 3000)).toBe(false); // already below
    expect(alertCrossed(4000, 3001, "below", 3000)).toBe(false); // still above
  });

  it("no prior sample: falls back to a level check on the first value", () => {
    expect(alertCrossed(null, 65000, "above", 65000)).toBe(true);
    expect(alertCrossed(undefined, 64999, "above", 65000)).toBe(false);
    expect(alertCrossed(Number.NaN, 2999, "below", 3000)).toBe(true);
  });

  it("ignores non-finite current values", () => {
    expect(alertCrossed(64000, Number.NaN, "above", 65000)).toBe(false);
    expect(alertCrossed(64000, Number.POSITIVE_INFINITY, "above", 65000)).toBe(false);
  });
});

describe("alertLabel + subject labels", () => {
  it("labels a symbol price alert with the resolved name", () => {
    const a = makeAlert({ subjectKind: "symbol", direction: "above", price: 65000 });
    expect(alertLabel(a, "BTC", (v) => v.toLocaleString())).toBe("BTC price above 65,000");
  });

  it("labels a token alert (price / cents)", () => {
    const a = makeAlert({ subjectKind: "token", field: "price", direction: "below", price: 12_50 });
    expect(alertLabel(a, "MOON", (v) => `$${(v / 100).toFixed(2)}`)).toBe("MOON price below $12.50");
  });

  it("labels a strategy alert (NAV / cents)", () => {
    const a = makeAlert({ subjectKind: "strategy", field: "nav", direction: "above", price: 100_00 });
    expect(alertLabel(a, "Alpha Fund", (v) => `$${(v / 100).toFixed(2)}`)).toBe(
      "Alpha Fund NAV above $100.00",
    );
  });

  it("falls back to a #id / subjectId name when unresolved", () => {
    const sym = makeAlert({ subjectKind: "symbol", symbolId: 7 });
    expect(alertLabel(sym, undefined, (v) => String(v))).toContain("#7");
    const tok = makeAlert({ subjectKind: "token", subjectId: "tok_abc" });
    expect(subjectFallbackName(tok)).toBe("tok_abc");
  });

  it("subjectKindLabel maps each kind", () => {
    expect(subjectKindLabel("symbol")).toBe("Symbol");
    expect(subjectKindLabel("token")).toBe("Creator token");
    expect(subjectKindLabel("strategy")).toBe("Strategy");
  });
});

describe("parsePriceToTicks", () => {
  it("scales a decimal price into integer ticks", () => {
    expect(parsePriceToTicks("65000", 1)).toBe(65000);
    expect(parsePriceToTicks("3000.5", 100)).toBe(300050);
    expect(parsePriceToTicks("150.25", 100)).toBe(15025);
  });

  it("rounds to the nearest tick", () => {
    expect(parsePriceToTicks("1.007", 100)).toBe(101);
    expect(parsePriceToTicks("1.002", 100)).toBe(100);
  });

  it("rejects blank / non-numeric / negative input", () => {
    expect(parsePriceToTicks("", 1)).toBeNull();
    expect(parsePriceToTicks("   ", 1)).toBeNull();
    expect(parsePriceToTicks("abc", 1)).toBeNull();
    expect(parsePriceToTicks("-5", 1)).toBeNull();
  });

  it("defaults scaler to 1 when unset", () => {
    expect(parsePriceToTicks("42")).toBe(42);
  });
});

describe("parseCentsToInt", () => {
  it("scales a dollar amount into integer cents", () => {
    expect(parseCentsToInt("12.50")).toBe(1250);
    expect(parseCentsToInt("100")).toBe(10000);
    expect(parseCentsToInt("0.99")).toBe(99);
  });

  it("rounds to the nearest cent", () => {
    expect(parseCentsToInt("1.007")).toBe(101); // 100.7 -> 101
    expect(parseCentsToInt("1.004")).toBe(100); // 100.4 -> 100
  });

  it("rejects blank / non-numeric / negative input", () => {
    expect(parseCentsToInt("")).toBeNull();
    expect(parseCentsToInt("abc")).toBeNull();
    expect(parseCentsToInt("-1")).toBeNull();
  });
});

describe("persistence + legacy migration", () => {
  beforeEach(() => {
    try {
      localStorage.clear();
    } catch {
      /* jsdom */
    }
  });
  afterEach(() => {
    try {
      localStorage.clear();
    } catch {
      /* jsdom */
    }
  });

  it("migrates a legacy symbol-only entry to the generalized shape", () => {
    // Legacy row: no subjectKind / subjectId / field.
    const legacy = [
      {
        id: "legacy1",
        symbolId: 3,
        direction: "above",
        price: 65000,
        createdTs: 1,
        triggeredTs: null,
        armed: true,
      },
    ];
    localStorage.setItem(PRICE_ALERTS_KEY, JSON.stringify(legacy));
    const loaded = loadPriceAlerts();
    expect(loaded).toHaveLength(1);
    const only = loaded[0]!;
    expect(only.subjectKind).toBe("symbol");
    expect(only.subjectId).toBe("3");
    expect(only.field).toBe("price");
    expect(only.symbolId).toBe(3);
  });

  it("round-trips a token alert and a strategy alert", () => {
    addPriceAlert({ subjectKind: "token", subjectId: "tok_1", direction: "above", price: 12_50 });
    addPriceAlert({
      subjectKind: "strategy",
      subjectId: "strat_1",
      field: "nav",
      direction: "below",
      price: 100_00,
    });
    const loaded = loadPriceAlerts();
    expect(loaded).toHaveLength(2);
    const tok = loaded.find((a) => a.subjectKind === "token");
    const strat = loaded.find((a) => a.subjectKind === "strategy");
    expect(tok?.field).toBe("price");
    expect(tok?.subjectId).toBe("tok_1");
    expect(strat?.field).toBe("nav");
    expect(strat?.subjectId).toBe("strat_1");
  });

  it("defaults a bare add to a symbol subject (back-compat callers)", () => {
    addPriceAlert({ symbolId: 9, direction: "above", price: 100 });
    const loaded = loadPriceAlerts();
    const only = loaded[0]!;
    expect(only.subjectKind).toBe("symbol");
    expect(only.subjectId).toBe("9");
    expect(only.field).toBe("price");
  });

  it("drops malformed rows", () => {
    localStorage.setItem(
      PRICE_ALERTS_KEY,
      JSON.stringify([{ id: "ok", symbolId: 1, direction: "above", price: 1, createdTs: 1, armed: true }, { junk: true }, 5]),
    );
    expect(loadPriceAlerts()).toHaveLength(1);
  });
});
