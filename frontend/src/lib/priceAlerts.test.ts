import { describe, expect, it } from "vitest";

import {
  evaluate,
  parsePriceToTicks,
  type PriceAlert,
} from "@/lib/priceAlerts";

function makeAlert(over: Partial<PriceAlert>): PriceAlert {
  return {
    id: "a1",
    symbolId: 1,
    direction: "above",
    price: 65000,
    createdTs: 0,
    triggeredTs: null,
    armed: true,
    ...over,
  };
}

describe("evaluate (pure price-alert edge trigger)", () => {
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
    // Simulate the store's one-shot: after firing we disarm.
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

  it("full lifecycle: armed→fires→disarm(one-shot)→re-arm→fires", () => {
    // armed, below threshold: no fire
    let a = makeAlert({ direction: "above", price: 65000, armed: true });
    expect(evaluate(a, 64000)).toBe(false);
    // crosses up: fire
    expect(evaluate(a, 65500)).toBe(true);
    // store disarms after firing (one-shot)
    a = { ...a, armed: false, triggeredTs: Date.now() };
    expect(evaluate(a, 66000)).toBe(false);
    // user re-arms
    a = { ...a, armed: true, triggeredTs: null };
    expect(evaluate(a, 66000)).toBe(true);
  });
});

describe("parsePriceToTicks", () => {
  it("scales a decimal price into integer ticks", () => {
    expect(parsePriceToTicks("65000", 1)).toBe(65000);
    expect(parsePriceToTicks("3000.5", 100)).toBe(300050);
    expect(parsePriceToTicks("150.25", 100)).toBe(15025);
  });

  it("rounds to the nearest tick", () => {
    expect(parsePriceToTicks("1.007", 100)).toBe(101); // 100.7 -> 101
    expect(parsePriceToTicks("1.002", 100)).toBe(100); // 100.2 -> 100
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
