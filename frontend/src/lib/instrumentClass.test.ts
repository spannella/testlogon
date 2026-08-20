import { describe, expect, it } from "vitest";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import {
  classesForSymbol,
  symbolInClass,
  CLASS_ORDER,
  CLASS_TAB_ORDER,
  CLASS_LABELS,
} from "./instrumentClass";

function mk(over: Partial<MarketSymbol>): MarketSymbol {
  return {
    symbol: "TEST",
    symbol_id: 1,
    instrument_id: 1,
    price_scaler: 1,
    lot_size: 1,
    reference_price: 100,
    matching_algo: "price_time",
    is_perpetual: false,
    funding_interval_s: 0,
    ...over,
  };
}

describe("classesForSymbol", () => {
  it("classifies a non-perpetual as spot only", () => {
    expect(classesForSymbol(mk({ is_perpetual: false }))).toEqual(["spot"]);
  });

  it("classifies a perpetual with funding interval as perp AND funding", () => {
    expect(classesForSymbol(mk({ is_perpetual: true, funding_interval_s: 3600 }))).toEqual([
      "perp",
      "funding",
    ]);
  });

  it("classifies a perpetual with NO funding interval as perp only", () => {
    expect(classesForSymbol(mk({ is_perpetual: true, funding_interval_s: 0 }))).toEqual(["perp"]);
  });

  it("adds prediction to a spot symbol when isPrediction is set", () => {
    expect(classesForSymbol(mk({ is_perpetual: false }), { isPrediction: true })).toEqual([
      "spot",
      "prediction",
    ]);
  });

  it("adds prediction to a perp+funding symbol and keeps canonical order", () => {
    expect(
      classesForSymbol(mk({ is_perpetual: true, funding_interval_s: 3600 }), { isPrediction: true }),
    ).toEqual(["perp", "prediction", "funding"]);
  });

  it("does not add prediction when isPrediction is false/undefined", () => {
    expect(classesForSymbol(mk({ is_perpetual: false }), { isPrediction: false })).toEqual(["spot"]);
    expect(classesForSymbol(mk({ is_perpetual: false }), {})).toEqual(["spot"]);
  });

  it("always returns classes in canonical CLASS_ORDER", () => {
    const classes = classesForSymbol(
      mk({ is_perpetual: true, funding_interval_s: 60 }),
      { isPrediction: true },
    );
    const idx = classes.map((c) => CLASS_ORDER.indexOf(c));
    expect(idx).toEqual([...idx].sort((a, b) => a - b));
  });
});

describe("symbolInClass", () => {
  const perp = mk({ is_perpetual: true, funding_interval_s: 3600 });
  const spot = mk({ is_perpetual: false });

  it("matches everything for the all tab", () => {
    expect(symbolInClass(spot, "all")).toBe(true);
    expect(symbolInClass(perp, "all")).toBe(true);
  });

  it("matches a perp in both perp and funding tabs", () => {
    expect(symbolInClass(perp, "perp")).toBe(true);
    expect(symbolInClass(perp, "funding")).toBe(true);
    expect(symbolInClass(perp, "spot")).toBe(false);
  });

  it("matches a spot only in the spot tab", () => {
    expect(symbolInClass(spot, "spot")).toBe(true);
    expect(symbolInClass(spot, "perp")).toBe(false);
    expect(symbolInClass(spot, "funding")).toBe(false);
  });

  it("respects the prediction flag", () => {
    expect(symbolInClass(spot, "prediction")).toBe(false);
    expect(symbolInClass(spot, "prediction", { isPrediction: true })).toBe(true);
  });
});

describe("class metadata", () => {
  it("has a label for every tab", () => {
    for (const tab of CLASS_TAB_ORDER) {
      expect(CLASS_LABELS[tab]).toBeTruthy();
    }
  });

  it("starts the tab order with all", () => {
    expect(CLASS_TAB_ORDER[0]).toBe("all");
  });
});
