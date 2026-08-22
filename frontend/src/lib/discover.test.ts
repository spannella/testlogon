import { describe, expect, it } from "vitest";

import type { MarketSymbol } from "@/api/endpoints/marketData";
import type { Token } from "@/api/endpoints/tokens";
import type { Strategy } from "@/api/endpoints/strategies";
import {
  normalizeQuery,
  matchesText,
  searchSymbols,
  searchTokens,
  searchStrategies,
  topMovers,
  changeBpsFromPrices,
  sortStrategies,
  sortTokens,
  capacityRemainingFraction,
  bpsToSignedPct,
  centsToUsd,
  marketItem,
  tokenItem,
  strategyItem,
  type SymbolChange,
} from "./discover";

// -- Fixtures ---------------------------------------------------------

function sym(partial: Partial<MarketSymbol> & { symbol: string; symbol_id: number }): MarketSymbol {
  return {
    instrument_id: partial.symbol_id,
    price_scaler: 1,
    lot_size: 1,
    reference_price: 100,
    matching_algo: "price_time",
    is_perpetual: false,
    funding_interval_s: 0,
    ...partial,
  };
}

function tok(partial: Partial<Token> & { token_id: string; name: string; ticker: string }): Token {
  return {
    creator_sub: "u1",
    total_supply: 1000,
    revenue_share_bps: 500,
    status: "listed",
    created_ts: 1000,
    ...partial,
  };
}

function strat(partial: Partial<Strategy> & { strategy_id: string; name: string }): Strategy {
  return {
    creator_sub: "u1",
    description: "",
    kind: "basket",
    status: "published",
    legs: [],
    rebalance: "none",
    min_investment_cents: 10000,
    max_aum_cents: 0,
    mgmt_fee_bps: 100,
    perf_fee_bps: 1000,
    high_water_mark: true,
    redemption: { type: "instant" },
    created_ts: 1000,
    ...partial,
  };
}

const BTC = sym({ symbol: "BTCUSDC", symbol_id: 1 });
const ETH = sym({ symbol: "ETHUSDC", symbol_id: 2, is_perpetual: true });
const SOL = sym({ symbol: "SOLUSDC", symbol_id: 3 });

// -- normalizeQuery / matchesText -------------------------------------

describe("normalizeQuery", () => {
  it("lower-cases and trims", () => {
    expect(normalizeQuery("  BtC ")).toBe("btc");
  });
  it("treats null/undefined as empty", () => {
    expect(normalizeQuery(null)).toBe("");
    expect(normalizeQuery(undefined)).toBe("");
  });
});

describe("matchesText", () => {
  it("empty query matches anything", () => {
    expect(matchesText("", "whatever")).toBe(true);
  });
  it("case-insensitive substring", () => {
    expect(matchesText("btc", "BTCUSDC")).toBe(true);
  });
  it("all tokens must be present (AND)", () => {
    expect(matchesText("moon coin", "Moon Rocket Coin")).toBe(true);
    expect(matchesText("moon zzz", "Moon Rocket Coin")).toBe(false);
  });
  it("no matchable fields -> false for a non-empty query", () => {
    expect(matchesText("btc", null, undefined, "")).toBe(false);
  });
  it("searches across multiple fields", () => {
    expect(matchesText("rocket", "MoonCoin", "The Rocket Fund")).toBe(true);
  });
});

// -- heterogeneous search ---------------------------------------------

describe("searchSymbols", () => {
  it("empty query returns all", () => {
    expect(searchSymbols([BTC, ETH, SOL], "")).toHaveLength(3);
  });
  it("filters by symbol text", () => {
    const r = searchSymbols([BTC, ETH, SOL], "eth");
    expect(r).toHaveLength(1);
    expect(r[0]!.symbol).toBe("ETHUSDC");
  });
  it("tolerates null input", () => {
    expect(searchSymbols(null as unknown as MarketSymbol[], "x")).toEqual([]);
  });
});

describe("searchTokens", () => {
  const tokens = [
    tok({ token_id: "t1", name: "Moon Coin", ticker: "MOON" }),
    tok({ token_id: "t2", name: "Rocket Fund", ticker: "RKT" }),
  ];
  it("matches by name", () => {
    expect(searchTokens(tokens, "moon").map((t) => t.token_id)).toEqual(["t1"]);
  });
  it("matches by ticker", () => {
    expect(searchTokens(tokens, "rkt").map((t) => t.token_id)).toEqual(["t2"]);
  });
  it("empty query returns all", () => {
    expect(searchTokens(tokens, "")).toHaveLength(2);
  });
});

describe("searchStrategies", () => {
  const strategies = [
    strat({ strategy_id: "s1", name: "Blue Chip", description: "large caps" }),
    strat({ strategy_id: "s2", name: "DeFi Basket", description: "yield tokens" }),
  ];
  it("matches by name", () => {
    expect(searchStrategies(strategies, "blue").map((s) => s.strategy_id)).toEqual(["s1"]);
  });
  it("matches by description", () => {
    expect(searchStrategies(strategies, "yield").map((s) => s.strategy_id)).toEqual(["s2"]);
  });
});

// -- ranking ----------------------------------------------------------

describe("changeBpsFromPrices", () => {
  it("computes a positive change", () => {
    expect(changeBpsFromPrices(100, 110)).toBeCloseTo(1000, 6);
  });
  it("computes a negative change", () => {
    expect(changeBpsFromPrices(100, 90)).toBeCloseTo(-1000, 6);
  });
  it("NaN on zero/undefined base", () => {
    expect(changeBpsFromPrices(0, 10)).toBeNaN();
    expect(changeBpsFromPrices(undefined, 10)).toBeNaN();
    expect(changeBpsFromPrices(100, null)).toBeNaN();
  });
});

describe("topMovers", () => {
  const items: SymbolChange[] = [
    { symbol: BTC, changeBps: 300 },
    { symbol: ETH, changeBps: -900 },
    { symbol: SOL, changeBps: 100 },
  ];
  it("orders by absolute change, biggest first", () => {
    expect(topMovers(items).map((i) => i.symbol.symbol)).toEqual([
      "ETHUSDC",
      "BTCUSDC",
      "SOLUSDC",
    ]);
  });
  it("respects the limit", () => {
    expect(topMovers(items, 2)).toHaveLength(2);
  });
  it("sinks non-finite changes to the bottom", () => {
    const withNaN: SymbolChange[] = [
      { symbol: BTC, changeBps: NaN },
      { symbol: ETH, changeBps: 50 },
    ];
    expect(topMovers(withNaN)[0]!.symbol.symbol).toBe("ETHUSDC");
  });
  it("does not mutate the input", () => {
    const copy = items.slice();
    topMovers(items);
    expect(items).toEqual(copy);
  });
});

describe("sortStrategies", () => {
  const strategies = [
    strat({ strategy_id: "a", name: "A", inception_return_bps: 500, aum_cents: 100 }),
    strat({ strategy_id: "b", name: "B", inception_return_bps: 1500, aum_cents: 50 }),
    strat({ strategy_id: "c", name: "C", aum_cents: 9999 }),
  ];
  it("sorts by inception return desc, missing last", () => {
    expect(sortStrategies(strategies, "inception").map((s) => s.strategy_id)).toEqual([
      "b",
      "a",
      "c",
    ]);
  });
  it("sorts by aum desc", () => {
    expect(sortStrategies(strategies, "aum").map((s) => s.strategy_id)).toEqual([
      "c",
      "a",
      "b",
    ]);
  });
  it("respects the limit", () => {
    expect(sortStrategies(strategies, "aum", 1).map((s) => s.strategy_id)).toEqual(["c"]);
  });
});

describe("sortTokens", () => {
  it("lists listed tokens before non-listed, then by created desc", () => {
    const tokens = [
      tok({ token_id: "draft", name: "D", ticker: "D", status: "draft", created_ts: 5000 }),
      tok({ token_id: "old", name: "O", ticker: "O", status: "listed", created_ts: 1000 }),
      tok({ token_id: "new", name: "N", ticker: "N", status: "listed", created_ts: 3000 }),
    ];
    expect(sortTokens(tokens).map((t) => t.token_id)).toEqual(["new", "old", "draft"]);
  });
});

describe("capacityRemainingFraction", () => {
  it("uncapped -> 1", () => {
    expect(capacityRemainingFraction(500, 0)).toBe(1);
    expect(capacityRemainingFraction(500, null)).toBe(1);
  });
  it("half full -> 0.5", () => {
    expect(capacityRemainingFraction(500, 1000)).toBe(0.5);
  });
  it("over-full clamps to 0", () => {
    expect(capacityRemainingFraction(2000, 1000)).toBe(0);
  });
  it("empty fund -> 1", () => {
    expect(capacityRemainingFraction(0, 1000)).toBe(1);
  });
});

// -- formatting -------------------------------------------------------

describe("bpsToSignedPct", () => {
  it("positive gets a plus sign", () => {
    expect(bpsToSignedPct(250)).toBe("+2.5%");
  });
  it("negative keeps the minus", () => {
    expect(bpsToSignedPct(-250)).toBe("-2.5%");
  });
});

describe("centsToUsd", () => {
  it("formats cents", () => {
    expect(centsToUsd(123456)).toBe("$1,234.56");
  });
  it("undefined on non-finite", () => {
    expect(centsToUsd(undefined)).toBeUndefined();
    expect(centsToUsd(NaN)).toBeUndefined();
  });
});

// -- mappers ----------------------------------------------------------

describe("marketItem", () => {
  it("maps a spot symbol with a change", () => {
    const item = marketItem(BTC, 250);
    expect(item).toMatchObject({
      kind: "market",
      id: "1",
      title: "BTCUSDC",
      subtitle: "Spot",
      metric: "+2.5%",
      changeBps: 250,
      href: "/markets/1",
    });
  });
  it("labels perps and omits metric on non-finite change", () => {
    const item = marketItem(ETH, NaN);
    expect(item.subtitle).toBe("Perpetual");
    expect(item.metric).toBeUndefined();
    expect(item.changeBps).toBeUndefined();
  });
});

describe("tokenItem", () => {
  it("uses ticker as title and links to the token", () => {
    const item = tokenItem(tok({ token_id: "t1", name: "Moon Coin", ticker: "MOON", clearing_price: 5000 }));
    expect(item).toMatchObject({
      kind: "token",
      id: "t1",
      title: "MOON",
      subtitle: "Moon Coin",
      metric: "$50.00",
      href: "/tokens/t1",
    });
  });
  it("falls back to status when unpriced", () => {
    const item = tokenItem(tok({ token_id: "t2", name: "X", ticker: "X", status: "draft" }));
    expect(item.metric).toBe("draft");
  });
});

describe("strategyItem", () => {
  it("maps inception return as the metric", () => {
    const item = strategyItem(strat({ strategy_id: "s1", name: "Blue Chip", inception_return_bps: 1200, aum_cents: 500000 }));
    expect(item).toMatchObject({
      kind: "strategy",
      id: "s1",
      title: "Blue Chip",
      subtitle: "AUM $5,000.00",
      metric: "+12%",
      changeBps: 1200,
      href: "/strategies/s1",
    });
  });
  it("falls back to NAV when no inception return", () => {
    const item = strategyItem(strat({ strategy_id: "s2", name: "New", nav_per_unit: 1000 }));
    expect(item.metric).toBe("$10.00");
    expect(item.changeBps).toBeUndefined();
  });
});
