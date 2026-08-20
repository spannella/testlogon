import { describe, expect, it } from "vitest";

import {
  scaleTick,
  tsToIso,
  csvEscape,
  toCsv,
  buildTradeHistoryCsv,
  buildPnlSummaryCsv,
  buildStatementCsv,
  TRADE_HISTORY_HEADER,
  PNL_SUMMARY_HEADER,
  type ReportFill,
  type ReportSymbolPnl,
  type ReportPnlTotals,
  type SymbolResolver,
} from "./exportReport";

// A scaler of 100 (2dp) named per symbolid; unknown ids fall back to "#id".
const resolve: SymbolResolver = (id) =>
  id === 1 ? { name: "BTC", scaler: 100 } : id === 2 ? { name: "ETH", scaler: 100 } : { name: `#${id}`, scaler: 1 };

describe("scaleTick", () => {
  it("scales an int64 tick by the price scaler", () => {
    expect(scaleTick(123456, 100, 2)).toBe("1234.56");
  });
  it("emits no thousands grouping (delimiter-safe)", () => {
    expect(scaleTick(1234567890, 100, 2)).toBe("12345678.9");
  });
  it("returns empty string for null / non-finite", () => {
    expect(scaleTick(null)).toBe("");
    expect(scaleTick(undefined)).toBe("");
    expect(scaleTick(NaN)).toBe("");
  });
  it("tolerates a zero scaler (treats as 1)", () => {
    expect(scaleTick(42, 0, 2)).toBe("42");
  });
});

describe("tsToIso", () => {
  it("treats a small value as seconds", () => {
    expect(tsToIso(1_700_000_000)).toBe(new Date(1_700_000_000 * 1000).toISOString());
  });
  it("treats a large value as milliseconds", () => {
    expect(tsToIso(1_700_000_000_000)).toBe(new Date(1_700_000_000_000).toISOString());
  });
  it("returns empty string for null", () => {
    expect(tsToIso(null)).toBe("");
  });
});

describe("csvEscape", () => {
  it("leaves plain values untouched", () => {
    expect(csvEscape("BTC")).toBe("BTC");
    expect(csvEscape(42)).toBe("42");
  });
  it("quotes and doubles embedded quotes", () => {
    expect(csvEscape('a"b')).toBe('"a""b"');
  });
  it("quotes values containing a comma", () => {
    expect(csvEscape("a,b")).toBe('"a,b"');
  });
  it("quotes values containing a newline", () => {
    expect(csvEscape("a\nb")).toBe('"a\nb"');
  });
  it("renders null/undefined as empty", () => {
    expect(csvEscape(null)).toBe("");
    expect(csvEscape(undefined)).toBe("");
  });
});

describe("toCsv", () => {
  it("joins a header + rows with \\n and escapes fields", () => {
    const csv = toCsv(["A", "B"], [["1", "x,y"], ["2", 'q"q']]);
    expect(csv).toBe('A,B\n1,"x,y"\n2,"q""q"');
  });
});

describe("buildTradeHistoryCsv", () => {
  const fills: ReportFill[] = [
    { symbolid: 1, price: 12000, qty: 200, side: "sell", liquidity: "taker", fee: 5, ts: 1_700_000_100 },
    { symbolid: 1, price: 10000, qty: 100, side: "buy", liquidity: "maker", fee: 3, ts: 1_700_000_050 },
  ];

  it("emits the documented header", () => {
    const csv = buildTradeHistoryCsv(fills, resolve);
    expect(csv.split("\n")[0]).toBe(TRADE_HISTORY_HEADER.join(","));
  });

  it("orders rows oldest-first and scales price/qty/notional", () => {
    const lines = buildTradeHistoryCsv(fills, resolve).split("\n");
    // Row 1 = the older buy (ts 50): price 10000/100=100, qty 100/100=1, notional (10000*100)/(100*100)=100
    expect(lines[1]).toBe("2023-11-14T22:14:10.000Z,BTC,BUY,maker,100,1,0.03,100");
    // Row 2 = the newer sell (ts 100): price 12000/100=120, qty 200/100=2, notional 240
    expect(lines[2]).toBe("2023-11-14T22:15:00.000Z,BTC,SELL,taker,120,2,0.05,240");
  });

  it("produces only a header for no fills", () => {
    expect(buildTradeHistoryCsv([], resolve)).toBe(TRADE_HISTORY_HEADER.join(","));
  });
});

describe("buildPnlSummaryCsv", () => {
  const perSymbol: ReportSymbolPnl[] = [
    { symbolid: 1, net: 20000, realized: 20500, fees: 50, funding: 0, volume: 220000, tradeCount: 2, closes: 1, wins: 1 },
    { symbolid: 2, net: -10000, realized: -9500, fees: 50, funding: 0, volume: 110000, tradeCount: 2, closes: 1, wins: 0 },
  ];
  const totals: ReportPnlTotals = {
    netRealized: 10000,
    totalRealized: 11000,
    totalFees: 100,
    totalFunding: 0,
    totalVolume: 330000,
    tradeCount: 4,
    closeCount: 2,
    winCount: 1,
    winRate: 0.5,
  };

  it("emits header + one row per symbol + a TOTAL row", () => {
    const lines = buildPnlSummaryCsv(perSymbol, totals, resolve, 100).split("\n");
    expect(lines[0]).toBe(PNL_SUMMARY_HEADER.join(","));
    expect(lines).toHaveLength(4); // header + 2 symbols + TOTAL
    expect(lines[3]?.startsWith("TOTAL,")).toBe(true);
  });

  it("scales net PnL + win% correctly", () => {
    const lines = buildPnlSummaryCsv(perSymbol, totals, resolve, 100).split("\n");
    // BTC net 20000/100 = 200, win% 100.0
    expect(lines[1]).toBe("BTC,200,205,0.5,0,22,2,1,1,100.0");
    // TOTAL net 10000/100 = 100, win% 50.0
    expect(lines[3]).toBe("TOTAL,100,110,1,0,33,4,2,1,50.0");
  });
});

describe("buildStatementCsv", () => {
  it("emits a self-describing preamble + header + rows", () => {
    const csv = buildStatementCsv(
      [
        { section: "Spot", label: "USD", amount: 500000, scaler: 100, note: "available" },
        { section: "Margin", label: "Balance", amount: 250000, scaler: 100 },
      ],
      { period: "Last 7 days", generatedAt: 1_700_000_000_000 },
    );
    const lines = csv.split("\n");
    expect(lines[0]).toBe("# Account statement — Last 7 days");
    expect(lines[1]).toBe(`# Generated ${new Date(1_700_000_000_000).toISOString()}`);
    expect(lines[2]).toBe("");
    expect(lines[3]).toBe("Section,Account / Asset,Amount,Note");
    expect(lines[4]).toBe("Spot,USD,5000,available");
    expect(lines[5]).toBe("Margin,Balance,2500,");
  });
});
