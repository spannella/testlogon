import { describe, expect, it } from "vitest";

import { custodyBalanceOf, trimToDecimals } from "@/pages/custody/CustodyExtras";

describe("custodyBalanceOf (case-insensitive balance lookup)", () => {
  it("reads an exact-key balance", () => {
    expect(custodyBalanceOf({ ETH: "1.5" }, "ETH")).toBe(1.5);
  });

  it("is case-insensitive on the symbol", () => {
    expect(custodyBalanceOf({ eth: "2" }, "ETH")).toBe(2);
    expect(custodyBalanceOf({ ETH: "2" }, "eth")).toBe(2);
    expect(custodyBalanceOf({ Usdc: 10 }, "usdc")).toBe(10);
  });

  it("returns 0 for missing / undefined / non-numeric balances", () => {
    expect(custodyBalanceOf({ ETH: "1" }, "BTC")).toBe(0);
    expect(custodyBalanceOf(undefined, "ETH")).toBe(0);
    expect(custodyBalanceOf({ ETH: "not-a-number" }, "ETH")).toBe(0);
  });

  it("parses numeric-string balances", () => {
    expect(custodyBalanceOf({ POL: "0.000001" }, "POL")).toBeCloseTo(0.000001, 12);
  });
});

describe("trimToDecimals (Max respects asset decimals)", () => {
  it("trims to at most the asset decimals (capped at 8)", () => {
    // 6-decimal asset like USDC
    expect(trimToDecimals(12.3456789, 6)).toBe("12.345678");  // truncated, not rounded (Max must not exceed balance)
    // 18-decimal asset is capped at 8 decimals for display
    expect(trimToDecimals(1.123456789012, 18)).toBe("1.12345678");  // capped at 8, truncated
  });

  it("drops trailing zeros and a bare trailing dot", () => {
    expect(trimToDecimals(5, 8)).toBe("5");
    expect(trimToDecimals(1.5, 6)).toBe("1.5");
    expect(trimToDecimals(2.5000, 6)).toBe("2.5");
  });

  it("returns \"0\" for non-positive / non-finite values", () => {
    expect(trimToDecimals(0, 8)).toBe("0");
    expect(trimToDecimals(-1, 8)).toBe("0");
    expect(trimToDecimals(Number.NaN, 8)).toBe("0");
    expect(trimToDecimals(Number.POSITIVE_INFINITY, 8)).toBe("0");
  });
});

// Money-safety UX invariants mirrored from CustodyExtras Transfer/Bridge tabs:
//   overSpend  = sourceAvailable != null && amt > sourceAvailable
//   canSubmit  = amt > 0 && !overSpend   (transfer also requires from != to)
// These guards are computed inline in the components; the helpers above feed
// sourceAvailable (balance lookup) and the Max value (trimToDecimals).
describe("money-safety guard invariants", () => {
  const overSpend = (avail: number | null, amt: number) => avail != null && amt > avail;
  const canSubmit = (avail: number | null, amt: number) => amt > 0 && !overSpend(avail, amt);

  it("blocks over-spend", () => {
    const avail = custodyBalanceOf({ ETH: "1" }, "ETH");
    expect(overSpend(avail, 2)).toBe(true);
    expect(canSubmit(avail, 2)).toBe(false);
  });

  it("requires a positive amount", () => {
    expect(canSubmit(10, 0)).toBe(false);
    expect(canSubmit(10, -1)).toBe(false);
  });

  it("allows an in-budget positive amount", () => {
    const avail = custodyBalanceOf({ ETH: "1.5" }, "eth");
    expect(canSubmit(avail, 1.5)).toBe(true);
    expect(canSubmit(avail, 0.5)).toBe(true);
  });

  it("Max value fits within an asset's decimals and is submittable", () => {
    // A balance already within the asset's decimals round-trips exactly.
    const avail = custodyBalanceOf({ USDC: "12.345678" }, "usdc");
    const maxStr = trimToDecimals(avail, 6);
    expect(maxStr).toBe("12.345678");
    expect(canSubmit(avail, Number(maxStr))).toBe(true);
  });
});
