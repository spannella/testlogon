import { describe, expect, it } from "vitest";

import type { FeeQuote } from "@/api/endpoints/fees";
import {
  quoteExpirySeconds,
  isQuoteExpired,
  insufficientForQuote,
  insufficientForCents,
  rateLine,
  totalLine,
  feeLine,
  formatCoin,
  formatCountdown,
} from "@/lib/checkoutCrypto";

function makeQuote(over: Partial<FeeQuote> = {}): FeeQuote {
  return {
    pay_with: "ETH",
    asset_id: 1,
    amount_cents: 15000,
    rate: {
      usd_cents_per_coin_native: 300000000,
      usd_per_whole_coin: 3000,
      source: "book_mid",
    },
    conversion_fee_bps: 175,
    conversion_fee_pct: 1.75,
    liquidity: { spread_bps: 5 },
    variance: { realized_vol_bps: 10 },
    coin_native: 0.05,
    conversion_fee_native: 0.000875,
    total_native: 0.050875,
    expires_at: 1000,
    locked_seconds: 60,
    quote_token: "tok_abc",
    ...over,
  };
}

describe("quoteExpirySeconds", () => {
  it("counts down toward the lock expiry", () => {
    expect(quoteExpirySeconds(1000, 940)).toBe(60);
    expect(quoteExpirySeconds(1000, 999)).toBe(1);
  });

  it("clamps at zero once lapsed", () => {
    expect(quoteExpirySeconds(1000, 1000)).toBe(0);
    expect(quoteExpirySeconds(1000, 1200)).toBe(0);
  });

  it("returns 0 for non-finite inputs", () => {
    expect(quoteExpirySeconds(NaN, 100)).toBe(0);
    expect(quoteExpirySeconds(1000, Infinity)).toBe(0);
  });
});

describe("isQuoteExpired", () => {
  it("is false while time remains and true once lapsed", () => {
    expect(isQuoteExpired(1000, 990)).toBe(false);
    expect(isQuoteExpired(1000, 1000)).toBe(true);
    expect(isQuoteExpired(1000, 1001)).toBe(true);
  });
});

describe("insufficientForQuote", () => {
  it("compares base-unit balance against the quote total", () => {
    expect(insufficientForQuote(100, 200)).toBe(true);
    expect(insufficientForQuote(200, 200)).toBe(false);
    expect(insufficientForQuote(500, 200)).toBe(false);
  });

  it("treats a zero/negative total as sufficient (nothing owed)", () => {
    expect(insufficientForQuote(0, 0)).toBe(false);
    expect(insufficientForQuote(0, -5)).toBe(false);
  });

  it("fails closed on a bad balance", () => {
    expect(insufficientForQuote(NaN, 200)).toBe(true);
    expect(insufficientForQuote(-1, 200)).toBe(true);
  });
});

describe("insufficientForCents (against a FeeQuote total_native)", () => {
  it("uses the quote total_native", () => {
    const q = makeQuote({ total_native: 0.05 });
    expect(insufficientForCents(0.04, q)).toBe(true);
    expect(insufficientForCents(0.05, q)).toBe(false);
    expect(insufficientForCents(1, q)).toBe(false);
  });
});

describe("rateLine", () => {
  it("shows 1 COIN ~= $X when whole-coin rate is configured", () => {
    expect(rateLine(makeQuote())).toBe("1 ETH ≈ $3,000");
  });

  it("falls back to a per-native-unit rate when decimals unknown", () => {
    const q = makeQuote({
      rate: { usd_cents_per_coin_native: 500, usd_per_whole_coin: null, source: "reference" },
    });
    expect(rateLine(q)).toBe("1 ETH unit ≈ $5.0000");
  });

  it("shows the USD-wallet 1:1 note", () => {
    const q = makeQuote({ pay_with: "USD", convertible: false });
    expect(rateLine(q)).toBe("Paid from USD wallet (1:1)");
  });
});

describe("totalLine", () => {
  it("shows the total native coin to pay", () => {
    expect(totalLine(makeQuote({ total_native: 0.42 }))).toBe("Pay 0.42 ETH");
  });

  it("shows a dollar amount for the USD wallet path", () => {
    const q = makeQuote({ pay_with: "USD", convertible: false, amount_cents: 15000 });
    expect(totalLine(q)).toBe("Pay $150.00 from wallet");
  });
});

describe("feeLine", () => {
  it("shows the conversion fee pct when charged", () => {
    expect(feeLine(makeQuote({ conversion_fee_bps: 175, conversion_fee_pct: 1.75 }))).toBe(
      "1.75% conversion fee",
    );
  });

  it("shows no fee when bps is zero", () => {
    expect(feeLine(makeQuote({ conversion_fee_bps: 0 }))).toBe("no conversion fee");
  });
});

describe("formatCoin", () => {
  it("trims trailing zeros and keeps precision by magnitude", () => {
    expect(formatCoin(0)).toBe("0");
    expect(formatCoin(1.5)).toBe("1.5");
    expect(formatCoin(0.05)).toBe("0.05");
    expect(formatCoin(0.00012345)).toBe("0.00012345");
    expect(formatCoin(2)).toBe("2");
  });

  it("returns 0 for non-finite", () => {
    expect(formatCoin(NaN)).toBe("0");
  });
});

describe("formatCountdown", () => {
  it("formats seconds as m:ss", () => {
    expect(formatCountdown(60)).toBe("1:00");
    expect(formatCountdown(45)).toBe("0:45");
    expect(formatCountdown(5)).toBe("0:05");
    expect(formatCountdown(0)).toBe("0:00");
    expect(formatCountdown(-10)).toBe("0:00");
  });
});
