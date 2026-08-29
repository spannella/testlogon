import { describe, expect, it } from "vitest";
import {
  amountLabel,
  badgeVariant,
  fiatEquivalentCents,
  formatFiatCents,
  parseAmountToBaseUnits,
  statusLabel,
  transferDirection,
  transferPreview,
  trimAmount,
  validateSend,
} from "./cryptoTransfer";

describe("parseAmountToBaseUnits", () => {
  it("scales whole + fractional decimals to base units", () => {
    expect(parseAmountToBaseUnits("1", 18)).toBe(10n ** 18n);
    expect(parseAmountToBaseUnits("0.5", 18)).toBe(5n * 10n ** 17n);
    expect(parseAmountToBaseUnits("1.5", 6)).toBe(1500000n);
    expect(parseAmountToBaseUnits(".25", 2)).toBe(25n);
    expect(parseAmountToBaseUnits("10.", 2)).toBe(1000n);
  });
  it("rejects junk, empty, and over-precision", () => {
    expect(parseAmountToBaseUnits("", 18)).toBeNull();
    expect(parseAmountToBaseUnits(".", 18)).toBeNull();
    expect(parseAmountToBaseUnits("abc", 18)).toBeNull();
    expect(parseAmountToBaseUnits("1.2.3", 18)).toBeNull();
    expect(parseAmountToBaseUnits("-1", 18)).toBeNull();
    expect(parseAmountToBaseUnits("0.123", 2)).toBeNull(); // 3 dp > 2 decimals
  });
});

describe("fiatEquivalentCents", () => {
  it("computes amount * rate in integer cents (no drift)", () => {
    // 0.5 ETH * $2000 (200000c) = $1000 => 100000c
    expect(fiatEquivalentCents("0.5", 200000, 18)).toBe(100000);
    // 100 USDC * $1 (100c) = $100 => 10000c
    expect(fiatEquivalentCents("100", 100, 6)).toBe(10000);
  });
  it("rounds half up and rejects bad input", () => {
    // 1 unit-of-6dp * 100c / 1e6 => 0.0001c -> rounds to 0
    expect(fiatEquivalentCents("0.000001", 100, 6)).toBe(0);
    expect(fiatEquivalentCents("bad", 100, 6)).toBeNull();
    expect(fiatEquivalentCents("1", -5, 6)).toBeNull();
  });
});

describe("validateSend", () => {
  const dec = 18;
  it("passes a positive amount within balance", () => {
    expect(validateSend({ amountStr: "0.5", balanceStr: "1", decimals: dec })).toEqual({ ok: true });
  });
  it("rejects empty / invalid / non-positive", () => {
    expect(validateSend({ amountStr: "", decimals: dec }).reason).toBe("empty");
    expect(validateSend({ amountStr: "abc", decimals: dec }).reason).toBe("invalid");
    expect(validateSend({ amountStr: "0", decimals: dec }).reason).toBe("nonpositive");
  });
  it("rejects over-balance (insufficient)", () => {
    const r = validateSend({ amountStr: "2", balanceStr: "1", decimals: dec });
    expect(r).toEqual({ ok: false, reason: "insufficient" });
  });
  it("enforces min and max", () => {
    expect(validateSend({ amountStr: "0.001", min: "0.01", balanceStr: "1", decimals: dec }).reason).toBe("below_min");
    expect(validateSend({ amountStr: "5", max: "1", balanceStr: "10", decimals: dec }).reason).toBe("over_max");
  });
  it("blocks when KYC is not ok (before any amount parse)", () => {
    expect(validateSend({ amountStr: "abc", kycOk: false, decimals: dec }).reason).toBe("kyc");
  });
  it("accepts pre-parsed base-unit amounts and bigint balances", () => {
    expect(validateSend({ amountBaseUnits: 5n * 10n ** 17n, balance: 10n ** 18n, decimals: dec })).toEqual({ ok: true });
  });
});

describe("transferDirection", () => {
  it("prefers explicit isOwn", () => {
    expect(transferDirection({ sender_id: "x", isOwn: true })).toBe("sent");
    expect(transferDirection({ sender_id: "x", isOwn: false })).toBe("received");
  });
  it("falls back to sender vs currentUserId", () => {
    expect(transferDirection({ sender_id: "me" }, "me")).toBe("sent");
    expect(transferDirection({ sender_id: "them" }, "me")).toBe("received");
  });
});

describe("status + badge + formatting", () => {
  it("labels and badges each status, defaulting to pending", () => {
    expect(statusLabel("complete")).toBe("Complete");
    expect(statusLabel("failed")).toBe("Failed");
    expect(statusLabel(undefined)).toBe("Pending");
    expect(badgeVariant("complete")).toBe("success");
    expect(badgeVariant("failed")).toBe("danger");
    expect(badgeVariant("weird")).toBe("pending");
  });
  it("trims amounts and formats fiat + amount labels", () => {
    expect(trimAmount("0.50")).toBe("0.5");
    expect(trimAmount("1.000")).toBe("1");
    expect(trimAmount("2")).toBe("2");
    expect(amountLabel("0.50", "ETH")).toBe("0.5 ETH");
    expect(formatFiatCents(100000)).toBe("$1,000.00");
    expect(formatFiatCents(null)).toBe("");
  });
});

describe("transferPreview", () => {
  it("renders sent / received previews", () => {
    expect(transferPreview({ sender_id: "me", isOwn: true, asset: "ETH", amount: "0.50" })).toBe("[Sent 0.5 ETH]");
    expect(transferPreview({ sender_id: "you", isOwn: false, asset: "USDC", amount: "100" })).toBe("[Received 100 USDC]");
    expect(transferPreview({ sender_id: "me", isOwn: true })).toBe("[Sent crypto]");
  });
});
