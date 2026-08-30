// Pure helpers for the "Pay with crypto balance" checkout method (FE-152).
//
// Wraps the shipped pay-any-coin FeeQuote contract (see api/endpoints/fees.ts)
// with the small amount of pure, integer-safe math the Checkout UI needs:
//   - rate-lock countdown (seconds until the locked quote expires)
//   - insufficient-balance detection against the quote total
//   - human display lines (rate / total / conversion fee)
// No React, no network — unit-testable in isolation.

import type { FeeQuote } from "@/api/endpoints/fees";

/**
 * Seconds until a locked quote expires, given the quotes unix `expires_at`
 * and the current unix time (seconds). Clamped at >= 0 so an already-lapsed
 * lock reports 0 rather than a negative countdown.
 */
export function quoteExpirySeconds(
  expiresAt: number,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): number {
  if (!isFinite(expiresAt) || !isFinite(nowSeconds)) return 0;
  const remaining = Math.floor(expiresAt) - Math.floor(nowSeconds);
  return remaining > 0 ? remaining : 0;
}

/** True once the locked rate has lapsed (re-quote before charging). */
export function isQuoteExpired(
  expiresAt: number,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  return quoteExpirySeconds(expiresAt, nowSeconds) <= 0;
}

/**
 * True when the callers coin balance (in native base units) cannot cover the
 * quote total (also native base units). Non-finite/negative balances are
 * treated as insufficient (fail-closed).
 */
export function insufficientForQuote(
  balanceBaseUnits: number,
  totalCoinBaseUnits: number,
): boolean {
  if (!isFinite(totalCoinBaseUnits) || totalCoinBaseUnits <= 0) return false;
  if (!isFinite(balanceBaseUnits) || balanceBaseUnits < 0) return true;
  return balanceBaseUnits < totalCoinBaseUnits;
}

/**
 * Convenience: given a live FeeQuote, is the balance (native base units)
 * insufficient for its `total_native`?
 */
export function insufficientForCents(
  balanceBaseUnits: number,
  quote: FeeQuote,
): boolean {
  return insufficientForQuote(balanceBaseUnits, quote.total_native);
}

/**
 * The "1 COIN ~= $X" rate line for a quote (display only). Falls back to the
 * USD-wallet 1:1 note, then to the per-native-unit rate when whole-coin
 * decimals are not configured.
 */
export function rateLine(quote: FeeQuote): string {
  const coin = quote.pay_with;
  if (quote.convertible === false) {
    return "Paid from USD wallet (1:1)";
  }
  const whole = quote.rate?.usd_per_whole_coin;
  if (whole != null && isFinite(whole)) {
    return `1 ${coin} ≈ $${whole.toLocaleString(undefined, {
      maximumFractionDigits: 2,
    })}`;
  }
  const perNative = (quote.rate?.usd_cents_per_coin_native ?? 0) / 100;
  return `1 ${coin} unit ≈ $${perNative.toFixed(4)}`;
}

/** e.g. "Pay 0.42 ETH" — the total native coin debited on pay. */
export function totalLine(quote: FeeQuote): string {
  if (quote.convertible === false) {
    return `Pay $${(quote.amount_cents / 100).toFixed(2)} from wallet`;
  }
  return `Pay ${formatCoin(quote.total_native)} ${quote.pay_with}`;
}

/** e.g. "1.75% conversion fee" or "no conversion fee". */
export function feeLine(quote: FeeQuote): string {
  return quote.conversion_fee_bps > 0
    ? `${quote.conversion_fee_pct.toFixed(2)}% conversion fee`
    : "no conversion fee";
}

/**
 * Format a native coin amount for display, trimming trailing zeros while
 * keeping small amounts readable. Pure string math on the given number.
 */
export function formatCoin(nativeAmount: number): string {
  if (!isFinite(nativeAmount)) return "0";
  if (nativeAmount === 0) return "0";
  const abs = Math.abs(nativeAmount);
  const digits = abs >= 1 ? 4 : 8;
  const fixed = nativeAmount.toFixed(digits);
  // Trim trailing zeros (and a dangling ".").
  return fixed.replace(/\.?0+$/, "");
}

/** "0:45"-style mm:ss for a countdown given whole seconds. */
export function formatCountdown(seconds: number): string {
  const s = isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}:${rem.toString().padStart(2, "0")}`;
}
