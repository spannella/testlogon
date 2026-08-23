// Pure money helpers for the Cash (USD) custody/trading surface.
// Reuses the same money model as the billing wallet: integer USD cents.
// No React / no network — unit-testable in isolation.

/** Minimum deposit/withdraw, matching the billing wallet's $1.00 floor. */
export const MIN_CASH_CENTS = 100;

/**
 * Parse a user-typed dollar string into whole USD cents.
 * Returns NaN for blank / non-numeric / negative input so callers can
 * treat it as invalid. Rounds to the nearest cent (avoids fp drift).
 */
export function dollarsToCents(input: string | number): number {
  if (typeof input === "number") {
    if (!isFinite(input) || input < 0) return NaN;
    return Math.round(input * 100);
  }
  const trimmed = (input ?? "").toString().trim();
  if (trimmed === "") return NaN;
  // Reject anything that is not a plain, non-negative decimal number.
  if (!/^\d*\.?\d+$/.test(trimmed) && !/^\d+\.?\d*$/.test(trimmed)) return NaN;
  const n = parseFloat(trimmed);
  if (!isFinite(n) || n < 0) return NaN;
  return Math.round(n * 100);
}

/** Format integer USD cents as a localized currency string. */
export function formatCents(cents: number, currency = "USD"): string {
  const safe = isFinite(cents) ? cents : 0;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: (currency || "USD").toUpperCase(),
  }).format(safe / 100);
}

export interface AmountValidation {
  /** Parsed whole cents (NaN when unparseable). */
  cents: number;
  /** True only when the amount is a fundable/withdrawable value. */
  valid: boolean;
  /** A short human reason when invalid, else null. */
  reason: string | null;
}

/** Validate a deposit amount: parseable and >= the $1 minimum. */
export function validateDeposit(input: string | number): AmountValidation {
  const cents = dollarsToCents(input);
  if (isNaN(cents)) {
    return { cents: NaN, valid: false, reason: "Enter a valid amount" };
  }
  if (cents < MIN_CASH_CENTS) {
    return {
      cents,
      valid: false,
      reason: `Minimum is ${formatCents(MIN_CASH_CENTS)}`,
    };
  }
  return { cents, valid: true, reason: null };
}

/**
 * Validate a withdraw amount: parseable, >= $1, and <= the available balance.
 * `balanceCents` is the current usable cash balance.
 */
export function validateWithdraw(
  input: string | number,
  balanceCents: number,
): AmountValidation {
  const base = validateDeposit(input);
  if (!base.valid) return base;
  const bal = isFinite(balanceCents) ? balanceCents : 0;
  if (base.cents > bal) {
    return {
      cents: base.cents,
      valid: false,
      reason: `Exceeds balance (${formatCents(bal)})`,
    };
  }
  return base;
}
