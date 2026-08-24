import { api } from "@/api/client";

// ============================================================================
// Pay-any-coin fees: quote -> confirm -> pay.
//
// A user can pay any USD-cent platform fee (tips, checkout, unlocks, ...) with
// ANY supported coin. The flow:
//   1. quoteFee({ amount_cents, pay_with })  -> a FeeQuote with the SHOWN rate,
//      the per-coin conversion fee, the coin amount, and a 60s-locked
//      `quote_token` (+ `expires_at` / `locked_seconds`).
//   2. Show describeQuote(quote) in a confirm dialog (rate + fee + total).
//   3. On confirm, pass the SAME `quote_token` to the pay call so the locked
//      rate is honored server-side. If the token has expired the server returns
//      409 quote_expired -> re-quote and show the new rate before charging.
//
// Backend contract:
//   POST /me/fees/quote  { amount_cents, pay_with } -> FeeQuote
//   Pay endpoints accept { pay_with, quote_token }:
//     POST /ui/tips
//     POST /ui/checkout/orders/{order_id}/pay
//   pay_with "USD" = fiat wallet (no conversion); "USDC" = 1:1 stable; any other
//   supported coin = FX-converted at the quoted, locked rate.
//
// Error handling (ApiError.detail.code):
//   402 insufficient_<coin> / insufficient_balance  -> fund/top up first
//   409 quote_expired                                -> re-quote, re-confirm
//   422 unsupported_coin                             -> pick a supported coin
//   400 rate_unavailable / no_market                 -> no price for this coin yet
// ============================================================================

export type PayWith = "USD" | "USDC" | "BTC" | "ETH" | "SOL" | string;

export interface FeeQuoteReq {
  amount_cents: number;
  pay_with: PayWith;
}

export interface FeeQuoteRate {
  /** USD cents per 1 native unit of the coin (the money-math rate). */
  usd_cents_per_coin_native: number;
  /** Display-only "1 COIN = $X" (null if the coin's decimals aren't configured). */
  usd_per_whole_coin: number | null;
  /** "book_mid" when a live market exists, else "reference" (oracle/config fallback). */
  source: "book_mid" | "reference";
}

export interface FeeQuote {
  pay_with: PayWith;
  asset_id: number;
  amount_cents: number;
  rate: FeeQuoteRate;
  /** Per-coin conversion fee (basis points), from the coin's liquidity + variance. */
  conversion_fee_bps: number;
  conversion_fee_pct: number;
  liquidity: { spread_bps: number };
  variance: { realized_vol_bps: number };
  /** Coin native units to cover the fee (pre-conversion-fee). */
  coin_native: number;
  /** Extra native units taken as the conversion fee. */
  conversion_fee_native: number;
  /** Total native units debited on pay (coin_native + conversion_fee_native). */
  total_native: number;
  /** Unix seconds; the locked rate is valid until here. */
  expires_at: number;
  locked_seconds: number;
  /** Opaque signed token to pass to the pay call to honor the locked rate. */
  quote_token: string;
  // USD-wallet path only (no conversion):
  convertible?: boolean;
  note?: string;
}

/** Get a 60s rate-locked quote for paying `amount_cents` with `pay_with`. */
export const quoteFee = (body: FeeQuoteReq) =>
  api.post<FeeQuote>("/me/fees/quote", body);

// ---- pay calls that honor a locked quote ----------------------------------

export interface TipReq {
  recipient_user_id: string;
  amount_cents: number;
  content_type?: string;
  content_id?: string;
}

export interface PayResult {
  currency?: string;
  amount_cents?: number;
  net_cents?: number;
  platform_fee_cents?: number;
  coin_native_debited?: number;
  tip_id?: string;
  [k: string]: unknown;
}

/**
 * Send a creator tip. Pass the FeeQuote to pay with that coin at the locked
 * rate; omit it to pay from the USD wallet (pay_with defaults to "USD").
 */
export const payTip = (tip: TipReq, quote?: FeeQuote) =>
  api.post<PayResult>(
    "/ui/tips",
    quote
      ? { ...tip, pay_with: quote.pay_with, quote_token: quote.quote_token }
      : tip,
  );

/** Pay a pending checkout order; pass a FeeQuote to pay with that coin. */
export const payCheckout = (orderId: string, quote?: FeeQuote) =>
  api.post<PayResult>(
    `/ui/checkout/orders/${orderId}/pay`,
    quote ? { pay_with: quote.pay_with, quote_token: quote.quote_token } : {},
  );

// ---- display helpers -------------------------------------------------------

export interface QuoteDisplay {
  /** e.g. "1 SOL ≈ $150.00" */
  rateLabel: string;
  /** e.g. "1.75% conversion fee (SOL)" or "no conversion fee" */
  feeLabel: string;
  /** e.g. "Pay 11 SOL for $15.00" */
  totalLabel: string;
  /** Seconds until the locked rate expires (client clock). */
  expiresInSec: number;
  /** True once the lock has lapsed — re-quote before charging. */
  stale: boolean;
}

/** Human-readable labels for a quote, for the confirm dialog. */
export function describeQuote(q: FeeQuote): QuoteDisplay {
  const now = Math.floor(Date.now() / 1000);
  const expiresInSec = Math.max(0, q.expires_at - now);
  const usd = (q.amount_cents / 100).toFixed(2);
  const rateLabel =
    q.rate?.usd_per_whole_coin != null
      ? `1 ${q.pay_with} ≈ $${q.rate.usd_per_whole_coin.toLocaleString(undefined, {
          maximumFractionDigits: 2,
        })}`
      : q.convertible === false
        ? "Paid from USD wallet (1:1)"
        : `1 ${q.pay_with} unit ≈ $${((q.rate?.usd_cents_per_coin_native ?? 0) / 100).toFixed(4)}`;
  const feeLabel =
    q.conversion_fee_bps > 0
      ? `${q.conversion_fee_pct.toFixed(2)}% conversion fee (${q.pay_with})`
      : "no conversion fee";
  const totalLabel =
    q.convertible === false
      ? `Pay $${usd} from wallet`
      : `Pay ${q.total_native} ${q.pay_with} for $${usd}`;
  return { rateLabel, feeLabel, totalLabel, expiresInSec, stale: expiresInSec <= 0 };
}

/**
 * Default coin picker set. The authoritative list is the server's FEE_COIN_MAP;
 * this is the default beta set. Trim/extend as the server config evolves.
 */
export const SUPPORTED_PAY_COINS: PayWith[] = ["USD", "USDC", "BTC", "ETH", "SOL"];

// ============================================================================
// Maker/taker VIP FEE-TIER by 30-day trading volume (authoritative read).
//
// OPTIONAL authoritative read that overrides the client-side estimate computed
// from the trade-history feed. 404s until the exchange edge exposes it — callers
// MUST degrade to the client computation (retry:false / catch 404).
//
//   GET /me/fees/tier -> FeeTierResponse
// ============================================================================

export interface FeeTierNext {
  tier_id: string;
  name: string;
  /** 30-day volume (USD cents) required to reach this next tier. */
  volume_30d_cents: number;
  maker_bps: number;
  taker_bps: number;
}

export interface FeeTierResponse {
  /** Stable tier id (matches FEE_TIERS[].id in lib/feeTiers.ts). */
  tier_id: string;
  name: string;
  /** The caller's authoritative 30-day rolling volume, USD cents. */
  volume_30d_cents: number;
  maker_bps: number;
  taker_bps: number;
  /** The next-higher tier, absent when already at the top. */
  next_tier?: FeeTierNext | null;
}

/**
 * The caller's authoritative maker/taker fee tier. 404s until the edge deploys —
 * callers fall back to the client-side estimate from the fills feed.
 */
export const getFeeTier = () => api.get<FeeTierResponse>("/me/fees/tier");
