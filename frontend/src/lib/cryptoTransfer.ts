// Pure helpers for send-crypto-in-chat (EPIC B: FE-110 composer/confirm,
// FE-111 transfer card). Kept dependency-light + integer-based so validation,
// fiat-preview and direction/status derivation are unit-testable without React.

import type { Message } from "@/api/types";

export type TransferStatus = "pending" | "complete" | "failed";

// The wire/payload carried on a crypto_transfer message. Decimal amounts ride
// as STRINGS (crypto precision); the money-math below parses them to integer
// base units so there is no float drift.
export interface CryptoTransferPayload {
  asset: string;
  /** Human decimal amount, e.g. "0.5". */
  amount: string;
  /** Token decimals (18 for ETH, 6 for USDC…) — for base-unit conversion. */
  decimals: number;
  /** Recipient display name / id (attribution). */
  to?: string;
  /** Sender display name / id (attribution). */
  from?: string;
  /** USD cents equivalent shown at compose time (indicative). */
  fiat_cents?: number;
  status: TransferStatus;
}

// ── amount <-> base-unit parsing (pure integer) ──────────────────
//
// Parse a decimal amount string into integer base units for the given decimals.
// Returns null for anything that is not a clean, non-negative decimal (so the
// caller can reject it). No floats: we scale digit-strings by hand.

export function parseAmountToBaseUnits(
  amountStr: string,
  decimals: number,
): bigint | null {
  if (amountStr == null) return null;
  const s = String(amountStr).trim();
  if (s === "") return null;
  if (!/^\d*\.?\d*$/.test(s)) return null; // digits + at most one dot
  if (s === ".") return null;
  const [intPart = "", fracPartRaw = ""] = s.split(".");
  if (intPart === "" && fracPartRaw === "") return null;
  if (fracPartRaw.length > decimals) return null; // more precision than the token has
  const frac = fracPartRaw.padEnd(decimals, "0");
  const digits = (intPart === "" ? "0" : intPart) + frac;
  try {
    return BigInt(digits);
  } catch {
    return null;
  }
}

// ── fiat-equivalent (integer cents) ──────────────────────────────
//
// fiat cents = amount(whole coin) * ratePerWholeCoinCents. Computed on the
// base-unit integer so there is no float drift:
//   cents = round( baseUnits * rateCents / 10^decimals )

export function fiatEquivalentCents(
  amountStr: string,
  ratePerWholeCoinCents: number,
  decimals: number,
): number | null {
  const base = parseAmountToBaseUnits(amountStr, decimals);
  if (base == null) return null;
  if (!Number.isFinite(ratePerWholeCoinCents) || ratePerWholeCoinCents < 0) return null;
  const rate = BigInt(Math.round(ratePerWholeCoinCents));
  const scale = 10n ** BigInt(decimals);
  const num = base * rate;
  // round-half-up on the division by scale
  const cents = (num + scale / 2n) / scale;
  return Number(cents);
}

// ── validation ───────────────────────────────────────────────────

export interface ValidateSendArgs {
  /** Either a pre-parsed base-unit amount OR a decimal string (+decimals). */
  amountBaseUnits?: bigint | string | number;
  amountStr?: string;
  decimals?: number;
  /** Available balance in the SAME base units (bigint | decimal-string | number). */
  balance?: bigint | string | number;
  balanceStr?: string;
  /** Optional per-transfer min/max in base units (same convention as amount). */
  min?: bigint | string | number;
  max?: bigint | string | number;
  /** KYC gate — false ⇒ blocked with reason "kyc". */
  kycOk?: boolean;
}

export type ValidateReason =
  | "empty"
  | "invalid"
  | "nonpositive"
  | "insufficient"
  | "below_min"
  | "over_max"
  | "kyc";

export interface ValidateResult {
  ok: boolean;
  reason?: ValidateReason;
}

function toBase(
  v: bigint | string | number | undefined,
  decimals: number,
): bigint | null | undefined {
  if (v === undefined) return undefined;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) return null;
    return parseAmountToBaseUnits(String(v), decimals);
  }
  return parseAmountToBaseUnits(v, decimals);
}

/**
 * The single validation choke point for a crypto send. Order of checks:
 * kyc → parseable → > 0 → ≥ min → ≤ max → ≤ balance. Everything is compared in
 * integer base units so there is no float drift.
 */
export function validateSend(args: ValidateSendArgs): ValidateResult {
  const decimals = args.decimals ?? 18;

  if (args.kycOk === false) return { ok: false, reason: "kyc" };

  // Resolve the amount (base-units wins; else parse amountStr).
  let amount: bigint | null | undefined;
  if (args.amountBaseUnits !== undefined) {
    amount = toBase(args.amountBaseUnits, decimals);
  } else if (args.amountStr !== undefined) {
    if (args.amountStr.trim() === "") return { ok: false, reason: "empty" };
    amount = parseAmountToBaseUnits(args.amountStr, decimals);
  } else {
    return { ok: false, reason: "empty" };
  }
  if (amount == null) return { ok: false, reason: "invalid" };
  if (amount <= 0n) return { ok: false, reason: "nonpositive" };

  const min = toBase(args.min, decimals);
  if (min != null && amount < min) return { ok: false, reason: "below_min" };

  const max = toBase(args.max, decimals);
  if (max != null && amount > max) return { ok: false, reason: "over_max" };

  const balance = toBase(args.balance ?? args.balanceStr, decimals);
  if (balance != null && amount > balance) return { ok: false, reason: "insufficient" };

  return { ok: true };
}

// ── direction / status / preview (renderer + list preview) ───────

/**
 * Which way a crypto_transfer message points relative to the viewer. Prefers an
 * explicit `isOwn`; else compares the message sender to `currentUserId`.
 */
export function transferDirection(
  msg: Pick<Message, "sender_id"> & { isOwn?: boolean },
  currentUserId?: string,
): "sent" | "received" {
  if (typeof msg.isOwn === "boolean") return msg.isOwn ? "sent" : "received";
  if (currentUserId && msg.sender_id === currentUserId) return "sent";
  return "received";
}

const STATUS_LABELS: Record<TransferStatus, string> = {
  pending: "Pending",
  complete: "Complete",
  failed: "Failed",
};

export function statusLabel(status: string | undefined | null): string {
  if (status && status in STATUS_LABELS) return STATUS_LABELS[status as TransferStatus];
  return "Pending";
}

export type BadgeVariant = "pending" | "success" | "danger";

export function badgeVariant(status: string | undefined | null): BadgeVariant {
  if (status === "complete") return "success";
  if (status === "failed") return "danger";
  return "pending";
}

/** Trim trailing zeros from a decimal amount for display ("0.50" -> "0.5"). */
export function trimAmount(amountStr: string): string {
  const s = String(amountStr ?? "").trim();
  if (!/^\d*\.?\d*$/.test(s) || s === "" || s === ".") return s;
  if (!s.includes(".")) return s;
  const trimmed = s.replace(/0+$/, "").replace(/\.$/, "");
  return trimmed === "" ? "0" : trimmed;
}

/** e.g. "0.5 ETH". */
export function amountLabel(amount: string, asset: string): string {
  return `${trimAmount(amount)} ${asset}`;
}

/** e.g. "$1,250.00" from integer cents. */
export function formatFiatCents(cents: number | null | undefined): string {
  if (cents == null || !Number.isFinite(cents)) return "";
  return `$${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

/** Conversation-list / reply preview: "[Sent 0.5 ETH]" / "[Received 0.5 ETH]". */
export function transferPreview(
  msg: Pick<Message, "sender_id"> & {
    isOwn?: boolean;
    asset?: string | null;
    amount?: string | null;
  },
  currentUserId?: string,
): string {
  const dir = transferDirection(msg, currentUserId);
  const verb = dir === "sent" ? "Sent" : "Received";
  const asset = msg.asset ?? "";
  const amount = msg.amount != null ? trimAmount(String(msg.amount)) : "";
  const body = [amount, asset].filter(Boolean).join(" ").trim();
  return body ? `[${verb} ${body}]` : `[${verb} crypto]`;
}
