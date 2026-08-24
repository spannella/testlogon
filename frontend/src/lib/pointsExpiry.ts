// Pure helpers for the REWARDS POINTS EXPIRY + STATEMENT surface.
// No React / no network — unit-testable in isolation (see pointsExpiry.test.ts).
//
// Points are whole integers. Timestamps are UNIX SECONDS on the wire (rewards
// history + authoritative expiry), but this module works in MILLISECONDS
// internally for date math; callers pass `nowMs` in ms and each entry's `ts`
// (seconds) is normalized on the way in.
//
// CANONICAL POLICY (shared with Android):
//   EXPIRY_MONTHS      = 12   points expire 12 months after they were earned
//   EXPIRING_SOON_DAYS = 60   "expiring soon" = within 60 days from now

import type { RewardHistoryEntry } from "@/api/endpoints/rewards";

/** Points expire this many months after the date they were earned. */
export const EXPIRY_MONTHS = 12;
/** A lot counts as "expiring soon" when it expires within this many days. */
export const EXPIRING_SOON_DAYS = 60;

const DAY_MS = 86_400_000;
/** Seconds-vs-ms heuristic: values below this are treated as seconds. */
const MS_THRESHOLD = 1e12;

/** Normalize a wire timestamp (seconds OR ms) to milliseconds. */
export function tsToMs(ts: number | null | undefined): number {
  if (ts == null || !Number.isFinite(ts)) return Number.NaN;
  return ts < MS_THRESHOLD ? ts * 1000 : ts;
}

/**
 * Add `n` calendar months to an epoch-ms timestamp. Clamps the day-of-month so
 * e.g. Jan 31 + 1mo -> Feb 28/29 (never rolls into March). Pure, deterministic.
 */
export function addMonths(ms: number, n: number): number {
  if (!Number.isFinite(ms)) return Number.NaN;
  const d = new Date(ms);
  const day = d.getUTCDate();
  const base = new Date(
    Date.UTC(
      d.getUTCFullYear(),
      d.getUTCMonth(),
      1,
      d.getUTCHours(),
      d.getUTCMinutes(),
      d.getUTCSeconds(),
      d.getUTCMilliseconds(),
    ),
  );
  base.setUTCMonth(base.getUTCMonth() + n);
  // Clamp day to the last valid day of the target month.
  const lastDay = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth() + 1, 0)).getUTCDate();
  base.setUTCDate(Math.min(day, lastDay));
  return base.getTime();
}

/** True when an entry adds points to the balance (an EARN lot). */
function isEarn(e: RewardHistoryEntry): boolean {
  return Number.isFinite(e.points) && e.points > 0;
}
/** Magnitude of a debit (redeem/expire/reverse) in points, else 0. */
function debitPoints(e: RewardHistoryEntry): number {
  return Number.isFinite(e.points) && e.points < 0 ? -e.points : 0;
}

/** A remaining earn lot after FIFO consumption. */
export interface ExpiryLot {
  earnedTs: number; // ms
  remaining: number; // whole points still live in this lot
  expiresTs: number; // ms = earnedTs + policyMonths
}

export interface ExpiryComputation {
  lots: ExpiryLot[];
  expiringSoonPoints: number;
  nextExpiryTs: number | null; // ms
  nextExpiryPoints: number;
}

/**
 * Compute remaining live earn-lots + expiry view from the rewards history,
 * FIFO (oldest-earned consumed first by redeem/expire/reverse debits). Lots
 * that have ALREADY expired (expiresTs <= nowMs) are dropped from the live view.
 *
 * `entries` are the raw history rows (ts in seconds); `nowMs` is the reference
 * "now" in ms; `policyMonths` defaults to EXPIRY_MONTHS.
 */
export function computeExpiryFromHistory(
  entries: RewardHistoryEntry[] | null | undefined,
  nowMs: number,
  policyMonths: number = EXPIRY_MONTHS,
): ExpiryComputation {
  const empty: ExpiryComputation = {
    lots: [],
    expiringSoonPoints: 0,
    nextExpiryTs: null,
    nextExpiryPoints: 0,
  };
  if (!Array.isArray(entries) || entries.length === 0 || !Number.isFinite(nowMs)) {
    return empty;
  }

  // Chronological order (oldest first) so FIFO consumption is deterministic.
  const ordered = [...entries]
    .filter((e) => e && Number.isFinite(e.points) && Number.isFinite(tsToMs(e.ts)))
    .sort((a, b) => tsToMs(a.ts) - tsToMs(b.ts));

  // Build the queue of earn lots and apply debits FIFO across them.
  const lots: { earnedTs: number; remaining: number }[] = [];
  for (const e of ordered) {
    if (isEarn(e)) {
      lots.push({ earnedTs: tsToMs(e.ts), remaining: Math.trunc(e.points) });
    } else {
      let debit = Math.trunc(debitPoints(e));
      // Consume oldest live lots first.
      for (const lot of lots) {
        if (debit <= 0) break;
        if (lot.remaining <= 0) continue;
        const take = Math.min(lot.remaining, debit);
        lot.remaining -= take;
        debit -= take;
      }
      // Any un-matched debit is simply ignored (nothing left to consume).
    }
  }

  const soonCutoff = nowMs + EXPIRING_SOON_DAYS * DAY_MS;
  const live: ExpiryLot[] = [];
  for (const lot of lots) {
    if (lot.remaining <= 0) continue;
    const expiresTs = addMonths(lot.earnedTs, policyMonths);
    if (expiresTs <= nowMs) continue; // already expired — not live
    live.push({ earnedTs: lot.earnedTs, remaining: lot.remaining, expiresTs });
  }
  // Soonest expiry first.
  live.sort((a, b) => a.expiresTs - b.expiresTs);

  let expiringSoonPoints = 0;
  for (const lot of live) {
    if (lot.expiresTs <= soonCutoff) expiringSoonPoints += lot.remaining;
  }

  const next = live.length > 0 ? live[0] : null;
  return {
    lots: live,
    expiringSoonPoints,
    nextExpiryTs: next ? next.expiresTs : null,
    nextExpiryPoints: next ? next.remaining : 0,
  };
}

/** One statement row: a history entry with a running balance after it applies. */
export interface StatementRow {
  ts: number; // seconds (as delivered)
  type: string;
  description: string;
  points: number; // signed delta
  cashCents: number;
  status: string;
  balanceAfter: number; // running points balance after this row
}

/**
 * Build statement rows in ASCENDING chronological order with a running
 * `balanceAfter` (never below zero). Pure — safe on empty/garbage input.
 */
export function statementRows(
  entries: RewardHistoryEntry[] | null | undefined,
): StatementRow[] {
  if (!Array.isArray(entries) || entries.length === 0) return [];
  const ordered = [...entries]
    .filter((e) => e && Number.isFinite(tsToMs(e.ts)))
    .sort((a, b) => tsToMs(a.ts) - tsToMs(b.ts));
  let balance = 0;
  const rows: StatementRow[] = [];
  for (const e of ordered) {
    const delta = Number.isFinite(e.points) ? Math.trunc(e.points) : 0;
    balance = Math.max(0, balance + delta);
    rows.push({
      ts: e.ts,
      type: e.type ?? "",
      description: e.description ?? "",
      points: delta,
      cashCents: Number.isFinite(e.cash_cents) ? e.cash_cents : 0,
      status: e.status ?? "",
      balanceAfter: balance,
    });
  }
  return rows;
}

/** Format an epoch-ms (or null) as a short local date, e.g. "Jan 5, 2026". */
export function formatExpiryDate(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return "—";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

/** Whole days from `nowMs` until `expiresTs` (min 0). */
export function daysUntil(expiresTs: number, nowMs: number): number {
  if (!Number.isFinite(expiresTs) || !Number.isFinite(nowMs)) return 0;
  return Math.max(0, Math.ceil((expiresTs - nowMs) / DAY_MS));
}

// ── CSV export (reuses the shared RFC-4180 helpers) ──────────────────

export const STATEMENT_CSV_HEADER = [
  "Date (ISO)",
  "Type",
  "Description",
  "Points",
  "Cash",
  "Status",
  "Balance",
];

/** Format signed cents as a plain decimal dollar string (no locale commas). */
function csvCents(cents: number): string {
  if (!Number.isFinite(cents) || cents === 0) return "";
  return (cents / 100).toFixed(2);
}

function csvIso(ts: number): string {
  const ms = tsToMs(ts);
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/** Build a statement CSV string from statement rows. Delegates escaping/joining
 *  to the shared `toCsv`/`csvEscape` helpers so quoting stays RFC-4180 correct. */
export function expiryToCsv(
  rows: StatementRow[],
  toCsv: (header: string[], rows: (string | number)[][]) => string,
): string {
  const body: (string | number)[][] = (rows ?? []).map((r) => [
    csvIso(r.ts),
    r.type,
    r.description,
    r.points > 0 ? `+${r.points}` : String(r.points),
    csvCents(r.cashCents),
    r.status,
    r.balanceAfter,
  ]);
  return toCsv(STATEMENT_CSV_HEADER, body);
}
