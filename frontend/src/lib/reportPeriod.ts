// Period scoping for EXPORT & REPORTING. Pure helpers to turn a preset (24h /
// 7d / 30d / all / custom) into a [from, to] window (ms) and to filter fills by
// their `ts` (which may be seconds OR ms). Kept framework-free so the reports
// page, the PnL page and the blotter panel all scope identically.

export type PeriodPreset = "24h" | "7d" | "30d" | "all" | "custom";

export interface PeriodRange {
  preset: PeriodPreset;
  /** inclusive lower bound in ms; null = unbounded (All). */
  fromMs: number | null;
  /** inclusive upper bound in ms; null = now/unbounded. */
  toMs: number | null;
}

export const PERIOD_LABELS: Record<PeriodPreset, string> = {
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  all: "All time",
  custom: "Custom range",
};

const DAY_MS = 24 * 60 * 60 * 1000;

/** Resolve a rolling preset to a concrete [fromMs, toMs] window relative to `now`. */
export function presetRange(preset: Exclude<PeriodPreset, "custom">, now = Date.now()): PeriodRange {
  switch (preset) {
    case "24h":
      return { preset, fromMs: now - DAY_MS, toMs: now };
    case "7d":
      return { preset, fromMs: now - 7 * DAY_MS, toMs: now };
    case "30d":
      return { preset, fromMs: now - 30 * DAY_MS, toMs: now };
    case "all":
    default:
      return { preset: "all", fromMs: null, toMs: null };
  }
}

/** Build a custom [from, to] range from date-input strings (YYYY-MM-DD or ISO).
 *  Empty bounds are treated as unbounded. `to` is pushed to end-of-day when it is
 *  a bare date so the last day is inclusive. */
export function customRange(from: string, to: string): PeriodRange {
  const fromMs = from ? Date.parse(from) : NaN;
  let toMs = to ? Date.parse(to) : NaN;
  // Bare YYYY-MM-DD parses to UTC midnight — extend to end-of-day for inclusivity.
  if (!Number.isNaN(toMs) && /^\d{4}-\d{2}-\d{2}$/.test(to)) toMs += DAY_MS - 1;
  return {
    preset: "custom",
    fromMs: Number.isNaN(fromMs) ? null : fromMs,
    toMs: Number.isNaN(toMs) ? null : toMs,
  };
}

/** Normalize a fill `ts` (seconds OR ms) to ms. */
const MS_THRESHOLD = 1e12;
export function tsToMs(ts: number): number {
  return ts < MS_THRESHOLD ? ts * 1000 : ts;
}

/** Filter any `{ ts }`-bearing rows to a period window. `all`/null bounds keep everything. */
export function filterByPeriod<T extends { ts: number }>(rows: T[], range: PeriodRange): T[] {
  if (range.fromMs == null && range.toMs == null) return rows;
  return rows.filter((r) => {
    const ms = tsToMs(r.ts);
    if (range.fromMs != null && ms < range.fromMs) return false;
    if (range.toMs != null && ms > range.toMs) return false;
    return true;
  });
}

/** A short human label for the active range (for headers / filenames / statements). */
export function periodLabel(range: PeriodRange): string {
  if (range.preset !== "custom") return PERIOD_LABELS[range.preset];
  const fmt = (ms: number | null) => (ms == null ? "…" : new Date(ms).toISOString().slice(0, 10));
  return `${fmt(range.fromMs)} → ${fmt(range.toMs)}`;
}

/** A filename-safe slug for the active range (used in export filenames). */
export function periodSlug(range: PeriodRange): string {
  if (range.preset !== "custom") return range.preset;
  const fmt = (ms: number | null) => (ms == null ? "start" : new Date(ms).toISOString().slice(0, 10));
  return `${fmt(range.fromMs)}_${fmt(range.toMs)}`;
}
