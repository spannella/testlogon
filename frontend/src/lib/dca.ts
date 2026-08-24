/**
 * Pure, framework-free math for the DCA / RECURRING BUYS surface.
 *
 * A user schedules recurring dollar-cost-average buys of a target (a market
 * SYMBOL, a creator TOKEN, or a STRATEGY / basket fund), funded from their USD
 * cash wallet. The FRONTEND owns plan CRUD + a schedule PREVIEW (the next N run
 * timestamps) + execution HISTORY; the periodic execution itself is a
 * SERVER-SIDE runner ("recurring buys run automatically server-side once
 * scheduled").
 *
 * CONVENTIONS (locked): every monetary amount is INTEGER CENTS. Nothing here
 * touches React, the network, or the DOM — deterministic and unit-tested in
 * `dca.test.ts`. Timestamps are epoch MILLISECONDS at the boundary of these
 * helpers (`fromMs`, returned run times); the wire `start_ts` / `end_ts` /
 * `next_run_ts` are epoch SECONDS (matching the rest of the money surfaces), so
 * callers convert with the tiny helpers below.
 */

// -- Wire types (mirror api/endpoints/dca.ts, duplicated to keep this pure) --

export type DcaTargetKind = "symbol" | "token" | "strategy";
export type DcaFrequency = "daily" | "weekly" | "monthly";
export type DcaStatus = "active" | "paused" | "completed" | "cancelled";

export interface DcaTarget {
  kind: DcaTargetKind;
  id: string;
  label: string;
}

export interface DcaPlan {
  plan_id: string;
  target: DcaTarget;
  amount_cents: number;
  frequency: DcaFrequency;
  /** 0 (Sun) .. 6 (Sat) — required for weekly. */
  day_of_week?: number;
  /** 1 .. 28 — required for monthly (capped at 28 so every month is valid). */
  day_of_month?: number;
  /** Epoch SECONDS the schedule starts. */
  start_ts: number;
  /** Epoch SECONDS the schedule ends (optional). */
  end_ts?: number;
  /** Optional lifetime budget cap, in cents. */
  total_budget_cents?: number;
  funding: "usd_wallet";
  status: DcaStatus;
  /** Epoch SECONDS of the next scheduled run (server-authoritative when live). */
  next_run_ts: number;
  /** Cents spent so far across executed buys. */
  spent_cents: number;
  /** Number of buys executed so far. */
  buys_count: number;
  created_ts: number;
}

// -- Constants ---------------------------------------------------------

/** Minimum per-buy amount, in cents ($1.00). */
export const MIN_AMOUNT_CENTS = 100;

/** Highest valid day-of-month — capped so Feb/short months always have it. */
export const MAX_DAY_OF_MONTH = 28;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

// -- Time helpers ------------------------------------------------------

/** Epoch seconds -> epoch milliseconds. */
export function secToMs(sec: number | undefined | null): number {
  return (Number.isFinite(sec as number) ? (sec as number) : 0) * 1000;
}

/** Epoch milliseconds -> epoch seconds (floored). */
export function msToSec(ms: number): number {
  return Math.floor((Number.isFinite(ms) ? ms : 0) / 1000);
}

/** Clamp a day-of-month into the valid [1, 28] range. */
export function clampDayOfMonth(dom: number | undefined | null): number {
  const n = Math.floor(Number.isFinite(dom as number) ? (dom as number) : 1);
  return Math.min(MAX_DAY_OF_MONTH, Math.max(1, n));
}

/** Clamp a day-of-week into the valid [0, 6] range. */
export function clampDayOfWeek(dow: number | undefined | null): number {
  const n = Math.floor(Number.isFinite(dow as number) ? (dow as number) : 0);
  return Math.min(6, Math.max(0, n));
}

// -- Schedule projection ----------------------------------------------

/**
 * The next run time (epoch MS) for a plan at-or-after `fromMs`, or `null` when
 * the plan will never run again (completed / cancelled / paused, past end, or
 * budget exhausted).
 *
 * The projection is a pure function of the plan fields and `fromMs`; it does NOT
 * read the server `next_run_ts` (that is used for display only, since the runner
 * is authoritative once it ships). The first candidate is the later of the
 * plan start and `fromMs`; from there we advance by the cadence.
 */
export function nextRun(plan: DcaPlan, fromMs: number): number | null {
  const runs = upcomingRuns(plan, fromMs, 1);
  return runs.length ? runs[0]! : null;
}

/**
 * Project the next `n` run timestamps (epoch MS) at-or-after `fromMs`,
 * respecting start / end and the budget cap (a plan stops once it can no longer
 * afford another buy). Returns fewer than `n` when the schedule ends first.
 *
 *  - daily   : every calendar day from the start anchor.
 *  - weekly  : the plan's `day_of_week` each week (defaults to the start's DOW).
 *  - monthly : the plan's `day_of_month` each month (capped at 28), so Feb and
 *              30-day months are always valid.
 *
 * A paused / cancelled / completed plan yields no runs. Runs beyond `end_ts` (or
 * beyond the affordable budget) are dropped.
 */
export function upcomingRuns(plan: DcaPlan, fromMs: number, n: number): number[] {
  const out: number[] = [];
  if (!plan || n <= 0) return out;
  if (plan.status === "paused" || plan.status === "cancelled" || plan.status === "completed") {
    return out;
  }
  if (!Number.isFinite(plan.amount_cents) || plan.amount_cents <= 0) return out;

  const startMs = secToMs(plan.start_ts);
  const endMs = plan.end_ts != null ? secToMs(plan.end_ts) : null;

  // How many more buys can the budget still afford (null -> unlimited)?
  const remainingBudget =
    plan.total_budget_cents != null && plan.total_budget_cents > 0
      ? Math.max(0, plan.total_budget_cents - Math.max(0, plan.spent_cents))
      : null;
  let buysLeft =
    remainingBudget != null ? Math.floor(remainingBudget / plan.amount_cents) : Infinity;
  if (buysLeft <= 0) return out;

  const anchor = Math.max(startMs, fromMs);

  let cursor: number | null;
  switch (plan.frequency) {
    case "daily":
      cursor = firstDailyOnOrAfter(startMs, anchor);
      break;
    case "weekly":
      cursor = firstWeeklyOnOrAfter(startMs, anchor, plan.day_of_week);
      break;
    case "monthly":
      cursor = firstMonthlyOnOrAfter(startMs, anchor, plan.day_of_month);
      break;
    default:
      return out;
  }

  while (cursor != null && out.length < n && buysLeft > 0) {
    if (endMs != null && cursor > endMs) break;
    out.push(cursor);
    buysLeft -= 1;
    cursor = advance(cursor, plan.frequency, plan.day_of_month);
  }
  return out;
}

/** First daily run on-or-after `anchor`, aligned to the start's time-of-day. */
function firstDailyOnOrAfter(startMs: number, anchor: number): number {
  if (anchor <= startMs) return startMs;
  const elapsed = anchor - startMs;
  const periods = Math.ceil(elapsed / MS_PER_DAY);
  return startMs + periods * MS_PER_DAY;
}

/** First weekly run on-or-after `anchor` on the plan's day-of-week. */
function firstWeeklyOnOrAfter(startMs: number, anchor: number, dow?: number): number {
  const targetDow = dow != null ? clampDayOfWeek(dow) : new Date(startMs).getDay();
  const base = new Date(startMs);
  const floor = Math.max(startMs, anchor);
  let d = withTimeOfDay(new Date(floor), base);
  // Walk day-by-day to the first matching DOW that is on-or-after the floor.
  while (d.getTime() < floor || d.getDay() !== targetDow) {
    d = new Date(d.getTime() + MS_PER_DAY);
    d = withTimeOfDay(d, base);
  }
  return d.getTime();
}

/** First monthly run on-or-after `anchor` on the plan's day-of-month. */
function firstMonthlyOnOrAfter(startMs: number, anchor: number, dom?: number): number {
  const base = new Date(startMs);
  const targetDom = dom != null ? clampDayOfMonth(dom) : clampDayOfMonth(base.getDate());
  const floor = Math.max(startMs, anchor);
  const from = new Date(floor);
  let year = from.getFullYear();
  let month = from.getMonth();
  for (let i = 0; i < 600; i++) {
    const cand = makeMonthly(year, month, targetDom, base);
    if (cand >= floor) return cand;
    month += 1;
    if (month > 11) {
      month = 0;
      year += 1;
    }
  }
  return makeMonthly(year, month, targetDom, base);
}

/** Advance one cadence step from `ms`. */
function advance(ms: number, freq: DcaFrequency, dom?: number): number {
  if (freq === "daily") return ms + MS_PER_DAY;
  if (freq === "weekly") return ms + 7 * MS_PER_DAY;
  // monthly: same day-of-month next month (capped), preserving time-of-day.
  const base = new Date(ms);
  const targetDom = dom != null ? clampDayOfMonth(dom) : clampDayOfMonth(base.getDate());
  let year = base.getFullYear();
  let month = base.getMonth() + 1;
  if (month > 11) {
    month = 0;
    year += 1;
  }
  return makeMonthly(year, month, targetDom, base);
}

/** Build a Date at year/month/day with the time-of-day copied from `base`. */
function makeMonthly(year: number, month: number, dom: number, base: Date): number {
  const d = new Date(
    year,
    month,
    dom,
    base.getHours(),
    base.getMinutes(),
    base.getSeconds(),
    base.getMilliseconds(),
  );
  return d.getTime();
}

/** Copy the hours/min/sec/ms of `base` onto the date part of `d`. */
function withTimeOfDay(d: Date, base: Date): Date {
  return new Date(
    d.getFullYear(),
    d.getMonth(),
    d.getDate(),
    base.getHours(),
    base.getMinutes(),
    base.getSeconds(),
    base.getMilliseconds(),
  );
}

// -- Budget math -------------------------------------------------------

/**
 * Remaining budget (cents) for a capped plan = max(0, total - spent). Returns
 * null for an uncapped plan (no total_budget_cents).
 */
export function budgetRemainingCents(plan: DcaPlan): number | null {
  if (plan.total_budget_cents == null || !(plan.total_budget_cents > 0)) return null;
  return Math.max(0, plan.total_budget_cents - Math.max(0, plan.spent_cents));
}

/**
 * Estimated whole buys remaining for a capped plan = floor(remaining / amount).
 * Returns null for an uncapped plan (unbounded), 0 when exhausted.
 */
export function estimatedRunsRemaining(plan: DcaPlan): number | null {
  const remaining = budgetRemainingCents(plan);
  if (remaining == null) return null;
  if (!(plan.amount_cents > 0)) return 0;
  return Math.floor(remaining / plan.amount_cents);
}

/** Fraction (0..1) of the budget already spent, for a progress gauge. Uncapped -> 0. */
export function budgetSpentFraction(plan: DcaPlan): number {
  if (plan.total_budget_cents == null || !(plan.total_budget_cents > 0)) return 0;
  const f = Math.max(0, plan.spent_cents) / plan.total_budget_cents;
  return Math.min(1, Math.max(0, f));
}

// -- Validation --------------------------------------------------------

export type DcaValidationError =
  | "no_target"
  | "amount_below_min"
  | "invalid_frequency"
  | "invalid_day_of_week"
  | "invalid_day_of_month"
  | "end_before_start"
  | "budget_below_amount";

export interface DcaPlanDraft {
  target?: DcaTarget | null;
  amount_cents: number;
  frequency: DcaFrequency;
  day_of_week?: number;
  day_of_month?: number;
  /** Epoch SECONDS. */
  start_ts: number;
  /** Epoch SECONDS. */
  end_ts?: number;
  total_budget_cents?: number;
}

export interface DcaValidation {
  valid: boolean;
  errors: DcaValidationError[];
}

/**
 * Validate a plan draft before creation: a target must be chosen, the amount
 * must be >= the minimum, the frequency must be valid with a valid day for the
 * weekly / monthly cadence, any end must be strictly after the start, and any
 * total budget must cover at least one buy.
 */
export function validatePlan(draft: DcaPlanDraft): DcaValidation {
  const errors: DcaValidationError[] = [];

  if (!draft.target || !draft.target.id) errors.push("no_target");

  if (!Number.isFinite(draft.amount_cents) || draft.amount_cents < MIN_AMOUNT_CENTS) {
    errors.push("amount_below_min");
  }

  if (
    draft.frequency !== "daily" &&
    draft.frequency !== "weekly" &&
    draft.frequency !== "monthly"
  ) {
    errors.push("invalid_frequency");
  }

  if (draft.frequency === "weekly") {
    const d = draft.day_of_week;
    if (d == null || !Number.isInteger(d) || d < 0 || d > 6) errors.push("invalid_day_of_week");
  }

  if (draft.frequency === "monthly") {
    const d = draft.day_of_month;
    if (d == null || !Number.isInteger(d) || d < 1 || d > MAX_DAY_OF_MONTH) {
      errors.push("invalid_day_of_month");
    }
  }

  if (draft.end_ts != null && Number.isFinite(draft.end_ts)) {
    if (draft.end_ts <= draft.start_ts) errors.push("end_before_start");
  }

  if (
    draft.total_budget_cents != null &&
    draft.total_budget_cents > 0 &&
    Number.isFinite(draft.amount_cents) &&
    draft.amount_cents > 0 &&
    draft.total_budget_cents < draft.amount_cents
  ) {
    errors.push("budget_below_amount");
  }

  return { valid: errors.length === 0, errors };
}

// -- Formatting --------------------------------------------------------

/** Integer cents -> "$1,234.56". Non-finite -> "—". */
export function formatCents(cents: number | undefined | null): string {
  if (cents == null || !Number.isFinite(cents)) return "—";
  return `$${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

/** Human day-of-week name for 0..6. */
export const DOW_LABELS = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
] as const;

/** Human summary of a plan cadence, e.g. "Weekly on Monday", "Monthly on the 15th". */
export function frequencyLabel(
  frequency: DcaFrequency,
  dayOfWeek?: number,
  dayOfMonth?: number,
): string {
  if (frequency === "daily") return "Daily";
  if (frequency === "weekly") {
    const dow = dayOfWeek != null ? DOW_LABELS[clampDayOfWeek(dayOfWeek)] : "Monday";
    return `Weekly on ${dow}`;
  }
  if (frequency === "monthly") {
    const dom = clampDayOfMonth(dayOfMonth ?? 1);
    return `Monthly on the ${ordinal(dom)}`;
  }
  return frequency;
}

/** English ordinal for 1..28. */
export function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return `${n}${s[(v - 20) % 10] ?? s[v] ?? s[0]}`;
}
