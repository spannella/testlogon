import { describe, expect, it } from "vitest";

import {
  secToMs,
  msToSec,
  clampDayOfMonth,
  clampDayOfWeek,
  nextRun,
  upcomingRuns,
  budgetRemainingCents,
  estimatedRunsRemaining,
  budgetSpentFraction,
  validatePlan,
  formatCents,
  frequencyLabel,
  ordinal,
  MIN_AMOUNT_CENTS,
  MAX_DAY_OF_MONTH,
  type DcaPlan,
  type DcaPlanDraft,
} from "./dca";

/** Build a plan from partial overrides with sane defaults. */
function makePlan(over: Partial<DcaPlan> = {}): DcaPlan {
  return {
    plan_id: "p1",
    target: { kind: "symbol", id: "1", label: "BTC-USD" },
    amount_cents: 5000,
    frequency: "daily",
    start_ts: msToSec(Date.UTC(2026, 0, 1, 12, 0, 0)),
    funding: "usd_wallet",
    status: "active",
    next_run_ts: msToSec(Date.UTC(2026, 0, 1, 12, 0, 0)),
    spent_cents: 0,
    buys_count: 0,
    created_ts: msToSec(Date.UTC(2026, 0, 1, 0, 0, 0)),
    ...over,
  };
}

describe("time + clamp helpers", () => {
  it("converts seconds <-> ms", () => {
    expect(secToMs(1000)).toBe(1_000_000);
    expect(secToMs(undefined)).toBe(0);
    expect(msToSec(1_500)).toBe(1);
    expect(msToSec(1_999)).toBe(1);
  });

  it("clamps day-of-month to [1,28]", () => {
    expect(clampDayOfMonth(0)).toBe(1);
    expect(clampDayOfMonth(15)).toBe(15);
    expect(clampDayOfMonth(31)).toBe(28);
    expect(clampDayOfMonth(undefined)).toBe(1);
  });

  it("clamps day-of-week to [0,6]", () => {
    expect(clampDayOfWeek(-1)).toBe(0);
    expect(clampDayOfWeek(3)).toBe(3);
    expect(clampDayOfWeek(9)).toBe(6);
  });
});

describe("upcomingRuns — daily", () => {
  it("projects consecutive days from the start when fromMs precedes start", () => {
    const start = Date.UTC(2026, 0, 1, 12, 0, 0);
    const plan = makePlan({ frequency: "daily", start_ts: msToSec(start) });
    const runs = upcomingRuns(plan, start - 5 * 86_400_000, 3);
    expect(runs).toEqual([
      start,
      start + 86_400_000,
      start + 2 * 86_400_000,
    ]);
  });

  it("starts at the next daily boundary when fromMs is mid-schedule", () => {
    const start = Date.UTC(2026, 0, 1, 12, 0, 0);
    const plan = makePlan({ frequency: "daily", start_ts: msToSec(start) });
    // ask from 2.5 days in -> next run is day 3 at the start time-of-day.
    const from = start + 2 * 86_400_000 + 3_600_000;
    const runs = upcomingRuns(plan, from, 2);
    expect(runs[0]).toBe(start + 3 * 86_400_000);
    expect(runs[1]).toBe(start + 4 * 86_400_000);
  });
});

describe("upcomingRuns — weekly", () => {
  it("lands on the requested day_of_week each week", () => {
    // 2026-01-01 is a Thursday (getDay()===4) in local time on most TZs, but we
    // assert only the cadence + DOW invariant, which is TZ-agnostic.
    const start = new Date(2026, 0, 5, 9, 0, 0).getTime(); // Jan 5 2026 local
    const plan = makePlan({
      frequency: "weekly",
      day_of_week: 1, // Monday
      start_ts: msToSec(start),
    });
    const runs = upcomingRuns(plan, start, 3);
    expect(runs.length).toBe(3);
    for (const r of runs) expect(new Date(r).getDay()).toBe(1);
    // 7 days apart.
    expect(runs[1]! - runs[0]!).toBe(7 * 86_400_000);
    expect(runs[2]! - runs[1]!).toBe(7 * 86_400_000);
  });
});

describe("upcomingRuns — monthly", () => {
  it("lands on the requested day_of_month each month", () => {
    const start = new Date(2026, 0, 15, 8, 0, 0).getTime(); // Jan 15 2026 local
    const plan = makePlan({
      frequency: "monthly",
      day_of_month: 15,
      start_ts: msToSec(start),
    });
    const runs = upcomingRuns(plan, start, 3);
    expect(runs.length).toBe(3);
    expect(new Date(runs[0]!).getDate()).toBe(15);
    expect(new Date(runs[0]!).getMonth()).toBe(0);
    expect(new Date(runs[1]!).getMonth()).toBe(1); // Feb
    expect(new Date(runs[1]!).getDate()).toBe(15);
    expect(new Date(runs[2]!).getMonth()).toBe(2); // Mar
  });

  it("caps day_of_month at 28 so February is always valid", () => {
    const start = new Date(2026, 0, 31, 8, 0, 0).getTime();
    const plan = makePlan({
      frequency: "monthly",
      day_of_month: 31, // will be clamped to 28
      start_ts: msToSec(start),
    });
    const runs = upcomingRuns(plan, start, 3);
    for (const r of runs) {
      expect(new Date(r).getDate()).toBe(28);
    }
    // Jan 28 precedes the Jan-31 start, so the first run is Feb 28 (non-leap 2026).
    expect(new Date(runs[0]!).getMonth()).toBe(1);
    expect(new Date(runs[0]!).getDate()).toBe(28);
    expect(new Date(runs[1]!).getMonth()).toBe(2); // Mar
  });
});

describe("upcomingRuns — bounds + status", () => {
  it("returns nothing for paused / cancelled / completed", () => {
    const plan = makePlan({ status: "paused" });
    expect(upcomingRuns(plan, secToMs(plan.start_ts), 5)).toEqual([]);
    expect(upcomingRuns(makePlan({ status: "cancelled" }), 0, 5)).toEqual([]);
    expect(upcomingRuns(makePlan({ status: "completed" }), 0, 5)).toEqual([]);
  });

  it("stops at end_ts", () => {
    const start = Date.UTC(2026, 0, 1, 12, 0, 0);
    const end = start + 2 * 86_400_000; // allow days 0,1,2
    const plan = makePlan({
      frequency: "daily",
      start_ts: msToSec(start),
      end_ts: msToSec(end),
    });
    const runs = upcomingRuns(plan, start, 10);
    expect(runs.length).toBe(3);
    expect(runs[runs.length - 1]).toBe(end);
  });

  it("stops when the budget can no longer afford another buy", () => {
    const start = Date.UTC(2026, 0, 1, 12, 0, 0);
    const plan = makePlan({
      frequency: "daily",
      amount_cents: 5000,
      total_budget_cents: 12000, // affords 2 more (spent 0)
      spent_cents: 0,
      start_ts: msToSec(start),
    });
    const runs = upcomingRuns(plan, start, 10);
    expect(runs.length).toBe(2);
  });

  it("returns nothing once the budget is exhausted", () => {
    const plan = makePlan({
      amount_cents: 5000,
      total_budget_cents: 10000,
      spent_cents: 10000,
    });
    expect(upcomingRuns(plan, secToMs(plan.start_ts), 5)).toEqual([]);
  });

  it("guards zero / negative n and amount", () => {
    expect(upcomingRuns(makePlan(), 0, 0)).toEqual([]);
    expect(upcomingRuns(makePlan({ amount_cents: 0 }), 0, 3)).toEqual([]);
  });
});

describe("nextRun", () => {
  it("returns the first upcoming run", () => {
    const start = Date.UTC(2026, 0, 1, 12, 0, 0);
    const plan = makePlan({ frequency: "daily", start_ts: msToSec(start) });
    expect(nextRun(plan, start - 86_400_000)).toBe(start);
  });

  it("returns null when there is no future run", () => {
    expect(nextRun(makePlan({ status: "cancelled" }), 0)).toBeNull();
  });
});

describe("budget math", () => {
  it("computes remaining budget for a capped plan", () => {
    expect(budgetRemainingCents(makePlan({ total_budget_cents: 10000, spent_cents: 3000 }))).toBe(
      7000,
    );
    expect(budgetRemainingCents(makePlan({ total_budget_cents: 10000, spent_cents: 15000 }))).toBe(
      0,
    );
  });

  it("returns null remaining for an uncapped plan", () => {
    expect(budgetRemainingCents(makePlan({ total_budget_cents: undefined }))).toBeNull();
  });

  it("estimates whole runs remaining", () => {
    expect(
      estimatedRunsRemaining(makePlan({ amount_cents: 5000, total_budget_cents: 12000, spent_cents: 0 })),
    ).toBe(2);
    expect(estimatedRunsRemaining(makePlan({ total_budget_cents: undefined }))).toBeNull();
  });

  it("computes spent fraction, clamped", () => {
    expect(budgetSpentFraction(makePlan({ total_budget_cents: 10000, spent_cents: 2500 }))).toBe(
      0.25,
    );
    expect(budgetSpentFraction(makePlan({ total_budget_cents: 10000, spent_cents: 99999 }))).toBe(1);
    expect(budgetSpentFraction(makePlan({ total_budget_cents: undefined }))).toBe(0);
  });
});

describe("validatePlan", () => {
  const base: DcaPlanDraft = {
    target: { kind: "symbol", id: "1", label: "BTC" },
    amount_cents: 5000,
    frequency: "daily",
    start_ts: msToSec(Date.UTC(2026, 0, 1)),
  };

  it("accepts a valid daily draft", () => {
    expect(validatePlan(base).valid).toBe(true);
  });

  it("requires a target", () => {
    const v = validatePlan({ ...base, target: null });
    expect(v.valid).toBe(false);
    expect(v.errors).toContain("no_target");
  });

  it("enforces the minimum amount", () => {
    const v = validatePlan({ ...base, amount_cents: MIN_AMOUNT_CENTS - 1 });
    expect(v.errors).toContain("amount_below_min");
  });

  it("requires a valid day_of_week for weekly", () => {
    expect(validatePlan({ ...base, frequency: "weekly", day_of_week: 9 }).errors).toContain(
      "invalid_day_of_week",
    );
    expect(validatePlan({ ...base, frequency: "weekly", day_of_week: 2 }).valid).toBe(true);
  });

  it("requires a valid day_of_month for monthly", () => {
    expect(
      validatePlan({ ...base, frequency: "monthly", day_of_month: MAX_DAY_OF_MONTH + 1 }).errors,
    ).toContain("invalid_day_of_month");
    expect(validatePlan({ ...base, frequency: "monthly", day_of_month: 15 }).valid).toBe(true);
  });

  it("rejects end <= start", () => {
    expect(
      validatePlan({ ...base, end_ts: base.start_ts }).errors,
    ).toContain("end_before_start");
    expect(validatePlan({ ...base, end_ts: base.start_ts + 86_400 }).valid).toBe(true);
  });

  it("rejects a budget below one buy", () => {
    expect(
      validatePlan({ ...base, amount_cents: 5000, total_budget_cents: 4000 }).errors,
    ).toContain("budget_below_amount");
    expect(
      validatePlan({ ...base, amount_cents: 5000, total_budget_cents: 5000 }).valid,
    ).toBe(true);
  });
});

describe("formatting", () => {
  it("formats cents", () => {
    expect(formatCents(123456)).toBe("$1,234.56");
    expect(formatCents(undefined)).toBe("—");
  });

  it("builds ordinals", () => {
    expect(ordinal(1)).toBe("1st");
    expect(ordinal(2)).toBe("2nd");
    expect(ordinal(3)).toBe("3rd");
    expect(ordinal(4)).toBe("4th");
    expect(ordinal(11)).toBe("11th");
    expect(ordinal(15)).toBe("15th");
    expect(ordinal(21)).toBe("21st");
  });

  it("labels the cadence", () => {
    expect(frequencyLabel("daily")).toBe("Daily");
    expect(frequencyLabel("weekly", 1)).toBe("Weekly on Monday");
    expect(frequencyLabel("monthly", undefined, 15)).toBe("Monthly on the 15th");
  });
});
