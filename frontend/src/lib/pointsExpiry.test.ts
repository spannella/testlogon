import { describe, expect, it } from "vitest";

import type { RewardHistoryEntry } from "@/api/endpoints/rewards";
import { toCsv } from "@/lib/exportReport";
import {
  EXPIRING_SOON_DAYS,
  EXPIRY_MONTHS,
  addMonths,
  computeExpiryFromHistory,
  daysUntil,
  expiryToCsv,
  formatExpiryDate,
  statementRows,
  tsToMs,
} from "@/lib/pointsExpiry";

const DAY = 86_400_000;

/** UNIX seconds for a UTC date. */
function secs(y: number, m: number, d: number): number {
  return Math.floor(Date.UTC(y, m - 1, d) / 1000);
}

function entry(part: Partial<RewardHistoryEntry> & { ts: number; points: number }): RewardHistoryEntry {
  return {
    ts: part.ts,
    type: part.type ?? "earn",
    description: part.description ?? "",
    points: part.points,
    cash_cents: part.cash_cents ?? 0,
    status: part.status ?? "posted",
  };
}

describe("policy constants", () => {
  it("matches the canonical shared-with-Android policy", () => {
    expect(EXPIRY_MONTHS).toBe(12);
    expect(EXPIRING_SOON_DAYS).toBe(60);
  });
});

describe("tsToMs", () => {
  it("scales seconds to ms and passes ms through", () => {
    expect(tsToMs(1_700_000_000)).toBe(1_700_000_000_000);
    expect(tsToMs(1_700_000_000_000)).toBe(1_700_000_000_000);
  });
  it("returns NaN for garbage", () => {
    expect(Number.isNaN(tsToMs(null))).toBe(true);
    expect(Number.isNaN(tsToMs(undefined))).toBe(true);
  });
});

describe("addMonths", () => {
  it("adds whole months", () => {
    const jan = Date.UTC(2026, 0, 15);
    expect(addMonths(jan, 12)).toBe(Date.UTC(2027, 0, 15));
  });
  it("clamps day-of-month at end-of-month (Jan 31 + 1mo -> Feb 28)", () => {
    const jan31 = Date.UTC(2026, 0, 31);
    expect(addMonths(jan31, 1)).toBe(Date.UTC(2026, 1, 28));
  });
  it("returns NaN for garbage input", () => {
    expect(Number.isNaN(addMonths(Number.NaN, 12))).toBe(true);
  });
});

describe("computeExpiryFromHistory", () => {
  it("guards empty / garbage input", () => {
    const now = Date.UTC(2026, 5, 1);
    expect(computeExpiryFromHistory([], now)).toEqual({
      lots: [],
      expiringSoonPoints: 0,
      nextExpiryTs: null,
      nextExpiryPoints: 0,
    });
    expect(computeExpiryFromHistory(null, now).lots).toEqual([]);
    expect(computeExpiryFromHistory([entry({ ts: secs(2026, 1, 1), points: 100 })], Number.NaN).lots).toEqual([]);
  });

  it("keeps a single un-touched earn lot with a +12mo expiry", () => {
    const earned = secs(2026, 1, 10);
    const now = Date.UTC(2026, 2, 1); // Mar 1 2026
    const r = computeExpiryFromHistory([entry({ ts: earned, points: 500 })], now);
    expect(r.lots).toHaveLength(1);
    expect(r.lots[0]!.remaining).toBe(500);
    expect(r.lots[0]!.expiresTs).toBe(addMonths(earned * 1000, EXPIRY_MONTHS));
    expect(r.nextExpiryPoints).toBe(500);
    expect(r.nextExpiryTs).toBe(r.lots[0]!.expiresTs);
  });

  it("consumes lots FIFO (oldest earned first)", () => {
    const e1 = secs(2026, 1, 1);
    const e2 = secs(2026, 3, 1);
    const now = Date.UTC(2026, 3, 15);
    const r = computeExpiryFromHistory(
      [
        entry({ ts: e1, points: 100 }),
        entry({ ts: e2, points: 100 }),
        entry({ ts: secs(2026, 3, 10), points: -120, type: "redeem" }),
      ],
      now,
    );
    // 120 consumed: all 100 from lot1, 20 from lot2 -> lot1 gone, lot2=80.
    expect(r.lots).toHaveLength(1);
    expect(r.lots[0]!.earnedTs).toBe(e2 * 1000);
    expect(r.lots[0]!.remaining).toBe(80);
  });

  it("drops already-expired lots", () => {
    const oldEarn = secs(2024, 1, 1); // expires Jan 2025
    const now = Date.UTC(2026, 0, 1); // 2026 — past expiry
    const r = computeExpiryFromHistory([entry({ ts: oldEarn, points: 300 })], now);
    expect(r.lots).toEqual([]);
    expect(r.nextExpiryTs).toBeNull();
  });

  it("flags points expiring within EXPIRING_SOON_DAYS", () => {
    // earned so it expires ~30 days from now (within the 60-day window).
    const now = Date.UTC(2026, 5, 1);
    const expiresSoon = now + 30 * DAY;
    const earnedForSoon = addMonths(expiresSoon, -EXPIRY_MONTHS);
    const earnedForLater = addMonths(now + 200 * DAY, -EXPIRY_MONTHS);
    const r = computeExpiryFromHistory(
      [
        entry({ ts: Math.floor(earnedForSoon / 1000), points: 40 }),
        entry({ ts: Math.floor(earnedForLater / 1000), points: 90 }),
      ],
      now,
    );
    expect(r.expiringSoonPoints).toBe(40);
    // soonest-first ordering
    expect(r.lots[0]!.remaining).toBe(40);
    expect(r.nextExpiryPoints).toBe(40);
  });

  it("ignores debits with nothing left to consume", () => {
    const now = Date.UTC(2026, 5, 1);
    const r = computeExpiryFromHistory(
      [entry({ ts: secs(2026, 1, 1), points: -50, type: "redeem" })],
      now,
    );
    expect(r.lots).toEqual([]);
  });
});

describe("statementRows", () => {
  it("returns [] for empty input", () => {
    expect(statementRows([])).toEqual([]);
    expect(statementRows(null)).toEqual([]);
  });

  it("orders ascending with a non-negative running balance", () => {
    const rows = statementRows([
      entry({ ts: secs(2026, 3, 1), points: -30, type: "redeem", description: "Redeem" }),
      entry({ ts: secs(2026, 1, 1), points: 100, type: "earn", description: "Signup" }),
      entry({ ts: secs(2026, 2, 1), points: 50, type: "earn" }),
    ]);
    expect(rows.map((r) => r.balanceAfter)).toEqual([100, 150, 120]);
    expect(rows[0]!.description).toBe("Signup");
  });

  it("clamps the running balance at zero on over-redemption", () => {
    const rows = statementRows([
      entry({ ts: secs(2026, 1, 1), points: 10 }),
      entry({ ts: secs(2026, 2, 1), points: -50, type: "redeem" }),
    ]);
    expect(rows[1]!.balanceAfter).toBe(0);
  });
});

describe("expiryToCsv", () => {
  it("emits a header + one row per statement row, with signed points", () => {
    const rows = statementRows([
      entry({ ts: secs(2026, 1, 1), points: 100, description: "Signup, welcome" }),
      entry({ ts: secs(2026, 2, 1), points: -40, type: "redeem", cash_cents: 400 }),
    ]);
    const csv = expiryToCsv(rows, toCsv);
    const lines = csv.split("\n");
    expect(lines[0]).toBe("Date (ISO),Type,Description,Points,Cash,Status,Balance");
    expect(lines).toHaveLength(3);
    // signed points + running balance present
    expect(lines[1]).toContain("+100");
    expect(lines[1]).toContain("100"); // balance
    expect(lines[2]).toContain("-40");
    expect(lines[2]).toContain("4.00"); // cash dollars
    // comma inside a description is RFC-4180 quoted
    expect(lines[1]).toContain('"Signup, welcome"');
  });

  it("emits just a header for empty rows", () => {
    expect(expiryToCsv([], toCsv)).toBe(
      "Date (ISO),Type,Description,Points,Cash,Status,Balance",
    );
  });
});

describe("formatExpiryDate / daysUntil", () => {
  it("formats null as an em dash", () => {
    expect(formatExpiryDate(null)).toBe("—");
    expect(formatExpiryDate(Number.NaN)).toBe("—");
  });
  it("formats a real date", () => {
    expect(formatExpiryDate(Date.UTC(2026, 0, 5, 12))).toContain("2026");
  });
  it("computes whole days until, min zero", () => {
    const now = Date.UTC(2026, 5, 1);
    expect(daysUntil(now + 10 * DAY, now)).toBe(10);
    expect(daysUntil(now - 5 * DAY, now)).toBe(0);
  });
});
