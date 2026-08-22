import { describe, expect, it } from "vitest";

import {
  toMs,
  tickToCents,
  normalizeFills,
  normalizeFunding,
  normalizeLiquidations,
  mergeEvents,
  groupByDay,
  dayKey,
  filterByCategory,
  isUnread,
  unreadCount,
  type ActivityEvent,
  type NormalizeContext,
} from "./activity";

const ctx: NormalizeContext = {
  symbolName: (id) => (id === 1 ? "BTC" : id === 2 ? "ETH" : `#${id}`),
  scalerFor: () => 100, // 100 ticks == 1 unit -> amountCents = tick
};

describe("toMs", () => {
  it("passes ms through and scales seconds to ms", () => {
    expect(toMs(1_700_000_000_000)).toBe(1_700_000_000_000);
    expect(toMs(1_700_000_000)).toBe(1_700_000_000_000);
  });
  it("returns 0 for missing / non-finite", () => {
    expect(toMs(undefined)).toBe(0);
    expect(toMs(NaN)).toBe(0);
  });
});

describe("tickToCents", () => {
  it("converts an int tick to integer cents via the scaler", () => {
    // 100 ticks / scaler 100 = 1 unit = 100 cents
    expect(tickToCents(100, ctx, 1)).toBe(100);
    expect(tickToCents(250, ctx, 1)).toBe(250);
  });
  it("defaults scaler to 1 when no context", () => {
    expect(tickToCents(5, undefined, 1)).toBe(500);
  });
  it("keeps sign and returns undefined for missing", () => {
    expect(tickToCents(-100, ctx, 1)).toBe(-100);
    expect(tickToCents(undefined, ctx, 1)).toBeUndefined();
  });
});

describe("normalizeFills", () => {
  it("maps a fill to a trade event with deep-link + severity", () => {
    const ev = normalizeFills(
      [{ symbolid: 1, price: 500, qty: 3, side: "buy", fee: 100, ts: 1_700_000_000 }],
      ctx,
    )[0]!;
    expect(ev.category).toBe("trade");
    expect(ev.kind).toBe("fill");
    expect(ev.title).toBe("Filled BTC");
    expect(ev.severity).toBe("success");
    expect(ev.href).toBe("/markets/1");
    expect(ev.ts).toBe(1_700_000_000_000);
    expect(ev.id).toContain("fill:1:");
  });
  it("handles empty / undefined", () => {
    expect(normalizeFills(undefined)).toEqual([]);
    expect(normalizeFills([])).toEqual([]);
  });
});

describe("normalizeFunding", () => {
  it("marks received funding as success with signed cents", () => {
    const ev = normalizeFunding(
      [{ symbolid: 2, payment: 100, received: true, funding_rate_bps: 12, ts: 1_700_000_100 }],
      ctx,
    )[0]!;
    expect(ev.category).toBe("funding");
    expect(ev.severity).toBe("success");
    expect(ev.amountCents).toBe(100);
    expect(ev.title).toBe("Funding received");
    expect(ev.href).toBe("/markets/2");
  });
  it("marks paid funding as info", () => {
    const ev = normalizeFunding([{ symbolid: 2, payment: -50, received: false, ts: 1 }], ctx)[0]!;
    expect(ev.severity).toBe("info");
    expect(ev.amountCents).toBe(-50);
    expect(ev.title).toBe("Funding paid");
  });
});

describe("normalizeLiquidations", () => {
  it("maps a liquidation to a critical event", () => {
    const ev = normalizeLiquidations(
      [{ symbolid: 1, qty: 5, mark_price: 400, realized_pnl: -300, ts: 1_700_000_200 }],
      ctx,
    )[0]!;
    expect(ev.category).toBe("liquidation");
    expect(ev.severity).toBe("critical");
    expect(ev.amountCents).toBe(-300);
    expect(ev.href).toBe("/portfolio/analytics");
  });
});

describe("mergeEvents", () => {
  const a: ActivityEvent = { id: "a", ts: 100, kind: "x", category: "trade", title: "A", severity: "info" };
  const b: ActivityEvent = { id: "b", ts: 300, kind: "x", category: "trade", title: "B", severity: "info" };
  const c: ActivityEvent = { id: "c", ts: 200, kind: "x", category: "trade", title: "C", severity: "info" };

  it("merges + sorts descending by ts", () => {
    const out = mergeEvents([a], [b, c]);
    expect(out.map((e) => e.id)).toEqual(["b", "c", "a"]);
  });
  it("dedupes by id (first occurrence wins)", () => {
    const dup: ActivityEvent = { ...a, title: "DUP" };
    const out = mergeEvents([a], [dup, b]);
    expect(out.filter((e) => e.id === "a")).toHaveLength(1);
    expect(out.find((e) => e.id === "a")!.title).toBe("A");
  });
  it("is a stable sort for equal ts (insertion order preserved)", () => {
    const t1: ActivityEvent = { ...a, id: "t1", ts: 500 };
    const t2: ActivityEvent = { ...a, id: "t2", ts: 500 };
    const out = mergeEvents([t1, t2]);
    expect(out.map((e) => e.id)).toEqual(["t1", "t2"]);
  });
});

describe("dayKey + groupByDay", () => {
  it("groups consecutive same-day events into one bucket", () => {
    const d1 = new Date(2024, 0, 2, 10, 0, 0).getTime();
    const d1b = new Date(2024, 0, 2, 12, 0, 0).getTime();
    const d0 = new Date(2024, 0, 1, 9, 0, 0).getTime();
    const events: ActivityEvent[] = [
      { id: "1", ts: d1b, kind: "x", category: "trade", title: "", severity: "info" },
      { id: "2", ts: d1, kind: "x", category: "trade", title: "", severity: "info" },
      { id: "3", ts: d0, kind: "x", category: "trade", title: "", severity: "info" },
    ];
    const groups = groupByDay(events);
    expect(groups).toHaveLength(2);
    expect(groups[0]!.day).toBe(dayKey(d1b));
    expect(groups[0]!.events.map((e) => e.id)).toEqual(["1", "2"]);
    expect(groups[1]!.events.map((e) => e.id)).toEqual(["3"]);
  });
  it("dayKey is zero-padded YYYY-MM-DD", () => {
    expect(dayKey(new Date(2024, 2, 5, 0, 0, 0).getTime())).toBe("2024-03-05");
  });
});

describe("filterByCategory", () => {
  const events: ActivityEvent[] = [
    { id: "1", ts: 1, kind: "fill", category: "trade", title: "", severity: "info" },
    { id: "2", ts: 2, kind: "funding", category: "funding", title: "", severity: "info" },
  ];
  it("passes through for all / undefined", () => {
    expect(filterByCategory(events, "all")).toHaveLength(2);
    expect(filterByCategory(events, undefined)).toHaveLength(2);
  });
  it("filters to the requested category", () => {
    expect(filterByCategory(events, "funding").map((e) => e.id)).toEqual(["2"]);
  });
});

describe("unread markers", () => {
  const events: ActivityEvent[] = [
    { id: "1", ts: 100, kind: "x", category: "trade", title: "", severity: "info" },
    { id: "2", ts: 200, kind: "x", category: "trade", title: "", severity: "info" },
    { id: "3", ts: 300, kind: "x", category: "trade", title: "", severity: "info" },
  ];
  it("isUnread compares against lastSeen", () => {
    expect(isUnread(events[2]!, 200)).toBe(true);
    expect(isUnread(events[1]!, 200)).toBe(false); // equal is not newer
    expect(isUnread(events[0]!, undefined)).toBe(true); // never seen -> all unread
  });
  it("unreadCount counts events strictly newer than lastSeen", () => {
    expect(unreadCount(events, 200)).toBe(1);
    expect(unreadCount(events, 0)).toBe(3);
    expect(unreadCount(events, undefined)).toBe(3);
    expect(unreadCount(events, 300)).toBe(0);
  });
});
