import { describe, expect, it } from "vitest";

import {
  interleaveSponsored,
  sponsoredSlotCount,
  isValidServeResponse,
  type SponsoredEntry,
} from "./sponsoredSlots";
import type { AdServeResponse } from "@/api/types";

/** Build a minimal valid served ad. */
function ad(id: string): AdServeResponse {
  return { filled: true, status: "filled", creative_id: id };
}

/** Extract a compact string representation for assertions. */
function shape<T>(entries: SponsoredEntry<T>[]): string {
  return entries
    .map((e) => (e.type === "organic" ? "o" : "s"))
    .join("");
}

const items = Array.from({ length: 12 }, (_, i) => `item-${i}`);

describe("isValidServeResponse", () => {
  it("accepts filled responses with a creative_id", () => {
    expect(isValidServeResponse(ad("c1"))).toBe(true);
  });

  it("rejects null/undefined", () => {
    expect(isValidServeResponse(null)).toBe(false);
    expect(isValidServeResponse(undefined)).toBe(false);
  });

  it("rejects unfilled responses (degrade-on-unfilled)", () => {
    expect(isValidServeResponse({ filled: false, status: "no_fill" })).toBe(false);
  });

  it("rejects filled-but-missing-creative", () => {
    expect(isValidServeResponse({ filled: true, status: "filled" })).toBe(false);
  });
});

describe("sponsoredSlotCount", () => {
  it("is 0 for an empty list", () => {
    expect(sponsoredSlotCount(0, { everyN: 5 })).toBe(0);
  });

  it("is 0 when fewer items than everyN", () => {
    expect(sponsoredSlotCount(4, { everyN: 5 })).toBe(0);
  });

  it("inserts one slot per full block, never trailing on an exact multiple", () => {
    // 10 items / everyN 5 => slots after item5 and item10; item10 is the end,
    // so it is dropped -> 1 slot.
    expect(sponsoredSlotCount(10, { everyN: 5 })).toBe(1);
  });

  it("counts a mid-list slot for non-multiple lengths", () => {
    // 12 items / 5 => slots after 5 and 10 (11,12 follow) -> 2.
    expect(sponsoredSlotCount(12, { everyN: 5 })).toBe(2);
  });

  it("respects max", () => {
    expect(sponsoredSlotCount(100, { everyN: 5, max: 3 })).toBe(3);
  });

  it("defaults everyN to 5", () => {
    expect(sponsoredSlotCount(12)).toBe(2);
  });
});

describe("interleaveSponsored", () => {
  it("returns all organic when no ads are supplied", () => {
    const out = interleaveSponsored(items, [], { everyN: 5 });
    expect(out).toHaveLength(items.length);
    expect(out.every((e) => e.type === "organic")).toBe(true);
    expect(shape(out)).toBe("oooooooooooo");
  });

  it("returns all organic when ads are all invalid (degrade-on-404)", () => {
    const out = interleaveSponsored(
      items,
      [null, { filled: false, status: "no_fill" }, undefined],
      { everyN: 5 },
    );
    expect(out.every((e) => e.type === "organic")).toBe(true);
    expect(out).toHaveLength(items.length);
  });

  it("inserts a slot after every N organic items", () => {
    const out = interleaveSponsored(items, [ad("a"), ad("b")], { everyN: 5 });
    // 12 items: slot after 5th and after 10th.
    expect(shape(out)).toBe("ooooosooooosoo");
  });

  it("never places two slots adjacent", () => {
    const out = interleaveSponsored(items, [ad("a"), ad("b"), ad("c")], {
      everyN: 1,
      max: 3,
    });
    for (let i = 1; i < out.length; i++) {
      if (out[i]!.type === "sponsored") {
        expect(out[i - 1]!.type).toBe("organic");
      }
    }
  });

  it("never places a trailing slot past the end", () => {
    const ten = items.slice(0, 10);
    const out = interleaveSponsored(ten, [ad("a"), ad("b")], { everyN: 5 });
    // slot after item5 only; item10 is the end -> no trailing slot.
    expect(out[out.length - 1]!.type).toBe("organic");
    expect(out.filter((e) => e.type === "sponsored")).toHaveLength(1);
  });

  it("respects max", () => {
    const many = Array.from({ length: 30 }, (_, i) => i);
    const out = interleaveSponsored(
      many,
      [ad("a"), ad("b"), ad("c"), ad("d"), ad("e")],
      { everyN: 5, max: 2 },
    );
    expect(out.filter((e) => e.type === "sponsored")).toHaveLength(2);
  });

  it("is capped by the number of available ads", () => {
    const many = Array.from({ length: 30 }, (_, i) => i);
    const out = interleaveSponsored(many, [ad("a")], { everyN: 5, max: 5 });
    expect(out.filter((e) => e.type === "sponsored")).toHaveLength(1);
  });

  it("filters invalid ads before consuming slots", () => {
    const out = interleaveSponsored(
      items,
      [null, ad("a"), { filled: false, status: "x" }, ad("b")],
      { everyN: 5 },
    );
    const slots = out.filter((e) => e.type === "sponsored");
    expect(slots).toHaveLength(2);
    expect(slots.map((s) => (s.type === "sponsored" ? s.ad.creative_id : ""))).toEqual([
      "a",
      "b",
    ]);
  });

  it("honors startAt for the first insertion", () => {
    const out = interleaveSponsored(items, [ad("a"), ad("b")], {
      everyN: 5,
      startAt: 3,
    });
    // first slot after item3, next after item8.
    expect(shape(out)).toBe("ooosooooosoooo");
  });

  it("produces stable, unique keys", () => {
    const out = interleaveSponsored(items, [ad("a"), ad("b")], { everyN: 5 });
    const keys = out.map((e) => e.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("uses a custom keyOf for organic entries", () => {
    const out = interleaveSponsored(
      ["x", "y"],
      [],
      { everyN: 5 },
      (item) => `k-${item}`,
    );
    expect(out.map((e) => e.key)).toEqual(["k-x", "k-y"]);
  });

  it("handles an empty item list", () => {
    expect(interleaveSponsored([], [ad("a")], { everyN: 5 })).toEqual([]);
  });
});
