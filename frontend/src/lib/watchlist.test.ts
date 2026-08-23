import { describe, expect, it } from "vitest";

import {
  watchKey,
  kindLabel,
  isWatched,
  toggleWatch,
  removeWatch,
  migrateLegacy,
  sortWatchItems,
  type WatchItem,
} from "./watchlist";

describe("watchKey", () => {
  it("builds a stable composite key", () => {
    expect(watchKey("symbol", 3)).toBe("symbol:3");
    expect(watchKey("token", "tk_1")).toBe("token:tk_1");
    expect(watchKey("strategy", "st_9")).toBe("strategy:st_9");
  });
  it("normalizes numeric and string ids to the same key", () => {
    expect(watchKey("symbol", 3)).toBe(watchKey("symbol", "3"));
  });
});

describe("kindLabel", () => {
  it("maps kinds to human labels", () => {
    expect(kindLabel("symbol")).toBe("Symbol");
    expect(kindLabel("token")).toBe("Token");
    expect(kindLabel("strategy")).toBe("Strategy");
  });
});

describe("isWatched", () => {
  const list: WatchItem[] = [
    { kind: "symbol", id: "1" },
    { kind: "token", id: "tk_a" },
  ];
  it("finds present items across kinds (number or string id)", () => {
    expect(isWatched(list, "symbol", 1)).toBe(true);
    expect(isWatched(list, "symbol", "1")).toBe(true);
    expect(isWatched(list, "token", "tk_a")).toBe(true);
  });
  it("does not confuse the same id across different kinds", () => {
    expect(isWatched(list, "strategy", "1")).toBe(false);
    expect(isWatched(list, "token", "1")).toBe(false);
  });
});

describe("toggleWatch", () => {
  it("adds an absent item to the end and coerces id to string", () => {
    const next = toggleWatch([], "symbol", 5);
    expect(next).toEqual([{ kind: "symbol", id: "5" }]);
  });
  it("removes a present item", () => {
    const start: WatchItem[] = [{ kind: "symbol", id: "5" }];
    expect(toggleWatch(start, "symbol", 5)).toEqual([]);
  });
  it("is immutable (does not mutate the input)", () => {
    const start: WatchItem[] = [{ kind: "token", id: "tk_a" }];
    const copy = [...start];
    toggleWatch(start, "strategy", "st_1");
    expect(start).toEqual(copy);
  });
  it("preserves insertion order when appending different kinds", () => {
    let l: WatchItem[] = [];
    l = toggleWatch(l, "symbol", 1);
    l = toggleWatch(l, "token", "tk_a");
    l = toggleWatch(l, "strategy", "st_1");
    expect(l.map((x) => watchKey(x.kind, x.id))).toEqual([
      "symbol:1",
      "token:tk_a",
      "strategy:st_1",
    ]);
  });
});

describe("removeWatch", () => {
  it("removes by kind+id and is a no-op when absent", () => {
    const start: WatchItem[] = [
      { kind: "symbol", id: "1" },
      { kind: "token", id: "tk_a" },
    ];
    expect(removeWatch(start, "symbol", 1)).toEqual([{ kind: "token", id: "tk_a" }]);
    expect(removeWatch(start, "strategy", "nope")).toEqual(start);
  });
});

describe("migrateLegacy", () => {
  it("migrates a bare legacy number[] to symbol items", () => {
    expect(migrateLegacy([1, 2, 3])).toEqual([
      { kind: "symbol", id: "1" },
      { kind: "symbol", id: "2" },
      { kind: "symbol", id: "3" },
    ]);
  });
  it("accepts the new object shape and normalizes ids", () => {
    expect(
      migrateLegacy([
        { kind: "token", id: "tk_a" },
        { kind: "strategy", id: 7 },
      ]),
    ).toEqual([
      { kind: "token", id: "tk_a" },
      { kind: "strategy", id: "7" },
    ]);
  });
  it("drops unknown kinds, empty ids, and junk entries", () => {
    expect(
      migrateLegacy([
        { kind: "bogus", id: "x" },
        { kind: "symbol", id: "" },
        null,
        NaN,
        true,
        { id: "no-kind" },
      ]),
    ).toEqual([]);
  });
  it("de-duplicates by composite key, first occurrence wins", () => {
    expect(
      migrateLegacy([
        { kind: "symbol", id: "1" },
        1,
        { kind: "symbol", id: "1" },
      ]),
    ).toEqual([{ kind: "symbol", id: "1" }]);
  });
  it("returns [] for non-array / malformed input", () => {
    expect(migrateLegacy(null)).toEqual([]);
    expect(migrateLegacy(undefined)).toEqual([]);
    expect(migrateLegacy("nope")).toEqual([]);
    expect(migrateLegacy(42)).toEqual([]);
  });
  it("does not lose token/strategy entries when mixed with legacy symbols", () => {
    expect(
      migrateLegacy([2, { kind: "token", id: "tk_a" }, 5]),
    ).toEqual([
      { kind: "symbol", id: "2" },
      { kind: "token", id: "tk_a" },
      { kind: "symbol", id: "5" },
    ]);
  });
});

describe("sortWatchItems", () => {
  it("groups by kind (symbol -> token -> strategy), stable within a kind", () => {
    const list: WatchItem[] = [
      { kind: "strategy", id: "st_1" },
      { kind: "symbol", id: "9" },
      { kind: "token", id: "tk_a" },
      { kind: "symbol", id: "3" },
    ];
    expect(sortWatchItems(list).map((x) => watchKey(x.kind, x.id))).toEqual([
      "symbol:9",
      "symbol:3",
      "token:tk_a",
      "strategy:st_1",
    ]);
  });
  it("does not mutate the input", () => {
    const list: WatchItem[] = [
      { kind: "token", id: "tk_a" },
      { kind: "symbol", id: "1" },
    ];
    const copy = [...list];
    sortWatchItems(list);
    expect(list).toEqual(copy);
  });
});
