import { describe, expect, it } from "vitest";

import { parseMdData } from "@/hooks/useMdStream";

const book = { bid_px: 100, ask_px: 102 } as never;
const bars = { bars: [{ close: 101 } as never], count: 1, interval_sec: 1, symbol: 1 };

describe("parseMdData (SSE md frame parser)", () => {
  it("parses a valid md frame into {book,bars,lastPrice}", () => {
    const raw = JSON.stringify({ symbol: 1, book, bars });
    const out = parseMdData(raw);
    expect(out).not.toBeNull();
    expect(out!.book).toEqual(book);
    expect(out!.bars).toEqual(bars.bars);
    // lastPrice derives from the newest bar close
    expect(out!.lastPrice).toBe(101);
  });

  it("falls back to bid/ask mid when there are no bars", () => {
    const raw = JSON.stringify({ symbol: 1, book, bars: { bars: [], count: 0, interval_sec: 1, symbol: 1 } });
    const out = parseMdData(raw);
    expect(out!.bars).toEqual([]);
    expect(out!.lastPrice).toBe(101); // (100 + 102) / 2
  });

  it("merges with previous book/bars for fields the frame omits", () => {
    const raw = JSON.stringify({ symbol: 1 }); // no book, no bars
    const out = parseMdData(raw, { book, bars: bars.bars });
    expect(out!.book).toEqual(book);
    expect(out!.bars).toEqual(bars.bars);
    expect(out!.lastPrice).toBe(101);
  });

  it("ignores malformed / non-JSON payloads (heartbeats, comments)", () => {
    expect(parseMdData("")).toBeNull();
    expect(parseMdData(":heartbeat")).toBeNull();
    expect(parseMdData("{not json")).toBeNull();
    expect(parseMdData("null")).toBeNull();
    expect(parseMdData("42")).toBeNull();
  });
});
