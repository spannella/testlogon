import { describe, expect, it } from "vitest";

import {
  matchSequence,
  IDLE_SEQUENCE,
  CHORD_WINDOW_MS,
  type ShortcutEntry,
} from "@/hooks/useKeyboardShortcuts";

/** Build a small registry: one single ("/"), one single ("b"), two chords. */
function makeEntries() {
  const fired: string[] = [];
  const entries: ShortcutEntry[] = [
    {
      def: { kind: "single", key: "/", label: "Search", group: "General" },
      action: () => fired.push("search"),
    },
    {
      def: { kind: "single", key: "b", label: "Buy", group: "Trading" },
      action: () => fired.push("buy"),
    },
    {
      def: { kind: "chord", first: "g", second: "m", label: "Markets", group: "Navigation" },
      action: () => fired.push("markets"),
    },
    {
      def: { kind: "chord", first: "g", second: "h", label: "Home", group: "Navigation" },
      action: () => fired.push("home"),
    },
  ];
  return { entries, fired };
}

describe("matchSequence (keyboard shortcut sequence matcher)", () => {
  it("fires a bare single-key shortcut immediately", () => {
    const { entries, fired } = makeEntries();
    const r = matchSequence(IDLE_SEQUENCE, "b", entries, 1000);
    expect(r.consumed).toBe(true);
    expect(r.matched).not.toBeNull();
    r.matched!.action();
    expect(fired).toEqual(["buy"]);
    expect(r.state).toEqual(IDLE_SEQUENCE);
  });

  it("matches the special '/' single key", () => {
    const { entries } = makeEntries();
    const r = matchSequence(IDLE_SEQUENCE, "/", entries, 1000);
    expect(r.consumed).toBe(true);
    expect(r.matched?.def.label).toBe("Search");
  });

  it("enters a pending state on a chord first-key and does not fire yet", () => {
    const { entries } = makeEntries();
    const r = matchSequence(IDLE_SEQUENCE, "g", entries, 1000);
    expect(r.consumed).toBe(true);
    expect(r.matched).toBeNull();
    expect(r.state.pendingFirst).toBe("g");
    expect(r.state.pendingAt).toBe(1000);
  });

  it("completes a g-m chord within the window", () => {
    const { entries, fired } = makeEntries();
    const first = matchSequence(IDLE_SEQUENCE, "g", entries, 1000);
    const second = matchSequence(first.state, "m", entries, 1500);
    expect(second.consumed).toBe(true);
    expect(second.matched?.def.label).toBe("Markets");
    second.matched!.action();
    expect(fired).toEqual(["markets"]);
    expect(second.state).toEqual(IDLE_SEQUENCE);
  });

  it("completes a different g-h chord from the same first key", () => {
    const { entries } = makeEntries();
    const first = matchSequence(IDLE_SEQUENCE, "g", entries, 0);
    const second = matchSequence(first.state, "h", entries, 100);
    expect(second.matched?.def.label).toBe("Home");
  });

  it("is case-insensitive for keys", () => {
    const { entries } = makeEntries();
    const first = matchSequence(IDLE_SEQUENCE, "G", entries, 0);
    expect(first.state.pendingFirst).toBe("g");
    const second = matchSequence(first.state, "M", entries, 100);
    expect(second.matched?.def.label).toBe("Markets");
  });

  it("expires the pending chord after the window and re-evaluates fresh", () => {
    const { entries } = makeEntries();
    const first = matchSequence(IDLE_SEQUENCE, "g", entries, 1000);
    // Second key arrives after the window: the pending 'g' is dropped.
    const second = matchSequence(first.state, "m", entries, 1000 + CHORD_WINDOW_MS + 1);
    // 'm' is not a single shortcut nor a chord-start, so nothing matches.
    expect(second.matched).toBeNull();
    expect(second.state).toEqual(IDLE_SEQUENCE);
  });

  it("cancels a pending chord when a non-matching key follows, re-evaluating it", () => {
    const { entries } = makeEntries();
    const first = matchSequence(IDLE_SEQUENCE, "g", entries, 0);
    // 'b' is not a valid second key for 'g'; the chord cancels and 'b' fires as a single.
    const second = matchSequence(first.state, "b", entries, 100);
    expect(second.matched?.def.label).toBe("Buy");
    expect(second.state).toEqual(IDLE_SEQUENCE);
  });

  it("does not consume an unmapped key when idle", () => {
    const { entries } = makeEntries();
    const r = matchSequence(IDLE_SEQUENCE, "z", entries, 0);
    expect(r.consumed).toBe(false);
    expect(r.matched).toBeNull();
    expect(r.state).toEqual(IDLE_SEQUENCE);
  });

  it("restarts a pending chord if the follow-up key is itself a chord start", () => {
    const { entries } = makeEntries();
    const first = matchSequence(IDLE_SEQUENCE, "g", entries, 0);
    // Second 'g' is not a valid second key, but IS a chord start -> new pending.
    const second = matchSequence(first.state, "g", entries, 100);
    expect(second.matched).toBeNull();
    expect(second.state.pendingFirst).toBe("g");
    expect(second.state.pendingAt).toBe(100);
  });
});
