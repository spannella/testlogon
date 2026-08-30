import { describe, expect, it } from "vitest";
import {
  MIN_REVEAL_LEAD_SEC,
  isRevealLocked,
  isRevealable,
  revealCountdownLabel,
  secondsUntilReveal,
} from "./revealAt";

const NOW = 1_000_000; // fixed epoch seconds for determinism

describe("revealAt", () => {
  it("exposes a positive minimum lead", () => {
    expect(MIN_REVEAL_LEAD_SEC).toBeGreaterThan(0);
  });

  describe("isRevealLocked", () => {
    it("never locks the sender", () => {
      expect(isRevealLocked(NOW + 3600, true, NOW)).toBe(false);
    });

    it("locks a recipient before the reveal time", () => {
      expect(isRevealLocked(NOW + 3600, false, NOW)).toBe(true);
    });

    it("unlocks a recipient once now reaches reveal_at", () => {
      expect(isRevealLocked(NOW, false, NOW)).toBe(false);
      expect(isRevealLocked(NOW - 1, false, NOW)).toBe(false);
    });

    it("is never locked when reveal_at is missing", () => {
      expect(isRevealLocked(undefined, false, NOW)).toBe(false);
      expect(isRevealLocked(null, false, NOW)).toBe(false);
    });

    it("treats non-finite reveal_at as absent", () => {
      expect(isRevealLocked(NaN, false, NOW)).toBe(false);
      expect(isRevealLocked(Infinity, false, NOW)).toBe(false);
    });
  });

  describe("secondsUntilReveal", () => {
    it("returns the remaining seconds", () => {
      expect(secondsUntilReveal(NOW + 125, NOW)).toBe(125);
    });

    it("clamps to zero once elapsed", () => {
      expect(secondsUntilReveal(NOW - 50, NOW)).toBe(0);
      expect(secondsUntilReveal(NOW, NOW)).toBe(0);
    });

    it("returns 0 with no reveal_at", () => {
      expect(secondsUntilReveal(undefined, NOW)).toBe(0);
    });
  });

  describe("isRevealable", () => {
    it("is false before the reveal time", () => {
      expect(isRevealable(NOW + 1, NOW)).toBe(false);
    });

    it("is true at/after the reveal time", () => {
      expect(isRevealable(NOW, NOW)).toBe(true);
      expect(isRevealable(NOW - 1, NOW)).toBe(true);
    });

    it("is true with no reveal_at", () => {
      expect(isRevealable(undefined, NOW)).toBe(true);
    });
  });

  describe("revealCountdownLabel", () => {
    it("shows hours + minutes for multi-hour waits", () => {
      // 2h 05m 00s
      const label = revealCountdownLabel(NOW + 2 * 3600 + 5 * 60, NOW);
      expect(label).toBe("Reveals in 2h 05m");
    });

    it("shows minutes + seconds under an hour", () => {
      const label = revealCountdownLabel(NOW + 5 * 60 + 3, NOW);
      expect(label).toBe("Reveals in 5m 03s");
    });

    it("shows seconds only under a minute", () => {
      expect(revealCountdownLabel(NOW + 9, NOW)).toBe("Reveals in 9s");
    });

    it("shows an absolute time when a day or more out", () => {
      const label = revealCountdownLabel(NOW + 86400 + 3600, NOW);
      expect(label.startsWith("Reveals at ")).toBe(true);
    });

    it("says Revealing… once elapsed", () => {
      expect(revealCountdownLabel(NOW - 1, NOW)).toBe("Revealing…");
    });

    it("is empty with no reveal_at", () => {
      expect(revealCountdownLabel(undefined, NOW)).toBe("");
    });
  });
});
