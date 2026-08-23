import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ONBOARDING_KEY,
  loadSeen,
  saveSeen,
  shouldShow,
  markSeen,
  resetOnboarding,
  tourSteps,
  surfaceIntros,
  surfaceIntro,
} from "@/lib/onboarding";

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  window.localStorage.clear();
});

describe("shouldShow / markSeen (pure)", () => {
  it("shows an id that is not in the seen-set", () => {
    expect(shouldShow("welcome", new Set())).toBe(true);
  });

  it("hides an id once seen", () => {
    const seen = new Set<string>(["welcome"]);
    expect(shouldShow("welcome", seen)).toBe(false);
  });

  it("markSeen returns a NEW set and does not mutate the input", () => {
    const orig = new Set<string>();
    const next = markSeen("welcome", orig);
    expect(orig.has("welcome")).toBe(false);
    expect(next.has("welcome")).toBe(true);
    expect(next).not.toBe(orig);
  });

  it("markSeen is idempotent", () => {
    const once = markSeen("x", new Set());
    const twice = markSeen("x", once);
    expect([...twice]).toEqual(["x"]);
  });
});

describe("persistence store", () => {
  it("loadSeen returns an empty set when nothing is stored", () => {
    expect(loadSeen().size).toBe(0);
  });

  it("saveSeen round-trips through localStorage", () => {
    saveSeen(new Set(["welcome", "intro:invest"]));
    const raw = window.localStorage.getItem(ONBOARDING_KEY);
    expect(raw).toBeTruthy();
    const loaded = loadSeen();
    expect(loaded.has("welcome")).toBe(true);
    expect(loaded.has("intro:invest")).toBe(true);
    expect(loaded.size).toBe(2);
  });

  it("loadSeen tolerates corrupt JSON", () => {
    window.localStorage.setItem(ONBOARDING_KEY, "{not json");
    expect(loadSeen().size).toBe(0);
  });

  it("loadSeen ignores a non-array payload", () => {
    window.localStorage.setItem(ONBOARDING_KEY, JSON.stringify({ a: 1 }));
    expect(loadSeen().size).toBe(0);
  });

  it("loadSeen filters non-string members", () => {
    window.localStorage.setItem(ONBOARDING_KEY, JSON.stringify(["welcome", 3, null]));
    const loaded = loadSeen();
    expect([...loaded]).toEqual(["welcome"]);
  });

  it("saveSeen dispatches the same-tab onboarding event", () => {
    let fired = false;
    const handler = () => {
      fired = true;
    };
    window.addEventListener("tl:onboarding", handler);
    saveSeen(new Set(["welcome"]));
    window.removeEventListener("tl:onboarding", handler);
    expect(fired).toBe(true);
  });

  it("resetOnboarding clears the stored seen-set", () => {
    saveSeen(new Set(["welcome", "intro:invest"]));
    resetOnboarding();
    expect(loadSeen().size).toBe(0);
  });
});

describe("registry", () => {
  it("tourSteps leads with the welcome step and includes surfaces with routes", () => {
    const steps = tourSteps();
    expect(steps.length).toBeGreaterThan(1);
    const first = steps[0]!;
    expect(first.id).toBe("welcome");
    expect(first.route).toBeUndefined();
    // every non-welcome step must carry a deep-link + copy.
    for (const s of steps.slice(1)) {
      expect(s.route).toBeTruthy();
      expect(s.title.length).toBeGreaterThan(0);
      expect(s.body.length).toBeGreaterThan(0);
    }
  });

  it("tourSteps ids are unique", () => {
    const ids = tourSteps().map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("surfaceIntros are namespaced under intro: and carry routes", () => {
    const intros = surfaceIntros();
    expect(intros.length).toBeGreaterThan(0);
    for (const e of intros) {
      expect(e.id.startsWith("intro:")).toBe(true);
      expect(e.route).toBeTruthy();
      expect(e.body.length).toBeGreaterThan(0);
    }
  });

  it("surfaceIntro looks up a single entry by raw surface id", () => {
    const invest = surfaceIntro("invest");
    expect(invest).toBeDefined();
    expect(invest?.id).toBe("intro:invest");
    expect(invest?.route).toBe("/invest");
  });

  it("surfaceIntro returns undefined for an unknown surface", () => {
    expect(surfaceIntro("nope")).toBeUndefined();
  });
});
