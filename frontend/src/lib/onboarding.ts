// Product onboarding: first-run Welcome tour + per-surface dismissible intros
// for the trading / investing surfaces. Framework-free + event-based, mirroring
// the price-alerts / paper-mode store pattern: a single persisted "seen" set in
// localStorage under `onboarding.v1`, a same-tab `tl:onboarding` event, and
// cross-tab sync via the native `storage` event.
//
// The step/intro copy is derived from the shared TRADING_SURFACES registry so
// the tour and the Home quick-links stay in lock-step.

import { useCallback, useEffect, useState } from "react";
import { TRADING_SURFACES } from "@/pages/home/tradingSurfaces";

/** localStorage key for the persisted "seen" set. */
export const ONBOARDING_KEY = "onboarding.v1";

/** Fired (same-tab) whenever the seen-set changes. */
export const ONBOARDING_EVENT = "tl:onboarding";

/** Stable id of the first-run welcome tour (persisted once completed/skipped). */
export const WELCOME_TOUR_ID = "welcome-tour";

/** A single tour step or per-surface intro entry. */
export interface OnboardingEntry {
  /** Stable id — the localStorage seen-set member + React key + test anchor. */
  id: string;
  title: string;
  body: string;
  /** Optional deep-link ("Go there" / used by the surface intro's page). */
  route?: string;
}

// ── Registry (derived from TRADING_SURFACES for copy) ────────────────────────

/** Longer per-surface blurbs keyed by TRADING_SURFACES id (fallback: tile desc). */
const SURFACE_BLURB: Record<string, string> = {
  invest:
    "Your one front door to everything investable — markets, creator tokens, strategy funds, staking and open opportunities. Start here, then dive deeper.",
  strategies:
    "Invest in NAV-unit funds: baskets of target weights you can paper-trade and backtest before buying in at net asset value.",
  tokens:
    "Mint and trade creator tokens — tradeable revenue-share claims issued by content creators, with their own order books.",
  bailouts:
    "Rescue distressed-but-solvent margin positions by injecting capital for a position-share before a forced liquidation.",
  "portfolio-analytics":
    "Client-computed allocation, concentration, exposure and risk across custody, spot, margin, tokens, funds and staking.",
  "activity-center":
    "A single feed of fills, funding, liquidations and other account events so nothing that moves your money slips by.",
  algos:
    "Monitor your working TWAP and iceberg algorithms — progress, slices and controls — while they execute.",
  "custody-providers":
    "Connect an external custodian to hold and settle assets, then manage the connection from one place.",
  "reports-tax":
    "Realized gains and tax-lot reporting you can review and export come tax time.",
};

/** Map a TRADING_SURFACES tile into an onboarding entry (id/title/body/route). */
function surfaceEntry(id: string): OnboardingEntry | undefined {
  const s = TRADING_SURFACES.find((t) => t.id === id);
  if (!s) return undefined;
  return { id, title: s.label, body: SURFACE_BLURB[id] ?? s.desc, route: s.path };
}

/** The ordered surface ids the onboarding walks through. */
const SURFACE_ORDER = [
  "invest",
  "strategies",
  "tokens",
  "bailouts",
  "portfolio-analytics",
  "activity-center",
  "algos",
];

/**
 * The ordered welcome-tour steps: a leading "welcome" step, then a walk through
 * the headline new surfaces (each with a "Go there" deep-link). Pure.
 */
export function tourSteps(): OnboardingEntry[] {
  const intro: OnboardingEntry = {
    id: "welcome",
    title: "Welcome to Investing on TestLogon",
    body: "We just added a full suite of trading & investing surfaces. Take a 60-second tour, or skip and explore on your own — you can replay this anytime from Settings.",
  };
  const steps = SURFACE_ORDER.map((id) => surfaceEntry(id)).filter(
    (e): e is OnboardingEntry => e != null,
  );
  return [intro, ...steps];
}

/** The per-surface intro callouts, keyed by their own stable ids ("intro:<id>"). */
export function surfaceIntros(): OnboardingEntry[] {
  return SURFACE_ORDER.map((id) => {
    const e = surfaceEntry(id);
    return e ? { ...e, id: `intro:${id}` } : undefined;
  }).filter((e): e is OnboardingEntry => e != null);
}

/** Look up a single surface intro entry by its raw surface id (e.g. "invest"). */
export function surfaceIntro(surfaceId: string): OnboardingEntry | undefined {
  return surfaceIntros().find((e) => e.id === `intro:${surfaceId}`);
}

// ── Persisted seen-set store ─────────────────────────────────────────────────

/** Load the persisted seen-set (ids that should no longer auto-show). */
export function loadSeen(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const raw = window.localStorage.getItem(ONBOARDING_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return new Set(parsed.filter((x) => typeof x === "string"));
    return new Set();
  } catch {
    return new Set();
  }
}

/** Persist the seen-set and notify same-tab listeners. */
export function saveSeen(seen: Set<string>): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ONBOARDING_KEY, JSON.stringify([...seen]));
  } catch {
    /* quota / private-mode — degrade to no-op */
  }
  try {
    window.dispatchEvent(new Event(ONBOARDING_EVENT));
  } catch {
    /* SSR — no-op */
  }
}

// ── Pure helpers (unit-tested) ───────────────────────────────────────────────

/** True when the entry `id` has not yet been marked seen. */
export function shouldShow(id: string, seen: Set<string>): boolean {
  return !seen.has(id);
}

/**
 * Return a NEW seen-set with `id` added (pure — does not persist). Callers that
 * want persistence pass the result to `saveSeen`.
 */
export function markSeen(id: string, seen: Set<string>): Set<string> {
  const next = new Set(seen);
  next.add(id);
  return next;
}

/** Clear ALL onboarding state (welcome tour + every surface intro) + persist. */
export function resetOnboarding(): void {
  saveSeen(new Set());
}

// ── React hook (thin wrapper over the store; not part of the pure surface) ────

/**
 * Subscribe to the persisted seen-set. Returns the current set plus a `mark`
 * helper that persists + fans the change out to every consumer (same + cross
 * tab). Re-reads on the same-tab `tl:onboarding` event and native `storage`.
 */
export function useOnboarding(): {
  seen: Set<string>;
  mark: (id: string) => void;
  reset: () => void;
} {
  const [seen, setSeen] = useState<Set<string>>(() => loadSeen());

  useEffect(() => {
    const reload = () => setSeen(loadSeen());
    window.addEventListener("storage", reload);
    window.addEventListener(ONBOARDING_EVENT, reload);
    return () => {
      window.removeEventListener("storage", reload);
      window.removeEventListener(ONBOARDING_EVENT, reload);
    };
  }, []);

  const mark = useCallback((id: string) => {
    setSeen((prev) => {
      const next = markSeen(id, prev);
      saveSeen(next);
      return next;
    });
  }, []);

  const reset = useCallback(() => {
    resetOnboarding();
    setSeen(new Set());
  }, []);

  return { seen, mark, reset };
}
