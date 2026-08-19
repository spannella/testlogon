/**
 * Client-side trading preference storage (localStorage-backed).
 *
 * These preferences are surfaced in the Settings > Trading section and read by
 * the trading surfaces (alerts hook, markets landing). All access is failure-
 * safe and backward-compatible: missing keys fall back to sensible defaults
 * (default symbol = none; every alert kind = enabled).
 */

import type { TradingAlertKind } from "@/hooks/useTradingAlerts";

// ── localStorage keys ───────────────────────────────────────────────
export const DEFAULT_SYMBOL_KEY = "md.defaultSymbol";
export const ALERT_PREFS_KEY = "md.alertPrefs.v1";
/** Dockview layout key owned by TradingWorkspacePage — kept in sync there. */
export const BLOTTER_LAYOUT_KEY = "testlogon.trading.dock.v3";

// ── Alert preferences ───────────────────────────────────────────────
export type AlertPrefs = Record<TradingAlertKind, boolean>;

/** Default: every alert kind enabled. */
export const DEFAULT_ALERT_PREFS: AlertPrefs = {
  fill: true,
  liquidation: true,
  funding: true,
  margin: true,
  pm_resolved: true,
};

export function loadAlertPrefs(): AlertPrefs {
  try {
    const raw = localStorage.getItem(ALERT_PREFS_KEY);
    if (!raw) return { ...DEFAULT_ALERT_PREFS };
    const parsed = JSON.parse(raw) as Partial<AlertPrefs>;
    // Backward-compatible merge: any missing kind defaults to enabled.
    return { ...DEFAULT_ALERT_PREFS, ...parsed };
  } catch {
    return { ...DEFAULT_ALERT_PREFS };
  }
}

export function saveAlertPrefs(prefs: AlertPrefs): void {
  try {
    localStorage.setItem(ALERT_PREFS_KEY, JSON.stringify(prefs));
  } catch {
    /* quota / private-mode — degrade to defaults */
  }
}

// ── Default symbol ──────────────────────────────────────────────────
/** Returns the persisted default symbol id, or null if unset/invalid. */
export function loadDefaultSymbol(): number | null {
  try {
    const raw = localStorage.getItem(DEFAULT_SYMBOL_KEY);
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

export function saveDefaultSymbol(symbolId: number | null): void {
  try {
    if (symbolId == null) localStorage.removeItem(DEFAULT_SYMBOL_KEY);
    else localStorage.setItem(DEFAULT_SYMBOL_KEY, String(symbolId));
  } catch {
    /* ignore */
  }
}

// ── Blotter layout reset ────────────────────────────────────────────
/** Clears the persisted dockview layout so the workspace resets to defaults. */
export function resetBlotterLayout(): void {
  try {
    localStorage.removeItem(BLOTTER_LAYOUT_KEY);
  } catch {
    /* ignore */
  }
}
