// localStorage persistence for the isolated paper-trading account. Survives
// reloads under the `paper.account.v1` key. Framework-free; the page loads once
// on mount and saves after every state change.

import { newAccount, resetAccount, type PaperAccount } from "./paperEngine";

export const PAPER_ACCOUNT_KEY = "paper.account.v1";

/**
 * Load the persisted account, or seed a fresh one. Any parse/shape error falls
 * back to a new account so a corrupt value can never wedge the page.
 */
export function loadAccount(startingCash?: number): PaperAccount {
  if (typeof window === "undefined") return newAccount(startingCash);
  try {
    const raw = window.localStorage.getItem(PAPER_ACCOUNT_KEY);
    if (!raw) return newAccount(startingCash);
    const parsed = JSON.parse(raw) as Partial<PaperAccount>;
    if (
      parsed &&
      typeof parsed.cash === "number" &&
      typeof parsed.startingCash === "number" &&
      typeof parsed.realizedPnl === "number" &&
      parsed.positions &&
      Array.isArray(parsed.orders) &&
      Array.isArray(parsed.fills)
    ) {
      return {
        cash: parsed.cash,
        positions: parsed.positions,
        orders: parsed.orders,
        fills: parsed.fills,
        realizedPnl: parsed.realizedPnl,
        startingCash: parsed.startingCash,
      };
    }
  } catch {
    // fall through to fresh
  }
  return newAccount(startingCash);
}

/** Persist the account. Silently ignores quota/serialisation errors. */
export function saveAccount(acct: PaperAccount): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(PAPER_ACCOUNT_KEY, JSON.stringify(acct));
  } catch {
    // ignore
  }
}

/** Reset to a fresh account (same starting cash) AND persist it. Returns it. */
export function resetAndSave(startingCash?: number): PaperAccount {
  const fresh = resetAccount(startingCash);
  saveAccount(fresh);
  return fresh;
}
