/**
 * Price-alert store — client-side, localStorage-persisted watch list of
 * "notify me when <symbol> crosses <price>" rules.
 *
 * Prices are stored as INTEGER TICKS (int64-scaled, same units the market-data
 * endpoints use). Callers convert user-entered decimals to ticks via the
 * symbol's `price_scaler` (see parsePriceToTicks) before persisting.
 *
 * The evaluator (useEvaluatePriceAlerts) polls each armed alert's symbol last
 * price and, on an EDGE CROSS of the threshold, fires it once (one-shot).
 */

export type PriceAlertDirection = "above" | "below";

export interface PriceAlert {
  /** Stable id. */
  id: string;
  /** Market symbol_id this alert watches. */
  symbolId: number;
  /** Fire when price goes above / below the threshold. */
  direction: PriceAlertDirection;
  /** Threshold price in integer ticks (int64-scaled). */
  price: number;
  /** Optional free-text note shown on the alert. */
  note?: string;
  /** Epoch ms the alert was created. */
  createdTs: number;
  /** Epoch ms the alert last fired, or null if it has not fired. */
  triggeredTs?: number | null;
  /** Whether the alert is actively watching (false once fired / paused). */
  armed: boolean;
}

export const PRICE_ALERTS_KEY = "md.priceAlerts.v1";

/** Fired (same-tab) whenever the stored list changes so views re-read it. */
export const PRICE_ALERTS_EVENT = "tl:priceAlertsChanged";

// ── Persistence ─────────────────────────────────────────────────────

function isPriceAlert(x: unknown): x is PriceAlert {
  if (!x || typeof x !== "object") return false;
  const a = x as Record<string, unknown>;
  return (
    typeof a.id === "string" &&
    typeof a.symbolId === "number" &&
    (a.direction === "above" || a.direction === "below") &&
    typeof a.price === "number" &&
    typeof a.createdTs === "number" &&
    typeof a.armed === "boolean"
  );
}

export function loadPriceAlerts(): PriceAlert[] {
  try {
    const raw = localStorage.getItem(PRICE_ALERTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(isPriceAlert) : [];
  } catch {
    return [];
  }
}

function savePriceAlerts(list: PriceAlert[]): void {
  try {
    localStorage.setItem(PRICE_ALERTS_KEY, JSON.stringify(list));
  } catch {
    /* quota / private-mode — degrade to no-op */
  }
  try {
    window.dispatchEvent(new Event(PRICE_ALERTS_EVENT));
  } catch {
    /* SSR — no-op */
  }
}

// ── CRUD ────────────────────────────────────────────────────────────

function genId(): string {
  try {
    if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
      return crypto.randomUUID();
    }
  } catch {
    /* fall through */
  }
  return `pa_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

export interface NewPriceAlertInput {
  symbolId: number;
  direction: PriceAlertDirection;
  /** Threshold in integer ticks. */
  price: number;
  note?: string;
}

export function addPriceAlert(input: NewPriceAlertInput): PriceAlert {
  const alert: PriceAlert = {
    id: genId(),
    symbolId: input.symbolId,
    direction: input.direction,
    price: input.price,
    note: input.note?.trim() ? input.note.trim() : undefined,
    createdTs: Date.now(),
    triggeredTs: null,
    armed: true,
  };
  savePriceAlerts([alert, ...loadPriceAlerts()]);
  return alert;
}

export function removePriceAlert(id: string): void {
  savePriceAlerts(loadPriceAlerts().filter((a) => a.id !== id));
}

export function updatePriceAlert(id: string, patch: Partial<PriceAlert>): void {
  savePriceAlerts(
    loadPriceAlerts().map((a) => (a.id === id ? { ...a, ...patch, id: a.id } : a)),
  );
}

/** Re-arm a fired alert so it watches again (clears the trigger stamp). */
export function rearmPriceAlert(id: string): void {
  updatePriceAlert(id, { armed: true, triggeredTs: null });
}

/** Mark an alert as fired: stamp the time and disarm (one-shot). */
export function markPriceAlertTriggered(id: string, ts = Date.now()): void {
  updatePriceAlert(id, { armed: false, triggeredTs: ts });
}

// ── Tick <-> decimal conversion ─────────────────────────────────────

/**
 * Parse a user-entered decimal price string into integer ticks using the
 * symbol's price_scaler. Returns null for blank / non-numeric / negative input.
 */
export function parsePriceToTicks(input: string, scaler = 1): number | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round(n * (scaler || 1));
}

// ── Pure evaluation ─────────────────────────────────────────────────

/**
 * Decide whether an alert should fire given the latest price (in ticks).
 *
 * Edge-triggered: an armed alert fires only on the tick where the price CROSSES
 * the threshold — i.e. the price now MEETS the condition (above: price >=
 * threshold; below: price <= threshold). The one-shot / re-arm behavior lives in
 * the store (markPriceAlertTriggered / rearmPriceAlert); this helper only reads
 * `alert.armed`, so a disarmed alert never fires and a re-armed one can fire
 * again.
 *
 * Returns true = fire now, false = do nothing.
 */
export function evaluate(alert: PriceAlert, lastPriceTicks: number): boolean {
  if (!alert.armed) return false;
  if (!Number.isFinite(lastPriceTicks)) return false;
  if (alert.direction === "above") {
    return lastPriceTicks >= alert.price;
  }
  return lastPriceTicks <= alert.price;
}
