/**
 * Price-alert store — client-side, localStorage-persisted watch list of
 * "notify me when <subject> crosses <target>" rules.
 *
 * SUBJECT KINDS (generalized 2026-08):
 *  - "symbol"   : a market symbol_id; watches last price in INTEGER TICKS
 *                 (int64-scaled by the symbol's price_scaler). field = "price".
 *  - "token"    : a creator revenue-share token (token_id); watches the token's
 *                 last / clearing price in INTEGER CENTS. field = "price".
 *  - "strategy" : a strategy-fund (strategy_id); watches NAV per unit in
 *                 INTEGER CENTS. field = "nav".
 *
 * The `target` is always an integer in the subject's native units (ticks for a
 * symbol, cents for a token / strategy) — callers convert user-entered decimals
 * via parsePriceToTicks / parseCentsToInt before persisting.
 *
 * The evaluator (PriceAlertEvaluator) polls each armed alert's current value
 * and, on an EDGE CROSS of the threshold, fires it once (one-shot) through the
 * SAME trading-alerts bell path as symbol alerts (pushExternalTradingAlert).
 *
 * BACK-COMPAT: legacy entries persisted before the generalization only carried
 * { symbolId, direction, price, ... }. loadPriceAlerts() normalizes those to a
 * "symbol" subject transparently, so the storage key is unchanged (v1).
 */

export type PriceAlertDirection = "above" | "below";

/** What the alert watches. */
export type AlertSubjectKind = "symbol" | "token" | "strategy";

/** The observed field on the subject ("price" for symbol/token, "nav" for strategy). */
export type AlertField = "price" | "nav";

export interface PriceAlert {
  /** Stable id. */
  id: string;
  /** What kind of thing this alert watches. */
  subjectKind: AlertSubjectKind;
  /**
   * The subject identifier: a stringified symbol_id for "symbol", a token_id for
   * "token", a strategy_id for "strategy". (symbolId is retained below for the
   * "symbol" kind for back-compat with the existing evaluator/UI.)
   */
  subjectId: string;
  /** Observed field: "price" (symbol/token) or "nav" (strategy). */
  field: AlertField;
  /** Legacy: market symbol_id this alert watches (only meaningful for "symbol"). */
  symbolId: number;
  /** Fire when the value goes above / below the threshold. */
  direction: PriceAlertDirection;
  /** Threshold in the subject's native integer units (ticks for symbol, cents otherwise). */
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

/** condition is an alias for direction in the generalized vocabulary. */
export type AlertCondition = PriceAlertDirection;

export const PRICE_ALERTS_KEY = "md.priceAlerts.v1";

/** Fired (same-tab) whenever the stored list changes so views re-read it. */
export const PRICE_ALERTS_EVENT = "tl:priceAlertsChanged";

// -- Persistence ------------------------------------------------------

/**
 * Normalize a raw stored object into a fully-shaped PriceAlert, filling the
 * generalized fields (subjectKind / subjectId / field) for legacy symbol-only
 * entries. Returns null if the object is not a usable alert.
 */
function normalizeAlert(x: unknown): PriceAlert | null {
  if (!x || typeof x !== "object") return null;
  const a = x as Record<string, unknown>;
  if (typeof a.id !== "string") return null;
  if (a.direction !== "above" && a.direction !== "below") return null;
  if (typeof a.price !== "number") return null;
  if (typeof a.createdTs !== "number") return null;
  if (typeof a.armed !== "boolean") return null;

  const kind: AlertSubjectKind =
    a.subjectKind === "token" || a.subjectKind === "strategy" || a.subjectKind === "symbol"
      ? a.subjectKind
      : "symbol";

  // Legacy entries only have symbolId; derive subjectId/field from the kind.
  const symbolId = typeof a.symbolId === "number" ? a.symbolId : 0;
  let subjectId: string;
  if (typeof a.subjectId === "string" && a.subjectId) {
    subjectId = a.subjectId;
  } else {
    subjectId = String(symbolId);
  }
  const field: AlertField =
    a.field === "nav" || a.field === "price"
      ? a.field
      : kind === "strategy"
        ? "nav"
        : "price";

  return {
    id: a.id,
    subjectKind: kind,
    subjectId,
    field,
    symbolId,
    direction: a.direction,
    price: a.price,
    note: typeof a.note === "string" ? a.note : undefined,
    createdTs: a.createdTs,
    triggeredTs: typeof a.triggeredTs === "number" ? a.triggeredTs : null,
    armed: a.armed,
  };
}

export function loadPriceAlerts(): PriceAlert[] {
  try {
    const raw = localStorage.getItem(PRICE_ALERTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const out: PriceAlert[] = [];
    for (const item of parsed) {
      const norm = normalizeAlert(item);
      if (norm) out.push(norm);
    }
    return out;
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

// -- CRUD -------------------------------------------------------------

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
  /** Defaults to "symbol" when omitted (back-compat with existing callers). */
  subjectKind?: AlertSubjectKind;
  /** Subject id (token_id / strategy_id / stringified symbol_id). */
  subjectId?: string;
  /** Observed field; defaults from the kind when omitted. */
  field?: AlertField;
  /** Legacy symbol id; when present without subjectId, seeds subjectId for "symbol". */
  symbolId?: number;
  direction: PriceAlertDirection;
  /** Threshold in the subject's native integer units. */
  price: number;
  note?: string;
}

/** Default observed field for a subject kind. */
export function defaultFieldForKind(kind: AlertSubjectKind): AlertField {
  return kind === "strategy" ? "nav" : "price";
}

export function addPriceAlert(input: NewPriceAlertInput): PriceAlert {
  const kind: AlertSubjectKind = input.subjectKind ?? "symbol";
  const symbolId = input.symbolId ?? 0;
  const subjectId = input.subjectId ?? (kind === "symbol" ? String(symbolId) : "");
  const field = input.field ?? defaultFieldForKind(kind);
  const alert: PriceAlert = {
    id: genId(),
    subjectKind: kind,
    subjectId,
    field,
    symbolId,
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

// -- Decimal <-> integer conversion -----------------------------------

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

/**
 * Parse a user-entered dollar string into INTEGER CENTS (for token / strategy
 * targets). Returns null for blank / non-numeric / negative input.
 */
export function parseCentsToInt(input: string): number | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round(n * 100);
}

// -- Pure evaluation --------------------------------------------------

/**
 * Pure edge-cross test: given the PREVIOUS observed value and the CURRENT value,
 * decide whether the value just crossed the threshold in the requested
 * direction. This is a true edge trigger — it fires only on the transition, not
 * while the value merely sits past the threshold:
 *
 *   above: prev <  target AND curr >= target
 *   below: prev >  target AND curr <= target
 *
 * When `prev` is null/undefined/non-finite (no prior sample yet) we treat the
 * first sample as a LEVEL check (fire if the condition is already met), matching
 * the legacy one-shot behavior where the first poll can fire. Callers that want
 * strict edges pass a real prior value.
 */
export function alertCrossed(
  prev: number | null | undefined,
  curr: number,
  condition: AlertCondition,
  target: number,
): boolean {
  if (!Number.isFinite(curr)) return false;
  const meets = condition === "above" ? curr >= target : curr <= target;
  if (!meets) return false;
  if (prev == null || !Number.isFinite(prev)) return true;
  // Only fire on the transition into the met state.
  const prevMet = condition === "above" ? prev >= target : prev <= target;
  return !prevMet;
}

/**
 * Decide whether an alert should fire given the latest value (in the subject's
 * native integer units). LEVEL-based one-shot: an armed alert fires when the
 * value MEETS the condition (above: value >= threshold; below: value <=
 * threshold). The one-shot / re-arm behavior lives in the store
 * (markPriceAlertTriggered / rearmPriceAlert); this helper only reads
 * `alert.armed`, so a disarmed alert never fires and a re-armed one can again.
 */
export function evaluate(alert: PriceAlert, lastValue: number): boolean {
  if (!alert.armed) return false;
  if (!Number.isFinite(lastValue)) return false;
  if (alert.direction === "above") {
    return lastValue >= alert.price;
  }
  return lastValue <= alert.price;
}

/** Human short label for the subject kind. */
export function subjectKindLabel(kind: AlertSubjectKind): string {
  switch (kind) {
    case "token":
      return "Creator token";
    case "strategy":
      return "Strategy";
    case "symbol":
    default:
      return "Symbol";
  }
}

/**
 * Human one-line label for an alert, e.g.
 *   "BTC price above 65,000"  (symbol, name resolved by the caller)
 *   "Strategy NAV below $12.50".
 * `subjectName` is the resolved display name (symbol ticker / token ticker /
 * fund name); when omitted, a "#id"-style fallback is used. `format` renders the
 * threshold in the subject's units (ticks -> decimal, or cents -> "$x.xx").
 */
export function alertLabel(
  alert: PriceAlert,
  subjectName: string | undefined,
  format: (value: number) => string,
): string {
  const name = subjectName ?? subjectFallbackName(alert);
  const fieldWord = alert.field === "nav" ? "NAV" : "price";
  return `${name} ${fieldWord} ${alert.direction} ${format(alert.price)}`;
}

/** "#id"-style fallback display name when a subject cannot be resolved. */
export function subjectFallbackName(alert: PriceAlert): string {
  if (alert.subjectKind === "symbol") return `#${alert.symbolId}`;
  return alert.subjectId ? alert.subjectId : "?";
}
