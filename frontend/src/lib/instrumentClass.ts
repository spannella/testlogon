/**
 * Pure instrument classifier — the single source of truth for which "class"
 * a market symbol belongs to, shared by the Markets list and the Cmd+K palette
 * so they behave as ONE logical symbol picker.
 *
 * A symbol can belong to SEVERAL classes at once:
 *   - a perpetual is BOTH a "perp" AND (when funding_interval_s > 0) a "funding" book entry;
 *   - a symbol with a live prediction-market state ADDS "prediction".
 * Discriminators are the CONFIRMED backend fields only — do NOT invent new ones:
 *   - spot        := is_perpetual === false
 *   - perp        := is_perpetual === true
 *   - funding     := is_perpetual === true && funding_interval_s > 0 (a lens on perps)
 *   - prediction  := has a live PM state (detected out-of-band; passed in as a flag)
 */
import type { MarketSymbol } from "@/api/endpoints/marketData";

export type InstrumentClass = "spot" | "perp" | "prediction" | "funding";

/** The "All" pseudo-tab value used by the filter UI (not a real class). */
export const ALL_CLASS = "all" as const;
export type ClassTab = typeof ALL_CLASS | InstrumentClass;

/** Human labels for each class + the All pseudo-tab. */
export const CLASS_LABELS: Record<ClassTab, string> = {
  all: "All",
  spot: "Spot",
  perp: "Perp",
  prediction: "Prediction",
  funding: "Funding",
};

/** Display order for the class tabs / palette headings (All first). */
export const CLASS_TAB_ORDER: ClassTab[] = ["all", "spot", "perp", "prediction", "funding"];

/** Display order of the real classes (no All) — used for palette headings. */
export const CLASS_ORDER: InstrumentClass[] = ["spot", "perp", "prediction", "funding"];

/** Honest empty-state copy per class (shown when a filtered group is empty). */
export const CLASS_EMPTY_COPY: Record<InstrumentClass, string> = {
  spot: "No spot markets listed.",
  perp: "No perpetual contracts listed.",
  prediction: "No prediction markets listed.",
  funding: "No funding-book contracts listed.",
};

export interface ClassifyOpts {
  /** True when the symbol has a live prediction-market state (probed out-of-band). */
  isPrediction?: boolean;
}

/**
 * All classes a symbol belongs to, in {@link CLASS_ORDER}. A perp is also in
 * the funding book; a PM-enabled symbol additionally gets "prediction".
 */
export function classesForSymbol(sym: MarketSymbol, opts: ClassifyOpts = {}): InstrumentClass[] {
  const out: InstrumentClass[] = [];
  if (sym.is_perpetual) {
    out.push("perp");
    if ((sym.funding_interval_s ?? 0) > 0) out.push("funding");
  } else {
    out.push("spot");
  }
  if (opts.isPrediction) out.push("prediction");
  // Normalize to the canonical display order.
  return CLASS_ORDER.filter((c) => out.includes(c));
}

/** True when the symbol belongs to the given class tab ("all" always matches). */
export function symbolInClass(
  sym: MarketSymbol,
  tab: ClassTab,
  opts: ClassifyOpts = {},
): boolean {
  if (tab === ALL_CLASS) return true;
  return classesForSymbol(sym, opts).includes(tab);
}
