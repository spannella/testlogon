import type { RewardKind } from "@/api/endpoints/rewards";
import type { AdminCatalogInput } from "@/api/endpoints/adminRewards";

// Reuse the shared rewards formatters so the admin surface renders points/cents
// identically to the user-facing Rewards page.
export { formatPoints, formatCents } from "@/lib/rewards";

/** The subset of an item we validate (create + edit share this shape). */
export interface CatalogItemValidatable {
  name: string;
  cost_points: number;
  value_cents: number;
  kind: RewardKind;
  /** Optional inventory cap. null/undefined = unlimited (valid). */
  stock_limit?: number | null;
  /** Optional display order (>= 0). undefined = default 0 (valid). */
  sort_order?: number;
}

export interface ValidationResult {
  ok: boolean;
  errors: Partial<Record<"name" | "cost_points" | "value_cents" | "kind" | "stock_limit" | "sort_order", string>>;
}

const REWARD_KINDS: readonly RewardKind[] = ["cash", "perk"];

function isPositiveInt(n: number): boolean {
  return Number.isInteger(n) && n > 0;
}

function isNonNegativeInt(n: number): boolean {
  return Number.isInteger(n) && n >= 0;
}

/**
 * Validate a catalog item draft. Pure — no I/O.
 *
 * Rules:
 *  - name: required, non-empty (after trim)
 *  - cost_points: integer > 0
 *  - value_cents: integer >= 0
 *  - kind: one of "cash" | "perk"
 *  - a CASH reward must have value_cents > 0 (it credits the USD cash wallet)
 */
export function validateCatalogItem(item: CatalogItemValidatable): ValidationResult {
  const errors: ValidationResult["errors"] = {};

  if (!item.name || item.name.trim().length === 0) {
    errors.name = "Name is required.";
  }

  if (!isPositiveInt(item.cost_points)) {
    errors.cost_points = "Cost must be a whole number greater than 0.";
  }

  if (!isNonNegativeInt(item.value_cents)) {
    errors.value_cents = "Value must be a whole number of cents (0 or more).";
  }

  if (!REWARD_KINDS.includes(item.kind)) {
    errors.kind = "Kind must be cash or perk.";
  } else if (item.kind === "cash" && !(item.value_cents > 0)) {
    // Only meaningful once value_cents is otherwise valid; a cash reward with
    // no cash value is nonsensical.
    errors.value_cents = "A cash reward must have a value greater than $0.00.";
  }

  // stock_limit is OPTIONAL: null/undefined = unlimited (valid). When present it
  // must be a whole number >= 0. NaN (e.g. a half-typed field) is invalid.
  if (item.stock_limit !== null && item.stock_limit !== undefined) {
    if (!isNonNegativeInt(item.stock_limit)) {
      errors.stock_limit = "Stock limit must be a whole number (0 or more), or blank for unlimited.";
    }
  }

  // sort_order is OPTIONAL: undefined = default 0 (valid). When present it must
  // be a whole number >= 0.
  if (item.sort_order !== undefined && item.sort_order !== null) {
    if (!isNonNegativeInt(item.sort_order)) {
      errors.sort_order = "Sort order must be a whole number (0 or more).";
    }
  }

  return { ok: Object.keys(errors).length === 0, errors };
}

/** A blank draft for the create form. */
export function emptyDraft(): AdminCatalogInput {
  return {
    name: "",
    description: "",
    cost_points: 0,
    value_cents: 0,
    kind: "perk",
    active: true,
    stock_limit: null,
    featured: false,
    sort_order: 0,
  };
}
