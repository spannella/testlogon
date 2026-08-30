// FE-162 (EPIC G, <- BE-161/BE-162/BE-163): pure helpers for the
// promote-entity picker + behavioral-targeting UI.
//
// No network, no DOM - deterministic + unit-testable. The rendering layer
// (PromoteTargetingStep / CampaignEditor) consumes these to build the
// createCampaign / createTargeting request bodies and to render summaries.
//
// OPT-IN NOTE: behavioral targeting only applies to users who opted into
// personalization; everyone else falls into the untargeted pool. This is a
// product invariant surfaced in the UI (see respectsOptInNote).

import type { AdTargeting } from "@/api/types";

/** What a campaign can promote. */
export type PromoteEntityKind = "market" | "creator_token" | "product";

export const PROMOTE_ENTITY_KINDS: readonly PromoteEntityKind[] = [
  "market",
  "creator_token",
  "product",
] as const;

/** Human labels for each promote-entity kind. */
export const PROMOTE_ENTITY_LABELS: Record<PromoteEntityKind, string> = {
  market: "Market",
  creator_token: "Creator token",
  product: "Product",
};

/** The promote-entity descriptor persisted onto the campaign/creative. */
export interface PromotePayload {
  promote_kind: PromoteEntityKind;
  promote_entity_id: string;
}

/**
 * The UI-side selected targeting segments. Every field is optional and defaults
 * to "no constraint". Kept flat + serialisable so it maps 1:1 onto AdTargeting.
 */
export interface SelectedSegments {
  name?: string;
  age_ranges?: string[];
  genders?: string[];
  country_codes?: string[];
  device_types?: string[];
  content_categories?: string[];
  new_user_only?: boolean;
}

/** Preset option lists for the segment multi-selects. */
export const SEGMENT_OPTIONS = {
  age_ranges: ["18-24", "25-34", "35-44", "45-54", "55+"],
  genders: ["male", "female", "other"],
  countries: [
    { code: "US", label: "United States" },
    { code: "CA", label: "Canada" },
    { code: "GB", label: "United Kingdom" },
    { code: "DE", label: "Germany" },
    { code: "FR", label: "France" },
    { code: "AU", label: "Australia" },
    { code: "JP", label: "Japan" },
    { code: "BR", label: "Brazil" },
    { code: "IN", label: "India" },
    { code: "MX", label: "Mexico" },
  ],
  device_types: ["mobile", "desktop", "tablet"],
  content_categories: [
    "gaming",
    "finance",
    "sports",
    "music",
    "tech",
    "lifestyle",
    "news",
    "education",
  ],
} as const;

/** Constant disclosure copy: targeting respects the users opt-in choice. */
export const respectsOptInNote =
  "Targeting only applies to users who opted into personalization. " +
  "Everyone else is reached without behavioral segments.";

/**
 * Map the selected UI segments onto an AdTargeting request body, DROPPING empty
 * arrays / unset fields so the server never receives noise. `new_user_only` is
 * only sent when true. Always carries a name (defaults to "Default").
 */
export function buildTargetingPayload(
  segments: SelectedSegments,
): Partial<AdTargeting> {
  const body: Partial<AdTargeting> = {
    name: segments.name?.trim() || "Default",
  };
  const put = (k: keyof AdTargeting, v?: string[]) => {
    if (v && v.length) (body as Record<string, unknown>)[k] = v;
  };
  put("age_ranges", segments.age_ranges);
  put("genders", segments.genders);
  put("country_codes", segments.country_codes);
  put("device_types", segments.device_types);
  put("content_categories", segments.content_categories);
  if (segments.new_user_only) body.new_user_only = true;
  return body;
}

/** Build the promote-entity descriptor for a campaign/creative. */
export function buildPromotePayload(
  kind: PromoteEntityKind,
  entityId: string,
): PromotePayload {
  return { promote_kind: kind, promote_entity_id: entityId.trim() };
}

export interface PromoteCampaignDraft {
  name: string;
  budgetCents: number;
  kind: PromoteEntityKind | null;
  entityId: string | null;
}

/** Validate a promote-campaign draft; returns a (possibly empty) error list. */
export function validatePromoteCampaign(
  draft: PromoteCampaignDraft,
): string[] {
  const errors: string[] = [];
  if (!draft.name || !draft.name.trim()) {
    errors.push("Campaign name is required.");
  }
  if (!Number.isFinite(draft.budgetCents) || draft.budgetCents < 100) {
    errors.push("Minimum budget is $1.00.");
  }
  if (!draft.kind || !PROMOTE_ENTITY_KINDS.includes(draft.kind)) {
    errors.push("Choose what to promote (a market, creator token, or product).");
  }
  if (!draft.entityId || !draft.entityId.trim()) {
    errors.push("Select an item to promote.");
  }
  return errors;
}

/**
 * A compact human summary of a targeting body, e.g.
 * "US, 18-34, mobile - opt-in only". Segments are joined with ", "; the opt-in
 * suffix is always appended (the invariant). "Everyone" when no segments set.
 */
export function summarizeTargeting(
  targeting: Partial<AdTargeting> | null | undefined,
): string {
  const parts: string[] = [];
  if (targeting) {
    if (targeting.country_codes?.length) parts.push(targeting.country_codes.join("/"));
    if (targeting.age_ranges?.length) parts.push(targeting.age_ranges.join(", "));
    if (targeting.genders?.length) parts.push(targeting.genders.join("/"));
    if (targeting.device_types?.length) parts.push(targeting.device_types.join("/"));
    if (targeting.content_categories?.length)
      parts.push(targeting.content_categories.join("/"));
    if (targeting.new_user_only) parts.push("new users");
  }
  const lead = parts.length ? parts.join(", ") : "Everyone";
  return lead + " - opt-in only";
}

/** Compact reach formatter: 1234 -> "1.2K", 2_500_000 -> "2.5M". */
export function formatEstimatedReach(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0";
  if (n < 1000) return String(Math.floor(n));
  if (n < 1_000_000) {
    const k = n / 1000;
    return (k >= 100 ? Math.round(k) : Math.round(k * 10) / 10) + "K";
  }
  const m = n / 1_000_000;
  return (m >= 100 ? Math.round(m) : Math.round(m * 10) / 10) + "M";
}
