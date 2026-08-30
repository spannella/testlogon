// FE-161 (EPIC G): pure helpers for interleaving sponsored slots into a list.
//
// No network, no DOM — deterministic + unit-testable. The rendering layer
// (useSponsoredSlot / SponsoredSlotCard) consumes the {type} discriminated
// union this produces and handles beacons/tracking.

import type { AdServeResponse } from "@/api/types";

/** A rendered entry in an interleaved list: either an organic item or an ad. */
export type SponsoredEntry<T> =
  | { type: "organic"; item: T; key: string }
  | { type: "sponsored"; ad: AdServeResponse; key: string };

export interface InterleaveOpts {
  /** Insert a sponsored slot after every N organic items. Default 5. */
  everyN?: number;
  /** Skip this many organic items before the first eligible insert. Default = everyN. */
  startAt?: number;
  /** Hard cap on the number of sponsored slots inserted. Default = ads.length. */
  max?: number;
}

const DEFAULT_EVERY_N = 5;

/**
 * How many sponsored slots WOULD be inserted for a list of `itemCount`
 * organic items, before the ad-availability + `max` cap is applied. Callers
 * use this to decide how many ads to request.
 */
export function sponsoredSlotCount(
  itemCount: number,
  opts: { everyN?: number; max?: number } = {},
): number {
  const everyN = Math.max(1, Math.floor(opts.everyN ?? DEFAULT_EVERY_N));
  if (itemCount <= 0) return 0;
  // A slot goes after each full block of `everyN` items; never past the end
  // (a trailing slot only makes sense if more organic items follow, which the
  // interleave never does — so we place at most floor(itemCount / everyN),
  // and never after the final item).
  let slots = Math.floor(itemCount / everyN);
  // If itemCount is an exact multiple, the last slot would land at the very end
  // (after the last item) — drop it so slots are never trailing.
  if (slots > 0 && itemCount % everyN === 0) slots -= 1;
  if (opts.max != null) slots = Math.min(slots, Math.max(0, Math.floor(opts.max)));
  return slots;
}

/**
 * A serve response is renderable as a slot only if the server filled it and
 * it carries a creative id.
 */
export function isValidServeResponse(
  resp: AdServeResponse | null | undefined,
): resp is AdServeResponse {
  return !!resp && resp.filled === true && !!resp.creative_id;
}

/**
 * Interleave `sponsored` ads into `items`, one slot after every `everyN`
 * organic items, starting after `startAt` items. Slots are:
 *  - never adjacent (there is always >=1 organic item between two slots),
 *  - never past the end (no trailing slot after the final organic item),
 *  - capped by `max` AND by the number of valid ads available.
 * Invalid/unfilled ads are ignored. Deterministic.
 */
export function interleaveSponsored<T>(
  items: readonly T[],
  sponsored: readonly (AdServeResponse | null | undefined)[],
  opts: InterleaveOpts = {},
  keyOf?: (item: T, index: number) => string,
): SponsoredEntry<T>[] {
  const everyN = Math.max(1, Math.floor(opts.everyN ?? DEFAULT_EVERY_N));
  const startAt = Math.max(0, Math.floor(opts.startAt ?? everyN));
  const ads = sponsored.filter(isValidServeResponse);
  const maxSlots = Math.min(
    ads.length,
    opts.max != null ? Math.max(0, Math.floor(opts.max)) : ads.length,
  );

  const out: SponsoredEntry<T>[] = [];
  let adsUsed = 0;
  const n = items.length;

  for (let i = 0; i < n; i++) {
    const item = items[i]!;
    out.push({
      type: "organic",
      item,
      key: keyOf ? keyOf(item, i) : `organic-${i}`,
    });

    const consumed = i + 1; // organic items emitted so far
    const eligible =
      consumed >= startAt &&
      consumed < n && // never a trailing slot
      (consumed - startAt) % everyN === 0;

    if (eligible && adsUsed < maxSlots) {
      const ad = ads[adsUsed]!;
      out.push({
        type: "sponsored",
        ad,
        key: `sponsored-${ad.creative_id ?? adsUsed}-${consumed}`,
      });
      adsUsed++;
    }
  }

  return out;
}
