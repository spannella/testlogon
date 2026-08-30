// FE-161 (EPIC G): fetch sponsored slot ad(s) for a surface, degrade-on-404.
//
// Wraps serveAd (POST /ui/ads/serve). A surface can request >1 slot; each is
// an independent serve so an unfilled/errored slot never breaks the others.
// Returns only VALID (filled + creative_id) responses, so callers can hand the
// array straight to interleaveSponsored. Never throws.

import { useQuery } from "@tanstack/react-query";
import { serveAd } from "@/api/endpoints/ads";
import type { AdServeRequest, AdServeResponse } from "@/api/types";
import { isValidServeResponse } from "@/lib/sponsoredSlots";

export interface SponsoredSlotOptions {
  /** Surface identifier, e.g. "token_discovery" or "catalog". */
  surface: string;
  /** Slot type sent to the server + used in tracking. */
  slotType?: string;
  /** How many slots this surface wants. Default 2. */
  count?: number;
  /** Optional context passed through to the serve request. */
  contentType?: string;
  contentId?: string;
  creatorId?: string;
  /** Gate the fetch (e.g. only when the organic list is long enough). */
  enabled?: boolean;
}

/**
 * Serve up to `count` sponsored slots for a surface. Best-effort: any slot
 * that 404s / errors / comes back unfilled is silently dropped. The organic
 * experience is unaffected when this returns [].
 */
export function useSponsoredSlot(
  opts: SponsoredSlotOptions,
): { ads: AdServeResponse[]; isLoading: boolean } {
  const {
    surface,
    slotType = "sponsored_post",
    count = 2,
    contentType,
    contentId = "",
    creatorId = "",
    enabled = true,
  } = opts;

  const query = useQuery({
    queryKey: ["sponsored-slot", surface, slotType, count],
    enabled: enabled && count > 0,
    staleTime: 60_000,
    retry: false,
    queryFn: async (): Promise<AdServeResponse[]> => {
      const req: AdServeRequest = {
        surface,
        slot_type: slotType,
        content_type: contentType,
        content_id: contentId,
        creator_id: creatorId,
      };
      // Independent serves; a rejected/unfilled slot must not fail the batch.
      const settled = await Promise.allSettled(
        Array.from({ length: count }, () => serveAd(req)),
      );
      const filled: AdServeResponse[] = [];
      const seen = new Set<string>();
      for (const r of settled) {
        if (r.status !== "fulfilled") continue;
        const resp = r.value;
        if (!isValidServeResponse(resp)) continue;
        // De-dupe: a surface should not show the same creative twice.
        const id = resp.creative_id!;
        if (seen.has(id)) continue;
        seen.add(id);
        filled.push(resp);
      }
      return filled;
    },
  });

  return { ads: query.data ?? [], isLoading: query.isLoading };
}
