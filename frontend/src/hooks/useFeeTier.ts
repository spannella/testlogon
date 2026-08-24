// Shared MAKER/TAKER FEE-TIER resolver.
//
// Resolves the caller's current fee tier ONCE and shares it across surfaces
// (the Fees page + the trade ticket's fee gauge) via a single react-query key.
// Mirrors the resolution FeesPage originally did inline:
//   1. Prefer the AUTHORITATIVE backend read `GET /me/fees/tier` (retry:false;
//      404s until the exchange edge deploys).
//   2. On 404 / unavailable, fall back to a CLIENT-COMPUTED tier from the
//      30-day executed-fill volume (`GET /me/fills/fees`), using the pure
//      `lib/feeTiers` engine.
//
// Returns the resolved tier name + maker/taker bps + whether the numbers are
// authoritative or an estimate, so callers can badge accordingly.

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import { getFeeTier, type FeeTierResponse } from "@/api/endpoints/fees";
import type { FillFee } from "@/api/endpoints/trading";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { useFillsFees } from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import {
  volume30dCents,
  tierForVolume,
  tierById,
  type VolumeFill,
  type FeeTier,
} from "@/lib/feeTiers";

/** Shared query key so the authoritative tier read is fetched/cached once. */
export const FEE_TIER_QUERY_KEY = ["fees", "tier"] as const;

export interface ResolvedFeeTier {
  /** Human tier label (e.g. "Gold"). */
  tierName: string;
  /** Stable tier id (matches FEE_TIERS[].id). */
  tierId: string;
  /** The caller's maker fee, basis points. */
  makerBps: number;
  /** The caller's taker fee, basis points. */
  takerBps: number;
  /** 30-day rolling volume backing the tier, USD cents. */
  volumeCents: number;
  /** Where the numbers came from. */
  source: "authoritative" | "estimated";
  /** True while either the authoritative read or the fills feed is loading. */
  isPending: boolean;
}

/**
 * Resolve the caller's current maker/taker fee tier. Lightweight: it reuses the
 * shared symbols + fills feeds already in cache and a single authoritative
 * query key. Never throws — degrades to the client-side estimate.
 */
export function useFeeTier(): ResolvedFeeTier {
  const symbolsQuery = useSymbols();
  const fillsQuery = useFillsFees();

  const tierQuery = useQuery({
    queryKey: FEE_TIER_QUERY_KEY,
    queryFn: getFeeTier,
    retry: false,
  });

  // symbolid -> catalog entry (price scaler), same resolver as FeesPage/Tax.
  const symById = useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbolsQuery.data?.symbols ?? []) m.set(s.symbol_id, s);
    return m;
  }, [symbolsQuery.data]);

  const rawFills: FillFee[] = Array.isArray(fillsQuery.data?.fills)
    ? fillsQuery.data!.fills!
    : [];

  // Normalize the engine feed -> integer-cents fills (price tick / scaler).
  const normalized: VolumeFill[] = useMemo(() => {
    const out: VolumeFill[] = [];
    for (const f of rawFills) {
      const scaler = symById.get(f.symbolid)?.price_scaler || 1;
      const priceCents = Math.round((f.price / scaler) * 100);
      const qty = Math.abs(f.qty);
      if (!qty || priceCents <= 0) continue;
      out.push({ ts: f.ts, priceCents, qty });
    }
    return out;
  }, [rawFills, symById]);

  const estimatedVolumeCents = useMemo(
    () => volume30dCents(normalized, Date.now()),
    [normalized],
  );

  // Prefer the authoritative read when it resolved; else the client estimate.
  const authoritative: FeeTierResponse | undefined = tierQuery.isSuccess
    ? tierQuery.data
    : undefined;
  const isAuthoritative = !!authoritative;

  const volumeCents = authoritative?.volume_30d_cents ?? estimatedVolumeCents;

  const currentTier: FeeTier =
    (authoritative && tierById(authoritative.tier_id)) || tierForVolume(volumeCents);

  const makerBps = authoritative?.maker_bps ?? currentTier.makerBps;
  const takerBps = authoritative?.taker_bps ?? currentTier.takerBps;

  const isPending =
    tierQuery.isPending ||
    (!isAuthoritative && (fillsQuery.isLoading || symbolsQuery.isLoading));

  return {
    tierName: currentTier.name,
    tierId: currentTier.id,
    makerBps,
    takerBps,
    volumeCents,
    source: isAuthoritative ? "authoritative" : "estimated",
    isPending,
  };
}
