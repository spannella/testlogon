import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import * as trading from "@/api/endpoints/trading";
import { tradingKeys } from "@/hooks/useTrading";
import { useFundingPayments } from "@/hooks/useTrading";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import type { PmState } from "@/api/endpoints/trading";

/**
 * Prediction-market probe + funding-rate lens shared by the Markets list and
 * the Cmd+K palette so both are ONE logical, class-filtered picker.
 *
 * PM probing: there is NO list endpoint for prediction markets — the only way
 * to know a symbol is a PM is to read its per-symbol PM state (which 404s for a
 * non-PM symbol). We probe with react-query (`retry:false`, cached, staleTime)
 * so a 404 is a cheap one-shot "not a PM". To avoid a probe storm we probe ONLY
 * the caller-supplied `symbolIds` (the Markets page passes them only when the
 * Prediction tab is active; the palette passes at most a small filtered slice).
 */

/** Hard cap so we never fan out an unbounded number of PM probes at once. */
export const PM_PROBE_CAP = 40;

export interface PredictionProbe {
  /** symbol_id -> live PM state (present only for symbols that ARE prediction markets). */
  pmById: Map<number, PmState>;
  /** True when at least one probe is still in flight. */
  isProbing: boolean;
  /** Predicate: has this symbol resolved to a live PM state? */
  isPrediction: (symbolId: number) => boolean;
}

/**
 * Probe PM state for a bounded set of symbol ids. Pass `enabled: false` to skip
 * the network entirely (e.g. when the Prediction tab is not active) — it still
 * returns any already-cached probes so classification stays consistent.
 */
export function usePredictionProbe(symbolIds: number[], enabled = true): PredictionProbe {
  const ids = useMemo(() => {
    const uniq = Array.from(new Set(symbolIds.filter((n) => Number.isFinite(n) && n > 0)));
    return uniq.slice(0, PM_PROBE_CAP);
  }, [symbolIds]);

  const results = useQueries({
    queries: ids.map((id) => ({
      queryKey: tradingKeys.pmState(id),
      queryFn: () => trading.getPmState(id),
      enabled,
      retry: false,
      // A symbol’s PM-ness rarely changes; cache generously to keep probes cheap.
      staleTime: 60_000,
      gcTime: 300_000,
    })),
  });

  return useMemo(() => {
    const pmById = new Map<number, PmState>();
    let isProbing = false;
    results.forEach((r, i) => {
      if (r.isFetching) isProbing = true;
      const data = r.data as PmState | undefined;
      // A real PM state carries is_binary / state / face_value. A 404 lands in
      // r.error (retry:false) and leaves data undefined -> treated as not-a-PM.
      if (data && (data.is_binary != null || data.state != null || data.face_value != null)) {
        pmById.set(ids[i]!, data);
      }
    });
    return {
      pmById,
      isProbing,
      isPrediction: (symbolId: number) => pmById.has(symbolId),
    };
  }, [results, ids]);
}

/**
 * Latest funding rate (bps) per symbol, derived from the caller’s funding
 * payments feed (`/me/funding/payments`, newest-first). Returns "—"-able data:
 * a symbol with no funding row simply has no entry. The feed 404s until the
 * edge deploys (retry:false) — callers degrade to an empty map.
 */
export function useLatestFundingRates(enabled = true): Map<number, number> {
  const feed = useFundingPayments(enabled);
  return useMemo(() => {
    const latest = new Map<number, number>();
    const latestTs = new Map<number, number>();
    for (const p of feed.data?.funding ?? []) {
      const prev = latestTs.get(p.symbolid);
      if (prev == null || p.ts > prev) {
        latestTs.set(p.symbolid, p.ts);
        latest.set(p.symbolid, p.funding_rate_bps);
      }
    }
    return latest;
  }, [feed.data]);
}

/** Funding interval (seconds) for a symbol, or undefined when not a perp/funding book. */
export function fundingIntervalOf(sym: MarketSymbol): number | undefined {
  return sym.is_perpetual && (sym.funding_interval_s ?? 0) > 0 ? sym.funding_interval_s : undefined;
}
