import * as React from "react";
import {
  useFillsFees,
  useLiquidations,
  useFundingPayments,
} from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import {
  normalizeFills,
  normalizeFunding,
  normalizeLiquidations,
  mergeEvents,
  unreadCount as computeUnread,
  type ActivityEvent,
  type NormalizeContext,
} from "@/lib/activity";

/** localStorage key for the Activity Center last-seen high-water mark (epoch ms). */
export const ACTIVITY_LAST_SEEN_KEY = "activity.lastSeen.v1";

export function loadLastSeen(): number {
  try {
    const raw = localStorage.getItem(ACTIVITY_LAST_SEEN_KEY);
    if (!raw) return 0;
    const n = Number(raw);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

export function saveLastSeen(ts: number): void {
  try {
    localStorage.setItem(ACTIVITY_LAST_SEEN_KEY, String(ts));
  } catch {
    /* quota / private-mode — degrades to in-memory only */
  }
}

/** Custom event so a mark-all-read in the page updates the bell badge live. */
export const ACTIVITY_SEEN_EVENT = "tl:activitySeen";

/**
 * Aggregate the account-level `/me/*` trader feeds into ONE normalized,
 * newest-first Activity timeline. Each source degrades independently: a 404
 * (route not deployed) leaves that feed empty rather than failing the whole
 * page. This is the durable-history counterpart to `useTradingAlerts`.
 */
export function useActivityEvents(enabled = true): {
  events: ActivityEvent[];
  sources: { fills: boolean; funding: boolean; liquidations: boolean };
  isLoading: boolean;
} {
  const fills = useFillsFees(enabled);
  const funding = useFundingPayments(enabled);
  const liquidations = useLiquidations(enabled);
  const { data: symbolsData } = useSymbols();

  const ctx = React.useMemo<NormalizeContext>(() => {
    const byId = new Map<number, MarketSymbol>();
    for (const s of symbolsData?.symbols ?? []) byId.set(s.symbol_id, s);
    return {
      symbolName: (id) =>
        (id != null && byId.get(id)?.symbol) || (id != null ? `#${id}` : "?"),
      scalerFor: (id) => (id != null && byId.get(id)?.price_scaler) || 1,
    };
  }, [symbolsData]);

  const events = React.useMemo(
    () =>
      mergeEvents(
        normalizeFills(fills.data?.fills, ctx),
        normalizeFunding(funding.data?.funding, ctx),
        normalizeLiquidations(liquidations.data?.liquidations, ctx),
      ),
    [fills.data, funding.data, liquidations.data, ctx],
  );

  return {
    events,
    sources: {
      // A source is "available" unless it errored (typically a 404).
      fills: !fills.isError,
      funding: !funding.isError,
      liquidations: !liquidations.isError,
    },
    isLoading: fills.isLoading || funding.isLoading || liquidations.isLoading,
  };
}

/**
 * Lightweight unread badge for the header/nav: derives the count from the same
 * aggregated feeds vs the persisted last-seen marker. Re-reads the marker when
 * the page fires ACTIVITY_SEEN_EVENT (or another tab writes it).
 */
export function useActivityUnread(enabled = true): number {
  const { events } = useActivityEvents(enabled);
  const [lastSeen, setLastSeen] = React.useState<number>(() => loadLastSeen());

  React.useEffect(() => {
    const reload = () => setLastSeen(loadLastSeen());
    const onStorage = (e: StorageEvent) => {
      if (e.key === ACTIVITY_LAST_SEEN_KEY || e.key === null) reload();
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener(ACTIVITY_SEEN_EVENT, reload);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(ACTIVITY_SEEN_EVENT, reload);
    };
  }, []);

  return React.useMemo(() => computeUnread(events, lastSeen), [events, lastSeen]);
}
