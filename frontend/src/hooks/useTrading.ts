import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as trading from "@/api/endpoints/trading";

/** Query keys for the trader (`/me/*`) surface. */
export const tradingKeys = {
  marginAccount: ["me", "margin_account"] as const,
  execEvents: ["me", "algo_events"] as const,
  pmState: (symbolId: number) => ["me", "pm_state", symbolId] as const,
  spotBalance: ["me", "spot_balance"] as const,
  fillsFees: ["me", "fills_fees"] as const,
  liquidations: ["me", "liquidations"] as const,
  fundingPayments: ["me", "funding_payments"] as const,
  pmResolutions: ["me", "pm_resolutions"] as const,
};

/** Exchange account-feed poll (fills-fees / liquidations / funding). */
const FEED_REFETCH_MS = 10_000;

const ACCOUNT_REFETCH_MS = 5000;

/** Wallet / margin / net-position snapshot; polls while mounted. */
export function useMarginAccount(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.marginAccount,
    queryFn: trading.getMarginAccount,
    enabled,
    refetchInterval: ACCOUNT_REFETCH_MS,
  });
}

/**
 * Binary prediction-market state for a symbol. `retry: false` because a non-PM symbol (or a
 * backend without PM deployed) returns 404 — we simply treat that as "not a PM".
 */
export function usePmState(symbolId: number, enabled = true) {
  return useQuery({
    queryKey: tradingKeys.pmState(symbolId),
    queryFn: () => trading.getPmState(symbolId),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    retry: false,
    refetchInterval: ACCOUNT_REFETCH_MS,
  });
}

/** Async exec-event drain (fills + algo/OTO triggers since the last read). */
export function useExecEvents(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.execEvents,
    queryFn: trading.getExecEvents,
    enabled,
    refetchInterval: ACCOUNT_REFETCH_MS,
  });
}

function useInvalidateAccount() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: tradingKeys.marginAccount });
}

// ── Mutations ────────────────────────────────────────────────────────

export function usePlaceOrder() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: trading.placeOrder, onSuccess: invalidate });
}

export function useAmendOrder() {
  return useMutation({
    mutationFn: (args: { clordid: string; body: trading.AmendRequest }) =>
      trading.amendOrder(args.clordid, args.body),
  });
}

export function useCancelOrder() {
  const invalidate = useInvalidateAccount();
  return useMutation({
    mutationFn: (args: { clordid: string; symbolId: number }) =>
      trading.cancelOrder(args.clordid, args.symbolId),
    onSuccess: invalidate,
  });
}

export function useBulkCancel() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: trading.bulkCancel, onSuccess: invalidate });
}

export function useDeposit() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: (amount: number) => trading.marginDeposit(amount), onSuccess: invalidate });
}

export function usePlaceQuote() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: trading.placeQuote, onSuccess: invalidate });
}

export function usePlaceAlgo() {
  return useMutation({ mutationFn: trading.placeAlgo });
}

export function usePlaceOto() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: trading.placeOto, onSuccess: invalidate });
}

export function usePlaceOco() {
  const invalidate = useInvalidateAccount();
  return useMutation({
    mutationFn: (args: { symbolId: number; legs: trading.OcoLeg[] }) =>
      trading.placeOco(args.symbolId, args.legs),
    onSuccess: invalidate,
  });
}

/** Admin-only per-symbol margin/fee config. Refreshes the account snapshot on success. */
export function useMarginConfig() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: trading.marginConfig, onSuccess: invalidate });
}

export function usePlaceFunding() {
  const invalidate = useInvalidateAccount();
  return useMutation({ mutationFn: trading.placeFunding, onSuccess: invalidate });
}

/** Spot wallet balances; polls while mounted. `retry: false` — a backend without spot deployed 404s. */
export function useSpotBalance(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.spotBalance,
    queryFn: trading.getSpotBalance,
    enabled,
    refetchInterval: ACCOUNT_REFETCH_MS,
    retry: false,
  });
}

export function useSpotDeposit() {
  const invalidate = useInvalidateAccount();
  return useMutation({
    mutationFn: (args: { asset: number; amount: number }) => trading.spotDeposit(args.asset, args.amount),
    onSuccess: invalidate,
  });
}


// ── Exchange account feeds (REAL /me/fills/fees · /me/liquidations · /me/funding/payments) ──
// Poll ~10s; `retry: false` because each route 404s until the exchange edge
// deploys — callers render a graceful "unavailable" empty state on error.

/** Recent fills with the REAL per-fill engine fee + maker/taker flag. */
export function useFillsFees(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.fillsFees,
    queryFn: trading.getFillsFees,
    enabled,
    retry: false,
    refetchInterval: FEED_REFETCH_MS,
  });
}

/** The caller's forced-liquidation events. */
export function useLiquidations(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.liquidations,
    queryFn: trading.getLiquidations,
    enabled,
    retry: false,
    refetchInterval: FEED_REFETCH_MS,
  });
}

/** The caller's periodic funding payments. */
export function useFundingPayments(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.fundingPayments,
    queryFn: trading.getFundingPayments,
    enabled,
    retry: false,
    refetchInterval: FEED_REFETCH_MS,
  });
}


// ── Admin engine-config mutations (`/me/*`) ──────────────────────────
// Six admin-only engine-config POSTs. No account-invalidate needed (they tune
// the engine, not the caller balance). Each route MAY 404 on backends without
// the surface deployed — the calling UI reports that inline, no retry loop.

/** Admin-only: per-symbol matching algorithm (price-time / pro-rata / specialist). */
export function useMatchingAlgo() {
  return useMutation({ mutationFn: trading.setMatchingAlgo });
}

/** Admin-only: define a two-leg spread symbol. */
export function useSpreadConfig() {
  return useMutation({ mutationFn: trading.setSpreadConfig });
}

/** Admin-only: per-symbol trading limits / price bands / circuit breaker. */
export function useTradingParams() {
  return useMutation({ mutationFn: trading.setTradingParams });
}

/** Admin-only: per-MPID notional kill switch. */
export function useRiskConfig() {
  return useMutation({ mutationFn: trading.setRiskConfig });
}

/** Admin-only: set the perp funding index (ack echoes recomputed funding_rate_bps). */
export function useSpotIndex() {
  return useMutation({ mutationFn: trading.setSpotIndex });
}

/** Admin-only: mark a symbol spot-enforced (base/quote asset pair). */
export function useSpotConfig() {
  return useMutation({ mutationFn: trading.setSpotConfig });
}


// ── Prediction-market admin surfaces (`/me/pm_*`) ────────────────────
// Admin-only PM create/config + resolve mutations and the resolution audit-log
// query. No account-invalidate (they tune markets, not the caller balance).
// Routes MAY 404 (not deployed everywhere); resolve MAY 403 (not the resolver)
// — the calling UI reports either inline, no retry loop.

/** Admin-only: create/config a binary prediction market. */
export function usePmConfig() {
  return useMutation({ mutationFn: trading.pmConfig });
}

/** Admin-only: create/config a categorical (N linked binary outcomes). */
export function usePmGroupConfig() {
  return useMutation({ mutationFn: trading.pmGroupConfig });
}

/** Admin-only: settle a binary PM (403 if not the designated resolver). */
export function usePmResolve() {
  return useMutation({ mutationFn: trading.pmResolve });
}

/** Admin-only: resolve a categorical PM (403 if not the designated resolver). */
export function usePmGroupResolve() {
  return useMutation({ mutationFn: trading.pmGroupResolve });
}

/** PM resolution audit log. `retry: false` — the route 404s until the PM surface deploys. */
export function usePmResolutions(enabled = true) {
  return useQuery({
    queryKey: tradingKeys.pmResolutions,
    queryFn: trading.getPmResolutions,
    enabled,
    retry: false,
    refetchInterval: ACCOUNT_REFETCH_MS,
  });
}


// ── Staking & Auctions trader mutations (`/me/*`) ────────────────────
// Two PEER trader mechanisms (NOT admin). No account-invalidate — the created
// id (request_id / auction_id) is the caller-tracked handle. Each route MAY 404
// (not deployed to prod); the calling UI reports that inline, no retry loop.

/** Trader: create an outstanding stake request. */
export function useStakeRequest() {
  return useMutation({ mutationFn: trading.stakeRequest });
}

/** Trader: offer collateral to fill an outstanding stake request by id. */
export function useStakeOffer() {
  return useMutation({ mutationFn: trading.stakeOffer });
}

/** Trader: create an auction of a position qty. */
export function useAuctionRequest() {
  return useMutation({ mutationFn: trading.auctionRequest });
}

/** Trader: bid into an open auction by id. */
export function useAuctionBid() {
  return useMutation({ mutationFn: trading.auctionBid });
}
