import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as trading from "@/api/endpoints/trading";

/** Query keys for the trader (`/me/*`) surface. */
export const tradingKeys = {
  marginAccount: ["me", "margin_account"] as const,
  execEvents: ["me", "algo_events"] as const,
  pmState: (symbolId: number) => ["me", "pm_state", symbolId] as const,
  spotBalance: ["me", "spot_balance"] as const,
};

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
