import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import * as strategies from "@/api/endpoints/strategies";
import { ApiError } from "@/api/client";

/**
 * React-query hooks for the USER-CREATED STRATEGIES / BASKETS surface. Mirrors
 * the `useTokens` conventions: reads use `retry:false` because EVERY route 404s
 * until the backend ships (callers render an honest empty / "pending backend"
 * state); mutations surface a clear error toast on failure (never silent).
 */

export const strategyKeys = {
  all: ["me", "strategies"] as const,
  mine: ["me", "strategies", "mine"] as const,
  market: ["me", "strategies", "market"] as const,
  detail: (id: string) => ["me", "strategies", "detail", id] as const,
  nav: (id: string) => ["me", "strategies", "nav", id] as const,
  holdings: (id: string) => ["me", "strategies", "holdings", id] as const,
  position: (id: string) => ["me", "strategies", "position", id] as const,
  fees: (id: string) => ["me", "strategies", "fees", id] as const,
};

const POLL_MS = 15_000;

// -- Reads (degrade on 404 — retry:false) -----------------------------

export function useMyStrategies(enabled = true) {
  return useQuery({
    queryKey: strategyKeys.mine,
    queryFn: strategies.getMyStrategies,
    enabled,
    retry: false,
  });
}

export function useStrategyMarket(enabled = true) {
  return useQuery({
    queryKey: strategyKeys.market,
    queryFn: strategies.getStrategyMarket,
    enabled,
    retry: false,
  });
}

export function useStrategy(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: strategyKeys.detail(id ?? ""),
    queryFn: () => strategies.getStrategy(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useStrategyNav(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: strategyKeys.nav(id ?? ""),
    queryFn: () => strategies.getStrategyNav(id!),
    enabled: enabled && !!id,
    retry: false,
    refetchInterval: POLL_MS,
  });
}

export function useStrategyHoldings(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: strategyKeys.holdings(id ?? ""),
    queryFn: () => strategies.getStrategyHoldings(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useStrategyPosition(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: strategyKeys.position(id ?? ""),
    queryFn: () => strategies.getStrategyPosition(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useStrategyFees(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: strategyKeys.fees(id ?? ""),
    queryFn: () => strategies.getStrategyFees(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

/** True when a query error is the expected "backend not shipped yet" 404. */
export function isPendingBackend(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

/** Human error message for a failed mutation (404 -> "not available yet"). */
function mutationErrorText(err: unknown, action: string): string {
  if (err instanceof ApiError) {
    if (err.status === 404) {
      return `${action} is not available yet — the strategies backend has not shipped.`;
    }
    return err.detail || `${action} failed.`;
  }
  return `${action} failed.`;
}

// -- Mutations (clear error toast on failure — never silent) ----------

export function useCreateStrategy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: strategies.CreateStrategyRequest) => strategies.createStrategy(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: strategyKeys.mine }),
    onError: (err) => toast.error(mutationErrorText(err, "Creating the strategy")),
  });
}

export function useUpdateStrategy(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: strategies.UpdateStrategyRequest) => strategies.updateStrategy(id!, body),
    onSuccess: () => {
      if (id) qc.invalidateQueries({ queryKey: strategyKeys.detail(id) });
      qc.invalidateQueries({ queryKey: strategyKeys.mine });
    },
    onError: (err) => toast.error(mutationErrorText(err, "Saving the strategy")),
  });
}

export function usePublishStrategy(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => strategies.publishStrategy(id!),
    onSuccess: () => {
      if (id) qc.invalidateQueries({ queryKey: strategyKeys.detail(id) });
      qc.invalidateQueries({ queryKey: strategyKeys.mine });
      qc.invalidateQueries({ queryKey: strategyKeys.market });
    },
    onError: (err) => toast.error(mutationErrorText(err, "Publishing the strategy")),
  });
}

export function useInvestStrategy(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: strategies.InvestRequest) => strategies.investStrategy(id!, body),
    onSuccess: () => {
      if (id) {
        qc.invalidateQueries({ queryKey: strategyKeys.position(id) });
        qc.invalidateQueries({ queryKey: strategyKeys.nav(id) });
        qc.invalidateQueries({ queryKey: strategyKeys.detail(id) });
      }
    },
    onError: (err) => toast.error(mutationErrorText(err, "Investing")),
  });
}

export function useRedeemStrategy(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: strategies.RedeemRequest) => strategies.redeemStrategy(id!, body),
    onSuccess: () => {
      if (id) {
        qc.invalidateQueries({ queryKey: strategyKeys.position(id) });
        qc.invalidateQueries({ queryKey: strategyKeys.nav(id) });
        qc.invalidateQueries({ queryKey: strategyKeys.detail(id) });
      }
    },
    onError: (err) => toast.error(mutationErrorText(err, "Redeeming")),
  });
}
