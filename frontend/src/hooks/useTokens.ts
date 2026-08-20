import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import * as tokens from "@/api/endpoints/tokens";
import { ApiError } from "@/api/client";

/**
 * React-query hooks for the CREATOR REVENUE-SHARE TOKEN surface. Mirrors the
 * `useTrading` conventions: reads use `retry:false` because EVERY route 404s
 * until the backend ships (callers render an honest empty / "pending backend"
 * state); mutations surface a clear error toast on failure (never silent).
 */

export const tokenKeys = {
  all: ["me", "tokens"] as const,
  mine: ["me", "tokens", "mine"] as const,
  market: ["me", "tokens", "market"] as const,
  detail: (id: string) => ["me", "tokens", "detail", id] as const,
  captable: (id: string) => ["me", "tokens", "captable", id] as const,
  auction: (id: string) => ["me", "tokens", "auction", id] as const,
  revenue: (id: string) => ["me", "tokens", "revenue", id] as const,
  upkeep: (id: string) => ["me", "tokens", "upkeep", id] as const,
};

const POLL_MS = 15_000;

// ── Reads (degrade on 404 — retry:false) ─────────────────────────────

export function useMyTokens(enabled = true) {
  return useQuery({
    queryKey: tokenKeys.mine,
    queryFn: tokens.getMyTokens,
    enabled,
    retry: false,
  });
}

export function useTokenMarket(enabled = true) {
  return useQuery({
    queryKey: tokenKeys.market,
    queryFn: tokens.getTokenMarket,
    enabled,
    retry: false,
  });
}

export function useToken(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: tokenKeys.detail(id ?? ""),
    queryFn: () => tokens.getToken(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useCapTable(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: tokenKeys.captable(id ?? ""),
    queryFn: () => tokens.getCapTable(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useAuction(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: tokenKeys.auction(id ?? ""),
    queryFn: () => tokens.getAuction(id!),
    enabled: enabled && !!id,
    retry: false,
    refetchInterval: POLL_MS,
  });
}

export function useRevenue(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: tokenKeys.revenue(id ?? ""),
    queryFn: () => tokens.getRevenue(id!),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useUpkeep(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: tokenKeys.upkeep(id ?? ""),
    queryFn: () => tokens.getUpkeep(id!),
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
    if (err.status === 404) return `${action} is not available yet — the backend for creator tokens has not shipped.`;
    return err.detail || `${action} failed.`;
  }
  return `${action} failed.`;
}

// ── Mutations (clear error toast on failure — never silent) ──────────

export function useMintToken() {
  return useMutation({
    mutationFn: (body: tokens.MintTokenRequest) => tokens.mintToken(body),
    onError: (err) => toast.error(mutationErrorText(err, "Minting the token")),
  });
}

export function useListToken(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: tokens.ListTokenRequest) => tokens.listToken(id!, body),
    onSuccess: () => {
      if (id) {
        qc.invalidateQueries({ queryKey: tokenKeys.auction(id) });
        qc.invalidateQueries({ queryKey: tokenKeys.detail(id) });
      }
    },
    onError: (err) => toast.error(mutationErrorText(err, "Opening the IPO")),
  });
}

export function usePlaceAuctionBid(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: tokens.PlaceBidRequest) => tokens.placeAuctionBid(id!, body),
    onSuccess: () => id && qc.invalidateQueries({ queryKey: tokenKeys.auction(id) }),
    onError: (err) => toast.error(mutationErrorText(err, "Placing the bid")),
  });
}

export function useClearAuction(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => tokens.clearAuction(id!),
    onSuccess: () => {
      if (id) {
        qc.invalidateQueries({ queryKey: tokenKeys.auction(id) });
        qc.invalidateQueries({ queryKey: tokenKeys.detail(id) });
        qc.invalidateQueries({ queryKey: tokenKeys.captable(id) });
      }
    },
    onError: (err) => toast.error(mutationErrorText(err, "Clearing the auction")),
  });
}

export function useClaimRevenue(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => tokens.claimRevenue(id!),
    onSuccess: () => id && qc.invalidateQueries({ queryKey: tokenKeys.revenue(id) }),
    onError: (err) => toast.error(mutationErrorText(err, "Claiming revenue")),
  });
}

export function usePayUpkeep(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => tokens.payUpkeep(id!),
    onSuccess: () => {
      if (id) {
        qc.invalidateQueries({ queryKey: tokenKeys.upkeep(id) });
        qc.invalidateQueries({ queryKey: tokenKeys.detail(id) });
      }
    },
    onError: (err) => toast.error(mutationErrorText(err, "Paying upkeep")),
  });
}
