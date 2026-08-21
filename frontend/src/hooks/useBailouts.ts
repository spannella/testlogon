import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import * as bailouts from "@/api/endpoints/bailouts";
import { ApiError } from "@/api/client";

/**
 * React-query hooks for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION
 * surface. Mirrors the `useTokens` / `useTrading` conventions: reads use
 * `retry:false` because EVERY route 404s until the backend ships (callers render
 * an honest empty / "pending backend" state and NEVER fabricate distress);
 * mutations surface a clear error toast on failure (never silent).
 */

export const bailoutKeys = {
  all: ["me", "bailouts"] as const,
  distress: ["me", "margin", "distress"] as const,
  board: ["me", "bailouts", "board"] as const,
  position: (symbolId: number) => ["me", "bailouts", "position", symbolId] as const,
  auction: (auctionId: string) => ["me", "bailouts", "auction", auctionId] as const,
  prefs: ["me", "prefs", "bailout"] as const,
};

/** Distress polls fast — the band can shift under the mark in seconds. */
const DISTRESS_POLL_MS = 8_000;
const AUCTION_POLL_MS = 8_000;
const BOARD_POLL_MS = 12_000;

// -- Reads (degrade on 404 — retry:false) -----------------------------

/** The caller's margin positions + their server-computed distress read. */
export function useDistress(enabled = true) {
  return useQuery({
    queryKey: bailoutKeys.distress,
    queryFn: bailouts.getDistress,
    enabled,
    retry: false,
    refetchInterval: DISTRESS_POLL_MS,
  });
}

/** The open bailout opportunity board (rescuer view). */
export function useBailoutBoard(enabled = true) {
  return useQuery({
    queryKey: bailoutKeys.board,
    queryFn: bailouts.getBailouts,
    enabled,
    retry: false,
    refetchInterval: BOARD_POLL_MS,
  });
}

/** The bailout auction for one of the caller's positions (by symbol id). */
export function usePositionBailout(symbolId: number | undefined, enabled = true) {
  return useQuery({
    queryKey: bailoutKeys.position(symbolId ?? -1),
    queryFn: () => bailouts.getPositionBailout(symbolId!),
    enabled: enabled && symbolId != null && Number.isFinite(symbolId),
    retry: false,
    refetchInterval: AUCTION_POLL_MS,
  });
}

/** The auto-bailout account preference. */
export function useBailoutPrefs(enabled = true) {
  return useQuery({
    queryKey: bailoutKeys.prefs,
    queryFn: bailouts.getBailoutPrefs,
    enabled,
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
    if (err.status === 404)
      return `${action} is not available yet — the bailout-auction backend has not shipped.`;
    return err.detail || `${action} failed.`;
  }
  return `${action} failed.`;
}

// -- Mutations (clear error toast on failure — never silent) -----------

/** Owner: open a bailout auction on an eligible, in-band position. */
export function useOpenBailout(symbolId: number | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: bailouts.OpenBailoutRequest) => bailouts.openBailout(symbolId!, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: bailoutKeys.distress });
      if (symbolId != null) qc.invalidateQueries({ queryKey: bailoutKeys.position(symbolId) });
      qc.invalidateQueries({ queryKey: bailoutKeys.board });
    },
    onError: (err) => toast.error(mutationErrorText(err, "Opening the bailout auction")),
  });
}

/** Rescuer: escrow capital for a position-share in an auction. */
export function usePlaceRescueBid(auctionId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: bailouts.RescueBidRequest) => bailouts.placeRescueBid(auctionId!, body),
    onSuccess: () => {
      if (auctionId) qc.invalidateQueries({ queryKey: bailoutKeys.auction(auctionId) });
      qc.invalidateQueries({ queryKey: bailoutKeys.board });
    },
    onError: (err) => toast.error(mutationErrorText(err, "Placing the rescue bid")),
  });
}

/** Owner: trigger clearing at the least-dilutive single price. */
export function useClearBailout(auctionId: string | undefined, symbolId?: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => bailouts.clearBailout(auctionId!),
    onSuccess: () => {
      if (auctionId) qc.invalidateQueries({ queryKey: bailoutKeys.auction(auctionId) });
      if (symbolId != null) qc.invalidateQueries({ queryKey: bailoutKeys.position(symbolId) });
      qc.invalidateQueries({ queryKey: bailoutKeys.distress });
      qc.invalidateQueries({ queryKey: bailoutKeys.board });
    },
    onError: (err) => toast.error(mutationErrorText(err, "Clearing the auction")),
  });
}

/** Persist the auto-bailout account preference. */
export function usePutBailoutPrefs() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: bailouts.BailoutPrefs) => bailouts.putBailoutPrefs(body),
    onSuccess: (data) => qc.setQueryData(bailoutKeys.prefs, data),
    onError: (err) => toast.error(mutationErrorText(err, "Saving the preference")),
  });
}
