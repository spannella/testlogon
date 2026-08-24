import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import * as dca from "@/api/endpoints/dca";
import { ApiError } from "@/api/client";

/**
 * React-query hooks for the DCA / RECURRING BUYS surface. Mirrors the
 * `useStrategies` / `useTokens` conventions: reads use `retry:false` because
 * EVERY route 404s until the SERVER-SIDE runner ships (callers render an honest
 * empty / "recurring buys need the backend runner" state); mutations surface a
 * clear error toast on failure (never silent).
 */

export const dcaKeys = {
  all: ["me", "dca"] as const,
  plans: ["me", "dca", "plans"] as const,
  history: (id: string) => ["me", "dca", "history", id] as const,
};

const HISTORY_POLL_MS = 20_000;

// -- Reads (degrade on 404 — retry:false) -----------------------------

export function useDcaPlans(enabled = true) {
  return useQuery({
    queryKey: dcaKeys.plans,
    queryFn: dca.getDcaPlans,
    enabled,
    retry: false,
  });
}

export function useDcaHistory(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: dcaKeys.history(id ?? ""),
    queryFn: () => dca.getDcaHistory(id!),
    enabled: enabled && !!id,
    retry: false,
    refetchInterval: HISTORY_POLL_MS,
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
      return `${action} is not available yet — the recurring-buys backend runner has not shipped.`;
    }
    return err.detail || `${action} failed.`;
  }
  return `${action} failed.`;
}

// -- Mutations (clear error toast on failure — never silent) ----------

export function useCreateDcaPlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: dca.CreateDcaPlanRequest) => dca.createDcaPlan(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: dcaKeys.plans }),
    onError: (err) => toast.error(mutationErrorText(err, "Creating the plan")),
  });
}

export function usePauseDcaPlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => dca.pauseDcaPlan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: dcaKeys.plans }),
    onError: (err) => toast.error(mutationErrorText(err, "Pausing the plan")),
  });
}

export function useResumeDcaPlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => dca.resumeDcaPlan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: dcaKeys.plans }),
    onError: (err) => toast.error(mutationErrorText(err, "Resuming the plan")),
  });
}

export function useCancelDcaPlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => dca.cancelDcaPlan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: dcaKeys.plans }),
    onError: (err) => toast.error(mutationErrorText(err, "Cancelling the plan")),
  });
}

export function useRunDcaPlanNow(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => dca.runDcaPlanNow(id!),
    onSuccess: () => {
      if (id) qc.invalidateQueries({ queryKey: dcaKeys.history(id) });
      qc.invalidateQueries({ queryKey: dcaKeys.plans });
    },
    onError: (err) => toast.error(mutationErrorText(err, "Running the buy now")),
  });
}
