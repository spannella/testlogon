import { api } from "@/api/client";
import type {
  DcaPlan,
  DcaTarget,
  DcaFrequency,
} from "@/lib/dca";

/**
 * DCA / RECURRING BUYS surface (`/me/dca/*`).
 *
 * A user schedules recurring dollar-cost-average buys of a TARGET — a market
 * SYMBOL, a creator TOKEN, or a STRATEGY / basket fund — funded from their USD
 * CASH WALLET (`/custody/cash`). The FRONTEND owns plan CRUD + a schedule
 * preview + execution history; the periodic execution itself is a SERVER-SIDE
 * runner: "recurring buys run automatically server-side once scheduled."
 *
 * CONVENTIONS (locked): every monetary amount is INTEGER CENTS; `start_ts` /
 * `end_ts` / `next_run_ts` are epoch SECONDS. NONE of these endpoints exist on
 * the backend yet — every GET degrades on 404/absent to an empty-but-honest
 * state (callers use `retry:false` + render a "recurring buys need the backend
 * runner" note), and every mutation surfaces a clear error (never silently
 * "succeeds").
 */

export type { DcaPlan, DcaTarget, DcaFrequency } from "@/lib/dca";

export interface DcaPlansResult {
  plans: DcaPlan[];
}

/** One executed (or attempted) recurring-buy run. */
export interface DcaRun {
  /** Epoch seconds of the run. */
  ts: number;
  /** Amount debited from the USD wallet, in cents. */
  amount_cents: number;
  /** Quantity filled (base units), when the buy executed. */
  filled_qty?: number;
  /** Fill price in cents, when executed. */
  price?: number;
  /** Run outcome. */
  status: "filled" | "partial" | "skipped" | "failed" | string;
  /** Human note on skip / failure (insufficient funds, etc.). */
  note?: string;
}

export interface DcaHistoryResult {
  runs: DcaRun[];
}

/** Generic mutation ack; carries a message on the failure paths. */
export interface DcaAck {
  ok?: boolean;
  status?: string;
  plan_id?: string;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
}

// -- Requests ---------------------------------------------------------

export interface CreateDcaPlanRequest {
  target: DcaTarget;
  amount_cents: number;
  frequency: DcaFrequency;
  day_of_week?: number;
  day_of_month?: number;
  /** Epoch seconds. */
  start_ts: number;
  /** Epoch seconds. */
  end_ts?: number;
  total_budget_cents?: number;
}

// -- Calls (all 404 until the backend ships — callers degrade) --------

/** The caller's recurring-buy plans. */
export const getDcaPlans = () => api.get<DcaPlansResult>("/me/dca/plans");

/** Create a recurring-buy plan (server schedules the runner). */
export const createDcaPlan = (body: CreateDcaPlanRequest) =>
  api.post<DcaPlan>("/me/dca/plans", body);

/** Pause an active plan (no runs until resumed). */
export const pauseDcaPlan = (id: string) =>
  api.post<DcaPlan>(`/me/dca/plans/${encodeURIComponent(id)}/pause`, {});

/** Resume a paused plan. */
export const resumeDcaPlan = (id: string) =>
  api.post<DcaPlan>(`/me/dca/plans/${encodeURIComponent(id)}/resume`, {});

/** Cancel a plan permanently. */
export const cancelDcaPlan = (id: string) =>
  api.post<DcaPlan>(`/me/dca/plans/${encodeURIComponent(id)}/cancel`, {});

/** Execution history for one plan. */
export const getDcaHistory = (id: string) =>
  api.get<DcaHistoryResult>(`/me/dca/plans/${encodeURIComponent(id)}/history`);

/** Trigger a single buy now (the backend executes one run out-of-band). */
export const runDcaPlanNow = (id: string) =>
  api.post<DcaAck>(`/me/dca/plans/${encodeURIComponent(id)}/run-now`, {});

// -- Helpers ----------------------------------------------------------

/** Best human message off any DCA ack (error / detail / reject reason). */
export const dcaAckMessage = (a: DcaAck | null | undefined): string | undefined => {
  if (!a) return undefined;
  if (a.detail) return a.detail;
  if (a.error) return a.error;
  if (a.note) return a.note;
  return a.reason != null ? `rejected (${a.reason})` : undefined;
};
