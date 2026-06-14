/**
 * OBP PAY-001..PAY-004 — Counterparties, Standing Orders, Direct-Debit Mandates, FX
 *
 * All routes are gated by OPEN_BANK_PROJECT_ENABLED + payments_counterparties_enabled.
 * When either flag is off the backend returns 404. Handle gracefully with retry:false.
 */

import { api } from "@/api/client";

// ─── Counterparty types (PAY-001) ────────────────────────────────

export type CounterpartyScheme =
  | "IBAN"
  | "ACCOUNT_SORT_CODE"
  | "ACCOUNT_NUMBER"
  | "BANK";

export interface CounterpartyRoutingIn {
  scheme: CounterpartyScheme;
  iban?: string;
  account_number?: string;
  sort_code?: string;
  bank_code?: string;
  bank_name?: string;
  account_holder?: string;
  currency?: string;
}

export interface CounterpartyCreateIn {
  name: string;
  is_beneficiary?: boolean;
  routing: CounterpartyRoutingIn;
  description?: string;
  bespoke?: Record<string, unknown>;
}

export interface CounterpartyUpdateIn {
  name?: string;
  is_beneficiary?: boolean;
  description?: string;
  bespoke?: Record<string, unknown>;
}

export interface CounterpartyRoutingOut {
  scheme: string;
  iban_last4?: string;
  account_number_last4?: string;
  sort_code?: string;
  bank_code?: string;
  bank_name?: string;
  account_holder?: string;
  currency: string;
}

export interface Counterparty {
  counterparty_id: string;
  name: string;
  is_beneficiary: boolean;
  routing: CounterpartyRoutingOut;
  description?: string;
  bespoke?: Record<string, unknown>;
  created_at: number;
  updated_at: number;
}

export interface CounterpartiesListResp {
  counterparties: Counterparty[];
  cursor: string | null;
}

// ─── Standing order types (PAY-002) ──────────────────────────────

export type StandingOrderCadence = "weekly" | "biweekly" | "monthly";

export interface StandingOrderCreateIn {
  counterparty_id: string;
  amount_cents: number;
  currency?: string;
  cadence: StandingOrderCadence;
  start_at: number;
  end_at?: number;
  reason?: string;
}

export interface StandingOrderUpdateIn {
  amount_cents?: number;
  cadence?: StandingOrderCadence;
  end_at?: number;
  paused?: boolean;
}

export interface StandingOrder {
  standing_order_id: string;
  counterparty_id: string;
  amount_cents: number;
  currency: string;
  cadence: string;
  status: string;
  next_run_at?: number;
  last_run_at?: number;
  runs_count: number;
  created_at: number;
  updated_at: number;
}

export interface StandingOrdersListResp {
  standing_orders: StandingOrder[];
  cursor: string | null;
}

// ─── Mandate types (PAY-003) ──────────────────────────────────────

export type MandateCadence = "weekly" | "monthly";

export interface MandateCreateIn {
  counterparty_id: string;
  max_amount_cents: number;
  currency?: string;
  cadence: MandateCadence;
  start_at: number;
  end_at?: number;
  reference?: string;
}

export interface Mandate {
  mandate_id: string;
  counterparty_id: string;
  max_amount_cents: number;
  currency: string;
  cadence: string;
  status: string;
  next_run_at?: number;
  last_run_at?: number;
  pulled_this_window_cents: number;
  runs_count: number;
  created_at: number;
  updated_at: number;
}

export interface MandatesListResp {
  mandates: Mandate[];
  cursor: string | null;
}

// ─── FX types (PAY-004) ───────────────────────────────────────────

export interface FxRateOut {
  pair: string;
  source_currency: string;
  target_currency: string;
  rate: number;
  source: string;
  as_of: number;
  set_by: string;
}

export interface FxConvertOut {
  source_currency: string;
  target_currency: string;
  source_amount_cents: number;
  target_amount_cents: number;
  rate: number;
  as_of: number;
}

// ─── Counterparty API (PAY-001) ───────────────────────────────────

export const createCounterparty = (body: CounterpartyCreateIn) =>
  api.post<Counterparty>("/ui/counterparties", body);

export const listCounterparties = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CounterpartiesListResp>("/ui/counterparties", params);
};

export const getCounterparty = (id: string) =>
  api.get<Counterparty>(`/ui/counterparties/${id}`);

export const updateCounterparty = (id: string, body: CounterpartyUpdateIn) =>
  api.patch<Counterparty>(`/ui/counterparties/${id}`, body);

export const deleteCounterparty = (id: string) =>
  api.del<{ ok: boolean }>(`/ui/counterparties/${id}`);

// ─── Standing orders API (PAY-002) ────────────────────────────────

export const createStandingOrder = (body: StandingOrderCreateIn) =>
  api.post<StandingOrder>("/ui/standing-orders", body);

export const listStandingOrders = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<StandingOrdersListResp>("/ui/standing-orders", params);
};

export const getStandingOrder = (id: string) =>
  api.get<StandingOrder>(`/ui/standing-orders/${id}`);

export const updateStandingOrder = (id: string, body: StandingOrderUpdateIn) =>
  api.patch<StandingOrder>(`/ui/standing-orders/${id}`, body);

export const pauseStandingOrder = (id: string) =>
  api.post<StandingOrder>(`/ui/standing-orders/${id}/pause`);

export const resumeStandingOrder = (id: string) =>
  api.post<StandingOrder>(`/ui/standing-orders/${id}/resume`);

export const cancelStandingOrder = (id: string) =>
  api.del<StandingOrder>(`/ui/standing-orders/${id}`);

// ─── Mandate API (PAY-003) ────────────────────────────────────────

export const createMandate = (body: MandateCreateIn) =>
  api.post<Mandate>("/ui/mandates", body);

export const listMandates = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<MandatesListResp>("/ui/mandates", params);
};

export const getMandate = (id: string) =>
  api.get<Mandate>(`/ui/mandates/${id}`);

export const revokeMandate = (id: string) =>
  api.post<Mandate>(`/ui/mandates/${id}/revoke`);

export const pauseMandate = (id: string) =>
  api.post<Mandate>(`/ui/mandates/${id}/pause`);

// ─── FX API (PAY-004) ─────────────────────────────────────────────

export const getFxRate = (source: string, target: string) =>
  api.get<FxRateOut>(`/ui/fx/rates/${source}/${target}`);

export const convertFx = (amount_cents: number, from: string, to: string) =>
  api.get<FxConvertOut>("/ui/fx/convert", {
    amount_cents: String(amount_cents),
    from,
    to,
  });
