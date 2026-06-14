/**
 * Rent-Ledger API endpoint wrappers — RNT-001..RNT-006
 * Backend route prefix: /ui/rent  (cookie-session auth)
 * Flag: RENT_LEDGER_ENABLED (default false → 404 on all endpoints)
 *
 * Admin run (root only): POST /ui/admin/rent/run
 */

import { api } from "@/api/client";

// ─── Inline TypeScript types (mirrors app/models.py RNT models) ──────────────

export type RentPaymentMethod =
  | "cash"
  | "check"
  | "bank_transfer"
  | "card_external"
  | "other";

export type RentChargeStatus =
  | "open"
  | "partial"
  | "paid"
  | "overdue"
  | "voided";

export interface RentLedgerRowOut {
  sk: string;
  ts: number;
  type: string;
  rent_kind: string;
  amount_cents: number;
  state: string;
  reason: string;
  period?: string | null;
  lease_id?: string | null;
  property_id?: string | null;
  unit_id?: string | null;
  tenant_id?: string | null;
  currency?: string | null;
  signed_amount_cents?: number | null;
  status?: string | null;
  method?: string | null;
  reference?: string | null;
  paid_on?: number | null;
  ledger_date?: string | null;
}

export interface RentPaymentIn {
  amount_cents: number;
  method: RentPaymentMethod;
  paid_on?: number | null;
  reference?: string;
  period?: string | null;
  notes?: string;
}

export interface RentPaymentOut {
  ledger_sk: string;
  period: string;
  amount_cents: number;
  method: string;
  reference: string;
  paid_on?: number | null;
  charge_status?: string | null;
}

export interface RentChargeOut {
  pk: string;
  sk: string;
  entry_id: string;
  ts: number;
  type: "rent_charge";
  state: string;
  amount_cents: number;
  reason: string;
  ledger_date: string;
  lease_id: string;
  property_id: string;
  unit_id: string;
  tenant_id: string;
  period: string;
  rent_kind: "charge";
  currency: string;
  signed_amount_cents?: number | null;
}

export interface RentChargeSkipOut {
  skipped: boolean;
  reason: "already_charged";
  period: string;
}

export interface RentChargeListOut {
  lease_id: string;
  charges: RentLedgerRowOut[];
  as_of_ts: number;
}

export interface RentHistoryOut {
  rows: RentLedgerRowOut[];
  count: number;
  next_cursor?: string | null;
}

export interface RentVoidIn {
  reason?: string;
}

export interface RentVoidOut {
  ok: boolean;
  ledger_sk: string;
  state: string;
}

export interface RentAgingOut {
  current_cents: number;
  days_30_cents: number;
  days_60_cents: number;
  days_90_plus_cents: number;
  total_open_cents: number;
  open_item_count: number;
  source: string;
}

export interface RentPeriodSummaryOut {
  period: string;
  scope: string;
  charged_cents: number;
  collected_cents: number;
  outstanding_cents: number;
  overdue_cents: number;
  due_settled_cents_all_time: number;
  charge_count: number;
  payment_count: number;
  lease_count: number;
  aging?: RentAgingOut | null;
}

export interface RentPeriodsOut {
  periods: string[];
  count: number;
}

export interface RentRunTriggerIn {
  period?: string | null;
}

export interface RentRunResultOut {
  period: string;
  charged: number;
  skipped: number;
  lease_count: number;
}

// ─── RNT-002: Record payment + get charges ───────────────────────────────────

export const recordRentPayment = (leaseId: string, body: RentPaymentIn) =>
  api.post<RentPaymentOut>(`/ui/rent/leases/${leaseId}/payments`, body);

export const getRentCharges = (leaseId: string, params?: { as_of_ts?: number }) => {
  const p: Record<string, string> = {};
  if (params?.as_of_ts != null) p["as_of_ts"] = String(params.as_of_ts);
  return api.get<RentChargeListOut>(`/ui/rent/leases/${leaseId}/charges`, p);
};

// ─── RNT-003: History + void ─────────────────────────────────────────────────

export const getRentLedger = (
  leaseId: string,
  params?: { kind?: "charge" | "payment"; limit?: number; cursor?: string },
) => {
  const p: Record<string, string> = {};
  if (params?.kind) p["kind"] = params.kind;
  if (params?.limit != null) p["limit"] = String(params.limit);
  if (params?.cursor) p["cursor"] = params.cursor;
  return api.get<RentHistoryOut>(`/ui/rent/leases/${leaseId}/ledger`, p);
};

export const voidRentRow = (leaseId: string, ledgerSk: string, body: RentVoidIn) =>
  api.post<RentVoidOut>(
    `/ui/rent/leases/${encodeURIComponent(leaseId)}/ledger/${encodeURIComponent(ledgerSk)}/void`,
    body,
  );

// ─── RNT-004: Summary + periods ──────────────────────────────────────────────

export const getRentSummary = (params?: { period?: string; lease_id?: string }) => {
  const p: Record<string, string> = {};
  if (params?.period) p["period"] = params.period;
  if (params?.lease_id) p["lease_id"] = params.lease_id;
  return api.get<RentPeriodSummaryOut>("/ui/rent/summary", p);
};

export const getRentPeriods = (params?: { lease_id?: string; count?: number }) => {
  const p: Record<string, string> = {};
  if (params?.lease_id) p["lease_id"] = params.lease_id;
  if (params?.count != null) p["count"] = String(params.count);
  return api.get<RentPeriodsOut>("/ui/rent/periods", p);
};

// ─── RNT-005: Manual charge + owner run + admin run ─────────────────────────

export const chargeLeaseNow = (leaseId: string, body: RentRunTriggerIn) =>
  api.post<RentChargeOut | RentChargeSkipOut>(`/ui/rent/leases/${leaseId}/charge`, body);

export const runRentForOwner = (body: RentRunTriggerIn) =>
  api.post<RentRunResultOut>("/ui/rent/run", body);

export const adminRunRent = (body: RentRunTriggerIn) =>
  api.post<RentRunResultOut>("/ui/admin/rent/run", body);
