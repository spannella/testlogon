import { api } from "@/api/client";
import type {
  ComputeBillingTickIn,
  ComputeBillingTickOut,
  SpendingSummaryOut,
  BillingLedgerOut,
  ResourceBreakdownOut,
  BudgetOut,
  UpdateBudgetIn,
} from "@/api/types";

const BASE = "/ui/remote/billing";

export const getSpending = (month?: string) =>
  api.get<SpendingSummaryOut>(`${BASE}/spending`, month ? { month } : undefined);

export const getResources = (month?: string) =>
  api.get<ResourceBreakdownOut>(`${BASE}/resources`, month ? { month } : undefined);

export const getResourceSpending = (resourceId: string, month?: string) =>
  api.get<ResourceBreakdownOut>(`${BASE}/resources/${resourceId}`, month ? { month } : undefined);

export const getHistory = (params?: {
  resource_id?: string;
  limit?: number;
  cursor?: string;
}) => {
  const query: Record<string, string> = {};
  if (params?.resource_id) query.resource_id = params.resource_id;
  if (params?.limit !== undefined) query.limit = String(params.limit);
  if (params?.cursor) query.cursor = params.cursor;
  return api.get<BillingLedgerOut>(`${BASE}/history`, Object.keys(query).length ? query : undefined);
};

export const getBudget = () => api.get<BudgetOut>(`${BASE}/budget`);

export const setBudget = (body: UpdateBudgetIn) =>
  api.post<BudgetOut>(`${BASE}/budget`, body);

export const recordTick = (body: ComputeBillingTickIn) =>
  api.post<ComputeBillingTickOut>(`${BASE}/tick`, body);
