import { api } from "@/api/client";

export interface LeaderboardItem {
  key: string;
  label?: string;
  calls_total?: number;
  cost_subtotal_micros?: number;
  request_units_total?: number;
}

export interface LeaderboardResponse {
  period_id: string;
  dimension: string;
  metric: string;
  top_n: number;
  scope: string;
  items: LeaderboardItem[];
  total_rows_scanned: number;
}

export const getApiUsageLeaderboard = (opts: {
  periodId?: string;
  dimension?: "consumers" | "endpoints";
  metric?: "calls_total" | "cost_subtotal_micros" | "request_units_total";
  topN?: number;
  userSubFilter?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts.periodId) params.period_id = opts.periodId;
  if (opts.dimension) params.dimension = opts.dimension;
  if (opts.metric) params.metric = opts.metric;
  if (opts.topN != null) params.top_n = String(opts.topN);
  if (opts.userSubFilter) params.user_sub_filter = opts.userSubFilter;
  return api.get<LeaderboardResponse>("/v1/admin/api-usage/leaderboard", params);
};

export const getUserUsageDetail = (userId: string, periodId?: string) => {
  const params: Record<string, string> = {};
  if (periodId) params.period_id = periodId;
  return api.get<Record<string, unknown>>(`/v1/admin/usage/user/${encodeURIComponent(userId)}`, params);
};

export const finalizeBillingPeriod = (body: { period_id: string; user_id?: string }) =>
  api.post<Record<string, unknown>>("/v1/admin/billing/finalize-period", body);

export const recomputeUsage = (body: {
  scope: "user" | "all";
  period_id?: string;
  user_id?: string;
  apply: boolean;
}) => api.post<Record<string, unknown>>("/v1/admin/usage/recompute", body);

export const generateInvoiceLines = (body: {
  user_id: string;
  period_id: string;
  snapshot_version: number;
  pricing_catalog_version?: string;
}) => api.post<Record<string, unknown>>("/v1/admin/billing/generate-invoice-lines", body);

export const createBillingAdjustment = (body: {
  user_id: string;
  period_id: string;
  snapshot_version: number;
  adjustment_type: "credit" | "debit";
  amount_cents: number;
  reason: string;
  reference_id?: string;
}) => api.post<Record<string, unknown>>("/v1/admin/billing/adjustments", body);
