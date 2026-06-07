import { api } from "@/api/client";
import type {
  PayoutBalance,
  PayoutCreateResp,
  PayoutActionResp,
  PayoutListResp,
  EarningsSummary,
  EarningsTransactionsResp,
  PayoutMethod,
  PayoutMethodListResp,
  PayoutMethodCreate,
  PayoutStats,
} from "@/api/types";

// ─── Payouts ────────────────────────────────────────────────────

export const getPayoutBalance = () =>
  api.get<PayoutBalance>("/ui/payouts/balance");

export const requestPayout = (body: {
  amount_cents: number;
  method?: string;
  method_id?: string;
  notes?: string;
}) =>
  api.post<PayoutCreateResp>("/ui/payouts/request", body);

export const cancelPayout = (payoutId: string) =>
  api.post<PayoutActionResp>(`/ui/payouts/${payoutId}/cancel`);

export const listPayouts = (params?: { limit?: number; cursor?: string }) => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<PayoutListResp>("/ui/payouts", p);
};

// ─── Earnings ───────────────────────────────────────────────────

export const getEarningsSummary = (params?: {
  from_ts?: number;
  to_ts?: number;
}) => {
  const p: Record<string, string> = {};
  if (params?.from_ts) p.from_ts = String(params.from_ts);
  if (params?.to_ts) p.to_ts = String(params.to_ts);
  return api.get<EarningsSummary>("/ui/earnings/summary", p);
};

export const getEarningsTransactions = (params?: {
  limit?: number;
  cursor?: string;
  from_ts?: number;
  to_ts?: number;
}) => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  if (params?.from_ts) p.from_ts = String(params.from_ts);
  if (params?.to_ts) p.to_ts = String(params.to_ts);
  return api.get<EarningsTransactionsResp>("/ui/earnings/transactions", p);
};

// ─── Payout Methods (GAP-0195 / FIN-009) ─────────────────────────

export const listPayoutMethods = () =>
  api.get<PayoutMethodListResp>("/ui/payouts/methods");

export const addPayoutMethod = (body: PayoutMethodCreate) =>
  api.post<PayoutMethod>("/ui/payouts/methods", body);

export const updatePayoutMethod = (methodId: string, nickname: string) =>
  api.put<PayoutMethod>(`/ui/payouts/methods/${methodId}`, { nickname });

export const deletePayoutMethod = (methodId: string) =>
  api.del<void>(`/ui/payouts/methods/${methodId}`);

export const setDefaultPayoutMethod = (methodId: string) =>
  api.post<PayoutMethod>(`/ui/payouts/methods/${methodId}/default`);

// ─── Admin Payout Queue (GAP-0196 / FIN-009) ─────────────────────

export const adminListPayouts = (params?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const p: Record<string, string> = {};
  if (params?.status) p.status = params.status;
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<PayoutListResp>("/v1/admin/payouts", p);
};

export const adminGetPayoutStats = () =>
  api.get<PayoutStats>("/v1/admin/payouts/stats");

export const adminApprovePayout = (payoutId: string) =>
  api.post<PayoutActionResp>(`/v1/admin/payouts/${payoutId}/approve`);

export const adminRejectPayout = (payoutId: string, reason: string) =>
  api.post<PayoutActionResp>(`/v1/admin/payouts/${payoutId}/reject`, { reason });

export const adminCompletePayout = (payoutId: string) =>
  api.post<PayoutActionResp>(`/v1/admin/payouts/${payoutId}/complete`);
