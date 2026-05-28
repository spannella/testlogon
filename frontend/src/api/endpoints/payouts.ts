import { api } from "@/api/client";
import type {
  PayoutBalance,
  PayoutCreateResp,
  PayoutActionResp,
  PayoutListResp,
  EarningsSummary,
  EarningsTransactionsResp,
} from "@/api/types";

// ─── Payouts ────────────────────────────────────────────────────

export const getPayoutBalance = () =>
  api.get<PayoutBalance>("/ui/payouts/balance");

export const requestPayout = (body: {
  amount_cents: number;
  method?: string;
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
