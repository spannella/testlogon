import { api } from "@/api/client";
import type {
  EarningsSummary,
  EarningsTransactionsResp,
  EarningsQuickStats,
} from "@/api/types";

export const getEarningsSummary = (params: {
  from_date?: string;
  to_date?: string;
  granularity?: string;
}) =>
  api.get<EarningsSummary>(
    "/ui/earnings/summary",
    params as Record<string, string>,
  );

export const getEarningsTransactions = (params: {
  from_date?: string;
  to_date?: string;
  limit?: string;
  cursor?: string;
}) =>
  api.get<EarningsTransactionsResp>(
    "/ui/earnings/transactions",
    params as Record<string, string>,
  );

export const getEarningsQuickStats = () =>
  api.get<EarningsQuickStats>("/ui/earnings/quick-stats");
