import { api } from "@/api/client";
import type {
  RevenueListOut,
  RevenueSplitPreviewOut,
  AdminRevenueListOut,
} from "@/api/types";

// ─── User revenue endpoints ─────────────────────────────────────

export const getEarnedRevenue = (params?: {
  source_type?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.source_type) q.source_type = params.source_type;
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<RevenueListOut>(
    "/ui/licenses/revenue/earned",
    Object.keys(q).length ? q : undefined,
  );
};

export const getPaidRevenue = (params?: {
  source_type?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.source_type) q.source_type = params.source_type;
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<RevenueListOut>(
    "/ui/licenses/revenue/paid",
    Object.keys(q).length ? q : undefined,
  );
};

export const getLicenseRevenue = (
  issuedLicenseId: string,
  params?: { limit?: number; cursor?: string },
) => {
  const q: Record<string, string> = {};
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<{ transactions: RevenueListOut["transactions"]; next_cursor?: string }>(
    `/ui/licenses/revenue/license/${issuedLicenseId}`,
    Object.keys(q).length ? q : undefined,
  );
};

export const calculateSplitPreview = (params: {
  amount: number;
  revenue_share_pct?: number;
  profit_share_pct?: number;
  fixed_cost_cents?: number;
}) => {
  const q: Record<string, string> = { amount: String(params.amount) };
  if (params.revenue_share_pct !== undefined)
    q.revenue_share_pct = String(params.revenue_share_pct);
  if (params.profit_share_pct !== undefined)
    q.profit_share_pct = String(params.profit_share_pct);
  if (params.fixed_cost_cents !== undefined)
    q.fixed_cost_cents = String(params.fixed_cost_cents);
  return api.get<RevenueSplitPreviewOut>(
    "/ui/licenses/revenue/calculate",
    q,
  );
};

// ─── Admin endpoints ────────────────────────────────────────────

export const getAdminPlatformRevenue = (params?: {
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<AdminRevenueListOut>(
    "/ui/admin/licenses/revenue",
    Object.keys(q).length ? q : undefined,
  );
};
