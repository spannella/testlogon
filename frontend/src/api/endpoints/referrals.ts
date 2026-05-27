import { api } from "@/api/client";
import type {
  ReferralCode,
  ReferralCodeCreateResp,
  ReferralDashboardStats,
  CommissionListResp,
  ReferralAttribution,
  ReferralItem,
} from "@/api/types";

export const createReferralCode = () =>
  api.post<ReferralCodeCreateResp>("/ui/referrals/code");

export const getReferralCodes = () =>
  api.get<ReferralCode[]>("/ui/referrals/codes");

export const deactivateReferralCode = (code: string) =>
  api.del<{ ok: boolean }>(`/ui/referrals/codes/${code}`);

export const getReferralDashboard = () =>
  api.get<ReferralDashboardStats>("/ui/referrals/dashboard");

export const getReferralCommissions = (params?: { limit?: number; cursor?: string }) => {
  const qp: Record<string, string> = {};
  if (params?.limit != null) qp.limit = String(params.limit);
  if (params?.cursor) qp.cursor = params.cursor;
  return api.get<CommissionListResp>("/ui/referrals/commissions", qp);
};

export const getReferralAttribution = () =>
  api.get<ReferralAttribution>("/ui/referrals/attribution");

export const getReferralsList = () =>
  api.get<ReferralItem[]>("/ui/referrals/referrals");
