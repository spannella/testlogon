import { api } from "@/api/client";
import type { TierDetails, TierRequirements } from "@/api/types";

export const getMyTier = () => api.get<TierDetails>("/v1/kyc/tiers/me");

export const checkRequirements = (targetTier: number) =>
  api.get<TierRequirements>(`/v1/kyc/tiers/me/requirements/${targetTier}`);

export const evaluateTier = () => api.post<TierDetails>("/v1/kyc/tiers/me/evaluate");

export const adminGetUserTier = (userSub: string) =>
  api.get<TierDetails>(`/v1/kyc/tiers/admin/${userSub}`);

export const adminOverrideTier = (userSub: string, data: { tier: number; reason: string }) =>
  api.post<TierDetails>(`/v1/kyc/tiers/admin/${userSub}/override`, data);

export const adminListByTier = (tier: number) =>
  api.get<{ tier: number; users: Array<{ user_sub: string; kyc_tier: number; kyc_tier_updated_at: number | null; display_name: string | null }> }>(`/v1/kyc/tiers/admin/by-tier/${tier}`);
