import { api } from "@/api/client";
import type {
  RiskScoreOut,
  RiskFactorOut,
  RiskProfileOut,
  RiskDistributionOut,
  RiskOverrideIn,
} from "@/api/types";

// ─── User endpoints ──────────────────────────────────────────────

export function fetchOwnRiskScore(): Promise<{ score: RiskScoreOut | null }> {
  return api.get<{ score: RiskScoreOut | null }>("/ui/risk/score");
}

export function fetchOwnRiskFactors(): Promise<{ factors: RiskFactorOut[] }> {
  return api.get<{ factors: RiskFactorOut[] }>("/ui/risk/factors");
}

// ─── Admin endpoints ─────────────────────────────────────────────

export function fetchHighRiskUsers(params?: {
  threshold?: number;
  limit?: number;
}): Promise<{ items: RiskScoreOut[] }> {
  const q: Record<string, string> = {};
  if (params?.threshold != null) q.threshold = String(params.threshold);
  if (params?.limit != null) q.limit = String(params.limit);
  return api.get<{ items: RiskScoreOut[] }>("/ui/admin/risk/high-risk", q);
}

export function fetchUserRiskProfile(userId: string): Promise<RiskProfileOut> {
  return api.get<RiskProfileOut>(`/ui/admin/risk/users/${userId}/profile`);
}

export function overrideUserRiskScore(
  userId: string,
  body: RiskOverrideIn,
): Promise<{ ok: boolean } & RiskScoreOut> {
  return api.post(`/ui/admin/risk/users/${userId}/override`, body);
}

export function fetchUserRiskFactors(
  userId: string,
): Promise<{ factors: RiskFactorOut[] }> {
  return api.get<{ factors: RiskFactorOut[] }>(
    `/ui/admin/risk/users/${userId}/factors`,
  );
}

export function fetchRiskDistribution(): Promise<RiskDistributionOut> {
  return api.get<RiskDistributionOut>("/ui/admin/risk/distribution");
}

export function fetchUsersByTier(
  tier: string,
  limit?: number,
): Promise<{ tier: string; items: RiskScoreOut[]; total: number }> {
  const q: Record<string, string> = {};
  if (limit != null) q.limit = String(limit);
  return api.get(`/ui/admin/risk/tier/${tier}`, q);
}

export function rescoreCase(
  caseId: string,
): Promise<{ ok: boolean } & RiskScoreOut> {
  return api.post(`/ui/admin/risk/rescore/${caseId}`, {});
}

export function rescoreApprovedUsers(
  batchSize?: number,
): Promise<{ rescored_count: number; errors: number; tier_changes: number }> {
  const q: Record<string, string> = {};
  if (batchSize != null) q.batch_size = String(batchSize);
  return api.post("/ui/admin/risk/rescore-approved", {});
}
