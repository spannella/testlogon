import { api } from "@/api/client";
import type {
  ABTestResult,
  ApplyRecommendationResult,
  BudgetRecommendation,
  OptimizationConfigResult,
  OptimizationConfigUpdate,
  OptimizationGenerateResult,
  OptimizationRecommendationList,
  SuggestedBid,
} from "@/api/types";

// ─── Ad Performance Optimization (ADS-017) ──────────────────────────────────

const BASE = "/ui/ads/optimization";

/** Run a deterministic optimization pass and persist recommendations. */
export const generateRecommendations = (
  campaignId: string,
  days?: number,
): Promise<OptimizationGenerateResult> =>
  api.post<OptimizationGenerateResult>(
    `${BASE}/campaigns/${campaignId}/generate`,
    undefined,
    days != null ? { days: String(days) } : undefined,
  );

/** List recommendation history for a campaign (newest first). */
export const listRecommendations = (
  campaignId: string,
  status?: string,
): Promise<OptimizationRecommendationList> =>
  api.get<OptimizationRecommendationList>(
    `${BASE}/campaigns/${campaignId}/recommendations`,
    status ? { status } : undefined,
  );

/** Apply a recommendation (mutates the underlying campaign/creative). */
export const applyRecommendation = (
  campaignId: string,
  recommendationId: string,
): Promise<ApplyRecommendationResult> =>
  api.post<ApplyRecommendationResult>(
    `${BASE}/campaigns/${campaignId}/recommendations/${recommendationId}/apply`,
  );

/** Dismiss a recommendation without applying it. */
export const dismissRecommendation = (
  campaignId: string,
  recommendationId: string,
): Promise<{ ok: boolean; status: string }> =>
  api.post<{ ok: boolean; status: string }>(
    `${BASE}/campaigns/${campaignId}/recommendations/${recommendationId}/dismiss`,
  );

/** Two-proportion Z-test between two creatives. */
export const getABTestResults = (
  campaignId: string,
  params: {
    creative_a_id: string;
    creative_b_id: string;
    confidence_level?: number;
  },
): Promise<ABTestResult> => {
  const qs: Record<string, string> = {
    creative_a_id: params.creative_a_id,
    creative_b_id: params.creative_b_id,
  };
  if (params.confidence_level != null)
    qs.confidence_level = String(params.confidence_level);
  return api.get<ABTestResult>(`${BASE}/campaigns/${campaignId}/ab-test`, qs);
};

/** Suggested bid range based on campaign targeting specificity. */
export const getSuggestedBid = (campaignId: string): Promise<SuggestedBid> =>
  api.get<SuggestedBid>(`${BASE}/campaigns/${campaignId}/suggested-bid`);

/** Recommended daily budget that scales with desired reach. */
export const getBudgetRecommendation = (
  campaignId: string,
  desiredDailyReach: number,
): Promise<BudgetRecommendation> =>
  api.get<BudgetRecommendation>(
    `${BASE}/campaigns/${campaignId}/budget-recommendation`,
    { desired_daily_reach: String(desiredDailyReach) },
  );

/** Update auto-optimize toggle + threshold configuration on a campaign. */
export const updateOptimizationConfig = (
  campaignId: string,
  data: OptimizationConfigUpdate,
): Promise<OptimizationConfigResult> =>
  api.patch<OptimizationConfigResult>(
    `${BASE}/campaigns/${campaignId}/optimization-config`,
    data,
  );
