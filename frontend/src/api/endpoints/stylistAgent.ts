import { api } from "@/api/client";
import type {
  CreateDesignRuleInput,
  CreateIssueTicketResult,
  DesignRule,
  OverallDesignScore,
  PageDesignScore,
  StylistConfig,
  TriggerUIReviewResult,
  UIReview,
  UIReviewListResult,
  UpdateDesignRuleInput,
} from "@/api/types";

const BASE = "/ui/agents/stylist";

export const listUIReviews = (filters?: { page_url?: string; review_type?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (filters?.page_url) params.page_url = filters.page_url;
  if (filters?.review_type) params.review_type = filters.review_type;
  if (filters?.limit) params.limit = String(filters.limit);
  return api.get<UIReviewListResult>(`${BASE}/reviews`, params);
};

export const getUIReview = (reviewId: string) =>
  api.get<UIReview>(`${BASE}/reviews/${reviewId}`);

export const getPageScores = () => api.get<PageDesignScore[]>(`${BASE}/scores`);

export const getOverallScore = () => api.get<OverallDesignScore>(`${BASE}/scores/overall`);

export const createIssueTicket = (reviewId: string, issueId: string) =>
  api.post<CreateIssueTicketResult>(`${BASE}/reviews/${reviewId}/issues/${issueId}/ticket`, {});

export const listDesignRules = (category?: string) =>
  api.get<DesignRule[]>(`${BASE}/rules`, category ? { category } : undefined);

export const createDesignRule = (data: CreateDesignRuleInput) =>
  api.post<DesignRule>(`${BASE}/rules`, data);

export const updateDesignRule = (ruleId: string, data: UpdateDesignRuleInput) =>
  api.put<DesignRule>(`${BASE}/rules/${ruleId}`, data);

export const deleteDesignRule = (ruleId: string) =>
  api.del<{ ok: boolean; rule_id: string }>(`${BASE}/rules/${ruleId}`);

export const getStylistConfig = () => api.get<StylistConfig>(`${BASE}/config`);

export const updateStylistConfig = (config: Partial<StylistConfig>) =>
  api.put<StylistConfig>(`${BASE}/config`, config);

export const triggerUIReview = (
  pages: string[],
  reviewType: "full_page" | "responsive" | "accessibility" = "full_page",
) =>
  api.post<TriggerUIReviewResult>(`${BASE}/trigger-review`, {
    pages,
    review_type: reviewType,
  });
