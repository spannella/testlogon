import { api } from "@/api/client";
import type {
  CreateFeatureIdeaIn,
  FeatureIdea,
  FeatureIdeaList,
  PmAgentConfig,
  PmReviewScreenshot,
  PmReviewSessionList,
  PmTriggerReviewResult,
  PreferenceSummaryList,
  UpdatePmConfigIn,
} from "@/api/types";

const BASE = "/ui/agents/pm";

export const createFeatureIdea = (body: CreateFeatureIdeaIn) =>
  api.post<FeatureIdea>(`${BASE}/ideas`, body);

export const listFeatureIdeas = (status?: string, cursor?: string) => {
  const params: Record<string, string> = {};
  if (status) params.status = status;
  if (cursor) params.cursor = cursor;
  return api.get<FeatureIdeaList>(`${BASE}/ideas`, params);
};

export const getFeatureIdea = (ideaId: string) =>
  api.get<FeatureIdea>(`${BASE}/ideas/${ideaId}`);

export const approveIdea = (ideaId: string) =>
  api.post<FeatureIdea>(`${BASE}/ideas/${ideaId}/approve`, {});

export const rejectIdea = (ideaId: string, reason: string) =>
  api.post<FeatureIdea>(`${BASE}/ideas/${ideaId}/reject`, { reason });

export const archiveIdea = (ideaId: string) =>
  api.post<FeatureIdea>(`${BASE}/ideas/${ideaId}/archive`, {});

export const getPreferenceSummary = () =>
  api.get<PreferenceSummaryList>(`${BASE}/preferences`);

export const listReviewSessions = () =>
  api.get<PmReviewSessionList>(`${BASE}/reviews`);

export const getReviewScreenshots = (reviewId: string) =>
  api.get<{ screenshots: PmReviewScreenshot[] }>(
    `${BASE}/reviews/${reviewId}/screenshots`,
  );

export const getPmConfig = () => api.get<PmAgentConfig>(`${BASE}/config`);

export const updatePmConfig = (config: UpdatePmConfigIn) =>
  api.put<PmAgentConfig>(`${BASE}/config`, config);

export const triggerReview = (agentId?: string, count?: number) =>
  api.post<PmTriggerReviewResult>(`${BASE}/trigger-review`, {
    agent_id: agentId ?? "pm-agent",
    count: count ?? 3,
  });
