import { api } from "@/api/client";
import type {
  ContentCalendarEntry,
  ContentEngagementStats,
  CreateMarketingContentIn,
  MarketingConfig,
  MarketingContent,
  MarketingContentList,
  MarketingEngagementSummary,
  MarketingGenerateResult,
  UpdateMarketingConfigIn,
  UpdateMarketingContentIn,
} from "@/api/types";

const BASE = "/ui/agents/marketing";

export const listContent = (filters?: {
  type?: string;
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (filters?.type) params.type = filters.type;
  if (filters?.status) params.status = filters.status;
  if (filters?.limit != null) params.limit = String(filters.limit);
  if (filters?.cursor) params.cursor = filters.cursor;
  return api.get<MarketingContentList>(`${BASE}/content`, params);
};

export const createContent = (data: CreateMarketingContentIn) =>
  api.post<MarketingContent>(`${BASE}/content`, data);

export const getContent = (contentId: string) =>
  api.get<MarketingContent>(`${BASE}/content/${contentId}`);

export const updateContent = (contentId: string, data: UpdateMarketingContentIn) =>
  api.put<MarketingContent>(`${BASE}/content/${contentId}`, data);

export const approveContent = (contentId: string) =>
  api.post<MarketingContent>(`${BASE}/content/${contentId}/approve`);

export const scheduleContent = (contentId: string, publishAt: number) =>
  api.post<MarketingContent>(`${BASE}/content/${contentId}/schedule`, {
    publish_at: publishAt,
  });

export const publishContent = (contentId: string) =>
  api.post<MarketingContent>(`${BASE}/content/${contentId}/publish`);

export const archiveContent = (contentId: string) =>
  api.post<MarketingContent>(`${BASE}/content/${contentId}/archive`);

export const deleteContent = (contentId: string) =>
  api.del<{ ok: boolean; content_id: string; deleted: boolean }>(
    `${BASE}/content/${contentId}`,
  );

export const getCalendar = (month: string) =>
  api.get<ContentCalendarEntry[]>(`${BASE}/calendar`, { month });

export const getContentEngagement = (contentId: string, days = 30) =>
  api.get<ContentEngagementStats>(`${BASE}/content/${contentId}/engagement`, {
    days: String(days),
  });

export const getEngagementSummary = (days = 30) =>
  api.get<MarketingEngagementSummary>(`${BASE}/engagement/summary`, {
    days: String(days),
  });

export const getMarketingConfig = () =>
  api.get<MarketingConfig>(`${BASE}/config`);

export const updateMarketingConfig = (config: UpdateMarketingConfigIn) =>
  api.put<MarketingConfig>(`${BASE}/config`, config);

export const generateContent = (
  featureTicketIds: string[],
  contentTypes: string[] = ["blog_post", "changelog"],
) =>
  api.post<MarketingGenerateResult>(`${BASE}/generate`, {
    feature_ticket_ids: featureTicketIds,
    content_types: contentTypes,
  });
