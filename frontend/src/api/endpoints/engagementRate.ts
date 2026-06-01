import { api } from "@/api/client";
import type {
  EngagementRate,
  EngagementTimeSeries,
  EngagementPublic,
} from "@/api/types";

export const getEngagementRate = (periodDays = 30) =>
  api.get<EngagementRate>("/ui/analytics/engagement", {
    period_days: String(periodDays),
  });

export interface EngagementHistoryParams {
  from_date?: string;
  to_date?: string;
}

export const getEngagementHistory = (params?: EngagementHistoryParams) =>
  api.get<EngagementTimeSeries>(
    "/ui/analytics/engagement/history",
    params as Record<string, string>,
  );

export const setEngagementPublic = (visible: boolean) =>
  api.put<EngagementPublic>("/ui/analytics/engagement/public", { visible });

export const getPublicEngagement = (creatorId: string) =>
  api.get<EngagementPublic>(`/api/creators/${creatorId}/engagement`);
