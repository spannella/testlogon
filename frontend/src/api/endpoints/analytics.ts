import { api } from "@/api/client";
import type {
  AnalyticsOverview,
  AnalyticsRevenue,
  AnalyticsViews,
  AnalyticsSubscribers,
  AnalyticsTopContent,
  AnalyticsAudience,
  AnalyticsRefresh,
  AnalyticsDateRangeParams,
  ContentAnalytics,
} from "@/api/types";

export const getAnalyticsOverview = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsOverview>("/ui/analytics/overview", params as Record<string, string>);

export const getAnalyticsRevenue = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsRevenue>("/ui/analytics/revenue", params as Record<string, string>);

export const getAnalyticsViews = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsViews>("/ui/analytics/views", params as Record<string, string>);

export const getAnalyticsSubscribers = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsSubscribers>("/ui/analytics/subscribers", params as Record<string, string>);

export const getAnalyticsTopContent = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsTopContent>("/ui/analytics/top-content", params as Record<string, string>);

export const getAnalyticsAudience = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsAudience>("/ui/analytics/audience", params as Record<string, string>);

export const refreshAnalytics = () =>
  api.post<AnalyticsRefresh>("/ui/analytics/refresh");

export interface ContentDetailParams {
  from_date?: string;
  to_date?: string;
  granularity?: string;
}

export const getAnalyticsContentDetail = (contentId: string, params?: ContentDetailParams) =>
  api.get<ContentAnalytics>(`/ui/analytics/content/${contentId}`, params as Record<string, string>);
