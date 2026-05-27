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
} from "@/api/types";

export const getAnalyticsOverview = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsOverview>("/ui/analytics/overview", { params }).then((r) => r.data);

export const getAnalyticsRevenue = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsRevenue>("/ui/analytics/revenue", { params }).then((r) => r.data);

export const getAnalyticsViews = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsViews>("/ui/analytics/views", { params }).then((r) => r.data);

export const getAnalyticsSubscribers = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsSubscribers>("/ui/analytics/subscribers", { params }).then((r) => r.data);

export const getAnalyticsTopContent = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsTopContent>("/ui/analytics/top-content", { params }).then((r) => r.data);

export const getAnalyticsAudience = (params: AnalyticsDateRangeParams) =>
  api.get<AnalyticsAudience>("/ui/analytics/audience", { params }).then((r) => r.data);

export const refreshAnalytics = () =>
  api.post<AnalyticsRefresh>("/ui/analytics/refresh").then((r) => r.data);
