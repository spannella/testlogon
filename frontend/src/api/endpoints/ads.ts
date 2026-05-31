import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AdSlot {
  type: "pre_roll" | "mid_roll" | "overlay";
  timestamp_seconds: number;
  duration_seconds: number;
  creative_id: string;
  creative_url: string;
  creative_type: "video" | "image";
  skip_after_seconds: number;
  slot_index: number;
}

export interface AdPlacementResponse {
  ads_enabled: boolean;
  slots: AdSlot[];
  ad_free: boolean;
}

export interface AdImpressionRequest {
  slot_type: string;
  slot_index: number;
  creative_id: string;
  event_type: "impression" | "complete" | "skip";
}

export interface AdImpressionResponse {
  ok: boolean;
  event_id: string;
}

export interface AdConfigRequest {
  pre_roll: boolean;
  mid_roll_intervals_seconds: number[];
  overlay_enabled: boolean;
  skip_after_seconds: number;
  ads_free_for_subscribers: boolean;
}

export interface AdConfigResponse {
  ok: boolean;
  ad_config: {
    pre_roll: boolean;
    mid_roll_intervals_seconds: number[];
    overlay_enabled: boolean;
    skip_after_seconds: number;
  };
  ads_free_for_subscribers: boolean;
}

export interface AdRevenueResponse {
  video_id: string;
  ad_impression_count: number;
  ad_revenue_cents: number;
  estimated_cpm_cents: number;
}

// ─── API calls ──────────────────────────────────────────────────────────────

/** Get ad placement config for a video (viewer-facing) */
export const getAdConfig = (
  videoId: string,
): Promise<AdPlacementResponse> =>
  api.get<AdPlacementResponse>(`/ui/videos/${videoId}/ad-config`);

/** Record an ad impression event */
export const recordAdImpression = (
  videoId: string,
  body: AdImpressionRequest,
): Promise<AdImpressionResponse> =>
  api.post<AdImpressionResponse>(
    `/ui/videos/${videoId}/ad-impression`,
    body,
  );

/** Get ad revenue stats for a video (owner only) */
export const getAdStats = (
  videoId: string,
): Promise<AdRevenueResponse> =>
  api.get<AdRevenueResponse>(`/ui/videos/${videoId}/ad-stats`);

/** Configure ad placement for a video (owner only) */
export const setAdConfig = (
  videoId: string,
  body: AdConfigRequest,
): Promise<AdConfigResponse> =>
  api.patch<AdConfigResponse>(`/ui/videos/${videoId}/ad-config`, body);


// ─── Ad Analytics (ADS-008) ─────────────────────────────────────────────────

import type {
  AdAnalyticsSummary,
  AdTimeSeriesPoint,
  AdBreakdownEntry,
} from "../types";

/** Get analytics summary (KPIs with period comparison) */
export const getAnalyticsSummary = (
  accountId: string,
  params?: { campaign_id?: string; days?: number },
): Promise<AdAnalyticsSummary> => {
  const qp = new URLSearchParams({ account_id: accountId });
  if (params?.campaign_id) qp.set("campaign_id", params.campaign_id);
  if (params?.days) qp.set("days", String(params.days));
  return api.get<AdAnalyticsSummary>(`/ui/ads/analytics/summary?${qp}`);
};

/** Get time series data points for charts */
export const getAnalyticsTimeseries = (
  accountId: string,
  params?: { campaign_id?: string; days?: number; granularity?: string },
): Promise<AdTimeSeriesPoint[]> => {
  const qp = new URLSearchParams({ account_id: accountId });
  if (params?.campaign_id) qp.set("campaign_id", params.campaign_id);
  if (params?.days) qp.set("days", String(params.days));
  if (params?.granularity) qp.set("granularity", params.granularity);
  return api.get<AdTimeSeriesPoint[]>(`/ui/ads/analytics/timeseries?${qp}`);
};

/** Get breakdown by dimension (creative/surface/targeting) */
export const getAnalyticsBreakdown = (
  accountId: string,
  params?: { campaign_id?: string; dimension?: string; days?: number },
): Promise<AdBreakdownEntry[]> => {
  const qp = new URLSearchParams({ account_id: accountId });
  if (params?.campaign_id) qp.set("campaign_id", params.campaign_id);
  if (params?.dimension) qp.set("dimension", params.dimension);
  if (params?.days) qp.set("days", String(params.days));
  return api.get<AdBreakdownEntry[]>(`/ui/ads/analytics/breakdown?${qp}`);
};

/** Export analytics as CSV */
export const exportAnalyticsCsv = (
  accountId: string,
  params?: { campaign_id?: string; days?: number },
): string => {
  const qp = new URLSearchParams({ account_id: accountId });
  if (params?.campaign_id) qp.set("campaign_id", params.campaign_id);
  if (params?.days) qp.set("days", String(params.days));
  return `/ui/ads/analytics/export?${qp}`;
};
