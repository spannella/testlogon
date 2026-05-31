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

// ─── Ad Targeting (ADS-003) ────────────────────────────────────────────────

import type {
  AdTargeting,
  AudienceEstimate,
  CreatorAdSettings,
  AdBlock,
} from "../types";

// Targeting

export const createTargeting = (
  campaignId: string,
  body: Partial<AdTargeting>,
): Promise<AdTargeting> =>
  api.post<AdTargeting>(`/ui/ads/campaigns/${campaignId}/targeting`, body);

export const listTargeting = (
  campaignId: string,
): Promise<AdTargeting[]> =>
  api.get<AdTargeting[]>(`/ui/ads/campaigns/${campaignId}/targeting`);

export const getTargeting = (
  campaignId: string,
  targetSetId: string,
): Promise<AdTargeting> =>
  api.get<AdTargeting>(
    `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`,
  );

export const updateTargeting = (
  campaignId: string,
  targetSetId: string,
  body: Partial<AdTargeting>,
): Promise<AdTargeting> =>
  api.put<AdTargeting>(
    `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`,
    body,
  );

export const deleteTargeting = (
  campaignId: string,
  targetSetId: string,
): Promise<{ ok: boolean }> =>
  api.del<{ ok: boolean }>(
    `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`,
  );

export const estimateAudience = (
  campaignId: string,
  body: Partial<AdTargeting>,
): Promise<AudienceEstimate> =>
  api.post<AudienceEstimate>(
    `/ui/ads/campaigns/${campaignId}/targeting/estimate`,
    body,
  );

// Creator Ad Settings

export const getCreatorAdSettings = (): Promise<CreatorAdSettings> =>
  api.get<CreatorAdSettings>("/ui/ads/creator/ad-settings");

export const updateCreatorAdSettings = (
  body: Partial<CreatorAdSettings>,
): Promise<{ ok: boolean }> =>
  api.patch<{ ok: boolean }>("/ui/ads/creator/ad-settings", body);

export const blockAdvertiser = (
  body: { account_id: string; reason?: string },
): Promise<{ ok: boolean }> =>
  api.post<{ ok: boolean }>("/ui/ads/creator/ad-blocks", body);

export const unblockAdvertiser = (
  accountId: string,
): Promise<{ ok: boolean }> =>
  api.del<{ ok: boolean }>(`/ui/ads/creator/ad-blocks/${accountId}`);

export const listBlockedAdvertisers = (): Promise<AdBlock[]> =>
  api.get<AdBlock[]>("/ui/ads/creator/ad-blocks");
