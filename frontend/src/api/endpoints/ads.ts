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


// ─── Advertiser Campaign Manager (ADS-001) ────────────────────────────────

import type { AdAccount, Campaign } from "../types";

/** Create a new advertiser account */
export const createAdAccount = (data: { company_name: string; billing_email: string }) =>
  api.post<AdAccount>("/ui/ads/accounts", data);

/** List advertiser accounts owned by the current user */
export const listMyAdAccounts = () =>
  api.get<AdAccount[]>("/ui/ads/accounts");

/** Get a single advertiser account by ID */
export const getAdAccount = (accountId: string) =>
  api.get<AdAccount>(`/ui/ads/accounts/${accountId}`);

/** Create a campaign under an advertiser account */
export const createCampaign = (accountId: string, data: {
  name: string;
  objective: string;
  budget_cents: number;
  budget_type: string;
  start_date?: number;
  end_date?: number;
}) =>
  api.post<Campaign>(`/ui/ads/accounts/${accountId}/campaigns`, data);

/** List campaigns for an advertiser account */
export const listCampaigns = (accountId: string) =>
  api.get<Campaign[]>(`/ui/ads/accounts/${accountId}/campaigns`);

/** Get a single campaign */
export const getCampaign = (accountId: string, campaignId: string) =>
  api.get<Campaign>(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}`);

/** Update a campaign */
export const updateCampaign = (accountId: string, campaignId: string, data: Partial<Campaign>) =>
  api.patch<{ ok: boolean }>(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}`, data);

/** Submit a campaign for admin review */
export const submitCampaignForReview = (accountId: string, campaignId: string) =>
  api.post(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}/submit`);
