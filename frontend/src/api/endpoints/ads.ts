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

import type { AdCreative } from "../types";
// ─── Advertiser Account & Campaign (ADS-001) ─────────────────────────────

import type { AdAccount, Campaign, AdBillingEntry, AdInvoice } from "../types";

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
  // FE-162 (<- BE-161): promote-entity descriptor. Additive + optional; a
  // backend that does not persist it ignores the extra keys.
  promote_kind?: string;
  promote_entity_id?: string;
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


// ─── Ad Creatives (ADS-002) ──────────────────────────────────────────────

/** Create a creative under a campaign */
export const createCreative = (campaignId: string, data: {
  format: string;
  title: string;
  headline?: string;
  body_text?: string;
  cta_text?: string;
  cta_url?: string;
  alt_text?: string;
  width?: number;
  height?: number;
  duration_seconds?: number;
  skip_after_seconds?: number;
  rotation_weight?: number;
  promo_code_id?: string;
  affiliate_link_id?: string;
}) =>
  api.post<AdCreative>(`/ui/ads/campaigns/${campaignId}/creatives`, data);

/** List creatives for a campaign */
export const listCreatives = (campaignId: string) =>
  api.get<AdCreative[]>(`/ui/ads/campaigns/${campaignId}/creatives`);

/** Get a single creative */
export const getCreative = (campaignId: string, creativeId: string) =>
  api.get<AdCreative>(`/ui/ads/campaigns/${campaignId}/creatives/${creativeId}`);

/** Update a creative */
export const updateCreative = (campaignId: string, creativeId: string, data: Partial<AdCreative>) =>
  api.patch<{ ok: boolean }>(`/ui/ads/campaigns/${campaignId}/creatives/${creativeId}`, data);

/** Delete a creative */
export const deleteCreative = (campaignId: string, creativeId: string) =>
  api.del<{ ok: boolean }>(`/ui/ads/campaigns/${campaignId}/creatives/${creativeId}`);

/** Upload an asset (image/video/thumbnail) for a creative */
export const uploadCreativeAsset = (campaignId: string, creativeId: string, file: File, assetType: string = "image") => {
  const form = new FormData();
  form.append("file", file);
  form.append("asset_type", assetType);
  return api.post<{ url: string }>(`/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/upload`, form);
};

/** Submit a creative for admin review */
export const submitCreativeForReview = (campaignId: string, creativeId: string) =>
  api.post<{ ok: boolean }>(`/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/submit`);

/** List pending creatives (admin) */
export const listPendingCreatives = () =>
  api.get<AdCreative[]>("/ui/admin/ads/creatives/pending");

/** Review a creative (admin) */
export const reviewCreative = (creativeId: string, data: { decision: string; notes?: string }) =>
  api.post<{ ok: boolean; status: string }>(`/ui/admin/ads/creatives/${creativeId}/review`, data);
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
// ─── Ad Serving (ADS-004) ──────────────────────────────────────────────────

import type {
  AdServeRequest,
  AdServeResponse,
  AdTrackRequest,
  AdTrackResponse,
  AdServingStats,
} from "../types";

/** Request an ad for the given surface and context */
export const serveAd = (data: AdServeRequest): Promise<AdServeResponse> =>
  api.post<AdServeResponse>("/ui/ads/serve", data);

/** Track an ad event (impression, click, skip, complete) */
export const trackAdEvent = (data: AdTrackRequest): Promise<AdTrackResponse> =>
  api.post<AdTrackResponse>("/ui/ads/track", data);

/** Get serving stats for a campaign (owner only) */
export const getServingStats = (campaignId: string): Promise<AdServingStats> =>
  api.get<AdServingStats>(`/ui/ads/stats/${campaignId}`);
// ─── Ad Feedback & Sponsored Posts (ADS-005) ───────────────────────────────

import type { AdFeedbackRequest, WhyThisAdResponse } from "../types";

/** Submit feedback on a sponsored post (hide, not_relevant, etc.) */
export const submitAdFeedback = (
  body: AdFeedbackRequest,
): Promise<{ ok: boolean }> =>
  api.post<{ ok: boolean }>("/ui/ads/feedback", body);

/** Get the reason why a sponsored ad is shown */
export const whyThisAd = (
  creativeId: string,
): Promise<WhyThisAdResponse> =>
  api.get<WhyThisAdResponse>(`/ui/ads/why/${creativeId}`);

// ─── Ad Billing (ADS-007) ────────────────────────────────────────────────

/**
 * Deposit funds into an ad account.
 *
 * Card/default path: omit pay_with/quote_token (unchanged behaviour).
 * Pay-with-crypto (FE-160 / BE-160): pass a locked FeeQuote pay_with +
 * quote_token to fund the budget from a crypto balance at the shown rate —
 * the same pay-any-coin contract as checkout (see api/endpoints/fees.ts).
 * Server returns 409 quote_expired (re-quote) / 402 insufficient_<coin>.
 */
export const depositAdFunds = (accountId: string, data: {
  amount_cents: number;
  payment_method_id?: string;
  pay_with?: string;
  quote_token?: string;
}) =>
  api.post<{ ok: boolean; entry_id: string; new_balance_cents: number }>(
    `/ui/ads/accounts/${accountId}/deposit`,
    data,
  );

/** Get billing history for an ad account */
export const getAdBillingHistory = (accountId: string, limit = 50) =>
  api.get<AdBillingEntry[]>(`/ui/ads/accounts/${accountId}/billing?limit=${limit}`);

/** Get spending for a specific campaign */
export const getCampaignSpending = (accountId: string, campaignId: string, limit = 100) =>
  api.get<AdBillingEntry[]>(
    `/ui/ads/accounts/${accountId}/billing/campaigns/${campaignId}?limit=${limit}`,
  );

/** Get monthly invoice */
export const getAdInvoice = (accountId: string, month: string) =>
  api.get<AdInvoice>(`/ui/ads/accounts/${accountId}/invoices/${month}`);
// ─── Ad Analytics (ADS-008) ─────────────────────────────────────────────────

import type {
  AdAnalyticsSummary,
  AdTimeSeriesPoint,
  AdBreakdownEntry,
  AdRoasReport,
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

/** ADV3-8: ROAS report (spend / conversions / attributed value / ROAS) from the
 * ad_billing ledger - the single source of truth reconciling with the KPI summary. */
export const getAdRoasReport = (
  accountId: string,
  params?: { campaign_id?: string; days?: number },
): Promise<AdRoasReport> => {
  const qp = new URLSearchParams({ account_id: accountId });
  if (params?.campaign_id) qp.set("campaign_id", params.campaign_id);
  if (params?.days) qp.set("days", String(params.days));
  return api.get<AdRoasReport>(`/ui/ads/roas?${qp}`);
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
