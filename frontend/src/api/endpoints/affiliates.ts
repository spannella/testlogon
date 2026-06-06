import { api } from "@/api/client";

export interface AffiliateLinkOut {
  link_id: string;
  affiliate_user_id: string;
  product_owner_id: string;
  target_type: string;
  target_id: string;
  target_name: string;
  tracking_code: string;
  short_url: string;
  destination_url: string;
  commission_percent: number;
  status: string;
  click_count: number;
  unique_click_count: number;
  conversion_count: number;
  revenue_cents: number;
  commission_earned_cents: number;
  conversion_rate_pct: number;
  created_at: number;
  updated_at: number;
}

export interface AffiliateLinkCreateIn {
  target_type: string;
  target_id: string;
  commission_percent?: number;
  custom_code?: string;
}

export interface AffiliateLinkListOut {
  links: AffiliateLinkOut[];
}

export interface AffiliateLinkStatsOut {
  link_id: string;
  click_count: number;
  unique_click_count: number;
  conversion_count: number;
  revenue_cents: number;
  commission_earned_cents: number;
  conversion_rate_pct: number;
}

export const createAffiliateLink = (data: AffiliateLinkCreateIn) =>
  api.post<AffiliateLinkOut>("/ui/affiliates/links", data);

export const listAffiliateLinks = () =>
  api.get<AffiliateLinkListOut>("/ui/affiliates/links");

export const getAffiliateLink = (linkId: string) =>
  api.get<AffiliateLinkOut>(`/ui/affiliates/links/${linkId}`);

export const deleteAffiliateLink = (linkId: string) =>
  api.del<{ ok: boolean; link_id: string }>(`/ui/affiliates/links/${linkId}`);

export const getAffiliateLinkStats = (linkId: string) =>
  api.get<AffiliateLinkStatsOut>(`/ui/affiliates/links/${linkId}/stats`);

// --- Analytics (GAP-0198 / FIN-010): summary, time-series, earnings, top products ---

export interface AffiliateSummaryOut {
  total_links: number;
  active_links: number;
  total_clicks: number;
  unique_clicks: number;
  total_conversions: number;
  total_revenue_cents: number;
  total_commission_cents: number;
  overall_conversion_rate_pct: number;
}

export interface AffiliateClickBucket {
  bucket: string; // epoch-seconds string (day) or "YYYY-WWW" (week)
  clicks: number;
}

export interface AffiliateClickTimeSeriesOut {
  items: AffiliateClickBucket[];
  interval: string;
}

export interface AffiliateEarningsItem {
  link_id: string;
  target_name: string;
  target_type: string;
  commission_earned_cents: number;
  revenue_cents: number;
  conversions: number;
}

export interface AffiliateEarningsBreakdownOut {
  items: AffiliateEarningsItem[];
  total_commission_cents: number;
}

export interface AffiliateTopProductItem {
  link_id: string;
  target_name: string;
  target_id: string;
  click_count: number;
  conversion_count: number;
  commission_earned_cents: number;
}

export interface AffiliateTopProductsOut {
  items: AffiliateTopProductItem[];
}

export const getAffiliateSummary = () =>
  api.get<AffiliateSummaryOut>("/ui/affiliates/summary");

export const getLinkClickTimeSeries = (params?: {
  interval?: "day" | "week";
  from_ts?: number;
  to_ts?: number;
}) => {
  const p: Record<string, string> = {};
  if (params?.interval) p.interval = params.interval;
  if (params?.from_ts) p.from_ts = String(params.from_ts);
  if (params?.to_ts) p.to_ts = String(params.to_ts);
  return api.get<AffiliateClickTimeSeriesOut>("/ui/affiliates/timeseries", p);
};

export const getAffiliateEarnings = (params?: {
  from_ts?: number;
  to_ts?: number;
}) => {
  const p: Record<string, string> = {};
  if (params?.from_ts) p.from_ts = String(params.from_ts);
  if (params?.to_ts) p.to_ts = String(params.to_ts);
  return api.get<AffiliateEarningsBreakdownOut>("/ui/affiliates/earnings", p);
};

export const getTopProducts = (limit = 10) =>
  api.get<AffiliateTopProductsOut>("/ui/affiliates/top-products", {
    limit: String(limit),
  });
