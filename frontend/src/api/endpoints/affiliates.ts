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
