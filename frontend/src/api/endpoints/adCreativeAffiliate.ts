import { api } from "@/api/client";
import type {
  AdAffiliateClickResult,
  AdAffiliateDiscount,
  AdAffiliateDiscountList,
  AdAffiliateRedeemResult,
  AdAffiliateStats,
} from "@/api/types";

const BASE = "/ui/ads/affiliate";

export interface AdAffiliateAttachBody {
  campaign_id: string;
  affiliate_code?: string | null;
  promo_code?: string | null;
  promo_value_display?: string | null;
  click_through_url?: string | null;
}

export interface AdAffiliateUpdateBody {
  affiliate_code?: string | null;
  promo_code?: string | null;
  promo_value_display?: string | null;
  click_through_url?: string | null;
  clear_affiliate_code?: boolean;
  clear_promo_code?: boolean;
}

export interface AdAffiliateRedeemBody {
  creative_id: string;
  checkout_type?: string;
  item_price_cents: number;
  creator_user_id: string;
  order_id?: string | null;
}

export const attachAdAffiliateDiscount = (
  creativeId: string,
  body: AdAffiliateAttachBody,
): Promise<AdAffiliateDiscount> =>
  api.post<AdAffiliateDiscount>(`${BASE}/creatives/${creativeId}/discount`, body);

export const getAdAffiliateDiscount = (
  creativeId: string,
): Promise<AdAffiliateDiscount> =>
  api.get<AdAffiliateDiscount>(`${BASE}/creatives/${creativeId}/discount`);

export const listAdAffiliateDiscounts = (): Promise<AdAffiliateDiscountList> =>
  api.get<AdAffiliateDiscountList>(`${BASE}/discounts`);

export const updateAdAffiliateDiscount = (
  creativeId: string,
  body: AdAffiliateUpdateBody,
): Promise<AdAffiliateDiscount> =>
  api.patch<AdAffiliateDiscount>(`${BASE}/creatives/${creativeId}/discount`, body);

export const removeAdAffiliateDiscount = (
  creativeId: string,
): Promise<{ ok: boolean }> =>
  api.del<{ ok: boolean }>(`${BASE}/creatives/${creativeId}/discount`);

export const getAdAffiliateStats = (
  creativeId: string,
): Promise<AdAffiliateStats> =>
  api.get<AdAffiliateStats>(`${BASE}/creatives/${creativeId}/stats`);

export const previewAdAffiliateClick = (
  creativeId: string,
): Promise<AdAffiliateClickResult> =>
  api.get<AdAffiliateClickResult>(`${BASE}/click/${creativeId}/preview`);

export const redeemAdAffiliateDiscount = (
  body: AdAffiliateRedeemBody,
): Promise<AdAffiliateRedeemResult> =>
  api.post<AdAffiliateRedeemResult>(`${BASE}/redeem`, body);
