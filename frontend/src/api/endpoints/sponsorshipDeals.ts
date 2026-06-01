import { api } from "@/api/client";
import type {
  SponsorshipDeal,
  SponsorshipDealCreate,
  SponsorshipDealEvent,
} from "@/api/types";

const BASE = "/ui/ads/sponsorships";

export const createSponsorshipDeal = (data: SponsorshipDealCreate) =>
  api.post<SponsorshipDeal>(BASE, data);

export const listSponsorshipDeals = (params?: { status?: string; role?: "advertiser" | "creator" }) =>
  api.get<SponsorshipDeal[]>(BASE, params as Record<string, string> | undefined);

export const getSponsorshipDeal = (dealId: string) =>
  api.get<SponsorshipDeal>(`${BASE}/${dealId}`);

export const getSponsorshipDealHistory = (dealId: string) =>
  api.get<SponsorshipDealEvent[]>(`${BASE}/${dealId}/history`);

export const acceptSponsorshipDeal = (dealId: string) =>
  api.post<SponsorshipDeal>(`${BASE}/${dealId}/accept`);

export const rejectSponsorshipDeal = (dealId: string, reason = "") =>
  api.post<SponsorshipDeal>(`${BASE}/${dealId}/reject`, { reason });

export const counterSponsorshipDeal = (
  dealId: string,
  data: { compensation_cents?: number; note?: string },
) => api.post<SponsorshipDeal>(`${BASE}/${dealId}/counter`, data);

export const submitSponsorshipContent = (dealId: string, contentId: string) =>
  api.post<SponsorshipDeal>(`${BASE}/${dealId}/submit-content`, { content_id: contentId });

export const completeSponsorshipDeal = (dealId: string) =>
  api.post<SponsorshipDeal>(`${BASE}/${dealId}/complete`);

export const cancelSponsorshipDeal = (dealId: string, reason: string) =>
  api.post<SponsorshipDeal>(`${BASE}/${dealId}/cancel`, { reason });
