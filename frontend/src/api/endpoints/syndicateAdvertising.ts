import { api } from "@/api/client";
import type {
  SyndicateCampaignAnalyticsOut,
  SyndicateCampaignCreateIn,
  SyndicateCampaignOut,
} from "@/api/types";

// -- Syndicate Advertising (SYND-006) --

export const listSyndicateCampaigns = (syndicateId: string, status?: string) =>
  api.get<SyndicateCampaignOut[]>(
    `/ui/syndicates/advertising/${syndicateId}/campaigns`,
    status ? { status } : undefined,
  );

export const getSyndicateCampaign = (syndicateId: string, campaignId: string) =>
  api.get<SyndicateCampaignOut>(
    `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}`,
  );

export const createSyndicateCampaign = (
  syndicateId: string,
  body: SyndicateCampaignCreateIn,
) =>
  api.post<SyndicateCampaignOut>(
    `/ui/syndicates/advertising/${syndicateId}/campaigns`,
    body,
  );

export const updateSyndicateCampaignStatus = (
  syndicateId: string,
  campaignId: string,
  status: "active" | "paused" | "cancelled",
) =>
  api.post<SyndicateCampaignOut>(
    `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/status`,
    { status },
  );

export const addSyndicateCampaignBudget = (
  syndicateId: string,
  campaignId: string,
  additionalCents: number,
) =>
  api.post<SyndicateCampaignOut>(
    `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/add-budget`,
    { additional_cents: additionalCents },
  );

export const getSyndicateCampaignAnalytics = (
  syndicateId: string,
  campaignId: string,
) =>
  api.get<SyndicateCampaignAnalyticsOut>(
    `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/analytics`,
  );
