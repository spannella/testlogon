import { api } from "@/api/client";
import type {
  BudgetPacing,
  CampaignScheduleOut,
  CampaignScheduleUpdate,
  ScheduleEligibility,
  ScheduleTemplatesResponse,
} from "@/api/types";

// ─── Ad Scheduling & Dayparting (ADS-016) ───────────────────────────────────

const BASE = "/ui/ads/scheduling";

/** List predefined dayparting schedule templates. */
export const getScheduleTemplates = (): Promise<ScheduleTemplatesResponse> =>
  api.get<ScheduleTemplatesResponse>(`${BASE}/templates`);

/** Get the current dayparting / flight schedule for a campaign. */
export const getCampaignSchedule = (
  campaignId: string,
): Promise<CampaignScheduleOut> =>
  api.get<CampaignScheduleOut>(`${BASE}/campaigns/${campaignId}/schedule`);

/** Update dayparting and/or flights and/or timezone on a campaign. */
export const updateCampaignSchedule = (
  campaignId: string,
  data: CampaignScheduleUpdate,
): Promise<CampaignScheduleOut> =>
  api.patch<CampaignScheduleOut>(
    `${BASE}/campaigns/${campaignId}/schedule`,
    data,
  );

/** Check whether the campaign is eligible to serve right now. */
export const getScheduleEligibility = (
  campaignId: string,
  now?: number,
): Promise<ScheduleEligibility> => {
  const qs = now != null ? `?now=${now}` : "";
  return api.get<ScheduleEligibility>(
    `${BASE}/campaigns/${campaignId}/schedule/eligibility${qs}`,
  );
};

/** Get dayparting-aware budget pacing for the campaign. */
export const getBudgetPacing = (
  campaignId: string,
  now?: number,
): Promise<BudgetPacing> => {
  const qs = now != null ? `?now=${now}` : "";
  return api.get<BudgetPacing>(
    `${BASE}/campaigns/${campaignId}/schedule/pacing${qs}`,
  );
};
