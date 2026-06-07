import { api } from "@/api/client";
import type {
  AdminAdAccount,
  AdminAdAccountDetail,
  AdminAdCampaign,
  AdminAdCreative,
  AdminAdKillSwitchState,
  AdminAdKillSwitchToggleIn,
  AdminAdModerationAction,
  AdminAdModerationEvent,
  AdminAdModerationQueue,
  AdminAdModerationResult,
  AdminAdPlatformMetrics,
  AdminAdRevenuePoint,
  AdminAdTopSpender,
} from "@/api/types";

const BASE = "/ui/admin/ad-platform";

// ── Cross-user listing ──────────────────────────────────────────────────────

export const listAdvertiserAccounts = (opts?: { status?: string; owner_sub?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.owner_sub) params["owner_sub"] = opts.owner_sub;
  return api.get<AdminAdAccount[]>(`${BASE}/accounts`, params);
};

export const getAdvertiserAccount = (accountId: string) =>
  api.get<AdminAdAccountDetail>(`${BASE}/accounts/${accountId}`);

export const listAdCampaigns = (opts?: { status?: string; account_id?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.account_id) params["account_id"] = opts.account_id;
  return api.get<AdminAdCampaign[]>(`${BASE}/campaigns`, params);
};

export const listAdCreatives = (opts?: {
  status?: string;
  account_id?: string;
  campaign_id?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.account_id) params["account_id"] = opts.account_id;
  if (opts?.campaign_id) params["campaign_id"] = opts.campaign_id;
  return api.get<AdminAdCreative[]>(`${BASE}/creatives`, params);
};

// ── Moderation ───────────────────────────────────────────────────────────────

export const getModerationQueue = () =>
  api.get<AdminAdModerationQueue>(`${BASE}/moderation/queue`);

export const getModerationHistory = (itemType: "account" | "creative", itemId: string) =>
  api.get<AdminAdModerationEvent[]>(`${BASE}/moderation/${itemType}/${itemId}/history`);

export const moderateAccount = (accountId: string, data: AdminAdModerationAction) =>
  api.post<AdminAdModerationResult>(`${BASE}/accounts/${accountId}/moderate`, data);

export const moderateCreative = (creativeId: string, data: AdminAdModerationAction) =>
  api.post<AdminAdModerationResult>(`${BASE}/creatives/${creativeId}/moderate`, data);

// ── Platform metrics ───────────────────────────────────────────────────────

export const getPlatformMetrics = () =>
  api.get<AdminAdPlatformMetrics>(`${BASE}/metrics`);

export const getRevenueSeries = () =>
  api.get<AdminAdRevenuePoint[]>(`${BASE}/metrics/revenue-series`);

export const getTopSpenders = (limit?: number) => {
  const params: Record<string, string> = {};
  if (limit) params["limit"] = String(limit);
  return api.get<AdminAdTopSpender[]>(`${BASE}/metrics/top-spenders`, params);
};

// ── Emergency controls: platform-wide ad serving kill switch ─────────────────
// GET is readable by ADMIN/ROOT; POST toggle is ROOT-only (enforced server-side).

export const getKillSwitchState = () =>
  api.get<AdminAdKillSwitchState>(`${BASE}/kill-switch`);

export const toggleKillSwitch = (data: AdminAdKillSwitchToggleIn) =>
  api.post<AdminAdKillSwitchState>(`${BASE}/kill-switch`, data);
