import { api } from "@/api/client";
import type {
  AdRevenueBreakdown,
  AdvertiserTransparency,
  ContentAdOverride,
  ContentAdOverrideInput,
  RevenueShare,
} from "@/api/types";

const BASE = "/ui/ads/content-controls";

// ── Per-content ad overrides ───────────────────────────────────────────────

export function listContentAdOverrides() {
  return api.get<ContentAdOverride[]>(`${BASE}/overrides`);
}

export function getContentAdOverride(contentId: string) {
  return api.get<ContentAdOverride>(`${BASE}/overrides/${contentId}`);
}

export function upsertContentAdOverride(contentId: string, body: ContentAdOverrideInput) {
  return api.put<ContentAdOverride>(`${BASE}/overrides/${contentId}`, body);
}

export function deleteContentAdOverride(contentId: string) {
  return api.del<{ ok: boolean }>(`${BASE}/overrides/${contentId}`);
}

// ── Revenue share ──────────────────────────────────────────────────────────

export function getRevenueShare() {
  return api.get<RevenueShare>(`${BASE}/revenue-share`);
}

export function setRevenueShare(revenueShareBps: number) {
  return api.put<RevenueShare & { ok: boolean }>(`${BASE}/revenue-share`, {
    revenue_share_bps: revenueShareBps,
  });
}

// ── Transparency / ad-revenue breakdown ─────────────────────────────────────

export function getAdRevenueBreakdown(days = 30) {
  return api.get<AdRevenueBreakdown>(`${BASE}/revenue-breakdown`, {
    days: String(days),
  });
}

export function getAdvertiserTransparency(month?: string) {
  return api.get<AdvertiserTransparency[]>(
    `${BASE}/transparency`,
    month ? { month } : undefined,
  );
}
