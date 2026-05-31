import { api } from "@/api/client";
import type {
  SubscriptionTierAnalytics,
  SubscriptionTierCreate,
  SubscriptionTierDeleteResult,
  SubscriptionTierOut,
  SubscriptionTierPreviewOut,
  SubscriptionTierReorderResult,
  SubscriptionTierUpdate,
} from "@/api/types";

const BASE = "/ui/admin/subscription-tiers";

export function createSubscriptionTier(body: SubscriptionTierCreate) {
  return api.post<SubscriptionTierOut>(BASE, body);
}

export function listSubscriptionTiers(includeArchived = false) {
  return api.get<SubscriptionTierOut[]>(
    BASE,
    includeArchived ? { include_archived: "true" } : undefined,
  );
}

export function getSubscriptionTier(tierId: string) {
  return api.get<SubscriptionTierOut>(`${BASE}/${tierId}`);
}

export function updateSubscriptionTier(tierId: string, body: SubscriptionTierUpdate) {
  return api.patch<SubscriptionTierOut>(`${BASE}/${tierId}`, body);
}

export function archiveSubscriptionTier(tierId: string) {
  return api.post<SubscriptionTierOut>(`${BASE}/${tierId}/archive`);
}

export function unarchiveSubscriptionTier(tierId: string) {
  return api.post<SubscriptionTierOut>(`${BASE}/${tierId}/unarchive`);
}

export function deleteSubscriptionTier(tierId: string) {
  return api.del<SubscriptionTierDeleteResult>(`${BASE}/${tierId}`);
}

export function reorderSubscriptionTiers(tierIds: string[]) {
  return api.put<SubscriptionTierReorderResult[]>(`${BASE}/reorder`, { tier_ids: tierIds });
}

export function getSubscriptionTierAnalytics(params?: { start_date?: string; end_date?: string }) {
  return api.get<SubscriptionTierAnalytics>(`${BASE}/analytics`, params as Record<string, string>);
}

export function previewSubscriptionTiers() {
  return api.get<SubscriptionTierPreviewOut>(`${BASE}/preview`);
}
