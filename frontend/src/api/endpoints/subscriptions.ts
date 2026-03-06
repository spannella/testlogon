import { api } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type {
  SubscriptionPlan,
  SubscriptionOut,
  SubscriptionSummary,
  SubscriptionInvoice,
} from "@/api/types";

// ─── Auth helper ────────────────────────────────────────────────
// The subscription server authenticates via X-User-Id header (not Bearer token).

function userIdHeader(): Record<string, string> {
  const userId = useAuthStore.getState().userId;
  return userId ? { "X-User-Id": userId } : {};
}

function subGet<T>(path: string, params?: Record<string, string>) {
  return api<T>(path, { method: "GET", headers: userIdHeader(), params });
}

function subPost<T>(path: string, body?: unknown) {
  return api<T>(path, {
    method: "POST",
    headers: { ...userIdHeader(), "Content-Type": "application/json" },
    body: body != null ? JSON.stringify(body) : undefined,
  });
}

// ─── Plans ──────────────────────────────────────────────────────

// Public endpoint — no X-User-Id required
export const listPlans = (creatorId: string) =>
  api.get<SubscriptionPlan[]>(`/api/creators/${creatorId}/plans`);

// ─── Subscribe ──────────────────────────────────────────────────

export const subscribe = (
  planId: string,
  body?: { interval?: string; discount_code?: string; trial_days?: number },
) => subPost<SubscriptionOut>(`/api/plans/${planId}/subscribe`, body ?? {});

// ─── My Subscriptions ───────────────────────────────────────────

export const listSubscriptions = (params?: { include_summary?: boolean }) => {
  const qs: Record<string, string> = {};
  if (params?.include_summary) qs.include_summary = "true";
  return subGet<SubscriptionOut[]>(
    "/api/subscriptions",
    Object.keys(qs).length > 0 ? qs : undefined,
  );
};

export const getSubscriptionSummary = (subId: string) =>
  subGet<SubscriptionSummary>(`/api/subscriptions/${subId}/summary`);

export const listInvoices = (subId: string) =>
  subGet<SubscriptionInvoice[]>(`/api/subscriptions/${subId}/invoices`);

// ─── Actions ────────────────────────────────────────────────────

export const cancelSubscription = (
  subId: string,
  body: { cancel_at_period_end?: boolean; reason?: string },
) => subPost<SubscriptionOut>(`/api/subscriptions/${subId}/cancel`, body);

export const resumeSubscription = (subId: string, reason?: string) =>
  subPost<SubscriptionOut>(`/api/subscriptions/${subId}/resume`, { reason });

export const changePlan = (
  subId: string,
  body: { plan_id: string; interval?: string; effective?: string; proration_policy?: string },
) => subPost<SubscriptionOut>(`/api/subscriptions/${subId}/change-plan`, body);

export const updateRenewal = (
  subId: string,
  body: { auto_renew: boolean; effective?: string; renewal_policy?: string; reason?: string },
) => subPost<SubscriptionOut>(`/api/subscriptions/${subId}/renewal`, body);
