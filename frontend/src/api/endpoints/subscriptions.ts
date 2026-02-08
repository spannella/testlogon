import { api } from "@/api/client";
import type {
  SubscriptionPlan,
  SubscriptionOut,
  SubscriptionSummary,
  SubscriptionInvoice,
} from "@/api/types";

// ─── Plans ──────────────────────────────────────────────────────

export const listPlans = (creatorId: string) =>
  api.get<SubscriptionPlan[]>(`/api/creators/${creatorId}/plans`);

// ─── Subscribe ──────────────────────────────────────────────────

export const subscribe = (
  planId: string,
  body?: { interval?: string; discount_code?: string; trial_days?: number },
) => api.post<SubscriptionOut>(`/api/plans/${planId}/subscribe`, body ?? {});

// ─── My Subscriptions ───────────────────────────────────────────

export const listSubscriptions = (params?: { include_summary?: boolean }) => {
  const qs: Record<string, string> = {};
  if (params?.include_summary) qs.include_summary = "true";
  return api.get<SubscriptionOut[]>(
    "/api/subscriptions",
    Object.keys(qs).length > 0 ? qs : undefined,
  );
};

export const getSubscriptionSummary = (subId: string) =>
  api.get<SubscriptionSummary>(`/api/subscriptions/${subId}/summary`);

export const listInvoices = (subId: string) =>
  api.get<SubscriptionInvoice[]>(`/api/subscriptions/${subId}/invoices`);

// ─── Actions ────────────────────────────────────────────────────

export const cancelSubscription = (
  subId: string,
  body: { cancel_at_period_end?: boolean; reason?: string },
) => api.post<SubscriptionOut>(`/api/subscriptions/${subId}/cancel`, body);

export const resumeSubscription = (subId: string, reason?: string) =>
  api.post<SubscriptionOut>(`/api/subscriptions/${subId}/resume`, { reason });

export const changePlan = (
  subId: string,
  body: { plan_id: string; interval?: string; effective?: string; proration_policy?: string },
) => api.post<SubscriptionOut>(`/api/subscriptions/${subId}/change-plan`, body);

export const updateRenewal = (
  subId: string,
  body: { auto_renew: boolean; effective?: string; renewal_policy?: string; reason?: string },
) => api.post<SubscriptionOut>(`/api/subscriptions/${subId}/renewal`, body);
