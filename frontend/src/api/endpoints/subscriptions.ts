import { api } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type {
  SubscriptionPlan,
  SubscriptionOut,
  SubscriptionSummary,
  SubscriptionInvoice,
  PlanCreateReq,
  PlanUpdateReq,
  DiscountCodeCreateReq,
  DiscountCode,
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

// ─── Plan CRUD (Creator) ──────────────────────────────────────────

function subPatch<T>(path: string, body?: unknown) {
  return api<T>(path, {
    method: "PATCH",
    headers: { ...userIdHeader(), "Content-Type": "application/json" },
    body: body != null ? JSON.stringify(body) : undefined,
  });
}

export const createPlan = (creatorId: string, body: PlanCreateReq) =>
  subPost<SubscriptionPlan>(`/api/creators/${creatorId}/plans`, body);

export const updatePlan = (planId: string, body: PlanUpdateReq) =>
  subPatch<SubscriptionPlan>(`/api/plans/${planId}`, body);

export const archivePlan = (planId: string) =>
  subPost<SubscriptionPlan>(`/api/plans/${planId}/archive`, {});

// ─── Discount Codes ───────────────────────────────────────────────

export const createDiscount = (creatorId: string, body: DiscountCodeCreateReq) =>
  subPost<DiscountCode>(`/api/creators/${creatorId}/discounts`, body);

export const listDiscounts = (creatorId: string) =>
  subGet<DiscountCode[]>(`/api/creators/${creatorId}/discounts`);

export const disableDiscount = (creatorId: string, code: string) =>
  subPost<DiscountCode>(
    `/api/creators/${creatorId}/discounts/${encodeURIComponent(code)}/disable`,
    {},
  );

// ─── SUBX-41 — creator subscribers + MRR/analytics console (E4 endpoints) ──────
// Owner-scoped: the subscription server resolves the signed-in creator from the
// X-User-Id header; a creator only ever sees their own subscribers. These back the
// web /subscriptions/subscribers console (parity with the Android creator screen).

export interface CreatorSubscriberRow {
  subscription_id: string;
  subscriber_id: string;
  subscriber_name?: string | null;
  plan_id?: string | null;
  plan_name?: string | null;
  status: string;
  interval: string;
  price_cents: number;
  currency: string;
  since: number;
  current_period_end?: number | null;
  next_billing_date?: number | null;
  cancel_at_period_end: boolean;
  auto_renew: boolean;
  is_gift: boolean;
  is_trial: boolean;
}

export interface CreatorSubscriberList {
  creator_id: string;
  status_filter?: string | null;
  count: number;
  total: number;
  next_cursor?: string | null;
  subscribers: CreatorSubscriberRow[];
}

export interface SubscriptionTierBreakdown {
  plan_id?: string | null;
  plan_name?: string | null;
  level?: number | null;
  active_subscribers: number;
  trialing: number;
  past_due: number;
  total_subscribers: number;
  mrr_cents: number;
  gross_revenue_to_date_cents: number;
  refunded_to_date_cents: number;
  net_revenue_to_date_cents: number;
}

export interface CreatorSubscriptionAnalytics {
  creator_id: string;
  currency: string;
  active_subscribers: number;
  trialing: number;
  past_due: number;
  canceled_total: number;
  total_subscribers: number;
  mrr_cents: number;
  arpu_cents: number;
  past_due_mrr_cents: number;
  period_days: number;
  new_subs_30d: number;
  churned_30d: number;
  active_at_window_start: number;
  churn_rate: number;
  gross_revenue_to_date_cents: number;
  fee_to_date_cents: number;
  refunded_to_date_cents: number;
  net_revenue_to_date_cents: number;
  by_tier: SubscriptionTierBreakdown[];
}

export const listCreatorSubscribers = (
  creatorId: string,
  params?: { status?: string; plan_id?: string; cursor?: string },
) => {
  const qs: Record<string, string> = {};
  if (params?.status) qs.status = params.status;
  if (params?.plan_id) qs.plan_id = params.plan_id;
  if (params?.cursor) qs.cursor = params.cursor;
  return subGet<CreatorSubscriberList>(
    `/api/creators/${creatorId}/subscribers`,
    Object.keys(qs).length > 0 ? qs : undefined,
  );
};

export const getCreatorSubscriptionAnalytics = (creatorId: string) =>
  subGet<CreatorSubscriptionAnalytics>(`/api/creators/${creatorId}/subscription-analytics`);

export const removeCreatorSubscriber = (creatorId: string, subId: string, reason?: string) =>
  subPost<SubscriptionOut>(`/api/creators/${creatorId}/subscriptions/${subId}/remove`, { reason });

export const stopCreatorSubscriberRenewal = (creatorId: string, subId: string, reason?: string) =>
  subPost<SubscriptionOut>(`/api/creators/${creatorId}/subscriptions/${subId}/stop-renewal`, { reason });

export const reorderPlans = (creatorId: string, planIds: string[]) =>
  subPost<SubscriptionPlan[]>(`/api/creators/${creatorId}/plans/reorder`, { plan_ids: planIds });
