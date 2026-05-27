import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export interface ScheduledActionOut {
  action_id: string;
  action_type: string;
  status: string;
  scheduled_at: number;
  created_at: number;
  updated_at?: number | null;
  completed_at?: number | null;
  title: string;
  description: string;
  payload: Record<string, unknown>;
  error?: string | null;
  retry_count: number;
  max_retries: number;
  notify_before_seconds: number;
  reminder_sent: boolean;
}

export interface ScheduledActionListOut {
  actions: ScheduledActionOut[];
  cursor: string | null;
}

export interface ScheduledCalendarOut {
  actions: ScheduledActionOut[];
  total: number;
}

export interface CreateActionReq {
  action_type: string;
  scheduled_at: number;
  title?: string;
  description?: string;
  payload?: Record<string, unknown>;
  notify_before_seconds?: number;
}

export interface UpdateActionReq {
  scheduled_at?: number;
  title?: string;
  description?: string;
  payload?: Record<string, unknown>;
  notify_before_seconds?: number;
}

export interface SchedulePostReq {
  text: string;
  image_urls?: string[];
  lock_price_cents?: number;
  visibility?: string;
  scheduled_at: number;
}

export interface CatalogSaleReq {
  sale_price_cents: number;
  sale_starts_at: number;
  sale_ends_at: number;
  sale_label?: string;
}

export interface CatalogSaleOut {
  start_action_id: string;
  end_action_id: string;
  sale_starts_at: number;
  sale_ends_at: number;
}

// ─── API Functions ──────────────────────────────────────────────

export const createScheduledAction = (body: CreateActionReq) =>
  api.post<ScheduledActionOut>("/ui/scheduler/actions", body);

export const listScheduledActions = (params?: { types?: string; status?: string }) =>
  api.get<ScheduledActionListOut>("/ui/scheduler/actions", params as Record<string, string>);

export const getScheduledAction = (actionId: string) =>
  api.get<ScheduledActionOut>(`/ui/scheduler/actions/${actionId}`);

export const updateScheduledAction = (actionId: string, body: UpdateActionReq) =>
  api.patch<ScheduledActionOut>(`/ui/scheduler/actions/${actionId}`, body);

export const deleteScheduledAction = (actionId: string) =>
  api.del<{ ok: boolean; action_id: string; status: string }>(
    `/ui/scheduler/actions/${actionId}`,
  );

export const getSchedulerCalendar = (params: {
  from_date: number;
  to_date: number;
  types?: string;
}) =>
  api.get<ScheduledCalendarOut>("/ui/scheduler/calendar", params as unknown as Record<string, string>);

export const schedulePost = (body: SchedulePostReq) =>
  api.post<ScheduledActionOut>("/ui/feed/posts/schedule", body);

export const scheduleCatalogSale = (productId: string, body: CatalogSaleReq) =>
  api.post<CatalogSaleOut>(`/ui/catalog/products/${productId}/sale`, body);
