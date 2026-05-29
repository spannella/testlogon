import { api } from "@/api/client";
import type { AlertsResp, AlertPreferences, MarkReadReq, ActivityFeedResp, TipsSummary } from "@/api/types";

export const getAlerts = (opts?: { limit?: number; cursor?: string; unread_only?: boolean }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.unread_only) params["unread_only"] = "true";
  return api.get<AlertsResp>("/ui/alerts", params);
};

export const searchAlerts = (q: string, limit = 50) =>
  api.get<AlertsResp>("/ui/alerts/search", { q, limit: String(limit) });

export const markRead = (body: MarkReadReq) =>
  api.post<{ ok: boolean; updated: number }>("/ui/alerts/mark_read", body);

export const getAlertTypes = () =>
  api.get<{ types: string[]; event_types: string[] }>("/ui/alerts/types");

// ─── Preferences ─────────────────────────────────────────────────

export const getEmailPrefs = () =>
  api.get<AlertPreferences>("/ui/alerts/email_prefs");

export const setEmailPrefs = (emailEventTypes: string[]) =>
  api.post<AlertPreferences>("/ui/alerts/email_prefs", { email_event_types: emailEventTypes });

export const getSmsPrefs = () =>
  api.get<AlertPreferences>("/ui/alerts/sms_prefs");

export const setSmsPrefs = (smsEventTypes: string[]) =>
  api.post<AlertPreferences>("/ui/alerts/sms_prefs", { sms_event_types: smsEventTypes });

export const getToastPrefs = () =>
  api.get<AlertPreferences>("/ui/alerts/toast_prefs");

export const setToastPrefs = (toastEventTypes: string[]) =>
  api.post<AlertPreferences>("/ui/alerts/toast_prefs", { toast_event_types: toastEventTypes });

export const getWebhookPrefs = () =>
  api.get<AlertPreferences>("/ui/alerts/webhook_prefs");

export const setWebhookPrefs = (webhookUrls: string[], webhookEventTypes: string[]) =>
  api.post<AlertPreferences>("/ui/alerts/webhook_prefs", {
    webhook_urls: webhookUrls,
    webhook_event_types: webhookEventTypes,
  });

// ─── Alert channel management ────────────────────────────────────

export const alertSmsBegin = (phone: string) =>
  api.post<{ challenge_id: string; sent_to: string }>("/ui/alerts/sms/begin", { phone });

export const alertSmsConfirm = (challengeId: string, code: string) =>
  api.post<AlertPreferences>("/ui/alerts/sms/confirm", { challenge_id: challengeId, code });

export const alertSmsRemove = (phone: string) =>
  api.post<AlertPreferences>("/ui/alerts/sms/remove", { phone });

export const alertEmailBegin = (email: string) =>
  api.post<{ challenge_id: string; sent_to: string }>("/ui/alerts/emails/begin", { email });

export const alertEmailConfirm = (challengeId: string, code: string) =>
  api.post<AlertPreferences>("/ui/alerts/emails/confirm", { challenge_id: challengeId, code });

export const alertEmailRemove = (email: string) =>
  api.post<AlertPreferences>("/ui/alerts/emails/remove", { email });

// ─── Unread count & mark-all-read ────────────────────────────────

export const getUnreadCount = () =>
  api.get<{ count: number; unread_count: number }>("/ui/alerts/unread-count");

export const markAllAlertRead = () =>
  api.post<{ ok: boolean; count: number; marked_count: number }>("/ui/alerts/mark-all-read", {});

// ─── Activity Feed (PLATFORM-012) ───────────────────────────────

export const getActivityFeed = (params?: { limit?: number; cursor?: string; category?: string }) => {
  const p: Record<string, string> = {};
  if (params?.limit) p["limit"] = String(params.limit);
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.category) p["category"] = params.category;
  return api.get<ActivityFeedResp>("/ui/alerts/activity", p);
};

export const getTipsSummary = (period: "7d" | "30d" | "all" = "30d") =>
  api.get<TipsSummary>("/ui/alerts/tips-summary", { period });

export const markGroupRead = (alertIds: string[]) =>
  api.post<{ ok: boolean; marked_count: number }>("/ui/alerts/mark-group-read", {
    alert_ids: alertIds,
  });

// ─── SSE stream URL ──────────────────────────────────────────────

export const alertStreamUrl = "/ui/alerts/stream";
