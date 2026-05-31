import { api } from "@/api/client";
import type {
  DashboardBreakdown,
  DashboardTimeseries,
  EmailDashboardStats,
  MessagingDeliveryList,
  MessagingSuppressionList,
  NotificationTemplate,
  NotificationTemplatePreview,
  NotificationTemplateTestSendResult,
  NotificationTemplateUpdate,
  SmsDashboardStats,
} from "@/api/types";

// ── Email ──────────────────────────────────────────────────────────────
export const getEmailDashboardStats = (days = 7) =>
  api.get<EmailDashboardStats>("/ui/admin/email/dashboard/stats", { days: String(days) });

export const getEmailTimeseries = (days = 7) =>
  api.get<DashboardTimeseries>("/ui/admin/email/dashboard/timeseries", { days: String(days) });

export const getEmailBounceDomains = (days = 7, limit = 10) =>
  api.get<DashboardBreakdown>("/ui/admin/email/dashboard/bounce-domains", {
    days: String(days),
    limit: String(limit),
  });

export const getEmailDeliveries = (limit = 50, cursor?: string, status?: string) => {
  const params: Record<string, string> = { limit: String(limit) };
  if (cursor) params["cursor"] = cursor;
  if (status) params["status"] = status;
  return api.get<MessagingDeliveryList>("/ui/admin/email/deliveries", params);
};

export const getEmailBounces = (limit = 50, cursor?: string) => {
  const params: Record<string, string> = { limit: String(limit) };
  if (cursor) params["cursor"] = cursor;
  return api.get<MessagingDeliveryList>("/ui/admin/email/bounces", params);
};

export const getEmailComplaints = (limit = 50, cursor?: string) => {
  const params: Record<string, string> = { limit: String(limit) };
  if (cursor) params["cursor"] = cursor;
  return api.get<MessagingDeliveryList>("/ui/admin/email/complaints", params);
};

export const getEmailSuppressions = (limit = 200) =>
  api.get<MessagingSuppressionList>("/ui/admin/email/suppressed", { limit: String(limit) });

export const addEmailSuppression = (address: string, reason: string) =>
  api.post<{ ok: boolean }>("/ui/admin/email/suppressed", { address, reason });

export const removeEmailSuppression = (email: string) =>
  api.del<{ ok: boolean }>(`/ui/admin/email/suppressed/${encodeURIComponent(email)}`);

// ── SMS ────────────────────────────────────────────────────────────────
export const getSmsDashboardStats = (days = 7) =>
  api.get<SmsDashboardStats>("/ui/admin/sms/dashboard/stats", { days: String(days) });

export const getSmsTimeseries = (days = 7) =>
  api.get<DashboardTimeseries>("/ui/admin/sms/dashboard/timeseries", { days: String(days) });

export const getSmsFailureTypes = (days = 7, limit = 10) =>
  api.get<DashboardBreakdown>("/ui/admin/sms/dashboard/failure-types", {
    days: String(days),
    limit: String(limit),
  });

export const getSmsDeliveries = (limit = 50, cursor?: string) => {
  const params: Record<string, string> = { limit: String(limit) };
  if (cursor) params["cursor"] = cursor;
  return api.get<MessagingDeliveryList>("/ui/admin/sms/deliveries", params);
};

export const getSmsFailures = (limit = 50, cursor?: string) => {
  const params: Record<string, string> = { limit: String(limit) };
  if (cursor) params["cursor"] = cursor;
  return api.get<MessagingDeliveryList>("/ui/admin/sms/failures", params);
};

export const getSmsSuppressions = (limit = 200) =>
  api.get<MessagingSuppressionList>("/ui/admin/sms/suppressed", { limit: String(limit) });

export const addSmsSuppression = (address: string, reason: string) =>
  api.post<{ ok: boolean }>("/ui/admin/sms/suppressed", { address, reason });

export const removeSmsSuppression = (phone: string) =>
  api.del<{ ok: boolean }>(`/ui/admin/sms/suppressed/${encodeURIComponent(phone)}`);

// ── Templates ──────────────────────────────────────────────────────────
export const listNotificationTemplates = (channel?: string) =>
  api.get<NotificationTemplate[]>(
    "/ui/admin/notifications/templates",
    channel ? { channel } : undefined,
  );

export const getNotificationTemplate = (id: string) =>
  api.get<NotificationTemplate>(`/ui/admin/notifications/templates/${encodeURIComponent(id)}`);

export const updateNotificationTemplate = (id: string, data: NotificationTemplateUpdate) =>
  api.patch<NotificationTemplate>(
    `/ui/admin/notifications/templates/${encodeURIComponent(id)}`,
    data,
  );

export const previewNotificationTemplate = (
  id: string,
  sample_vars: Record<string, string>,
) =>
  api.post<NotificationTemplatePreview>(
    `/ui/admin/notifications/templates/${encodeURIComponent(id)}/preview`,
    { sample_vars },
  );

export const testSendNotificationTemplate = (
  id: string,
  recipient: string,
  sample_vars: Record<string, string>,
) =>
  api.post<NotificationTemplateTestSendResult>(
    `/ui/admin/notifications/templates/${encodeURIComponent(id)}/test-send`,
    { recipient, sample_vars },
  );
