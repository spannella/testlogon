import { api } from "@/api/client";
import type {
  NotificationListResponse,
  MarkNotificationsReadReq,
  SendNotificationReq,
} from "@/api/types";

export const getNotifications = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<NotificationListResponse>("/ui/notifications", params);
};

export const getNotificationUnreadCount = () =>
  api.get<{ count: number }>("/ui/notifications/unread-count");

export const markNotificationsRead = (body: MarkNotificationsReadReq) =>
  api.post<{ ok: boolean; marked_count: number }>("/ui/notifications/mark-read", body);

export const markAllNotificationsRead = () =>
  api.post<{ ok: boolean; marked_count: number }>("/ui/notifications/mark-all-read", {});

export const sendNotification = (body: SendNotificationReq) =>
  api.post<{ ok: boolean; notification_id: string; created_at: number; batch_count: number }>(
    "/ui/notifications/send",
    body,
  );
