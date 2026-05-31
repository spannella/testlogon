import { api } from "@/api/client";
import type { ActivityFeedPageResponse, UnreadCountResponse } from "@/api/types";

export const getActivityFeed = (opts?: {
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<ActivityFeedPageResponse>("/ui/activity/feed", params);
};

export const getActivityFeedFiltered = (
  activityType: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = { activity_type: activityType };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<ActivityFeedPageResponse>("/ui/activity/feed/filter", params);
};

export const getActivityUnreadCount = () =>
  api.get<UnreadCountResponse>("/ui/activity/feed/unread-count");

export const markActivitiesRead = (upToTs?: number) =>
  api.post<{ ok: boolean; marked_count: number }>("/ui/activity/feed/mark-read", {
    up_to_ts: upToTs ?? null,
  });

export const recordActivity = (data: {
  user_id: string;
  actor_id: string;
  activity_type: string;
  target_type?: string;
  target_id?: string;
  metadata?: Record<string, unknown>;
}) =>
  api.post<{ ok: boolean; activity_id: string; created_at: number }>(
    "/ui/activity/feed/record",
    data,
  );
