import { api } from "@/api/client";
import type {
  VideoReviewQueueItem,
  VideoReviewQueueList,
  VideoReviewQueueStats,
  VideoReviewDetail,
  VideoReviewDecision,
} from "@/api/types";

const BASE = "/ui/moderation/video-queue";

export function enqueueVideoForReview(body: {
  video_id: string;
  owner_user_id: string;
  title?: string;
  description?: string;
  priority?: "urgent" | "high" | "normal" | "low";
  source?: "manual" | "flagged" | "upload";
  thumbnail_url?: string;
  hls_manifest_url?: string;
  duration_seconds?: number;
  flag_reason?: string;
}): Promise<VideoReviewQueueItem> {
  return api.post<VideoReviewQueueItem>(`${BASE}/enqueue`, body);
}

export function listVideoReviewQueue(params?: {
  status?: string;
  order_by?: "priority" | "created_at";
  limit?: number;
  cursor?: string;
  owner_user_id?: string;
}): Promise<VideoReviewQueueList> {
  const qp: Record<string, string> = {};
  if (params?.status) qp.status = params.status;
  if (params?.order_by) qp.order_by = params.order_by;
  if (params?.limit != null) qp.limit = String(params.limit);
  if (params?.cursor) qp.cursor = params.cursor;
  if (params?.owner_user_id) qp.owner_user_id = params.owner_user_id;
  return api.get<VideoReviewQueueList>(BASE, qp);
}

export function getVideoReviewQueueStats(): Promise<VideoReviewQueueStats> {
  return api.get<VideoReviewQueueStats>(`${BASE}/stats`);
}

export function getVideoReviewDetail(entryId: string): Promise<VideoReviewDetail> {
  return api.get<VideoReviewDetail>(`${BASE}/${entryId}`);
}

export function claimVideoReviewEntry(entryId: string): Promise<{ ok: boolean; entry: VideoReviewQueueItem }> {
  return api.post(`${BASE}/${entryId}/claim`);
}

export function releaseVideoReviewEntry(entryId: string): Promise<{ ok: boolean; entry: VideoReviewQueueItem }> {
  return api.post(`${BASE}/${entryId}/release`);
}

export function approveVideoReviewEntry(
  entryId: string,
  body?: { review_notes?: string; notify_creator?: boolean },
): Promise<VideoReviewDecision> {
  return api.post<VideoReviewDecision>(`${BASE}/${entryId}/approve`, body ?? {});
}

export function rejectVideoReviewEntry(
  entryId: string,
  body: { rejection_reason: string; notify_creator?: boolean },
): Promise<VideoReviewDecision> {
  return api.post<VideoReviewDecision>(`${BASE}/${entryId}/reject`, body);
}

export function escalateVideoReviewEntry(
  entryId: string,
  body: { escalation_reason: string; notify_creator?: boolean },
): Promise<VideoReviewDecision> {
  return api.post<VideoReviewDecision>(`${BASE}/${entryId}/escalate`, body);
}
