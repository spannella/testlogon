import { api } from "../client";

export interface VideoReviewQueueItem {
  video_id: string;
  owner_user_id: string;
  title: string;
  description?: string;
  status: string;
  created_at: number;
  updated_at: number;
  thumbnail_url?: string;
  hls_manifest_url?: string;
  duration_seconds?: number;
  width?: number;
  height?: number;
  file_size_bytes?: number;
  source_type: string;
  visibility: string;
  owner_display_name?: string;
  owner_profile_photo_url?: string;
}

export interface VideoReviewQueue {
  items: VideoReviewQueueItem[];
  total_pending: number;
  next_cursor?: string;
}

export interface VideoReviewDecision {
  ok: boolean;
  video_id: string;
  decision: "approved" | "rejected";
  new_status: string;
  reviewed_by: string;
  reviewed_at: number;
  audit_id: string;
  auto_publish_failed?: boolean;
}

export interface BatchReviewResult {
  results: Array<{
    video_id: string;
    ok: boolean;
    decision?: string;
    new_status?: string;
    error?: string;
    audit_id?: string;
  }>;
  total: number;
  succeeded: number;
  failed: number;
}

export interface VideoReviewDetail {
  video: VideoReviewQueueItem;
  owner_profile: Record<string, unknown>;
  prior_review_history: Array<Record<string, unknown>>;
  prior_rejections_count: number;
  prior_approvals_count: number;
}

export function fetchVideoReviewQueue(params?: {
  limit?: number;
  cursor?: string;
  owner_user_id?: string;
}): Promise<VideoReviewQueue> {
  const qp: Record<string, string> = {};
  if (params?.limit) qp.limit = String(params.limit);
  if (params?.cursor) qp.cursor = params.cursor;
  if (params?.owner_user_id) qp.owner_user_id = params.owner_user_id;
  return api<VideoReviewQueue>("/v1/admin/videos/review-queue", {
    params: Object.keys(qp).length ? qp : undefined,
  });
}

export function fetchVideoReviewDetail(
  videoId: string,
): Promise<VideoReviewDetail> {
  return api<VideoReviewDetail>(`/v1/admin/videos/${videoId}/review-detail`);
}

export function approveVideo(
  videoId: string,
  data: { review_notes?: string; auto_publish?: boolean },
): Promise<VideoReviewDecision> {
  return api<VideoReviewDecision>(`/v1/admin/videos/${videoId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export function rejectVideo(
  videoId: string,
  data: { rejection_reason: string; notify_creator?: boolean },
): Promise<VideoReviewDecision> {
  return api<VideoReviewDecision>(`/v1/admin/videos/${videoId}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export function batchReviewVideos(
  decisions: Array<{
    video_id: string;
    action: "approve" | "reject";
    reason?: string;
  }>,
): Promise<BatchReviewResult> {
  return api<BatchReviewResult>("/v1/admin/videos/batch-review", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decisions }),
  });
}
