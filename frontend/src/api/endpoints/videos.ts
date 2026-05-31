import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface VideoPresignRequest {
  filename: string;
  content_type: string;
  file_size_bytes: number;
  title?: string;
  description?: string;
  folder_path?: string;
}

export interface VideoPresignResponse {
  upload_url: string;
  bucket: string;
  key: string;
  ticket_id: string;
  video_id: string;
  content_type: string;
  expires_at: string;
  max_size_bytes: number;
}

export interface VideoCompleteRequest {
  ticket_id: string;
  key: string;
  content_type?: string;
  client_checksum?: string;
}

export interface VideoCompleteResponse {
  ok: boolean;
  video_id: string;
  s3_key: string;
  size_bytes: number;
  content_type: string;
  duration_seconds: number | null;
  thumbnail_url: string | null;
  status: string;
  created_at: number;
}

export interface VideoListItem {
  video_id: string;
  title: string;
  status: string;
  visibility: string;
  created_at: number;
  updated_at: number;
  duration_seconds?: number | null;
  width?: number | null;
  height?: number | null;
  thumbnail_url?: string | null;
  file_size_bytes?: number | null;
  review_status?: string | null;
  owner_user_id?: string | null;
}

export interface VideoListResponse {
  items: VideoListItem[];
  cursor?: string | null;
}

export interface VideoDetail {
  video_id: string;
  owner_user_id: string;
  title: string;
  description?: string | null;
  status: string;
  visibility: string;
  created_at: number;
  updated_at: number;
  duration_seconds?: number | null;
  width?: number | null;
  height?: number | null;
  frame_rate?: number | null;
  video_codec?: string | null;
  audio_codec?: string | null;
  file_size_bytes?: number | null;
  container_format?: string | null;
  renditions: unknown[];
  thumbnail_url?: string | null;
  hls_manifest_url?: string | null;
  playback_token?: string | null;
  playback_expires_at?: number | null;
  encoding_job_id?: string | null;
  encoding_error_message?: string | null;
  review_status?: string | null;
  published_at?: number | null;
  // Download (VOD-012)
  allow_download?: boolean;
  download_available?: boolean;
  download_mp4_size_bytes?: number;
  // Watermarked Downloads (VOD-020)
  watermark_downloads?: boolean;
  // Pay-per-view (MON-001)
  price_cents?: number | null;
  access_mode?: string | null;
  purchase_count?: number;
  is_entitled?: boolean;
  // Subscription-gated VOD (MON-005)
  access_reason?: string;
  subscription_available?: boolean;
  purchase_available?: boolean;
  subscription_upsell?: boolean;
}

// MON-005: Creator video list with subscription-aware access info
export interface CreatorVideoListItem {
  video_id: string;
  title: string;
  description?: string | null;
  thumbnail_url?: string | null;
  duration_seconds?: number | null;
  price_cents?: number | null;
  access_mode?: string | null;
  entitled: boolean;
  access_reason: string;
  created_at: number;
}

export interface CreatorVideoListResponse {
  videos: CreatorVideoListItem[];
  viewer_has_subscription: boolean;
  next_cursor?: string | null;
}

export interface VideoDownloadResponse {
  download_url: string;
  download_expires_at: number;
  file_size_bytes: number;
  filename: string;
  content_type: string;
}

export interface VideoUpdateRequest {
  title?: string;
  description?: string;
  visibility?: string;
  allow_download?: boolean;
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const presignVideoUpload = (body: VideoPresignRequest) =>
  api.post<VideoPresignResponse>("/ui/videos/upload/presign", body);

export const completeVideoUpload = (body: VideoCompleteRequest) =>
  api.post<VideoCompleteResponse>("/ui/videos/upload/complete", body);

/** @deprecated Use completeVideoUpload with ticket_id + key instead */
export const completeVideoUploadLegacy = (videoId: string) =>
  api.post<{ video_id: string; status: string }>(`/ui/videos/${videoId}/upload/complete`);

export const listMyVideos = (params?: { limit?: number; cursor?: string; status?: string }) => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  if (params?.status) p.status = params.status;
  return api.get<VideoListResponse>("/ui/videos", p);
};

export const getVideoDetail = (videoId: string) =>
  api.get<VideoDetail>(`/ui/videos/${videoId}`);

export const updateVideo = (videoId: string, body: VideoUpdateRequest) =>
  api.patch<VideoDetail>(`/ui/videos/${videoId}`, body);

export const deleteVideo = (videoId: string) =>
  api.del(`/ui/videos/${videoId}`);

export const getVideoDownload = (videoId: string) =>
  api.get<VideoDownloadResponse>(`/ui/videos/${videoId}/download`);

export const listCreatorVideos = (creatorId: string, params?: { limit?: number; cursor?: string }) => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<VideoListResponse>(`/ui/videos/creator/${encodeURIComponent(creatorId)}`, p);
};

// MON-005: Subscription-aware creator video list
export const listCreatorVideosWithAccess = (creatorId: string, params?: { limit?: number; cursor?: string }): Promise<CreatorVideoListResponse> => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<CreatorVideoListResponse>(`/ui/videos/by-creator/${encodeURIComponent(creatorId)}`, p);
};
