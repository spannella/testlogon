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

export interface VideoRendition {
  label: string;
  width: number;
  height: number;
  bitrate_kbps: number;
}

export interface VideoDetailResponse {
  video_id: string;
  owner_user_id: string;
  title: string;
  description: string | null;
  status: string;
  visibility: string;
  created_at: number;
  updated_at: number;
  duration_seconds: number | null;
  width: number | null;
  height: number | null;
  frame_rate: number | null;
  video_codec: string | null;
  audio_codec: string | null;
  file_size_bytes: number | null;
  container_format: string | null;
  renditions: VideoRendition[];
  thumbnail_url: string | null;
  hls_manifest_url: string | null;
  playback_token: string | null;
  playback_expires_at: number | null;
  encoding_job_id: string | null;
  encoding_error_message: string | null;
  review_status: string | null;
  published_at: number | null;
}

export interface VideoListItem {
  video_id: string;
  title: string;
  status: string;
  visibility: string;
  created_at: number;
  updated_at: number;
  duration_seconds: number | null;
  width: number | null;
  height: number | null;
  thumbnail_url: string | null;
  file_size_bytes: number | null;
  review_status: string | null;
  owner_user_id: string | null;
}

export interface VideoListResponse {
  items: VideoListItem[];
  cursor: string | null;
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const presignVideoUpload = (body: VideoPresignRequest) =>
  api.post<VideoPresignResponse>("/ui/videos/upload/presign", body);

export const completeVideoUpload = (body: VideoCompleteRequest) =>
  api.post<VideoCompleteResponse>("/ui/videos/upload/complete", body);

/** @deprecated Use completeVideoUpload with ticket_id + key instead */
export const completeVideoUploadLegacy = (videoId: string) =>
  api.post<{ video_id: string; status: string }>(`/ui/videos/${videoId}/upload/complete`);

export const getVideoDetail = (videoId: string): Promise<VideoDetailResponse> =>
  api.get<VideoDetailResponse>(`/ui/videos/${videoId}`);

export const listOwnVideos = (params?: {
  limit?: number;
  cursor?: string;
  status?: string;
  visibility?: string;
}): Promise<VideoListResponse> => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  if (params?.status) p.status = params.status;
  if (params?.visibility) p.visibility = params.visibility;
  return api.get<VideoListResponse>("/ui/videos", p);
};

export const listPublicVideos = (params?: {
  limit?: number;
  cursor?: string;
}): Promise<VideoListResponse> => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<VideoListResponse>("/ui/videos/public", p);
};
