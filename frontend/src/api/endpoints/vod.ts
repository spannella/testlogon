import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface VideoPresignRequest {
  filename: string;
  content_type: string;
  size_bytes: number;
}

export interface VideoPresignResponse {
  video_id: string;
  presigned_url: string;
  s3_key: string;
  expires_in_seconds: number;
}

export interface VideoCompleteResponse {
  video_id: string;
  status: string;
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

export const completeVideoUpload = (videoId: string) =>
  api.post<VideoCompleteResponse>(`/ui/videos/${videoId}/upload/complete`);

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
