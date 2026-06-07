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
  // VOD ↔ File Manager bridge (VOD-014): set when this video originated from a
  // file-manager node. Used to render the "In Files" badge on video cards.
  source_file_node_id?: string | null;
}

export interface VideoListResponse {
  items: VideoListItem[];
  cursor: string | null;
}

// ─── VOD ↔ File Manager bridge (VOD-014) ─────────────────────────────────────

export interface VodImportToVodIn {
  file_path: string;
  title?: string;
  visibility?: "private" | "unlisted" | "public";
}

export interface VodImportToVodOut {
  video_id: string;
  status: string;
  file_path: string;
}

export interface VodBridgeStatusOut {
  video_id: string;
  vod_status: string;
  file_path?: string | null;
  hls_manifest_url?: string | null;
  thumbnail_url?: string | null;
  duration_seconds?: number | null;
  width?: number | null;
  height?: number | null;
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

// ─── VOD ↔ File Manager bridge (VOD-014) ─────────────────────────────────────

/** Import a file-manager video file into the VOD pipeline. */
export const importFileToVod = (body: VodImportToVodIn): Promise<VodImportToVodOut> =>
  api.post<VodImportToVodOut>("/ui/vod-bridge/import", body);

/** Fetch the VOD bridge / encoding status for a previously imported video. */
export const getVodBridgeStatus = (videoId: string): Promise<VodBridgeStatusOut> =>
  api.get<VodBridgeStatusOut>(`/ui/vod-bridge/status/${videoId}`);

/** Unlink a VOD video from its source file-manager node. */
export const unlinkVodBridge = (videoId: string): Promise<unknown> =>
  api.del(`/ui/vod-bridge/${videoId}/link`);
