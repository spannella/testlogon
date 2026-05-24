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

// ─── API calls ──────────────────────────────────────────────────────────────

export const presignVideoUpload = (body: VideoPresignRequest) =>
  api.post<VideoPresignResponse>("/ui/videos/upload/presign", body);

export const completeVideoUpload = (videoId: string) =>
  api.post<VideoCompleteResponse>(`/ui/videos/${videoId}/upload/complete`);
