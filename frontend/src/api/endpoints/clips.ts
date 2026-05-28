import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ClipVideoRequest {
  start_seconds: number;
  end_seconds: number;
  title?: string;
}

export interface ClipVideoResponse {
  video_id: string;
  title: string;
  status: string;
  source_video_id: string;
  clip_start_seconds: number;
  clip_end_seconds: number;
  created_via: string;
  clip_job_id: string;
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const createClip = (videoId: string, body: ClipVideoRequest) =>
  api.post<ClipVideoResponse>(`/ui/videos/${videoId}/clip`, body);
