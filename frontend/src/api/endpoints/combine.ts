import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CombineVideosRequest {
  source_video_ids: string[];
  title: string;
  description?: string;
}

export interface CombineVideosResponse {
  video_id: string;
  title: string;
  status: string;
  source_video_ids: string[];
  created_via: string;
  estimated_duration_seconds: number;
  concat_method: string;
  concat_job_id: string;
}

// ─── API calls ─────────────────────────────────────────────────────────────

export const combineVideos = (body: CombineVideosRequest) =>
  api.post<CombineVideosResponse>("/ui/videos/combine", body);
