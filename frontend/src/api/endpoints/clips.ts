import { api } from "../client";
import type { BroadcastClip, ClipListResponse } from "@/api/types";

// ─── VOD Clip Types (VOD-015) ───────────────────────────────────────────────

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

// ─── VOD Clip API (VOD-015) ─────────────────────────────────────────────────

export const createClip = (videoId: string, body: ClipVideoRequest) =>
  api.post<ClipVideoResponse>(`/ui/videos/${videoId}/clip`, body);

// ─── Broadcast Clip API (ENGAGE-005) ────────────────────────────────────────

export const createBroadcastClip = (
  sessionId: string,
  data: { start_seconds: number; end_seconds: number; title?: string },
) => api.post<BroadcastClip>(`/broadcast/sessions/${sessionId}/clips`, data);

export const getClip = (clipId: string) =>
  api.get<BroadcastClip>(`/broadcast/clips/${clipId}`);

export const listSessionClips = (sessionId: string) =>
  api.get<ClipListResponse>(`/broadcast/sessions/${sessionId}/clips`);

export const listGallery = (params?: { sort?: string; limit?: number; cursor?: string }) => {
  const p: Record<string, string> = {};
  if (params?.sort) p["sort"] = params.sort;
  if (params?.limit) p["limit"] = String(params.limit);
  if (params?.cursor) p["cursor"] = params.cursor;
  return api.get<ClipListResponse>("/ui/clips", p);
};

export const listMyClips = () =>
  api.get<ClipListResponse>("/ui/clips/mine");

export const deleteClip = (clipId: string) =>
  api.del<{ ok: boolean; clip_id: string; status: string }>(`/broadcast/clips/${clipId}`);

export const recordClipView = (clipId: string) =>
  api.post<{ ok: boolean; view_count: number }>(`/broadcast/clips/${clipId}/view`);

export const recordClipShare = (clipId: string) =>
  api.post<{ ok: boolean; share_count: number; share_url: string }>(`/broadcast/clips/${clipId}/share`);
