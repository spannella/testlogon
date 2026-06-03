import { api } from "@/api/client";

// ─── Types (ADS-006) ─────────────────────────────────────────────

export interface BroadcastPreRoll {
  creative_id: string;
  format: string;
  video_url?: string | null;
  image_url?: string | null;
  cta_url?: string | null;
  skip_after_seconds: number;
  impression_url: string;
  click_url: string;
  skip_url: string;
}

export interface BroadcastAdJoinResponse {
  session_id: string;
  stream_url?: string | null;
  pre_roll?: BroadcastPreRoll | null;
  ad_free: boolean;
  mid_roll_skip_after_seconds: number;
}

export interface BroadcastAdConfig {
  session_id: string;
  pre_roll_enabled: boolean;
  mid_roll_ad_break_duration_seconds: number;
  mid_roll_skip_after_seconds: number;
  ad_break_active: boolean;
  ad_break_started_at?: number | null;
  total_ad_breaks: number;
}

export interface BroadcastAdConfigUpdate {
  pre_roll_enabled?: boolean;
  mid_roll_ad_break_duration_seconds?: number;
  mid_roll_skip_after_seconds?: number;
}

export interface AdBreakResponse {
  ok: boolean;
  duration_seconds: number;
  started_at: number;
  skip_after_seconds: number;
}

export type AdEventType = "impression" | "skip" | "complete" | "click";

// ─── API functions ───────────────────────────────────────────────

export const adJoin = (sessionId: string) =>
  api.post<BroadcastAdJoinResponse>(`/broadcast/sessions/${sessionId}/ad-join`);

export const getAdConfig = (sessionId: string) =>
  api.get<BroadcastAdConfig>(`/broadcast/sessions/${sessionId}/ad-config`);

export const updateAdConfig = (sessionId: string, body: BroadcastAdConfigUpdate) =>
  api.patch<BroadcastAdConfig>(`/broadcast/sessions/${sessionId}/ad-config`, body);

export const triggerAdBreak = (sessionId: string) =>
  api.post<AdBreakResponse>(`/broadcast/sessions/${sessionId}/ad-break`);

export const endAdBreak = (sessionId: string) =>
  api.post<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/ad-break/end`);

export const trackAdEvent = (
  sessionId: string,
  creativeId: string,
  event: AdEventType,
  slotType?: string,
) =>
  api.post<{ ok: boolean; event_id: string; event_type: string }>(
    `/broadcast/sessions/${sessionId}/ads/${creativeId}/track`,
    null,
    { event, ...(slotType ? { slot_type: slotType } : {}) } as Record<string, string>,
  );
