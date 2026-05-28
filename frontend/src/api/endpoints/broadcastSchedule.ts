import { api } from "@/api/client";
import type { BroadcastSession } from "./broadcast";

// ─── Types ──────────────────────────────────────────────────────

export interface ScheduleSessionReq {
  scheduled_at: number;
  name?: string | null;
  description?: string | null;
}

export interface RescheduleSessionReq {
  scheduled_at: number;
}

export interface ScheduledListResponse {
  items: BroadcastSession[];
  count: number;
}

export interface ReminderResponse {
  ok: boolean;
  remind_at: number;
}

// ─── API functions ──────────────────────────────────────────────

export const scheduleSession = (sessionId: string, body: ScheduleSessionReq) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${sessionId}/schedule`, body);

export const rescheduleSession = (sessionId: string, body: RescheduleSessionReq) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${sessionId}/reschedule`, body);

export const cancelSchedule = (sessionId: string) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${sessionId}/cancel-schedule`);

export const registerReminder = (sessionId: string) =>
  api.post<ReminderResponse>(`/broadcast/sessions/${sessionId}/remind-me`);

export const cancelReminder = (sessionId: string) =>
  api.del<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/remind-me`);

export const listScheduledSessions = (params?: { limit?: number }) =>
  api.get<ScheduledListResponse>("/broadcast/sessions/scheduled", params as Record<string, string>);

export const downloadIcal = (sessionId: string) =>
  window.open(`/broadcast/sessions/${sessionId}/ical`, "_blank");
