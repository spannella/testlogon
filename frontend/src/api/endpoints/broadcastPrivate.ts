import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export interface PrivateRequest {
  request_id: string;
  private_session_id: string;
  session_id: string;
  viewer_id: string;
  viewer_display_name: string;
  rate_per_minute_cents: number;
  status: string;
  behavior: string | null;
  call_id: string | null;
  max_duration_minutes: number;
  requested_at: number;
  accepted_at: number | null;
  started_at: number | null;
  ended_at: number | null;
  ended_by: string | null;
  total_billed_cents: number;
}

export interface PrivateRequestListResponse {
  requests: PrivateRequest[];
}

export interface PrivateAcceptResponse {
  private_session_id: string;
  session_id: string;
  status: string;
  behavior: string;
  call_id: string;
  rate_per_minute_cents: number;
}

export interface PrivateSessionEndResponse {
  private_session_id: string;
  session_id: string;
  status: string;
  duration_seconds: number;
  total_billed_cents: number;
  ended_by: string;
}

export interface PrivateStatusResponse {
  status: string;
  request_id?: string;
  private_session_id?: string;
  session_id?: string;
  viewer_id?: string;
  viewer_display_name?: string;
  rate_per_minute_cents?: number;
  behavior?: string | null;
  call_id?: string | null;
}

// ─── API Functions ──────────────────────────────────────────────

export const submitPrivateRequest = (
  sessionId: string,
  data: {
    rate_per_minute_cents: number;
    payment_method_id: string;
    max_duration_minutes?: number;
  },
) =>
  api.post<PrivateRequest>(
    `/broadcast/sessions/${sessionId}/private/request`,
    data,
  );

export const listPrivateRequests = (sessionId: string) =>
  api.get<PrivateRequestListResponse>(
    `/broadcast/sessions/${sessionId}/private/requests`,
  );

export const acceptPrivateRequest = (
  sessionId: string,
  requestId: string,
  data: { behavior: "pause" | "end" | "continue" },
) =>
  api.post<PrivateAcceptResponse>(
    `/broadcast/sessions/${sessionId}/private/${requestId}/accept`,
    data,
  );

export const declinePrivateRequest = (
  sessionId: string,
  requestId: string,
) =>
  api.post<{ ok: boolean; request_id: string }>(
    `/broadcast/sessions/${sessionId}/private/${requestId}/decline`,
  );

export const cancelPrivateRequest = (
  sessionId: string,
  requestId: string,
) =>
  api.post<{ ok: boolean; request_id: string }>(
    `/broadcast/sessions/${sessionId}/private/${requestId}/cancel`,
  );

export const endPrivateSession = (
  sessionId: string,
  privateId: string,
) =>
  api.post<PrivateSessionEndResponse>(
    `/broadcast/sessions/${sessionId}/private/${privateId}/end`,
  );

export const getPrivateStatus = (sessionId: string) =>
  api.get<PrivateStatusResponse>(
    `/broadcast/sessions/${sessionId}/private/status`,
  );

export const resumeBroadcast = (sessionId: string) =>
  api.post<unknown>(`/broadcast/sessions/${sessionId}/resume`);
