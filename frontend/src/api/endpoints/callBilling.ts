import { api, ApiError } from "@/api/client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CallRate {
  rate_cents_per_minute: number;
  enabled: boolean;
  currency: string;
  min_balance_minutes: number;
  max_duration_minutes: number;
}

export interface CallRateIn {
  rate_cents_per_minute: number;
  enabled?: boolean;
  min_balance_minutes?: number;
  max_duration_minutes?: number;
}

export interface HeartbeatResponse {
  call_id: string;
  elapsed_seconds: number;
  total_cost_cents: number;
  balance_remaining_cents: number;
  rate_cents_per_minute: number;
  next_bill_in_seconds: number;
  warn_low_balance: boolean;
  minutes_remaining: number;
  max_duration_warning: boolean;
  action: string;
}

export interface CallBillingStatus {
  call_id: string;
  paid: boolean;
  rate_cents_per_minute: number;
  total_cost_cents: number;
  total_billed_seconds: number;
  billing_cycle_count: number;
  caller_balance_remaining_cents: number;
  platform_fee_bps: number;
  max_duration_seconds: number;
  elapsed_seconds: number;
  billing_status: string;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

/**
 * Get a creator's per-minute call rate.
 *
 * Returns `null` when the creator has not configured a paid-call rate (the
 * backend responds 404), so callers can treat "no rate" as a clean absence
 * rather than an error.
 */
export const getCallRate = async (creatorId: string): Promise<CallRate | null> => {
  try {
    return await api.get<CallRate>(`/ui/calls/rates/${creatorId}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
};

/** Set own call rate (creator). */
export const setCallRate = (data: CallRateIn) =>
  api.post<CallRate>("/ui/calls/rates", data);

/** Update own call rate. */
export const updateCallRate = (data: CallRateIn) =>
  api.put<CallRate>("/ui/calls/rates", data);

/** Delete own call rate (disable paid calls). */
export const deleteCallRate = () =>
  api.del("/ui/calls/rates");

/** Send heartbeat for a paid call. */
export const sendCallHeartbeat = (callId: string) =>
  api.patch<HeartbeatResponse>(
    `/messaging/messages/calls/${callId}/heartbeat`,
    { client_ts: Math.floor(Date.now() / 1000) },
  );

/** Get billing summary for a call. */
export const getCallBilling = (callId: string) =>
  api.get<CallBillingStatus>(
    `/messaging/messages/calls/${callId}/billing`,
  );

/** Negotiate rate — convenience wrapper that sets rate on the creator side. */
export const negotiateCallRate = (callId: string, rateCentsPerMin: number) =>
  api.post(`/messaging/messages/calls/${callId}/rate`, {
    rate_cents_per_minute: rateCentsPerMin,
  });
