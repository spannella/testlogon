import { api } from "@/api/client";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KycQueueItem {
  kyc_case_id: string;
  user_sub: string;
  status: string;
  assigned_admin_sub: string | null;
  created_at: number;
  updated_at: number;
  waiting_seconds: number | null;
  risk_tier: string | null;
}

export interface KycQueueEnvelope {
  items: KycQueueItem[];
  next_cursor: string | null;
}

export interface KycTimelineEvent {
  event_type: string;
  source: "kyc_case" | "ticket";
  created_at: number | null;
  actor_sub: string | null;
  details: Record<string, unknown>;
}

export interface KycFileRef {
  type: string;
  path: string;
  verification_state: string;
  uploaded_at?: number;
}

export interface KycCaseDetail {
  kyc_case_id: string;
  user_sub: string;
  status: string;
  questionnaire_ref: Record<string, unknown>;
  files_ref: KycFileRef[];
  signature_ref: Record<string, unknown>;
  ticket_ref: Record<string, unknown>;
  decision_state: {
    decision: string | null;
    decided_at: number | null;
    reason_codes: string[];
    assigned_admin_sub: string | null;
  };
  timeline: KycTimelineEvent[];
}

export interface KycMetrics {
  funnel_counts: Record<string, number>;
  review_latency_seconds: Record<string, number | null>;
  stale_queue_count: number;
  submit_guard_failures_by_reason: Record<string, number>;
  ticket_sync_counters: Record<string, number>;
  ticket_sync_deadletter_count: number;
}

// ─── API calls ────────────────────────────────────────────────────────────────

export function fetchKycQueue(params: {
  status?: string;
  assignee_admin_sub?: string;
  risk_tier?: string;
  min_waiting_seconds?: number;
  cursor?: string;
  limit?: number;
}): Promise<KycQueueEnvelope> {
  const q: Record<string, string> = {};
  if (params.status) q.status = params.status;
  if (params.assignee_admin_sub) q.assignee_admin_sub = params.assignee_admin_sub;
  if (params.risk_tier) q.risk_tier = params.risk_tier;
  if (params.min_waiting_seconds != null) q.min_waiting_seconds = String(params.min_waiting_seconds);
  if (params.cursor) q.cursor = params.cursor;
  if (params.limit != null) q.limit = String(params.limit);
  return api.get<KycQueueEnvelope>("/v1/kyc/cases/admin/queue", q);
}

export function fetchKycCaseDetail(caseId: string): Promise<{ case: KycCaseDetail }> {
  return api.get<{ case: KycCaseDetail }>(`/v1/kyc/cases/admin/cases/${caseId}`);
}

export function fetchKycMetrics(staleAfterSeconds?: number): Promise<{ metrics: KycMetrics }> {
  const q: Record<string, string> = {};
  if (staleAfterSeconds != null) q.stale_after_seconds = String(staleAfterSeconds);
  return api.get<{ metrics: KycMetrics }>("/v1/kyc/cases/admin/metrics", q);
}

export function approveKycCase(
  caseId: string,
  body: { expected_version: number; reason_codes: string[]; note: string },
) {
  return api.post(`/v1/kyc/cases/admin/cases/${caseId}/approve`, {
    ...body,
    decision: "approve",
  });
}

export function rejectKycCase(
  caseId: string,
  body: { expected_version: number; reason_codes: string[]; note: string },
) {
  return api.post(`/v1/kyc/cases/admin/cases/${caseId}/reject`, {
    ...body,
    decision: "reject",
  });
}

export function requestKycInfo(
  caseId: string,
  body: { expected_version: number; requested_items: string[]; note: string },
) {
  return api.post(`/v1/kyc/cases/admin/cases/${caseId}/request-info`, body);
}
