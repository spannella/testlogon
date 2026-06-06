import { api } from "@/api/client";

// ─── Types (mirror app/models.py Appeal* models) ─────────────────────────────

export type AppealStatus =
  | "submitted"
  | "under_review"
  | "upheld"
  | "modified"
  | "reversed"
  | "withdrawn";

export type AppealDecision = "upheld" | "modified" | "reversed";

export interface Appeal {
  appeal_id: string;
  user_id: string;
  enforcement_id: string;
  enforcement_type: string;
  source_ticket_id: string;
  appeal_text: string;
  status: string;
  created_at: number;
  updated_at: number;
  decided_at?: number | null;
  decision_note?: string | null;
  modified_enforcement_type?: string | null;
  modified_duration_days?: number | null;
}

export interface AppealListOut {
  items: Appeal[];
  next_cursor?: string | null;
}

export interface AppealCreateOut {
  ok: boolean;
  appeal_id: string;
  status: string;
  created_at: number;
}

export interface AppealWithdrawOut {
  ok: boolean;
  appeal_id: string;
  status: string;
}

export interface AppealDetailOut {
  appeal: Appeal;
  enforcement_record: Record<string, unknown>;
  moderation_ticket: Record<string, unknown>;
  user_enforcement_history: Array<Record<string, unknown>>;
  user_appeal_history: Appeal[];
}

export interface AppealClaimOut {
  ok: boolean;
  appeal_id: string;
  assigned_admin_user_id: string;
}

export interface AppealDecisionOut {
  ok: boolean;
  appeal_id: string;
  status: string;
  decision: string;
  decided_at: number;
  enforcement_reversed: boolean;
  enforcement_modified: boolean;
}

export interface AppealQueueStatsOut {
  total_submitted: number;
  total_under_review: number;
  oldest_submitted_age_minutes: number;
}

export interface AppealDecisionPayload {
  decision: AppealDecision;
  decision_note?: string;
  modified_enforcement_type?: string;
  modified_duration_days?: number;
}

// ─── User-facing endpoints (prefix /v1/appeals) ──────────────────────────────

export const submitAppeal = (payload: { enforcement_id: string; appeal_text: string }) =>
  api.post<AppealCreateOut>("/v1/appeals", payload);

export const listMyAppeals = (opts?: { status?: string; limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  return api.get<AppealListOut>("/v1/appeals", params);
};

export const getAppeal = (appealId: string) =>
  api.get<Appeal>(`/v1/appeals/${encodeURIComponent(appealId)}`);

export const withdrawAppeal = (appealId: string) =>
  api.post<AppealWithdrawOut>(`/v1/appeals/${encodeURIComponent(appealId)}/withdraw`);

// ─── Admin-facing endpoints (prefix /v1/admin/appeals) ───────────────────────

export const listAppealQueue = (opts?: {
  status?: string;
  assigned_admin?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.assigned_admin) params.assigned_admin = opts.assigned_admin;
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  return api.get<AppealListOut>("/v1/admin/appeals", params);
};

export const getAppealQueueStats = () =>
  api.get<AppealQueueStatsOut>("/v1/admin/appeals/stats");

export const getAppealDetail = (appealId: string) =>
  api.get<AppealDetailOut>(`/v1/admin/appeals/${encodeURIComponent(appealId)}`);

export const claimAppeal = (appealId: string) =>
  api.post<AppealClaimOut>(`/v1/admin/appeals/${encodeURIComponent(appealId)}/claim`);

export const decideAppeal = (appealId: string, payload: AppealDecisionPayload) =>
  api.post<AppealDecisionOut>(`/v1/admin/appeals/${encodeURIComponent(appealId)}/decide`, payload);
