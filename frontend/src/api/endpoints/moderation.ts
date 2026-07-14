import { api } from "@/api/client";

export interface CreateModerationReportReq {
  content_type: "feed_post" | "feed_comment" | "feed_media" | "message" | "message_media" | "profile_photo";
  content_id: string;
  topics: string[];
  reason_text: string;
  post_id?: string;
  comment_id?: string;
  media_index?: number;
  conversation_id?: string;
  message_id?: string;
  profile_user_id?: string;
}

export interface ModerationTicket {
  ticket_id: string;
  content_type: string;
  content_id: string;
  status: string;
  priority: string;
  queue: string;
  assigned_admin_user_id?: string | null;
  report_count: number;
  aggregated_topics: string[];
  latest_report_at: number;
  updated_at: number;
  created_at: number;
}

export interface ModerationTicketListResp {
  items: ModerationTicket[];
  next_cursor?: string | null;
}

export interface ModerationLinkedReport {
  report_id: string;
  reporter_user_id: string;
  topics: string[];
  reason_text: string;
  created_at: number;
  metadata: Record<string, unknown>;
}

// MODX-17 (D7): the REAL projected shape emitted by admin_moderation._project_enforcement_row.
// The old UI type ({ ticket_id, decision, decided_by, decided_at }) never matched the payload,
// so every prior-enforcement row rendered `undefined`.
export interface ModerationEnforcementRecord {
  user_id: string;
  enforcement_id: string;
  enforcement_type: string;
  status: string;
  source_ticket_id: string;
  created_at: number;
  created_by_admin_user_id?: string | null;
  duration_days: number;
  note: string;
}

export interface ModerationTicketDetailResp {
  ticket: ModerationTicket;
  content_snapshot: Record<string, unknown>;
  linked_reports: ModerationLinkedReport[];
  offender_history_summary: {
    offender_user_id?: string | null;
    total_tickets: number;
    open_tickets: number;
    total_reports: number;
    total_enforcements?: number;
  };
  prior_enforcement_history: ModerationEnforcementRecord[];
  // MODX-17 (D1): the state-machine surface the web board must operate on.
  case_state: string;
  hold_until?: number | null;
  owner_user_id?: string | null;
  distinct_reporter_count: number;
  needs_human_review: boolean;
  human_review_reason?: string | null;
  illegal_lane: boolean;
  sla_deadline?: number | null;
  poster_response?: string | null;
  responded_at?: number | null;
}

// MODX-18 (D5): the live 6-category taxonomy (+ illegal lane) with legacy topics accepted
// server-side as synonyms. Replaces the dead Literal["sexual","extortion","criminal","spam","racist"].
export type ModerationTopic =
  | "sexual"
  | "violence_threats"
  | "hate"
  | "harassment"
  | "spam"
  | "other"
  | "illegal"
  | "extortion"
  | "criminal"
  | "racist"
  | "csam";

export interface ModerationKpis {
  generated_at: number;
  lookback_hours: number;
  surge_window_minutes: number;
  ticket_volume: number;
  resolution_count: number;
  resolution_latency_avg_seconds: number;
  resolution_latency_p95_seconds: number;
  warning_count: number;
  ban_count: number;
  warning_rate: number;
  ban_rate: number;
  open_ticket_count: number;
  critical_backlog: number;
  oldest_open_age_minutes: number;
  on_hold_count: number;
  extortion_criminal_reports_window_count: number;
}

export interface ModerationCaseActionResp {
  ok: boolean;
  ticket_id: string;
  case_id: string;
  state: string;
  hidden: boolean;
  hold_until?: number | null;
  owner_user_id?: string | null;
  enforcement_id?: string | null;
}

export interface ModerationBanEntry {
  user_id: string;
  enforcement_id: string;
  source_ticket_id: string;
  created_at: number;
  created_by_admin_user_id?: string | null;
  duration_days: number;
  ban_until: number;
  permanent: boolean;
  note: string;
  account_status: string;
  active: boolean;
}

export interface ModerationBanRoster {
  items: ModerationBanEntry[];
  next_cursor?: string | null;
}

export interface ModerationAuditEvent {
  audit_id: string;
  action: string;
  actor_user_id: string;
  ticket_id: string;
  content_type?: string;
  content_id?: string;
  target_user_id: string;
  created_at: number;
  metadata?: Record<string, unknown>;
}

export interface ModerationBulkResult {
  action: string;
  total: number;
  succeeded: number;
  failed: number;
  results: Array<{
    ticket_id: string;
    ok: boolean;
    state?: string | null;
    error_code?: string | null;
    error?: string | null;
  }>;
}

export const createModerationReport = (body: CreateModerationReportReq) =>
  api.post<{ ok: boolean; report_id: string }>("/moderation/reports", body);

export const listModerationTickets = (params?: {
  status?: string;
  queue?: string;
  topic?: ModerationTopic;
  assignee?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (!params) return api.get<ModerationTicketListResp>("/v1/admin/moderation/tickets", q);
  if (params.status) q.status = params.status;
  if (params.queue) q.queue = params.queue;
  if (params.topic) q.topic = params.topic;
  if (params.assignee) q.assignee = params.assignee;
  if (typeof params.limit === "number") q.limit = String(params.limit);
  if (params.cursor) q.cursor = params.cursor;
  return api.get<ModerationTicketListResp>("/v1/admin/moderation/tickets", q);
};

export const getModerationTicketDetail = (ticketId: string) =>
  api.get<ModerationTicketDetailResp>(`/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}`);

export const claimModerationTicket = (ticketId: string) =>
  api.post<ModerationTicket>(`/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/claim`, {});

export const unclaimModerationTicket = (ticketId: string, reassignTo?: string) =>
  api.post<ModerationTicket>(
    `/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/unclaim`,
    {},
    reassignTo ? { reassign_to: reassignTo } : undefined,
  );

// MODX-17 (D1): the STATE-MACHINE actions (the legacy decide/resolve below are kept as thin
// compatibility wrappers over the same tickets, but a moderator should drive these).
export const dismissModerationCase = (ticketId: string, steal = false) =>
  api.post<ModerationCaseActionResp>(
    `/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/dismiss`,
    {},
    steal ? { steal: "true" } : undefined,
  );

export const confirmModerationCase = (ticketId: string, steal = false) =>
  api.post<ModerationCaseActionResp>(
    `/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/confirm`,
    {},
    steal ? { steal: "true" } : undefined,
  );

export const finalCallModerationCase = (
  ticketId: string,
  body: {
    action: "reinstate" | "delete";
    note?: string;
    ban?: boolean;
    ban_duration_days?: number;
    second_approver_admin_user_id?: string;
  },
  steal = false,
) =>
  api.post<ModerationCaseActionResp>(
    `/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/final-call`,
    body,
    steal ? { steal: "true" } : undefined,
  );

// MODX-22 (D11): bulk triage over many tickets.
export const bulkModerationAction = (body: {
  ticket_ids: string[];
  action: "dismiss" | "confirm" | "reinstate" | "delete";
  note?: string;
  steal?: boolean;
}) => api.post<ModerationBulkResult>("/v1/admin/moderation/tickets/bulk", body);

// MODX-18 (D12): KPIs for the header strip.
export const getModerationKpis = () =>
  api.get<ModerationKpis>("/v1/admin/moderation/kpis");

// MODX-20 (D6): decision audit trail.
export const getTicketAuditTrail = (ticketId: string) =>
  api.get<{ items: ModerationAuditEvent[] }>(`/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/audit`);

export const getAuditByActor = (actor: string) =>
  api.get<{ items: ModerationAuditEvent[] }>("/v1/admin/moderation/audit", { actor });

// MODX-19 (D4): ban management.
export const listModerationBans = (includeInactive = false) =>
  api.get<ModerationBanRoster>(
    "/v1/admin/moderation/bans",
    includeInactive ? { include_inactive: "true" } : {},
  );

export const liftModerationBan = (userId: string, note?: string) =>
  api.post<{ ok: boolean; user_id: string; account_status: string; lifted_enforcement_ids: string[] }>(
    `/v1/admin/moderation/bans/${encodeURIComponent(userId)}/lift`,
    { note },
  );

// ---- Legacy compatibility wrappers (kept so existing callers/tests still resolve). ----
export const decideModerationTicket = (
  ticketId: string,
  body: { decision: "no_violation" | "remove" | "warn" | "ban"; note?: string },
) => api.post<ModerationTicket>(`/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/decision`, body);

export const resolveModerationTicket = (
  ticketId: string,
  body: {
    resolution: "no_violation" | "content_removed";
    enforcement_action: "none" | "warn" | "ban";
    note?: string;
  },
) => api.post<ModerationTicket>(`/v1/admin/moderation/tickets/${encodeURIComponent(ticketId)}/resolve`, body);
