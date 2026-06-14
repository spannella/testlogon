// SuiteCRM CASES / PORTAL (CAS) cluster — frontend endpoint wrappers.
//
// CAS is purely *additive fields on the tickets system* (see app/routers/tickets.py):
// case_number (CAS-002), priority (CAS-003), contact/account soft FKs (CAS-005),
// watchers / CC list (CAS-007), and case-to-case relationship links (CAS-011).
//
// These wrappers therefore re-call the LIVE /tickets endpoints, projected for the
// "Cases" view. The CAS-specific fields (case_number/priority/contact_id/account_id)
// only populate when the backend `crm_cases_enabled` flag is ON; otherwise the
// dedicated CAS routes (priority / contact-account / by-contact / by-account /
// watchers / links) return 404 and tickets carry null case fields.
//
// Types are declared INLINE here (NOT in shared api/types.ts) and mirror the LIVE
// Pydantic models in app/routers/tickets.py + app/models.py.

import { api } from "@/api/client";

// ─── Enums / literals (mirror app/routers/tickets.py) ────────────────────────

export type CasePriority = "urgent" | "high" | "medium" | "low";
export type CaseStatus = "open" | "in_progress" | "waiting_on_user" | "done";
export type CaseStatusWritable = CaseStatus | "reopened";
export type CaseLinkType = "duplicate" | "blocks" | "relates_to";

// ─── Message / activity (TicketMessage / TicketActivity) ─────────────────────

export interface CaseMessage {
  message_id: string;
  sender_sub: string;
  sender_role: string;
  body: string;
  created_at: number;
  email_alert_queued_for: string[];
}

export interface CaseActivity {
  type: string;
  actor_sub: string;
  assignee_sub?: string | null;
  status?: string | null;
  created_at: number;
}

// ─── Case (= TicketOut projected for CAS fields) ─────────────────────────────

export interface Case {
  ticket_id: string;
  subject: string;
  owner_sub: string;
  status: CaseStatus;
  space_id?: string | null;
  assigned_admin_sub?: string | null;
  assigned_to_sub?: string | null;
  assigned_by?: string | null;
  assigned_at?: number | null;
  created_at: number;
  updated_at: number;
  version: number;
  // CAS-002: sequential human-readable case number
  case_number?: string | null;
  // CAS-003: priority
  priority?: CasePriority | string | null;
  // CAS-005: contact / account soft FKs
  contact_id?: string | null;
  account_id?: string | null;
  messages: CaseMessage[];
  activity: CaseActivity[];
}

export interface CaseEnvelope {
  ticket: Case;
}

// TicketListItemOut adds source/sync_freshness; CAS list view reuses Case fields.
export interface CaseListItem extends Omit<Case, "messages" | "activity"> {
  messages?: CaseMessage[];
  activity?: CaseActivity[];
  source?: "internal" | "jira";
}

export interface CaseListEnvelope {
  items: CaseListItem[];
  next_cursor?: string | null;
}

export interface CaseAdminSummary {
  by_status: Record<string, number>;
  unassigned_count: number;
  stale_count: number;
  stale_after_seconds: number;
  total_count: number;
}

export interface CaseAdminSummaryEnvelope {
  summary: CaseAdminSummary;
}

// ─── Watchers (CAS-007 — app/models.py TicketWatcherOut) ─────────────────────

export interface CaseWatcher {
  ticket_id: string;
  watcher_sub: string;
  added_by_sub?: string | null;
  created_at: number;
}

export interface CaseWatcherListEnvelope {
  watchers: CaseWatcher[];
}

// ─── Links (CAS-011 — app/models.py TicketLinkOut) ───────────────────────────

export interface CaseLink {
  ticket_id: string;
  related_ticket_id: string;
  link_type: CaseLinkType;
  created_by_sub?: string | null;
  created_at: number;
}

export interface CaseLinkListEnvelope {
  links: CaseLink[];
}

// ─── Read / list ─────────────────────────────────────────────────────────────

export const listCases = (opts?: {
  status?: CaseStatus;
  priority?: CasePriority;
  assignee_admin_sub?: string;
  owner_sub?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.priority) params.priority = opts.priority;
  if (opts?.assignee_admin_sub) params.assignee_admin_sub = opts.assignee_admin_sub;
  if (opts?.owner_sub) params.owner_sub = opts.owner_sub;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<CaseListEnvelope>("/tickets", params);
};

export const getCase = (caseId: string) => api.get<CaseEnvelope>(`/tickets/${caseId}`);

export const getCaseSummary = (staleAfterSeconds?: number) =>
  api.get<CaseAdminSummaryEnvelope>(
    "/tickets/admin/summary",
    staleAfterSeconds ? { stale_after_seconds: String(staleAfterSeconds) } : undefined,
  );

// ─── Create / mutate (CAS-002/003/005) ───────────────────────────────────────

export const createCase = (payload: {
  subject: string;
  description: string;
  priority?: CasePriority;
  contact_id?: string | null;
  account_id?: string | null;
}) => api.post<CaseEnvelope>("/tickets", payload);

export const addCaseMessage = (caseId: string, body: string) =>
  api.post<CaseEnvelope>(`/tickets/${caseId}/messages`, { body });

export const setCaseStatus = (caseId: string, status: CaseStatusWritable) =>
  api.post<CaseEnvelope>(`/tickets/${caseId}/status`, { status });

export const assignCase = (caseId: string, assigneeAdminSub: string) =>
  api.post<CaseEnvelope>(`/tickets/${caseId}/assign`, { assignee_admin_sub: assigneeAdminSub });

// CAS-003: PATCH priority (admin-only; 404 when crm_cases_enabled is OFF)
export const setCasePriority = (caseId: string, priority: CasePriority) =>
  api.patch<CaseEnvelope>(`/tickets/${caseId}/priority`, { priority });

// CAS-005: PATCH contact / account soft FKs (admin-only; 404 when flag OFF)
export const setCaseContactAccount = (
  caseId: string,
  payload: { contact_id?: string | null; account_id?: string | null },
) => api.patch<CaseEnvelope>(`/tickets/${caseId}/contact-account`, payload);

// CAS-005: list cases by contact / account (admin-only; 404 when flag OFF)
export const listCasesByContact = (contactId: string, opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<CaseListEnvelope>(`/tickets/by-contact/${encodeURIComponent(contactId)}`, params);
};

export const listCasesByAccount = (accountId: string, opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<CaseListEnvelope>(`/tickets/by-account/${encodeURIComponent(accountId)}`, params);
};

// ─── Watchers (CAS-007; 404 when flag OFF) ───────────────────────────────────

export const listCaseWatchers = (caseId: string) =>
  api.get<CaseWatcherListEnvelope>(`/tickets/${caseId}/watchers`);

export const addCaseWatcher = (caseId: string, watcherSub: string) =>
  api.post<CaseWatcherListEnvelope>(`/tickets/${caseId}/watchers`, { watcher_sub: watcherSub });

export const removeCaseWatcher = (caseId: string, watcherSub: string) =>
  api.del<{ ok: boolean }>(`/tickets/${caseId}/watchers/${encodeURIComponent(watcherSub)}`);

// ─── Case-to-case links (CAS-011; 404 when flag OFF) ─────────────────────────

export const listCaseLinks = (caseId: string) =>
  api.get<CaseLinkListEnvelope>(`/tickets/${caseId}/links`);

export const createCaseLink = (
  caseId: string,
  payload: { related_ticket_id: string; link_type: CaseLinkType },
) => api.post<CaseLinkListEnvelope>(`/tickets/${caseId}/links`, payload);

export const deleteCaseLink = (caseId: string, relatedTicketId: string) =>
  api.del<{ ok: boolean }>(`/tickets/${caseId}/links/${encodeURIComponent(relatedTicketId)}`);
