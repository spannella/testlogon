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

export interface ModerationTicketDetailResp {
  ticket: ModerationTicket;
  content_snapshot: Record<string, unknown>;
  linked_reports: ModerationLinkedReport[];
  offender_history_summary: {
    offender_user_id?: string | null;
    total_tickets: number;
    open_tickets: number;
    total_reports: number;
  };
  prior_enforcement_history: Array<{
    ticket_id: string;
    decision: string;
    note: string;
    decided_at: number;
    decided_by: string;
  }>;
}

export const createModerationReport = (body: CreateModerationReportReq) =>
  api.post<{ ok: boolean; report_id: string }>("/moderation/reports", body);

export const listModerationTickets = (params?: {
  status?: string;
  queue?: string;
  topic?: "sexual" | "extortion" | "criminal" | "spam" | "racist";
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
