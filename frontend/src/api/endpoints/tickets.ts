import { api } from "@/api/client";

export type TicketStatus = "open" | "in_progress" | "waiting_on_user" | "done";
export type TicketStatusWritable = TicketStatus | "reopened";

export interface TicketMessage {
  message_id: string;
  sender_sub: string;
  sender_role: string;
  body: string;
  created_at: number;
  email_alert_queued_for: string[];
}

export interface TicketActivity {
  type: string;
  actor_sub: string;
  assignee_sub?: string | null;
  status?: string | null;
  created_at: number;
}

export interface Ticket {
  ticket_id: string;
  subject: string;
  owner_sub: string;
  status: TicketStatus;
  assigned_admin_sub?: string | null;
  assigned_by?: string | null;
  assigned_at?: number | null;
  created_at: number;
  updated_at: number;
  version: number;
  messages: TicketMessage[];
  activity: TicketActivity[];
  space_id?: string | null;
  assigned_to_sub?: string | null;
}

export interface TicketEnvelope {
  ticket: Ticket;
}

export interface TicketListEnvelope {
  items: Ticket[];
  next_cursor?: string | null;
}

export interface TicketAdminSummary {
  by_status: Record<string, number>;
  unassigned_count: number;
  stale_count: number;
  stale_after_seconds: number;
  total_count: number;
}

export interface TicketAdminSummaryEnvelope {
  summary: TicketAdminSummary;
}

export type SpaceRole = "owner" | "editor" | "viewer";

export interface TicketSpaceMember {
  space_id: string;
  member_sub: string;
  role: SpaceRole;
  created_at: number;
  updated_at: number;
}

export interface TicketSpace {
  space_id: string;
  owner_sub: string;
  name: string;
  visibility: "private" | "shared";
  created_at: number;
  updated_at: number;
  members: TicketSpaceMember[];
}

export interface TicketSpaceEnvelope {
  space: TicketSpace;
}

export interface TicketSpaceListEnvelope {
  items: TicketSpace[];
  next_cursor?: string | null;
}

export const createTicket = (payload: { subject: string; description: string }) =>
  api.post<TicketEnvelope>("/tickets", payload);

export const listTickets = (opts?: {
  status?: TicketStatus;
  assignee_admin_sub?: string;
  owner_sub?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.assignee_admin_sub) params.assignee_admin_sub = opts.assignee_admin_sub;
  if (opts?.owner_sub) params.owner_sub = opts.owner_sub;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<TicketListEnvelope>("/tickets", params);
};

export const getTicket = (ticketId: string) => api.get<TicketEnvelope>(`/tickets/${ticketId}`);

export const assignTicket = (ticketId: string, assigneeAdminSub: string) =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/assign`, { assignee_admin_sub: assigneeAdminSub });

export const addTicketMessage = (ticketId: string, body: string) =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/messages`, { body });

export const setTicketStatus = (ticketId: string, status: TicketStatusWritable) =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/status`, { status });

export const getAdminTicketSummary = (staleAfterSeconds?: number) =>
  api.get<TicketAdminSummaryEnvelope>(
    "/tickets/admin/summary",
    staleAfterSeconds ? { stale_after_seconds: String(staleAfterSeconds) } : undefined,
  );

export const createTicketSpace = (payload: { name: string; visibility: "private" | "shared" }) =>
  api.post<TicketSpaceEnvelope>("/ticket-spaces", payload);

export const listTicketSpaces = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<TicketSpaceListEnvelope>("/ticket-spaces", params);
};

export const getTicketSpace = (spaceId: string) => api.get<TicketSpaceEnvelope>(`/ticket-spaces/${spaceId}`);

export const addTicketSpaceMember = (spaceId: string, payload: { member_sub: string; role: SpaceRole }) =>
  api.post<TicketSpaceEnvelope>(`/ticket-spaces/${spaceId}/members`, payload);

export const removeTicketSpaceMember = (spaceId: string, memberSub: string) =>
  api.del<TicketSpaceEnvelope>(`/ticket-spaces/${spaceId}/members/${encodeURIComponent(memberSub)}`);

export const listSpaceTickets = (
  spaceId: string,
  opts?: { status?: TicketStatus; assignee_sub?: string; cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.assignee_sub) params.assignee_sub = opts.assignee_sub;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<TicketListEnvelope>(`/ticket-spaces/${spaceId}/tickets`, params);
};

export const getSpaceTicket = (spaceId: string, ticketId: string) =>
  api.get<TicketEnvelope>(`/ticket-spaces/${spaceId}/tickets/${ticketId}`);

export const assignSpaceTicket = (spaceId: string, ticketId: string, assignee_sub: string) =>
  api.post<TicketEnvelope>(`/ticket-spaces/${spaceId}/tickets/${ticketId}/assign`, { assignee_sub });

export const addSpaceTicketMessage = (spaceId: string, ticketId: string, body: string) =>
  api.post<TicketEnvelope>(`/ticket-spaces/${spaceId}/tickets/${ticketId}/messages`, { body });

export const setSpaceTicketStatus = (spaceId: string, ticketId: string, status: TicketStatusWritable) =>
  api.post<TicketEnvelope>(`/ticket-spaces/${spaceId}/tickets/${ticketId}/status`, { status });
