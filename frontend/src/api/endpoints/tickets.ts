import { api } from "@/api/client";

export type TicketStatus = "open" | "in_progress" | "waiting_on_user" | "done" | "cancelled";
export type TicketStatusWritable = TicketStatus | "reopened";

// B8/B9 B-SUP2 #15 / B-HELP2 #17: the ticket OWNER may close ("close" -> done)
// or cancel ("cancel" -> cancelled) their own ticket via the dedicated endpoint.
export type TicketCloseAction = "close" | "cancel";

// B-HELP-SHAPE / B10 B-HELPMEDIA: typed projection of one ticket-message media
// item. Numeric fields are plain JSON numbers (backend coerces DDB Decimals).
export interface TicketMedia {
  kind: string; // "image" | "video" | "file" | ...
  url?: string | null;
  path?: string | null;
  name?: string | null;
  content_type?: string | null;
  size_bytes?: number | null;
  width?: number | null;
  height?: number | null;
  thumbnail?: string | null;
}

export interface TicketMessage {
  message_id: string;
  sender_sub: string;
  sender_role: string;
  body: string;
  // B9 B-HELP2 #14: optional inline image attachment.
  image_url?: string | null;
  // B10 B-HELPMEDIA: images/videos/files + file-mgr refs on a ticket message.
  media?: TicketMedia[];
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

export const addTicketMessage = (
  ticketId: string,
  body: string,
  opts?: { image_url?: string; media?: Array<Record<string, unknown>> },
) =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/messages`, {
    body,
    ...(opts?.image_url ? { image_url: opts.image_url } : {}),
    ...(opts?.media ? { media: opts.media } : {}),
  });

export const setTicketStatus = (ticketId: string, status: TicketStatusWritable) =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/status`, { status });

// B8 B-SUP2 #15: the ticket OWNER (or an admin) closes/cancels their OWN ticket.
// close -> "done"; cancel -> "cancelled". Owner-authorized (unlike setTicketStatus,
// which is admin-only server-side).
export const closeOwnTicket = (ticketId: string, action: TicketCloseAction = "close") =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/close`, { action });

// B9 B-HELP2 #17: the ticket OWNER (or an admin) reopens a closed/cancelled ticket.
export const reopenOwnTicket = (ticketId: string) =>
  api.post<TicketEnvelope>(`/tickets/${ticketId}/reopen`, {});

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

// ─── Boards (TKB-010) ─────────────────────────────────────────────
// /boards mirrors /ticket-spaces; board_id == space_id (physical PK stays
// SPACE#{id}). The old *TicketSpace* wrappers above remain exported for
// backward compatibility during the rename.

export type BoardRole = "owner" | "editor" | "viewer";

export interface BoardMember {
  board_id: string;
  space_id: string;
  member_sub: string;
  role: BoardRole;
  created_at: number;
  updated_at: number;
}

export interface BoardColumn {
  column_id: string;
  title: string;
  status_key: TicketStatus | string;
  order: number;
  wip_limit?: number | null;
  color?: string | null;
}

export interface Board {
  board_id: string;
  space_id: string;
  owner_sub: string;
  name: string;
  visibility: "private" | "shared";
  created_at: number;
  updated_at: number;
  columns: BoardColumn[];
  members: BoardMember[];
}

export interface BoardEnvelope {
  board: Board;
}

export interface BoardListEnvelope {
  items: Board[];
  next_cursor?: string | null;
}

export interface BoardColumnsEnvelope {
  board_id: string;
  columns: BoardColumn[];
}

// A board ticket carries the same shape as a helpdesk ticket plus board_id.
// labels/complexity are optional: the backend BoardTicketOut model may not
// surface them yet (follow-up), so they are typed but not required.
export interface BoardTicket extends Ticket {
  board_id?: string | null;
  labels?: string[];
  complexity?: string | null;
}

export interface BoardTicketEnvelope {
  ticket: BoardTicket;
}

export interface BoardTicketListEnvelope {
  items: BoardTicket[];
  next_cursor?: string | null;
}

// Column update payload (PUT /boards/{id}/columns).
export interface BoardColumnInput {
  column_id?: string;
  title: string;
  status_key: TicketStatus | string;
  order?: number;
  wip_limit?: number | null;
  color?: string | null;
}

export const createBoard = (payload: { name: string; visibility: "private" | "shared" }) =>
  api.post<BoardEnvelope>("/boards", payload);

export const listBoards = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<BoardListEnvelope>("/boards", params);
};

export const getBoard = (boardId: string) => api.get<BoardEnvelope>(`/boards/${boardId}`);

export const addBoardMember = (boardId: string, payload: { member_sub: string; role: BoardRole }) =>
  api.post<BoardEnvelope>(`/boards/${boardId}/members`, payload);

export const removeBoardMember = (boardId: string, memberSub: string) =>
  api.del<BoardEnvelope>(`/boards/${boardId}/members/${encodeURIComponent(memberSub)}`);

export const getBoardColumns = (boardId: string) =>
  api.get<BoardColumnsEnvelope>(`/boards/${boardId}/columns`);

export const updateBoardColumns = (boardId: string, columns: BoardColumnInput[]) =>
  api.put<BoardEnvelope>(`/boards/${boardId}/columns`, { columns });

export const createBoardTicket = (boardId: string, payload: { subject: string; description: string }) =>
  api.post<BoardTicketEnvelope>(`/boards/${boardId}/tickets`, payload);

export const listBoardTickets = (
  boardId: string,
  opts?: { status?: TicketStatus; assignee_sub?: string; cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.assignee_sub) params.assignee_sub = opts.assignee_sub;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<BoardTicketListEnvelope>(`/boards/${boardId}/tickets`, params);
};

export const getBoardTicket = (boardId: string, ticketId: string) =>
  api.get<BoardTicketEnvelope>(`/boards/${boardId}/tickets/${ticketId}`);

export const assignBoardTicket = (boardId: string, ticketId: string, assignee_sub: string) =>
  api.post<BoardTicketEnvelope>(`/boards/${boardId}/tickets/${ticketId}/assign`, { assignee_sub });

export const addBoardTicketMessage = (boardId: string, ticketId: string, body: string) =>
  api.post<BoardTicketEnvelope>(`/boards/${boardId}/tickets/${ticketId}/messages`, { body });

export const setBoardTicketStatus = (boardId: string, ticketId: string, status: TicketStatusWritable) =>
  api.post<BoardTicketEnvelope>(`/boards/${boardId}/tickets/${ticketId}/status`, { status });
