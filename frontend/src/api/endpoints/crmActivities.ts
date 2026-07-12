import { api } from "@/api/client";

// ─── SuiteCRM ACTIVITIES (ACT) endpoint wrappers ───────────────────────────
//
// Live backend routers (source of truth):
//   - /ui/calls/logs                 (ACT-006/007 — CRM Call Logs)
//   - /ui/crm/tasks                  (ACT-008 — CRM Tasks)
//   - /ui/crm/timeline               (ACT-009 — CRM Activity Timeline)
//   - /ui/crm/notes                  (ACT-010 — CRM Notes)
//
// All routers are gated by S.crm_activities_enabled (+ a per-module flag).
// When disabled, the backend returns 404 — callers should handle gracefully.
//
// TS interfaces below mirror the live Pydantic models in app/models.py.

// ─── Shared link types ─────────────────────────────────────────────────────

export type CrmEntityType = "contact" | "lead" | "account" | "opportunity";

// ─── Call Logs (ACT-006 / ACT-007) ─────────────────────────────────────────

export type CallDirection = "inbound" | "outbound";
export type CallType = "audio" | "video" | "phone";
export type CallOutcome =
  | "connected"
  | "not_connected"
  | "left_message"
  | "wrong_number"
  | "busy";

export interface CallLogCreateIn {
  subject: string;
  description?: string;
  direction: CallDirection;
  duration_seconds?: number;
  outcome: CallOutcome;
  call_type?: CallType;
  contact_user_sub?: string | null;
  linked_entity_type?: CrmEntityType | null;
  linked_entity_id?: string | null;
}

export interface CallLogUpdateIn {
  subject?: string;
  description?: string;
  outcome?: CallOutcome;
}

export interface CallLogOut {
  call_id: string;
  user_sub: string;
  subject: string;
  description: string;
  direction: string;
  duration_seconds: number;
  outcome: string;
  call_type: string;
  contact_user_sub?: string | null;
  linked_entity_type?: string | null;
  linked_entity_id?: string | null;
  created_at: number;
  updated_at: number;
}

export interface CallLogListResponse {
  items: CallLogOut[];
  next_cursor?: string | null;
}

export const listCallLogs = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CallLogListResponse>("/ui/calls/logs", params);
};

export const listCallLogsForEntity = (
  entityType: string,
  entityId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {
    entity_type: entityType,
    entity_id: entityId,
  };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CallLogListResponse>("/ui/calls/logs/by-entity", params);
};

export const getCallLog = (callId: string) =>
  api.get<CallLogOut>(`/ui/calls/logs/${encodeURIComponent(callId)}`);

export const createCallLog = (body: CallLogCreateIn) =>
  api.post<CallLogOut>("/ui/calls/logs", body);

export const updateCallLog = (callId: string, body: CallLogUpdateIn) =>
  api.patch<CallLogOut>(`/ui/calls/logs/${encodeURIComponent(callId)}`, body);

export const deleteCallLog = (callId: string) =>
  api.del<{ ok: boolean }>(`/ui/calls/logs/${encodeURIComponent(callId)}`);

// ─── Tasks (ACT-008) ────────────────────────────────────────────────────────

export type CrmTaskStatus =
  | "not_started"
  | "in_progress"
  | "completed"
  | "deferred"
  | "waiting";

export type CrmTaskPriority = "low" | "medium" | "high" | "urgent";

export interface CrmTaskCreateIn {
  subject: string;
  description?: string;
  status?: CrmTaskStatus;
  priority?: CrmTaskPriority;
  due_date_ts?: number | null;
  assignee_sub?: string | null;
  linked_entity_type?: CrmEntityType | null;
  linked_entity_id?: string | null;
}

export interface CrmTaskUpdateIn {
  subject?: string;
  description?: string;
  status?: CrmTaskStatus;
  priority?: CrmTaskPriority;
  due_date_ts?: number | null;
  assignee_sub?: string | null;
}

export interface CrmTaskOut {
  task_id: string;
  user_sub: string;
  subject: string;
  description: string;
  status: string;
  priority: string;
  due_date_ts?: number | null;
  assignee_sub?: string | null;
  linked_entity_type?: string | null;
  linked_entity_id?: string | null;
  created_at: number;
  updated_at: number;
}

export interface CrmTaskListOut {
  items: CrmTaskOut[];
  next_cursor?: string | null;
  count: number;
}

export const listTasks = (opts?: {
  limit?: number;
  cursor?: string;
  status?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.status) params["status"] = opts.status;
  return api.get<CrmTaskListOut>("/ui/crm/tasks", params);
};

export const getTask = (taskId: string) =>
  api.get<CrmTaskOut>(`/ui/crm/tasks/${encodeURIComponent(taskId)}`);

export const createTask = (body: CrmTaskCreateIn) =>
  api.post<CrmTaskOut>("/ui/crm/tasks", body);

export const updateTask = (taskId: string, body: CrmTaskUpdateIn) =>
  api.patch<CrmTaskOut>(`/ui/crm/tasks/${encodeURIComponent(taskId)}`, body);

export const deleteTask = (taskId: string) =>
  api.del<{ ok: boolean }>(`/ui/crm/tasks/${encodeURIComponent(taskId)}`);

// ─── Notes (ACT-010) ─────────────────────────────────────────────────────────

export interface CrmNoteCreateIn {
  body?: string;
  linked_entity_type?: CrmEntityType | null;
  linked_entity_id?: string | null;
}

export interface CrmNoteUpdateIn {
  body: string;
}

export interface CrmNoteOut {
  note_id: string;
  user_sub: string;
  body: string;
  linked_entity_type?: string | null;
  linked_entity_id?: string | null;
  attachment_s3_key?: string | null;
  attachment_filename?: string | null;
  attachment_content_type?: string | null;
  attachment_url?: string | null;
  created_at: number;
  updated_at: number;
}

export interface CrmNoteListOut {
  notes: CrmNoteOut[];
  next_cursor?: string | null;
}

export const listNotes = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmNoteListOut>("/ui/crm/notes", params);
};

export const listNotesByEntity = (
  entityType: string,
  entityId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {
    entity_type: entityType,
    entity_id: entityId,
  };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmNoteListOut>("/ui/crm/notes/by-entity", params);
};

export const getNote = (noteId: string) =>
  api.get<CrmNoteOut>(`/ui/crm/notes/${encodeURIComponent(noteId)}`);

export const createNote = (body: CrmNoteCreateIn) =>
  api.post<CrmNoteOut>("/ui/crm/notes", body);

export const updateNote = (noteId: string, body: string) =>
  api.patch<CrmNoteOut>(`/ui/crm/notes/${encodeURIComponent(noteId)}`, { body });

export const deleteNote = (noteId: string) =>
  api.del<{ ok: boolean }>(`/ui/crm/notes/${encodeURIComponent(noteId)}`);

export const uploadNoteAttachment = (noteId: string, file: File) => {
  const fd = new FormData();
  fd.append("file", file);
  return api.upload<CrmNoteOut>(
    `/ui/crm/notes/${encodeURIComponent(noteId)}/attachment`,
    fd,
  );
};

// ─── Activity Timeline (ACT-009) ──────────────────────────────────────────────

export type CrmActivityKind =
  | "call"
  | "task"
  | "note"
  | "calendar_event"
  | "email";

export interface CrmActivityOut {
  activity_id: string;
  entity_type: string;
  entity_id: string;
  activity_type: string; // call | task | note | calendar_event | email
  user_sub: string;
  summary: string;
  metadata: Record<string, unknown>;
  created_at: number;
}

export interface CrmActivityTimelineOut {
  entity_type: string;
  entity_id: string;
  items: CrmActivityOut[];
  next_cursor?: string | null;
}

export const getEntityTimeline = (
  entityType: string,
  entityId: string,
  opts?: { limit?: number; cursor?: string; activity_type?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.activity_type) params["activity_type"] = opts.activity_type;
  return api.get<CrmActivityTimelineOut>(
    `/ui/crm/timeline/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`,
    params,
  );
};

export const deleteTimelineEntry = (
  entityType: string,
  entityId: string,
  sk: string,
) =>
  api.del<{ ok: boolean }>(
    `/ui/crm/timeline/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}/${sk}`,
  );
