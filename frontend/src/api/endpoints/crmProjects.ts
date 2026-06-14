import { api } from "@/api/client";

// ─── SuiteCRM PROJECTS (PRJ) endpoint wrappers ─────────────────────────────
//
// Live backend router (source of truth): app/routers/crm_projects.py
//   prefix = /v1/crm/projects
//   gated by S.crm_projects_enabled (CRM_PROJECTS_ENABLED, default OFF) → 404 when off
//
// TS interfaces below mirror the live Pydantic models in app/models.py
// (CrmProject*, CrmProjectTask*, CrmMilestone*, CrmTemplate*, members,
//  status history, contact links).

// ─── Enums ─────────────────────────────────────────────────────────────────

export type CrmProjectStatus =
  | "draft"
  | "in_review"
  | "underway"
  | "completed"
  | "deferred";

export type CrmProjectResourceType = "user" | "contact";

export type CrmProjectMemberRole = "owner" | "member" | "viewer";

// ─── Project header (PRJ-002) ────────────────────────────────────────────────

export interface CrmProjectOut {
  id: string;
  owner_sub: string;
  name: string;
  description?: string | null;
  status: CrmProjectStatus;
  priority: number;
  start_date?: number | null;
  end_date?: number | null;
  assigned_user_sub?: string | null;
  account_id?: string | null;
  created_at: number;
  updated_at: number;
}

export interface CrmProjectListResp {
  items: CrmProjectOut[];
  cursor?: string | null;
}

export interface CrmProjectCreateIn {
  name: string;
  description?: string | null;
  status?: CrmProjectStatus;
  priority?: number;
  start_date?: number | null;
  end_date?: number | null;
  assigned_user_sub?: string | null;
  account_id?: string | null;
}

export interface CrmProjectUpdateIn {
  name?: string;
  description?: string | null;
  status?: CrmProjectStatus;
  priority?: number;
  start_date?: number | null;
  end_date?: number | null;
  assigned_user_sub?: string | null;
  account_id?: string | null;
}

// ─── Tasks (PRJ-003/004/005) ─────────────────────────────────────────────────

export interface CrmProjectTaskModel {
  id: string;
  project_id: string;
  owner_sub: string;
  name: string;
  description?: string | null;
  task_order: number;
  duration_days: number;
  start_date?: number | null;
  end_date?: number | null;
  percent_complete: number;
  is_milestone: boolean;
  assigned_user_sub?: string | null;
  predecessor_task_ids: string[];
  project_resource_type: CrmProjectResourceType;
  linked_contact_id?: string | null;
  created_at: number;
  updated_at: number;
}

export interface CrmProjectTaskListResp {
  items: CrmProjectTaskModel[];
  cursor?: string | null;
}

export interface CrmProjectTaskCreateReq {
  name: string;
  description?: string | null;
  task_order?: number;
  duration_days?: number;
  start_date?: number | null;
  end_date?: number | null;
  percent_complete?: number;
  is_milestone?: boolean;
  assigned_user_sub?: string | null;
  predecessor_task_ids?: string[];
  project_resource_type?: CrmProjectResourceType | null;
  linked_contact_id?: string | null;
}

export interface CrmProjectTaskUpdateReq {
  name?: string;
  description?: string | null;
  task_order?: number;
  duration_days?: number;
  start_date?: number | null;
  end_date?: number | null;
  percent_complete?: number;
  is_milestone?: boolean;
  assigned_user_sub?: string | null;
  predecessor_task_ids?: string[];
  project_resource_type?: CrmProjectResourceType | null;
  linked_contact_id?: string | null;
}

export interface CrmProjectTaskReorderReq {
  task_ids: string[];
}

// ─── Workload (PRJ-004) ──────────────────────────────────────────────────────

export interface CrmTaskWorkloadEntry {
  assignee_key: string;
  resource_type: CrmProjectResourceType;
  assigned_id: string;
  task_count: number;
  overdue_count: number;
}

export interface CrmProjectWorkloadResp {
  project_id: string;
  entries: CrmTaskWorkloadEntry[];
}

// ─── Milestones (PRJ-005) ────────────────────────────────────────────────────

export interface CrmMilestoneSummaryItem {
  id: string;
  project_id: string;
  name: string;
  task_order: number;
  start_date?: number | null;
  end_date?: number | null;
  percent_complete: number;
  on_track: boolean;
  overdue: boolean;
  created_at: number;
  updated_at: number;
}

export interface CrmMilestoneSummaryResp {
  items: CrmMilestoneSummaryItem[];
  cursor?: string | null;
  total_milestones: number;
  overdue_count: number;
  on_track_count: number;
  no_date_count: number;
}

// ─── Templates (PRJ-006) ─────────────────────────────────────────────────────

export interface CrmTemplateTaskDef {
  template_task_id: string;
  name: string;
  description?: string | null;
  task_order: number;
  duration_days?: number;
  is_milestone?: boolean;
  predecessor_template_task_ids?: string[];
}

export interface CrmProjectTemplateModel {
  id: string;
  owner_sub: string;
  name: string;
  description?: string | null;
  task_defs: CrmTemplateTaskDef[];
  created_at: number;
  updated_at: number;
}

export interface CrmTemplateListOut {
  items: CrmProjectTemplateModel[];
  cursor?: string | null;
}

export interface CrmTemplateCreateIn {
  name: string;
  description?: string | null;
  task_defs?: CrmTemplateTaskDef[];
}

export interface CrmTemplateFromProjectIn {
  name: string;
  description?: string | null;
}

export interface CrmTemplateInstantiateIn {
  project_name: string;
  start_date?: number | null;
}

// ─── Members (PRJ-007) ───────────────────────────────────────────────────────

export interface CrmProjectMemberOut {
  project_id: string;
  user_sub: string;
  role: CrmProjectMemberRole;
  added_by: string;
  added_at: number;
}

export interface CrmProjectMemberListResp {
  items: CrmProjectMemberOut[];
  cursor?: string | null;
}

export interface CrmProjectAddMemberIn {
  user_sub: string;
  role?: CrmProjectMemberRole;
}

export interface CrmProjectUpdateMemberIn {
  role: CrmProjectMemberRole;
}

// ─── Status history (PRJ-009) ────────────────────────────────────────────────

export interface CrmProjectStatusHistoryEntry {
  project_id: string;
  from_status?: string | null;
  to_status: string;
  changed_by: string;
  changed_at: number;
  event_id: string;
}

export interface CrmProjectStatusHistoryResp {
  items: CrmProjectStatusHistoryEntry[];
  cursor?: string | null;
}

// ─── Contact links (PRJ-010) ─────────────────────────────────────────────────

export interface CrmProjectContactLinkOut {
  project_id: string;
  linked_entity_id: string;
  linked_entity_type: string;
  added_by: string;
  added_at: number;
  note?: string | null;
}

export interface CrmProjectContactLinkListResp {
  items: CrmProjectContactLinkOut[];
  cursor?: string | null;
}

export interface CrmProjectAddContactLinkIn {
  linked_entity_id: string;
  linked_entity_type?: string;
  note?: string | null;
}

// ===========================================================================
// API wrappers — EXACT live paths under /v1/crm/projects
// ===========================================================================

const BASE = "/v1/crm/projects";

// ─── Projects ────────────────────────────────────────────────────────────────

export const listCrmProjects = (opts?: {
  limit?: number;
  cursor?: string;
  status?: CrmProjectStatus;
  name_query?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.status) params["status"] = opts.status;
  if (opts?.name_query) params["name_query"] = opts.name_query;
  return api.get<CrmProjectListResp>(BASE, params);
};

export const createCrmProject = (body: CrmProjectCreateIn) =>
  api.post<CrmProjectOut>(BASE, body);

export const getCrmProject = (projectId: string) =>
  api.get<CrmProjectOut>(`${BASE}/${projectId}`);

export const updateCrmProject = (projectId: string, body: CrmProjectUpdateIn) =>
  api.patch<CrmProjectOut>(`${BASE}/${projectId}`, body);

export const deleteCrmProject = (projectId: string) =>
  api.del<{ ok: boolean } | Record<string, unknown>>(`${BASE}/${projectId}`);

// ─── Tasks ───────────────────────────────────────────────────────────────────

export const listProjectTasks = (
  projectId: string,
  opts?: { limit?: number; cursor?: string; milestones_only?: boolean },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.milestones_only) params["milestones_only"] = "true";
  return api.get<CrmProjectTaskListResp>(`${BASE}/${projectId}/tasks`, params);
};

export const createProjectTask = (projectId: string, body: CrmProjectTaskCreateReq) =>
  api.post<CrmProjectTaskModel>(`${BASE}/${projectId}/tasks`, body);

export const getProjectTask = (projectId: string, taskId: string) =>
  api.get<CrmProjectTaskModel>(`${BASE}/${projectId}/tasks/${taskId}`);

export const updateProjectTask = (
  projectId: string,
  taskId: string,
  body: CrmProjectTaskUpdateReq,
) => api.patch<CrmProjectTaskModel>(`${BASE}/${projectId}/tasks/${taskId}`, body);

export const deleteProjectTask = (projectId: string, taskId: string) =>
  api.del<{ ok: boolean } | Record<string, unknown>>(
    `${BASE}/${projectId}/tasks/${taskId}`,
  );

export const reorderProjectTasks = (projectId: string, body: CrmProjectTaskReorderReq) =>
  api.put<{ items: CrmProjectTaskModel[] }>(`${BASE}/${projectId}/tasks/order`, body);

// ─── Milestones / Workload ───────────────────────────────────────────────────

export const getMilestoneSummary = (
  projectId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmMilestoneSummaryResp>(`${BASE}/${projectId}/milestones`, params);
};

export const getProjectWorkload = (projectId: string) =>
  api.get<CrmProjectWorkloadResp>(`${BASE}/${projectId}/workload`);

// ─── Templates ───────────────────────────────────────────────────────────────

export const listTemplates = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmTemplateListOut>(`${BASE}/templates`, params);
};

export const getTemplate = (templateId: string) =>
  api.get<CrmProjectTemplateModel>(`${BASE}/templates/${templateId}`);

export const createTemplate = (body: CrmTemplateCreateIn) =>
  api.post<CrmProjectTemplateModel>(`${BASE}/templates`, body);

export const createTemplateFromProject = (
  projectId: string,
  body: CrmTemplateFromProjectIn,
) => api.post<CrmProjectTemplateModel>(`${BASE}/templates/from-project/${projectId}`, body);

export const deleteTemplate = (templateId: string) =>
  api.del<{ ok: boolean } | Record<string, unknown>>(`${BASE}/templates/${templateId}`);

export const instantiateFromTemplate = (
  templateId: string,
  body: CrmTemplateInstantiateIn,
) => api.post<CrmProjectOut>(`${BASE}/templates/${templateId}/instantiate`, body);

// ─── Members ─────────────────────────────────────────────────────────────────

export const listProjectMembers = (
  projectId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmProjectMemberListResp>(`${BASE}/${projectId}/members`, params);
};

export const addProjectMember = (projectId: string, body: CrmProjectAddMemberIn) =>
  api.post<CrmProjectMemberOut>(`${BASE}/${projectId}/members`, body);

export const updateProjectMember = (
  projectId: string,
  userSub: string,
  body: CrmProjectUpdateMemberIn,
) => api.patch<CrmProjectMemberOut>(`${BASE}/${projectId}/members/${userSub}`, body);

export const removeProjectMember = (projectId: string, userSub: string) =>
  api.del<{ ok: boolean } | Record<string, unknown>>(
    `${BASE}/${projectId}/members/${userSub}`,
  );

// ─── Contact links ───────────────────────────────────────────────────────────

export const listContactLinks = (
  projectId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmProjectContactLinkListResp>(
    `${BASE}/${projectId}/contact-links`,
    params,
  );
};

export const addContactLink = (projectId: string, body: CrmProjectAddContactLinkIn) =>
  api.post<CrmProjectContactLinkOut>(`${BASE}/${projectId}/contact-links`, body);

export const removeContactLink = (projectId: string, entityId: string) =>
  api.del<{ ok: boolean } | Record<string, unknown>>(
    `${BASE}/${projectId}/contact-links/${entityId}`,
  );

// ─── Status history ──────────────────────────────────────────────────────────

export const getStatusHistory = (
  projectId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmProjectStatusHistoryResp>(
    `${BASE}/${projectId}/status-history`,
    params,
  );
};
