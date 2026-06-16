/**
 * SuiteCRM SECURITY/STUDIO (STU) cluster — API endpoint wrappers.
 *
 * Covers three LIVE backend routers (all admin/root-only):
 *   - ACL roles            /ui/admin/crm/acl-roles            (STU-002 / STU-003)
 *   - Security groups      /ui/admin/crm/security-groups      (STU-004)
 *   - Studio custom fields /ui/admin/studio/fields/...        (STU-011)
 *
 * Flags: crm_acl_enabled + crm_studio_enabled (default OFF → routers not
 * registered → 404 on every path). Callers handle the disabled state via
 * ApiError.status.
 *
 * TS interfaces are defined INLINE here (mirroring app/models.py) and exported.
 */
import { api } from "@/api/client";

// ─── ACL: permission matrix ──────────────────────────────────────────────────

/** Seven per-module boolean permission flags (CrmAclPermissionMatrix). */
export interface CrmAclPermissionMatrix {
  create?: boolean;
  read?: boolean;
  update?: boolean;
  delete?: boolean;
  export?: boolean;
  /** Reserved word in Python; serialized as "import" by the backend. */
  import?: boolean;
  mass_update?: boolean;
}

/** The seven canonical actions, in display order. */
export const ACL_ACTIONS: Array<{ key: keyof CrmAclPermissionMatrix; label: string }> = [
  { key: "create", label: "Create" },
  { key: "read", label: "Read" },
  { key: "update", label: "Update" },
  { key: "delete", label: "Delete" },
  { key: "export", label: "Export" },
  { key: "import", label: "Import" },
  { key: "mass_update", label: "Mass Update" },
];

/** Common CRM modules used by the ACL matrix (free-form on the backend). */
export const ACL_MODULES: string[] = [
  "contacts",
  "accounts",
  "leads",
  "opportunities",
  "cases",
  "projects",
  "tickets",
];

// ─── ACL: role models ────────────────────────────────────────────────────────

export interface CrmAclRole {
  role_id: string;
  name: string;
  description: string;
  permissions: Record<string, CrmAclPermissionMatrix>;
  created_at: number;
  created_by_sub: string;
  updated_at?: number | null;
  updated_by_sub?: string | null;
}

export interface CrmAclRoleCreateIn {
  name: string;
  description?: string;
  permissions?: Record<string, CrmAclPermissionMatrix>;
}

export interface CrmAclRoleUpdateIn {
  name?: string;
  description?: string;
  permissions?: Record<string, CrmAclPermissionMatrix>;
}

export interface CrmAclRoleListOut {
  roles: CrmAclRole[];
  next_cursor?: string | null;
}

export interface CrmAclAssignmentOut {
  role_id: string;
  user_sub: string;
  assigned_by_sub: string;
  assigned_at: number;
}

export interface CrmAclGroupAssignmentOut {
  role_id: string;
  group_key: string;
  assigned_by_sub: string;
  assigned_at: number;
}

export interface CrmAclRoleAssignmentsOut {
  role_id: string;
  /** Free-form user assignment dicts from the backend. */
  user_assignments: Array<Record<string, unknown>>;
  group_assignments: CrmAclGroupAssignmentOut[];
}

export interface CrmEffectivePermissionsOut {
  user_sub: string;
  permissions: Record<string, Record<string, boolean>>;
}

// ─── ACL: role endpoints ─────────────────────────────────────────────────────

const ACL_BASE = "/ui/admin/crm/acl-roles";

export const listAclRoles = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<CrmAclRoleListOut>(`${ACL_BASE}/`, params);
};

export const getAclRole = (roleId: string) =>
  api.get<CrmAclRole>(`${ACL_BASE}/${encodeURIComponent(roleId)}`);

export const createAclRole = (body: CrmAclRoleCreateIn) =>
  api.post<CrmAclRole>(`${ACL_BASE}/`, body);

export const updateAclRole = (roleId: string, body: CrmAclRoleUpdateIn) =>
  api.patch<CrmAclRole>(`${ACL_BASE}/${encodeURIComponent(roleId)}`, body);

export const deleteAclRole = (roleId: string) =>
  api.del<void>(`${ACL_BASE}/${encodeURIComponent(roleId)}`);

export const getMyCrmPermissions = () =>
  api.get<CrmEffectivePermissionsOut>(`${ACL_BASE}/my-permissions`);

// ─── ACL: assignments ────────────────────────────────────────────────────────

export const listRoleAssignments = (roleId: string) =>
  api.get<CrmAclRoleAssignmentsOut>(`${ACL_BASE}/${encodeURIComponent(roleId)}/assignments`);

export const assignRoleToUser = (roleId: string, userSub: string) =>
  api.post<CrmAclAssignmentOut>(`${ACL_BASE}/${encodeURIComponent(roleId)}/assignments`, {
    user_sub: userSub,
  });

export const revokeRoleFromUser = (roleId: string, userSub: string) =>
  api.del<void>(
    `${ACL_BASE}/${encodeURIComponent(roleId)}/assignments/${encodeURIComponent(userSub)}`,
  );

export const assignRoleToGroup = (roleId: string, groupKey: string) =>
  api.post<CrmAclGroupAssignmentOut>(
    `${ACL_BASE}/${encodeURIComponent(roleId)}/group-assignments`,
    { group_key: groupKey },
  );

export const revokeRoleFromGroup = (roleId: string, groupKey: string) =>
  api.del<void>(
    `${ACL_BASE}/${encodeURIComponent(roleId)}/group-assignments/${encodeURIComponent(groupKey)}`,
  );

// ─── Security groups ─────────────────────────────────────────────────────────

export interface CrmSecurityGroup {
  group_id: string;
  name: string;
  description: string;
  owner_sub: string;
  created_at: number;
  is_global: boolean;
  member_count: number;
  record_count: number;
}

export interface CrmSecurityGroupMember {
  user_sub: string;
  added_by_sub: string;
  added_at: number;
  can_edit: boolean;
}

export interface CrmSecurityGroupRecord {
  entity_type: string;
  record_id: string;
  record_ref: string;
  assigned_by_sub: string;
  created_at: number;
}

export interface CrmSecurityGroupDetail {
  group: CrmSecurityGroup;
  members: CrmSecurityGroupMember[];
  records: CrmSecurityGroupRecord[];
}

export interface CrmSecurityGroupListOut {
  groups: CrmSecurityGroup[];
  next_cursor?: string | null;
}

export interface CrmSecurityGroupCreateIn {
  name: string;
  description?: string;
  is_global?: boolean;
}

const SG_BASE = "/ui/admin/crm/security-groups";

export const listSecurityGroups = (opts?: {
  cursor?: string;
  limit?: number;
  is_global?: boolean;
}) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.is_global !== undefined) params["is_global"] = String(opts.is_global);
  return api.get<CrmSecurityGroupListOut>(`${SG_BASE}/`, params);
};

export const getSecurityGroup = (groupId: string) =>
  api.get<CrmSecurityGroupDetail>(`${SG_BASE}/${encodeURIComponent(groupId)}`);

export const createSecurityGroup = (body: CrmSecurityGroupCreateIn) =>
  api.post<CrmSecurityGroup>(`${SG_BASE}/`, body);

export const deleteSecurityGroup = (groupId: string) =>
  api.del<void>(`${SG_BASE}/${encodeURIComponent(groupId)}`);

export const addSecurityGroupMember = (
  groupId: string,
  userSub: string,
  canEdit: boolean,
) =>
  api.post<void>(`${SG_BASE}/${encodeURIComponent(groupId)}/members`, {
    user_sub: userSub,
    can_edit: canEdit,
  });

export const removeSecurityGroupMember = (groupId: string, userSub: string) =>
  api.del<void>(
    `${SG_BASE}/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userSub)}`,
  );

export const assignSecurityGroupRecord = (
  groupId: string,
  entityType: string,
  recordId: string,
) =>
  api.post<void>(`${SG_BASE}/${encodeURIComponent(groupId)}/records`, {
    entity_type: entityType,
    record_id: recordId,
  });

export const unassignSecurityGroupRecord = (
  groupId: string,
  entityType: string,
  recordId: string,
) =>
  api.del<void>(
    `${SG_BASE}/${encodeURIComponent(groupId)}/records/${encodeURIComponent(entityType)}/${encodeURIComponent(recordId)}`,
  );

// ─── Studio: custom fields ───────────────────────────────────────────────────

/** Entity types that accept custom fields (ALLOWED_ENTITY_TYPES). */
export const STUDIO_ENTITY_TYPES: string[] = [
  "contact",
  "ticket",
  "opportunity",
  "lead",
  "case",
  "project",
  "account",
];

export type StudioFieldType =
  | "text"
  | "integer"
  | "decimal"
  | "boolean"
  | "date"
  | "picklist"
  | "multi_picklist";

/** Field types that accept custom fields (ALLOWED_FIELD_TYPES). */
export const STUDIO_FIELD_TYPES: StudioFieldType[] = [
  "text",
  "integer",
  "decimal",
  "boolean",
  "date",
  "picklist",
  "multi_picklist",
];

export interface StudioField {
  entity_type: string;
  field_key: string;
  label: string;
  field_type: string;
  required: boolean;
  default_value: unknown;
  picklist_name?: string | null;
  max_length: number;
  min_value?: number | null;
  max_value?: number | null;
  sort_order: number;
  is_active: boolean;
  created_by_sub: string;
  created_at: number;
  updated_by_sub: string;
  updated_at: number;
}

export interface StudioFieldListOut {
  fields: StudioField[];
  next_cursor?: string | null;
  total_count?: number | null;
}

export interface StudioFieldCreateIn {
  field_key: string;
  label: string;
  field_type: StudioFieldType;
  required?: boolean;
  default_value?: unknown;
  picklist_name?: string | null;
  max_length?: number;
  min_value?: number | null;
  max_value?: number | null;
  sort_order?: number;
}

export interface StudioFieldUpdateIn {
  label?: string;
  required?: boolean;
  default_value?: unknown;
  max_length?: number;
  min_value?: number | null;
  max_value?: number | null;
  sort_order?: number;
  reactivate?: boolean;
}

const STUDIO_BASE = "/ui/admin/studio/fields";

export const listStudioFields = (
  entityType: string,
  opts?: { include_inactive?: boolean; cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.include_inactive) params["include_inactive"] = "true";
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<StudioFieldListOut>(`${STUDIO_BASE}/${encodeURIComponent(entityType)}`, params);
};

export const getStudioField = (entityType: string, fieldKey: string) =>
  api.get<StudioField>(
    `${STUDIO_BASE}/${encodeURIComponent(entityType)}/${encodeURIComponent(fieldKey)}`,
  );

export const createStudioField = (entityType: string, body: StudioFieldCreateIn) =>
  api.post<StudioField>(`${STUDIO_BASE}/${encodeURIComponent(entityType)}`, body);

export const updateStudioField = (
  entityType: string,
  fieldKey: string,
  body: StudioFieldUpdateIn,
) =>
  api.patch<StudioField>(
    `${STUDIO_BASE}/${encodeURIComponent(entityType)}/${encodeURIComponent(fieldKey)}`,
    body,
  );

export const deactivateStudioField = (entityType: string, fieldKey: string) =>
  api.del<void>(
    `${STUDIO_BASE}/${encodeURIComponent(entityType)}/${encodeURIComponent(fieldKey)}`,
  );
