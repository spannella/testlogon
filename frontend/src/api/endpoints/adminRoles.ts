import { api } from "@/api/client";

export type AdminProfileType = "general" | "scoped";
export type AdminScope = "auth_support" | "billing_support" | "content_moderation";

export interface AdminProfile {
  type: AdminProfileType;
  scopes?: AdminScope[];
}

export interface RoleGrantReq {
  target_user_sub: string;
  role: "admin";
  reason: string;
  admin_profile_type?: AdminProfileType;
  admin_scopes?: AdminScope[];
}

export interface RoleUpdateProfileReq {
  target_user_sub: string;
  reason: string;
  admin_profile_type: AdminProfileType;
  admin_scopes?: AdminScope[];
}

export interface RoleGrantRevokeResp {
  ok: boolean;
  target_user_sub: string;
  role: "admin" | "user";
  event_id: string;
  admin_profile?: AdminProfile;
}

export interface RoleAuditItem {
  event_id: string;
  action: "grant" | "revoke" | "update_profile" | string;
  actor_sub: string;
  target_user_sub: string;
  previous_role: string;
  new_role: string;
  reason: string;
  previous_admin_profile?: AdminProfile | null;
  new_admin_profile?: AdminProfile | null;
  ip?: string;
  request_id?: string;
  ts: number;
}

export interface RoleAuditResp {
  items: RoleAuditItem[];
  cursor?: string | null;
}

export function grantAdminRole(body: RoleGrantReq) {
  return api.post<RoleGrantRevokeResp>("/admin/roles/grant", body);
}

export function updateAdminProfile(body: RoleUpdateProfileReq) {
  return api.post<RoleGrantRevokeResp>("/admin/roles/update-profile", body);
}

export function revokeAdminRole(body: Pick<RoleGrantReq, "target_user_sub" | "role" | "reason">) {
  return api.post<RoleGrantRevokeResp>("/admin/roles/revoke", body);
}

export function listRoleAudit(params?: {
  actor_sub?: string;
  start_ts?: string;
  end_ts?: string;
  limit?: string;
  cursor?: string;
}) {
  return api.get<RoleAuditResp>("/admin/roles/audit", params);
}
