import { api } from "@/api/client";

export interface RoleGrantRevokeReq {
  target_user_sub: string;
  role: "admin";
  reason: string;
}

export interface RoleGrantRevokeResp {
  ok: boolean;
  target_user_sub: string;
  role: "admin" | "user";
  event_id: string;
}

export interface RoleAuditItem {
  event_id: string;
  action: "grant" | "revoke" | string;
  actor_sub: string;
  target_user_sub: string;
  previous_role: string;
  new_role: string;
  reason: string;
  ip?: string;
  request_id?: string;
  ts: number;
}

export interface RoleAuditResp {
  items: RoleAuditItem[];
  cursor?: string | null;
}

export function grantAdminRole(body: RoleGrantRevokeReq) {
  return api.post<RoleGrantRevokeResp>("/admin/roles/grant", body);
}

export function revokeAdminRole(body: RoleGrantRevokeReq) {
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
