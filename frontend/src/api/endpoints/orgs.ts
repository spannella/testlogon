import { api } from "@/api/client";

// ── Types ────────────────────────────────────────────────────────

export interface OrgOut {
  org_id: string;
  name: string;
  description?: string;
  slug: string;
  owner_user_sub: string;
  status: string;
  plan: string;
  member_count: number;
  storage_used_bytes: number;
  storage_limit_bytes: number;
  billing_mode: string;
  created_at: number;
  updated_at: number;
  org_role?: string;
  team_calendar_id?: string;
}

export interface OrgMemberOut {
  user_sub: string;
  org_role: string;
  status: string;
  joined_at: number;
  storage_used_bytes: number;
  last_active_at?: number;
}

export interface OrgInviteOut {
  invite_id: string;
  org_id: string;
  org_name: string;
  email: string;
  org_role: string;
  status: string;
  invited_by: string;
  created_at: number;
  expires_at: number;
  token?: string;
}

export interface OrgEventOut {
  event_id: string;
  title: string;
  description?: string;
  start_time: string;
  end_time: string;
  all_day: boolean;
  created_by: string;
  org_id: string;
  attendees: string[];
  created_at: number;
  updated_at: number;
}

// ── Org CRUD ─────────────────────────────────────────────────────

export const createOrg = (req: { name: string; description?: string; billing_mode?: string }) =>
  api.post<OrgOut>("/ui/orgs", req);

export const listOrgs = () =>
  api.get<OrgOut[]>("/ui/orgs");

export const getOrg = (orgId: string) =>
  api.get<OrgOut>(`/ui/orgs/${orgId}`);

export const updateOrg = (orgId: string, req: Partial<{ name: string; description: string }>) =>
  api.patch<OrgOut>(`/ui/orgs/${orgId}`, req);

export const archiveOrg = (orgId: string) =>
  api.del(`/ui/orgs/${orgId}`);

// ── Members ──────────────────────────────────────────────────────

export const listMembers = (orgId: string) =>
  api.get<OrgMemberOut[]>(`/ui/orgs/${orgId}/members`);

export const inviteMember = (orgId: string, req: { email: string; org_role?: string }) =>
  api.post<OrgInviteOut>(`/ui/orgs/${orgId}/members/invite`, req);

export const removeMember = (orgId: string, userSub: string) =>
  api.del(`/ui/orgs/${orgId}/members/${userSub}`);

export const changeMemberRole = (orgId: string, userSub: string, req: { org_role: string }) =>
  api.patch(`/ui/orgs/${orgId}/members/${userSub}/role`, req);

export const acceptInvite = (inviteId: string, token: string) =>
  api.post(`/ui/orgs/invites/${inviteId}/accept`, { token });

export const declineInvite = (inviteId: string) =>
  api.post(`/ui/orgs/invites/${inviteId}/decline`);

export const listPendingInvites = () =>
  api.get<OrgInviteOut[]>("/ui/orgs/invites/pending");

export const leaveOrg = (orgId: string) =>
  api.post(`/ui/orgs/${orgId}/leave`);

export const transferOwnership = (orgId: string, newOwnerUserSub: string) =>
  api.post(`/ui/orgs/${orgId}/transfer-ownership`, { new_owner_user_sub: newOwnerUserSub });

// ── Calendar ─────────────────────────────────────────────────────

export const listOrgEvents = (orgId: string) =>
  api.get<OrgEventOut[]>(`/ui/orgs/${orgId}/calendar/events`);

export const createOrgEvent = (orgId: string, req: any) =>
  api.post<OrgEventOut>(`/ui/orgs/${orgId}/calendar/events`, req);

export const updateOrgEvent = (orgId: string, eventId: string, req: any) =>
  api.patch<OrgEventOut>(`/ui/orgs/${orgId}/calendar/events/${eventId}`, req);

export const deleteOrgEvent = (orgId: string, eventId: string) =>
  api.del(`/ui/orgs/${orgId}/calendar/events/${eventId}`);

// ── Files ────────────────────────────────────────────────────────

export const listOrgFiles = (orgId: string) =>
  api.get(`/ui/orgs/${orgId}/files`);

export const uploadOrgFile = (orgId: string, file: File) => {
  const form = new FormData();
  form.append("file", file);
  return api.upload(`/ui/orgs/${orgId}/files/upload`, form);
};

export const deleteOrgFile = (orgId: string, nodeId: string) =>
  api.del(`/ui/orgs/${orgId}/files/${nodeId}`);

// ── Billing ──────────────────────────────────────────────────────

export const listOrgPaymentMethods = (orgId: string) =>
  api.get(`/ui/orgs/${orgId}/billing/payment-methods`);

export const addOrgPaymentMethod = (orgId: string, req: any) =>
  api.post(`/ui/orgs/${orgId}/billing/payment-methods`, req);

export const removeOrgPaymentMethod = (orgId: string, pmId: string) =>
  api.del(`/ui/orgs/${orgId}/billing/payment-methods/${pmId}`);

export const setOrgDefaultPm = (orgId: string, pmId: string) =>
  api.post(`/ui/orgs/${orgId}/billing/set-default`, { payment_method_id: pmId });

export const getOrgBillingHistory = (orgId: string) =>
  api.get(`/ui/orgs/${orgId}/billing/history`);
