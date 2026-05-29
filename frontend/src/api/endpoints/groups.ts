import { api } from "@/api/client";
import type {
  UserGroup,
  GroupMember,
  GroupListOut,
  GroupMemberListOut,
} from "@/api/types";

// -- Group CRUD --

export const createGroup = (body: {
  name: string;
  description?: string;
  visibility?: "public" | "private";
  topic?: string;
}) => api.post<UserGroup>("/ui/groups", body);

export const listMyGroups = () =>
  api.get<UserGroup[]>("/ui/groups");

export const discoverGroups = (params?: {
  query?: string;
  topic?: string;
  limit?: number;
}) => api.get<GroupListOut>("/ui/groups/discover", { params });

export const getGroup = (groupId: string) =>
  api.get<UserGroup>(`/ui/groups/${groupId}`);

export const updateGroup = (
  groupId: string,
  body: {
    name?: string;
    description?: string;
    visibility?: "public" | "private";
    topic?: string;
  },
) => api.patch<UserGroup>(`/ui/groups/${groupId}`, body);

export const deleteGroup = (groupId: string) =>
  api.delete<{ ok: boolean; status: string }>(`/ui/groups/${groupId}`);

// -- Membership --

export const listGroupMembers = (groupId: string) =>
  api.get<GroupMemberListOut>(`/ui/groups/${groupId}/members`);

export const joinGroup = (groupId: string) =>
  api.post<GroupMember>(`/ui/groups/${groupId}/join`);

export const leaveGroup = (groupId: string) =>
  api.post<{ ok: boolean }>(`/ui/groups/${groupId}/leave`);

export const inviteToGroup = (groupId: string, userId: string) =>
  api.post<GroupMember>(`/ui/groups/${groupId}/invite`, { user_id: userId });

export const respondToInvite = (
  groupId: string,
  userId: string,
  accept: boolean,
) =>
  api.post<{ ok: boolean; status: string }>(
    `/ui/groups/${groupId}/invites/${userId}/respond`,
    { accept },
  );

export const reviewJoinRequest = (
  groupId: string,
  userId: string,
  approved: boolean,
) =>
  api.post<{ ok: boolean; status: string }>(
    `/ui/groups/${groupId}/requests/${userId}/review`,
    { approved },
  );

export const updateMemberRole = (
  groupId: string,
  userId: string,
  role: "moderator" | "member",
) =>
  api.patch<GroupMember>(`/ui/groups/${groupId}/members/${userId}/role`, {
    role,
  });

export const removeMember = (groupId: string, userId: string) =>
  api.delete<{ ok: boolean }>(`/ui/groups/${groupId}/members/${userId}`);

export const listPendingMembers = (groupId: string) =>
  api.get<GroupMember[]>(`/ui/groups/${groupId}/pending`);
