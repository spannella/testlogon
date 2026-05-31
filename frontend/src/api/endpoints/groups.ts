import { api } from "@/api/client";
import type { UserGroup, GroupMember, GroupFeedResponse } from "@/api/types";
import axios from "axios";

// ── GROUP-001: User Groups ──────────────────────────────────────

export const createGroup = (data: {
  name: string;
  description?: string;
  visibility?: "public" | "private";
  topic?: string;
}) => api.post<UserGroup>("/ui/groups", data);

export const listMyGroups = () =>
  api.get<{ groups: UserGroup[] }>("/ui/groups");

export const discoverGroups = (params?: { query?: string; limit?: number }) =>
  api.get<{ groups: UserGroup[] }>("/ui/groups/discover", params as Record<string, string>);

export const getGroup = (groupId: string) =>
  api.get<UserGroup>(`/ui/groups/${groupId}`);

export const updateGroup = (groupId: string, data: {
  name?: string;
  description?: string;
  visibility?: "public" | "private";
  topic?: string;
}) => api.patch<UserGroup>(`/ui/groups/${groupId}`, data);

export const deleteGroup = (groupId: string) =>
  api.del(`/ui/groups/${groupId}`);

export const listGroupMembers = (groupId: string) =>
  api.get<{ members: GroupMember[]; count: number }>(`/ui/groups/${groupId}/members`);

export const joinGroup = (groupId: string) =>
  api.post(`/ui/groups/${groupId}/join`);

export const leaveGroup = (groupId: string) =>
  api.post(`/ui/groups/${groupId}/leave`);

export const inviteToGroup = (groupId: string, userId: string) =>
  api.post(`/ui/groups/${groupId}/invite`, { user_id: userId });

export const respondToInvite = (groupId: string, userId: string, accept: boolean) =>
  api.post(`/ui/groups/${groupId}/invites/${userId}/respond`, { accept });

export const reviewJoinRequest = (groupId: string, userId: string, approved: boolean) =>
  api.post(`/ui/groups/${groupId}/requests/${userId}/review`, { approved });

export const updateMemberRole = (groupId: string, userId: string, role: string) =>
  api.patch(`/ui/groups/${groupId}/members/${userId}/role`, { role });

export const removeMember = (groupId: string, userId: string) =>
  api.del(`/ui/groups/${groupId}/members/${userId}`);

// ── GROUP-002: Group Feed ───────────────────────────────────────

export const createGroupPost = (groupId: string, data: {
  text: string;
  body_format?: string;
  image_url?: string;
  audience?: "public" | "members_only";
  unlock_price_cents?: number;
}) => api.post(`/ui/groups/${groupId}/posts`, data);

export const getGroupFeed = (groupId: string, params?: {
  cursor?: string;
  limit?: number;
}) => api.get<GroupFeedResponse>(`/ui/groups/${groupId}/feed`, params as Record<string, string>);

export const getPublicGroupFeed = (groupId: string, params?: {
  cursor?: string;
  limit?: number;
}) => axios.get<GroupFeedResponse>(`/public/groups/${groupId}/feed`, { params }).then(r => r.data);

export const pinGroupPost = (groupId: string, postId: string) =>
  api.post(`/ui/groups/${groupId}/posts/${postId}/pin`);

export const unpinGroupPost = (groupId: string, postId: string) =>
  api.del(`/ui/groups/${groupId}/posts/${postId}/pin`);

export const deleteGroupPost = (groupId: string, postId: string) =>
  api.del(`/ui/groups/${groupId}/posts/${postId}`);
