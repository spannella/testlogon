import { api } from "@/api/client";
import type {
  SyndicateOut,
  SyndicateInviteOut,
  SyndicateRequestOut,
  SyndicateAuditOut,
  SyndicateMemberOut,
  SyndicateUserEntry,
} from "@/api/types";

// -- Syndicate CRUD --

export const createSyndicate = (body: { name: string; description?: string }) =>
  api.post<SyndicateOut>("/ui/syndicates", body);

export const listMySyndicates = () =>
  api.get<SyndicateUserEntry[]>("/ui/syndicates");

export const getSyndicate = (syndicateId: string) =>
  api.get<SyndicateOut>(`/ui/syndicates/${syndicateId}`);

export const discoverSyndicates = (limit = 50) =>
  api.get<SyndicateOut[]>(`/ui/syndicates/discover`, { limit: String(limit) });

// -- Membership management --

export const inviteMember = (syndicateId: string, userId: string) =>
  api.post<SyndicateInviteOut>(`/ui/syndicates/${syndicateId}/invite`, { user_id: userId });

export const respondToInvite = (syndicateId: string, accept: boolean) =>
  api.post<{ ok: boolean; status: string }>(`/ui/syndicates/${syndicateId}/invite/respond`, { accept });

export const requestToJoin = (syndicateId: string, message = "") =>
  api.post<SyndicateRequestOut>(`/ui/syndicates/${syndicateId}/request`, { message });

export const approveRequest = (syndicateId: string, userId: string) =>
  api.post<{ ok: boolean }>(`/ui/syndicates/${syndicateId}/request/${userId}/approve`);

export const rejectRequest = (syndicateId: string, userId: string) =>
  api.post<{ ok: boolean }>(`/ui/syndicates/${syndicateId}/request/${userId}/reject`);

export const transferAdmin = (syndicateId: string, newAdminUserId: string) =>
  api.post<SyndicateOut>(`/ui/syndicates/${syndicateId}/transfer-admin`, { new_admin_user_id: newAdminUserId });

export const leaveSyndicate = (syndicateId: string) =>
  api.post<{ dissolved: boolean; syndicate_id: string }>(`/ui/syndicates/${syndicateId}/leave`);

export const removeMember = (syndicateId: string, userId: string) =>
  api.post<{ ok: boolean }>(`/ui/syndicates/${syndicateId}/remove/${userId}`);

// -- Queries --

export const listMembers = (syndicateId: string) =>
  api.get<SyndicateMemberOut[]>(`/ui/syndicates/${syndicateId}/members`);

export const listMyInvites = () =>
  api.get<SyndicateInviteOut[]>("/ui/syndicates/invites");

export const listRequests = (syndicateId: string) =>
  api.get<SyndicateRequestOut[]>(`/ui/syndicates/${syndicateId}/requests`);

export const getAuditLog = (syndicateId: string, limit = 50) =>
  api.get<SyndicateAuditOut[]>(`/ui/syndicates/${syndicateId}/audit`, { params: { limit } });
