import { api } from "@/api/client";
import type {
  SyndicateOut,
  SyndicateInviteOut,
  SyndicateRequestOut,
  SyndicateAuditOut,
  SyndicateMemberOut,
  SyndicateUserEntry,
  BundlePlanOut,
  BundleSubscriptionOut,
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

// -- Bundle Plans (SYND-002) --

export const createBundlePlan = (syndicateId: string, body: { name: string; description?: string; price_cents: number; interval?: string }) =>
  api.post<BundlePlanOut>(`/ui/syndicates/${syndicateId}/plans`, body);

export const listBundlePlans = (syndicateId: string) =>
  api.get<BundlePlanOut[]>(`/ui/syndicates/${syndicateId}/plans`);

export const getBundlePlan = (syndicateId: string, planId: string) =>
  api.get<BundlePlanOut>(`/ui/syndicates/${syndicateId}/plans/${planId}`);

export const updateBundlePlan = (syndicateId: string, planId: string, body: { name?: string; description?: string; price_cents?: number }) =>
  api.put<BundlePlanOut>(`/ui/syndicates/${syndicateId}/plans/${planId}`, body);

export const archiveBundlePlan = (syndicateId: string, planId: string) =>
  api.del<{ ok: boolean; plan_id: string; status: string }>(`/ui/syndicates/${syndicateId}/plans/${planId}`);

export const subscribeToBundlePlan = (syndicateId: string, planId: string, body: { payment_method_id?: string } = {}) =>
  api.post<BundleSubscriptionOut>(`/ui/syndicates/${syndicateId}/plans/${planId}/subscribe`, body);

export const cancelBundleSubscription = (syndicateId: string, subscriptionId: string) =>
  api.post<{ subscription_id: string; status: string; current_period_end: number; cancelled_at: number }>(`/ui/syndicates/${syndicateId}/subscriptions/${subscriptionId}/cancel`);

export const listMyBundles = () =>
  api.get<BundleSubscriptionOut[]>("/ui/syndicates/my-bundles");
