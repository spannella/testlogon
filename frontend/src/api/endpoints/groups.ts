import { api } from "@/api/client";
import type { UserGroup, GroupMember, GroupFeedResponse } from "@/api/types";

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

export const listPendingMembers = (groupId: string) =>
  api.get<GroupMember[]>(`/ui/groups/${groupId}/pending`);

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
}) => api.get<GroupFeedResponse>(`/public/groups/${groupId}/feed`, params as Record<string, string>);

export const pinGroupPost = (groupId: string, postId: string) =>
  api.post(`/ui/groups/${groupId}/posts/${postId}/pin`);

export const unpinGroupPost = (groupId: string, postId: string) =>
  api.del(`/ui/groups/${groupId}/posts/${postId}/pin`);

export const deleteGroupPost = (groupId: string, postId: string) =>
  api.del(`/ui/groups/${groupId}/posts/${postId}`);
import type {
  TreasuryBalance,
  TreasuryLedgerResponse,
  ContributorListResponse,
  ContributeResponse,
  SpendResponse,
} from "@/api/types";

// ---------------------------------------------------------------------------
// Group Treasury (GROUP-004)
// ---------------------------------------------------------------------------

export const getTreasuryBalance = (groupId: string) =>
  api.get<TreasuryBalance>(`/ui/groups/${groupId}/treasury`);

export const contributeToTreasury = (groupId: string, amountCents: number) =>
  api.post<ContributeResponse>(`/ui/groups/${groupId}/treasury/contribute`, {
    amount_cents: amountCents,
  });

export const getTreasuryLedger = (
  groupId: string,
  params?: { cursor?: string; limit?: number },
) => api.get<TreasuryLedgerResponse>(`/ui/groups/${groupId}/treasury/ledger`, { params });

export const getTreasuryContributors = (groupId: string) =>
  api.get<ContributorListResponse>(`/ui/groups/${groupId}/treasury/contributors`);

export const setFundraisingGoal = (groupId: string, goalCents: number | null) =>
  api.patch<{ ok: boolean; fundraising_goal_cents: number | null }>(
    `/ui/groups/${groupId}/treasury/goal`,
    { goal_cents: goalCents },
  );

export const spendTreasury = (
  groupId: string,
  data: {
    amount_cents: number;
    reason: string;
    category?: string;
    reference_id?: string;
  },
) => api.post<SpendResponse>(`/ui/groups/${groupId}/treasury/spend`, data);


// ---------------------------------------------------------------------------
// GROUP-003: Group Advertising & Fundraising
// ---------------------------------------------------------------------------

import type {
  GroupFundraiser,
  GroupFundraiserListResponse,
  GroupPublicFundraiser,
  GroupDonation,
  GroupDonationListResponse,
  GroupDonationReceipt,
  GroupCampaign,
  GroupCampaignListResponse,
  GroupCampaignStats,
} from "@/api/types";

// Advertising campaigns (admin / member)
export const createGroupCampaign = (
  groupId: string,
  data: {
    name: string;
    daily_budget_cents: number;
    lifetime_budget_cents: number;
    creative_text?: string;
    creative_image_url?: string;
  },
) => api.post<GroupCampaign>(`/ui/groups/fundraising/${groupId}/campaigns`, data);

export const listGroupCampaigns = (groupId: string) =>
  api.get<GroupCampaignListResponse>(`/ui/groups/fundraising/${groupId}/campaigns`);

export const getGroupCampaignStats = (groupId: string, campaignId: string) =>
  api.get<GroupCampaignStats>(`/ui/groups/fundraising/${groupId}/campaigns/${campaignId}/stats`);

export const updateGroupCampaign = (
  groupId: string,
  campaignId: string,
  data: { status?: "active" | "paused"; daily_budget_cents?: number },
) => api.patch<GroupCampaign>(`/ui/groups/fundraising/${groupId}/campaigns/${campaignId}`, data);

// Fundraisers (admin / member)
export const createGroupFundraiser = (
  groupId: string,
  data: {
    title: string;
    description?: string;
    goal_cents?: number;
    cover_image_url?: string;
    ends_at?: number;
  },
) => api.post<GroupFundraiser>(`/ui/groups/fundraising/${groupId}/fundraisers`, data);

export const listGroupFundraisers = (groupId: string) =>
  api.get<GroupFundraiserListResponse>(`/ui/groups/fundraising/${groupId}/fundraisers`);

export const getGroupFundraiser = (groupId: string, fundraiserId: string) =>
  api.get<GroupFundraiser>(`/ui/groups/fundraising/${groupId}/fundraisers/${fundraiserId}`);

export const updateGroupFundraiser = (
  groupId: string,
  fundraiserId: string,
  data: {
    title?: string;
    description?: string;
    goal_cents?: number;
    status?: "active" | "paused" | "cancelled";
    ends_at?: number;
  },
) => api.patch<GroupFundraiser>(`/ui/groups/fundraising/${groupId}/fundraisers/${fundraiserId}`, data);

export const listGroupDonations = (groupId: string, fundraiserId: string) =>
  api.get<GroupDonationListResponse>(
    `/ui/groups/fundraising/${groupId}/fundraisers/${fundraiserId}/donations`,
  );

// Public donor-facing endpoints (no auth). These hit /public/* routes; the api
// client only attaches an Authorization header / CSRF token when a session is
// present, so unauthenticated visitors call these cleanly.
export const getPublicFundraiser = (fundraiserId: string) =>
  api.get<GroupPublicFundraiser>(`/public/fundraisers/${fundraiserId}`);

export const submitDonation = (
  fundraiserId: string,
  data: { amount_cents: number; donor_name?: string; donor_email?: string },
) =>
  api.post<GroupDonation>(`/public/fundraisers/${fundraiserId}/donate`, data);

export const getDonationReceipt = (fundraiserId: string, donationId: string) =>
  api.get<GroupDonationReceipt>(
    `/public/fundraisers/${fundraiserId}/donations/${donationId}/receipt`,
  );
