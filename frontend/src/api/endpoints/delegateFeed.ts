import { api } from "@/api/client";
import type {
  DelegatedPostCreateReq,
  DelegatedPostEditReq,
  DelegatedPostOut,
  DraftApprovalReq,
  CommentModerationReq,
  FeedAnalyticsOut,
  FeedDelegateAuditEntry,
  FeedDelegationSettingsReq,
  FeedDelegationSettingsOut,
} from "@/api/types";

const BASE = "/ui/newsfeed/delegate";

// -- Post CRUD --

export async function createDelegatedPost(
  creatorId: string,
  req: DelegatedPostCreateReq,
): Promise<DelegatedPostOut> {
  return api.post<DelegatedPostOut>(`${BASE}/${creatorId}/posts`, req);
}

export async function editDelegatedPost(
  creatorId: string,
  postId: string,
  req: DelegatedPostEditReq,
): Promise<DelegatedPostOut> {
  return api.put<DelegatedPostOut>(
    `${BASE}/${creatorId}/posts/${postId}`,
    req,
  );
}

export async function deleteDelegatedPost(
  creatorId: string,
  postId: string,
): Promise<void> {
  return api.del<void>(`${BASE}/${creatorId}/posts/${postId}`);
}

export async function listDelegatedPosts(
  creatorId: string,
  limit = 50,
): Promise<DelegatedPostOut[]> {
  return api.get<DelegatedPostOut[]>(
    `${BASE}/${creatorId}/posts?limit=${limit}`,
  );
}

// -- Draft approval --

export async function listPendingDrafts(
  creatorId: string,
  limit = 50,
): Promise<DelegatedPostOut[]> {
  return api.get<DelegatedPostOut[]>(
    `${BASE}/${creatorId}/drafts?limit=${limit}`,
  );
}

export async function approveDraft(
  creatorId: string,
  postId: string,
  req?: DraftApprovalReq,
): Promise<DelegatedPostOut> {
  return api.post<DelegatedPostOut>(
    `${BASE}/${creatorId}/drafts/${postId}/approve`,
    req ?? {},
  );
}

export async function rejectDraft(
  creatorId: string,
  postId: string,
  req?: DraftApprovalReq,
): Promise<DelegatedPostOut> {
  return api.post<DelegatedPostOut>(
    `${BASE}/${creatorId}/drafts/${postId}/reject`,
    req ?? {},
  );
}

// -- Comment moderation --

export async function moderateComment(
  creatorId: string,
  postId: string,
  commentId: string,
  req: CommentModerationReq,
): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(
    `${BASE}/${creatorId}/posts/${postId}/comments/${commentId}/moderate`,
    req,
  );
}

// -- Analytics --

export async function getFeedAnalytics(
  creatorId: string,
  period = "30d",
): Promise<FeedAnalyticsOut> {
  return api.get<FeedAnalyticsOut>(
    `${BASE}/${creatorId}/analytics?period=${period}`,
  );
}

// -- Audit --

export async function getFeedDelegateAudit(
  creatorId: string,
  limit = 50,
): Promise<FeedDelegateAuditEntry[]> {
  return api.get<FeedDelegateAuditEntry[]>(
    `${BASE}/${creatorId}/audit?limit=${limit}`,
  );
}

// -- Settings --

export async function getFeedDelegationSettings(
  creatorId: string,
): Promise<FeedDelegationSettingsOut> {
  return api.get<FeedDelegationSettingsOut>(`${BASE}/${creatorId}/settings`);
}

export async function updateFeedDelegationSettings(
  creatorId: string,
  req: FeedDelegationSettingsReq,
): Promise<FeedDelegationSettingsOut> {
  return api.put<FeedDelegationSettingsOut>(
    `${BASE}/${creatorId}/settings`,
    req,
  );
}
