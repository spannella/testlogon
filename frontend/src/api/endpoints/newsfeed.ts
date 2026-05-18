import { api } from "@/api/client";
import type {
  FeedPost,
  FeedComment,
  CreatePostReq,
  CreateCommentReq,
  EditPostReq,
  EditCommentReq,
  HidePostReq,
  TipReq,
  DraftPost,
  CreateDraftPostReq,
  UpdateDraftPostReq,
  ListDraftPostsResp,
  ScheduledPostsResp,
} from "@/api/types";

export const getFeed = (cursor?: string) =>
  api.get<{ items: FeedPost[]; next_cursor?: string }>(
    "/feed",
    cursor ? { cursor } : undefined,
  );

export const createPost = (body: CreatePostReq) =>
  api.post<FeedPost>("/posts", body);

export const likePost = (postId: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/like`);

export const unlikePost = (postId: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/unlike`);

export const getComments = (postId: string, cursor?: string) =>
  api.get<{ items: FeedComment[]; next_cursor?: string }>(
    `/posts/${postId}/comments`,
    cursor ? { cursor } : undefined,
  );

export const createComment = (postId: string, body: CreateCommentReq) =>
  api.post<FeedComment>(`/posts/${postId}/comments`, body);

export const tipPost = (postId: string, commentId: string, amountCents: number) =>
  api.post(`/posts/${postId}/comments/${commentId}/tip`, { amount_cents: amountCents });

export const follow = (userId: string) =>
  api.post<{ ok: boolean }>("/social/refollow", { target_user_id: userId });

export const unfollow = (userId: string) =>
  api.post<{ ok: boolean }>("/social/unfollow", { target_user_id: userId });

export const unlockPost = (postId: string, paymentMethodId?: string) =>
  api.post<{ ok: boolean }>("/posts/unlock", {
    post_id: postId,
    ...(paymentMethodId ? { payment_method_id: paymentMethodId } : {}),
  });

// ── Post CRUD ──────────────────────────────────────────────────

export const getPost = (postId: string) =>
  api.get<FeedPost>(`/posts/${postId}`);

export const editPost = (postId: string, body: EditPostReq) =>
  api.patch<FeedPost>(`/posts/${postId}`, body);

export const editScheduledPost = (postId: string, body: EditPostReq) =>
  api.patch<FeedPost>(`/posts/${postId}`, body);

export const getScheduledPosts = (cursor?: string) =>
  api.get<ScheduledPostsResp>(
    "/posts/scheduled",
    cursor ? { cursor } : undefined,
  );

export const cancelScheduledPost = (postId: string) =>
  api.post<FeedPost>(`/posts/${postId}/cancel`, {});

export const deletePost = (postId: string) =>
  api.del<{ ok: boolean }>(`/posts/${postId}`);

// ── Comment CRUD ───────────────────────────────────────────────

export const editComment = (postId: string, commentId: string, body: EditCommentReq) =>
  api.patch<FeedComment>(`/posts/${postId}/comments/${commentId}`, body);

export const deleteComment = (postId: string, commentId: string) =>
  api.del<{ ok: boolean }>(`/posts/${postId}/comments/${commentId}`);

// ── Hide ───────────────────────────────────────────────────────

export const hidePost = (body: HidePostReq) =>
  api.post<{ ok: boolean }>("/feed/hide", body);

// ── Image upload ───────────────────────────────────────────────

export const uploadPostImage = (file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<{ url: string; s3_key: string }>("/uploads/image", formData);
};

// ── Tipping ────────────────────────────────────────────────────

export const tipPostDirect = (postId: string, body: TipReq) =>
  api.post<{ ok: boolean; tip_total_cents: number }>(`/posts/${postId}/tip`, body);

// ── Reactions ──────────────────────────────────────────────────

export const addPostReaction = (postId: string, emoji: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/reactions`, { emoji });

export const removePostReaction = (postId: string, emoji: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/unreact`, { emoji });

/** SSE stream URL for real-time feed updates */
export const feedSseUrl = "/sse";




// ── Draft CRUD ──────────────────────────────────────────────────

export const createDraftPost = (body: CreateDraftPostReq) =>
  api.post<DraftPost>("/posts/drafts", body);

export const listDraftPosts = (cursor?: string, limit?: number) =>
  api.get<ListDraftPostsResp>("/posts/drafts", {
    ...(cursor ? { cursor } : {}),
    ...(typeof limit === "number" ? { limit: String(limit) } : {}),
  });

export const getDraftPost = (draftId: string) =>
  api.get<DraftPost>(`/posts/drafts/${draftId}`);

export const updateDraftPost = (draftId: string, body: UpdateDraftPostReq) =>
  api.patch<DraftPost>(`/posts/drafts/${draftId}`, body);

export const deleteDraftPost = (draftId: string, expectedUpdatedAt?: string) =>
  api.del<{ ok: boolean }>(`/posts/drafts/${draftId}`, expectedUpdatedAt ? { expected_updated_at: expectedUpdatedAt } : undefined);

export const publishDraftPost = (draftId: string, keepCopy = false, expectedUpdatedAt?: string) =>
  api.post<FeedPost>(`/posts/drafts/${draftId}/publish`, {
    keep_copy: keepCopy,
    ...(expectedUpdatedAt ? { expected_updated_at: expectedUpdatedAt } : {}),
  });
export interface ReportFeedContentReq {
  content_type: "feed_post" | "feed_comment" | "feed_media";
  content_id: string;
  topics: string[];
  reason_text: string;
  post_id?: string;
  comment_id?: string;
  media_index?: number;
}

export const reportFeedContent = (body: ReportFeedContentReq) =>
  api.post<{ ok: boolean; report_id: string }>("/moderation/reports", body);
