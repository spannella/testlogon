import { api } from "@/api/client";
import type {
  FeedPost,
  FeedComment,
  FeedCapabilities,
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
  CreateFindDateTimePostReq,
  FindDateTimePost,
  FindDateTimePostPoll,
} from "@/api/types";

export interface FeedQueryParams {
  cursor?: string;
  author_id?: string;
  q?: string;
  from?: string;
  to?: string;
  has_media?: boolean;
}

export const getFeed = async (params?: FeedQueryParams) => {
  const query: Record<string, string> = {};
  if (params?.cursor) query.cursor = params.cursor;
  if (params?.author_id) query.author_id = params.author_id;
  if (params?.q) query.q = params.q;
  if (params?.from) query.from = params.from;
  if (params?.to) query.to = params.to;
  if (typeof params?.has_media === "boolean") query.has_media = String(params.has_media);

  const networkFn = () =>
    api.get<{ items: FeedPost[]; next_cursor?: string }>(
      "/feed",
      Object.keys(query).length ? query : undefined,
    );

  // Wrap with offline cache (PWA-003)
  const { useAuthStore } = await import("@/stores/authStore");
  const userId = useAuthStore.getState().userId ?? "";
  const { withOfflineCache } = await import("@/lib/withOfflineCache");
  const queryString = Object.entries(query)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const cacheKey = `/feed${queryString ? `?${queryString}` : ""}`;
  return withOfflineCache(networkFn, { endpoint: "feed", cacheKey }, userId)();
};

export interface ForYouFeedResp {
  items: FeedPost[];
  next_cursor?: string;
  source: "for_you" | "chronological_fallback" | "cold_start";
}

/**
 * NRS-009/NRS-011: Ranked "For You" newsfeed. The backend always returns posts:
 * when NEWSFEED_RECSYS_ENABLED is off, no pre-computed row exists, or ranking
 * yields zero items, it transparently falls back to the chronological feed and
 * reports `source` accordingly. Same item shape as {@link getFeed}.
 */
export const getForYouFeed = (params?: { cursor?: string; limit?: number }) => {
  const query: Record<string, string> = {};
  if (params?.cursor) query.cursor = params.cursor;
  if (typeof params?.limit === "number") query.limit = String(params.limit);
  return api.get<ForYouFeedResp>(
    "/feed/for-you",
    Object.keys(query).length ? query : undefined,
  );
};

export const getFeedCapabilities = () =>
  api.get<FeedCapabilities>("/feed/capabilities");

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

export const reactToComment = (postId: string, commentId: string, emoji: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/comments/${commentId}/reactions`, { emoji });

export const unreactFromComment = (postId: string, commentId: string, emoji: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/comments/${commentId}/unreact`, { emoji });

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

// ── Reposts (SOCIAL-002) ──────────────────────────────────────────────

export const repostPost = (postId: string, body?: { quote?: string }) =>
  api.post<{ ok: boolean; repost_id: string; repost_count: number }>(
    `/posts/${postId}/repost`, body ?? {},
  );

export const undoRepost = (postId: string) =>
  api.del<{ ok: boolean; repost_count: number }>(`/posts/${postId}/repost`);

export const getReposts = (postId: string, params?: { limit?: number; cursor?: string }) =>
  api.get<{ reposts: Array<{ repost_id: string; user_id: string; display_name: string; quote?: string; created_at: string }>; next_cursor?: string; total_count: number }>(
    `/posts/${postId}/reposts`, params as Record<string, string> | undefined,
  );

export function issueVideoPostEntitlement(postId: string) {
  return api.post<{
    video_id: string;
    hls_manifest_url: string;
    playback_token: string;
    playback_expires_at: number;
  }>(`/ui/posts/${postId}/video/entitlement`);
}

// ── Bulk Operations (UX-004) ────────────────────────────────────────────────

export interface PostBulkResult {
  results: Array<{ post_id: string; ok: boolean; error?: string }>;
  succeeded: number;
  failed: number;
}

export const bulkDeletePosts = (postIds: string[]) =>
  api.post<PostBulkResult>("/posts/bulk-delete", { post_ids: postIds });

export const bulkArchivePosts = (postIds: string[]) =>
  api.post<PostBulkResult>("/posts/bulk-archive", { post_ids: postIds });

// ── FEED-003: Find-a-DateTime posts ─────────────────────────────────────────

export const createFindDateTimePost = (body: CreateFindDateTimePostReq) =>
  api.post<FindDateTimePost>("/posts/find-datetime", body);

export const getPostFindDateTime = (pollId: string) =>
  api.get<FindDateTimePostPoll>(`/posts/find-datetime/${pollId}`);

export const submitPostAvailability = (pollId: string, slots: string[]) =>
  api.post<{
    ok: boolean;
    poll_id: string;
    your_slot_count: number;
    participant_count: number;
    submitted_at: number;
  }>(`/posts/find-datetime/${pollId}/availability`, { slots });

export const closePostFindDateTime = (pollId: string) =>
  api.post<{
    ok: boolean;
    poll_id: string;
    status: string;
    participant_count: number;
    best_windows: FindDateTimePostPoll["best_windows"];
  }>(`/posts/find-datetime/${pollId}/close`);
