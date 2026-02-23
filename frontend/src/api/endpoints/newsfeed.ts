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

export const unlockPost = (postId: string) =>
  api.post<{ ok: boolean }>("/posts/unlock", { post_id: postId });

// ── Post CRUD ──────────────────────────────────────────────────

export const getPost = (postId: string) =>
  api.get<FeedPost>(`/posts/${postId}`);

export const editPost = (postId: string, body: EditPostReq) =>
  api.patch<FeedPost>(`/posts/${postId}`, body);

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

/** SSE stream URL for real-time feed updates */
export const feedSseUrl = "/sse";
