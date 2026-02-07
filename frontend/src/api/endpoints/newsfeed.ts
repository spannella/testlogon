import { api } from "@/api/client";
import type { FeedPost, FeedComment, CreatePostReq, CreateCommentReq } from "@/api/types";

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
  api.post<{ ok: boolean }>("/social/follow", { user_id: userId });

export const unfollow = (userId: string) =>
  api.post<{ ok: boolean }>("/social/unfollow", { user_id: userId });

export const unlockPost = (postId: string) =>
  api.post<{ ok: boolean }>(`/posts/${postId}/unlock`);

/** SSE stream URL for real-time feed updates */
export const feedSseUrl = "/newsfeed/sse";
