import { api } from "@/api/client";

// FEED-006: Hide / Unhide posts in the newsfeed.
//
// The hide endpoint already exists on the backend (POST /feed/hide). These
// wrappers add the unhide + list-hidden surface. Types are kept local to avoid
// coupling to the broader feed post model.

export interface HideMutationResponse {
  ok: boolean;
  post_id: string;
  hidden: boolean;
}

export interface HiddenPostSummary {
  post_id: string;
  hidden: boolean;
  user_id?: string;
  body?: string | null;
  [key: string]: unknown;
}

export interface HiddenPostsPageResponse {
  items: HiddenPostSummary[];
  next_cursor: string | null;
}

export async function hidePost(postId: string): Promise<HideMutationResponse> {
  const { data } = await api.post<HideMutationResponse>("/feed/hide", {
    post_id: postId,
  });
  return data;
}

export async function unhidePost(postId: string): Promise<HideMutationResponse> {
  const { data } = await api.post<HideMutationResponse>("/feed/unhide", {
    post_id: postId,
  });
  return data;
}

export async function listHiddenPosts(
  cursor?: string,
  limit = 20,
): Promise<HiddenPostsPageResponse> {
  const params = new URLSearchParams();
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const { data } = await api.get<HiddenPostsPageResponse>(
    `/feed/hidden?${params.toString()}`,
  );
  return data;
}
