// FEED-007: Mark Post Interesting — per-viewer "more like this" signal.
import { api } from "@/api/client";

export interface PostInterestingResult {
  ok: boolean;
  post_id: string;
  is_interesting: boolean;
}

export interface PostInterestingList {
  post_ids: string[];
  count: number;
}

/** Mark a post interesting for the current viewer (idempotent toggle ON). */
export const markPostInteresting = (postId: string) =>
  api.post<PostInterestingResult>("/feed/interesting", { post_id: postId });

/** Remove the viewer's interesting signal (idempotent toggle OFF). */
export const unmarkPostInteresting = (postId: string) =>
  api.post<PostInterestingResult>("/feed/uninteresting", { post_id: postId });

/** List post_ids the current viewer has marked interesting. */
export const listInterestingPosts = (limit = 200) =>
  api.get<PostInterestingList>("/feed/interesting", { params: { limit } });
