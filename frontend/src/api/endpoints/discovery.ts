import { api } from "../client";

export interface DiscoveryUser {
  user_id: string;
  display_name: string;
  profile_photo_url?: string;
  description?: string;
  follower_count: number;
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
}

export interface DiscoverySearchResponse {
  items: DiscoveryUser[];
  next_cursor?: string;
  total_estimate: number;
}

export interface DiscoveryProfile {
  user_id: string;
  display_name: string;
  profile_photo_url?: string;
  cover_photo_url?: string;
  description?: string;
  location?: string;
  follower_count: number;
  following_count: number;
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
}

export const searchDiscoverUsers = (q: string, limit = 20, cursor?: string) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (cursor) params.cursor = cursor;
  return api.get<DiscoverySearchResponse>("/ui/discover/search", params);
};

export const getSuggestedUsers = (limit = 12) =>
  api.get<DiscoverySearchResponse>("/ui/discover/suggested", { limit: String(limit) });

export const getTrendingCreators = (limit = 20) =>
  api.get<DiscoverySearchResponse>("/ui/discover/trending", { limit: String(limit) });

export const getDiscoveryProfile = (userId: string) =>
  api.get<DiscoveryProfile>(`/ui/discover/profile/${userId}`);

export const reindexSelf = () =>
  api.post("/ui/discover/reindex");

// ─── SOCIAL-006: Hashtag/Tag Discovery ──────────────────────────────────

export interface TrendingTag {
  tag: string;
  count: number;
  last_used_at: string;
}

export interface TrendingTagsResponse {
  tags: TrendingTag[];
}

export interface TagDiscoverResponse {
  tag: string;
  posts: import("@/api/types").FeedPost[];
  next_cursor?: string;
}

export const getTrendingTags = (limit = 20) =>
  api.get<TrendingTagsResponse>("/ui/discover/trending-tags", { limit: String(limit) });

export const getPostsByTag = (tag: string, limit = 20, cursor?: string) => {
  const params: Record<string, string> = { limit: String(limit) };
  if (cursor) params.cursor = cursor;
  return api.get<TagDiscoverResponse>(`/ui/discover/tags/${encodeURIComponent(tag)}`, params);
};
