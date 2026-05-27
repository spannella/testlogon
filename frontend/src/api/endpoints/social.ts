import { api } from "../client";

// ── Types ────────────────────────────────────────────────────────

export interface FollowUser {
  user_id: string;
  display_name?: string;
  profile_photo_url?: string;
  is_following: boolean;
  is_mutual: boolean;
}

export interface FollowListResponse {
  items: FollowUser[];
  next_cursor?: string;
  total_count: number;
}

export interface FollowCounts {
  follower_count: number;
  following_count: number;
}

export interface FollowStatus {
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
}

export interface FollowResponse {
  ok: boolean;
  status: "followed" | "already_following";
  follower_count: number;
  following_count: number;
}

export interface UnfollowResponse {
  ok: boolean;
  status: "unfollowed" | "not_following";
}

// ── API calls ────────────────────────────────────────────────────

export const followUser = (userId: string) =>
  api.post<FollowResponse>("/ui/social/follow", { target_user_id: userId });

export const unfollowUser = (userId: string) =>
  api.post<UnfollowResponse>("/ui/social/unfollow", { target_user_id: userId });

export const getFollowers = (userId: string, params?: Record<string, string>) =>
  api.get<FollowListResponse>(`/ui/social/${userId}/followers`, params);

export const getFollowing = (userId: string, params?: Record<string, string>) =>
  api.get<FollowListResponse>(`/ui/social/${userId}/following`, params);

export const getFollowCounts = (userId: string) =>
  api.get<FollowCounts>(`/ui/social/${userId}/counts`);

export const getFollowStatus = (userId: string) =>
  api.get<FollowStatus>(`/ui/social/status/${userId}`);

export const getMutualFollowers = (userId: string, params?: Record<string, string>) =>
  api.get<FollowListResponse>(`/ui/social/mutual/${userId}`, params);
