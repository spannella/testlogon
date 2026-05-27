import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface RecommendedVideo {
  video_id: string;
  title: string;
  description?: string;
  thumbnail_url?: string;
  duration_seconds?: number;
  creator_id: string;
  creator_name: string;
  view_count: number;
  like_count: number;
  category?: string;
  created_at: number;
  recommendation_reason?: string;
}

export interface ForYouResponse {
  videos: RecommendedVideo[];
  next_cursor?: string | null;
  source: string;
}

export interface SimilarVideosResponse {
  videos: RecommendedVideo[];
  source: string;
}

export interface CreatorSuggestion {
  user_id: string;
  display_name: string;
  avatar_url?: string;
  subscriber_count: number;
  video_count: number;
  overlap_reason?: string;
}

export interface CreatorSuggestionsResponse {
  creators: CreatorSuggestion[];
  source: string;
}

export interface EngagementSignal {
  video_id: string;
  watch_pct?: number;
  liked?: boolean;
}

export interface RefreshRequest {
  user_id?: string;
}

export interface RefreshResponse {
  ok: boolean;
  users_processed: number;
  duration_seconds: number;
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const getForYou = (params?: {
  limit?: number;
  cursor?: string;
}): Promise<ForYouResponse> => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<ForYouResponse>("/ui/videos/gallery/for-you", p);
};

export const getSimilarVideos = (
  videoId: string,
  limit = 8,
): Promise<SimilarVideosResponse> =>
  api.get<SimilarVideosResponse>(`/ui/videos/${videoId}/similar`, {
    limit: String(limit),
  });

export const getCreatorSuggestions = (
  limit = 10,
): Promise<CreatorSuggestionsResponse> =>
  api.get<CreatorSuggestionsResponse>("/ui/discover/creators", {
    limit: String(limit),
  });

export const recordEngagement = (
  signal: EngagementSignal,
): Promise<{ ok: boolean }> =>
  api.post<{ ok: boolean }>("/ui/recommendations/engagement", signal);

export const refreshRecommendations = (
  body: RefreshRequest = {},
): Promise<RefreshResponse> =>
  api.post<RefreshResponse>("/internal/recommendations/refresh", body);
