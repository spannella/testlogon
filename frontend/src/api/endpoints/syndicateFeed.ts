import { api } from "@/api/client";
import type {
  SyndicateProfile,
  SyndicateProfileUpdate,
  SyndicateFeed,
  SyndicatePost,
  SyndicatePostCreate,
} from "@/api/types";

// SYND-005: Syndicate Page & Newsfeed
// Endpoints live under the distinct prefix /ui/syndicates/feed.

export const getSyndicateProfile = (syndicateId: string) =>
  api.get<SyndicateProfile>(`/ui/syndicates/feed/${syndicateId}/profile`);

export const updateSyndicateProfile = (syndicateId: string, body: SyndicateProfileUpdate) =>
  api.put<SyndicateProfile>(`/ui/syndicates/feed/${syndicateId}/profile`, body);

export const getSyndicateFeed = (
  syndicateId: string,
  params?: { cursor?: string; limit?: number },
) => {
  const q: Record<string, string> = {};
  if (params?.cursor) q.cursor = params.cursor;
  if (params?.limit) q.limit = String(params.limit);
  return api.get<SyndicateFeed>(`/ui/syndicates/feed/${syndicateId}`, q);
};

export const createSyndicatePost = (syndicateId: string, body: SyndicatePostCreate) =>
  api.post<SyndicatePost>(`/ui/syndicates/feed/${syndicateId}`, body);

export const deleteSyndicatePost = (syndicateId: string, postId: string) =>
  api.del<{ ok: boolean; post_id: string }>(`/ui/syndicates/feed/${syndicateId}/${postId}`);
