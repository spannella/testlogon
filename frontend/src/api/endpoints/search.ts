import { api } from "../client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SearchResultType =
  | "user"
  | "post"
  | "catalog"
  | "file"
  | "message"
  | "ticket"
  | "contact"
  | "video"
  | "calendar";

export interface SearchResultItem {
  type: SearchResultType;
  id: string;
  title: string;
  snippet: string;
  thumbnail_url?: string;
  url: string;
  meta?: Record<string, unknown>;
}

export interface SearchResultSection {
  items: SearchResultItem[];
  total_estimate: number;
  has_more: boolean;
}

export interface GlobalSearchResponse {
  query: string;
  results: {
    users: SearchResultSection;
    posts: SearchResultSection;
    catalog: SearchResultSection;
    files: SearchResultSection;
    messages?: SearchResultSection;
    tickets?: SearchResultSection;
    contacts?: SearchResultSection;
    videos?: SearchResultSection;
    calendar?: SearchResultSection;
  };
  partial?: boolean;
}

export interface SearchHistoryItem {
  id: string;
  query: string;
  ts: number;
  result_count: number;
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export const globalSearch = (q: string, types?: string, limit = 5) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (types) params.types = types;
  return api.get<GlobalSearchResponse>("/ui/search", params);
};

export const recordSearchHistory = (query: string, resultCount?: number) =>
  api.post<{ ok: boolean; id: string }>("/ui/search/history", {
    query,
    result_count: resultCount ?? 0,
  });

export const getSearchHistory = (limit = 20) =>
  api.get<{ items: SearchHistoryItem[] }>("/ui/search/history", {
    limit: String(limit),
  });

export const deleteSearchHistoryItem = (id: string) =>
  api.del<{ ok: boolean }>(`/ui/search/history/${encodeURIComponent(id)}`);

export const clearSearchHistory = () =>
  api.del<{ ok: boolean; deleted_count: number }>("/ui/search/history");
