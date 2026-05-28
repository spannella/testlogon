import { api } from "../client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SearchResultItem {
  type: "user" | "post" | "catalog" | "file";
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
  };
  partial?: boolean;
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export const globalSearch = (q: string, types?: string, limit = 5) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (types) params.types = types;
  return api.get<GlobalSearchResponse>("/ui/search", params);
};
