import { api } from "@/api/client";

// ── Types ──────────────────────────────────────────────────────────

export interface BookmarkItem {
  content_type: "post" | "video";
  content_id: string;
  collection_id: string;
  created_at: string;
  content_preview: {
    author_id: string;
    author_display_name?: string;
    body_snippet?: string;
    image_url?: string | null;
    like_count?: number;
  };
}

export interface BookmarkCollection {
  collection_id: string;
  name: string;
  item_count: number;
  created_at: string;
}

export interface BookmarkListResponse {
  bookmarks: BookmarkItem[];
  next_cursor?: string;
  total_count: number;
}

// ── API calls ──────────────────────────────────────────────────────

export const createBookmark = (body: {
  content_type: string;
  content_id: string;
  collection_id?: string;
}) => api.post<{ ok: boolean; content_type: string; content_id: string; collection_id: string; created_at: string }>("/ui/bookmarks", body);

export const removeBookmark = (contentType: string, contentId: string) =>
  api.del<{ ok: boolean }>(`/ui/bookmarks/${contentType}/${contentId}`);

export const getBookmarks = (params?: {
  limit?: number;
  cursor?: string;
  content_type?: string;
  collection_id?: string;
}) => {
  const query: Record<string, string> = {};
  if (params?.limit) query.limit = String(params.limit);
  if (params?.cursor) query.cursor = params.cursor;
  if (params?.content_type) query.content_type = params.content_type;
  if (params?.collection_id) query.collection_id = params.collection_id;
  return api.get<BookmarkListResponse>("/ui/bookmarks", Object.keys(query).length ? query : undefined);
};

export const getBookmarkStatus = (ids: string[]) =>
  api.get<{ statuses: Record<string, boolean> }>("/ui/bookmarks/status", { ids: ids.join(",") });

// ── Collections ────────────────────────────────────────────────────

export const getCollections = () =>
  api.get<{ collections: BookmarkCollection[] }>("/ui/bookmark-collections");

export const createCollection = (body: { name: string }) =>
  api.post<{ ok: boolean; collection_id: string; name: string; item_count: number; created_at: string }>("/ui/bookmark-collections", body);

export const renameCollection = (collectionId: string, body: { name: string }) =>
  api.patch<{ ok: boolean; collection_id: string; name: string }>(`/ui/bookmark-collections/${collectionId}`, body);

export const deleteCollection = (collectionId: string) =>
  api.del<{ ok: boolean; moved_count: number }>(`/ui/bookmark-collections/${collectionId}`);
