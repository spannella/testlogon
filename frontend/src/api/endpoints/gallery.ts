import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GalleryVideoItem {
  video_id: string;
  title: string;
  description?: string;
  thumbnail_url?: string;
  duration_seconds?: number;
  category?: string;
  tags: string[];
  view_count: number;
  like_count: number;
  comment_count: number;
  owner_user_id: string;
  price_cents?: number;
  access_mode?: string;
  created_at: number;
  published_at?: number;
}

export interface GalleryCategory {
  slug: string;
  label: string;
}

export interface GalleryListResponse {
  videos: GalleryVideoItem[];
  categories: GalleryCategory[];
  cursor?: string;
}

export interface GallerySearchResponse {
  videos: GalleryVideoItem[];
  cursor?: string;
}

export interface ViewRecordResponse {
  view_count: number;
  is_new_view: boolean;
}

export interface LikeToggleResponse {
  liked: boolean;
  like_count: number;
}

export interface LikeCheckResponse {
  liked: boolean;
}

export interface PublishToGalleryRequest {
  category: string;
  tags: string[];
  title?: string;
  description?: string;
}

export interface PublishToGalleryResponse {
  video_id: string;
  gallery_published: boolean;
  category: string;
  tags: string[];
  published_at: number;
}

export interface VideoComment {
  comment_id: string;
  video_id: string;
  user_id: string;
  text: string;
  created_at: number;
}

export interface VideoCommentListResponse {
  comments: VideoComment[];
  cursor?: string;
}

export interface CategoriesResponse {
  categories: GalleryCategory[];
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const browseGallery = (params?: {
  category?: string;
  limit?: number;
  cursor?: string;
}): Promise<GalleryListResponse> => {
  const p: Record<string, string> = {};
  if (params?.category) p.category = params.category;
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<GalleryListResponse>("/ui/videos/gallery", p);
};

export const searchGallery = (params: {
  q: string;
  limit?: number;
  cursor?: string;
}): Promise<GallerySearchResponse> => {
  const p: Record<string, string> = { q: params.q };
  if (params.limit) p.limit = String(params.limit);
  if (params.cursor) p.cursor = params.cursor;
  return api.get<GallerySearchResponse>("/ui/videos/gallery/search", p);
};

export const getGalleryCategories = (): Promise<CategoriesResponse> =>
  api.get<CategoriesResponse>("/ui/videos/gallery/categories");

export const publishToGallery = (
  videoId: string,
  body: PublishToGalleryRequest,
): Promise<PublishToGalleryResponse> =>
  api.post<PublishToGalleryResponse>(
    `/ui/videos/${videoId}/gallery/publish`,
    body,
  );

export const unpublishFromGallery = (
  videoId: string,
): Promise<{ video_id: string; gallery_published: boolean }> =>
  api.post(`/ui/videos/${videoId}/gallery/unpublish`);

export const recordView = (
  videoId: string,
): Promise<ViewRecordResponse> =>
  api.post<ViewRecordResponse>(`/ui/videos/${videoId}/view`);

export const toggleLike = (
  videoId: string,
): Promise<LikeToggleResponse> =>
  api.post<LikeToggleResponse>(`/ui/videos/${videoId}/like`);

export const checkLike = (
  videoId: string,
): Promise<LikeCheckResponse> =>
  api.get<LikeCheckResponse>(`/ui/videos/${videoId}/like`);

export const addVideoComment = (
  videoId: string,
  text: string,
): Promise<VideoComment> =>
  api.post<VideoComment>(`/ui/videos/${videoId}/comments`, { text });

export const listVideoComments = (
  videoId: string,
  params?: { limit?: number; cursor?: string },
): Promise<VideoCommentListResponse> => {
  const p: Record<string, string> = {};
  if (params?.limit) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<VideoCommentListResponse>(
    `/ui/videos/${videoId}/comments`,
    p,
  );
};

export const deleteVideoComment = (
  videoId: string,
  commentId: string,
): Promise<void> =>
  api.del(`/ui/videos/${videoId}/comments/${commentId}`);
