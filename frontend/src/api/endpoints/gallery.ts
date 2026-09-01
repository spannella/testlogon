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
  text: string | null;
  created_at: number;
  edited_at?: number | null;
  parent_comment_id?: string | null;
  kind?: "text" | "gif" | "sticker" | "image";
  gif_url?: string | null;
  gif_alt_text?: string | null;
  gif_width?: number | null;
  gif_height?: number | null;
  sticker_id?: string | null;
  sticker_collection_id?: string | null;
  sticker_url?: string | null;
  sticker_alt_text?: string | null;
  // Image comment fields (kind="image")
  image_url?: string | null;
  image_alt_text?: string | null;
  image_width?: number | null;
  image_height?: number | null;
  reactions_counts?: Record<string, number>;
  my_reactions?: string[];
  // TIP-303: running total tipped to this comment (cents).
  tip_total_cents?: number;
}

export interface AddVideoCommentReq {
  parent_comment_id?: string;
  kind?: "text" | "gif" | "sticker" | "image";
  text?: string;
  gif_url?: string;
  gif_alt_text?: string;
  gif_width?: number;
  gif_height?: number;
  sticker_id?: string;
  sticker_collection_id?: string;
  sticker_url?: string;
  sticker_alt_text?: string;
  // Image comment fields (kind="image")
  image_url?: string;
  image_alt_text?: string;
  image_width?: number;
  image_height?: number;
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
  body: AddVideoCommentReq | string,
): Promise<VideoComment> =>
  api.post<VideoComment>(
    `/ui/videos/${videoId}/comments`,
    typeof body === "string" ? { kind: "text", text: body } : body,
  );

export const editVideoComment = (
  videoId: string,
  commentId: string,
  text: string,
): Promise<VideoComment> =>
  api.patch<VideoComment>(
    `/ui/videos/${videoId}/comments/${commentId}`,
    { text },
  );

export const reactToVideoComment = (
  videoId: string,
  commentId: string,
  emoji: string,
): Promise<VideoComment> =>
  api.post<VideoComment>(
    `/ui/videos/${videoId}/comments/${commentId}/reactions`,
    { emoji },
  );

export const unreactFromVideoComment = (
  videoId: string,
  commentId: string,
  emoji: string,
): Promise<VideoComment> =>
  api.post<VideoComment>(
    `/ui/videos/${videoId}/comments/${commentId}/unreact`,
    { emoji },
  );

export interface VideoCommentTipResponse {
  ok: boolean;
  video_id: string;
  comment_id: string;
  amount_cents: number;
  currency: string;
  tip_total_cents: number;
}

// TIP-303 (web): tip a video comment. Mirrors the newsfeed comment-tip idiom
// (POST /ui/videos/{id}/comments/{cid}/tip) and threads the chosen payment
// method so the tipper is charged on their selected card.
export const tipVideoComment = (
  videoId: string,
  commentId: string,
  amountCents: number,
  paymentMethodId?: string,
): Promise<VideoCommentTipResponse> =>
  api.post<VideoCommentTipResponse>(
    `/ui/videos/${videoId}/comments/${commentId}/tip`,
    {
      amount_cents: amountCents,
      currency: "usd",
      ...(paymentMethodId ? { payment_method_id: paymentMethodId } : {}),
    },
  );

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

export interface ReportVideoCommentReq {
  videoId: string;
  commentId: string;
  topics: string[];
  reason_text: string;
}

export const reportVideoComment = (
  body: ReportVideoCommentReq,
): Promise<{ ok: boolean; report_id: string }> =>
  api.post<{ ok: boolean; report_id: string }>("/moderation/reports", {
    content_type: "video_comment",
    content_id: body.commentId,
    video_id: body.videoId,
    topics: body.topics,
    reason_text: body.reason_text,
  });
