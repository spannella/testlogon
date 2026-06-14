import { api } from "@/api/client";

// ─── TS interfaces (mirror app/models.py Kb* Pydantic models) ────────────────

export type KbArticleStatus = "draft" | "published" | "expired";

export interface KbAttachment {
  attachment_id: string;
  article_id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  url: string;
  uploaded_by: string;
  created_at: number;
}

export interface KbArticle {
  article_id: string;
  title: string;
  body_html: string;
  excerpt: string;
  status: KbArticleStatus;
  category_id: string | null;
  category: string | null;
  author_sub: string;
  tags: string[];
  created_at: number;
  updated_at: number;
  published_at: number | null;
  expires_at: number | null;
  expired_at: number | null;
  expiry_reason: string | null;
  view_count: number;
  helpful_count: number;
  not_helpful_count: number;
  attachments: KbAttachment[];
}

export interface KbArticleSummary {
  article_id: string;
  title: string;
  excerpt: string;
  status: KbArticleStatus;
  category_id: string | null;
  category: string | null;
  author_sub: string;
  tags: string[];
  created_at: number;
  updated_at: number;
  published_at: number | null;
  view_count: number;
  helpful_count: number;
  not_helpful_count: number;
}

export interface KbArticleListOut {
  items: KbArticleSummary[];
  cursor: string | null;
  total: number;
}

export interface KbSearchOut {
  items: KbArticleSummary[];
  query: string;
  cursor: string | null;
}

export interface KbCategory {
  category_id: string;
  name: string;
  parent_id: string | null;
  path: string;
  description: string;
  sort_order: number;
  created_at: number;
  updated_at: number;
  children: KbCategory[];
}

export interface KbCategoryListOut {
  categories: KbCategory[];
}

export interface KbTagStats {
  tag: string;
  article_count: number;
}

export interface KbTagListOut {
  tags: KbTagStats[];
}

export interface KbRateOut {
  ok: boolean;
  already_rated: boolean;
  helpful_count: number;
  not_helpful_count: number;
}

export interface KbArticleCreateIn {
  title: string;
  body_html?: string;
  excerpt?: string;
  category_id?: string | null;
  tags?: string[];
  expires_at?: number | null;
}

export interface KbArticleUpdateIn {
  title?: string;
  body_html?: string;
  excerpt?: string;
  category_id?: string | null;
  tags?: string[];
  expires_at?: number | null;
}

export interface KbCategoryIn {
  name: string;
  parent_id?: string | null;
  description?: string;
  sort_order?: number;
}

// ─── Articles (authenticated) ────────────────────────────────────────────────

export const listArticles = (opts?: {
  status?: string;
  category_id?: string;
  author_sub?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.category_id) params["category_id"] = opts.category_id;
  if (opts?.author_sub) params["author_sub"] = opts.author_sub;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<KbArticleListOut>("/kb/articles", params);
};

export const listMyArticles = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<KbArticleListOut>("/kb/my-articles", params);
};

export const getArticle = (articleId: string) =>
  api.get<KbArticle>(`/kb/articles/${encodeURIComponent(articleId)}`);

export const searchArticles = (q: string, opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = { q };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<KbSearchOut>("/kb/search", params);
};

export const createArticle = (body: KbArticleCreateIn) =>
  api.post<KbArticle>("/kb/articles", body);

export const updateArticle = (articleId: string, body: KbArticleUpdateIn) =>
  api.put<KbArticle>(`/kb/articles/${encodeURIComponent(articleId)}`, body);

export const deleteArticle = (articleId: string) =>
  api.del<{ ok: boolean }>(`/kb/articles/${encodeURIComponent(articleId)}`);

// ─── Article lifecycle ───────────────────────────────────────────────────────

export const publishArticle = (articleId: string) =>
  api.post<KbArticle>(`/kb/articles/${encodeURIComponent(articleId)}/publish`, {});

export const unpublishArticle = (articleId: string) =>
  api.post<KbArticle>(`/kb/articles/${encodeURIComponent(articleId)}/unpublish`, {});

export const expireArticle = (articleId: string, reason = "") =>
  api.post<KbArticle>(`/kb/articles/${encodeURIComponent(articleId)}/expire`, { reason });

export const rateArticle = (articleId: string, helpful: boolean) =>
  api.post<KbRateOut>(`/kb/articles/${encodeURIComponent(articleId)}/rate`, { helpful });

// ─── Attachments ─────────────────────────────────────────────────────────────

export const listAttachments = (articleId: string) =>
  api.get<{ attachments: KbAttachment[] }>(
    `/kb/articles/${encodeURIComponent(articleId)}/attachments`,
  );

export const uploadAttachment = (articleId: string, file: File) => {
  const fd = new FormData();
  fd.append("file", file);
  return api.upload<KbAttachment>(
    `/kb/articles/${encodeURIComponent(articleId)}/attachments`,
    fd,
  );
};

export const deleteAttachment = (articleId: string, attachmentId: string) =>
  api.del<{ ok: boolean }>(
    `/kb/articles/${encodeURIComponent(articleId)}/attachments/${encodeURIComponent(attachmentId)}`,
  );

// ─── Categories ──────────────────────────────────────────────────────────────

export const listCategories = () =>
  api.get<KbCategoryListOut>("/kb/categories");

export const getCategory = (categoryId: string) =>
  api.get<KbCategory>(`/kb/categories/${encodeURIComponent(categoryId)}`);

export const createCategory = (body: KbCategoryIn) =>
  api.post<KbCategory>("/kb/categories", body);

export const updateCategory = (categoryId: string, body: KbCategoryIn) =>
  api.put<KbCategory>(`/kb/categories/${encodeURIComponent(categoryId)}`, body);

export const deleteCategory = (categoryId: string) =>
  api.del<{ ok: boolean }>(`/kb/categories/${encodeURIComponent(categoryId)}`);

// ─── Tags ────────────────────────────────────────────────────────────────────

export const listPopularTags = (limit = 50) =>
  api.get<KbTagListOut>("/kb/tags", { limit: String(limit) });

export const listArticlesByTag = (tag: string, opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<KbArticleListOut>(`/kb/tags/${encodeURIComponent(tag)}/articles`, params);
};

// ─── Public portal (unauthenticated) ─────────────────────────────────────────

export const publicSearchArticles = (q: string, opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = { q };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<KbSearchOut>("/public/kb/search", params);
};

export const publicListArticles = (opts?: {
  category_id?: string;
  tag?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.category_id) params["category_id"] = opts.category_id;
  if (opts?.tag) params["tag"] = opts.tag;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<KbArticleListOut>("/public/kb/articles", params);
};

export const publicGetArticle = (articleId: string) =>
  api.get<KbArticle>(`/public/kb/articles/${encodeURIComponent(articleId)}`);

export const publicListCategories = () =>
  api.get<KbCategoryListOut>("/public/kb/categories");

export const publicListTags = (limit = 50) =>
  api.get<KbTagListOut>("/public/kb/tags", { limit: String(limit) });
