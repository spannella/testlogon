import { api } from "@/api/client";
import type {
  CartSummary,
  CartItemIn,
  CartItem,
  CartItemsResp,
  CartTotal,
  CartPurchase,
  OkResp,
  CatalogCategory,
  CatalogCategoryIn,
  CatalogItem,
  CatalogItemIn,
  CatalogReview,
  CatalogReviewIn,
  PaginatedList,
  StockAdjustment,
} from "@/api/types";

// ─── Shopping Cart ───────────────────────────────────────────────

export const createCart = () =>
  api.post<CartSummary>("/ui/shoppingcart/carts");

export const getCarts = () =>
  api.get<CartSummary[]>("/ui/shoppingcart/carts");

export const getCartItems = (cartId: string) =>
  api.get<CartItemsResp>(`/ui/shoppingcart/carts/${cartId}/items`);

export const addCartItem = (cartId: string, body: CartItemIn) =>
  api.post<CartItem>(`/ui/shoppingcart/carts/${cartId}/items`, body);

export const updateCartItemQty = (cartId: string, sku: string, quantity: number) =>
  api.patch<CartItem>(`/ui/shoppingcart/carts/${cartId}/items/${sku}`, { quantity });

export const removeCartItem = (cartId: string, sku: string) =>
  api.del<OkResp>(`/ui/shoppingcart/carts/${cartId}/items/${sku}`);

export const getCartTotal = (cartId: string) =>
  api.get<CartTotal>(`/ui/shoppingcart/carts/${cartId}/total`);

export const purchaseCart = (
  cartId: string,
  body?: { promo_code?: string; promo_code_id?: string },
) => {
  // The purchase endpoint requires an X-Idempotency-Key header (backend returns
  // 400 idempotency_key_required without it). Generate one per attempt so retries
  // after a hard failure get a fresh key while a single click is idempotent.
  const idempotencyKey =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `cart-${cartId}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return api<CartPurchase>(`/ui/shoppingcart/carts/${cartId}/purchase`, {
    method: "POST",
    body: JSON.stringify(body ?? {}),
    headers: { "X-Idempotency-Key": idempotencyKey },
  });
};

export const deleteCart = (cartId: string) =>
  api.del<OkResp>(`/ui/shoppingcart/carts/${cartId}`);

// ─── Catalog ─────────────────────────────────────────────────────

export const getCategories = (pageSize = 50, nextToken?: string) => {
  const params: Record<string, string> = { page_size: String(pageSize) };
  if (nextToken) params["next_token"] = nextToken;
  return api.get<PaginatedList<CatalogCategory>>("/ui/catalog/categories", params);
};

export const createCategory = (body: CatalogCategoryIn) =>
  api.post<CatalogCategory>("/ui/catalog/categories", body);

export const deleteCategory = (categoryId: string, cascade = false) =>
  api.del<OkResp>(`/ui/catalog/categories/${categoryId}`, cascade ? { cascade: "true" } : undefined);

export const getCategoryItems = (categoryId: string, pageSize = 50, nextToken?: string) => {
  const params: Record<string, string> = { page_size: String(pageSize) };
  if (nextToken) params["next_token"] = nextToken;
  return api.get<PaginatedList<CatalogItem>>(
    `/ui/catalog/categories/${categoryId}/items`,
    params,
  );
};

export const createCatalogItem = (categoryId: string, body: CatalogItemIn) =>
  api.post<CatalogItem>(`/ui/catalog/categories/${categoryId}/items`, body);

export const updateCatalogItem = (categoryId: string, itemId: string, body: Partial<CatalogItemIn>) =>
  api.patch<CatalogItem>(`/ui/catalog/categories/${categoryId}/items/${itemId}`, body);

export const searchCatalogItems = (q: string, pageSize = 50) =>
  api.get<PaginatedList<CatalogItem>>("/ui/catalog/items/search", {
    q,
    page_size: String(pageSize),
  });

export const getItemReviews = (itemId: string, pageSize = 50) =>
  api.get<PaginatedList<CatalogReview>>(`/ui/catalog/items/${itemId}/reviews`, {
    page_size: String(pageSize),
  });

export const deleteCatalogItem = (categoryId: string, itemId: string) =>
  api.del<OkResp>(`/ui/catalog/categories/${categoryId}/items/${itemId}`);

export const uploadItemImage = (categoryId: string, itemId: string, file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<CatalogItem>(
    `/ui/catalog/categories/${categoryId}/items/${itemId}/images/upload`,
    formData,
  );
};

export const createReview = (itemId: string, body: CatalogReviewIn) =>
  api.post<CatalogReview>(`/ui/catalog/items/${itemId}/reviews`, body);

export const adjustStock = (
  itemId: string,
  body: { delta?: number; absolute?: number; reason?: string },
) => api.patch<StockAdjustment>(`/ui/catalog/items/${itemId}/stock`, body);

export const reorderCatalogItems = (itemIds: string[]) =>
  api.patch<{ ok: boolean; results: Array<{ item_id: string; ok: boolean; error?: string }> }>(
    "/ui/catalog/items/reorder",
    { item_ids: itemIds },
  );

// ─── Bulk Operations (UX-004) ──────────────────────���────────────────────────

export interface BulkResult {
  results: Array<{ item_id: string; ok: boolean; error?: string }>;
  succeeded: number;
  failed: number;
}

export const bulkDeleteCatalogItems = (itemIds: string[]) =>
  api.post<BulkResult>("/ui/catalog/items/bulk-delete", { item_ids: itemIds });

export const bulkUpdateCatalogItems = (
  itemIds: string[],
  updates: Record<string, string>,
) =>
  api.post<BulkResult>("/ui/catalog/items/bulk-update", {
    item_ids: itemIds,
    updates,
  });
