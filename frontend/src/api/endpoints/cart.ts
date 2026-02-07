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

export const purchaseCart = (cartId: string) =>
  api.post<CartPurchase>(`/ui/shoppingcart/carts/${cartId}/purchase`);

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

export const createReview = (itemId: string, body: CatalogReviewIn) =>
  api.post<CatalogReview>(`/ui/catalog/items/${itemId}/reviews`, body);
