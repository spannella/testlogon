import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export interface ShelfItem {
  session_id: string;
  item_id: string;
  category_id: string;
  name: string;
  description: string | null;
  price_cents: number;
  currency: string;
  image_url: string | null;
  display_order: number;
  added_by: string;
  added_at: number;
  // Broadcast-exclusive pricing fields (LCOM-004 / GAP-0291).
  // All optional/nullable; backend defaults them when no broadcast price is set,
  // so existing callers that read only base fields remain unaffected.
  broadcast_price_cents?: number | null;
  broadcast_price_expires_at?: number | null;
  broadcast_price_set_at?: number | null;
  effective_price_cents?: number | null;
  is_broadcast_price?: boolean;
  discount_pct?: number;
  original_price_cents?: number | null;
}

export interface ShelfListResponse {
  session_id: string;
  items: ShelfItem[];
  count: number;
}

export interface ShelfAddRequest {
  item_id: string;
  category_id: string;
  display_order?: number;
}

// Request body for setting a broadcast-exclusive price.
// `broadcast_price_cents` must be strictly less than the catalog price
// (enforced server-side); `expires_in_seconds` is 60–86400 when provided.
export interface SetBroadcastPriceRequest {
  broadcast_price_cents: number;
  expires_in_seconds?: number;
}

export interface BroadcastPriceResponse {
  session_id: string;
  item_id: string;
  original_price_cents: number;
  broadcast_price_cents: number;
  broadcast_price_expires_at: number | null;
  discount_pct: number;
  set_by: string;
  set_at: number;
}

export interface ClearBroadcastPriceResponse {
  ok: boolean;
  item_id: string;
}

// ─── API functions ──────────────────────────────────────────────

export const addShelfProduct = (sessionId: string, body: ShelfAddRequest) =>
  api.post<ShelfItem>(`/broadcast/sessions/${sessionId}/products`, body);

export const removeShelfProduct = (sessionId: string, itemId: string) =>
  api.del<{ ok: boolean; item_id: string }>(`/broadcast/sessions/${sessionId}/products/${itemId}`);

export const getShelfProducts = (sessionId: string) =>
  api.get<ShelfListResponse>(`/broadcast/sessions/${sessionId}/products`);

export const reorderShelf = (sessionId: string, itemOrder: string[]) =>
  api.patch<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/products/reorder`, { item_order: itemOrder });

// Set a broadcast-exclusive price on a shelf product (broadcaster only).
export const setBroadcastPrice = (
  sessionId: string,
  itemId: string,
  body: SetBroadcastPriceRequest,
) =>
  api.patch<BroadcastPriceResponse>(
    `/broadcast/sessions/${sessionId}/products/${itemId}/price`,
    body,
  );

// Remove broadcast-exclusive pricing, restoring the catalog price (broadcaster only).
export const clearBroadcastPrice = (sessionId: string, itemId: string) =>
  api.del<ClearBroadcastPriceResponse>(
    `/broadcast/sessions/${sessionId}/products/${itemId}/price`,
  );
