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

// ─── API functions ──────────────────────────────────────────────

export const addShelfProduct = (sessionId: string, body: ShelfAddRequest) =>
  api.post<ShelfItem>(`/broadcast/sessions/${sessionId}/products`, body);

export const removeShelfProduct = (sessionId: string, itemId: string) =>
  api.del<{ ok: boolean; item_id: string }>(`/broadcast/sessions/${sessionId}/products/${itemId}`);

export const getShelfProducts = (sessionId: string) =>
  api.get<ShelfListResponse>(`/broadcast/sessions/${sessionId}/products`);

export const reorderShelf = (sessionId: string, itemOrder: string[]) =>
  api.patch<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/products/reorder`, { item_order: itemOrder });
