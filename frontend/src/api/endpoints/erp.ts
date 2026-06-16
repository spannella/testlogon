// ─────────────────────────────────────────────────────────────────────────────
// OFBiz Core ERP Admin — API endpoint wrappers + inline types (OFB cluster).
//
// LIVE backend coverage (source of truth = as-built routers):
//   • Inventory    — app/routers/inventory.py     (prefix /ui/inventory)
//   • Returns/RMA  — app/routers/returns_rma.py   (prefix /ui/returns)
//
// NOT exposed over HTTP at build time (services exist but no router is mounted):
//   • GL chart-of-accounts / journal entries (app/services/gl_accounts.py,
//     gl_posting.py) — no router → deferred.
//   • AR/AP aging (app/services/ar_subledger.py) — no router → deferred.
//   • Pricing rules (app/services/pricing_rules.py) — consumed internally by
//     shoppingcart only, no admin router → deferred.
//
// Both live routers are flag-gated default-OFF:
//   INVENTORY_RESERVATIONS_ENABLED → /ui/inventory/* returns 404 when off
//   RETURNS_RMA_ENABLED            → /ui/returns/*   returns 404 when off
// The pages handle ApiError.status === 404 as a "feature not enabled" state.
// ─────────────────────────────────────────────────────────────────────────────

import { api } from "@/api/client";

// ─── Inventory types (mirror app/models.py) ──────────────────────────────────

export type InventoryStatus = "in_stock" | "low_stock" | "out_of_stock";

export interface InventoryRecord {
  sku: string;
  location_id: string;
  on_hand: number;
  reserved: number;
  available: number;
  reorder_point: number;
  status: InventoryStatus;
  updated_at: number;
}

export interface InventorySetOnHandReq {
  sku: string;
  on_hand: number;
  location_id?: string;
  reorder_point?: number | null;
  reason?: string | null;
}

export interface InventoryAdjustReq {
  sku: string;
  delta: number;
  location_id?: string;
  reason?: string | null;
}

export interface InventoryReserveReq {
  sku: string;
  quantity: number;
  location_id?: string;
  cart_id?: string | null;
  ttl_seconds?: number | null;
}

export type ReservationStatus = "active" | "committed" | "released" | "expired";

export interface Reservation {
  reservation_id: string;
  sku: string;
  location_id: string;
  quantity: number;
  status: ReservationStatus;
  cart_id?: string | null;
  user_sub?: string | null;
  created_at: number;
  expires_at: number;
}

export interface LowStockResp {
  items: InventoryRecord[];
}

// ─── Inventory endpoints ─────────────────────────────────────────────────────

/** GET /ui/inventory/items/{sku} — single inventory record (storefront read). */
export const getInventoryItem = (sku: string) =>
  api.get<InventoryRecord>(`/ui/inventory/items/${encodeURIComponent(sku)}`);

/** PUT /ui/inventory/items — admin: set absolute on-hand for a SKU. */
export const setInventoryOnHand = (body: InventorySetOnHandReq) =>
  api.put<InventoryRecord>("/ui/inventory/items", body);

/** POST /ui/inventory/items/adjust — admin: delta-adjust on-hand for a SKU. */
export const adjustInventory = (body: InventoryAdjustReq) =>
  api.post<InventoryRecord>("/ui/inventory/items/adjust", body);

/**
 * GET /ui/inventory/low-stock?status=… — admin: list records by derived status.
 * status ∈ {low_stock, out_of_stock, in_stock} (default low_stock).
 */
export const listInventoryByStatus = (status: InventoryStatus = "low_stock") =>
  api.get<LowStockResp>("/ui/inventory/low-stock", { status });

/** POST /ui/inventory/reservations — create a soft reservation (customer). */
export const createReservation = (body: InventoryReserveReq) =>
  api.post<Reservation>("/ui/inventory/reservations", body);

/** GET /ui/inventory/reservations/{id} — read a reservation. */
export const getReservation = (reservationId: string) =>
  api.get<Reservation>(`/ui/inventory/reservations/${encodeURIComponent(reservationId)}`);

/** POST /ui/inventory/reservations/{id}/release — release a reservation. */
export const releaseReservation = (reservationId: string) =>
  api.post<Reservation>(
    `/ui/inventory/reservations/${encodeURIComponent(reservationId)}/release`,
  );

// ─── Returns / RMA types (mirror app/models.py) ──────────────────────────────

export type ReturnStatus =
  | "requested"
  | "approved"
  | "rejected"
  | "received"
  | "refunded"
  | "closed";

export interface ReturnLineIn {
  item_id: string;
  quantity: number;
}

export interface ReturnLineOut {
  item_id: string;
  sku?: string | null;
  quantity: number;
  amount_cents: number;
}

export interface ReturnRecord {
  return_id: string;
  order_id: string;
  user_sub: string;
  status: ReturnStatus;
  reason?: string | null;
  currency: string;
  refund_amount_cents: number;
  refund_ledger_sk?: string | null;
  provider?: string | null;
  lines: ReturnLineOut[];
  created_at: number;
  updated_at: number;
  decided_by?: string | null;
  decision_note?: string | null;
}

export interface ReturnRequestReq {
  order_id: string;
  reason: string;
  lines: ReturnLineIn[];
}

export interface ReturnDecisionReq {
  note?: string | null;
}

export interface ReturnQueueResp {
  returns: ReturnRecord[];
}

// ─── Returns / RMA endpoints ─────────────────────────────────────────────────

/** POST /ui/returns — customer: request a return. */
export const requestReturn = (body: ReturnRequestReq) =>
  api.post<ReturnRecord>("/ui/returns", body);

/** GET /ui/returns/{id} — read a single return (own, or admin via queue). */
export const getReturn = (returnId: string) =>
  api.get<ReturnRecord>(`/ui/returns/${encodeURIComponent(returnId)}`);

/** GET /ui/returns/admin/queue?status=… — admin: returns by status. */
export const listReturnsQueue = (status: ReturnStatus = "requested") =>
  api.get<ReturnQueueResp>("/ui/returns/admin/queue", { status });

/** POST /ui/returns/admin/{id}/approve — admin decision. */
export const approveReturn = (returnId: string, note?: string) =>
  api.post<ReturnRecord>(
    `/ui/returns/admin/${encodeURIComponent(returnId)}/approve`,
    note ? { note } : undefined,
  );

/** POST /ui/returns/admin/{id}/reject — admin decision. */
export const rejectReturn = (returnId: string, note?: string) =>
  api.post<ReturnRecord>(
    `/ui/returns/admin/${encodeURIComponent(returnId)}/reject`,
    note ? { note } : undefined,
  );

/** POST /ui/returns/admin/{id}/receive — mark goods received. */
export const receiveReturn = (returnId: string) =>
  api.post<ReturnRecord>(`/ui/returns/admin/${encodeURIComponent(returnId)}/receive`);

/** POST /ui/returns/admin/{id}/refund — issue refund. */
export const refundReturn = (returnId: string) =>
  api.post<ReturnRecord>(`/ui/returns/admin/${encodeURIComponent(returnId)}/refund`);

/** POST /ui/returns/admin/{id}/close — close the return. */
export const closeReturn = (returnId: string) =>
  api.post<ReturnRecord>(`/ui/returns/admin/${encodeURIComponent(returnId)}/close`);

// ─── Shared helpers ──────────────────────────────────────────────────────────

/** Integer cents → localized currency string (e.g. 1299 → "$12.99"). */
export function formatCents(cents: number | null | undefined, currency = "usd"): string {
  const value = (cents ?? 0) / 100;
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: (currency || "usd").toUpperCase(),
    }).format(value);
  } catch {
    return `$${value.toFixed(2)}`;
  }
}
