import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// ECOMX-SELLDASH-E2 — seller-scoped sales / fulfilment endpoint wrappers.
//
// Mirrors the LIVE router app/routers/seller_ship_groups.py (mounted at
// /ui/seller/sales, + /ui/seller/analytics). A NON-ADMIN authenticated seller
// lists + fetches ONLY their own per-seller ship groups (with the buyer
// shipping address + real line-item names) and advances the order-lifecycle
// state machine scoped to their own group, entering a carrier + tracking# on
// the ship transition.
//
// Feature gate: S.order_lifecycle_enabled — every handler returns 503
// {code:"order_lifecycle_not_enabled"} when off. UI handles 503 gracefully.
// ─────────────────────────────────────────────────────────────────────────────

export interface SellerSaleLineItem {
  item_id: string;
  sku: string;
  name: string;
  quantity: number;
  unit_price_cents: number;
  line_total_cents: number;
}

/** Mirror of app.routers.seller_ship_groups.SellerSaleOut. */
export interface SellerSale {
  ship_group_id: string;
  order_id: string;
  status: string;
  allowed_transitions: string[];
  buyer_name: string;
  buyer_email: string;
  ship_to: Record<string, unknown>;
  line_items: SellerSaleLineItem[];
  item_count: number;
  subtotal_cents: number;
  currency: string;
  tracking_number: string | null;
  carrier: string | null;
  created_at: number;
  updated_at: number;
}

export interface SellerSaleListOut {
  sales: SellerSale[];
  next_cursor: string | null;
}

export interface SellerSaleTransitionRequest {
  target_status: string;
  reason?: string;
  tracking_number?: string;
  carrier?: string;
  idempotency_key?: string;
}

export interface SellerTopItem {
  item_id: string;
  name: string;
  units: number;
  revenue_cents: number;
}

/** Mirror of app.routers.seller_ship_groups.SellerAnalyticsOut. */
export interface SellerAnalytics {
  gmv_cents: number;
  units: number;
  order_count: number;
  aov_cents: number;
  open_fulfilment_count: number;
  shipped_count: number;
  delivered_count: number;
  cancelled_or_returned_count: number;
  top_item: SellerTopItem | null;
  currency: string;
}

/**
 * GET /ui/seller/sales?limit=50&cursor=
 * The authenticated seller's OWN received sales (ship groups). Seller-scoped;
 * never leaks another seller's items. 503 when order-lifecycle is off.
 */
export const listSellerSales = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  params["limit"] = String(opts?.limit ?? 50);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<SellerSaleListOut>("/ui/seller/sales", params);
};

/**
 * GET /ui/seller/sales/{ship_group_id}
 * One of the seller's own ship groups. 404 if not theirs.
 */
export const getSellerSale = (shipGroupId: string) =>
  api.get<SellerSale>(`/ui/seller/sales/${encodeURIComponent(shipGroupId)}`);

/**
 * POST /ui/seller/sales/{ship_group_id}/transition
 * Advance the seller's own ship group through the lifecycle
 * (approved→allocated→picking→packed→shipped). On the ship transition the
 * seller supplies carrier + tracking_number. 409 on an illegal transition.
 */
export const transitionSellerSale = (
  shipGroupId: string,
  body: SellerSaleTransitionRequest,
) =>
  api.post<SellerSale>(
    `/ui/seller/sales/${encodeURIComponent(shipGroupId)}/transition`,
    body,
  );

/**
 * GET /ui/seller/analytics?from_ts=&to_ts=
 * Month-to-date GMV / units / AOV / open-fulfilment count + top item, scoped
 * to the authenticated seller's OWN ship groups.
 */
export const getSellerAnalytics = (opts?: { fromTs?: number; toTs?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.fromTs) params["from_ts"] = String(opts.fromTs);
  if (opts?.toTs) params["to_ts"] = String(opts.toTs);
  return api.get<SellerAnalytics>("/ui/seller/analytics", Object.keys(params).length ? params : undefined);
};

// ─── Display helpers ─────────────────────────────────────────────────────────

/** All statuses the seller flow can transition a ship group through. */
export const SELLER_SHIP_STATUSES = [
  "created",
  "approved",
  "allocated",
  "picking",
  "packed",
  "shipped",
  "completed",
  "held",
  "backorder",
  "cancelled",
  "returned",
] as const;

/**
 * Ordered "happy-path" fulfilment stages (for a progress indicator). Terminal /
 * exception states (held/backorder/cancelled/returned) are handled separately.
 */
export const SELLER_FULFILMENT_STAGES = [
  "approved",
  "allocated",
  "picking",
  "packed",
  "shipped",
] as const;

export function prettySellerStatus(status: string | null | undefined): string {
  if (!status) return "—";
  return status.charAt(0).toUpperCase() + status.slice(1);
}

/** True while the ship group has not yet been shipped/completed/closed. */
export function isOpenFulfilment(status: string): boolean {
  return !["shipped", "completed", "cancelled", "returned"].includes(status);
}

/** Format a compact one-line ship-to address from the buyer's ship_to blob. */
export function formatShipTo(shipTo: Record<string, unknown>): string {
  if (!shipTo || Object.keys(shipTo).length === 0) return "";
  const pick = (k: string) => {
    const v = shipTo[k];
    return typeof v === "string" && v.trim() ? v.trim() : "";
  };
  const parts = [
    pick("name") || pick("full_name") || pick("recipient"),
    pick("line1") || pick("address_line1") || pick("street") || pick("address1"),
    pick("line2") || pick("address_line2") || pick("address2"),
    [pick("city"), pick("state") || pick("region"), pick("postal_code") || pick("zip") || pick("zip_code")]
      .filter(Boolean)
      .join(", "),
    pick("country"),
  ].filter(Boolean);
  return parts.join(" · ");
}
