import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz ORDER-LIFECYCLE (ORD-001..ORD-015) endpoint wrappers.
//
// Types are defined INLINE here (not in the shared api/types.ts) and mirror the
// LIVE Pydantic models in app/models.py (OrderLifecycleOut, OrderLineItemOut,
// OrderStatusHistoryEntry, OrderTransitionResult, …) and the LIVE router
// app/routers/order_lifecycle.py (prefix /ui/orders).
//
// NOTE: the live router exposes NO "list orders" endpoint. Order discovery is
// driven by entering an order id (lookup-by-id) on the list page; the status
// filter is applied client-side over the looked-up orders.
//
// Feature gate: S.order_lifecycle_enabled (default OFF). When off every handler
// returns 503 {code: "feature_disabled"}. UI handles 503/404 gracefully.
// ─────────────────────────────────────────────────────────────────────────────

export type OrderLifecycleStatus =
  | "created"
  | "approved"
  | "allocated"
  | "picking"
  | "packed"
  | "shipped"
  | "completed"
  | "held"
  | "backorder"
  | "cancelled"
  | "returned";

export type OrderAdjustmentType =
  | "discount"
  | "surcharge"
  | "tax"
  | "shipping"
  | "promotion";

export interface OrderLineItem {
  item_id: string;
  sku: string;
  name: string;
  quantity: number;
  unit_price_cents: number;
  currency: string;
  metadata: Record<string, unknown>;
}

export interface OrderStatusHistoryEntry {
  event_id: string;
  from_status: string | null;
  to_status: string;
  actor: string;
  reason: string;
  ts: number; // Unix seconds
}

export interface OrderAdjustment {
  adjustment_id: string;
  adj_type: OrderAdjustmentType;
  amount_cents: number;
  currency: string;
  label: string;
  taxable: boolean;
  source_rule_ref: string | null;
  created_at: number;
}

export interface ShipGroup {
  ship_group_id: string;
  ship_method: string;
  address_id: string | null;
  item_ids: string[];
  ship_status: OrderLifecycleStatus;
  ship_date_bucket: string | null;
  ship_ts: number | null;
  tracking_number: string | null;
  tracking_url: string | null;
  created_at: number;
  updated_at: number;
}

/** Mirror of app.models.OrderLifecycleOut. */
export interface OrderLifecycle {
  order_id: string;
  status: string; // legacy mirror status
  created_at: string; // ISO string
  updated_at: string; // ISO string
  source_system: string;
  correlation_id: string;
  amount_cents: number;
  currency: string;
  line_item_count: number;
  metadata: Record<string, unknown>;

  // Lifecycle fields (present only when ORDER_LIFECYCLE_ENABLED is on)
  lifecycle_status: OrderLifecycleStatus | null;
  updated_ts: number | null;
  pre_hold_status: string | null;

  // Enriched collections (null = not fetched; [] = fetched but empty)
  adjustments: OrderAdjustment[] | null;
  ship_groups: ShipGroup[] | null;
  status_history: OrderStatusHistoryEntry[] | null;

  // Derived from the transition graph
  allowed_transitions: string[] | null;

  // Joined order items
  line_items: OrderLineItem[] | null;
}

/** Mirror of app.models.OrderTransitionResult. */
export interface OrderTransitionResult {
  order: OrderLifecycle;
  event_id: string;
  from_status: string | null;
  to_status: string;
}

export interface OrderTransitionRequest {
  target_status: OrderLifecycleStatus;
  reason?: string;
  idempotency_key?: string;
}

export interface OrderCancelRequest {
  reason?: string;
  refund?: boolean;
}

/** Comma-separated include groups accepted by GET /lifecycle. */
export type LifecycleInclude = "history" | "adjustments" | "ship_groups";

// ─── List orders (LIVE: GET /ui/orders) ─────────────────────────────────────

/** One row of GET /ui/orders. Owner-scoped for users; admin may filter. */
export interface OrderListItem {
  order_id: string;
  user_id: string;
  status: string;
  lifecycle_status: OrderLifecycleStatus | null;
  created_at: string; // ISO 8601 string (backend OrderListItem.created_at: str)
  updated_at: string; // ISO 8601 string
  source_system: string;
  correlation_id: string;
  amount_cents: number;
  currency: string;
  line_item_count: number;
}

export interface OrderListOut {
  orders: OrderListItem[];
  next_cursor: string | null;
}

/**
 * GET /ui/orders?user_id=&status=&limit=50&cursor=
 * Normal users list their own orders; admins may pass user_id/status filters.
 * Feature-gated: returns 503 {code:"feature_disabled"} when the order-lifecycle
 * flag is off.
 */
export const listOrders = (opts?: {
  userId?: string;
  status?: OrderLifecycleStatus;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.userId) params["user_id"] = opts.userId;
  if (opts?.status) params["status"] = opts.status;
  params["limit"] = String(opts?.limit ?? 50);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<OrderListOut>("/ui/orders", params);
};

// ─── Endpoints (LIVE paths under /ui/orders) ────────────────────────────────

/**
 * GET /ui/orders/{order_id}/lifecycle
 * Enriched order read. `include` requests sub-collections (history/adjustments/
 * ship_groups). Owner-or-admin gated (404 for non-owner non-admin).
 */
export const getOrderLifecycle = (
  orderId: string,
  include: LifecycleInclude[] = [],
) =>
  api.get<OrderLifecycle>(
    `/ui/orders/${encodeURIComponent(orderId)}/lifecycle`,
    include.length ? { include: include.join(",") } : undefined,
  );

/**
 * GET /ui/orders/{order_id}/history
 * Status-history entries, newest-first. Owner-or-admin gated.
 */
export const getOrderHistory = (orderId: string) =>
  api.get<OrderStatusHistoryEntry[]>(
    `/ui/orders/${encodeURIComponent(orderId)}/history`,
  );

/**
 * POST /ui/orders/{order_id}/transition
 * Execute one state-machine transition. ADMIN/ROOT only (CSRF enforced).
 */
export const transitionOrder = (orderId: string, body: OrderTransitionRequest) =>
  api.post<OrderTransitionResult>(
    `/ui/orders/${encodeURIComponent(orderId)}/transition`,
    body,
  );

/**
 * POST /ui/orders/{order_id}/cancel
 * Cancel an order (optionally refund). Owner (only created/approved) or admin.
 */
export const cancelOrder = (orderId: string, body: OrderCancelRequest = {}) =>
  api.post<OrderLifecycle>(
    `/ui/orders/${encodeURIComponent(orderId)}/cancel`,
    body,
  );

// ─── Adjustments ─────────────────────────────────────────────────────────────

export interface AdjustmentListResponse {
  order_id: string;
  adjustments: OrderAdjustment[];
  total_adjustments_cents: number;
}

export interface AddAdjustmentRequest {
  adj_type: OrderAdjustmentType;
  amount_cents: number;
  currency?: string;
  label: string;
  taxable?: boolean;
}

/**
 * GET /ui/orders/{order_id}/adjustments
 * List price adjustments on an order. Owner-or-admin gated.
 */
export const listOrderAdjustments = (orderId: string) =>
  api.get<AdjustmentListResponse>(
    `/ui/orders/${encodeURIComponent(orderId)}/adjustments`,
  );

/**
 * POST /ui/orders/{order_id}/adjustments
 * Add a price adjustment. ADMIN/ROOT only.
 */
export const addOrderAdjustment = (
  orderId: string,
  body: AddAdjustmentRequest,
) =>
  api.post<OrderAdjustment>(
    `/ui/orders/${encodeURIComponent(orderId)}/adjustments`,
    body,
  );

/**
 * DELETE /ui/orders/{order_id}/adjustments/{adj_id}
 * Remove a price adjustment. ADMIN/ROOT only.
 */
export const removeOrderAdjustment = (orderId: string, adjId: string) =>
  api.del<{ ok: boolean }>(
    `/ui/orders/${encodeURIComponent(orderId)}/adjustments/${encodeURIComponent(adjId)}`,
  );

// ─── Ship groups ──────────────────────────────────────────────────────────────

export interface ShipGroupListResponse {
  order_id: string;
  ship_groups: ShipGroup[];
}

export interface CreateShipGroupRequest {
  ship_method: string;
  address_id?: string | null;
  item_ids?: string[];
}

export interface UpdateShipGroupRequest {
  tracking_number?: string | null;
  tracking_url?: string | null;
  ship_status?: OrderLifecycleStatus;
  ship_date_bucket?: string | null;
  ship_ts?: number | null;
}

/**
 * GET /ui/orders/{order_id}/ship-groups
 * List ship groups for an order. Owner-or-admin gated.
 */
export const listShipGroups = (orderId: string) =>
  api.get<ShipGroupListResponse>(
    `/ui/orders/${encodeURIComponent(orderId)}/ship-groups`,
  );

/**
 * POST /ui/orders/{order_id}/ship-groups
 * Create a new ship group. ADMIN/ROOT only.
 */
export const createShipGroup = (
  orderId: string,
  body: CreateShipGroupRequest,
) =>
  api.post<ShipGroup>(
    `/ui/orders/${encodeURIComponent(orderId)}/ship-groups`,
    body,
  );

/**
 * PATCH /ui/orders/{order_id}/ship-groups/{sg_id}
 * Update tracking / status of a ship group. ADMIN/ROOT only.
 */
export const updateShipGroup = (
  orderId: string,
  sgId: string,
  body: UpdateShipGroupRequest,
) =>
  api.patch<ShipGroup>(
    `/ui/orders/${encodeURIComponent(orderId)}/ship-groups/${encodeURIComponent(sgId)}`,
    body,
  );

/**
 * DELETE /ui/orders/{order_id}/ship-groups/{sg_id}
 * Remove a ship group. ADMIN/ROOT only.
 */
export const deleteShipGroup = (orderId: string, sgId: string) =>
  api.del<{ ok: boolean }>(
    `/ui/orders/${encodeURIComponent(orderId)}/ship-groups/${encodeURIComponent(sgId)}`,
  );

// ─── Display helpers ─────────────────────────────────────────────────────────

/** All 11 lifecycle statuses (for filter dropdowns). */
export const ORDER_LIFECYCLE_STATUSES: OrderLifecycleStatus[] = [
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
];

/** Render integer cents as a currency string. */
export function formatCents(cents: number, currency = "USD"): string {
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: currency || "USD",
    }).format((cents || 0) / 100);
  } catch {
    return `$${((cents || 0) / 100).toFixed(2)}`;
  }
}

/** Human-friendly title-cased status label. */
export function prettyStatus(status: string | null | undefined): string {
  if (!status) return "—";
  return status.charAt(0).toUpperCase() + status.slice(1);
}
