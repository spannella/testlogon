// Pure helpers for the ecommerce-in-chat cards (EPIC F: FE-150 product card,
// FE-151 order/purchase-share card). Kept dependency-light so payload building,
// the PII choke point and previews are unit-testable without React.

import type { CatalogItem } from "@/api/types";
import type { OrderLineItem } from "@/api/endpoints/orderLifecycle";

// ── Product card (FE-150) ────────────────────────────────────────

// The wire/payload carried on a product_card message. Prices ride as integer
// cents (no float drift); category_id + currency travel so the Buy button can
// deep-link to the existing product detail / checkout route.
export interface ProductCardPayload {
  product_id: string;
  category_id?: string;
  title: string;
  price_cents: number;
  currency: string;
  image?: string;
  in_stock: boolean;
}

/**
 * Project a catalog item into a shareable product_card payload. `in_stock` is
 * derived from stock_status / stock_count so the renderer never has to re-derive
 * it (out_of_stock, or a numeric count of 0, ⇒ not in stock).
 */
export function buildProductCardPayload(item: CatalogItem): ProductCardPayload {
  const status = String(item.stock_status ?? "").toLowerCase();
  const countOut = typeof item.stock_count === "number" && item.stock_count <= 0;
  const inStock = !(status === "out_of_stock" || countOut);
  return {
    product_id: item.item_id,
    category_id: item.category_id,
    title: item.name,
    price_cents: item.price_cents,
    currency: item.currency || "USD",
    image: item.image_urls?.[0],
    in_stock: inStock,
  };
}

// ── Order/purchase-share card (FE-151) ───────────────────────────

export type OrderShareMode = "receipt" | "gift" | "recommendation";

export interface OrderCardItemSummary {
  name: string;
  quantity: number;
}

// The wire/payload carried on an order_card message. In "receipt" mode this is
// the PII choke point: NO buyer name and NO shipping address are ever included.
// gift / recommendation modes carry the item summary (never PII either -- the
// point of the card is to share WHAT, not WHO/WHERE).
export interface OrderCardPayload {
  order_id: string;
  mode: OrderShareMode;
  status: string;
  currency: string;
  amount_cents?: number;
  item_count: number;
  items: OrderCardItemSummary[];
}

// Loose shape accepted by buildOrderCardPayload: an order-list row plus optional
// joined line items (from getOrderLifecycle include=line_items). Fields that
// COULD carry PII (buyer_name / ship_to / address_* ) are deliberately NOT read.
export interface OrderCardSource {
  order_id: string;
  status?: string | null;
  lifecycle_status?: string | null;
  currency?: string | null;
  amount_cents?: number | null;
  line_item_count?: number | null;
  line_items?: Pick<OrderLineItem, "name" | "quantity">[] | null;
}

/**
 * Build an order_card payload for the chosen share mode. This is the single PII
 * choke point (FE-151): the function ONLY ever reads order id / status / totals
 * / item names+quantities. It has no code path that reads buyer name or a
 * shipping address, so receipt mode cannot leak PII by construction. gift /
 * recommendation include the same item summary (buyer identity is still never
 * carried). Receipt mode additionally omits the money total.
 */
export function buildOrderCardPayload(
  order: OrderCardSource,
  mode: OrderShareMode,
): OrderCardPayload {
  const items: OrderCardItemSummary[] = (order.line_items ?? [])
    .filter((li) => li && typeof li.name === "string")
    .map((li) => ({ name: li.name, quantity: Number(li.quantity) || 1 }));

  const status = String(order.lifecycle_status ?? order.status ?? "unknown");
  const itemCount =
    typeof order.line_item_count === "number" && order.line_item_count > 0
      ? order.line_item_count
      : items.reduce((n, it) => n + (it.quantity || 1), 0) || items.length;

  const payload: OrderCardPayload = {
    order_id: order.order_id,
    mode,
    status,
    currency: order.currency || "USD",
    item_count: itemCount,
    items,
  };
  // Receipt mode shares the fact of purchase + items, but NOT the amount paid.
  if (mode !== "receipt" && typeof order.amount_cents === "number") {
    payload.amount_cents = order.amount_cents;
  }
  return payload;
}

// ── price format + previews ──────────────────────────────────────

/** e.g. "$12.50" from integer cents. Currency-aware. */
export function formatPriceCents(
  cents: number | null | undefined,
  currency = "USD",
): string {
  if (cents == null || !Number.isFinite(cents)) return "";
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(
      cents / 100,
    );
  } catch {
    return `$${(cents / 100).toFixed(2)}`;
  }
}

/** Conversation-list / reply preview: "[Product: Blue Widget]". */
export function productCardPreview(
  msg: { product_title?: string | null; title?: string | null },
): string {
  const title = (msg.product_title ?? msg.title ?? "").trim();
  return title ? `[Product: ${title}]` : "[Product]";
}

const ORDER_MODE_LABEL: Record<OrderShareMode, string> = {
  receipt: "Receipt",
  gift: "Gift",
  recommendation: "Recommendation",
};

export function orderModeLabel(mode: string | undefined | null): string {
  if (mode && mode in ORDER_MODE_LABEL) return ORDER_MODE_LABEL[mode as OrderShareMode];
  return "Order";
}

/** Conversation-list / reply preview: "[Order: 2 items]" / "[Order: Blue Widget]". */
export function orderCardPreview(
  msg: {
    order_items?: OrderCardItemSummary[] | null;
    order_item_count?: number | null;
  },
): string {
  const items = msg.order_items ?? [];
  if (items.length === 1 && items[0]?.name) return `[Order: ${items[0].name}]`;
  const count =
    typeof msg.order_item_count === "number" && msg.order_item_count > 0
      ? msg.order_item_count
      : items.reduce((n, it) => n + (it.quantity || 1), 0) || items.length;
  if (count > 0) return `[Order: ${count} item${count === 1 ? "" : "s"}]`;
  return "[Order]";
}
