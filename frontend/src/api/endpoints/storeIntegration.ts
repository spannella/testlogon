import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz ECM Storefront Integration — endpoint wrappers + inline TS types.
//
// These mirror the LIVE Pydantic models in app/models.py:
//   StorefrontAvailabilityOut, StorefrontVariantOut, AppliedPricingRuleLineOut,
//   CartPricingBreakdownOut, ShipGroupFulfillmentOut, OrderFulfillmentStatusOut,
//   CatalogItemOut (variants/availability enrichment), ShoppingCartTotalOut
//   (pricing_breakdown enrichment).
//
// Backend flags (STORE_INTEGRATION_ENABLED + per-surface sub-flags) default OFF.
// When off, the enriched fields come back null (the endpoints themselves never
// 404/503 — they return the legacy/minimal shape), so the UI degrades gracefully.
// ─────────────────────────────────────────────────────────────────────────────

// ── ECM-005: live availability ───────────────────────────────────────────────

export interface StorefrontAvailability {
  available: number; // on_hand - reserved (may be negative if oversold)
  on_hand: number;
  reserved: number;
  low_stock: boolean;
  stock_status: string; // in_stock | low_stock | out_of_stock | unlimited
}

// ── ECM-004: variant ──────────────────────────────────────────────────────────

export interface StorefrontVariant {
  variant_id: string;
  sku: string;
  option_selections: Record<string, unknown>;
  price_cents: number;
  availability: StorefrontAvailability | null;
}

// ── Catalog item (enriched) ───────────────────────────────────────────────────

export interface CatalogItem {
  category_id: string;
  item_id: string;
  name: string;
  description: string | null;
  price_cents: number;
  currency: string;
  image_urls: string[];
  attributes: Record<string, unknown>;
  creator_id: string | null;
  created_at: string;
  updated_at: string;
  stock_count: number | null;
  stock_status: string;
  low_stock_threshold: number;
  stock_updated_at: string | null;
  position: number | null;
  // ECM enrichment (null when integration flags off / not applicable)
  variants: StorefrontVariant[] | null;
  availability: StorefrontAvailability | null;
}

export interface CatalogItemList {
  items: CatalogItem[];
  next_token: string | null;
}

export interface CatalogCategory {
  category_id: string;
  name: string;
  description: string | null;
  creator_id: string | null;
  created_at: string;
}

export interface CatalogCategoryList {
  items: CatalogCategory[];
  next_token: string | null;
}

// ── ECM-006: pricing breakdown ────────────────────────────────────────────────

export interface AppliedPricingRuleLine {
  rule_id: string;
  rule_name: string;
  discount_type: string;
  discount_cents: number;
  applies_to_skus: string[];
}

export interface CartPricingBreakdown {
  cart_id: string;
  subtotal_cents: number;
  applied_rules: AppliedPricingRuleLine[];
  discount_cents: number;
  final_total_cents: number;
  currency: string;
}

export interface ShoppingCartTotal {
  cart_id: string;
  total_cents: number;
  currency: string;
  pricing_breakdown: CartPricingBreakdown | null;
}

export interface ShoppingCartSummary {
  cart_id: string;
  status: string;
  created_at: string;
  purchased_at: string | null;
  purchased_total_cents: number | null;
  currency: string;
  last_activity_at: number | null;
  abandoned_at: number | null;
  reminder_count: number | null;
}

export interface ShoppingCartItem {
  sku: string;
  name: string;
  quantity: number;
  unit_price_cents: number;
  line_total_cents: number;
  updated_at: string;
  image_url: string | null;
  category_id: string | null;
  item_id: string | null;
  product_type: string | null;
}

export interface ShoppingCartItems {
  cart_id: string;
  items: ShoppingCartItem[];
}

// ── ECM-007: order fulfillment ────────────────────────────────────────────────

export interface ShipGroupFulfillment {
  ship_group_id: string;
  status: string; // pending | picked | packed | shipped | delivered
  items: string[];
  carrier: string | null;
  tracking_number: string | null;
  shipped_at: number | null;
  estimated_delivery: string | null;
}

export interface OrderFulfillmentStatus {
  order_id: string;
  lifecycle_status: string | null;
  fulfillment_status: string | null;
  ship_groups: ShipGroupFulfillment[];
  tracking_numbers: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Catalog (storefront browse) — LIVE: /ui/catalog/*
// ─────────────────────────────────────────────────────────────────────────────

export const listStorefrontCategories = (opts?: { pageSize?: number; nextToken?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.pageSize) params["page_size"] = String(opts.pageSize);
  if (opts?.nextToken) params["next_token"] = opts.nextToken;
  return api.get<CatalogCategoryList>("/ui/catalog/categories", params);
};

export const listStorefrontItems = (
  categoryId: string,
  opts?: { pageSize?: number; nextToken?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.pageSize) params["page_size"] = String(opts.pageSize);
  if (opts?.nextToken) params["next_token"] = opts.nextToken;
  return api.get<CatalogItemList>(
    `/ui/catalog/categories/${encodeURIComponent(categoryId)}/items`,
    params,
  );
};

export const searchStorefrontItems = (q: string, opts?: { pageSize?: number }) => {
  const params: Record<string, string> = { q };
  if (opts?.pageSize) params["page_size"] = String(opts.pageSize);
  return api.get<CatalogItemList>("/ui/catalog/items/search", params);
};

// ─────────────────────────────────────────────────────────────────────────────
// Shopping cart (pricing breakdown + order fulfillment) — LIVE: /ui/shoppingcart/*
// ─────────────────────────────────────────────────────────────────────────────

export const listCarts = () => api.get<ShoppingCartSummary[]>("/ui/shoppingcart/carts");

export const getCartItems = (cartId: string) =>
  api.get<ShoppingCartItems>(`/ui/shoppingcart/carts/${encodeURIComponent(cartId)}/items`);

export const getCartTotal = (cartId: string) =>
  api.get<ShoppingCartTotal>(`/ui/shoppingcart/carts/${encodeURIComponent(cartId)}/total`);

export const getOrderFulfillment = (orderId: string) =>
  api.get<OrderFulfillmentStatus>(`/ui/shoppingcart/orders/${encodeURIComponent(orderId)}`);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Convert integer cents to a localized currency string. */
export function formatCents(cents: number | null | undefined, currency = "USD"): string {
  const value = (cents ?? 0) / 100;
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: (currency || "USD").toUpperCase(),
    }).format(value);
  } catch {
    return `$${value.toFixed(2)}`;
  }
}
