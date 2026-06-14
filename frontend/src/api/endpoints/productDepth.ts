import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz CATALOG-DEPTH (PRD-006 / PRD-007 / PRD-012) — admin product depth API.
//
// All wrappers target the LIVE catalog router (prefix /ui/catalog). The product
// depth feature flag (S.product_depth_enabled) defaults OFF → every endpoint
// below returns 404 when disabled. Callers must handle 404 gracefully.
//
// Types are defined INLINE here (per shared-tree rules) and mirror the LIVE
// Pydantic models in app/models.py + the dict shapes returned by the service
// layer (app/services/product_features.py, product_variants.py,
// product_price_components.py).
// ─────────────────────────────────────────────────────────────────────────────

// ─── Feature categories & values (PRD-006) ──────────────────────────────────

export interface FeatureValue {
  feature_value_id: string;
  feature_category_id: string;
  name: string;
  price_delta_cents: number;
  position: number;
  creator_id?: string;
  created_at?: number;
  updated_at?: number;
}

export interface FeatureCategory {
  feature_category_id: string;
  name: string;
  description?: string | null;
  creator_id: string;
  created_at?: number;
  updated_at?: number;
  /** Present only when listed/attached with include_values=true. */
  values?: FeatureValue[];
}

export interface FeatureCategoryListResp {
  feature_categories: FeatureCategory[];
  count: number;
}

export interface ItemFeaturesResp {
  item_id: string;
  features: FeatureCategory[];
  count: number;
}

export const listFeatureCategories = (includeValues = true) =>
  api.get<FeatureCategoryListResp>("/ui/catalog/feature-categories", {
    include_values: includeValues ? "true" : "false",
  });

export const createFeatureCategory = (body: {
  name: string;
  description?: string | null;
  feature_category_id?: string;
}) => api.post<FeatureCategory>("/ui/catalog/feature-categories", body);

export const deleteFeatureCategory = (fcId: string) =>
  api.del<void>(`/ui/catalog/feature-categories/${encodeURIComponent(fcId)}`);

export const addFeatureValue = (
  fcId: string,
  body: { name: string; price_delta_cents?: number; position?: number },
) =>
  api.post<FeatureValue>(
    `/ui/catalog/feature-categories/${encodeURIComponent(fcId)}/values`,
    body,
  );

export const deleteFeatureValue = (fcId: string, fvId: string) =>
  api.del<void>(
    `/ui/catalog/feature-categories/${encodeURIComponent(fcId)}/values/${encodeURIComponent(fvId)}`,
  );

// Product ↔ feature-category binding (feature applications)
export const attachFeatureCategory = (itemId: string, featureCategoryId: string) =>
  api.post<Record<string, unknown>>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/feature-categories`,
    { feature_category_id: featureCategoryId },
  );

export const detachFeatureCategory = (itemId: string, fcId: string) =>
  api.del<void>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/feature-categories/${encodeURIComponent(fcId)}`,
  );

export const listItemFeatures = (itemId: string) =>
  api.get<ItemFeaturesResp>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/features`,
  );

// ─── Product type (virtual / variant) (PRD-007) ─────────────────────────────

export type ProductType =
  | "standalone"
  | "virtual"
  | "variant"
  | "bundle"
  | "kit"
  | "digital";

export interface ProductTypeResp {
  item_id: string;
  product_type: ProductType;
}

export const getProductType = (itemId: string) =>
  api.get<ProductTypeResp>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/product-type`,
  );

export const setProductType = (itemId: string, productType: ProductType) =>
  api.post<Record<string, unknown>>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/product-type`,
    { product_type: productType },
  );

// ─── Variants (PRD-007) ─────────────────────────────────────────────────────

export interface Variant {
  variant_id: string;
  parent_item_id: string;
  sku: string;
  /** {feature_category_id: feature_value_id} */
  feature_values: Record<string, string>;
  price_delta_cents: number;
  effective_price_cents: number;
  creator_id: string;
  created_at: number;
}

export interface VariantListResp {
  item_id: string;
  variants: Variant[];
  count: number;
}

export const listVariants = (itemId: string, limit = 100) =>
  api.get<VariantListResp>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/variants`,
    { limit: String(limit) },
  );

export const createVariant = (
  itemId: string,
  body: { feature_values: Record<string, string>; sku_override?: string },
) =>
  api.post<Variant>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/variants`,
    body,
  );

export const deleteVariant = (itemId: string, variantId: string) =>
  api.del<void>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/variants/${encodeURIComponent(variantId)}`,
  );

// ─── Price components (PRD-012) ─────────────────────────────────────────────

export type PriceType =
  | "LIST"
  | "DEFAULT"
  | "PROMO"
  | "COMPETITIVE"
  | "MINIMUM"
  | "AVERAGE_COST";

export interface PriceComponentIn {
  price_type: PriceType;
  amount_cents: number;
  currency?: string;
  effective_at: number;
  expires_at?: number | null;
}

export interface PriceComponent {
  price_component_id: string;
  item_id: string;
  price_type: string;
  amount_cents: number;
  currency: string;
  effective_at: number;
  expires_at?: number | null;
  is_active: boolean;
}

export interface PriceComponentListResp {
  item_id: string;
  components: PriceComponent[];
  count: number;
}

export interface SetPriceComponentsResp {
  item_id: string;
  price_type: string;
  components: PriceComponent[];
}

export interface EffectivePrice {
  amount_cents: number;
  currency: string;
  price_component_id?: string | null;
  source: string; // "price_component" | "scalar_fallback"
}

export const listPriceComponents = (itemId: string, priceType?: PriceType) =>
  api.get<PriceComponentListResp>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/price-components`,
    priceType ? { price_type: priceType } : undefined,
  );

export const addPriceComponent = (itemId: string, body: PriceComponentIn) =>
  api.post<PriceComponent>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/price-components`,
    body,
  );

export const setPriceComponents = (
  itemId: string,
  priceType: PriceType,
  components: PriceComponentIn[],
) =>
  api.put<SetPriceComponentsResp>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/price-components`,
    { price_type: priceType, components },
  );

export const getEffectivePrice = (
  itemId: string,
  priceType: PriceType = "DEFAULT",
  asOf?: number,
) => {
  const params: Record<string, string> = { price_type: priceType };
  if (asOf != null) params["as_of"] = String(asOf);
  return api.get<EffectivePrice>(
    `/ui/catalog/items/${encodeURIComponent(itemId)}/effective-price`,
    params,
  );
};

// ─── Categories & items (base catalog, reused by the admin tree) ────────────

export interface CatalogCategory {
  category_id: string;
  name: string;
  description?: string | null;
  creator_id?: string | null;
  created_at: string;
}

export interface CatalogCategoryListResp {
  items: CatalogCategory[];
  next_token?: string | null;
}

export interface CatalogItem {
  category_id: string;
  item_id: string;
  name: string;
  description?: string | null;
  price_cents: number;
  currency: string;
  image_urls: string[];
  attributes: Record<string, unknown>;
  creator_id?: string | null;
  created_at: string;
  updated_at: string;
  stock_count?: number | null;
  stock_status: string;
  low_stock_threshold: number;
  stock_updated_at?: string | null;
  position?: number | null;
}

export interface CatalogItemListResp {
  items: CatalogItem[];
  next_token?: string | null;
}

export const listCategories = (pageSize = 200, nextToken?: string) => {
  const params: Record<string, string> = { page_size: String(pageSize) };
  if (nextToken) params["next_token"] = nextToken;
  return api.get<CatalogCategoryListResp>("/ui/catalog/categories", params);
};

export const createCategory = (body: {
  name: string;
  description?: string | null;
  category_id?: string;
}) => api.post<CatalogCategory>("/ui/catalog/categories", body);

export const deleteCategory = (categoryId: string, cascade = false) =>
  api.del<{ ok: boolean }>(
    `/ui/catalog/categories/${encodeURIComponent(categoryId)}`,
    cascade ? { cascade: "true" } : undefined,
  );

export const listItems = (categoryId: string, pageSize = 200, nextToken?: string) => {
  const params: Record<string, string> = { page_size: String(pageSize) };
  if (nextToken) params["next_token"] = nextToken;
  return api.get<CatalogItemListResp>(
    `/ui/catalog/categories/${encodeURIComponent(categoryId)}/items`,
    params,
  );
};

export const createItem = (
  categoryId: string,
  body: {
    name: string;
    description?: string | null;
    price_cents: number;
    currency?: string;
    image_urls?: string[];
    attributes?: Record<string, unknown>;
    stock_count?: number | null;
    low_stock_threshold?: number | null;
    item_id?: string;
  },
) =>
  api.post<CatalogItem>(
    `/ui/catalog/categories/${encodeURIComponent(categoryId)}/items`,
    body,
  );

export const deleteItem = (categoryId: string, itemId: string) =>
  api.del<{ ok: boolean }>(
    `/ui/catalog/categories/${encodeURIComponent(categoryId)}/items/${encodeURIComponent(itemId)}`,
  );

// ─── Currency helper ────────────────────────────────────────────────────────

/** Render integer cents as a localized currency string. */
export function formatCents(cents: number, currency = "USD"): string {
  const amount = (cents || 0) / 100;
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency,
    }).format(amount);
  } catch {
    return `$${amount.toFixed(2)}`;
  }
}

/** Render a signed delta (e.g. variant price delta) with explicit +/-. */
export function formatDeltaCents(cents: number, currency = "USD"): string {
  const sign = cents > 0 ? "+" : cents < 0 ? "-" : "";
  return `${sign}${formatCents(Math.abs(cents), currency)}`;
}
