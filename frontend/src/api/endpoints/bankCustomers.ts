/**
 * CUS-001..CUS-005 — Bank Customers, Cards, and Financial Products API wrappers.
 *
 * All types are defined inline (not imported from shared api/types.ts).
 * Backend mounts everything under /ui/* and /ui/financial-products/*.
 * Feature flags: OPEN_BANK_PROJECT_ENABLED + customer_entity_enabled (CUS)
 *                             and OPEN_BANK_PROJECT_ENABLED + financial_products_enabled (FP).
 */

import { api } from "@/api/client";

// ─── Shared attribute type ────────────────────────────────────────────────────

export type AttributeType = "STRING" | "INTEGER" | "DOUBLE" | "DATE_WITH_DAY";

// ─── CUS-001: Customer entity ─────────────────────────────────────────────────

export interface CustomerOut {
  customer_id: string;
  customer_number: string;
  legal_name: string;
  date_of_birth: string | null;
  mobile_phone: string | null;
  email: string | null;
  kyc_status: string;
  branch_id: string | null;
  created_at: number;
  updated_at: number;
  version: number;
}

export interface CustomerListOut {
  customers: CustomerOut[];
  cursor: string | null;
}

export interface CustomerCreateIn {
  legal_name: string;
  date_of_birth?: string | null;
  mobile_phone?: string | null;
  email?: string | null;
  branch_id?: string | null;
}

export interface CustomerPatchIn {
  legal_name?: string | null;
  date_of_birth?: string | null;
  mobile_phone?: string | null;
  email?: string | null;
  branch_id?: string | null;
  kyc_status?: string | null;
  expected_version: number;
}

export interface CustomerAttributeOut {
  attribute_id: string;
  name: string;
  type: string;
  value: string;
  created_at: number;
}

export interface CustomerAttributeSetIn {
  name: string;
  type: AttributeType;
  value: string;
}

// ─── CUS-002: Customer user-link + messages ───────────────────────────────────

export interface CustomerLinkIn {
  user_sub: string;
}

export interface CustomerLinkOut {
  customer_id: string;
  user_sub: string;
  linked_at: number;
  linked_by: string;
}

export interface CustomerMessageOut {
  message_id: string;
  author_sub: string;
  author_role: "STAFF" | "CUSTOMER";
  body: string;
  created_at: number;
}

export interface CustomerMessageListOut {
  messages: CustomerMessageOut[];
  cursor: string | null;
}

// ─── CUS-003: Card resource ───────────────────────────────────────────────────

export interface CardOut {
  card_id: string;
  brand: string | null;
  last4: string | null;
  exp_month: number | null;
  exp_year: number | null;
  label: string | null;
  is_default: boolean;
  card_status: string;
  card_version: number;
  created_at: number | null;
}

export interface CardListOut {
  cards: CardOut[];
}

export interface CardStatusUpdateIn {
  status: string;
  expected_version: number;
}

export interface CardAttributeOut {
  attribute_id: string;
  name: string;
  type: string;
  value: string;
  created_at: number | null;
}

export interface CardAttributeSetIn {
  name: string;
  type: AttributeType;
  value: string;
}

// ─── CUS-004: Financial Products ─────────────────────────────────────────────

export interface FinancialProductOut {
  product_code: string;
  name: string;
  parent_product_code: string | null;
  category: string | null;
  family: string | null;
  super_family: string | null;
  more_info_url: string | null;
  description: string | null;
  created_at: number;
  updated_at: number;
  version: number;
}

export interface FinancialProductListOut {
  items: FinancialProductOut[];
  cursor: string | null;
}

export interface FinancialProductCreateIn {
  product_code: string;
  name: string;
  parent_product_code?: string | null;
  category?: string | null;
  family?: string | null;
  super_family?: string | null;
  more_info_url?: string | null;
  description?: string | null;
}

export interface FinancialProductPatchIn {
  name?: string | null;
  parent_product_code?: string | null;
  category?: string | null;
  family?: string | null;
  super_family?: string | null;
  more_info_url?: string | null;
  description?: string | null;
  expected_version: number;
}

export interface ProductAttributeOut {
  attribute_id: string;
  name: string;
  type: string;
  value: string;
  created_at: number;
}

export interface ProductAttributeListOut {
  attributes: ProductAttributeOut[];
}

export interface ProductAttributeSetIn {
  name: string;
  type: AttributeType;
  value: string;
}

export interface ProductCollectionOut {
  collection_code: string;
  name: string;
  product_codes: string[];
  updated_at: number;
}

export interface ProductCollectionListOut {
  items: ProductCollectionOut[];
  cursor: string | null;
}

export interface ProductCollectionUpsertIn {
  name: string;
  product_codes: string[];
}

// ─── CUS-001: Customer CRUD ───────────────────────────────────────────────────

export const listCustomers = (opts?: { branch_id?: string; cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.branch_id) params["branch_id"] = opts.branch_id;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit != null) params["limit"] = String(opts.limit);
  return api.get<CustomerListOut>("/ui/customers", params);
};

export const getCustomer = (customer_id: string) =>
  api.get<CustomerOut>(`/ui/customers/${customer_id}`);

export const getMyCustomer = () =>
  api.get<CustomerOut>("/ui/customers/me");

export const createCustomer = (body: CustomerCreateIn) =>
  api.post<CustomerOut>("/ui/customers", body);

export const patchCustomer = (customer_id: string, body: CustomerPatchIn) =>
  api.patch<CustomerOut>(`/ui/customers/${customer_id}`, body);

// ─── CUS-001: Customer attributes ────────────────────────────────────────────

export const listCustomerAttributes = (customer_id: string) =>
  api.get<CustomerAttributeOut[]>(`/ui/customers/${customer_id}/attributes`);

export const setCustomerAttribute = (customer_id: string, body: CustomerAttributeSetIn) =>
  api.put<CustomerAttributeOut>(`/ui/customers/${customer_id}/attributes`, body);

export const deleteCustomerAttribute = (customer_id: string, attribute_id: string) =>
  api.del<{ ok: boolean }>(`/ui/customers/${customer_id}/attributes/${attribute_id}`);

// ─── CUS-002: Customer user-link ──────────────────────────────────────────────

export const listCustomerLinks = (customer_id: string) =>
  api.get<CustomerLinkOut[]>(`/ui/customers/${customer_id}/links`);

export const linkCustomerUser = (customer_id: string, body: CustomerLinkIn) =>
  api.post<CustomerLinkOut>(`/ui/customers/${customer_id}/link`, body);

// ─── CUS-002: Customer messages ───────────────────────────────────────────────

export const listCustomerMessages = (
  customer_id: string,
  opts?: { cursor?: string; limit?: number; newest_first?: boolean },
) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit != null) params["limit"] = String(opts.limit);
  if (opts?.newest_first) params["newest_first"] = "true";
  return api.get<CustomerMessageListOut>(`/ui/customers/${customer_id}/messages`, params);
};

export const postCustomerMessage = (customer_id: string, body: string) =>
  api.post<CustomerMessageOut>(`/ui/customers/${customer_id}/messages`, { body });

// ─── CUS-003: Cards ───────────────────────────────────────────────────────────

export const listCards = () =>
  api.get<CardListOut>("/ui/cards");

export const updateCardStatus = (card_id: string, body: CardStatusUpdateIn) =>
  api.patch<CardOut>(`/ui/cards/${card_id}/status`, body);

export const listCardAttributes = (card_id: string) =>
  api.get<CardAttributeOut[]>(`/ui/cards/${card_id}/attributes`);

export const setCardAttribute = (card_id: string, body: CardAttributeSetIn) =>
  api.put<CardAttributeOut>(`/ui/cards/${card_id}/attributes`, body);

export const deleteCardAttribute = (card_id: string, name: string) =>
  api.del<{ ok: boolean }>(`/ui/cards/${card_id}/attributes/${name}`);

// ─── CUS-004: Financial Products ─────────────────────────────────────────────

export const listFinancialProducts = (opts?: { category?: string; cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.category) params["category"] = opts.category;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit != null) params["limit"] = String(opts.limit);
  return api.get<FinancialProductListOut>("/ui/financial-products", params);
};

export const getFinancialProduct = (product_code: string) =>
  api.get<FinancialProductOut>(`/ui/financial-products/${product_code}`);

export const createFinancialProduct = (body: FinancialProductCreateIn) =>
  api.post<FinancialProductOut>("/ui/financial-products", body);

export const patchFinancialProduct = (product_code: string, body: FinancialProductPatchIn) =>
  api.patch<FinancialProductOut>(`/ui/financial-products/${product_code}`, body);

export const deleteFinancialProduct = (product_code: string) =>
  api.del<{ ok: boolean }>(`/ui/financial-products/${product_code}`);

export const listProductAttributes = (product_code: string) =>
  api.get<ProductAttributeListOut>(`/ui/financial-products/${product_code}/attributes`);

export const setProductAttribute = (product_code: string, body: ProductAttributeSetIn) =>
  api.put<ProductAttributeOut>(`/ui/financial-products/${product_code}/attributes`, body);

export const deleteProductAttribute = (product_code: string, attribute_id: string) =>
  api.del<{ ok: boolean }>(`/ui/financial-products/${product_code}/attributes/${attribute_id}`);

// ─── CUS-004: Financial Product Collections ───────────────────────────────────

export const listCollections = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit != null) params["limit"] = String(opts.limit);
  return api.get<ProductCollectionListOut>("/ui/financial-products/collections", params);
};

export const getCollection = (collection_code: string) =>
  api.get<ProductCollectionOut>(`/ui/financial-products/collections/${collection_code}`);

export const upsertCollection = (collection_code: string, body: ProductCollectionUpsertIn) =>
  api.put<ProductCollectionOut>(`/ui/financial-products/collections/${collection_code}`, body);

export const addToCollection = (collection_code: string, product_code: string) =>
  api.post<ProductCollectionOut>(
    `/ui/financial-products/collections/${collection_code}/members`,
    { product_code },
  );

export const removeFromCollection = (collection_code: string, product_code: string) =>
  api.del<ProductCollectionOut>(
    `/ui/financial-products/collections/${collection_code}/members/${product_code}`,
  );
