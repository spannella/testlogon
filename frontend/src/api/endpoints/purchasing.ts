import { api } from "@/api/client";

// ─── Types (mirror app/models.py PUR models — defined inline per cluster rules) ───

export interface SupplierAddress {
  [key: string]: unknown;
}

export interface Supplier {
  supplier_id: string;
  name: string;
  status: string; // "active" | "inactive"
  email?: string | null;
  phone?: string | null;
  address?: SupplierAddress | null;
  default_currency: string;
  payment_terms_days: number;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface SupplierListResp {
  suppliers: Supplier[];
  cursor?: string | null;
}

export interface SupplierProduct {
  supplier_id: string;
  sku: string;
  supplier_sku?: string | null;
  unit_cost_cents: number;
  currency: string;
  lead_time_days: number;
  min_order_qty: number;
  preferred: boolean;
  updated_at: number;
}

export interface SupplierProductListResp {
  products: SupplierProduct[];
}

export interface PurchaseOrderLine {
  line_no: number;
  sku: string;
  quantity_ordered: number;
  quantity_received: number;
  unit_cost_cents: number;
  line_total_cents: number;
}

export interface PurchaseOrder {
  po_id: string;
  supplier_id: string;
  status: string;
  currency: string;
  subtotal_cents: number;
  expected_delivery_date?: string | null;
  created_by: string;
  approved_by?: string | null;
  approved_at?: number | null;
  rejected_by?: string | null;
  rejected_reason?: string | null;
  ledger_entry_sk?: string | null;
  paid_at?: number | null;
  correlation_id: string;
  created_at: number;
  updated_at: number;
  lines: PurchaseOrderLine[];
}

export interface PurchaseOrderListResp {
  purchase_orders: PurchaseOrder[];
  cursor?: string | null;
}

export interface PoReceipt {
  receipt_id: string;
  po_id: string;
  received_by: string;
  lines: Array<Record<string, unknown>>;
  created_at: number;
}

export interface PoReceiveResp {
  receipt: PoReceipt;
  po: PurchaseOrder;
}

export interface ReorderSuggestion {
  sku: string;
  available: number;
  reorder_point: number;
  suggested_qty: number;
  supplier_id?: string | null;
  supplier_name?: string | null;
  unit_cost_cents?: number | null;
  lead_time_days?: number | null;
  warning?: string | null;
}

export interface ReorderSuggestionListResp {
  suggestions: ReorderSuggestion[];
  no_supplier_skus: string[];
}

export interface ApPayable {
  po_id: string;
  entry_id: string;
  amount_cents: number;
  state: string;
  ledger_date: string;
  supplier_id: string;
  ts: number;
}

// ─── Request payload shapes ──────────────────────────────────────────────────

export interface SupplierCreatePayload {
  name: string;
  email?: string | null;
  phone?: string | null;
  address?: SupplierAddress | null;
  default_currency?: string;
  payment_terms_days?: number;
}

export interface SupplierPatchPayload {
  name?: string;
  email?: string | null;
  phone?: string | null;
  address?: SupplierAddress | null;
  default_currency?: string;
  payment_terms_days?: number;
}

export interface SupplierProductUpsertPayload {
  unit_cost_cents: number;
  currency?: string;
  lead_time_days?: number;
  min_order_qty?: number;
  supplier_sku?: string | null;
  preferred?: boolean;
}

export interface PurchaseOrderLinePayload {
  sku: string;
  quantity_ordered: number;
  unit_cost_cents?: number | null;
}

export interface PurchaseOrderCreatePayload {
  supplier_id: string;
  lines: PurchaseOrderLinePayload[];
  currency?: string;
  expected_delivery_date?: string | null;
  correlation_id?: string | null;
}

export interface PoTransitionPayload {
  reason?: string;
  rejected_reason?: string;
}

export interface PoReceiveLinePayload {
  line_no: number;
  quantity: number;
}

export interface PoReceivePayload {
  lines: PoReceiveLinePayload[];
  receipt_correlation_id?: string | null;
}

export interface PoSettlePaymentPayload {
  payment_ref: string;
  provider?: string;
}

// ─── Suppliers ────────────────────────────────────────────────────────────────

export const listSuppliers = (opts?: {
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<SupplierListResp>("/ui/purchasing/suppliers", params);
};

export const getSupplier = (supplierId: string) =>
  api.get<Supplier>(`/ui/purchasing/suppliers/${encodeURIComponent(supplierId)}`);

export const createSupplier = (body: SupplierCreatePayload) =>
  api.post<Supplier>("/ui/purchasing/suppliers", body);

export const updateSupplier = (supplierId: string, body: SupplierPatchPayload) =>
  api.patch<Supplier>(`/ui/purchasing/suppliers/${encodeURIComponent(supplierId)}`, body);

export const setSupplierStatus = (supplierId: string, status: string) =>
  api.post<Supplier>(
    `/ui/purchasing/suppliers/${encodeURIComponent(supplierId)}/status`,
    { status },
  );

// ─── Supplier products ──────────────────────────────────────────────────────

export const listSupplierProducts = (supplierId: string) =>
  api.get<SupplierProductListResp>(
    `/ui/purchasing/suppliers/${encodeURIComponent(supplierId)}/products`,
  );

export const getSupplierProduct = (supplierId: string, sku: string) =>
  api.get<SupplierProduct>(
    `/ui/purchasing/suppliers/${encodeURIComponent(supplierId)}/products/${encodeURIComponent(sku)}`,
  );

export const upsertSupplierProduct = (
  supplierId: string,
  sku: string,
  body: SupplierProductUpsertPayload,
) =>
  api.put<SupplierProduct>(
    `/ui/purchasing/suppliers/${encodeURIComponent(supplierId)}/products/${encodeURIComponent(sku)}`,
    body,
  );

// ─── Purchase orders ────────────────────────────────────────────────────────

export const listPurchaseOrders = (opts?: {
  supplier_id?: string;
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.supplier_id) params["supplier_id"] = opts.supplier_id;
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<PurchaseOrderListResp>("/ui/purchasing/purchase-orders", params);
};

export const getPurchaseOrder = (poId: string) =>
  api.get<PurchaseOrder>(`/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}`);

export const createPurchaseOrder = (body: PurchaseOrderCreatePayload) =>
  api.post<PurchaseOrder>("/ui/purchasing/purchase-orders", body);

export const submitPurchaseOrder = (poId: string, body?: PoTransitionPayload) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/submit`,
    body ?? {},
  );

export const approvePurchaseOrder = (poId: string, body?: PoTransitionPayload) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/approve`,
    body ?? {},
  );

export const rejectPurchaseOrder = (poId: string, body?: PoTransitionPayload) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/reject`,
    body ?? {},
  );

export const orderPurchaseOrder = (poId: string, body?: PoTransitionPayload) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/order`,
    body ?? {},
  );

export const cancelPurchaseOrder = (poId: string, body?: PoTransitionPayload) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/cancel`,
    body ?? {},
  );

export const receivePurchaseOrder = (poId: string, body: PoReceivePayload) =>
  api.post<PoReceiveResp>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/receive`,
    body,
  );

export const getApPayable = (poId: string) =>
  api.get<ApPayable>(`/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/ap-payable`);

export const settlePoPayment = (poId: string, body: PoSettlePaymentPayload) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/purchase-orders/${encodeURIComponent(poId)}/settle-payment`,
    body,
  );

// ─── Reorder suggestions ────────────────────────────────────────────────────

export const getReorderSuggestions = () =>
  api.get<ReorderSuggestionListResp>("/ui/purchasing/reorder-suggestions");

export const createPoFromSuggestion = (supplierId: string, skus: string[]) =>
  api.post<PurchaseOrder>(
    `/ui/purchasing/reorder-suggestions/${encodeURIComponent(supplierId)}/create-po`,
    { skus },
  );

// ─── Shared helpers ─────────────────────────────────────────────────────────

export const PO_STATUS_TRANSITIONS: Record<string, string[]> = {
  draft: ["submitted", "cancelled"],
  submitted: ["approved", "rejected", "cancelled"],
  approved: ["ordered", "rejected", "cancelled"],
  ordered: ["partially_received", "received", "cancelled"],
  partially_received: ["received"],
  received: ["closed"],
};

export function formatCents(cents: number | null | undefined, currency = "USD"): string {
  const value = (cents ?? 0) / 100;
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: currency || "USD",
    }).format(value);
  } catch {
    return `${(currency || "USD")} ${value.toFixed(2)}`;
  }
}
